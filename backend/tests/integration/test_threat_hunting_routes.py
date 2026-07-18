from __future__ import annotations

from datetime import datetime, timedelta, timezone

from httpx import AsyncClient

from app.core.config import settings
from app.services.auth import TeamUser, current_user


HUNT = {
    "title": "Suspicious PowerShell execution",
    "hypothesis": "An adversary is using encoded PowerShell on managed endpoints.",
    "description": "Review process creation and script-block telemetry.",
    "scope": "Windows endpoints in the finance segment",
    "priority": "P1 High",
    "technique_ids": ["t1059.001", "T1027", "T1059.001"],
    "tactics": ["execution", "stealth"],
    "telemetry_sources": ["Process creation", "PowerShell Script Block Logging"],
    "required_fields": ["host.name", "process.command_line"],
    "query_language": "kql",
    "query_text": "process.name : powershell.exe",
    "expected_evidence": "Encoded commands with suspicious parent/child activity.",
    "false_positive_notes": "Approved automation and deployment tooling.",
    "tags": ["powershell", "endpoint"],
}


async def test_threat_hunting_templates_and_empty_stats(client: AsyncClient):
    templates = await client.get("/api/threat-hunting/templates")
    assert templates.status_code == 200
    assert len(templates.json()) >= 6
    assert templates.json()[0]["technique_ids"]

    stats = await client.get("/api/threat-hunting/stats")
    assert stats.status_code == 200
    assert stats.json() == {
        "total_hunts": 0,
        "active_hunts": 0,
        "completed_hunts": 0,
        "total_findings": 0,
        "high_priority_findings": 0,
        "by_status": {},
        "by_priority": {},
    }


async def test_threat_hunt_full_lifecycle(client: AsyncClient):
    created = await client.post("/api/threat-hunting/hunts", json=HUNT)
    assert created.status_code == 201, created.text
    hunt = created.json()
    hunt_id = hunt["id"]
    assert hunt["technique_ids"] == ["T1059.001", "T1027"]
    assert hunt["created_by"] == "local"

    listed = await client.get("/api/threat-hunting/hunts")
    assert listed.status_code == 200
    assert [row["id"] for row in listed.json()] == [hunt_id]

    oversized_versions = await client.get(
        f"/api/threat-hunting/hunts/{hunt_id}/query-versions",
        params={"limit": 501},
    )
    invalid_findings_offset = await client.get(
        f"/api/threat-hunting/hunts/{hunt_id}/findings",
        params={"offset": -1},
    )
    assert oversized_versions.status_code == 422
    assert invalid_findings_offset.status_code == 422

    planned = await client.patch(
        f"/api/threat-hunting/hunts/{hunt_id}",
        json={"status": "planned", "owner": "hunt-team"},
    )
    assert planned.status_code == 200

    updated = await client.patch(
        f"/api/threat-hunting/hunts/{hunt_id}",
        json={"status": "running", "owner": "hunt-team", "disposition": "undetermined"},
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "running"

    finding = await client.post(
        f"/api/threat-hunting/hunts/{hunt_id}/findings",
        json={
            "title": "Encoded PowerShell from spreadsheet process",
            "summary": "Observed encoded PowerShell spawned by an office process.",
            "severity": "high",
            "confidence": 85,
            "verdict": "supports",
            "evidence_ref": "siem:event:12345",
            "observables": ["host-01", "10.0.0.5"],
            "technique_ids": ["T1059.001"],
        },
    )
    assert finding.status_code == 201, finding.text
    assert finding.json()["analyst"] == "local"
    assert finding.json()["tlp"] == "TLP:AMBER"
    finding_id = finding.json()["id"]

    forged_attribution = await client.post(
        f"/api/threat-hunting/hunts/{hunt_id}/findings",
        json={"title": "Forged attribution", "analyst": "forged-client-name"},
    )
    assert forged_attribution.status_code == 422

    forged_review_state = await client.post(
        f"/api/threat-hunting/hunts/{hunt_id}/findings",
        json={
            "title": "Finding created as already reviewed",
            "summary": "This would bypass review provenance.",
            "status": "reviewed",
            "verdict": "supports",
            "evidence_ref": "siem:event:forged-review",
        },
    )
    assert forged_review_state.status_code == 422
    assert "must start with status new" in forged_review_state.json()["detail"]

    detail = await client.get(f"/api/threat-hunting/hunts/{hunt_id}")
    assert detail.status_code == 200
    assert detail.json()["findings"][0]["id"] == finding_id
    assert detail.json()["query_versions"][0]["version"] == 1

    patched_finding = await client.patch(
        f"/api/threat-hunting/hunts/{hunt_id}/findings/{finding_id}",
        json={"status": "escalated", "notes": "Promoted to incident review."},
    )
    assert patched_finding.status_code == 200
    assert patched_finding.json()["status"] == "escalated"

    exported = await client.get(f"/api/threat-hunting/hunts/{hunt_id}/export")
    assert exported.status_code == 200
    assert exported.json()["schema"] == "adversarygraph-threat-hunt-v1"
    assert exported.json()["hunt"]["id"] == hunt_id
    assert len(exported.json()["findings"]) == 1
    assert exported.json()["query_versions"][0]["checksum"]
    assert "did not execute" in exported.json()["execution_boundary"]


async def test_threat_hunt_enforces_review_and_completion(client: AsyncClient):
    created = await client.post("/api/threat-hunting/hunts", json=HUNT)
    hunt_id = created.json()["id"]
    finding = await client.post(
        f"/api/threat-hunting/hunts/{hunt_id}/findings",
        json={"title": "Evidence awaiting review", "verdict": "inconclusive"},
    )
    assert finding.status_code == 201
    finding_id = finding.json()["id"]

    invalid_jump = await client.patch(
        f"/api/threat-hunting/hunts/{hunt_id}",
        json={"status": "completed", "result_summary": "No suspicious evidence.", "disposition": "no_matches"},
    )
    assert invalid_jump.status_code == 409

    for status in ("planned", "running", "review"):
        response = await client.patch(f"/api/threat-hunting/hunts/{hunt_id}", json={"status": status})
        assert response.status_code == 200, response.text

    missing_outcome = await client.patch(
        f"/api/threat-hunting/hunts/{hunt_id}",
        json={"status": "completed"},
    )
    assert missing_outcome.status_code == 422

    unresolved_finding = await client.patch(
        f"/api/threat-hunting/hunts/{hunt_id}",
        json={
            "status": "completed",
            "result_summary": "No matching activity was present in the bounded, retained data.",
            "disposition": "no_matches",
        },
    )
    assert unresolved_finding.status_code == 422
    assert "new findings" in unresolved_finding.text

    reviewed = await client.patch(
        f"/api/threat-hunting/hunts/{hunt_id}/findings/{finding_id}",
        json={"status": "reviewed"},
    )
    assert reviewed.status_code == 200

    completed = await client.patch(
        f"/api/threat-hunting/hunts/{hunt_id}",
        json={
            "status": "completed",
            "result_summary": "No matching activity was present in the bounded, retained data.",
            "disposition": "no_matches",
        },
    )
    assert completed.status_code == 200
    assert completed.json()["completed_at"]

    immutable = await client.patch(
        f"/api/threat-hunting/hunts/{hunt_id}",
        json={"query_text": "changed after completion"},
    )
    assert immutable.status_code == 409

    immutable_finding = await client.patch(
        f"/api/threat-hunting/hunts/{hunt_id}/findings/{finding_id}",
        json={"notes": "changed after completion"},
    )
    assert immutable_finding.status_code == 409

    archived = await client.post(f"/api/threat-hunting/hunts/{hunt_id}/archive")
    assert archived.status_code == 200
    assert archived.json()["status"] == "archived"
    assert archived.json()["archived_at"]


async def test_reviewed_findings_require_real_evidence_and_valid_transitions(client: AsyncClient):
    created = await client.post("/api/threat-hunting/hunts", json=HUNT)
    hunt_id = created.json()["id"]
    finding = await client.post(
        f"/api/threat-hunting/hunts/{hunt_id}/findings",
        json={
            "title": "Candidate command execution",
            "summary": "Process and network telemetry support the hunt hypothesis.",
            "verdict": "supports",
        },
    )
    assert finding.status_code == 201
    finding_id = finding.json()["id"]

    missing_evidence = await client.patch(
        f"/api/threat-hunting/hunts/{hunt_id}/findings/{finding_id}",
        json={"status": "reviewed"},
    )
    assert missing_evidence.status_code == 422
    assert "evidence_ref" in missing_evidence.text

    staged_evidence = await client.patch(
        f"/api/threat-hunting/hunts/{hunt_id}/findings/{finding_id}",
        json={"evidence_ref": "siem:event:67890"},
    )
    assert staged_evidence.status_code == 200
    reviewed = await client.patch(
        f"/api/threat-hunting/hunts/{hunt_id}/findings/{finding_id}",
        json={"status": "reviewed"},
    )
    assert reviewed.status_code == 200

    cannot_remove_evidence = await client.patch(
        f"/api/threat-hunting/hunts/{hunt_id}/findings/{finding_id}",
        json={"evidence_ref": "   "},
    )
    assert cannot_remove_evidence.status_code == 422

    invalid_backward_transition = await client.patch(
        f"/api/threat-hunting/hunts/{hunt_id}/findings/{finding_id}",
        json={"status": "new"},
    )
    assert invalid_backward_transition.status_code == 409


async def test_threat_hunting_routes_require_analyst_role(
    app,
    client: AsyncClient,
    monkeypatch,
):
    async def analyst_user():
        return TeamUser(name="analyst", roles=["analyst"], permissions=["read", "run_analysis"])

    async def viewer_user():
        return TeamUser(name="viewer", roles=["viewer"], permissions=["read"])

    async def export_user():
        return TeamUser(
            name="exporter",
            roles=["analyst"],
            permissions=["read", "run_analysis", "export_data"],
        )

    previous = app.dependency_overrides.get(current_user)
    monkeypatch.setattr(settings, "auth_enabled", True)
    try:
        app.dependency_overrides[current_user] = analyst_user
        for path in ("/api/threat-hunting/templates", "/api/threat-hunting/stats"):
            allowed_read = await client.get(path)
            assert allowed_read.status_code == 200, path

        created = await client.post("/api/threat-hunting/hunts", json=HUNT)
        assert created.status_code == 201, created.text
        hunt_id = created.json()["id"]
        export_path = f"/api/threat-hunting/hunts/{hunt_id}/export"
        hunt_read_paths = (
            "/api/threat-hunting/hunts",
            f"/api/threat-hunting/hunts/{hunt_id}",
            f"/api/threat-hunting/hunts/{hunt_id}/query-versions",
            f"/api/threat-hunting/hunts/{hunt_id}/findings",
        )
        for path in hunt_read_paths:
            allowed_read = await client.get(path)
            assert allowed_read.status_code == 200, path

        denied_export = await client.get(export_path)
        assert denied_export.status_code == 403

        app.dependency_overrides[current_user] = export_user
        allowed_export = await client.get(export_path)
        assert allowed_export.status_code == 200

        app.dependency_overrides[current_user] = viewer_user
        for path in (
            "/api/threat-hunting/templates",
            "/api/threat-hunting/stats",
            *hunt_read_paths,
            export_path,
        ):
            denied_read = await client.get(path)
            assert denied_read.status_code == 403, path

        denied = await client.post("/api/threat-hunting/hunts", json=HUNT)
        assert denied.status_code == 403
    finally:
        if previous is None:
            app.dependency_overrides.pop(current_user, None)
        else:
            app.dependency_overrides[current_user] = previous


async def test_threat_hunting_rejects_invalid_inputs(client: AsyncClient):
    forged_source = await client.post(
        "/api/threat-hunting/hunts",
        json={**HUNT, "source_type": "threat_radar", "source_ref": "forged-case"},
    )
    assert forged_source.status_code == 422

    invalid_technique = await client.post(
        "/api/threat-hunting/hunts",
        json={**HUNT, "technique_ids": ["TA0002"]},
    )
    assert invalid_technique.status_code == 422

    now = datetime.now(timezone.utc)
    invalid_range = await client.post(
        "/api/threat-hunting/hunts",
        json={
            **HUNT,
            "time_range_start": (now + timedelta(hours=1)).isoformat(),
            "time_range_end": now.isoformat(),
        },
    )
    assert invalid_range.status_code == 422

    invalid_filter = await client.get("/api/threat-hunting/hunts", params={"technique_id": "TA0002"})
    assert invalid_filter.status_code == 422

    incomplete_planned = await client.post(
        "/api/threat-hunting/hunts",
        json={
            "title": "Incomplete planned hunt",
            "hypothesis": "An adversary behavior may be present in local telemetry.",
            "status": "planned",
        },
    )
    assert incomplete_planned.status_code == 422
    assert "telemetry_sources" in incomplete_planned.text

async def test_archival_preserves_classified_finding(client: AsyncClient):
    classified = await client.post(
        "/api/threat-hunting/hunts",
        json={**HUNT, "title": "Classified hunt", "tlp": "TLP:AMBER"},
    )
    assert classified.status_code == 201
    hunt_id = classified.json()["id"]

    finding = await client.post(
        f"/api/threat-hunting/hunts/{hunt_id}/findings",
        json={"title": "Restricted evidence reference", "evidence_ref": "case:event:red-1"},
    )
    assert finding.status_code == 201
    assert finding.json()["tlp"] == "TLP:AMBER"

    raised_hunt = await client.patch(
        f"/api/threat-hunting/hunts/{hunt_id}",
        json={"tlp": "TLP:RED"},
    )
    assert raised_hunt.status_code == 200
    assert raised_hunt.json()["tlp"] == "TLP:RED"

    inherited_raise = await client.get(f"/api/threat-hunting/hunts/{hunt_id}/findings")
    assert inherited_raise.status_code == 200
    assert inherited_raise.json()[0]["tlp"] == "TLP:RED"

    explicit_null = await client.patch(
        f"/api/threat-hunting/hunts/{hunt_id}/findings/{finding.json()['id']}",
        json={"tlp": None},
    )
    assert explicit_null.status_code == 422

    downgrade_hunt = await client.patch(
        f"/api/threat-hunting/hunts/{hunt_id}",
        json={"tlp": "TLP:CLEAR"},
    )
    assert downgrade_hunt.status_code == 422

    downgrade_finding = await client.post(
        f"/api/threat-hunting/hunts/{hunt_id}/findings",
        json={"title": "Overly broad classification", "tlp": "TLP:CLEAR"},
    )
    assert downgrade_finding.status_code == 422

    archived = await client.post(
        f"/api/threat-hunting/hunts/{hunt_id}/findings/{finding.json()['id']}/archive"
    )
    assert archived.status_code == 200
    assert archived.json()["archived_at"]

    visible = await client.get(f"/api/threat-hunting/hunts/{hunt_id}/findings")
    assert visible.status_code == 200
    assert visible.json() == []

    exported = await client.get(f"/api/threat-hunting/hunts/{hunt_id}/export")
    assert exported.status_code == 200
    assert exported.json()["findings"][0]["id"] == finding.json()["id"]
    assert exported.json()["findings"][0]["tlp"] == "TLP:RED"
