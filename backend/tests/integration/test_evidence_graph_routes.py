from __future__ import annotations

import pytest

from app.core.config import settings
from app.services.auth import TeamUser, current_user


@pytest.fixture(autouse=True)
def _auth_disabled_by_default(monkeypatch, app):
    monkeypatch.setattr(settings, "auth_enabled", False)
    async def test_user():
        return TeamUser(name="test-analyst", roles=["admin", "analyst", "viewer"], permissions=["read", "run_analysis", "export_data", "manage_auth"])
    app.dependency_overrides[current_user] = test_user
    yield
    app.dependency_overrides.pop(current_user, None)


def _auth_headers(role: str = "admin") -> dict[str, str]:
    headers = {
        "X-Auth-User": f"test-{role}",
        "X-Auth-Roles": role,
    }
    if settings.proxy_secret:
        headers["X-Internal-Proxy-Secret"] = settings.proxy_secret
    return headers


async def _node(client, node_type: str, title: str, **extra):
    response = await client.post("/api/evidence-graph/nodes", json={
        "node_type": node_type,
        "title": title,
        **extra,
    }, headers=_auth_headers())
    assert response.status_code == 201, response.text
    return response.json()


async def _edge(client, source: str, target: str, edge_type: str):
    response = await client.post("/api/evidence-graph/edges", json={
        "source_node_id": source,
        "target_node_id": target,
        "edge_type": edge_type,
        "rationale": "test edge",
    }, headers=_auth_headers())
    assert response.status_code == 201, response.text
    return response.json()


@pytest.mark.asyncio
async def test_evidence_graph_node_and_edge_crud(client):
    evidence = await _node(client, "evidence", "Report excerpt", source_type="report_text", raw_excerpt="Observed powershell.exe usage")
    claim = await _node(client, "claim", "PowerShell was used", statement="PowerShell execution was observed", ai_generated=True)
    edge = await _edge(client, evidence["id"], claim["id"], "SUPPORTS")

    assert claim["review_status"] == "draft"
    assert edge["edge_type"] == "SUPPORTS"

    updated = await client.patch(
        f"/api/evidence-graph/nodes/{claim['id']}",
        json={"review_status": "analyst_reviewed"},
        headers=_auth_headers(),
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["review_status"] == "analyst_reviewed"

    edge_update = await client.patch(
        f"/api/evidence-graph/edges/{edge['id']}",
        json={"review_status": "analyst_reviewed"},
        headers=_auth_headers(),
    )
    assert edge_update.status_code == 200, edge_update.text
    assert edge_update.json()["review_status"] == "analyst_reviewed"


@pytest.mark.asyncio
async def test_evidence_graph_full_path_gaps_and_score(client):
    evidence = await _node(client, "evidence", "EDR event", review_status="analyst_reviewed")
    claim = await _node(client, "claim", "Encoded command claim", review_status="analyst_reviewed")
    behavior = await _node(client, "behavior", "Command execution behavior", review_status="analyst_reviewed")
    technique = await _node(client, "attack_technique", "T1059.001 PowerShell", technique_id="T1059.001", review_status="analyst_reviewed")
    telemetry = await _node(client, "required_telemetry", "PowerShell telemetry", availability_status="available", required_fields=["EventID", "ScriptBlockText"])
    candidate = await _node(client, "detection_candidate", "PowerShell encoded command detection", status="testable")
    rule = await _node(client, "detection_rule", "Sigma PowerShell encoded command", rule_format="sigma", rule_body="title: test")
    scenario = await _node(client, "validation_scenario", "Replay PowerShell event", scenario_type="replay")
    result = await _node(client, "siem_result", "SIEM matched rule", forwarding_status="sent", detection_matched=True)
    decision = await _node(client, "analyst_decision", "Accept detection", decision="accepted", review_status="analyst_reviewed")

    for source, target, edge_type in [
        (evidence, claim, "SUPPORTS"),
        (claim, behavior, "DESCRIBES"),
        (behavior, technique, "MAPS_TO"),
        (technique, telemetry, "REQUIRES_TELEMETRY"),
        (telemetry, candidate, "ENABLES_DETECTION"),
        (candidate, rule, "IMPLEMENTED_AS"),
        (rule, scenario, "VALIDATED_BY"),
        (scenario, result, "PRODUCED_RESULT"),
        (result, decision, "REVIEWED_AS"),
    ]:
        await _edge(client, source["id"], target["id"], edge_type)

    summary = await client.get("/api/evidence-graph/summary", headers=_auth_headers())
    assert summary.status_code == 200, summary.text
    assert summary.json()["detection_readiness_score"] == 100

    paths = await client.get(
        "/api/evidence-graph/paths",
        params={"from_node_id": evidence["id"], "to_node_type": "analyst_decision"},
        headers=_auth_headers(),
    )
    assert paths.status_code == 200, paths.text
    assert [node["node_type"] for node in paths.json()["paths"][0]][0] == "evidence"
    assert [node["node_type"] for node in paths.json()["paths"][0]][-1] == "analyst_decision"

    gaps = await client.get("/api/evidence-graph/gaps", headers=_auth_headers())
    assert gaps.status_code == 200, gaps.text
    assert all(gap["missing_step"] != "rule_missing" for gap in gaps.json()["gaps"])


@pytest.mark.asyncio
async def test_evidence_graph_gap_detection_and_export_redaction(client):
    technique = await _node(client, "attack_technique", "T1190 exploit public app", technique_id="T1190")
    telemetry = await _node(
        client,
        "required_telemetry",
        "Web access logs",
        availability_status="unavailable",
        metadata_json={"api_token": "secret-value", "safe": "ok"},
    )
    await _edge(client, technique["id"], telemetry["id"], "REQUIRES_TELEMETRY")

    gaps = await client.get("/api/evidence-graph/gaps", headers=_auth_headers())
    assert gaps.status_code == 200, gaps.text
    missing = {item["missing_step"] for item in gaps.json()["gaps"]}
    assert "telemetry_not_validated" in missing
    assert "detection_candidate_missing" in missing

    export = await client.get("/api/evidence-graph/export", params={"fmt": "json"}, headers=_auth_headers())
    assert export.status_code == 200
    assert "secret-value" not in export.text
    assert "[REDACTED]" in export.text


@pytest.mark.asyncio
async def test_evidence_graph_generation_from_report_and_simulation(client):
    report = await client.post("/api/evidence-graph/from-report/report-demo-1", headers=_auth_headers())
    assert report.status_code == 200, report.text
    assert report.json()["nodes_created"] >= 1

    simulation = await client.post(
        "/api/evidence-graph/from-simulation/run-sim-t1059-001-demo",
        headers=_auth_headers(),
    )
    assert simulation.status_code == 200, simulation.text
    assert simulation.json()["nodes_created"] == 2
    assert simulation.json()["edges_created"] == 1


@pytest.mark.asyncio
async def test_evidence_graph_viewer_cannot_mutate_when_auth_enabled(client, app, monkeypatch):
    monkeypatch.setattr(settings, "auth_enabled", True)

    async def viewer():
        return TeamUser(name="viewer", roles=["viewer"], permissions=["read"])

    app.dependency_overrides[current_user] = viewer
    try:
        response = await client.post(
            "/api/evidence-graph/nodes",
            json={"node_type": "evidence", "title": "blocked"},
            headers=_auth_headers("viewer"),
        )
        assert response.status_code == 403
    finally:
        monkeypatch.setattr(settings, "auth_enabled", False)
