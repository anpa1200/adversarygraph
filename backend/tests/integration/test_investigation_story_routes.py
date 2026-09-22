from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

REPORT = "The workstation sent repeated POST requests. Initial access is not established."


@pytest.mark.asyncio
async def test_marking_is_explicit_audited_and_not_writable_via_generic_update(client):
    row = await create(client)
    assert row["tlp"] == "TLP:AMBER+STRICT"
    url = f"/api/operations/investigations/{row['id']}"
    assert (await client.put(url, json={"name": "test", "tlp": "TLP:CLEAR"})).status_code == 422
    assert (await client.patch(url + "/marking", json={"tlp": "TLP:CLEAR", "reason": "short"})).status_code == 422
    marked = await client.patch(url + "/marking", json={"tlp": "TLP:CLEAR", "reason": "Public synthetic training fixture only."})
    assert marked.status_code == 200 and marked.json()["tlp"] == "TLP:CLEAR"
    checked = await client.get(url + "/summary/preflight", params={"report_id": "full-report"})
    assert checked.status_code == 200 and checked.json()["effective_tlp"] == "TLP:CLEAR"


async def create(client, report=True):
    response = await client.post("/api/operations/investigations", json={
        "name": "Story fixture", "evidence_nodes": [
            {"id": "full-report", "type": "investigation-report", "content": REPORT}
        ] if report else [],
    })
    assert response.status_code == 201, response.text
    return response.json()


def install_fake_provider(monkeypatch, mutate=None):
    monkeypatch.setattr("app.services.threat_hunting_ai.create_adapter", lambda *a, **k: SimpleNamespace(provider="local", model="test-only"))
    async def complete(adapter, system, user, *, timeout_seconds=None):
        assert timeout_seconds == 120.0
        assert "UNTRUSTED DATA" in system
        pack = json.loads(user)["untrusted_evidence"]
        assert "".join(p["text"] for p in pack["sources"][0]["passages"]) == REPORT
        if mutate:
            await mutate()
        def claim(text, quote):
            return {"text": text, "basis": "reported", "evidence": [{"source_id": "S0001.1"}]}
        return json.dumps({"what_happened": [claim("Repeated outbound requests were reported.", "The workstation sent repeated POST requests.")],
            "identities": [], "ttps": [], "iocs": [], "next_steps": [],
            "uncertainties": [claim("Initial access remains unknown.", "Initial access is not established.")]})
    monkeypatch.setattr("app.services.threat_hunting_ai.complete", complete)


@pytest.mark.asyncio
async def test_story_saved_separately_retrievable_and_no_intelligence_promotion(client, monkeypatch):
    row = await create(client)
    install_fake_provider(monkeypatch)
    response = await client.post(f"/api/operations/investigations/{row['id']}/summary", json={"report_id": "full-report"})
    assert response.status_code == 200, response.text
    summary = response.json()
    assert summary["authoritative"] is False
    assert summary["token_usage"] is None
    assert summary["model"] == "test-only"
    assert summary["coverage"]["full_report_included"] is True
    saved = (await client.get("/api/operations/investigations")).json()[0]
    assert saved["evidence_nodes"][0]["content"] == REPORT
    assert saved["evidence_nodes"][1] == summary
    assert saved["actor_ids"] == saved["technique_ids"] == saved["report_ids"] == []
    check = await client.get(f"/api/operations/investigations/{row['id']}/summaries/{summary['id']}")
    assert check.status_code == 200
    assert check.json()["stale"] is False
    await client.put(f"/api/operations/investigations/{row['id']}", json={
        "name": "Updated case", "evidence_nodes": saved["evidence_nodes"],
    })
    check = await client.get(f"/api/operations/investigations/{row['id']}/summaries/{summary['id']}")
    assert check.json()["stale"] is True


@pytest.mark.asyncio
async def test_story_requires_full_report(client):
    row = await create(client, report=False)
    response = await client.post(f"/api/operations/investigations/{row['id']}/summary", json={"report_id": "full-report"})
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_changed_source_never_saves_a_stale_summary(client, monkeypatch):
    row = await create(client)
    async def mutate():
        body = {k: row[k] for k in ("name", "evidence_nodes")}
        body["evidence_nodes"][0]["content"] += " New evidence."
        assert (await client.put(f"/api/operations/investigations/{row['id']}", json=body)).status_code == 200
    install_fake_provider(monkeypatch, mutate)
    response = await client.post(f"/api/operations/investigations/{row['id']}/summary", json={"report_id": "full-report"})
    assert response.status_code == 409, response.text
    saved = (await client.get("/api/operations/investigations")).json()[0]
    assert len(saved["evidence_nodes"]) == 1


@pytest.mark.asyncio
async def test_invalid_model_output_is_not_saved_or_exposed(client, monkeypatch):
    row = await create(client)
    install_fake_provider(monkeypatch)
    async def bad(*args, **kwargs):
        return '{"provider_secret":"must not be exposed"}'
    monkeypatch.setattr("app.services.threat_hunting_ai.complete", bad)
    response = await client.post(f"/api/operations/investigations/{row['id']}/summary", json={"report_id": "full-report"})
    assert response.status_code == 502
    assert "provider_secret" not in response.text
    saved = (await client.get("/api/operations/investigations")).json()[0]
    assert len(saved["evidence_nodes"]) == 1


@pytest.mark.asyncio
async def test_cloud_acknowledgement_does_not_downgrade_private_workspace(client, monkeypatch):
    row = await create(client)
    monkeypatch.setattr("app.services.threat_hunting_ai.settings.threat_hunting_ai_enabled", True)
    monkeypatch.setattr("app.services.threat_hunting_ai.settings.threat_hunting_ai_cloud_enabled", True)
    monkeypatch.setattr("app.services.threat_hunting_ai._provider_configured", lambda p: True)
    response = await client.post(f"/api/operations/investigations/{row['id']}/summary", json={
        "report_id": "full-report", "provider": "openai", "cloud_processing_acknowledged": True,
    })
    assert response.status_code == 403, response.text
    assert "AMBER+STRICT" in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("permission", ["run_analysis", "manage_intel"])
async def test_both_permissions_are_required(client, app, monkeypatch, permission):
    from app.core.config import settings
    from app.services.auth import TeamUser, current_user
    row = await create(client)
    monkeypatch.setattr(settings, "auth_enabled", True)
    async def limited_user():
        return TeamUser(name="limited", roles=[], permissions=[permission])
    app.dependency_overrides[current_user] = limited_user
    try:
        response = await client.post(f"/api/operations/investigations/{row['id']}/summary", json={"report_id": "full-report"})
        assert response.status_code == 403, response.text
    finally:
        app.dependency_overrides.pop(current_user, None)


@pytest.mark.asyncio
async def test_timeout_is_sanitized(client, monkeypatch):
    from app.services.threat_hunting_ai import AIProviderTimeoutError
    row = await create(client)
    install_fake_provider(monkeypatch)
    async def timed_out(*args, **kwargs):
        raise AIProviderTimeoutError("sensitive provider details")
    monkeypatch.setattr("app.services.threat_hunting_ai.complete", timed_out)
    response = await client.post(f"/api/operations/investigations/{row['id']}/summary", json={"report_id": "full-report"})
    assert response.status_code == 504
    assert "sensitive" not in response.text
