from __future__ import annotations

import json
from uuid import UUID, uuid4

import pytest
from httpx import AsyncClient

from app.core.config import settings
from app.core.rate_limit import _windows
from app.models.analysis import AnalysisSession
from app.models.pipeline import AuditEvent
from app.models.threat_radar import ThreatHuntRequest
from app.services import threat_hunting_ai as hunt_ai
from app.services.auth import TeamUser, current_user
from tests import conftest


HUNT = {
    "title": "Suspicious PowerShell execution",
    "hypothesis": "An adversary is using encoded PowerShell on managed endpoints.",
    "description": "Review process creation and script-block telemetry.",
    "scope": "Windows endpoints in the finance segment",
    "priority": "P1 High",
    "technique_ids": [],
    "tactics": ["execution"],
    "telemetry_sources": ["Process creation"],
    "required_fields": ["host.name", "process.command_line"],
    "query_language": "kql",
    "query_text": "process.name : powershell.exe",
    "expected_evidence": "Encoded commands with suspicious parent activity.",
    "false_positive_notes": "Approved automation and deployment tooling.",
    "tags": ["powershell", "endpoint"],
}

ASSIST_OUTPUT = json.dumps({
    "summary": "Strengthen the hypothesis and validate process telemetry coverage.",
    "recommended_actions": ["Confirm PowerShell script-block logging coverage"],
    "questions": ["Are administrative automation accounts baselined?"],
    "evidence_gaps": ["Script-block logging retention is unknown"],
    "cautions": ["This suggestion does not show local compromise"],
    "suggested_patch": {
        "hypothesis": "If an adversary uses encoded PowerShell, process telemetry should show encoded commands and unusual ancestry.",
        "expected_evidence": "Encoded command flags with unusual parent-child process relationships.",
    },
    "finding_drafts": [],
    "citations": [{
        "source_type": "hunt",
        "source_ref": "draft-context",
        "quote": "encoded PowerShell",
        "start": 999,
        "end": 1005,
    }],
})

HYPOTHESIS_OUTPUT = json.dumps({
    "candidates": [{
        "title": "Hunt encoded PowerShell launched by Office",
        "hypothesis": "If the reported behavior occurs locally, Office processes will spawn encoded PowerShell commands.",
        "description": "Test the report behavior against retained endpoint process telemetry.",
        "scope": "Managed Windows endpoints; analyst must select an approved time range.",
        "technique_ids": [],
        "tactics": ["execution"],
        "telemetry_sources": ["EDR process telemetry"],
        "required_fields": ["process.parent.name", "process.command_line"],
        "tags": ["report-derived", "powershell"],
        "query_language": "generic",
        "query_text": "parent process is Office AND child process is PowerShell with encoded arguments",
        "expected_evidence": "Office parent process and encoded PowerShell command line.",
        "false_positive_notes": "Approved Office automation may spawn PowerShell.",
        "assumptions": "Endpoint process creation telemetry is complete.",
        "rationale": "The stored source explicitly describes the process chain.",
        "source_evidence": [{
            "source_type": "research",
            "source_ref": "source",
            "quote": "Office spawned encoded PowerShell",
            "start": 0,
            "end": 5,
        }],
    }],
    "warnings": [],
})


class _FakeAdapter:
    def __init__(self, provider: str, model: str, response: str):
        self.provider = provider
        self.model = model
        self.response = response

    async def _raw_complete(self, system: str, user: str) -> str:
        assert "untrusted" in system
        assert "SUPER_SECRET_FOCUS" not in system
        return self.response


@pytest.fixture(autouse=True)
def _ai_defaults(monkeypatch: pytest.MonkeyPatch):
    _windows.clear()
    monkeypatch.setattr(settings, "threat_hunting_ai_enabled", True)
    monkeypatch.setattr(settings, "threat_hunting_ai_cloud_enabled", False)
    monkeypatch.setattr(settings, "local_llm_base_url", "http://local-llm.test/v1")
    monkeypatch.setattr(settings, "local_llm_model", "test-local-model")


def _fake_provider(monkeypatch: pytest.MonkeyPatch, response: str):
    monkeypatch.setattr(
        hunt_ai,
        "get_adapter",
        lambda provider, model=None: _FakeAdapter(provider, model or "test-local-model", response),
    )


async def _store_research(client: AsyncClient, *, domain: str = "enterprise-attack") -> str:
    response = await client.post(
        "/api/analyze/sessions/research",
        data={
            "name": "Stored PowerShell research",
            "domain": domain,
            "text": "The report states that Office spawned encoded PowerShell during the intrusion.",
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["session_id"]


async def test_provider_catalog_and_unsaved_plan_assistance_are_safe(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    _fake_provider(monkeypatch, ASSIST_OUTPUT)

    providers = await client.get("/api/threat-hunting/ai/providers")
    assert providers.status_code == 200
    local = next(row for row in providers.json() if row["id"] == "local")
    assert local == {
        "id": "local",
        "label": "Local / private OpenAI-compatible",
        "model": "test-local-model",
        "configured": True,
        "remote": False,
        "requires_acknowledgement": False,
        "default": True,
    }

    response = await client.post("/api/threat-hunting/ai/assist", json={
        "provider": "local",
        "stage": "plan",
        "context": {**HUNT, "status": "completed", "tlp": "TLP:RED"},
        "analyst_focus": "SUPER_SECRET_FOCUS",
        # Local processing must persist false even if a client sends a stale true value.
        "cloud_processing_acknowledged": True,
    })
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["assistance_id"]
    assert body["lifecycle_status"] == "suggested"
    assert body["requires_human_review"] is True
    assert "status" not in body["suggested_patch"]
    assert body["citations"][0]["verified"] is True
    assert "did not execute" in body["execution_boundary"]

    history = await client.get("/api/threat-hunting/ai/history")
    assert history.status_code == 200
    stored = history.json()[0]
    serialized = json.dumps(stored)
    assert "SUPER_SECRET_FOCUS" not in serialized
    assert "encoded PowerShell on managed endpoints" not in serialized
    assert stored["input_checksum"]
    assert stored["output_checksum"]
    assert stored["cloud_processing_acknowledged"] is False
    audit_event = next(
        row for (model, _), row in conftest._mock_session._objects.items()
        if model is AuditEvent and row.object_id == stored["id"]
    )
    assert audit_event.details["cloud_processing_acknowledged"] is False


async def test_remote_assistance_persists_cloud_acknowledgement(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "threat_hunting_ai_cloud_enabled", True)
    monkeypatch.setattr(settings, "openai_api_key", "configured-test-key")
    monkeypatch.setattr(settings, "openai_model", "test-openai-model")
    _fake_provider(monkeypatch, ASSIST_OUTPUT)
    created = await client.post("/api/threat-hunting/hunts", json=HUNT)
    assert created.status_code == 201

    response = await client.post("/api/threat-hunting/ai/assist", json={
        "provider": "openai",
        "stage": "plan",
        "hunt_id": created.json()["id"],
        "context": HUNT,
        "cloud_processing_acknowledged": True,
    })
    assert response.status_code == 200, response.text

    history = await client.get("/api/threat-hunting/ai/history")
    assert history.status_code == 200
    stored = history.json()[0]
    assert stored["provider"] == "openai"
    assert stored["cloud_processing_acknowledged"] is True
    audit_event = next(
        row for (model, _), row in conftest._mock_session._objects.items()
        if model is AuditEvent and row.object_id == stored["id"]
    )
    assert audit_event.details["cloud_processing_acknowledged"] is True


async def test_saved_hunt_assistance_does_not_mutate_hunt(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    _fake_provider(monkeypatch, ASSIST_OUTPUT)
    created = await client.post("/api/threat-hunting/hunts", json=HUNT)
    assert created.status_code == 201
    hunt = created.json()

    response = await client.post("/api/threat-hunting/ai/assist", json={
        "provider": "local",
        "stage": "plan",
        "hunt_id": hunt["id"],
        "context": {**HUNT, "title": "Unsaved analyst title"},
        "cloud_processing_acknowledged": False,
    })
    assert response.status_code == 200, response.text

    unchanged = await client.get(f"/api/threat-hunting/hunts/{hunt['id']}")
    assert unchanged.status_code == 200
    assert unchanged.json()["title"] == HUNT["title"]
    assert unchanged.json()["hypothesis"] == HUNT["hypothesis"]
    assert unchanged.json()["query_versions"][0]["version"] == 1


async def test_hypotheses_use_stored_source_and_bind_exact_evidence(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    _fake_provider(monkeypatch, HYPOTHESIS_OUTPUT)
    session_id = await _store_research(client)
    stored_source = conftest._mock_session._objects[(AnalysisSession, UUID(session_id))]
    stored_source.source_text = f"  \n{stored_source.source_text}\n  "

    response = await client.post("/api/threat-hunting/ai/hypotheses", json={
        "provider": "local",
        "source_session_id": session_id,
        "source_type": "research",
        "source_title": "Forged browser title",
        "source_ref": "https://attacker.invalid/forged",
        "tlp": "TLP:CLEAR",
        "analyst_focus": "Build one endpoint hunt",
        "cloud_processing_acknowledged": False,
    })
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["source_title"] == "Stored PowerShell research"
    assert body["source_ref"] == session_id
    assert body["lifecycle_status"] == "suggested"
    assert body["candidates"][0]["source_evidence"][0]["verified"] is True
    assert any("could not lower the stored report TLP" in warning for warning in body["warnings"])

    history = await client.get("/api/threat-hunting/ai/history", params={"source_session_id": session_id})
    assert history.status_code == 200
    assert history.json()[0]["effective_tlp"] == "TLP:AMBER+STRICT"
    assert "The report states" not in json.dumps(history.json()[0])


async def test_stored_report_tlp_cannot_be_lowered_at_cloud_egress(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "threat_hunting_ai_cloud_enabled", True)
    monkeypatch.setattr(settings, "openai_api_key", "configured-test-key")
    _fake_provider(monkeypatch, HYPOTHESIS_OUTPUT)
    session_id = await _store_research(client)

    blocked = await client.post("/api/threat-hunting/ai/hypotheses", json={
        "provider": "openai",
        "source_session_id": session_id,
        "source_type": "research",
        "tlp": "TLP:CLEAR",
        "cloud_processing_acknowledged": True,
    })
    assert blocked.status_code == 403
    assert "TLP:AMBER+STRICT" in blocked.text

    # Classification changes are restricted to the manage-intel report-edit
    # path. Mutate the in-memory test store to represent that committed update;
    # the mock query engine does not model joined PATCH lookups.
    stored = conftest._mock_session._objects[(AnalysisSession, UUID(session_id))]
    stored.tlp = "TLP:CLEAR"

    allowed = await client.post("/api/threat-hunting/ai/hypotheses", json={
        "provider": "openai",
        "source_session_id": session_id,
        "source_type": "research",
        "tlp": "TLP:CLEAR",
        "cloud_processing_acknowledged": True,
    })
    assert allowed.status_code == 200, allowed.text
    history = await client.get(
        "/api/threat-hunting/ai/history",
        params={"source_session_id": session_id},
    )
    assert history.json()[0]["effective_tlp"] == "TLP:CLEAR"


async def test_hypotheses_reject_raw_source_and_non_enterprise_session(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    _fake_provider(monkeypatch, HYPOTHESIS_OUTPUT)
    session_id = await _store_research(client, domain="atlas")

    raw_source = await client.post("/api/threat-hunting/ai/hypotheses", json={
        "provider": "local",
        "source_session_id": session_id,
        "source_type": "research",
        "tlp": "TLP:AMBER",
        "source_text": "browser-controlled raw report",
        "cloud_processing_acknowledged": False,
    })
    assert raw_source.status_code == 422

    unsupported = await client.post("/api/threat-hunting/ai/hypotheses", json={
        "provider": "local",
        "source_session_id": session_id,
        "source_type": "research",
        "tlp": "TLP:AMBER",
        "cloud_processing_acknowledged": False,
    })
    assert unsupported.status_code == 422
    assert "Enterprise ATT&CK" in unsupported.text


async def test_cloud_policy_uses_maximum_finding_tlp(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "threat_hunting_ai_cloud_enabled", True)
    monkeypatch.setattr(settings, "openai_api_key", "configured-test-key")
    _fake_provider(monkeypatch, ASSIST_OUTPUT)
    created = await client.post("/api/threat-hunting/hunts", json=HUNT)
    hunt_id = created.json()["id"]
    finding = await client.post(f"/api/threat-hunting/hunts/{hunt_id}/findings", json={
        "title": "Restricted evidence",
        "summary": "Sensitive reviewed evidence",
        "tlp": "TLP:RED",
    })
    assert finding.status_code == 201

    response = await client.post("/api/threat-hunting/ai/assist", json={
        "provider": "openai",
        "stage": "findings",
        "hunt_id": hunt_id,
        "context": HUNT,
        "cloud_processing_acknowledged": True,
    })
    assert response.status_code == 403
    assert "TLP:RED" in response.text


async def test_cloud_policy_honors_stricter_unsaved_draft_tlp(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "threat_hunting_ai_cloud_enabled", True)
    monkeypatch.setattr(settings, "openai_api_key", "configured-test-key")
    _fake_provider(monkeypatch, ASSIST_OUTPUT)
    created = await client.post("/api/threat-hunting/hunts", json=HUNT)
    hunt_id = created.json()["id"]

    response = await client.post("/api/threat-hunting/ai/assist", json={
        "provider": "openai",
        "stage": "query",
        "hunt_id": hunt_id,
        "context": {**HUNT, "tlp": "TLP:RED"},
        "cloud_processing_acknowledged": True,
    })

    assert response.status_code == 403
    assert "TLP:RED" in response.text


async def test_model_override_and_non_plan_unsaved_context_are_rejected(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    _fake_provider(monkeypatch, ASSIST_OUTPUT)
    override = await client.post("/api/threat-hunting/ai/assist", json={
        "provider": "local",
        "model": "attacker-selected-model",
        "stage": "plan",
        "context": HUNT,
        "cloud_processing_acknowledged": False,
    })
    assert override.status_code == 422

    wrong_stage = await client.post("/api/threat-hunting/ai/assist", json={
        "provider": "local",
        "stage": "outcome",
        "context": HUNT,
        "cloud_processing_acknowledged": False,
    })
    assert wrong_stage.status_code == 422


async def test_ai_routes_require_analyst_role(
    app,
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    async def viewer_user():
        return TeamUser(name="viewer", roles=["viewer"], permissions=["read"])

    monkeypatch.setattr(settings, "auth_enabled", True)
    app.dependency_overrides[current_user] = viewer_user
    try:
        providers = await client.get("/api/threat-hunting/ai/providers")
        assert providers.status_code == 403
        assist = await client.post("/api/threat-hunting/ai/assist", json={
            "provider": "local",
            "stage": "plan",
            "context": HUNT,
            "cloud_processing_acknowledged": False,
        })
        assert assist.status_code == 403
        hypotheses = await client.post("/api/threat-hunting/ai/hypotheses", json={
            "provider": "local",
            "source_session_id": str(uuid4()),
            "source_type": "research",
            "tlp": "TLP:AMBER",
            "cloud_processing_acknowledged": False,
        })
        assert hypotheses.status_code == 403
        history = await client.get("/api/threat-hunting/ai/history")
        assert history.status_code == 403
    finally:
        app.dependency_overrides.pop(current_user, None)


async def test_ai_assistance_rate_limit_returns_429(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    _fake_provider(monkeypatch, ASSIST_OUTPUT)
    payload = {
        "provider": "local",
        "stage": "plan",
        "context": HUNT,
        "cloud_processing_acknowledged": False,
    }

    responses = [await client.post("/api/threat-hunting/ai/assist", json=payload) for _ in range(7)]

    assert [response.status_code for response in responses[:6]] == [200] * 6
    assert responses[6].status_code == 429
    assert responses[6].headers["Retry-After"]


async def test_hypothesis_generation_rejects_source_metadata_changed_during_provider_call(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    session_id = await _store_research(client)
    stored = conftest._mock_session._objects[(AnalysisSession, UUID(session_id))]

    class _MutatingSourceAdapter(_FakeAdapter):
        async def _raw_complete(self, system: str, user: str) -> str:
            stored.name = "Renamed while the provider was running"
            return await super()._raw_complete(system, user)

    monkeypatch.setattr(
        hunt_ai,
        "get_adapter",
        lambda provider, model=None: _MutatingSourceAdapter(provider, model or "test-local-model", HYPOTHESIS_OUTPUT),
    )
    response = await client.post("/api/threat-hunting/ai/hypotheses", json={
        "provider": "local",
        "source_session_id": session_id,
        "source_type": "research",
        "tlp": "TLP:AMBER",
        "cloud_processing_acknowledged": False,
    })

    assert response.status_code == 409
    assert "changed" in response.text
    history = await client.get("/api/threat-hunting/ai/history")
    assert history.json() == []


async def test_saved_hunt_assistance_rejects_stale_canonical_context(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    created = await client.post("/api/threat-hunting/hunts", json=HUNT)
    hunt_id = UUID(created.json()["id"])
    stored = conftest._mock_session._objects[(ThreatHuntRequest, hunt_id)]

    class _MutatingHuntAdapter(_FakeAdapter):
        async def _raw_complete(self, system: str, user: str) -> str:
            stored.description = "Changed concurrently while the provider was running."
            return await super()._raw_complete(system, user)

    monkeypatch.setattr(
        hunt_ai,
        "get_adapter",
        lambda provider, model=None: _MutatingHuntAdapter(provider, model or "test-local-model", ASSIST_OUTPUT),
    )
    response = await client.post("/api/threat-hunting/ai/assist", json={
        "provider": "local",
        "stage": "plan",
        "hunt_id": str(hunt_id),
        "context": HUNT,
        "cloud_processing_acknowledged": False,
    })

    assert response.status_code == 409
    assert "changed" in response.text
    history = await client.get("/api/threat-hunting/ai/history")
    assert history.json() == []


async def test_provider_failure_is_sanitized_and_not_persisted(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    class _FailingAdapter(_FakeAdapter):
        async def _raw_complete(self, system: str, user: str) -> str:
            raise RuntimeError("secret provider payload and credential detail")

    monkeypatch.setattr(
        hunt_ai,
        "get_adapter",
        lambda provider, model=None: _FailingAdapter(provider, model or "test-local-model", ""),
    )
    response = await client.post("/api/threat-hunting/ai/assist", json={
        "provider": "local",
        "stage": "plan",
        "context": HUNT,
        "cloud_processing_acknowledged": False,
    })

    assert response.status_code == 502
    assert "secret provider payload" not in response.text
    history = await client.get("/api/threat-hunting/ai/history")
    assert history.json() == []
