from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import httpx
import pytest
from fastapi import HTTPException

from app.core.config import settings
from app.api.routes.threat_hunting_ai import _canonical_hunt_context, _hunt_context_warnings, _safe_source_ref
from app.services import threat_hunting_ai as ai


def _assist_payload(*, patch: dict | None = None, citations: list[dict] | None = None) -> str:
    return json.dumps({
        "summary": "Review the proposed hunt improvements.",
        "recommended_actions": ["Validate telemetry coverage"],
        "questions": [],
        "evidence_gaps": [],
        "cautions": [],
        "suggested_patch": patch or {},
        "finding_drafts": [],
        "citations": citations or [],
    })


def test_strict_parser_rejects_model_attempt_to_set_lifecycle_state():
    raw = _assist_payload(patch={"status": "completed", "disposition": "confirmed_malicious"})

    with pytest.raises(ai.AIOutputError):
        ai.parse_assist_output(raw)


@pytest.mark.parametrize("raw", [
    "Here is the requested JSON:\n" + _assist_payload(),
    _assist_payload() + "\nThis suggestion requires analyst review.",
])
def test_strict_parser_rejects_prose_outside_json(raw: str):
    with pytest.raises(ai.AIOutputError, match="outside the JSON object"):
        ai.parse_assist_output(raw)


def test_citations_ignore_provider_offsets_bind_exact_slice_and_drop_fabrication():
    parsed = ai.parse_assist_output(_assist_payload(citations=[{
        "source_type": "report",
        "source_ref": "report-1",
        "quote": "PowerShell spawned from Excel",
        "start": 0,
        "end": 3,
    }, {
        "source_type": "report",
        "source_ref": "report-1",
        "quote": "fabricated excerpt",
        "start": 10,
        "end": 28,
    }]))
    source = ai.CitationSource(
        source_type="report",
        source_ref="report-1",
        source_session_id=uuid4(),
        text="Observed PowerShell spawned from Excel during execution.",
    )

    citations = ai.bind_citations(parsed.citations, [source])

    assert citations[0]["verified"] is True
    assert citations[0]["start"] == 9
    assert citations[0]["end"] == 38
    assert len(citations) == 1


@pytest.mark.asyncio
async def test_query_stage_removes_destructive_query_text():
    parsed = ai.parse_assist_output(_assist_payload(patch={
        "query_language": "sql",
        "query_text": "DELETE FROM security_events WHERE event_time < now()",
        "expected_evidence": "Matching process events",
    }))

    output, warnings = await ai.sanitize_assist_output(
        parsed,
        stage="query",
        effective_tlp="TLP:AMBER",
        source_texts=[],
        db=None,  # No technique lookup is needed for this payload.
    )

    assert "query_text" not in output["suggested_patch"]
    assert output["suggested_patch"]["expected_evidence"] == "Matching process events"
    assert any("destructive" in warning for warning in warnings)


@pytest.mark.asyncio
async def test_query_stage_requires_provider_output_to_match_selected_language():
    parsed = ai.parse_assist_output(_assist_payload(patch={
        "query_language": "kql",
        "query_text": "DeviceProcessEvents | where FileName =~ \"powershell.exe\"",
        "required_fields": ["FileName"],
    }))

    output, warnings = await ai.sanitize_assist_output(
        parsed,
        stage="query",
        effective_tlp="TLP:AMBER",
        source_texts=[],
        target_query_language="spl",
        db=None,
    )

    assert "query_language" not in output["suggested_patch"]
    assert "query_text" not in output["suggested_patch"]
    assert output["suggested_patch"]["required_fields"] == ["FileName"]
    assert any("instead of the requested spl query" in warning for warning in warnings)


def test_query_prompt_binds_hypothesis_to_explicit_target_language():
    system, user = ai.assist_prompt(
        "query",
        {"canonical": {"hypothesis": "Encoded PowerShell should appear in process telemetry"}},
        "Use endpoint data",
        target_query_language="spl",
    )

    assert "target query language identifier is `spl` (Splunk SPL)" in system
    assert "suggested_patch.query_language to exactly `spl`" in system
    assert '"target_query_language":"spl"' in user
    assert "hypothesis" in user


def test_query_prompt_defines_yaral_as_google_secops_udm_rule():
    system, user = ai.assist_prompt(
        "query",
        {"canonical": {"hypothesis": "Encoded PowerShell should appear in UDM process events"}},
        "Use Google SecOps",
        target_query_language="yaral",
    )

    assert "identifier is `yaral` (YARA-L 2.0 for Google SecOps UDM)" in system
    assert "complete YARA-L 2.0 rule" in system
    assert "Unified Data Model (UDM)" in system
    assert '"target_query_language":"yaral"' in user


@pytest.mark.asyncio
async def test_hypothesis_screen_removes_destructive_candidate_query():
    raw = json.dumps({
        "candidates": [{
            "title": "Suspicious PowerShell execution",
            "hypothesis": "If an attacker uses PowerShell, process telemetry will show encoded commands.",
            "query_text": "Invoke-Command -ComputerName production-host -ScriptBlock { Remove-Item C:\\data }",
            "rationale": "The report describes PowerShell execution.",
            "source_evidence": [],
        }],
        "warnings": [],
    })
    parsed = ai.parse_hypothesis_output(raw)

    candidates, warnings = await ai.sanitize_hypothesis_output(
        parsed,
        count=1,
        domain="enterprise-attack",
        source=ai.CitationSource("report", "report-1", "The report describes PowerShell execution."),
        db=None,
    )

    assert candidates[0]["query_text"] == ""
    assert any("destructive" in warning for warning in warnings)


def test_model_override_is_rejected(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "threat_hunting_ai_enabled", True)
    monkeypatch.setattr(settings, "local_llm_base_url", "http://local-llm.test/v1")

    with pytest.raises(HTTPException) as exc:
        ai.create_adapter(
            "local",
            "unapproved-model",
            effective_tlp="TLP:AMBER",
            cloud_processing_acknowledged=False,
        )

    assert exc.value.status_code == 422
    assert "override" in str(exc.value.detail).lower()


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("http://127.0.0.1:11434/v1", True),
        ("http://ollama:11434/v1", True),
        ("http://ollama.default.svc:11434/v1", True),
        ("http://local-llm.test/v1", True),
        ("https://api.example.com/v1", False),
        ("http://8.8.8.8/v1", False),
        ("http://user:secret@127.0.0.1/v1", False),
    ],
)
def test_local_ai_endpoint_must_be_a_private_origin(url: str, expected: bool):
    assert ai.local_ai_endpoint_is_private(url) is expected


def test_local_provider_rejects_public_endpoint_label(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "threat_hunting_ai_enabled", True)
    monkeypatch.setattr(settings, "local_llm_base_url", "https://api.example.com/v1")

    with pytest.raises(HTTPException) as exc:
        ai.create_adapter(
            "local",
            None,
            effective_tlp="TLP:AMBER+STRICT",
            cloud_processing_acknowledged=False,
        )

    assert exc.value.status_code == 503
    assert "private" in str(exc.value.detail).lower()


def test_remote_provider_requires_policy_acknowledgement_and_permitted_tlp(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "threat_hunting_ai_enabled", True)
    monkeypatch.setattr(settings, "openai_api_key", "configured-test-key")
    adapter = SimpleNamespace(provider="openai", model=settings.openai_model)
    factory = MagicMock(return_value=adapter)
    monkeypatch.setattr(ai, "get_adapter", factory)

    monkeypatch.setattr(settings, "threat_hunting_ai_cloud_enabled", False)
    with pytest.raises(HTTPException) as cloud_disabled:
        ai.create_adapter(
            "openai",
            None,
            effective_tlp="TLP:AMBER",
            cloud_processing_acknowledged=True,
        )
    assert cloud_disabled.value.status_code == 403
    assert "disabled" in str(cloud_disabled.value.detail).lower()

    monkeypatch.setattr(settings, "threat_hunting_ai_cloud_enabled", True)
    with pytest.raises(HTTPException) as acknowledgement_required:
        ai.create_adapter(
            "openai",
            None,
            effective_tlp="TLP:AMBER",
            cloud_processing_acknowledged=False,
        )
    assert acknowledgement_required.value.status_code == 422
    assert "acknowledgement" in str(acknowledgement_required.value.detail).lower()

    with pytest.raises(HTTPException) as restricted_tlp:
        ai.create_adapter(
            "openai",
            None,
            effective_tlp="TLP:RED",
            cloud_processing_acknowledged=True,
        )
    assert restricted_tlp.value.status_code == 403
    assert "TLP:RED" in str(restricted_tlp.value.detail)

    created = ai.create_adapter(
        "openai",
        None,
        effective_tlp="TLP:AMBER",
        cloud_processing_acknowledged=True,
    )
    assert created is adapter
    factory.assert_called_once_with("openai", settings.openai_model)


def test_remote_provider_catalog_separates_configuration_from_cloud_policy(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "threat_hunting_ai_enabled", True)
    monkeypatch.setattr(settings, "threat_hunting_ai_cloud_enabled", False)
    monkeypatch.setattr(settings, "threat_hunting_ai_default_provider", "openai")
    monkeypatch.setattr(settings, "openai_api_key", "configured-but-disabled")

    catalog = ai.provider_catalog()
    openai = next(row for row in catalog if row["id"] == "openai")
    local = next(row for row in catalog if row["id"] == "local")

    assert openai["configured"] is True
    assert openai["available"] is False
    assert openai["status"] == "disabled_by_policy"
    assert openai["default"] is False
    assert local["default"] is True
    assert "disabled" in openai["reason"].lower()


def test_remote_provider_catalog_reports_missing_credential(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "threat_hunting_ai_enabled", True)
    monkeypatch.setattr(settings, "threat_hunting_ai_cloud_enabled", True)
    monkeypatch.setattr(settings, "openai_api_key", "")

    openai = next(row for row in ai.provider_catalog() if row["id"] == "openai")

    assert openai["configured"] is False
    assert openai["available"] is False
    assert openai["status"] == "missing_credential"
    assert openai["reason"] == "Configure OPENAI_API_KEY to use this provider."


def test_remote_provider_catalog_reports_configuration_without_network_probe(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "threat_hunting_ai_enabled", True)
    monkeypatch.setattr(settings, "threat_hunting_ai_cloud_enabled", True)
    monkeypatch.setattr(settings, "threat_hunting_ai_default_provider", "openai")
    monkeypatch.setattr(settings, "openai_api_key", "configured")

    openai = next(row for row in ai.provider_catalog() if row["id"] == "openai")

    assert openai["configured"] is True
    assert openai["available"] is True
    assert openai["status"] == "configured_and_permitted"
    assert "checked when a request runs" in openai["reason"]
    assert openai["default"] is True


def test_configured_provider_is_unavailable_when_threat_hunting_ai_is_disabled(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "threat_hunting_ai_enabled", False)
    monkeypatch.setattr(settings, "threat_hunting_ai_cloud_enabled", True)
    monkeypatch.setattr(settings, "openai_api_key", "configured")

    openai = next(row for row in ai.provider_catalog() if row["id"] == "openai")

    assert openai["configured"] is True
    assert openai["available"] is False
    assert openai["status"] == "disabled_by_policy"
    assert openai["reason"] == "Threat Hunting AI is disabled by the operator."


@pytest.mark.asyncio
async def test_local_provider_probe_reports_unreachable_without_leaking_error(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "local_llm_base_url", "http://local-llm.test/v1")
    monkeypatch.setattr(settings, "local_llm_api_key", "super-secret-local-key")

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("secret upstream network detail", request=request)

    readiness = await ai.probe_local_provider_readiness(transport=httpx.MockTransport(handler))

    assert readiness.status == "unreachable"
    assert readiness.available is False
    assert "secret" not in readiness.reason


@pytest.mark.asyncio
async def test_local_provider_probe_reports_model_missing(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "local_llm_base_url", "http://local-llm.test/v1")
    monkeypatch.setattr(settings, "local_llm_model", "configured-model")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == httpx.URL("http://local-llm.test/v1/models")
        return httpx.Response(200, json={"object": "list", "data": [{"id": "different-model"}]})

    readiness = await ai.probe_local_provider_readiness(transport=httpx.MockTransport(handler))

    assert readiness.status == "model_missing"
    assert readiness.available is False


@pytest.mark.asyncio
async def test_local_provider_probe_reports_auth_error(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "local_llm_base_url", "http://local-llm.test/v1")
    monkeypatch.setattr(settings, "local_llm_api_key", "super-secret-local-key")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer super-secret-local-key"
        return httpx.Response(401, text="credential detail that must not be returned")

    readiness = await ai.probe_local_provider_readiness(transport=httpx.MockTransport(handler))

    assert readiness.status == "auth_error"
    assert readiness.available is False
    assert "credential detail" not in readiness.reason
    assert "super-secret" not in readiness.reason


@pytest.mark.asyncio
async def test_local_provider_probe_reports_ready_and_does_not_follow_redirects(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "local_llm_base_url", "http://local-llm.test/v1")
    monkeypatch.setattr(settings, "local_llm_model", "configured-model")
    requests: list[httpx.Request] = []

    def ready_handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"object": "list", "data": [{"id": "configured-model"}]})

    readiness = await ai.probe_local_provider_readiness(transport=httpx.MockTransport(ready_handler))

    assert readiness.status == "ready"
    assert readiness.available is True
    assert len(requests) == 1

    def redirect_handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(302, headers={"location": "https://public.example/models"})

    readiness = await ai.probe_local_provider_readiness(transport=httpx.MockTransport(redirect_handler))

    assert readiness.status == "endpoint_error"
    assert len(requests) == 2


@pytest.mark.asyncio
async def test_catalog_overlays_local_runtime_readiness_and_reassigns_default(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "threat_hunting_ai_enabled", True)
    monkeypatch.setattr(settings, "threat_hunting_ai_cloud_enabled", True)
    monkeypatch.setattr(settings, "threat_hunting_ai_default_provider", "local")
    monkeypatch.setattr(settings, "local_llm_base_url", "http://local-llm.test/v1")
    monkeypatch.setattr(settings, "anthropic_api_key", "")
    monkeypatch.setattr(settings, "openai_api_key", "configured")
    monkeypatch.setattr(settings, "gemini_api_key", "")
    monkeypatch.setattr(settings, "minimax_api_key", "")
    probe = AsyncMock(return_value=ai.LocalProviderReadiness("unreachable", "Safe unavailable reason."))
    monkeypatch.setattr(ai, "probe_local_provider_readiness", probe)

    catalog = await ai.provider_catalog_with_readiness()
    local = next(row for row in catalog if row["id"] == "local")
    openai = next(row for row in catalog if row["id"] == "openai")

    assert local["configured"] is True
    assert local["available"] is False
    assert local["status"] == "unreachable"
    assert local["reason"] == "Safe unavailable reason."
    assert local["default"] is False
    assert openai["default"] is True
    probe.assert_awaited_once_with()


def test_source_coverage_is_explicit_and_hashes_are_deterministic(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "threat_hunting_ai_source_char_limit", 4_000)
    source = "A" * 4_500

    bounded, warnings = ai.bounded_source_text(source)

    assert len(bounded) == 4_000
    assert "4000 of 4500" in warnings[0]
    assert ai.checksum({"b": 2, "a": 1}) == ai.checksum({"a": 1, "b": 2})


def test_operator_candidate_cap_is_enforced(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "threat_hunting_ai_max_candidates", 1)

    assert ai.candidate_limit(3) == 1


def test_source_ref_redacts_credentials_queries_and_handles_invalid_ports_and_ipv6():
    assert _safe_source_ref("https://user:secret@example.test/report?token=secret#part") == "https://example.test/report"
    assert _safe_source_ref("https://example.test:not-a-port/report?token=secret") == "https://example.test/report"
    assert _safe_source_ref("https://[2001:db8::1]:8443/report?token=secret") == "https://[2001:db8::1]:8443/report"
    assert _safe_source_ref("https://user:secret@[broken?token=secret#part") == "invalid-source-ref"
    assert _safe_source_ref("C:\\Users\\analyst\\Desktop\\report.pdf\x00") == "report.pdf"
    assert _safe_source_ref("/home/analyst/research/report.txt") == "report.txt"
    assert _safe_source_ref("/home/analyst/research/report.txt?token=secret#part") == "report.txt"


def test_canonical_context_reports_every_truncation_boundary():
    hunt = SimpleNamespace(
        id=uuid4(), title="Title", hypothesis="Hypothesis", description="", scope="Scope", status="running",
        priority="P2 Medium", technique_ids=[], tactics=[], telemetry_sources=[], required_fields=[], query_language="kql",
        query_text="q" * 12_001, expected_evidence="Expected", false_positive_notes="Benign", assumptions="Assumption",
        result_summary="", disposition="undetermined", tlp="TLP:AMBER", updated_at=None,
    )
    versions = [
        SimpleNamespace(
            id=uuid4(), version=index + 1, language="kql", query_text="q" * 6_001,
            backend_assumptions="a" * 4_001, checksum=str(index),
        )
        for index in range(6)
    ]
    findings = [
        SimpleNamespace(
            id=uuid4(), title="Finding", summary="s" * 3_001, severity="medium", confidence=50,
            status="new", verdict="inconclusive", tlp="TLP:AMBER", technique_ids=[], notes="n" * 2_001,
            query_version_id=None,
        )
        for _ in range(51)
    ]

    context = _canonical_hunt_context(hunt, findings, versions)
    warnings = _hunt_context_warnings(hunt, findings, versions)

    assert context["coverage"] == {
        "query_versions_total": 6,
        "query_versions_included": 5,
        "findings_total": 51,
        "findings_included": 50,
    }
    assert len(warnings) == 7
