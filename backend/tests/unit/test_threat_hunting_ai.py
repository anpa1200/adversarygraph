from __future__ import annotations

import json
from types import SimpleNamespace
from uuid import uuid4

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


def test_remote_provider_catalog_is_not_usable_when_cloud_is_disabled(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "threat_hunting_ai_enabled", True)
    monkeypatch.setattr(settings, "threat_hunting_ai_cloud_enabled", False)
    monkeypatch.setattr(settings, "threat_hunting_ai_default_provider", "openai")
    monkeypatch.setattr(settings, "openai_api_key", "configured-but-disabled")

    catalog = ai.provider_catalog()
    openai = next(row for row in catalog if row["id"] == "openai")
    local = next(row for row in catalog if row["id"] == "local")

    assert openai["configured"] is False
    assert openai["default"] is False
    assert local["default"] is True
    assert "disabled" in openai["reason"].lower()


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
