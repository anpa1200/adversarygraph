from uuid import uuid4

from app.api.routes.analyze import (
    LinkedReportEntity,
    _dedupe_entities,
    _extract_cve_ids,
    _fallback_report_text,
)
from app.models.analysis import AnalysisResult, AnalysisSession


def test_extract_cve_ids_normalizes_and_deduplicates():
    values = _extract_cve_ids(
        "Observed CVE-2024-3094 and cve-2024-3094 in the report.",
        "Follow-on exploitation references CVE-2023-3519.",
    )

    assert values == ["CVE-2024-3094", "CVE-2023-3519"]


def test_dedupe_entities_keeps_first_entity_per_type_and_value():
    entities = _dedupe_entities(
        [
            LinkedReportEntity(type="cve", id="CVE-2024-3094", label="CVE-2024-3094", value="CVE-2024-3094"),
            LinkedReportEntity(type="cve", id="duplicate", label="duplicate", value="cve-2024-3094"),
            LinkedReportEntity(type="ioc", id="1.2.3.4", label="1.2.3.4", value="1.2.3.4"),
        ],
        limit=10,
    )

    assert [(item.type, item.value) for item in entities] == [
        ("cve", "CVE-2024-3094"),
        ("ioc", "1.2.3.4"),
    ]


def test_fallback_report_text_exposes_summary_and_techniques_for_old_sessions():
    session_id = uuid4()
    session = AnalysisSession(
        id=session_id,
        status="completed",
        name="Legacy report",
        input_type="text",
        filename=None,
        llm_provider="local",
        model="qwen",
        domain="enterprise-attack",
    )
    result = AnalysisResult(
        session_id=session_id,
        extracted_techniques=[{"attack_id": "T1059.001", "name": "PowerShell", "evidence": "PowerShell execution"}],
        apt_matches=[{"group_attack_id": "G0069", "group_name": "MuddyWater"}],
        summary="Actor used PowerShell and infrastructure overlap.",
        raw_response="",
    )

    text = _fallback_report_text(session, result, None)

    assert "Legacy report" in text
    assert "Actor used PowerShell" in text
    assert "T1059.001 PowerShell" in text
    assert "G0069 MuddyWater" in text
