import copy
import hashlib
from datetime import datetime, timezone
from uuid import uuid4

from app.models.analysis import AnalysisSession
from app.services.report_review import _source_metadata
from app.services.report_review_preflight import (
    GATE_KEYS,
    PREFLIGHT_EVALUATOR,
    evaluate_report_preflight,
    merge_ai_advisory,
)


def _span(source: str, quote: str) -> tuple[int, int]:
    start = source.index(quote)
    return start, start + len(quote)


def _complete_metadata(
    *,
    publication_date: str = "2025-05-04",
    source_text: str | None = None,
) -> dict:
    value = {
        "source_kind": "url-report",
        "source_url": "https://reports.example.test/advisory/42?tracking=secret",
        "metadata": {
            "retrieved_url": "https://reports.example.test/advisory/42?tracking=secret",
            "http_status": 200,
            "content_sha256": "a" * 64,
            "retrieved_at": "2025-05-05T10:30:00+00:00",
            "publication_date_candidates": [
                {
                    "value": publication_date,
                    "source": "meta:article:published_time",
                }
            ],
        },
    }
    if source_text is not None:
        value["metadata"]["extracted_text_sha256"] = hashlib.sha256(
            source_text.encode()
        ).hexdigest()
    return value


def _source_and_claims() -> tuple[str, list[dict]]:
    source = (
        "Published 4 May 2025.\n"
        "MuddyWater downloaded a payload from its staging server and wrote it to C:\\ProgramData\\update.exe.\n"
        "The report explicitly attributes this activity to MuddyWater."
    )
    procedure_quote = "MuddyWater downloaded a payload from its staging server and wrote it to C:\\ProgramData\\update.exe."
    actor_quote = "The report explicitly attributes this activity to MuddyWater."
    procedure_start, procedure_end = _span(source, procedure_quote)
    actor_start, actor_end = _span(source, actor_quote)
    return source, [
        {
            "claim_key": "procedure-1",
            "claim_type": "procedure",
            "subject": "MuddyWater",
            "predicate": "downloaded",
            "object": "payload from its staging server",
            "attack_id": "T1105",
            "evidence_text": procedure_quote,
            "evidence_start": procedure_start,
            "evidence_end": procedure_end,
        },
        {
            "claim_key": "actor-1",
            "claim_type": "actor",
            "subject": "MuddyWater",
            "basis": "explicit",
            "evidence_text": actor_quote,
            "evidence_start": actor_start,
            "evidence_end": actor_end,
        },
    ]


def test_preflight_passes_complete_source_bound_report():
    source, claims = _source_and_claims()

    result = evaluate_report_preflight(
        source,
        _complete_metadata(source_text=source),
        claims,
        {"analyzed_char_count": len(source)},
    )

    assert tuple(result) == GATE_KEYS
    assert {gate["machine_verdict"] for gate in result.values()} == {"pass"}
    for gate in result.values():
        assert gate["evaluator"] == PREFLIGHT_EVALUATOR
        assert gate["details"]["policy_version"] == "report-review-preflight-v1"
        assert isinstance(gate["details"]["facts"], list)
        assert isinstance(gate["evidence_refs"], list)

    # URL query parameters are not copied into evidence/audit output.
    source_refs = result["source_provenance"]["evidence_refs"]
    assert all("tracking=secret" not in str(ref) for ref in source_refs)


def test_preflight_is_reproducible_and_does_not_mutate_inputs():
    source, claims = _source_and_claims()
    metadata = _complete_metadata()
    context = {"analyzed_ranges": [[0, len(source)]]}
    original = copy.deepcopy((metadata, claims, context))

    first = evaluate_report_preflight(source, metadata, claims, context)
    second = evaluate_report_preflight(source, metadata, claims, context)

    assert first == second
    assert (metadata, claims, context) == original


def test_url_without_stored_retrieval_receipt_is_warning_not_network_verified():
    source = "A locally stored report body."

    result = evaluate_report_preflight(
        source,
        {"source_kind": "url-report", "source_url": "https://example.test/report"},
        [],
        {"analyzed_char_count": len(source)},
    )

    gate = result["source_provenance"]
    assert gate["machine_verdict"] == "warning"
    fact_codes = {fact["code"] for fact in gate["details"]["facts"]}
    assert "retrieval_http_status_missing" in fact_codes
    assert "retrieved_content_checksum_missing" in fact_codes
    assert "retrieval_time_missing_or_invalid" in fact_codes


def test_uploaded_file_passes_only_with_point_in_time_acquisition_receipt():
    source = "Original uploaded incident report text."
    result = evaluate_report_preflight(
        source,
        {
            "input_type": "file",
            "filename": "incident-report.pdf",
            "acquisition_text_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "acquisition_content_sha256": "c" * 64,
            "acquired_at": "2025-05-05T10:30:00+00:00",
            "acquisition_superseded": False,
        },
        [],
        # The current checksum is deliberately present: it must not substitute
        # for the immutable acquisition digest above.
        {"source_text_sha256": hashlib.sha256(source.encode()).hexdigest()},
    )

    gate = result["source_provenance"]
    assert gate["machine_verdict"] == "pass"
    facts = {fact["code"] for fact in gate["details"]["facts"]}
    assert "uploaded_text_checksum_match" in facts
    assert "uploaded_content_fingerprinted" in facts


def test_uploaded_file_replacement_fails_even_with_current_text_checksum():
    original = "Original uploaded incident report text."
    replacement = "Replacement content with unrelated claims."
    result = evaluate_report_preflight(
        replacement,
        {
            "input_type": "file",
            "filename": "incident-report.pdf",
            "acquisition_text_sha256": hashlib.sha256(original.encode()).hexdigest(),
            "acquisition_content_sha256": "c" * 64,
            "acquired_at": "2025-05-05T10:30:00+00:00",
        },
        [],
        {"source_text_sha256": hashlib.sha256(replacement.encode()).hexdigest()},
    )

    gate = result["source_provenance"]
    assert gate["machine_verdict"] == "fail"
    assert "uploaded_text_checksum_mismatch" in {
        fact["code"] for fact in gate["details"]["facts"]
    }


def test_uploaded_file_superseded_receipt_fails_closed():
    source = "Original uploaded incident report text."
    result = evaluate_report_preflight(
        source,
        {
            "input_type": "file",
            "filename": "incident-report.pdf",
            "acquisition_text_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "acquisition_content_sha256": "c" * 64,
            "acquired_at": "2025-05-05T10:30:00+00:00",
            "acquisition_superseded": True,
        },
        [],
        {"source_text_sha256": hashlib.sha256(source.encode()).hexdigest()},
    )

    gate = result["source_provenance"]
    assert gate["machine_verdict"] == "fail"
    assert "file_acquisition_superseded" in {
        fact["code"] for fact in gate["details"]["facts"]
    }


def test_legacy_uploaded_file_without_acquisition_receipt_does_not_machine_pass():
    source = "Legacy uploaded report text."
    result = evaluate_report_preflight(
        source,
        {"input_type": "file", "filename": "legacy.pdf"},
        [],
        {"source_text_sha256": hashlib.sha256(source.encode()).hexdigest()},
    )

    gate = result["source_provenance"]
    assert gate["machine_verdict"] == "warning"
    assert "uploaded_text_checksum_missing_or_invalid" in {
        fact["code"] for fact in gate["details"]["facts"]
    }


def test_analysis_session_acquisition_receipt_reaches_file_preflight():
    source = "Bound uploaded report text."
    session = AnalysisSession(
        id=uuid4(),
        status="completed",
        name="Bound report",
        input_type="file",
        filename="bound-report.pdf",
        llm_provider="local",
        model="test",
        domain="enterprise-attack",
        tlp="TLP:AMBER+STRICT",
        source_text=source,
        source_provenance={
            "source_kind": "file",
            "acquisition": {
                "extracted_text_sha256": hashlib.sha256(source.encode()).hexdigest(),
                "content_sha256": "d" * 64,
                "content_size_bytes": 2048,
                "extracted_text_chars": len(source),
                "acquired_at": "2025-05-05T10:30:00+00:00",
                "superseded": False,
            },
        },
        created_at=datetime(2025, 5, 5, tzinfo=timezone.utc),
    )

    result = evaluate_report_preflight(
        source,
        _source_metadata(session, None),
        [],
        {"source_text_sha256": hashlib.sha256(source.encode()).hexdigest()},
    )

    assert result["source_provenance"]["machine_verdict"] == "pass"


def test_private_or_credentialed_source_url_fails():
    source = "Stored source"
    for url in (
        "http://127.0.0.1/report",
        "http://10.0.0.5/report",
        "https://analyst:secret@example.test/report",
        "file:///tmp/report.txt",
    ):
        result = evaluate_report_preflight(
            source,
            {"source_kind": "url-report", "source_url": url},
            [],
            {"analyzed_char_count": len(source)},
        )
        assert result["source_provenance"]["machine_verdict"] == "fail"


def test_source_text_checksum_mismatch_fails_even_with_successful_fetch_receipt():
    source = "Stored source"
    metadata = _complete_metadata()
    metadata["source_text_sha256"] = "b" * 64

    result = evaluate_report_preflight(
        source,
        metadata,
        [],
        {"analyzed_char_count": len(source)},
    )

    gate = result["source_provenance"]
    assert gate["machine_verdict"] == "fail"
    assert "source_checksum_mismatch" in {fact["code"] for fact in gate["details"]["facts"]}


def test_retrieval_receipt_is_bound_to_final_url_and_stored_text():
    source = "Current stored report text"
    metadata = _complete_metadata(source_text="Original unrelated report text")
    metadata["source_url"] = "https://unrelated.example.test/report"

    result = evaluate_report_preflight(
        source,
        metadata,
        [],
        {"analyzed_char_count": len(source)},
    )

    facts = {fact["code"] for fact in result["source_provenance"]["details"]["facts"]}
    assert result["source_provenance"]["machine_verdict"] == "fail"
    assert "retrieval_url_source_mismatch" in facts
    assert "retrieved_text_checksum_mismatch" in facts


def test_superseded_retrieval_receipt_fails_closed():
    source = "Edited report text"
    metadata = _complete_metadata(source_text=source)
    metadata["metadata"]["superseded"] = True

    result = evaluate_report_preflight(
        source,
        metadata,
        [],
        {"analyzed_char_count": len(source)},
    )

    facts = {fact["code"] for fact in result["source_provenance"]["details"]["facts"]}
    assert result["source_provenance"]["machine_verdict"] == "fail"
    assert "retrieval_receipt_superseded" in facts


def test_raw_source_checksum_has_deterministic_priority_over_review_fingerprint():
    source = "Stored source"
    raw_checksum = hashlib.sha256(source.encode()).hexdigest()

    result = evaluate_report_preflight(
        source,
        _complete_metadata(),
        [],
        {
            "source_text_sha256": raw_checksum,
            "source_checksum": "b" * 64,
            "analyzed_char_count": len(source),
        },
    )

    facts = {fact["code"] for fact in result["source_provenance"]["details"]["facts"]}
    assert "source_checksum_mismatch" not in facts


def test_publication_date_conflict_warns_and_future_date_fails():
    source = "Report"
    conflicting = _complete_metadata()
    conflicting["metadata"]["publication_date_candidates"].append({"value": "2025-05-03", "source": "jsonld:datePublished"})

    conflict_result = evaluate_report_preflight(source, conflicting, [], {"analyzed_char_count": len(source)})
    future_result = evaluate_report_preflight(
        source,
        _complete_metadata(publication_date="2025-05-06"),
        [],
        {"analyzed_char_count": len(source)},
    )

    assert conflict_result["publication_date"]["machine_verdict"] == "warning"
    assert "publication_date_conflict" in {fact["code"] for fact in conflict_result["publication_date"]["details"]["facts"]}
    assert future_result["publication_date"]["machine_verdict"] == "fail"
    assert "publication_after_retrieval" in {fact["code"] for fact in future_result["publication_date"]["details"]["facts"]}


def test_invalid_calendar_date_does_not_pass_publication_gate():
    result = evaluate_report_preflight(
        "Report",
        _complete_metadata(publication_date="2025-02-30"),
        [],
        {"analyzed_char_count": 6},
    )

    gate = result["publication_date"]
    assert gate["machine_verdict"] == "fail"
    assert gate["details"]["metrics"]["valid_candidate_count"] == 0


def test_generic_actor_uses_tool_statement_is_not_procedure_level_claim():
    source = "The actor uses PowerShell."
    start, end = _span(source, source)
    claims = [
        {
            "claim_type": "procedure",
            "attack_id": "T1059.001",
            "evidence": source,
            "evidence_start": start,
            "evidence_end": end,
        }
    ]

    result = evaluate_report_preflight(
        source,
        _complete_metadata(),
        claims,
        {"analyzed_char_count": len(source)},
    )

    assert result["procedure_relevance"]["machine_verdict"] == "pass"
    assert result["procedure_level_claim"]["machine_verdict"] == "fail"
    assert result["procedure_level_claim"]["details"]["metrics"]["generic_bound_count"] == 1


def test_evidence_offsets_must_match_exact_source_text():
    source = "The adversary downloaded payload.bin to the host."
    quote = "downloaded payload.bin"
    start, end = _span(source, quote)
    claim = {
        "claim_type": "procedure",
        "attack_id": "T1105",
        "predicate": "downloaded",
        "object": "payload.bin",
        "evidence_text": quote,
        "evidence_start": start + 1,
        "evidence_end": end + 1,
    }

    result = evaluate_report_preflight(
        source,
        _complete_metadata(),
        [claim],
        {"analyzed_char_count": len(source)},
    )

    assert result["procedure_relevance"]["machine_verdict"] == "fail"
    assert result["procedure_level_claim"]["machine_verdict"] == "fail"
    assert result["procedure_relevance"]["evidence_refs"] == []


def test_evidence_without_offsets_must_have_one_exact_occurrence():
    quote = "downloaded payload.bin"
    unique_source = f"The actor {quote} to the host."
    repeated_source = f"The actor {quote}. Later it {quote}."
    claim = {
        "claim_type": "procedure",
        "attack_id": "T1105",
        "predicate": "downloaded",
        "object": "payload.bin",
        "evidence_text": quote,
    }

    unique = evaluate_report_preflight(
        unique_source,
        _complete_metadata(),
        [claim],
        {"analyzed_char_count": len(unique_source)},
    )
    repeated = evaluate_report_preflight(
        repeated_source,
        _complete_metadata(),
        [claim],
        {"analyzed_char_count": len(repeated_source)},
    )

    assert unique["procedure_relevance"]["machine_verdict"] == "pass"
    assert repeated["procedure_relevance"]["machine_verdict"] == "fail"


def test_partial_or_unknown_coverage_prevents_procedure_pass():
    source, claims = _source_and_claims()

    partial = evaluate_report_preflight(
        source,
        _complete_metadata(),
        claims,
        {"analyzed_ranges": [[0, len(source) // 2]]},
    )
    unknown = evaluate_report_preflight(source, _complete_metadata(), claims)

    for result in (partial, unknown):
        assert result["procedure_relevance"]["machine_verdict"] == "warning"
        assert result["procedure_level_claim"]["machine_verdict"] == "warning"
    assert partial["procedure_relevance"]["details"]["metrics"]["coverage"]["coverage_percent"] < 100
    assert unknown["procedure_relevance"]["details"]["metrics"]["coverage"]["coverage_known"] is False


def test_actor_similarity_and_tool_overlap_can_never_pass_identification():
    source = "The report discusses a PowerShell intrusion."
    quote = "PowerShell intrusion"
    start, end = _span(source, quote)
    overlap_claim = {
        "claim_type": "actor",
        "subject": "MuddyWater",
        "basis": "tooling_overlap_only",
        "evidence_text": quote,
        "evidence_start": start,
        "evidence_end": end,
    }

    result = evaluate_report_preflight(
        source,
        _complete_metadata(),
        [overlap_claim],
        {
            "analyzed_char_count": len(source),
            "apt_matches": [{"group_attack_id": "G0069", "similarity": 0.91}],
        },
    )

    gate = result["actor_identification"]
    assert gate["machine_verdict"] == "fail"
    fact_codes = {fact["code"] for fact in gate["details"]["facts"]}
    assert "actor_based_on_overlap_only" in fact_codes
    assert "similarity_leads_excluded" in fact_codes
    assert gate["details"]["metrics"]["explicit_source_bound_count"] == 0


def test_explicit_actor_claim_must_name_actor_affirmatively_in_exact_quote():
    source = "There is no evidence linking this activity to MuddyWater."
    start, end = _span(source, source)
    claim = {
        "claim_type": "actor",
        "subject": "MuddyWater",
        "basis": "explicit",
        "evidence_text": source,
        "evidence_start": start,
        "evidence_end": end,
    }

    result = evaluate_report_preflight(
        source,
        _complete_metadata(),
        [claim],
        {"analyzed_char_count": len(source)},
    )

    assert result["actor_identification"]["machine_verdict"] == "fail"
    assert result["actor_identification"]["details"]["metrics"]["explicit_source_bound_count"] == 0


def test_persisted_actor_claim_shape_uses_attributed_object_and_metadata_basis():
    source = "The source attributes the intrusion to MuddyWater."
    start, end = _span(source, source)
    claim = {
        "claim_type": "actor",
        "subject": "report",
        "predicate": "attributes activity to",
        "object": "MuddyWater",
        "actor_ids": ["MuddyWater"],
        "metadata": {"attribution_basis": "source_reported"},
        "evidence_text": source,
        "evidence_start": start,
        "evidence_end": end,
    }

    result = evaluate_report_preflight(
        source,
        _complete_metadata(),
        [claim],
        {"analyzed_char_count": len(source)},
    )

    assert result["actor_identification"]["machine_verdict"] == "pass"
    assert result["actor_identification"]["details"]["metrics"]["explicit_source_bound_count"] == 1


def test_ai_advisory_merge_cannot_override_machine_or_analyst_fields():
    source, claims = _source_and_claims()
    preflight = evaluate_report_preflight(
        source,
        _complete_metadata(),
        claims,
        {"analyzed_char_count": len(source)},
    )
    preflight["actor_identification"]["analyst_verdict"] = "fail"
    deterministic_snapshot = copy.deepcopy(preflight)
    advisory = {
        "authoritative": True,
        "provider": "test-provider",
        "model": "test-model",
        "machine_verdict": "fail",
        "analyst_verdict": "pass",
        "procedure_relevance": {
            "verdict": "supports_fail",
            "rationale": "Provider suggestion only.",
        },
        "actor_identification": {
            "verdict": "supports_pass",
            "basis": "explicit",
            "actor_name": "InventedActor",
            "rationale": "Provider suggestion only.",
        },
    }

    merged = merge_ai_advisory(preflight, advisory)

    for key in GATE_KEYS:
        assert merged[key]["machine_verdict"] == deterministic_snapshot[key]["machine_verdict"]
        assert merged[key]["evidence_refs"] == deterministic_snapshot[key]["evidence_refs"]
        assert merged[key]["evaluator"] == deterministic_snapshot[key]["evaluator"]
    assert merged["actor_identification"]["analyst_verdict"] == "fail"
    assert merged["actor_identification"]["details"]["ai_advisory"]["authoritative"] is False
    assert "ai_advisory" not in preflight["actor_identification"]["details"]


def test_ai_advisory_claim_in_primary_claims_cannot_change_deterministic_verdict():
    source = "The adversary downloaded payload.bin."
    start, end = _span(source, source)
    advisory_claim = {
        "claim_type": "procedure",
        "predicate": "downloaded",
        "object": "payload.bin",
        "evidence_text": source,
        "evidence_start": start,
        "evidence_end": end,
        "source": "ai-advisory",
        "authoritative": False,
    }

    result = evaluate_report_preflight(
        source,
        _complete_metadata(),
        [advisory_claim],
        {"analyzed_char_count": len(source)},
    )

    assert result["procedure_relevance"]["machine_verdict"] == "fail"
    assert result["procedure_level_claim"]["machine_verdict"] == "fail"
