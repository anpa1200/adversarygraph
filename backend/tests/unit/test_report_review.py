from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import datetime, timezone

from app.models.analysis import AnalysisResult, AnalysisSession
from app.models.report_review import ReportReview, ReportReviewClaim, ReportReviewGate
from app.services.report_review import (
    POLICY_VERSION,
    ReviewContext,
    _normalize_targets,
    build_promotion_manifest,
    canonical_json,
    claim_acceptance_errors,
    promotion_manifest_checksum,
    review_readiness,
)


NOW = datetime(2026, 8, 20, tzinfo=timezone.utc)
SOURCE = "Published 2026-08-20. The adversary executed PowerShell commands to download payload.bin."


def _context() -> ReviewContext:
    session_id = uuid.uuid4()
    session = AnalysisSession(
        id=session_id,
        status="completed",
        name="Test report",
        input_type="text",
        filename=None,
        llm_provider="local",
        model="test",
        domain="enterprise-attack",
        tlp="TLP:AMBER",
        source_text=SOURCE,
        created_at=NOW,
        updated_at=NOW,
    )
    result = AnalysisResult(
        id=1,
        session_id=session_id,
        extracted_techniques=[],
        apt_matches=[],
        summary="Test",
        raw_response="",
        created_at=NOW,
    )
    from app.services.report_review import analysis_fingerprint, source_fingerprint

    source_metadata = {
        "input_type": "text",
        "publication_date_candidates": [{"value": "2026-08-20"}],
    }

    return ReviewContext(
        session=session,
        result=result,
        intake=None,
        source_text=SOURCE,
        source_checksum=source_fingerprint(SOURCE, source_metadata),
        analysis_checksum=analysis_fingerprint(result, "completed"),
        source_metadata=source_metadata,
    )


def _review(context: ReviewContext) -> ReportReview:
    return ReportReview(
        id=uuid.uuid4(),
        session_id=context.session.id,
        revision=1,
        version=10,
        policy_version=POLICY_VERSION,
        profile="external_cti",
        state="draft",
        source_checksum=context.source_checksum,
        analysis_checksum=context.analysis_checksum,
        source_char_count=len(SOURCE),
        analyzed_char_count=len(SOURCE),
        coverage_complete=True,
        coverage_exception_reason="",
        coverage_exception_by="",
        coverage_exception_by_id="",
        created_by="creator",
        created_by_id="creator-id",
        submitted_by="submitter",
        submitted_by_id="submitter-id",
        approved_by="approver",
        approved_by_id="approver-id",
        approved_at=NOW,
        promoted_by="",
        promoted_by_id="",
        revoked_by="",
        revoked_by_id="",
        created_at=NOW,
        updated_at=NOW,
    )


def _gate(review: ReportReview, key: str, ordinal: int, *, verdict: str = "pass", reason: str = "source_verified") -> ReportReviewGate:
    source_start = SOURCE.index("Published")
    evidence = {
        "kind": "source_text",
        "excerpt": "Published 2026-08-20",
        "evidence_start": source_start,
        "evidence_end": source_start + len("Published 2026-08-20"),
    }
    return ReportReviewGate(
        id=uuid.uuid4(),
        review_id=review.id,
        gate_key=key,
        ordinal=ordinal,
        required=True,
        machine_verdict="pass",
        machine_details={"summary": "deterministic"},
        machine_evidence_refs=[],
        machine_evaluator="deterministic:report-review-preflight-v1",
        machine_evaluated_at=NOW,
        analyst_verdict=verdict,
        reason_code=reason,
        rationale="Analyst verified this gate against the stored report.",
        evidence_refs=[evidence] if key == "source_provenance" else [],
        reviewed_by="analyst",
        reviewed_by_id="analyst-id",
        reviewed_at=NOW,
        created_at=NOW,
        updated_at=NOW,
    )


def _claims(review: ReportReview) -> list[ReportReviewClaim]:
    procedure_text = "The adversary executed PowerShell commands to download payload.bin."
    procedure_start = SOURCE.index(procedure_text)
    date_text = "Published 2026-08-20"
    date_start = SOURCE.index(date_text)
    return [
        ReportReviewClaim(
            id=uuid.uuid4(),
            review_id=review.id,
            claim_key="p" * 64,
            claim_type="procedure",
            subject="adversary",
            predicate="executed PowerShell commands",
            object="payload.bin",
            statement=procedure_text,
            attack_id="T1059.001",
            actor_id="",
            evidence_text=procedure_text,
            evidence_start=procedure_start,
            evidence_end=procedure_start + len(procedure_text),
            extraction_method="analysis-extraction",
            status="accepted",
            reason_code="analyst_accepted",
            rationale="Specific behavior is bound to the report text.",
            evidence_refs=[],
            claim_metadata={"llm_verified": True, "tactic": "execution", "confidence": 0.91},
            reviewed_by="analyst",
            reviewed_by_id="analyst-id",
            reviewed_at=NOW,
            created_at=NOW,
            updated_at=NOW,
        ),
        ReportReviewClaim(
            id=uuid.uuid4(),
            review_id=review.id,
            claim_key="d" * 64,
            claim_type="publication_date",
            subject="report",
            predicate="published on",
            object="2026-08-20",
            statement="The report publication date is 2026-08-20.",
            attack_id="",
            actor_id="",
            evidence_text=date_text,
            evidence_start=date_start,
            evidence_end=date_start + len(date_text),
            extraction_method="analyst-created",
            status="accepted",
            reason_code="analyst_accepted",
            rationale="Date is printed in the report.",
            evidence_refs=[
                {
                    "kind": "source_text",
                    "excerpt": date_text,
                    "evidence_start": date_start,
                    "evidence_end": date_start + len(date_text),
                }
            ],
            claim_metadata={"date_candidate": "2026-08-20", "date_source": "report-text"},
            reviewed_by="analyst",
            reviewed_by_id="analyst-id",
            reviewed_at=NOW,
            created_at=NOW,
            updated_at=NOW,
        ),
    ]


def _ready_bundle():
    context = _context()
    review = _review(context)
    gates = [
        _gate(review, "source_provenance", 1, reason="source_verified"),
        _gate(review, "publication_date", 2, reason="date_verified"),
        _gate(review, "procedure_relevance", 3, reason="procedure_relevant"),
        _gate(review, "procedure_level_claim", 4, reason="source_bound_claims"),
        _gate(review, "actor_identification", 5, verdict="not_applicable", reason="no_actor_claim"),
    ]
    return context, review, gates, _claims(review)


def test_canonical_json_and_promotion_checksum_are_stable_and_target_bound():
    assert canonical_json({"b": 2, "a": 1}) == '{"a":1,"b":2}'
    manifest = {"schema_version": "v1", "accepted_claims": []}
    assert promotion_manifest_checksum(manifest, ["rag"]) == promotion_manifest_checksum(manifest, ["rag"])
    assert promotion_manifest_checksum(manifest, ["rag"]) != promotion_manifest_checksum(manifest, ["exports"])


def test_readiness_requires_human_gate_decisions_even_when_machine_passes():
    context, review, gates, claims = _ready_bundle()
    gates[2].analyst_verdict = "pending"

    readiness = review_readiness(review, gates, claims, context)

    assert readiness["ready"] is False
    assert "gate_pending:procedure_relevance" in readiness["blockers"]


def test_readiness_requires_deterministic_preflight_on_every_gate():
    context, review, gates, claims = _ready_bundle()
    gates[0].machine_verdict = "not_run"
    gates[0].machine_evaluated_at = None

    readiness = review_readiness(review, gates, claims, context)

    assert "deterministic_preflight_required:source_provenance" in readiness["blockers"]


def test_source_bound_catalog_verified_procedure_is_ready_for_promotion():
    context, review, gates, claims = _ready_bundle()

    readiness = review_readiness(review, gates, claims, context)

    assert readiness["ready"] is True
    assert readiness["blockers"] == []


def test_procedure_claim_rejects_unverified_catalog_mapping():
    context, review, _gates, claims = _ready_bundle()
    procedure = claims[0]
    procedure.claim_metadata = {"llm_verified": False}

    assert "procedure_attack_id_not_catalog_verified" in claim_acceptance_errors(procedure, context)


def test_publication_claim_requires_exact_path_and_value_binding():
    context, review, _gates, claims = _ready_bundle()
    publication = claims[1]
    publication.evidence_text = ""
    publication.evidence_start = None
    publication.evidence_end = None
    publication.evidence_refs = [
        {
            "kind": "metadata",
            "path": "source_metadata.input_type",
            "value": "e",
        }
    ]

    errors = claim_acceptance_errors(publication, context)

    assert "publication_date_not_source_bound" in errors

    publication.evidence_refs = [
        {
            "kind": "metadata",
            "path": "source_metadata.publication_date_candidates[0]",
            "value": "2026-08-20",
        }
    ]
    assert "publication_date_not_source_bound" not in claim_acceptance_errors(
        publication,
        context,
    )


def test_publication_claim_rejects_future_or_mismatched_date() -> None:
    context, _review, _gates, claims = _ready_bundle()
    publication = claims[1]
    publication.object = "2099-01-01"
    publication.claim_metadata = {
        "date_candidate": "2026-08-20",
        "date_source": "report-text",
    }

    errors = claim_acceptance_errors(publication, context)

    assert "publication_date_candidate_mismatch" in errors
    assert "publication_date_after_acquisition" in errors


def _source_bound_claim(
    review: ReportReview,
    source: str,
    *,
    claim_type: str,
    object_value: str,
    metadata: dict | None = None,
    actor_id: str = "",
) -> ReportReviewClaim:
    return ReportReviewClaim(
        id=uuid.uuid4(),
        review_id=review.id,
        claim_key="x" * 64,
        claim_type=claim_type,
        subject="report",
        predicate="contains",
        object=object_value,
        statement=f"The report contains {object_value}.",
        attack_id="",
        actor_id=actor_id,
        evidence_text=source,
        evidence_start=0,
        evidence_end=len(source),
        extraction_method="analyst-created",
        status="suggested",
        reason_code="",
        rationale="",
        evidence_refs=[],
        claim_metadata=metadata or {},
        reviewed_by="",
        reviewed_by_id="",
        created_at=NOW,
        updated_at=NOW,
    )


def test_actor_name_requires_phrase_boundary_and_rejects_short_aliases() -> None:
    context, review, _gates, _claims_value = _ready_bundle()
    source = "The report explicitly attributes the operation to APT10."
    context = replace(context, source_text=source)

    substring = _source_bound_claim(
        review,
        source,
        claim_type="actor",
        object_value="APT1",
        actor_id="APT1",
        metadata={"attribution_basis": "explicit"},
    )
    too_short = _source_bound_claim(
        review,
        source,
        claim_type="actor",
        object_value="a",
        actor_id="a",
        metadata={"attribution_basis": "explicit"},
    )

    assert "actor_not_named_in_evidence" in claim_acceptance_errors(substring, context)
    assert "actor_identifier_too_short" in claim_acceptance_errors(too_short, context)


def test_indicator_and_cve_values_must_be_typed_and_named_in_bound_evidence() -> None:
    context, review, _gates, _claims_value = _ready_bundle()
    source = "Observed good.example and CVE-2026-12345 during the incident."
    context = replace(context, source_text=source)

    fabricated_indicator = _source_bound_claim(
        review,
        source,
        claim_type="indicator",
        object_value="evil.example",
        metadata={"indicator_type": "domain"},
    )
    malformed_cve = _source_bound_claim(
        review,
        source,
        claim_type="vulnerability",
        object_value="CVE-NOT-VALID",
    )
    valid_cve = _source_bound_claim(
        review,
        source,
        claim_type="vulnerability",
        object_value="CVE-2026-12345",
    )

    assert "indicator_not_named_in_evidence" in claim_acceptance_errors(fabricated_indicator, context)
    assert "vulnerability_identifier_invalid" in claim_acceptance_errors(malformed_cve, context)
    assert "vulnerability_not_named_in_evidence" not in claim_acceptance_errors(valid_cve, context)


def test_not_applicable_gates_cannot_contradict_accepted_claims() -> None:
    context, review, gates, claims = _ready_bundle()
    source = "The source explicitly attributes the operation to MuddyWater."
    actor_context = replace(context, source_text=source)
    actor = _source_bound_claim(
        review,
        source,
        claim_type="actor",
        object_value="MuddyWater",
        actor_id="MuddyWater",
        metadata={"attribution_basis": "explicit"},
    )
    actor.status = "accepted"

    actor_readiness = review_readiness(
        review,
        gates,
        [*claims, actor],
        actor_context,
    )
    assert "accepted_actor_claim_conflicts_with_no_actor_claim" in actor_readiness["blockers"]

    review.profile = "internal_ir"
    publication_gate = next(gate for gate in gates if gate.gate_key == "publication_date")
    publication_gate.analyst_verdict = "not_applicable"
    publication_gate.reason_code = "internal_record_no_publication"
    publication_readiness = review_readiness(review, gates, claims, context)
    assert (
        "accepted_publication_date_conflicts_with_not_applicable_gate"
        in publication_readiness["blockers"]
    )


def test_manifest_contains_only_accepted_claims_and_required_integrity_fields():
    context, review, gates, claims = _ready_bundle()
    rejected = _claims(review)[0]
    rejected.id = uuid.uuid4()
    rejected.claim_key = "r" * 64
    rejected.status = "rejected"

    manifest = build_promotion_manifest(
        review,
        gates,
        [*claims, rejected],
        context,
        generated_at=NOW,
        targets=["canonical_intelligence", "exports"],
    )

    assert manifest["schema_version"] == "report-promotion-manifest-v1"
    assert manifest["session_id"] == str(review.session_id)
    assert manifest["source_checksum"] == context.source_checksum
    assert manifest["targets"] == ["canonical_intelligence", "exports"]
    assert len(manifest["accepted_claims"]) == 2
    assert all(item["status"] == "accepted" for item in manifest["accepted_claims"])
    procedure = next(item for item in manifest["accepted_claims"] if item["claim_type"] == "procedure")
    assert procedure["metadata"]["tactic"] == "execution"
    assert procedure["evidence_refs"][0]["metadata"]["locally_verified"] is True


def test_targets_are_deduplicated_allowlisted_and_canonicalized():
    assert _normalize_targets("rag,exports", ["rag"]) == ["canonical_intelligence", "exports", "rag"]
