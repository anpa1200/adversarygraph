from __future__ import annotations

from uuid import uuid4

from app.models.analysis import AnalysisResult, AnalysisSession
from app.models.ioc import IOCIndicator
from app.models.report_review import ReportPromotion, ReportReview
from app.services.report_promotion import (
    authorized_report_promotion_indicator_ids,
    promotion_integrity_valid,
    promotion_allows,
    promotion_matches_context,
)
from app.services.report_review import (
    _source_metadata,
    analysis_fingerprint,
    promotion_manifest_checksum,
    source_fingerprint,
)


def _promotion_bundle():
    session_id = uuid4()
    review_id = uuid4()
    session = AnalysisSession(
        id=session_id,
        status="completed",
        name="Reviewed report",
        input_type="text",
        llm_provider="local",
        model="test",
        domain="enterprise-attack",
        tlp="TLP:AMBER",
        source_text="The adversary downloaded payload.bin.",
    )
    result = AnalysisResult(
        id=17,
        session_id=session_id,
        extracted_techniques=[],
        apt_matches=[],
        summary="Reviewed report",
        raw_response="",
    )
    source_metadata = _source_metadata(session, None)
    source_checksum = source_fingerprint(session.source_text, source_metadata)
    analysis_checksum = analysis_fingerprint(result, session.status)
    review = ReportReview(
        id=review_id,
        session_id=session_id,
        revision=2,
        version=7,
        policy_version="report-review-policy-v1.0",
        profile="external_cti",
        state="promoted",
        source_checksum=source_checksum,
        analysis_checksum=analysis_checksum,
        source_char_count=len(session.source_text),
        analyzed_char_count=len(session.source_text),
        coverage_complete=True,
        created_by="analyst",
    )
    targets = ["canonical_intelligence", "rag"]
    manifest = {
        "schema_version": "report-promotion-manifest-v1",
        "session_id": str(session_id),
        "review_id": str(review_id),
        "review_revision": 2,
        "policy_version": review.policy_version,
        "profile": review.profile,
        "source_checksum": source_checksum,
        "analysis_checksum": analysis_checksum,
        "targets": targets,
        "accepted_claims": [],
    }
    promotion = ReportPromotion(
        id=uuid4(),
        review_id=review_id,
        session_id=session_id,
        review_revision=2,
        policy_version=review.policy_version,
        source_checksum=source_checksum,
        analysis_checksum=analysis_checksum,
        targets=targets,
        manifest=manifest,
        manifest_checksum=promotion_manifest_checksum(manifest, targets),
        idempotency_key="b" * 64,
        promoted_by="approver",
    )
    return session, result, review, promotion, source_metadata


def test_promotion_scope_is_explicit_and_fail_closed() -> None:
    _session, _result, _review, promotion, _metadata = _promotion_bundle()

    assert promotion_allows(promotion, "canonical_intelligence") is True
    assert promotion_allows(promotion, "rag") is True
    assert promotion_allows(promotion, "hunting") is False
    assert promotion_allows(promotion, "exports") is False


def test_promotion_fingerprints_must_match_current_source_and_analysis() -> None:
    session, result, review, promotion, metadata = _promotion_bundle()

    assert promotion_matches_context(promotion, review, session, result, metadata) is True

    session.source_text = f"{session.source_text} Mutated after review."
    assert promotion_matches_context(promotion, review, session, result, metadata) is False


def test_public_promotion_integrity_uses_the_strict_canonical_invariant() -> None:
    def recompute(promotion):
        promotion.manifest_checksum = promotion_manifest_checksum(
            promotion.manifest,
            promotion.targets,
        )

    for tamper in (
        "manifest_schema",
        "manifest_profile",
        "promotion_policy",
        "promotion_session",
        "promotion_source_checksum",
        "manifest_checksum",
    ):
        _session, _result, review, promotion, _metadata = _promotion_bundle()
        if tamper == "manifest_schema":
            promotion.manifest = {
                **promotion.manifest,
                "schema_version": "tampered-schema",
            }
            recompute(promotion)
        elif tamper == "manifest_profile":
            promotion.manifest = {
                **promotion.manifest,
                "profile": "tampered-profile",
            }
            recompute(promotion)
        elif tamper == "promotion_policy":
            promotion.policy_version = "tampered-policy"
            promotion.manifest = {
                **promotion.manifest,
                "policy_version": promotion.policy_version,
            }
            recompute(promotion)
        elif tamper == "promotion_session":
            promotion.session_id = uuid4()
            promotion.manifest = {
                **promotion.manifest,
                "session_id": str(promotion.session_id),
            }
            recompute(promotion)
        elif tamper == "promotion_source_checksum":
            promotion.source_checksum = "f" * 64
            promotion.manifest = {
                **promotion.manifest,
                "source_checksum": promotion.source_checksum,
            }
            recompute(promotion)
        else:
            promotion.manifest_checksum = "0" * 64

        assert promotion_integrity_valid(promotion, review) is False, tamper


async def test_promotion_ioc_authority_is_bound_to_exact_manifest_claim() -> None:
    session, result, review, promotion, _metadata = _promotion_bundle()
    claim = {
        "claim_key": "indicator-claim-1",
        "claim_type": "indicator",
        "status": "accepted",
        "object": "good.example",
        "value": "good.example",
        "indicator_type": "domain",
        "metadata": {"indicator_type": "domain"},
    }
    fingerprint_claim = {
        "claim_key": "indicator-claim-2",
        "claim_type": "indicator",
        "status": "accepted",
        "object": "A" * 32,
        "value": "A" * 32,
        "indicator_type": "ja3",
        "metadata": {"indicator_type": "ja3"},
    }
    promotion.manifest = {
        **promotion.manifest,
        "accepted_claims": [claim, fingerprint_claim],
    }
    promotion.manifest_checksum = promotion_manifest_checksum(
        promotion.manifest,
        promotion.targets,
    )
    source_id = f"report-promotion-{promotion.id}"
    common_raw = {
        "promotion_id": str(promotion.id),
        "review_id": str(review.id),
        "analysis_session_id": str(session.id),
        "manifest_checksum": promotion.manifest_checksum,
    }
    legitimate = IOCIndicator(
        id=1,
        value="good.example",
        indicator_type="domain",
        source_id=source_id,
        raw={**common_raw, "claim_key": "indicator-claim-1"},
    )
    injected = IOCIndicator(
        id=2,
        value="evil.example",
        indicator_type="domain",
        source_id=source_id,
        raw={**common_raw, "claim_key": "indicator-claim-1"},
    )
    normalized_fingerprint = IOCIndicator(
        id=3,
        value="a" * 32,
        indicator_type="ja3",
        source_id=source_id,
        raw={**common_raw, "claim_key": "indicator-claim-2"},
    )

    class Rows:
        def all(self):
            return [(promotion, review, session, result, None)]

    class DB:
        last_statement = None

        async def execute(self, statement):
            self.last_statement = statement
            return Rows()

    db = DB()
    authorized = await authorized_report_promotion_indicator_ids(
        db,  # type: ignore[arg-type]
        [legitimate, injected, normalized_fingerprint],
        target="rag",
    )

    assert authorized == {1, 3}
    assert "max(report_reviews.revision)" in str(db.last_statement).lower()
