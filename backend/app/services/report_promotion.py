"""Read-only helpers for authoritative report promotion projections.

Every downstream consumer uses this module instead of inferring authority from
an analysis-session status or an analyst technique flag. A promotion is active
only while its review is still in the promoted state and no append-only
revocation exists.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analysis import AnalysisResult, AnalysisSession
from app.models.ioc import IOCIndicator
from app.models.operations import ReportIntake
from app.models.report_review import (
    ReportPromotion,
    ReportPromotionRevocation,
    ReportReview,
)
from app.services.report_intake import latest_report_intake_id_subquery
from app.services.report_review import (
    _promotion_integrity_matches_review,
    analysis_fingerprint,
    _normalize_indicator_type,
    active_promotion,
    source_fingerprint,
)


@dataclass(frozen=True, slots=True)
class ActiveReportPromotion:
    promotion: ReportPromotion
    review: ReportReview


def promotion_matches_context(
    promotion: ReportPromotion,
    review: ReportReview,
    session: AnalysisSession,
    result: AnalysisResult | None,
    source_metadata: dict[str, Any],
) -> bool:
    """Verify every immutable promotion fingerprint against current storage."""

    current_source_checksum = source_fingerprint(
        session.source_text or "",
        source_metadata,
    )
    current_analysis_checksum = analysis_fingerprint(result, session.status)
    return (
        promotion_integrity_valid(promotion, review)
        and review.state == "promoted"
        and promotion.session_id == session.id
        and promotion.review_id == review.id
        and promotion.review_revision == review.revision
        and promotion.source_checksum == current_source_checksum
        and promotion.analysis_checksum == current_analysis_checksum
        and review.source_checksum == current_source_checksum
        and review.analysis_checksum == current_analysis_checksum
    )


def promotion_integrity_valid(
    promotion: ReportPromotion,
    review: ReportReview,
) -> bool:
    """Verify row/manifest duplication and the target-bound checksum."""

    return _promotion_integrity_matches_review(promotion, review)


async def get_active_report_promotion(
    db: AsyncSession,
    session_id: uuid.UUID | str,
) -> ActiveReportPromotion | None:
    """Return the latest non-revoked promotion for the active review revision."""

    try:
        normalized_id = session_id if isinstance(session_id, uuid.UUID) else uuid.UUID(str(session_id))
    except (TypeError, ValueError):
        return None

    promotion = await active_promotion(db, normalized_id)
    if promotion is None:
        return None
    review = await db.get(ReportReview, promotion.review_id)
    if review is None:
        return None
    return ActiveReportPromotion(promotion=promotion, review=review)


def accepted_claims(promotion: ReportPromotion) -> list[dict[str, Any]]:
    """Return the immutable, accepted claim projection from a promotion manifest."""

    manifest = promotion.manifest if isinstance(promotion.manifest, dict) else {}
    raw_claims = manifest.get("accepted_claims")
    if not isinstance(raw_claims, list):
        return []
    claims: list[dict[str, Any]] = []
    for item in raw_claims:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "accepted").strip().lower()
        if status != "accepted":
            continue
        claims.append(dict(item))
    return claims


def accepted_technique_ids(promotion: ReportPromotion) -> list[str]:
    values = {
        str(claim.get("attack_id") or "").strip().upper()
        for claim in accepted_claims(promotion)
        if str(claim.get("claim_type") or "") == "procedure"
    }
    return sorted(value for value in values if value)


def accepted_actor_ids(promotion: ReportPromotion) -> list[str]:
    values = {
        str(claim.get("actor_id") or "").strip().upper()
        for claim in accepted_claims(promotion)
        if str(claim.get("claim_type") or "") == "actor"
    }
    return sorted(value for value in values if value)


def promotion_allows(promotion: ReportPromotion, target: str) -> bool:
    """Fail closed unless the immutable promotion explicitly names a target."""

    return target in {str(value).strip() for value in (promotion.targets or []) if isinstance(value, str) and value.strip()}


def _promotion_id_from_source_id(source_id: str) -> uuid.UUID | None:
    prefix = "report-promotion-"
    if not source_id.startswith(prefix):
        return None
    try:
        return uuid.UUID(source_id[len(prefix) :])
    except ValueError:
        return None


async def authorized_report_promotion_indicator_ids(
    db: AsyncSession,
    indicators: Sequence[IOCIndicator],
    *,
    target: str,
) -> set[int]:
    """Validate every promotion-derived IOC against its immutable claim."""

    by_promotion_id: dict[uuid.UUID, list[IOCIndicator]] = {}
    for indicator in indicators:
        promotion_id = _promotion_id_from_source_id(str(indicator.source_id or ""))
        if promotion_id is not None:
            by_promotion_id.setdefault(promotion_id, []).append(indicator)
    if not by_promotion_id:
        return set()
    latest_review_revision = (
        select(func.max(ReportReview.revision))
        .where(ReportReview.session_id == ReportPromotion.session_id)
        .correlate(ReportPromotion)
        .scalar_subquery()
    )
    rows = (
        await db.execute(
            select(
                ReportPromotion,
                ReportReview,
                AnalysisSession,
                AnalysisResult,
                ReportIntake,
            )
            .join(ReportReview, ReportReview.id == ReportPromotion.review_id)
            .join(AnalysisSession, AnalysisSession.id == ReportPromotion.session_id)
            .join(AnalysisResult, AnalysisResult.session_id == AnalysisSession.id)
            .outerjoin(
                ReportIntake,
                ReportIntake.id == latest_report_intake_id_subquery(AnalysisSession.id),
            )
            .outerjoin(
                ReportPromotionRevocation,
                ReportPromotionRevocation.promotion_id == ReportPromotion.id,
            )
            .where(
                ReportPromotion.id.in_(list(by_promotion_id)),
                ReportReview.state == "promoted",
                ReportReview.revision == latest_review_revision,
                ReportPromotionRevocation.id.is_(None),
            )
        )
    ).all()
    authorized: set[int] = set()
    for promotion, review, session, result, intake in rows:
        if not promotion_allows(promotion, target) or not promotion_matches_context(
            promotion,
            review,
            session,
            result,
            _review_source_metadata(session, intake),
        ):
            continue
        claims = {
            str(claim.get("claim_key") or ""): claim
            for claim in accepted_claims(promotion)
            if claim.get("claim_type") == "indicator" and str(claim.get("claim_key") or "")
        }
        for indicator in by_promotion_id.get(promotion.id, []):
            raw = indicator.raw if isinstance(indicator.raw, dict) else {}
            claim_key = str(raw.get("claim_key") or "")
            claim = claims.get(claim_key)
            if claim is None:
                continue
            metadata = claim.get("metadata") if isinstance(claim.get("metadata"), dict) else {}
            expected_value = str(claim.get("value") or claim.get("object") or "").strip()
            expected_type = _normalize_indicator_type(claim.get("indicator_type") or metadata.get("indicator_type") or metadata.get("type"))
            stored_value = str(indicator.value or "").strip()
            if expected_type in {
                "ja3",
                "ja3s",
                "ja4",
                "ja4s",
                "ja4h",
                "ja4l",
                "ja4ls",
                "ja4x",
                "ja4ssh",
                "ja4t",
            }:
                stored_value = stored_value.casefold()
                expected_value = expected_value.casefold()
            if (
                str(raw.get("promotion_id") or "") != str(promotion.id)
                or str(raw.get("manifest_checksum") or "") != promotion.manifest_checksum
                or str(raw.get("review_id") or "") != str(promotion.review_id)
                or str(raw.get("analysis_session_id") or "") != str(promotion.session_id)
                or stored_value != expected_value
                or _normalize_indicator_type(indicator.indicator_type) != expected_type
            ):
                continue
            authorized.add(int(indicator.id))
    return authorized


def _review_source_metadata(
    session: AnalysisSession,
    intake: ReportIntake | None,
) -> dict[str, Any]:
    from app.services.report_review import _source_metadata

    return _source_metadata(session, intake)


async def authorized_report_promotions(
    db: AsyncSession,
    session_ids: set[str] | list[str] | tuple[str, ...],
    *,
    target: str,
) -> dict[str, ReportPromotion]:
    """Bulk-resolve current fingerprint-valid promotions for report sessions."""

    normalized_ids: set[uuid.UUID] = set()
    for value in session_ids:
        try:
            normalized_ids.add(uuid.UUID(str(value)))
        except (TypeError, ValueError):
            continue
    if not normalized_ids:
        return {}
    authorized: dict[str, ReportPromotion] = {}
    for session_id in sorted(normalized_ids, key=str):
        active = await get_active_report_promotion(db, session_id)
        if active is not None and promotion_allows(active.promotion, target):
            authorized[str(session_id)] = active.promotion
    return authorized


def promotion_summary(active: ActiveReportPromotion | None) -> dict[str, Any] | None:
    if active is None:
        return None
    promotion = active.promotion
    return {
        "id": str(promotion.id),
        "review_id": str(promotion.review_id),
        "review_revision": promotion.review_revision,
        "policy_version": promotion.policy_version,
        "source_checksum": promotion.source_checksum,
        "analysis_checksum": promotion.analysis_checksum,
        "targets": list(promotion.targets or []),
        "promoted_by": promotion.promoted_by,
        "promoted_at": promotion.promoted_at.isoformat() if promotion.promoted_at else None,
        "manifest_checksum": promotion.manifest_checksum,
    }
