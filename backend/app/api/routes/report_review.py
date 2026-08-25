"""Report-level deterministic Review Gate API."""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.core.payload_limits import BoundedPayloadModel
from app.models.report_review import ReportPromotion
from app.services.asset_intel import retrohunt_assets
from app.services.auth import TeamUser, audit, current_user, require_permission
from app.services import report_review as reviews
from app.services.report_promotion import promotion_allows
from app.services.report_promotion_effects import (
    materialize_report_promotion,
    withdraw_report_promotion,
)


router = APIRouter(prefix="/analyze/sessions", tags=["Report Review Gate"])
review_reports = require_permission("review_reports")
promote_reports = require_permission("promote_reports")
logger = logging.getLogger(__name__)


async def _finish_ai_egress_audit(
    db: AsyncSession,
    user: TeamUser,
    correlation_id: UUID | None,
    attempt_details: dict[str, Any],
    *,
    status: str,
    error_category: str = "",
    output_checksum: str = "",
) -> None:
    if correlation_id is None:
        return
    await db.rollback()
    await audit(
        db,
        user,
        f"report_review.ai_egress.{status}",
        "report_review.ai_cloud_egress",
        str(correlation_id),
        {
            **attempt_details,
            "status": status,
            "error_category": error_category,
            "output_checksum": output_checksum,
        },
    )
    await db.commit()


class StartReviewBody(BoundedPayloadModel):
    profile: str = Field("external_cti", pattern="^(external_cti|internal_ir)$")
    expected_source_checksum: str | None = Field(None, min_length=64, max_length=64, pattern="^[a-f0-9]{64}$")


class VersionBody(BoundedPayloadModel):
    expected_version: int = Field(..., ge=1)


class GateDecisionBody(VersionBody):
    verdict: str = Field(..., pattern="^(pass|fail|needs_information|not_applicable)$")
    reason_code: str = Field(..., min_length=2, max_length=80, pattern="^[a-z0-9_]+$")
    rationale: str = Field(..., min_length=8, max_length=4_000)
    evidence_refs: list[dict[str, Any]] = Field(default_factory=list, max_length=20)


class ClaimDecisionBody(VersionBody):
    status: str = Field(..., pattern="^(suggested|accepted|rejected|needs_evidence)$")
    rationale: str = Field("", max_length=4_000)
    evidence_refs: list[dict[str, Any]] | None = Field(None, max_length=20)


class CreateClaimBody(VersionBody):
    claim_type: str = Field(..., pattern="^(procedure|actor|publication_date|indicator|vulnerability)$")
    subject: str = Field(..., min_length=1, max_length=500)
    action: str = Field(..., min_length=1, max_length=255)
    object: str = Field(..., min_length=1, max_length=8_000)
    statement: str = Field(..., min_length=8, max_length=8_000)
    attack_id: str = Field("", max_length=30)
    actor_id: str = Field("", max_length=120)
    rationale: str = Field("", max_length=4_000)
    evidence_refs: list[dict[str, Any]] = Field(default_factory=list, max_length=20)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ApprovalBody(VersionBody):
    decision_note: str = Field("", max_length=1_000)


class ReasonBody(VersionBody):
    reason: str = Field(..., min_length=8, max_length=2_000)


class PromotionBody(VersionBody):
    target: str | None = Field(None, max_length=400, pattern="^[a-z_,]*$")
    targets: list[str] | None = Field(None, max_length=10)
    note: str = Field("", max_length=1_000)


class AIAssistBody(BoundedPayloadModel):
    expected_version: int = Field(..., ge=1)
    provider: str = Field("local", pattern="^(local|claude|openai|gemini|minimax)$")
    model: str | None = Field(None, max_length=160, pattern=r"^[\w./:@-]+$")
    cloud_processing_acknowledged: bool = False


def _actor(user: TeamUser) -> reviews.ReviewActor:
    return reviews.ReviewActor(
        name=user.name,
        actor_id=user.user_id or f"{user.auth_source}:{user.name}",
    )


def _require_human(user: TeamUser) -> None:
    # Service accounts may run ingestion or deterministic machine checks, but
    # cannot populate the analyst decision columns.
    if "service_account" in user.roles:
        raise HTTPException(403, "A human analyst identity is required for report review decisions")


def _raise_http(exc: reviews.ReportReviewError) -> None:
    detail: str | dict[str, Any]
    detail = exc.message if not exc.details else {"message": exc.message, **exc.details}
    raise HTTPException(exc.status_code, detail)


async def _finish_mutation(
    db: AsyncSession,
    user: TeamUser,
    session_id: UUID,
    *,
    action: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    value = await reviews.assessment(db, session_id)
    await audit(
        db,
        user,
        action,
        "report_review",
        value["id"],
        {"session_id": str(session_id), "revision": value["revision"], "version": value["version"], **(details or {})},
    )
    await db.commit()
    return value


async def _queue_rag_refresh(
    db: AsyncSession,
    promotion: ReportPromotion,
    user: TeamUser,
) -> dict[str, Any]:
    if not promotion_allows(promotion, "rag"):
        return {"status": "not_selected", "queued": False, "run_id": None}
    try:
        from app.services.rag_queue import queue_rag_after_ingest

        return await queue_rag_after_ingest(
            db,
            ["analysis_report", "ioc"],
            created_by=f"report-review:{user.user_id or user.name}",
        )
    except Exception:
        # Canonical promotion writes have already committed. Scheduled RAG
        # reconciliation is the durable fallback and must not turn a successful
        # promotion/revocation into a misleading HTTP 500.
        await db.rollback()
        logger.exception("Immediate report-promotion RAG refresh failed")
        return {"status": "deferred", "queued": False, "run_id": None}


@router.get("/{session_id}/review")
async def get_report_review(
    session_id: UUID,
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
) -> dict[str, Any]:
    try:
        return await reviews.assessment(db, session_id)
    except reviews.ReportReviewError as exc:
        _raise_http(exc)


@router.post("/{session_id}/review/start")
async def start_report_review(
    session_id: UUID,
    body: StartReviewBody,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(review_reports),
) -> dict[str, Any]:
    _require_human(user)
    try:
        await reviews.lock_review_source(db, session_id)
        review = await reviews.start_review(
            db,
            session_id,
            _actor(user),
            profile=body.profile,
            expected_source_checksum=body.expected_source_checksum,
        )
        return await _finish_mutation(
            db,
            user,
            session_id,
            action="report_review.start",
            details={"profile": review.profile},
        )
    except reviews.ReportReviewError as exc:
        await db.rollback()
        _raise_http(exc)


@router.post("/{session_id}/review/preflight")
async def run_report_review_preflight(
    session_id: UUID,
    body: VersionBody,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(review_reports),
) -> dict[str, Any]:
    try:
        await reviews.lock_review_source(db, session_id)
        await reviews.run_preflight(db, session_id, _actor(user), expected_version=body.expected_version)
        return await _finish_mutation(db, user, session_id, action="report_review.preflight")
    except reviews.ReportReviewError as exc:
        await db.rollback()
        _raise_http(exc)


@router.patch("/{session_id}/review/gates/{gate_key}")
async def record_gate_decision(
    session_id: UUID,
    gate_key: str,
    body: GateDecisionBody,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(review_reports),
) -> dict[str, Any]:
    _require_human(user)
    try:
        await reviews.lock_review_source(db, session_id)
        await reviews.update_gate(
            db,
            session_id,
            gate_key,
            _actor(user),
            expected_version=body.expected_version,
            verdict=body.verdict,
            reason_code=body.reason_code,
            rationale=body.rationale,
            evidence_refs=body.evidence_refs,
        )
        return await _finish_mutation(
            db,
            user,
            session_id,
            action="report_review.gate_decision",
            details={"gate_key": gate_key, "verdict": body.verdict},
        )
    except reviews.ReportReviewError as exc:
        await db.rollback()
        _raise_http(exc)


@router.patch("/{session_id}/review/claims/{claim_id}")
async def record_claim_decision(
    session_id: UUID,
    claim_id: UUID,
    body: ClaimDecisionBody,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(review_reports),
) -> dict[str, Any]:
    _require_human(user)
    try:
        await reviews.lock_review_source(db, session_id)
        await reviews.update_claim(
            db,
            session_id,
            claim_id,
            _actor(user),
            expected_version=body.expected_version,
            status=body.status,
            rationale=body.rationale,
            evidence_refs=body.evidence_refs,
        )
        return await _finish_mutation(
            db,
            user,
            session_id,
            action="report_review.claim_decision",
            details={"claim_id": str(claim_id), "status": body.status},
        )
    except reviews.ReportReviewError as exc:
        await db.rollback()
        _raise_http(exc)


@router.post("/{session_id}/review/claims")
async def create_report_review_claim(
    session_id: UUID,
    body: CreateClaimBody,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(review_reports),
) -> dict[str, Any]:
    _require_human(user)
    try:
        await reviews.lock_review_source(db, session_id)
        _, claim = await reviews.create_claim(
            db,
            session_id,
            _actor(user),
            expected_version=body.expected_version,
            claim_type=body.claim_type,
            subject=body.subject,
            predicate=body.action,
            object_value=body.object,
            statement=body.statement,
            attack_id=body.attack_id,
            actor_id=body.actor_id,
            rationale=body.rationale,
            evidence_refs=body.evidence_refs,
            metadata=body.metadata,
        )
        return await _finish_mutation(
            db,
            user,
            session_id,
            action="report_review.claim_create",
            details={"claim_id": str(claim.id), "claim_type": claim.claim_type},
        )
    except reviews.ReportReviewError as exc:
        await db.rollback()
        _raise_http(exc)


@router.post("/{session_id}/review/coverage-exception")
async def grant_report_review_coverage_exception(
    session_id: UUID,
    body: ReasonBody,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(promote_reports),
) -> dict[str, Any]:
    _require_human(user)
    try:
        await reviews.lock_review_source(db, session_id)
        await reviews.grant_coverage_exception(
            db,
            session_id,
            _actor(user),
            expected_version=body.expected_version,
            reason=body.reason,
        )
        return await _finish_mutation(db, user, session_id, action="report_review.coverage_exception")
    except reviews.ReportReviewError as exc:
        await db.rollback()
        _raise_http(exc)


@router.post("/{session_id}/review/submit")
async def submit_report_review(
    session_id: UUID,
    body: VersionBody,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(review_reports),
) -> dict[str, Any]:
    _require_human(user)
    try:
        await reviews.lock_review_source(db, session_id)
        await reviews.submit_review(db, session_id, _actor(user), expected_version=body.expected_version)
        return await _finish_mutation(db, user, session_id, action="report_review.submit")
    except reviews.ReportReviewError as exc:
        await db.rollback()
        _raise_http(exc)


@router.post("/{session_id}/review/approve")
async def approve_report_review(
    session_id: UUID,
    body: ApprovalBody,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(promote_reports),
) -> dict[str, Any]:
    _require_human(user)
    try:
        await reviews.lock_review_source(db, session_id)
        await reviews.approve_review(
            db,
            session_id,
            _actor(user),
            expected_version=body.expected_version,
            decision_note=body.decision_note,
        )
        return await _finish_mutation(db, user, session_id, action="report_review.approve")
    except reviews.ReportReviewError as exc:
        await db.rollback()
        _raise_http(exc)


@router.post("/{session_id}/review/request-changes")
async def request_report_review_changes(
    session_id: UUID,
    body: ReasonBody,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(promote_reports),
) -> dict[str, Any]:
    _require_human(user)
    try:
        await reviews.lock_review_source(db, session_id)
        await reviews.request_changes(
            db,
            session_id,
            _actor(user),
            expected_version=body.expected_version,
            reason=body.reason,
        )
        return await _finish_mutation(db, user, session_id, action="report_review.request_changes")
    except reviews.ReportReviewError as exc:
        await db.rollback()
        _raise_http(exc)


@router.post("/{session_id}/review/reject")
async def reject_report_review(
    session_id: UUID,
    body: ReasonBody,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(promote_reports),
) -> dict[str, Any]:
    _require_human(user)
    try:
        await reviews.lock_review_source(db, session_id)
        await reviews.reject_review(
            db,
            session_id,
            _actor(user),
            expected_version=body.expected_version,
            reason=body.reason,
        )
        return await _finish_mutation(db, user, session_id, action="report_review.reject")
    except reviews.ReportReviewError as exc:
        await db.rollback()
        _raise_http(exc)


@router.post("/{session_id}/review/promote")
async def promote_report_review(
    session_id: UUID,
    body: PromotionBody,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(promote_reports),
) -> dict[str, Any]:
    _require_human(user)
    try:
        await reviews.lock_review_source(db, session_id)
        _, promotion = await reviews.promote_review(
            db,
            session_id,
            _actor(user),
            expected_version=body.expected_version,
            target=body.target,
            targets=body.targets,
            note=body.note,
        )
        effects = await materialize_report_promotion(db, promotion)
        retrohunt = await retrohunt_assets(db)
        value = await _finish_mutation(
            db,
            user,
            session_id,
            action="report_review.promote",
            details={
                "promotion_id": str(promotion.id),
                "targets": promotion.targets or [],
                "materialized": effects,
                "asset_retrohunt": retrohunt,
            },
        )
        value["downstream_refresh"] = {
            "materialized": effects,
            "asset_retrohunt": retrohunt,
            "rag": await _queue_rag_refresh(db, promotion, user),
        }
        return value
    except reviews.ReportReviewError as exc:
        await db.rollback()
        _raise_http(exc)
    except Exception:
        await db.rollback()
        raise


@router.post("/{session_id}/review/revoke")
async def revoke_report_promotion(
    session_id: UUID,
    body: ReasonBody,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(promote_reports),
) -> dict[str, Any]:
    _require_human(user)
    try:
        await reviews.lock_review_source(db, session_id)
        _, revocation = await reviews.revoke_promotion(
            db,
            session_id,
            _actor(user),
            expected_version=body.expected_version,
            reason=body.reason,
        )
        promotion = await db.get(ReportPromotion, revocation.promotion_id)
        if promotion is None:
            raise reviews.ReviewNotFoundError("Promotion record not found")
        effects = await withdraw_report_promotion(db, promotion)
        retrohunt = await retrohunt_assets(db)
        value = await _finish_mutation(
            db,
            user,
            session_id,
            action="report_review.revoke",
            details={
                "revocation_id": str(revocation.id),
                "withdrawn": effects,
                "asset_retrohunt": retrohunt,
            },
        )
        value["downstream_refresh"] = {
            "withdrawn": effects,
            "asset_retrohunt": retrohunt,
            "rag": await _queue_rag_refresh(db, promotion, user),
        }
        return value
    except reviews.ReportReviewError as exc:
        await db.rollback()
        _raise_http(exc)
    except Exception:
        await db.rollback()
        raise


@router.get("/{session_id}/review/history")
async def get_report_review_history(
    session_id: UUID,
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
) -> dict[str, Any]:
    return {"items": await reviews.review_history(db, session_id)}


@router.get("/{session_id}/review/promotion")
async def get_active_report_promotion(
    session_id: UUID,
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
) -> dict[str, Any]:
    promotion = await reviews.active_promotion(db, session_id)
    if promotion is None:
        raise HTTPException(404, "No active version-matched promotion exists for this report")
    return {
        "id": str(promotion.id),
        "session_id": str(promotion.session_id),
        "review_id": str(promotion.review_id),
        "review_revision": promotion.review_revision,
        "policy_version": promotion.policy_version,
        "source_checksum": promotion.source_checksum,
        "analysis_checksum": promotion.analysis_checksum,
        "targets": promotion.targets or [],
        "manifest_checksum": promotion.manifest_checksum,
        "manifest": promotion.manifest,
        "promoted_by": promotion.promoted_by,
        "promoted_at": promotion.promoted_at.isoformat() if promotion.promoted_at else None,
    }


@router.post("/{session_id}/review/ai-assist")
async def assist_report_review(
    session_id: UUID,
    body: AIAssistBody,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(review_reports),
) -> dict[str, Any]:
    """Return source-bound AI suggestions without changing review decisions."""

    try:
        value = await reviews.assessment(db, session_id)
        context = await reviews.load_review_context(db, session_id)
    except reviews.ReportReviewError as exc:
        _raise_http(exc)
    if value["state"] not in {"draft", "changes_requested"}:
        raise HTTPException(409, f"AI assistance is unavailable while review state is {value['state']}")
    if value["version"] != body.expected_version:
        raise HTTPException(
            409,
            {
                "message": "Review was changed by another user; reload before requesting AI assistance",
                "expected_version": body.expected_version,
                "current_version": value["version"],
            },
        )
    try:
        from app.services.report_review_ai import generate_ai_review_suggestions
    except ImportError as exc:
        raise HTTPException(503, "Optional report-review AI assistance is not installed") from exc

    cloud_egress = body.provider != "local"
    correlation_id: UUID | None = uuid4() if cloud_egress else None
    attempt_details: dict[str, Any] = {
        "session_id": str(session_id),
        "review_id": value["id"],
        "review_revision": value["revision"],
        "review_version": value["version"],
        "provider": body.provider,
        "model": body.model or "provider-default",
        "effective_tlp": context.session.tlp,
        "cloud_processing_acknowledged": bool(body.cloud_processing_acknowledged),
        "source_checksum": value["source_checksum"],
        "analysis_checksum": value["analysis_checksum"],
        "source_char_count": len(context.source_text),
        "status": "attempted",
    }
    if cloud_egress:
        if not body.cloud_processing_acknowledged:
            raise HTTPException(422, "Remote AI assistance requires explicit cloud-processing acknowledgement")
        await audit(
            db,
            user,
            "report_review.ai_egress.attempt",
            "report_review.ai_cloud_egress",
            str(correlation_id),
            attempt_details,
        )
        # This commit is an egress gate: protected source text is never sent
        # remotely unless the redacted attempt record is already durable.
        await db.commit()
    else:
        await db.rollback()

    try:
        suggestions = await generate_ai_review_suggestions(
            source_text=context.source_text,
            provider=body.provider,
            model=body.model,
            effective_tlp=context.session.tlp,
            cloud_processing_acknowledged=body.cloud_processing_acknowledged,
        )
    except asyncio.CancelledError:
        await _finish_ai_egress_audit(
            db,
            user,
            correlation_id,
            attempt_details,
            status="failed",
            error_category="request_cancelled",
        )
        raise
    except ValueError:
        await _finish_ai_egress_audit(
            db,
            user,
            correlation_id,
            attempt_details,
            status="failed",
            error_category="invalid_provider_output",
        )
        raise
    except Exception:
        await _finish_ai_egress_audit(
            db,
            user,
            correlation_id,
            attempt_details,
            status="failed",
            error_category="provider_request_failed",
        )
        raise
    try:
        await reviews.lock_review_source(db, session_id)
        _review, suggested_claim_count = await reviews.apply_ai_advisory(
            db,
            session_id,
            _actor(user),
            expected_version=body.expected_version,
            expected_source_checksum=value["source_checksum"],
            expected_analysis_checksum=value["analysis_checksum"],
            suggestions=suggestions,
        )
        updated = await reviews.assessment(db, session_id)
    except reviews.ReportReviewError as exc:
        await _finish_ai_egress_audit(
            db,
            user,
            correlation_id,
            attempt_details,
            status="failed",
            error_category="review_context_changed",
        )
        _raise_http(exc)
    except Exception:
        await _finish_ai_egress_audit(
            db,
            user,
            correlation_id,
            attempt_details,
            status="failed",
            error_category="advisory_persistence_failed",
        )
        raise
    await audit(
        db,
        user,
        "report_review.ai_assist",
        "report_review",
        value["id"],
        {
            "session_id": str(session_id),
            "review_revision": value["revision"],
            "review_version_before": value["version"],
            "review_version_after": updated["version"],
            "provider": suggestions.get("provider"),
            "model": suggestions.get("model"),
            "prompt_version": suggestions.get("prompt_version"),
            "authoritative": False,
            "complete_coverage": suggestions.get("complete_coverage"),
            "suggested_claim_count": suggested_claim_count,
            "cloud_egress": cloud_egress,
            "cloud_egress_correlation_id": str(correlation_id) if correlation_id else "",
        },
    )
    if correlation_id is not None:
        await audit(
            db,
            user,
            "report_review.ai_egress.succeeded",
            "report_review.ai_cloud_egress",
            str(correlation_id),
            {
                **attempt_details,
                "status": "succeeded",
                "provider": suggestions.get("provider"),
                "model": suggestions.get("model"),
                "prompt_version": suggestions.get("prompt_version"),
                "output_checksum": reviews.checksum_json(suggestions),
                "suggested_claim_count": suggested_claim_count,
            },
        )
    await db.commit()
    return {
        **suggestions,
        "review_id": value["id"],
        "review_revision": value["revision"],
        "review_version": updated["version"],
        "suggested_claim_count": suggested_claim_count,
        "review": updated,
        "disclaimer": "Advisory only. AI output cannot set gate verdicts, accept claims, approve, or promote this report.",
    }
