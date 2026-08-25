"""Transactional materialization and withdrawal of promoted report intelligence."""

from __future__ import annotations

from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analysis import AnalysisResult, AnalysisSession
from app.models.intelligence import (
    IntelligenceEntityTag,
    IntelligenceRelationship,
    IntelligenceTag,
)
from app.models.ioc import IOCIndicator, IOCSource
from app.models.operations import ReportIntake
from app.models.report_review import ReportPromotion, ReportReview
from app.services.intelligence_graph import link_entities
from app.services.ioc_intel import IOCImportItem, _upsert_indicator
from app.services.report_promotion import accepted_claims
from app.services.report_review import (
    _CVE_ID,
    _indicator_value_valid,
    _normalize_indicator_type,
    _promotion_integrity_matches_review,
    load_review_context,
)
from app.services.taxonomy import normalize_freeform_tags


def _promotion_source_id(promotion: ReportPromotion) -> str:
    return f"report-promotion-{promotion.id}"


def _metadata(claim: dict[str, Any]) -> dict[str, Any]:
    value = claim.get("metadata")
    return dict(value) if isinstance(value, dict) else {}


def _statement(claim: dict[str, Any]) -> str:
    return str(claim.get("statement") or "").strip()


def _claim_value(claim: dict[str, Any]) -> str:
    metadata = _metadata(claim)
    return str(metadata.get("value") or claim.get("object") or "").strip()


def _bounded_confidence(value: Any, default: int = 70) -> int:
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return default
    if 0 <= confidence <= 1:
        confidence *= 100
    return max(0, min(100, int(round(confidence))))


async def _link_promotion_tagged_entities(
    db: AsyncSession,
    *,
    entity_type: str,
    entity_id: str | int,
    tags: list[str],
    promotion_id: str,
    confidence: int,
    evidence: str,
) -> list[str]:
    """Add reversible promotion tags under promotion-specific provenance."""

    canonical_tags = normalize_freeform_tags(tags, limit=200)
    for canonical in canonical_tags:
        namespace, value = canonical.split(":", 1)
        await db.execute(
            insert(IntelligenceTag)
            .values(namespace=namespace, value=value, canonical=canonical)
            .on_conflict_do_nothing(constraint="uq_intelligence_tag")
        )
        await db.execute(
            insert(IntelligenceEntityTag)
            .values(
                entity_type=entity_type[:40],
                entity_id=str(entity_id)[:255],
                tag=canonical,
                source_type="report_promotion",
                source_id=promotion_id[:500],
                confidence=max(0, min(100, confidence)),
                evidence=evidence,
            )
            .on_conflict_do_nothing(constraint="uq_intelligence_entity_tag")
        )
        target_type = {
            "actor": "attack_group",
            "ttp": "attack_technique",
            "tactic": "attack_tactic",
            "campaign": "attack_campaign",
            "cve": "cve",
        }.get(namespace, "tag")
        await link_entities(
            db,
            source_type=entity_type,
            source_id=entity_id,
            relationship_type="tagged-with" if target_type == "tag" else "related-to",
            target_type=target_type,
            target_id=value if target_type != "tag" else canonical,
            provenance_type="report_promotion",
            provenance_id=promotion_id,
            confidence=confidence,
            evidence=evidence,
        )
    return canonical_tags


async def _report_intake(
    db: AsyncSession,
    session: AnalysisSession,
    result: AnalysisResult,
) -> ReportIntake:
    intake = await db.scalar(
        select(ReportIntake)
        .where(ReportIntake.analysis_session_id == session.id)
        .order_by(ReportIntake.updated_at.desc(), ReportIntake.id.desc())
        .limit(1)
    )
    if intake is not None:
        return intake
    source_url = session.filename if session.input_type == "url" else ""
    intake = ReportIntake(
        analysis_session_id=session.id,
        title=session.name or session.filename or f"Analysis {str(session.id)[:8]}",
        url=source_url or "",
        publisher="",
        status="draft",
        summary=result.summary[:5_000],
        source_reliability="unknown",
        actor_ids=[],
        technique_ids=[],
        indicators=[],
        tags=["report"],
        provenance={"analysis_session_id": str(session.id)},
        analyst_notes="",
    )
    db.add(intake)
    await db.flush()
    return intake


async def materialize_report_promotion(
    db: AsyncSession,
    promotion: ReportPromotion,
) -> dict[str, Any]:
    """Project one immutable manifest into canonical downstream stores.

    The caller owns the transaction. Re-running this function for the same
    promotion is idempotent.
    """

    review = await db.get(ReportReview, promotion.review_id)
    if (
        review is None
        or review.state != "promoted"
        or not _promotion_integrity_matches_review(promotion, review)
    ):
        raise RuntimeError("Promotion manifest integrity verification failed")
    context = await load_review_context(db, promotion.session_id)
    if (
        context.source_checksum != promotion.source_checksum
        or context.analysis_checksum != promotion.analysis_checksum
    ):
        raise RuntimeError("Promotion source or analysis fingerprint is stale")

    session = context.session
    result = await db.scalar(
        select(AnalysisResult).where(AnalysisResult.session_id == promotion.session_id)
    )
    if session is None or result is None:
        raise RuntimeError("Promotion source analysis is missing")

    claims = accepted_claims(promotion)
    procedures = [claim for claim in claims if claim.get("claim_type") == "procedure"]
    actors = [claim for claim in claims if claim.get("claim_type") == "actor"]
    indicators = [claim for claim in claims if claim.get("claim_type") == "indicator"]
    vulnerabilities = [claim for claim in claims if claim.get("claim_type") == "vulnerability"]
    technique_ids = sorted({
        str(claim.get("attack_id") or "").strip().upper()
        for claim in procedures
        if str(claim.get("attack_id") or "").strip()
    })
    actor_ids = sorted({
        str(claim.get("actor_id") or "").strip().upper()
        for claim in actors
        if str(claim.get("actor_id") or "").strip()
    })
    cve_ids = sorted({
        _claim_value(claim).upper()
        for claim in vulnerabilities
        if _CVE_ID.fullmatch(_claim_value(claim)) is not None
    })
    tags = normalize_freeform_tags([
        "report",
        "review:promoted",
        *[f"ttp:{value}" for value in technique_ids],
        *[f"actor:{value}" for value in actor_ids],
        *[f"cve:{value}" for value in cve_ids],
    ])
    indicator_candidates = [
        (claim, {
            "value": _claim_value(claim),
            "indicator_type": str(
                _metadata(claim).get("indicator_type")
                or _metadata(claim).get("type")
                or claim.get("subject")
                or "unknown"
            )[:80],
            "claim_key": str(claim.get("claim_key") or ""),
            "evidence": str(claim.get("evidence_text") or "")[:500],
        })
        for claim in indicators
        if _indicator_value_valid(
            _claim_value(claim),
            _normalize_indicator_type(
                _metadata(claim).get("indicator_type") or _metadata(claim).get("type")
            ),
        )
    ]
    accepted_indicator_rows = [candidate for _claim, candidate in indicator_candidates]

    intake = await _report_intake(db, session, result)
    previous_active = (intake.provenance or {}).get("active_promotion")
    if (
        isinstance(previous_active, dict)
        and previous_active.get("promotion_id") == str(promotion.id)
        and isinstance(previous_active.get("pre_projection"), dict)
    ):
        pre_projection = previous_active["pre_projection"]
    else:
        pre_projection = {
            "status": intake.status,
            "source_reliability": intake.source_reliability,
            "actor_ids": list(intake.actor_ids or []),
            "technique_ids": list(intake.technique_ids or []),
            "indicators": list(intake.indicators or []),
            "tags": list(intake.tags or []),
        }
    intake.status = "promoted"
    intake.technique_ids = technique_ids
    intake.actor_ids = actor_ids
    intake.indicators = accepted_indicator_rows
    intake.tags = tags
    intake.source_reliability = "reviewed"
    accepted_summary = "\n".join(
        _statement(claim) for claim in claims if _statement(claim)
    )[:5_000]
    if accepted_summary:
        intake.summary = accepted_summary
    intake.provenance = {
        **(intake.provenance or {}),
        "analysis_session_id": str(session.id),
        "active_promotion": {
            "promotion_id": str(promotion.id),
            "review_id": str(promotion.review_id),
            "review_revision": promotion.review_revision,
            "policy_version": promotion.policy_version,
            "source_checksum": promotion.source_checksum,
            "analysis_checksum": promotion.analysis_checksum,
            "manifest_checksum": promotion.manifest_checksum,
            "pre_projection": pre_projection,
        },
    }
    await db.flush()

    provenance_id = str(promotion.id)
    await _link_promotion_tagged_entities(
        db,
        entity_type="analysis_report",
        entity_id=intake.id,
        tags=tags,
        promotion_id=provenance_id,
        confidence=100,
        evidence=promotion.manifest_checksum,
    )

    ioc_source_id = _promotion_source_id(promotion)
    await db.execute(
        insert(IOCSource)
        .values(
            source_id=ioc_source_id,
            label=f"Promoted report {str(session.id)[:8]}",
            kind="reviewed-report",
            url=(intake.url or "")[:500],
            enabled=True,
            sync_status="promoted",
            sync_error="",
        )
        .on_conflict_do_update(
            index_elements=["source_id"],
            set_={
                "label": f"Promoted report {str(session.id)[:8]}",
                "url": (intake.url or "")[:500],
                "enabled": True,
                "sync_status": "promoted",
                "sync_error": "",
            },
        )
    )
    materialized_ioc_ids: list[int] = []
    for claim, candidate in indicator_candidates:
        metadata = _metadata(claim)
        raw_technique_ids = metadata.get("technique_ids")
        technique_values = raw_technique_ids if isinstance(raw_technique_ids, list) else []
        item = IOCImportItem(
            value=candidate["value"],
            indicator_type=candidate["indicator_type"],
            source=ioc_source_id,
            source_url=intake.url or "",
            confidence=_bounded_confidence(metadata.get("confidence")),
            tlp=str(session.tlp or "TLP:AMBER").removeprefix("TLP:").lower(),
            technique_ids=[
                str(value).upper()
                for value in technique_values
                if isinstance(value, str)
            ][:50],
            tags=["review:promoted", "source:report"],
            description=_statement(claim) or candidate["evidence"],
            raw={
                "analysis_session_id": str(session.id),
                "promotion_id": str(promotion.id),
                "review_id": str(promotion.review_id),
                "claim_key": candidate["claim_key"],
                "manifest_checksum": promotion.manifest_checksum,
                "promotion_targets": list(promotion.targets or []),
            },
        )
        indicator_id, _inserted = await _upsert_indicator(
            db,
            item,
            allow_report_promotion_source=True,
        )
        materialized_ioc_ids.append(indicator_id)
        await _link_promotion_tagged_entities(
            db,
            entity_type="ioc",
            entity_id=indicator_id,
            tags=item.tags or [],
            promotion_id=provenance_id,
            confidence=item.confidence,
            evidence=item.description,
        )
        await link_entities(
            db,
            source_type="analysis_report",
            source_id=intake.id,
            relationship_type="contains-indicator",
            target_type="ioc",
            target_id=indicator_id,
            provenance_type="report_promotion",
            provenance_id=provenance_id,
            confidence=item.confidence,
            evidence=item.description,
            attributes={"claim_key": candidate["claim_key"]},
        )

    return {
        "report_intake_id": str(intake.id),
        "technique_count": len(technique_ids),
        "actor_count": len(actor_ids),
        "indicator_count": len(materialized_ioc_ids),
        "vulnerability_count": len(cve_ids),
        "ioc_ids": materialized_ioc_ids,
    }


async def withdraw_report_promotion(
    db: AsyncSession,
    promotion: ReportPromotion,
) -> dict[str, Any]:
    """Withdraw materialized projections without deleting review history."""

    provenance_id = str(promotion.id)
    ioc_source_id = _promotion_source_id(promotion)
    ioc_ids = list((await db.execute(
        select(IOCIndicator.id).where(IOCIndicator.source_id == ioc_source_id)
    )).scalars().all())

    await db.execute(
        delete(IntelligenceRelationship).where(
            (IntelligenceRelationship.provenance_type == "report_promotion")
            & (IntelligenceRelationship.provenance_id == provenance_id)
        )
    )
    await db.execute(
        delete(IntelligenceEntityTag).where(
            (IntelligenceEntityTag.source_type == "report_promotion")
            & (IntelligenceEntityTag.source_id == provenance_id)
        )
    )
    if ioc_ids:
        string_ids = [str(value) for value in ioc_ids]
        await db.execute(
            delete(IntelligenceRelationship).where(
                ((IntelligenceRelationship.source_type == "ioc") & (IntelligenceRelationship.source_id.in_(string_ids)))
                | ((IntelligenceRelationship.target_type == "ioc") & (IntelligenceRelationship.target_id.in_(string_ids)))
            )
        )
        await db.execute(
            delete(IntelligenceEntityTag).where(
                (IntelligenceEntityTag.entity_type == "ioc")
                & (IntelligenceEntityTag.entity_id.in_(string_ids))
            )
        )
    source = await db.get(IOCSource, ioc_source_id)
    if source is not None:
        await db.delete(source)

    intake = await db.scalar(
        select(ReportIntake)
        .where(ReportIntake.analysis_session_id == promotion.session_id)
        .order_by(ReportIntake.updated_at.desc(), ReportIntake.id.desc())
        .limit(1)
    )
    if intake is not None:
        active = (intake.provenance or {}).get("active_promotion")
        if isinstance(active, dict) and active.get("promotion_id") == provenance_id:
            snapshot = active.get("pre_projection") if isinstance(active.get("pre_projection"), dict) else {}
            result = await db.scalar(
                select(AnalysisResult)
                .where(AnalysisResult.session_id == promotion.session_id)
                .order_by(AnalysisResult.created_at.desc(), AnalysisResult.id.desc())
                .limit(1)
            )
            intake.status = str(snapshot.get("status") or "draft")
            if intake.status == "promoted":
                intake.status = "draft"
            intake.source_reliability = str(snapshot.get("source_reliability") or "unknown")
            intake.technique_ids = list(snapshot.get("technique_ids") or [])
            intake.actor_ids = list(snapshot.get("actor_ids") or [])
            intake.indicators = list(snapshot.get("indicators") or [])
            intake.tags = normalize_freeform_tags(list(snapshot.get("tags") or ["report"]))
            if result is not None:
                intake.summary = (result.summary or "")[:5_000]
            intake.provenance = {
                **(intake.provenance or {}),
                "active_promotion": None,
                "last_revoked_promotion_id": provenance_id,
            }

    return {
        "report_intake_id": str(intake.id) if intake is not None else None,
        "withdrawn_ioc_count": len(ioc_ids),
    }
