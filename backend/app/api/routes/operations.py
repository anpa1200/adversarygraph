from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import Field, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.core.payload_limits import BoundedPayloadModel
from app.models.operations import DetectionCandidate, Investigation, ReportIntake, TrackedActor
from app.services.auth import TeamUser, analyst, audit, require_permission

router = APIRouter(prefix="/operations", tags=["Operational Intelligence"])
manage_operations_intel = require_permission("manage_intel")
manage_operations_detections = require_permission("manage_detections")
run_operations_analysis = require_permission("run_analysis")


_REVIEW_GATE_DEFERRED = {
    "status": "deferred",
    "reason": "Report intelligence is not eligible for retrohunt until Review Gate promotion.",
}


class InvestigationBody(BoundedPayloadModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str = Field("", max_length=100_000)
    status: str = Field("active", max_length=30)
    domain: str = Field("enterprise-attack", max_length=50)
    actor_ids: list[str] = Field(default_factory=list, max_length=500)
    technique_ids: list[str] = Field(default_factory=list, max_length=500)
    report_ids: list[str] = Field(default_factory=list, max_length=500)
    evidence_nodes: list[dict] = Field(default_factory=list, max_length=1000)
    evidence_edges: list[dict] = Field(default_factory=list, max_length=1000)
    timeline: list[dict] = Field(default_factory=list, max_length=1000)


class InvestigationStoryBody(BoundedPayloadModel):
    report_id: str = Field(..., min_length=1, max_length=200)
    provider: str = Field("local", max_length=40)
    model: str | None = Field(None, max_length=100)
    cloud_processing_acknowledged: bool = False


class InvestigationMarkingBody(BoundedPayloadModel):
    tlp: Literal["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"]
    reason: str = Field(min_length=12, max_length=1000)


class IntakeBody(BoundedPayloadModel):
    title: str = Field(..., min_length=1, max_length=500)
    url: str = Field("", max_length=1000)
    publisher: str = Field("", max_length=255)
    status: str = Field(
        "pending",
        max_length=30,
        pattern="^(pending|stored|analyzed|under_review|reviewed|rejected|revoked)$",
    )
    summary: str = Field("", max_length=100_000)
    source_reliability: str = Field("unknown", max_length=30)
    actor_ids: list[str] = Field(default_factory=list, max_length=500)
    technique_ids: list[str] = Field(default_factory=list, max_length=500)
    indicators: list[dict] = Field(default_factory=list, max_length=2000)
    analyst_notes: str = Field("", max_length=100_000)


class DetectionBody(BoundedPayloadModel):
    title: str = Field(..., min_length=1, max_length=500)
    technique_id: str = Field(..., min_length=2, max_length=30)
    status: str = Field("idea", max_length=30)
    owner: str = Field("", max_length=255)
    telemetry: list[str] = Field(default_factory=list, max_length=500)
    query_language: str = Field("", max_length=50)
    query: str = Field("", max_length=250_000)
    validation_notes: str = Field("", max_length=100_000)
    source_refs: list[str] = Field(default_factory=list, max_length=1000)


class TrackBody(BoundedPayloadModel):
    actor_id: str = Field(..., min_length=2, max_length=30)
    actor_name: str = Field("", max_length=255)
    snapshot: dict = Field(default_factory=dict, max_length=1000)


def out(row):
    return {column.name: getattr(row, column.name) for column in row.__table__.columns}


async def get_or_404(db: AsyncSession, model, item_id: str):
    try:
        uid = uuid.UUID(item_id)
    except ValueError:
        raise HTTPException(400, "Invalid ID")
    row = await db.get(model, uid)
    if not row:
        raise HTTPException(404, "Item not found")
    return row


@router.get("/investigations")
async def investigations(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
):
    rows = await db.execute(
        select(Investigation)
        .order_by(Investigation.updated_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return [out(row) for row in rows.scalars().all()]


@router.post("/investigations", status_code=201)
async def create_investigation(body: InvestigationBody, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_operations_intel)):
    row = Investigation(**body.model_dump(), tlp="TLP:AMBER+STRICT")
    db.add(row); await db.flush()
    await audit(db, user, "operations.create_investigation", "investigation", str(row.id), {"name": row.name})
    await db.commit(); await db.refresh(row)
    return out(row)


@router.put("/investigations/{item_id}")
async def update_investigation(item_id: str, body: InvestigationBody, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_operations_intel)):
    row = await get_or_404(db, Investigation, item_id)
    for key, value in body.model_dump().items(): setattr(row, key, value)
    await audit(db, user, "operations.update_investigation", "investigation", item_id)
    await db.commit(); await db.refresh(row)
    return out(row)


@router.patch("/investigations/{item_id}/marking", dependencies=[Depends(require_permission("export_data"))])
async def mark_investigation(item_id: str, body: InvestigationMarkingBody, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_operations_intel)):
    row = await get_or_404(db, Investigation, item_id)
    previous = row.tlp or "TLP:AMBER+STRICT"
    row.tlp = body.tlp
    await audit(db, user, "operations.investigation.marking", "investigation", item_id,
                {"previous": previous, "tlp": body.tlp, "reason": body.reason,
                 "scope": "Workspace only; linked source restrictions remain authoritative"})
    await db.commit(); await db.refresh(row)
    return out(row)


@router.delete("/investigations/{item_id}", status_code=204)
async def delete_investigation(item_id: str, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_operations_intel)):
    row = await get_or_404(db, Investigation, item_id)
    await audit(db, user, "operations.delete_investigation", "investigation", item_id)
    await db.delete(row); await db.commit()


@router.get("/investigations/{item_id}/summary/preflight")
async def summary_preflight(item_id: str, report_id: str = Query(min_length=1, max_length=200),
                            db: AsyncSession = Depends(get_session), _: TeamUser = Depends(manage_operations_intel)):
    from app.services import investigation_story, threat_hunting_ai
    row = await get_or_404(db, Investigation, item_id)
    pack = await investigation_story.build_pack(db, row, report_id)
    providers = threat_hunting_ai.provider_catalog()
    for provider in providers:
        if provider["remote"] and pack["effective_tlp"] in {"TLP:AMBER+STRICT", "TLP:RED"}:
            provider.update(available=False, status="blocked_by_classification", reason="Workspace or linked source prohibits cloud disclosure")
    return {"effective_tlp": pack["effective_tlp"], "coverage": pack["coverage"],
            "source_sha256": pack["source_sha256"], "providers": providers,
            "scope": "No model call, provider lookup, or source reclassification was performed"}


@router.post("/investigations/{item_id}/summary", dependencies=[Depends(run_operations_analysis)])
async def summarize_investigation(
    item_id: str,
    body: InvestigationStoryBody,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(manage_operations_intel),
):
    from app.services import investigation_story, threat_hunting_ai

    row = await get_or_404(db, Investigation, item_id)
    if len(row.evidence_nodes or []) >= 1000:
        raise HTTPException(409, "Investigation has reached its evidence-node limit")
    pack = await investigation_story.build_pack(db, row, body.report_id)
    adapter = threat_hunting_ai.create_adapter(
        body.provider, body.model, effective_tlp=pack["effective_tlp"],
        cloud_processing_acknowledged=body.cloud_processing_acknowledged,
    )
    # Unknown workspace classification defaults to AMBER+STRICT. The adapter
    # rejects remote egress before this point, even with client acknowledgement.
    await audit(db, user, "operations.summary.attempt", "investigation", item_id, {
        "report_id": body.report_id, "source_sha256": pack["source_sha256"],
        "provider": adapter.provider, "model": adapter.model,
    })
    await db.commit()
    try:
        summary = await investigation_story.generate_story(pack, adapter)
    except threat_hunting_ai.AIProviderTimeoutError:
        raise HTTPException(504, "Summary provider timed out. No summary was saved.")
    except threat_hunting_ai.AIProviderCallError as exc:
        await audit(db, user, "operations.summary.provider_failed", "investigation", item_id,
                    {"provider": adapter.provider, "model": adapter.model, "category": exc.category, "http_status": exc.status_code, "rate_details": exc.rate_details,
                     "prior_attempts": getattr(exc, "prior_attempts", [])})
        await db.commit()
        raise HTTPException(503 if exc.category in {"rate_limited", "quota_exhausted"} else 502,
                            f"Summary provider failed ({exc.category}). Quota details: {exc.rate_details}. No summary was saved.")
    except ValueError as exc:
        code = getattr(exc, "code", investigation_story.validation_error_code(exc))
        await audit(db, user, "operations.summary.validation_failed", "investigation", item_id,
                    {"provider": adapter.provider, "model": adapter.model, "code": code,
                     "attempts": getattr(exc, "attempts", [])})
        await db.commit()
        raise HTTPException(502, f"Summary failed evidence or structure validation ({code}). No summary was saved; the original report is unchanged.")
    # Do not hold a transaction/row lock across a slow provider call. Re-read
    # after generation, then append under lock without replacing other work.
    current = await db.scalar(select(Investigation).where(Investigation.id == uuid.UUID(item_id))
                              .with_for_update().execution_options(populate_existing=True))
    if current is None:
        raise HTTPException(409, "Investigation was removed while its summary was generated")
    current_pack = await investigation_story.build_pack(db, current, body.report_id)
    if current_pack["source_sha256"] != pack["source_sha256"]:
        raise HTTPException(409, "Investigation changed while summarizing. Generate a new summary from the updated evidence.")
    nodes = [*(current.evidence_nodes or []), summary]
    # Use the same aggregate limits as ordinary investigation writes.
    try:
        InvestigationBody(**{**{key: getattr(current, key) for key in InvestigationBody.model_fields}, "evidence_nodes": nodes})
    except ValidationError:
        raise HTTPException(409, "Summary would exceed investigation storage limits. Split the investigation first.")
    current.evidence_nodes = nodes
    await audit(db, user, "operations.summary.created", "investigation", item_id, {
        "summary_id": summary["id"], "source_sha256": summary["source_sha256"],
        "report_id": body.report_id, "provider": adapter.provider, "model": adapter.model,
    })
    await db.commit()
    return summary


@router.get("/investigations/{item_id}/summaries/{summary_id}")
async def investigation_summary_snapshot(
    item_id: str, summary_id: str,
    db: AsyncSession = Depends(get_session), _: TeamUser = Depends(analyst),
):
    from app.services.investigation_story import build_pack

    row = await get_or_404(db, Investigation, item_id)
    nodes = [n for n in row.evidence_nodes or [] if n.get("type") == "investigation-summary" and n.get("id") == summary_id]
    if len(nodes) != 1:
        raise HTTPException(404, "Summary not found")
    summary = nodes[0]
    try:
        pack = await build_pack(db, row, str(summary.get("report_id", "")))
        stale = pack["source_sha256"] != summary.get("source_sha256")
    except HTTPException:
        stale = True
    return {"summary": summary, "stale": stale, "status": "source-changed" if stale else "snapshot-current"}


@router.get("/intake")
async def intake(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
):
    rows = await db.execute(
        select(ReportIntake)
        .order_by(ReportIntake.updated_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return [out(row) for row in rows.scalars().all()]


@router.post("/intake", status_code=201)
async def create_intake(body: IntakeBody, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_operations_intel)):
    row = ReportIntake(**body.model_dump()); db.add(row); await db.flush()
    await audit(db, user, "operations.create_intake", "report_intake", str(row.id), {"title": row.title})
    await db.commit(); await db.refresh(row)
    payload = out(row)
    payload["asset_retrohunt"] = dict(_REVIEW_GATE_DEFERRED)
    return payload


@router.put("/intake/{item_id}")
async def update_intake(item_id: str, body: IntakeBody, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_operations_intel)):
    row = await get_or_404(db, ReportIntake, item_id)
    if row.analysis_session_id is not None:
        raise HTTPException(
            409,
            "Linked report intake metadata must be changed through Reports / Research so the Review Gate revision is invalidated",
        )
    if row.status == "promoted":
        raise HTTPException(409, "Promoted reports must be changed through the Review Gate revocation workflow")
    for key, value in body.model_dump().items(): setattr(row, key, value)
    await audit(db, user, "operations.update_intake", "report_intake", item_id)
    await db.commit(); await db.refresh(row)
    payload = out(row)
    payload["asset_retrohunt"] = dict(_REVIEW_GATE_DEFERRED)
    return payload


@router.delete("/intake/{item_id}", status_code=204)
async def delete_intake(item_id: str, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_operations_intel)):
    row = await get_or_404(db, ReportIntake, item_id)
    if row.analysis_session_id is not None:
        raise HTTPException(
            409,
            "Linked report intake records are owned by Reports / Research and cannot be deleted through Operations",
        )
    if row.status == "promoted":
        raise HTTPException(409, "Revoke the report promotion before deleting its intake record")
    await audit(db, user, "operations.delete_intake", "report_intake", item_id)
    await db.delete(row); await db.commit()


@router.get("/detections")
async def detections(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
):
    rows = await db.execute(
        select(DetectionCandidate)
        .order_by(DetectionCandidate.updated_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return [out(row) for row in rows.scalars().all()]


@router.post("/detections", status_code=201)
async def create_detection(body: DetectionBody, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_operations_detections)):
    row = DetectionCandidate(**body.model_dump()); db.add(row); await db.flush()
    await audit(db, user, "operations.create_detection", "detection_candidate", str(row.id), {"title": row.title, "technique_id": row.technique_id})
    await db.commit(); await db.refresh(row); return out(row)


@router.put("/detections/{item_id}")
async def update_detection(item_id: str, body: DetectionBody, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_operations_detections)):
    row = await get_or_404(db, DetectionCandidate, item_id)
    for key, value in body.model_dump().items(): setattr(row, key, value)
    await audit(db, user, "operations.update_detection", "detection_candidate", item_id)
    await db.commit(); await db.refresh(row); return out(row)


@router.delete("/detections/{item_id}", status_code=204)
async def delete_detection(item_id: str, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_operations_detections)):
    row = await get_or_404(db, DetectionCandidate, item_id)
    await audit(db, user, "operations.delete_detection", "detection_candidate", item_id)
    await db.delete(row); await db.commit()


@router.get("/tracked-actors")
async def tracked_actors(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
):
    rows = await db.execute(
        select(TrackedActor)
        .order_by(TrackedActor.updated_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return [out(row) for row in rows.scalars().all()]


@router.post("/tracked-actors", status_code=201)
async def track_actor(body: TrackBody, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_operations_intel)):
    existing = await db.execute(select(TrackedActor).where(TrackedActor.actor_id == body.actor_id.upper()))
    row = existing.scalar_one_or_none()
    now = datetime.now(timezone.utc).isoformat()
    action = "operations.update_tracked_actor"
    if row:
        previous = row.last_snapshot or {}
        added = sorted(set(body.snapshot.get("technique_ids", [])) - set(previous.get("technique_ids", [])))
        removed = sorted(set(previous.get("technique_ids", [])) - set(body.snapshot.get("technique_ids", [])))
        if added or removed:
            row.change_log = [{"at": now, "added_techniques": added, "removed_techniques": removed}, *(row.change_log or [])][:100]
        row.last_snapshot = body.snapshot
        row.actor_name = body.actor_name or row.actor_name
    else:
        action = "operations.create_tracked_actor"
        row = TrackedActor(actor_id=body.actor_id.upper(), actor_name=body.actor_name, last_snapshot=body.snapshot, change_log=[])
        db.add(row)
    await db.flush()
    await audit(db, user, action, "tracked_actor", str(row.id), {"actor_id": row.actor_id})
    await db.commit(); await db.refresh(row); return out(row)


@router.delete("/tracked-actors/{item_id}", status_code=204)
async def delete_tracked_actor(item_id: str, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_operations_intel)):
    row = await get_or_404(db, TrackedActor, item_id)
    await audit(db, user, "operations.delete_tracked_actor", "tracked_actor", item_id)
    await db.delete(row); await db.commit()
