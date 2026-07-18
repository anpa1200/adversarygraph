from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.core.payload_limits import BoundedPayloadModel
from app.models.operations import DetectionCandidate, Investigation, ReportIntake, TrackedActor
from app.services.asset_intel import retrohunt_assets
from app.services.auth import TeamUser, analyst, audit, require_permission

router = APIRouter(prefix="/operations", tags=["Operational Intelligence"])
manage_operations_intel = require_permission("manage_intel")
manage_operations_detections = require_permission("manage_detections")


async def _retrohunt_assets_after_intake(db: AsyncSession) -> dict | None:
    try:
        return await retrohunt_assets(db)
    except Exception:
        return None


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


class IntakeBody(BoundedPayloadModel):
    title: str = Field(..., min_length=1, max_length=500)
    url: str = Field("", max_length=1000)
    publisher: str = Field("", max_length=255)
    status: str = Field("pending", max_length=30)
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
    row = Investigation(**body.model_dump())
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


@router.delete("/investigations/{item_id}", status_code=204)
async def delete_investigation(item_id: str, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_operations_intel)):
    row = await get_or_404(db, Investigation, item_id)
    await audit(db, user, "operations.delete_investigation", "investigation", item_id)
    await db.delete(row); await db.commit()


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
    asset_retrohunt = await _retrohunt_assets_after_intake(db)
    await audit(db, user, "operations.create_intake", "report_intake", str(row.id), {"title": row.title})
    await db.commit(); await db.refresh(row)
    payload = out(row)
    payload["asset_retrohunt"] = asset_retrohunt
    return payload


@router.put("/intake/{item_id}")
async def update_intake(item_id: str, body: IntakeBody, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_operations_intel)):
    row = await get_or_404(db, ReportIntake, item_id)
    for key, value in body.model_dump().items(): setattr(row, key, value)
    asset_retrohunt = await _retrohunt_assets_after_intake(db)
    await audit(db, user, "operations.update_intake", "report_intake", item_id)
    await db.commit(); await db.refresh(row)
    payload = out(row)
    payload["asset_retrohunt"] = asset_retrohunt
    return payload


@router.delete("/intake/{item_id}", status_code=204)
async def delete_intake(item_id: str, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_operations_intel)):
    row = await get_or_404(db, ReportIntake, item_id)
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
