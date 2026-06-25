from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, func, or_, cast
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.models.retrohunt import RetroHuntSignal

router = APIRouter(prefix="/retrohunt", tags=["RetroHunt"])


# ── Output schemas ────────────────────────────────────────────────────────────

class SignalOut(BaseModel):
    id: int
    source: str
    signal_type: str
    external_id: str
    title: str
    body: str
    url: str
    published_at: datetime | None
    severity: str
    cvss_score: float | None
    sector_tags: list[str]
    tech_tags: list[str]
    cve_ids: list[str]
    product_tags: list[str]

    model_config = {"from_attributes": True}


class StatsOut(BaseModel):
    total: int
    by_source: dict[str, int]
    by_severity: dict[str, int]
    by_signal_type: dict[str, int]
    latest_published_at: datetime | None


class CollectOut(BaseModel):
    task_id: str
    status: str


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/signals", response_model=list[SignalOut])
async def list_signals(
    q: str | None = Query(None, description="Keyword search in title + body"),
    source: str | None = Query(None),
    signal_type: str | None = Query(None),
    severity: str | None = Query(None),
    sector: str | None = Query(None, description="Filter by sector_id tag"),
    tech: str | None = Query(None, description="Filter by tech_tag"),
    cve: str | None = Query(None, description="Filter by CVE ID"),
    days: int = Query(90, ge=1, le=3650),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_session),
) -> list[RetroHuntSignal]:
    stmt = select(RetroHuntSignal)

    since = datetime.now(timezone.utc) - timedelta(days=days)
    stmt = stmt.where(
        or_(
            RetroHuntSignal.published_at >= since,
            RetroHuntSignal.published_at.is_(None),
        )
    )

    if q:
        pattern = f"%{q}%"
        stmt = stmt.where(
            or_(
                RetroHuntSignal.title.ilike(pattern),
                RetroHuntSignal.body.ilike(pattern),
            )
        )
    if source:
        stmt = stmt.where(RetroHuntSignal.source == source)
    if signal_type:
        stmt = stmt.where(RetroHuntSignal.signal_type == signal_type)
    if severity:
        stmt = stmt.where(RetroHuntSignal.severity == severity)
    if sector:
        stmt = stmt.where(
            RetroHuntSignal.sector_tags.contains(cast([sector], JSONB))
        )
    if tech:
        stmt = stmt.where(
            RetroHuntSignal.tech_tags.contains(cast([tech], JSONB))
        )
    if cve:
        cve_upper = cve.upper()
        stmt = stmt.where(
            RetroHuntSignal.cve_ids.contains(cast([cve_upper], JSONB))
        )

    stmt = stmt.order_by(RetroHuntSignal.published_at.desc().nullslast())
    stmt = stmt.limit(limit).offset(offset)

    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.get("/stats", response_model=StatsOut)
async def stats(
    days: int = Query(90, ge=1, le=3650),
    db: AsyncSession = Depends(get_session),
) -> StatsOut:
    since = datetime.now(timezone.utc) - timedelta(days=days)

    total_result = await db.execute(
        select(func.count()).select_from(RetroHuntSignal).where(
            or_(RetroHuntSignal.published_at >= since, RetroHuntSignal.published_at.is_(None))
        )
    )
    total = total_result.scalar_one()

    by_source_result = await db.execute(
        select(RetroHuntSignal.source, func.count())
        .where(or_(RetroHuntSignal.published_at >= since, RetroHuntSignal.published_at.is_(None)))
        .group_by(RetroHuntSignal.source)
    )
    by_source = {row[0]: row[1] for row in by_source_result}

    by_severity_result = await db.execute(
        select(RetroHuntSignal.severity, func.count())
        .where(or_(RetroHuntSignal.published_at >= since, RetroHuntSignal.published_at.is_(None)))
        .group_by(RetroHuntSignal.severity)
    )
    by_severity = {row[0]: row[1] for row in by_severity_result}

    by_type_result = await db.execute(
        select(RetroHuntSignal.signal_type, func.count())
        .where(or_(RetroHuntSignal.published_at >= since, RetroHuntSignal.published_at.is_(None)))
        .group_by(RetroHuntSignal.signal_type)
    )
    by_signal_type = {row[0]: row[1] for row in by_type_result}

    latest_result = await db.execute(
        select(func.max(RetroHuntSignal.published_at))
    )
    latest_published_at = latest_result.scalar_one_or_none()

    return StatsOut(
        total=total,
        by_source=by_source,
        by_severity=by_severity,
        by_signal_type=by_signal_type,
        latest_published_at=latest_published_at,
    )


@router.post("/collect", response_model=CollectOut)
async def trigger_collect(
    days: int = Query(30, ge=1, le=365, description="Lookback window for collection"),
) -> CollectOut:
    from app.tasks.retrohunt import collect_all
    task = collect_all.delay(days=days)
    return CollectOut(task_id=task.id, status="queued")


@router.get("/collect/{task_id}")
async def collect_status(task_id: str) -> dict[str, Any]:
    from app.tasks.celery_app import celery_app as ca
    result = ca.AsyncResult(task_id)
    return {
        "task_id": task_id,
        "status": result.status,
        "result": result.result if result.ready() else None,
    }
