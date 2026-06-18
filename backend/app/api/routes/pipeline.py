from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.models.operations import ReportIntake
from app.models.pipeline import AuditEvent, CollectionRun, CollectionSource, DetectionVersion, EnrichmentResult, Observable
from app.services.atlas import normalize_atlas
from app.services.auth import TeamUser, analyst, audit, current_user
from app.services.collection import extract_observables, fetch_rss, misp_reports, stix_reports
from app.services.detection_feeds import ensure_default_detection_feeds, sync_detection_rule_feed
from app.services.detections import generate_detection, validate_detection
from app.services.enrichment import enrich_observable
from app.services.sandbox_feeds import list_sandbox_behaviors, sync_sandbox_feed

router = APIRouter(prefix="/pipeline", tags=["Collection and Detection Pipeline"])


class SourceBody(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    kind: str = Field(..., pattern="^(rss|taxii|misp|atlas|sigma|yara|sandbox)$")
    url: str = ""
    enabled: bool = True
    interval_minutes: int = Field(default=60, ge=5, le=10080)
    config: dict = Field(default_factory=dict)


class ObservableBody(BaseModel):
    type: str = Field(..., min_length=2, max_length=30)
    value: str = Field(..., min_length=1, max_length=2000)
    status: str = "new"
    confidence: int = Field(default=0, ge=0, le=100)
    tags: list[str] = Field(default_factory=list)
    source_refs: list[str] = Field(default_factory=list)


class DetectionBody(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    technique_id: str = Field(..., min_length=2, max_length=30)
    format: str = "sigma"
    telemetry: list[str] = Field(default_factory=list)
    detection_id: str | None = None


class ValidationBody(BaseModel):
    format: str
    content: str


def out(row):
    return {column.name: getattr(row, column.name) for column in row.__table__.columns}


async def source_or_404(db: AsyncSession, source_id: str) -> CollectionSource:
    try:
        row = await db.get(CollectionSource, uuid.UUID(source_id))
    except ValueError:
        row = None
    if not row:
        raise HTTPException(404, "Collection source not found")
    return row


async def add_observable(db: AsyncSession, item: dict, source_ref: str = "") -> tuple[Observable, bool]:
    kind = item.get("type", "unknown").lower()
    value = str(item.get("value", "")).strip()
    normalized = str(item.get("normalized_value", value)).lower().strip()
    existing = await db.execute(select(Observable).where(Observable.type == kind, Observable.normalized_value == normalized))
    row = existing.scalar_one_or_none()
    if row:
        row.last_seen_at = datetime.now(timezone.utc)
        if source_ref and source_ref not in row.source_refs:
            row.source_refs = [*row.source_refs, source_ref]
        return row, False
    row = Observable(type=kind, value=value, normalized_value=normalized, source_refs=[source_ref] if source_ref else [])
    db.add(row)
    return row, True


async def ingest_reports(db: AsyncSession, reports: list[dict], publisher: str, source_ref: str) -> dict:
    created = observable_count = 0
    for item in reports:
        url = item.get("url", "")
        existing = await db.execute(select(ReportIntake).where(ReportIntake.url == url, ReportIntake.title == item["title"]))
        if not existing.scalar_one_or_none():
            indicators = item.get("indicators") or extract_observables(f'{item.get("title", "")} {item.get("summary", "")}')
            db.add(ReportIntake(
                title=item["title"], url=url, publisher=publisher, status="pending",
                summary=item.get("summary", ""), source_reliability="unknown", indicators=indicators,
                analyst_notes=f"Automated intake from {source_ref}. Review before promotion.",
            ))
            created += 1
            for indicator in indicators:
                _, was_created = await add_observable(db, indicator, url or source_ref)
                observable_count += int(was_created)
    return {"items_created": created, "observables_created": observable_count}


@router.get("/me")
async def me(user: TeamUser = Depends(current_user)):
    return {"name": user.name, "roles": user.roles}


@router.get("/sources")
async def sources(db: AsyncSession = Depends(get_session)):
    rows = await db.execute(select(CollectionSource).order_by(CollectionSource.updated_at.desc()))
    return [out(row) for row in rows.scalars().all()]


@router.post("/sources", status_code=201)
async def create_source(body: SourceBody, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    row = CollectionSource(**body.model_dump())
    db.add(row); await db.flush()
    await audit(db, user, "source.create", "collection_source", str(row.id), {"kind": row.kind, "name": row.name})
    await db.commit(); await db.refresh(row)
    return out(row)


@router.put("/sources/{source_id}")
async def update_source(source_id: str, body: SourceBody, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    row = await source_or_404(db, source_id)
    for key, value in body.model_dump().items():
        setattr(row, key, value)
    await audit(db, user, "source.update", "collection_source", source_id)
    await db.commit(); await db.refresh(row)
    return out(row)


@router.post("/sources/{source_id}/run")
async def run_source(source_id: str, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    source = await source_or_404(db, source_id)
    if source.kind in {"sigma", "yara"}:
        run = await sync_detection_rule_feed(db, source)
        await audit(db, user, "rule_feed.sync", "collection_source", source_id, {"status": run.status, "kind": source.kind})
        await db.commit()
        return out(run)
    if source.kind == "sandbox":
        run = await sync_sandbox_feed(db, source)
        await audit(db, user, "sandbox_feed.sync", "collection_source", source_id, {"status": run.status})
        await db.commit()
        return out(run)
    run = CollectionRun(source_id=source.id)
    db.add(run); await db.flush()
    try:
        if source.kind != "rss":
            raise ValueError(f"{source.kind.upper()} sources use the reviewed JSON import endpoint")
        reports = await fetch_rss(source.url)
        result = await ingest_reports(db, reports, source.name, source.url)
        run.status = "complete"; run.items_seen = len(reports)
        run.items_created = result["items_created"]; run.observables_created = result["observables_created"]
        source.last_run_at = datetime.now(timezone.utc)
    except Exception as exc:
        run.status = "failed"; run.error = str(exc)[:2000]
    run.completed_at = datetime.now(timezone.utc)
    await audit(db, user, "source.run", "collection_source", source_id, {"status": run.status})
    await db.commit(); await db.refresh(run)
    return out(run)


@router.post("/rule-feeds/defaults")
async def create_default_rule_feeds(db: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    rows = await ensure_default_detection_feeds(db)
    await audit(db, user, "rule_feed.defaults", "collection_source", details={"count": len(rows)})
    await db.commit()
    return [out(row) for row in rows]


@router.get("/runs")
async def runs(db: AsyncSession = Depends(get_session)):
    rows = await db.execute(select(CollectionRun).order_by(CollectionRun.started_at.desc()).limit(100))
    return [out(row) for row in rows.scalars().all()]


@router.post("/import/stix")
async def import_stix(bundle: dict, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    reports = stix_reports(bundle)
    result = await ingest_reports(db, reports, "STIX/TAXII import", "manual STIX/TAXII import")
    await audit(db, user, "import.stix", "report_intake", details={"seen": len(reports), **result})
    await db.commit()
    return {"items_seen": len(reports), **result}


@router.post("/import/misp")
async def import_misp(event: dict, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    reports = misp_reports(event)
    result = await ingest_reports(db, reports, "MISP import", "manual MISP import")
    await audit(db, user, "import.misp", "report_intake", details={"seen": len(reports), **result})
    await db.commit()
    return {"items_seen": len(reports), **result}


@router.post("/import/atlas")
async def import_atlas(payload: dict, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    result = normalize_atlas(payload)
    await audit(db, user, "import.atlas", "framework", "atlas", {"technique_count": result["technique_count"]})
    await db.commit()
    return result


@router.get("/observables")
async def observables(db: AsyncSession = Depends(get_session)):
    rows = await db.execute(select(Observable).order_by(Observable.last_seen_at.desc()).limit(500))
    return [out(row) for row in rows.scalars().all()]


@router.get("/sandbox/behaviors")
async def sandbox_behaviors(limit: int = 100, db: AsyncSession = Depends(get_session)):
    return await list_sandbox_behaviors(db, limit=limit)


@router.post("/observables", status_code=201)
async def create_observable(body: ObservableBody, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    row, created = await add_observable(db, {**body.model_dump(), "normalized_value": body.value.lower().strip()})
    row.status = body.status; row.confidence = body.confidence; row.tags = body.tags; row.source_refs = body.source_refs
    await audit(db, user, "observable.create" if created else "observable.update", "observable", str(row.id))
    await db.commit(); await db.refresh(row)
    return out(row)


@router.post("/observables/{observable_id}/enrich")
async def enrich(observable_id: str, provider: str = "auto", db: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    try:
        row = await db.get(Observable, uuid.UUID(observable_id))
    except ValueError:
        row = None
    if not row:
        raise HTTPException(404, "Observable not found")
    try:
        result = await enrich_observable(row.type, row.normalized_value, provider)
    except Exception as exc:
        result = {"provider": provider, "status": "failed", "verdict": "unknown", "confidence": 0, "raw_data": {"error": str(exc)}}
    enrichment = EnrichmentResult(observable_id=row.id, **result)
    db.add(enrichment)
    await audit(db, user, "observable.enrich", "observable", observable_id, {"provider": result["provider"], "status": result["status"]})
    await db.commit(); await db.refresh(enrichment)
    return out(enrichment)


@router.post("/detections/generate", status_code=201)
async def generate(body: DetectionBody, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    try:
        content = generate_detection(body.title, body.technique_id.upper(), body.format, body.telemetry)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    validation = validate_detection(body.format, content)
    try:
        detection_id = uuid.UUID(body.detection_id) if body.detection_id else None
    except ValueError:
        raise HTTPException(400, "Invalid detection ID")
    row = DetectionVersion(detection_id=detection_id, title=body.title, technique_id=body.technique_id.upper(), format=body.format.lower(), content=content, validation=validation, created_by=user.name)
    db.add(row); await db.flush()
    await audit(db, user, "detection.generate", "detection_version", str(row.id), {"format": row.format, "technique_id": row.technique_id})
    await db.commit(); await db.refresh(row)
    return out(row)


@router.post("/detections/validate")
async def validate(body: ValidationBody, user: TeamUser = Depends(current_user)):
    return validate_detection(body.format, body.content)


@router.get("/detections/versions")
async def detection_versions(db: AsyncSession = Depends(get_session)):
    rows = await db.execute(select(DetectionVersion).order_by(DetectionVersion.created_at.desc()).limit(200))
    return [out(row) for row in rows.scalars().all()]


@router.get("/audit")
async def audit_events(db: AsyncSession = Depends(get_session), user: TeamUser = Depends(current_user)):
    rows = await db.execute(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(500))
    return [out(row) for row in rows.scalars().all()]
