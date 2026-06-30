"""
GET  /api/sync/status          — current DB versions vs latest GitHub
POST /api/sync/trigger         — kick off a background sync via Celery
GET  /api/sync/task/{task_id}  — Celery task status
"""

from __future__ import annotations

import asyncio

import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.services.auth import TeamUser, analyst, audit, current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/sync", tags=["MITRE Sync"])


class DomainStatusOut(BaseModel):
    source: str = "mitre-attack"
    domain: str
    current_version: str | None
    latest_version: str | None
    needs_update: bool
    last_ingested: str | None
    content: list[str] = Field(default_factory=list)


class SyncSourceOut(BaseModel):
    id: str
    label: str
    status: str
    content: list[str]
    domains: list[str]
    schedule: str | None = None


class SyncStatusOut(BaseModel):
    sources: list[SyncSourceOut]
    domains: list[DomainStatusOut]
    any_updates_needed: bool


class TriggerRequest(BaseModel):
    source: str = Field(default="mitre-attack")
    domains: list[str] | None = None
    force: bool = False


class TriggerOut(BaseModel):
    task_id: str
    status: str
    source: str
    domains: list[str]
    force: bool


class IOCSyncOut(BaseModel):
    days: int
    totals: dict[str, int]
    sources: list[dict]


class CVESyncOut(BaseModel):
    days: int
    totals: dict[str, int]
    sources: list[dict]
    correlations: dict[str, int]


class DynamicSyncOut(BaseModel):
    attack: list | dict
    sector: dict | None = None
    ioc: dict | None = None
    cve: dict | None = None


MITRE_CONTENT = [
    "matrices",
    "tactics",
    "techniques",
    "sub-techniques",
    "APT groups",
    "campaigns",
    "group-technique relationships",
    "campaign-technique relationships",
    "references",
]
ATLAS_CONTENT = [
    "ATLAS matrix",
    "ATLAS tactics",
    "ATLAS techniques",
    "ATLAS sub-techniques",
    "AI system adversary behavior",
    "mitre-atlas references",
]
IOC_CONTENT = [
    "ThreatFox recent IOC sync",
    "Malpedia malware-family and actor-attribution sync",
    "AlienVault OTX actor pulse sync",
    "custom JSON/CSV/TXT IOC feeds",
    "actor IOC links",
    "IOC freshness and confidence metadata",
]
CVE_CONTENT = [
    "NVD CVE API 2.0 recent CVE/CVSS score/CWE/CPE sync",
    "CISA Known Exploited Vulnerabilities sync",
    "evidence-backed CVE-to-TTP links",
    "evidence-backed CVE-to-IOC links",
    "evidence-backed CVE-to-APT links",
]

SUPPORTED_SOURCES = {
    "mitre-attack": {
        "label": "MITRE ATT&CK and ATLAS STIX",
        "status": "active",
        "content": MITRE_CONTENT + ATLAS_CONTENT,
        "schedule": "daily at 03:00 UTC",
    },
    "ioc-intelligence": {
        "label": "IOC Intelligence",
        "status": "active",
        "content": IOC_CONTENT,
        "schedule": "manual, ThreatFox recent API supports 1-7 days",
    },
    "cve-intelligence": {
        "label": "CVE Library",
        "status": "active",
        "content": CVE_CONTENT,
        "schedule": "manual or dynamic DB sync; NVD recent window supports 1-120 days",
    },
    "other": {
        "label": "Other CTI references",
        "status": "planned",
        "content": ["external CTI feeds", "internal reference indexes"],
        "schedule": None,
    },
}


@router.get("/status", response_model=SyncStatusOut)
async def sync_status(session: AsyncSession = Depends(get_session), _: TeamUser = Depends(current_user)):
    """
    Check each configured domain: what version is in the DB vs latest on GitHub.
    The GitHub check is a lightweight API call (no download).
    """
    try:
        from app.services.attck.version_checker import get_status

        loop = asyncio.get_event_loop()
        statuses = await loop.run_in_executor(None, get_status)

        domains = [
            DomainStatusOut(
                source="mitre-attack",
                domain=s.domain,
                current_version=s.current_version,
                latest_version=s.latest_version,
                needs_update=s.needs_update,
                last_ingested=s.last_ingested,
                content=ATLAS_CONTENT if s.domain == "atlas" else MITRE_CONTENT,
            )
            for s in statuses
        ]
        sources = [
            SyncSourceOut(
                id=source_id,
                label=meta["label"],
                status=meta["status"],
                content=meta["content"],
                domains=[d.domain for d in domains] if source_id == "mitre-attack" else [],
                schedule=meta["schedule"],
            )
            for source_id, meta in SUPPORTED_SOURCES.items()
        ]
        try:
            from app.services.ioc_intel import list_ioc_sources
            from app.services.cve_intel import list_cve_sources
            ioc_sources = await list_ioc_sources(session)
            ioc_source = next((item for item in sources if item.id == "ioc-intelligence"), None)
            if ioc_source:
                healthy_statuses = {"ok", "active", "configured"}
                ioc_source.status = (
                    "active"
                    if all(item.sync_status in healthy_statuses for item in ioc_sources)
                    else "degraded"
                )
                ioc_source.content = [
                    *IOC_CONTENT,
                    *[f"{item.label}: {item.sync_status}" for item in ioc_sources],
                ]
            cve_sources = await list_cve_sources(session)
            cve_source = next((item for item in sources if item.id == "cve-intelligence"), None)
            if cve_source:
                healthy_statuses = {"ok", "active", "configured"}
                cve_source.status = (
                    "active"
                    if all(item.sync_status in healthy_statuses for item in cve_sources)
                    else "degraded"
                )
                cve_source.content = [
                    *CVE_CONTENT,
                    *[f"{item.label}: {item.sync_status}" for item in cve_sources],
                ]
        except Exception:
            pass
        return SyncStatusOut(
            sources=sources,
            domains=domains,
            any_updates_needed=any(d.needs_update for d in domains),
        )
    except Exception as exc:
        logger.error("sync status check failed: %s", exc, exc_info=True)
        raise HTTPException(500, "Operation failed. See server logs.") from exc


@router.post("/trigger", response_model=TriggerOut)
async def trigger_sync(body: TriggerRequest | None = None, session: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    """
    Submit a Celery task to download and ingest any out-of-date ATT&CK domains.
    Returns immediately; poll GET /sync/task/{task_id} for progress.
    """
    body = body or TriggerRequest()
    if body.source != "mitre-attack":
        raise HTTPException(400, "Only source='mitre-attack' is currently supported")

    from app.core.config import settings

    configured_domains = settings.attck_domain_list
    domains = body.domains or configured_domains
    invalid = sorted(set(domains) - set(configured_domains))
    if invalid:
        raise HTTPException(400, f"Unsupported or disabled ATT&CK domains: {invalid}")

    try:
        from app.tasks.sync import check_and_sync
        task = check_and_sync.delay(domains=domains, force=body.force)
        await audit(session, user, "sync.trigger", "attck_sync", task.id, {"source": body.source, "domains": domains, "force": body.force})
        await session.commit()
        return TriggerOut(
            task_id=task.id,
            status="queued",
            source=body.source,
            domains=domains,
            force=body.force,
        )
    except Exception as exc:
        logger.error("trigger sync failed (Celery unavailable): %s", exc, exc_info=True)
        raise HTTPException(503, "Operation failed. See server logs.") from exc


@router.post("/ioc", response_model=IOCSyncOut)
async def trigger_ioc_sync(
    days: int = Query(7, ge=1, le=7),
    domain: str = Query("enterprise-attack"),
    ai_enrich: bool = Query(False),
    ai_provider: str = Query("local", pattern="^(local|claude|openai|gemini|minimax)$"),
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    """Synchronize all configured IOC sources centrally."""
    try:
        from app.services.ioc_intel import sync_all_ioc_sources
        result = await sync_all_ioc_sources(session, days=days, domain=domain, ai_enrich=ai_enrich, ai_provider=ai_provider)
        await audit(session, user, "sync.ioc", "ioc_source", details={"days": days, "domain": domain})
        return result
    except Exception as exc:
        logger.error("IOC sync failed: %s", exc, exc_info=True)
        raise HTTPException(500, "Operation failed. See server logs.") from exc


@router.post("/cve", response_model=CVESyncOut)
async def trigger_cve_sync(
    days: int = Query(7, ge=1, le=120),
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    """Synchronize NVD/CISA CVE feeds and refresh strict CVE correlations."""
    try:
        from app.services.cve_intel import sync_all_cve_sources
        result = await sync_all_cve_sources(session, days=days)
        await audit(session, user, "sync.cve", "cve_source", details={"days": days})
        await session.commit()
        return {"days": days, **result}
    except Exception as exc:
        logger.error("CVE sync failed: %s", exc, exc_info=True)
        raise HTTPException(500, "Operation failed. See server logs.") from exc


@router.post("/dynamic-db", response_model=DynamicSyncOut)
async def trigger_dynamic_db_sync(
    days: int = Query(7, ge=1, le=7),
    force_attack: bool = Query(False),
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    """Synchronize the dynamic public reference DB immediately."""
    try:
        from app.tasks.sync import run_dynamic_reference_db_async
        result = await run_dynamic_reference_db_async(days=days, force_attack=force_attack)
        await audit(session, user, "sync.dynamic_db", "attck_sync", details={"days": days, "force_attack": force_attack})
        await session.commit()
        return result
    except Exception as exc:
        logger.error("dynamic DB sync failed: %s", exc, exc_info=True)
        raise HTTPException(500, "Operation failed. See server logs.") from exc


@router.get("/task/{task_id}")
async def task_status(task_id: str, _: TeamUser = Depends(current_user)):
    """Poll a Celery task by ID."""
    try:
        from app.tasks.celery_app import celery_app
        result = celery_app.AsyncResult(task_id)
        return {
            "task_id":  task_id,
            "status":   result.status,
            "result":   result.result if result.ready() else None,
        }
    except Exception as exc:
        logger.error("task status check failed (Celery unavailable): %s", exc, exc_info=True)
        raise HTTPException(503, "Operation failed. See server logs.") from exc
