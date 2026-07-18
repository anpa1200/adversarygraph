from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.services.auth import TeamUser, audit, current_user, require_permission
from app.services.cve_intel import (
    correlate_cves,
    cve_correlation_graph,
    cves_for_actor,
    cves_for_ioc,
    cves_for_technique,
    enrich_missing_cvss,
    get_cve_detail,
    list_cve_library,
    list_cve_sources,
    sync_all_cve_sources,
    sync_cisa_kev,
    sync_epss_scores,
    sync_github_advisories,
    sync_nvd_cve_ids,
    sync_nvd_recent,
    sync_osv_packages,
)

manage_cve_feeds = require_permission("manage_feeds")

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/cve", tags=["CVE Intelligence"])


class CVESourceOut(BaseModel):
    source_id: str
    label: str
    kind: str
    url: str
    enabled: bool
    last_synced_at: Any | None = None
    sync_status: str
    sync_error: str

    model_config = {"from_attributes": True}


class CVSSOut(BaseModel):
    version: str = ""
    score: str = ""
    severity: str = ""
    vector: str = ""


class CVEItemOut(BaseModel):
    id: int | None = None
    cve_id: str
    source: str
    description: str = ""
    published: str | None = None
    last_modified: str | None = None
    vuln_status: str = ""
    cvss: CVSSOut
    cwe_ids: list[str] = Field(default_factory=list)
    cpe_matches: list[str] = Field(default_factory=list)
    references: list[dict[str, Any]] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    known_exploited: bool = False
    kev_due_date: str = ""
    kev_required_action: str = ""


class CVELibraryOut(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[CVEItemOut]


class CVELinkOut(BaseModel):
    relationship: str
    confidence: int
    evidence: str
    source: str


class CVETechniqueLinkOut(CVELinkOut):
    attack_id: str
    name: str = ""


class CVEIOCLinkOut(CVELinkOut):
    indicator_id: int
    value: str = ""
    type: str = ""


class CVEActorLinkOut(CVELinkOut):
    actor_attack_id: str
    actor_name: str = ""


class CVEDetailOut(CVEItemOut):
    techniques: list[CVETechniqueLinkOut] = Field(default_factory=list)
    iocs: list[CVEIOCLinkOut] = Field(default_factory=list)
    actors: list[CVEActorLinkOut] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class CVECorrelationOut(BaseModel):
    cve: CVEItemOut
    relationship: str
    confidence: int
    evidence: str
    source: str
    path: list[dict[str, Any]] = Field(default_factory=list)


class CVECorrelationGraphOut(BaseModel):
    cve_id: str
    nodes: list[dict[str, Any]] = Field(default_factory=list)
    edges: list[dict[str, Any]] = Field(default_factory=list)


class CVESyncOut(BaseModel):
    totals: dict[str, int] | None = None
    sources: list[dict[str, Any]] | None = None
    correlations: dict[str, int] | None = None
    source: str | None = None
    mode: str | None = None
    days: int | None = None
    fetched: int | None = None
    requested: int | None = None
    imported_cves: int | None = None
    ecosystem: str | None = None
    severity: str | None = None
    missing_selected: int | None = None
    inserted: int | None = None
    updated: int | None = None
    package_results: list[dict[str, Any]] | None = None
    nvd_enrichment: dict[str, Any] | None = None
    asset_retrohunt: dict[str, Any] | None = None
    asset_retrohunt_error: str | None = None
    errors: list[str] | None = None


class CVEIdSyncIn(BaseModel):
    cve_ids: list[str] = Field(default_factory=list)


class OSVPackageIn(BaseModel):
    package_name: str = ""
    name: str = ""
    ecosystem: str = ""
    package_type: str = ""
    package_version: str = ""
    version: str = ""


class OSVPackageSyncIn(BaseModel):
    packages: list[OSVPackageIn] = Field(default_factory=list)


@router.get("/sources", response_model=list[CVESourceOut])
async def cve_sources(session: AsyncSession = Depends(get_session), _: TeamUser = Depends(current_user)):
    return await list_cve_sources(session)


@router.get("/library", response_model=CVELibraryOut)
async def cve_library(
    search: str = Query(""),
    severity: str = Query("", pattern="^(|LOW|MEDIUM|HIGH|CRITICAL|NONE)$"),
    known_exploited: bool | None = Query(None),
    limit: int = Query(100, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
):
    return await list_cve_library(
        session,
        search=search,
        severity=severity,
        known_exploited=known_exploited,
        limit=limit,
        offset=offset,
    )


@router.get("/{cve_id}", response_model=CVEDetailOut)
async def cve_detail(cve_id: str, session: AsyncSession = Depends(get_session), _: TeamUser = Depends(current_user)):
    detail = await get_cve_detail(session, cve_id)
    if detail is None:
        raise HTTPException(404, "CVE not found")
    return detail


@router.get("/{cve_id}/graph", response_model=CVECorrelationGraphOut)
async def cve_graph(cve_id: str, session: AsyncSession = Depends(get_session), _: TeamUser = Depends(current_user)):
    graph = await cve_correlation_graph(session, cve_id)
    if graph is None:
        raise HTTPException(404, "CVE not found")
    return graph


@router.get("/related/technique/{attack_id}", response_model=list[CVECorrelationOut])
async def related_cves_for_technique(
    attack_id: str,
    limit: int = Query(100, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
):
    return await cves_for_technique(session, attack_id, limit=limit)


@router.get("/related/actor/{actor_attack_id}", response_model=list[CVECorrelationOut])
async def related_cves_for_actor(
    actor_attack_id: str,
    limit: int = Query(100, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
):
    return await cves_for_actor(session, actor_attack_id, limit=limit)


@router.get("/related/ioc/{indicator_id}", response_model=list[CVECorrelationOut])
async def related_cves_for_ioc(
    indicator_id: int,
    limit: int = Query(100, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
):
    return await cves_for_ioc(session, indicator_id, limit=limit)


@router.post("/sync/all", response_model=CVESyncOut)
async def sync_all_cves(
    days: int = Query(7, ge=1, le=120),
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(manage_cve_feeds),
):
    try:
        result = await sync_all_cve_sources(session, days=days)
        await audit(session, user, "sync.cve", "cve_source", details={"days": days})
        await session.commit()
        return result
    except Exception as exc:
        logger.error("CVE sync failed: %s", exc, exc_info=True)
        raise HTTPException(500, "Operation failed. See server logs.") from exc


@router.post("/sync/nvd", response_model=CVESyncOut)
async def sync_nvd(
    days: int = Query(7, ge=1, le=120),
    limit: int = Query(2000, ge=1, le=2000),
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(manage_cve_feeds),
):
    try:
        result = await sync_nvd_recent(session, days=days, limit=limit)
        await audit(session, user, "sync.cve.nvd", "cve_source", details={"days": days, "limit": limit})
        await session.commit()
        return result
    except Exception as exc:
        logger.error("NVD sync failed: %s", exc, exc_info=True)
        raise HTTPException(500, "Operation failed. See server logs.") from exc


@router.post("/sync/nvd/cve-ids", response_model=CVESyncOut)
async def sync_nvd_by_cve_ids(
    payload: CVEIdSyncIn,
    limit: int = Query(100, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(manage_cve_feeds),
):
    try:
        result = await sync_nvd_cve_ids(session, payload.cve_ids, limit=limit)
        await audit(session, user, "sync.cve.nvd.cve_ids", "cve_source", details={"count": len(payload.cve_ids), "limit": limit})
        await session.commit()
        return result
    except Exception as exc:
        logger.error("NVD CVE-ID enrichment failed: %s", exc, exc_info=True)
        raise HTTPException(500, "Operation failed. See server logs.") from exc


@router.post("/sync/nvd/missing-cvss", response_model=CVESyncOut)
async def sync_missing_cvss(
    limit: int = Query(100, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(manage_cve_feeds),
):
    try:
        result = await enrich_missing_cvss(session, limit=limit)
        await audit(session, user, "sync.cve.nvd.missing_cvss", "cve_source", details={"limit": limit})
        await session.commit()
        return result
    except Exception as exc:
        logger.error("NVD missing-CVSS enrichment failed: %s", exc, exc_info=True)
        raise HTTPException(500, "Operation failed. See server logs.") from exc


@router.post("/sync/kev", response_model=CVESyncOut)
async def sync_kev(session: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_cve_feeds)):
    try:
        result = await sync_cisa_kev(session)
        await audit(session, user, "sync.cve.kev", "cve_source")
        await session.commit()
        return result
    except Exception as exc:
        logger.error("CISA KEV sync failed: %s", exc, exc_info=True)
        raise HTTPException(500, "Operation failed. See server logs.") from exc


@router.post("/sync/github-advisories", response_model=CVESyncOut)
async def sync_github_security_advisories(
    ecosystem: str = Query("", max_length=80),
    severity: str = Query("", pattern="^(|low|medium|high|critical)$"),
    limit: int = Query(100, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(manage_cve_feeds),
):
    try:
        result = await sync_github_advisories(session, ecosystem=ecosystem, severity=severity, limit=limit)
        await audit(session, user, "sync.cve.github_advisories", "cve_source", details={"ecosystem": ecosystem, "severity": severity, "limit": limit})
        await session.commit()
        return result
    except Exception as exc:
        logger.error("GitHub Advisory sync failed: %s", exc, exc_info=True)
        raise HTTPException(500, "Operation failed. See server logs.") from exc


@router.post("/sync/epss", response_model=CVESyncOut)
async def sync_epss(
    limit: int = Query(500, ge=1, le=2000),
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(manage_cve_feeds),
):
    try:
        result = await sync_epss_scores(session, limit=limit)
        await audit(session, user, "sync.cve.epss", "cve_source", details={"limit": limit})
        await session.commit()
        return result
    except Exception as exc:
        logger.error("EPSS sync failed: %s", exc, exc_info=True)
        raise HTTPException(500, "Operation failed. See server logs.") from exc


@router.post("/sync/osv/packages", response_model=CVESyncOut)
async def sync_osv_package_advisories(
    payload: OSVPackageSyncIn,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(manage_cve_feeds),
):
    try:
        packages = [item.model_dump() for item in payload.packages]
        result = await sync_osv_packages(session, packages)
        await audit(session, user, "sync.cve.osv_packages", "cve_source", details={"packages": len(packages)})
        await session.commit()
        return result
    except Exception as exc:
        logger.error("OSV package sync failed: %s", exc, exc_info=True)
        raise HTTPException(500, "Operation failed. See server logs.") from exc


@router.post("/correlate")
async def run_cve_correlation(session: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_cve_feeds)):
    try:
        result = await correlate_cves(session)
        await audit(session, user, "cve.correlate", "cve_record", details=result)
        await session.commit()
        return result
    except Exception as exc:
        logger.error("CVE correlation failed: %s", exc, exc_info=True)
        raise HTTPException(500, "Operation failed. See server logs.") from exc
