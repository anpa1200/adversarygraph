from __future__ import annotations

import csv
import io
import re
import uuid
from datetime import datetime
from typing import Any

import logging

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile

logger = logging.getLogger(__name__)
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete as sql_delete, desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.core.safe_http import require_body_size

_limit_10mb = require_body_size(10 * 1024 * 1024)
from app.services.auth import TeamUser, analyst, audit, current_user
from app.models.ioc import IOCInvestigationSession
from app.services.file_parser import extract_text
from app.services.ioc_extractor import extract_iocs_from_text
from app.services.ioc_intel import (
    IOCImportItem,
    actor_ioc_counts,
    actor_ioc_summary,
    actor_iocs,
    create_ioc_source,
    delete_ioc_source,
    enrich_actor_from_otx,
    enrich_ioc_ttp_mappings,
    get_ioc_detail,
    import_iocs,
    list_ioc_library,
    list_ioc_sources,
    sync_custom_source,
    sync_malpedia_families,
    sync_otx_actor_pulses,
    sync_otx_subscribed_pulses,
    sync_threatfox,
    update_ioc_source,
)
from app.services.virustotal import lookup_virustotal_ioc
from app.services.ioc_investigation import InvestigationOptions, investigate_ioc
from app.services.ioc_stix import export_ioc_stix_bundle, import_ioc_stix_bundle, import_taxii_collection
from app.services.opencti_sync import (
    OpenCTISyncError,
    opencti_status,
    pull_from_opencti,
    push_to_opencti,
    sync_opencti,
)

router = APIRouter(prefix="/ioc", tags=["IOC Intelligence"])


class IOCSourceOut(BaseModel):
    source_id: str
    label: str
    kind: str
    url: str
    enabled: bool
    last_synced_at: datetime | None
    sync_status: str
    sync_error: str

    model_config = {"from_attributes": True}


class SyncOut(BaseModel):
    source: str
    days: int | None = None
    inserted: int
    updated: int
    actor_links: int
    ttp_enriched: int = 0


class IOCMappingEnrichmentOut(BaseModel):
    checked: int
    updated: int
    normalized_types: int = 0
    ai_attempted: int = 0
    ai_mapped: int = 0
    priority: str


class IOCImportIn(BaseModel):
    value: str = Field(..., min_length=1)
    type: str = Field(..., min_length=2)
    actor_attack_id: str | None = None
    actor_name: str | None = None
    malware_family: str = ""
    campaign: str = ""
    technique_ids: list[str] = Field(default_factory=list)
    source: str = "manual-report-import"
    source_url: str = ""
    first_seen: str | None = None
    last_seen: str | None = None
    confidence: int = Field(60, ge=0, le=100)
    tlp: str = "clear"
    tags: list[str] = Field(default_factory=list)
    description: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)


class IOCImportRequest(BaseModel):
    indicators: list[IOCImportIn] = Field(..., min_length=1)


class IOCSourceCreateIn(BaseModel):
    label: str = Field(..., min_length=2)
    url: str = Field(..., min_length=8)
    kind: str = Field("custom-json", pattern="^custom-(json|csv|txt)$")
    source_id: str | None = None


class IOCSourceUpdateIn(BaseModel):
    label: str = Field(..., min_length=2)
    url: str = Field(..., min_length=8)
    kind: str = Field("custom-json", pattern="^custom-(json|csv|txt)$")


class TAXIIImportIn(BaseModel):
    objects_url: str = Field(..., min_length=8)
    token: str = ""
    username: str = ""
    password: str = ""
    source_label: str = "TAXII IOC Import"


class IOCOut(BaseModel):
    id: int
    value: str
    type: str
    source: str
    source_url: str
    first_seen: str | None
    last_seen: str | None
    confidence: int
    tlp: str
    malware_family: str
    campaign: str
    technique_ids: list[str] = Field(default_factory=list)
    tags: list[str]
    description: str
    relationship: str
    evidence: str


class IOCActorRefOut(BaseModel):
    actor_attack_id: str
    actor_name: str
    relationship: str
    confidence: int
    evidence: str
    source: str


class IOCLibraryItemOut(BaseModel):
    id: int
    value: str
    type: str
    source: str
    source_url: str
    first_seen: str | None
    last_seen: str | None
    confidence: int
    tlp: str
    malware_family: str
    campaign: str
    technique_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    description: str
    actors: list[IOCActorRefOut] = Field(default_factory=list)
    actor_count: int


class IOCLibraryOut(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[IOCLibraryItemOut]


class IOCSourceDetailOut(BaseModel):
    source_id: str
    label: str
    kind: str
    url: str
    enabled: bool
    last_synced_at: str | None = None
    sync_status: str = ""
    sync_error: str = ""


class IOCTechniqueDetailOut(BaseModel):
    attack_id: str
    name: str = ""
    tactics: list[str] = Field(default_factory=list)
    url: str = ""
    evidence: list[dict[str, str]] = Field(default_factory=list)


class IOCEnrichmentValueOut(BaseModel):
    key: str
    value: str


class IOCEnrichmentSectionOut(BaseModel):
    source: str
    label: str
    kind: str
    url: str = ""
    status: str = ""
    values: list[IOCEnrichmentValueOut] = Field(default_factory=list)


class IOCDetailOut(IOCLibraryItemOut):
    created_at: str = ""
    updated_at: str = ""
    source_details: IOCSourceDetailOut
    techniques: list[IOCTechniqueDetailOut] = Field(default_factory=list)
    enrichments: list[IOCEnrichmentSectionOut] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class ReportIOCPreviewOut(BaseModel):
    value: str
    type: str
    source: str
    source_url: str
    first_seen: str | None
    last_seen: str | None
    confidence: int
    tlp: str
    malware_family: str
    campaign: str
    technique_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    description: str
    relationship: str
    evidence: str


class ReportIOCImportOut(BaseModel):
    filename: str
    extracted: int
    imported: SyncOut
    preview: list[ReportIOCPreviewOut]


class IOCCountsOut(BaseModel):
    counts: dict[str, int]


class OpenCTISyncOut(BaseModel):
    source: str
    direction: str
    indicators_seen: int | None = None
    observables_seen: int | None = None
    reports_seen: int | None = None
    reports_imported: int | None = None
    inserted: int | None = None
    updated: int | None = None
    actor_links: int | None = None
    ttp_enriched: int | None = None
    seen: int | None = None
    pushed_indicators: int | None = None
    skipped: int | None = None
    pushed_reports: int | None = None
    errors: list[str] = Field(default_factory=list)
    pull: dict[str, Any] | None = None
    push: dict[str, Any] | None = None


class VirusTotalLookupIn(BaseModel):
    indicator: str = Field(..., min_length=1, max_length=2048)
    domain: str = "enterprise-attack"


class VirusTotalTechniqueOut(BaseModel):
    attack_id: str
    name: str = ""
    tactics: list[str] = Field(default_factory=list)
    url: str = ""


class VirusTotalActorOut(BaseModel):
    attack_id: str
    name: str
    aliases: list[str] = Field(default_factory=list)
    matched_terms: list[str] = Field(default_factory=list)
    evidence: list[dict[str, str]] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)
    url: str = ""


class VirusTotalDetectionOut(BaseModel):
    engine: str
    category: str
    result: str


class VirusTotalTtpEvidenceOut(BaseModel):
    attack_id: str
    name: str = ""
    tactic: str = ""
    source: str
    evidence: str


class VirusTotalRuleOut(BaseModel):
    type: str
    name: str = ""
    source: str = ""
    severity: str = ""
    description: str = ""


class VirusTotalSandboxVerdictOut(BaseModel):
    sandbox: str
    category: str = ""
    malware_classification: str = ""
    malware_names: str = ""
    confidence: str = ""


class VirusTotalDnsRecordOut(BaseModel):
    type: str = ""
    value: str = ""
    ttl: str = ""


class VirusTotalResolutionOut(BaseModel):
    host_name: str = ""
    ip_address: str = ""
    date: str = ""


class VirusTotalLookupOut(BaseModel):
    indicator: str
    type: str
    virustotal_url: str
    permalink: str
    summary: str
    reputation: int
    total_votes: dict[str, int] = Field(default_factory=dict)
    last_analysis_stats: dict[str, int] = Field(default_factory=dict)
    last_analysis_date: int | None = None
    first_submission_date: int | None = None
    last_submission_date: int | None = None
    last_modification_date: int | None = None
    names: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    threat_names: list[str] = Field(default_factory=list)
    detections: list[VirusTotalDetectionOut] = Field(default_factory=list)
    ttps: list[VirusTotalTechniqueOut] = Field(default_factory=list)
    ttp_evidence: list[VirusTotalTtpEvidenceOut] = Field(default_factory=list)
    actors: list[VirusTotalActorOut] = Field(default_factory=list)
    rules: list[VirusTotalRuleOut] = Field(default_factory=list)
    sandbox_verdicts: list[VirusTotalSandboxVerdictOut] = Field(default_factory=list)
    dns_records: list[VirusTotalDnsRecordOut] = Field(default_factory=list)
    resolutions: list[VirusTotalResolutionOut] = Field(default_factory=list)
    whois: str = ""
    network: dict[str, Any] = Field(default_factory=dict)
    context: dict[str, Any] = Field(default_factory=dict)


class IOCInvestigationIn(BaseModel):
    artifact: str = Field(..., min_length=1, max_length=1000)
    domain: str = "enterprise-attack"
    depth: int = Field(2, ge=1, le=3)
    max_tier_nodes: int = Field(25, ge=5, le=75)
    ai_summarize: bool = False
    ai_provider: str = Field("local", pattern="^(local|claude|openai|gemini|minimax)$")


class IOCInvestigationHistoryOut(BaseModel):
    session_id: str
    artifact: str
    artifact_type: str
    verdict: str
    suspicion_score: int
    depth: int
    ai_summarize: bool
    ai_provider: str
    created_at: str
    technique_count: int = 0
    actor_count: int = 0


class IOCInvestigationOut(BaseModel):
    session_id: str | None = None
    artifact: str
    artifact_type: str
    depth: int
    suspicion_score: int
    verdict: str
    summary: str
    kill_chain: list[dict[str, Any]] = Field(default_factory=list)
    techniques: list[dict[str, Any]] = Field(default_factory=list)
    actors: list[dict[str, Any]] = Field(default_factory=list)
    sources: list[dict[str, Any]] = Field(default_factory=list)
    tier2_sources: list[dict[str, Any]] = Field(default_factory=list)
    tier3_sources: list[dict[str, Any]] = Field(default_factory=list)
    relationships: dict[str, Any] = Field(default_factory=dict)
    ai_input: dict[str, Any] = Field(default_factory=dict)
    ai_error: str = ""


@router.get("/sources", response_model=list[IOCSourceOut])
async def sources(session: AsyncSession = Depends(get_session), _: TeamUser = Depends(current_user)):
    return await list_ioc_sources(session)


@router.post("/virustotal/lookup", response_model=VirusTotalLookupOut)
async def virustotal_lookup(payload: VirusTotalLookupIn, session: AsyncSession = Depends(get_session), _: TeamUser = Depends(analyst)):
    try:
        return await lookup_virustotal_ioc(session, payload.indicator, domain=payload.domain)
    except ValueError as exc:
        logger.warning("VirusTotal lookup validation error: %s", exc)
        raise HTTPException(404 if "not found" in str(exc).lower() else 400, "Operation failed. See server logs.") from exc
    except RuntimeError as exc:
        logger.error("VirusTotal lookup runtime error: %s", exc, exc_info=True)
        status_code = 400 if "VIRUSTOTAL_API_KEY" in str(exc) else 502
        raise HTTPException(status_code, "Operation failed. See server logs.") from exc
    except Exception as exc:
        logger.error("VirusTotal lookup failed: %s", exc, exc_info=True)
        raise HTTPException(502, "Operation failed. See server logs.") from exc


@router.post("/investigate", response_model=IOCInvestigationOut)
async def investigate_ioc_route(payload: IOCInvestigationIn, session: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    try:
        result = await investigate_ioc(
            session,
            payload.artifact,
            options=InvestigationOptions(
                domain=payload.domain,
                depth=payload.depth,
                max_tier_nodes=payload.max_tier_nodes,
                ai_summarize=payload.ai_summarize,
                ai_provider=payload.ai_provider,
            ),
        )
        saved = IOCInvestigationSession(
            id=uuid.uuid4(),
            artifact=result["artifact"],
            artifact_type=result["artifact_type"],
            verdict=result["verdict"],
            suspicion_score=result["suspicion_score"],
            depth=result["depth"],
            ai_summarize=payload.ai_summarize,
            ai_provider=payload.ai_provider,
            result=result,
        )
        session.add(saved)
        await session.flush()
        await audit(session, user, "ioc.investigate", "ioc_investigation", str(saved.id), {"artifact": result["artifact"], "verdict": result["verdict"]})
        await session.commit()
        result["session_id"] = str(saved.id)
        return result
    except ValueError as exc:
        logger.warning("IOC investigation validation error: %s", exc)
        raise HTTPException(400, "Operation failed. See server logs.") from exc
    except Exception as exc:
        logger.error("IOC investigation failed: %s", exc, exc_info=True)
        raise HTTPException(502, "Operation failed. See server logs.") from exc


@router.get("/investigations", response_model=list[IOCInvestigationHistoryOut])
async def list_ioc_investigations(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
):
    rows = await session.execute(
        select(IOCInvestigationSession)
        .order_by(desc(IOCInvestigationSession.created_at))
        .offset(offset)
        .limit(limit)
    )
    output: list[IOCInvestigationHistoryOut] = []
    for item in rows.scalars().all():
        result = item.result or {}
        output.append(IOCInvestigationHistoryOut(
            session_id=str(item.id),
            artifact=item.artifact,
            artifact_type=item.artifact_type,
            verdict=item.verdict,
            suspicion_score=item.suspicion_score,
            depth=item.depth,
            ai_summarize=item.ai_summarize,
            ai_provider=item.ai_provider,
            created_at=item.created_at.isoformat() if item.created_at else "",
            technique_count=len(result.get("techniques") or []),
            actor_count=len(result.get("actors") or []),
        ))
    return output


@router.get("/investigations/{session_id}", response_model=IOCInvestigationOut)
async def get_ioc_investigation(session_id: str, session: AsyncSession = Depends(get_session), _: TeamUser = Depends(current_user)):
    try:
        sid = uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(400, "Invalid investigation session ID") from None
    row = await session.execute(select(IOCInvestigationSession).where(IOCInvestigationSession.id == sid))
    item = row.scalar_one_or_none()
    if not item:
        raise HTTPException(404, "IOC investigation session not found")
    result = dict(item.result or {})
    result["session_id"] = str(item.id)
    return result


@router.delete("/investigations/{session_id}", status_code=204)
async def delete_ioc_investigation(session_id: str, session: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    try:
        sid = uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(400, "Invalid investigation session ID") from None
    await audit(session, user, "ioc.delete_investigation", "ioc_investigation", session_id)
    result = await session.execute(sql_delete(IOCInvestigationSession).where(IOCInvestigationSession.id == sid))
    if not getattr(result, "rowcount", 0):
        raise HTTPException(404, "IOC investigation session not found")
    await session.commit()


@router.post("/sources", response_model=IOCSourceOut)
async def create_source(payload: IOCSourceCreateIn, session: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    try:
        result = await create_ioc_source(
            session,
            label=payload.label,
            url=payload.url,
            kind=payload.kind,
            source_id=payload.source_id,
        )
        await audit(session, user, "ioc.create_source", "ioc_source", result.source_id, {"label": result.label, "kind": result.kind})
        return result
    except Exception as exc:
        logger.error("Custom IOC source creation failed: %s", exc, exc_info=True)
        raise HTTPException(400, "Operation failed. See server logs.") from exc


@router.patch("/sources/{source_id}", response_model=IOCSourceOut)
async def update_source(source_id: str, payload: IOCSourceUpdateIn, session: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    try:
        result = await update_ioc_source(
            session,
            source_id=source_id,
            label=payload.label,
            url=payload.url,
            kind=payload.kind,
        )
        await audit(session, user, "ioc.update_source", "ioc_source", source_id)
        return result
    except Exception as exc:
        logger.error("Custom IOC source update failed: %s", exc, exc_info=True)
        raise HTTPException(400, "Operation failed. See server logs.") from exc


@router.delete("/sources/{source_id}", status_code=204)
async def delete_source(source_id: str, session: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    try:
        await audit(session, user, "ioc.delete_source", "ioc_source", source_id)
        await delete_ioc_source(session, source_id=source_id)
    except Exception as exc:
        logger.error("Custom IOC source delete failed: %s", exc, exc_info=True)
        raise HTTPException(400, "Operation failed. See server logs.") from exc


@router.get("/library", response_model=IOCLibraryOut)
async def ioc_library_route(
    search: str = Query("", max_length=500),
    type: str = Query("", max_length=80),
    source: str = Query("", max_length=120),
    actor: list[str] = Query(default_factory=list),
    sort: str = Query(
        "last_seen_desc",
        pattern="^(last_seen|first_seen|type|value|source|confidence|actor)_(asc|desc)$",
    ),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
):
    return await list_ioc_library(
        session,
        search=search,
        indicator_type=type,
        source_id=source,
        actor=actor,
        sort=sort,
        limit=limit,
        offset=offset,
    )


@router.get("/library/{indicator_id}/detail", response_model=IOCDetailOut)
async def ioc_library_detail_route(
    indicator_id: int,
    domain: str = Query("enterprise-attack"),
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
):
    detail = await get_ioc_detail(session, indicator_id, domain=domain)
    if detail is None:
        raise HTTPException(404, "IOC not found")
    return detail


@router.get("/library/export/stix")
async def export_ioc_library_stix_route(
    search: str = Query("", max_length=500),
    type: str = Query("", max_length=80),
    source: str = Query("", max_length=120),
    actor: list[str] = Query(default_factory=list),
    sort: str = Query(
        "last_seen_desc",
        pattern="^(last_seen|first_seen|type|value|source|confidence|actor)_(asc|desc)$",
    ),
    limit: int = Query(5000, ge=1, le=5000),
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
):
    import json

    bundle = await export_ioc_stix_bundle(
        session,
        search=search,
        indicator_type=type,
        source_id=source,
        actor=actor,
        sort=sort,
        limit=limit,
    )
    payload = json.dumps(bundle, indent=2).encode("utf-8")
    return Response(
        content=payload,
        media_type="application/stix+json",
        headers={
            "Content-Disposition": 'attachment; filename="adversarygraph-ioc-library.stix.json"',
            "Cache-Control": "no-store",
        },
    )


@router.post("/import/stix")
async def import_ioc_stix_route(
    bundle: dict[str, Any],
    source_label: str = Query("STIX IOC Import", max_length=255),
    source_url: str = Query("", max_length=1000),
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    try:
        result = await import_ioc_stix_bundle(session, bundle, source_label=source_label, source_url=source_url)
        await audit(session, user, "ioc.import_stix", "ioc_source", details={"source_label": source_label})
        return result
    except Exception as exc:
        logger.error("STIX IOC import failed: %s", exc, exc_info=True)
        raise HTTPException(400, "Operation failed. See server logs.") from exc


@router.post("/import/taxii")
async def import_ioc_taxii_route(
    payload: TAXIIImportIn,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    try:
        result = await import_taxii_collection(
            session,
            objects_url=payload.objects_url,
            token=payload.token,
            username=payload.username,
            password=payload.password,
            source_label=payload.source_label,
        )
        await audit(session, user, "ioc.import_taxii", "ioc_source", details={"source_label": payload.source_label})
        return result
    except Exception as exc:
        logger.error("TAXII IOC import failed: %s", exc, exc_info=True)
        raise HTTPException(400, "Operation failed. See server logs.") from exc


@router.get("/opencti/status")
async def opencti_status_route(_: TeamUser = Depends(current_user)):
    try:
        return await opencti_status()
    except OpenCTISyncError as exc:
        logger.warning("OpenCTI status check sync error: %s", exc)
        raise HTTPException(400, "Operation failed. See server logs.") from exc
    except Exception as exc:
        logger.error("OpenCTI status check failed: %s", exc, exc_info=True)
        raise HTTPException(502, "Operation failed. See server logs.") from exc


@router.post("/opencti/pull", response_model=OpenCTISyncOut)
async def opencti_pull_route(
    limit: int = Query(500, ge=1, le=5000),
    domain: str = Query("enterprise-attack"),
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    try:
        result = await pull_from_opencti(session, limit=limit, domain=domain)
        await audit(session, user, "ioc.opencti_pull", "ioc_source", details={"domain": domain, "limit": limit})
        return result
    except OpenCTISyncError as exc:
        logger.warning("OpenCTI pull sync error: %s", exc)
        raise HTTPException(400, "Operation failed. See server logs.") from exc
    except Exception as exc:
        logger.error("OpenCTI pull failed: %s", exc, exc_info=True)
        raise HTTPException(502, "Operation failed. See server logs.") from exc


@router.post("/opencti/push", response_model=OpenCTISyncOut)
async def opencti_push_route(
    limit: int = Query(500, ge=1, le=5000),
    source_id: str = Query("", max_length=120),
    include_reports: bool = Query(True),
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    try:
        result = await push_to_opencti(session, limit=limit, source_id=source_id, include_reports=include_reports)
        await audit(session, user, "ioc.opencti_push", "ioc_source", details={"limit": limit, "source_id": source_id})
        return result
    except OpenCTISyncError as exc:
        logger.warning("OpenCTI push sync error: %s", exc)
        raise HTTPException(400, "Operation failed. See server logs.") from exc
    except Exception as exc:
        logger.error("OpenCTI push failed: %s", exc, exc_info=True)
        raise HTTPException(502, "Operation failed. See server logs.") from exc


@router.post("/opencti/sync", response_model=OpenCTISyncOut)
async def opencti_sync_route(
    limit: int = Query(500, ge=1, le=5000),
    domain: str = Query("enterprise-attack"),
    include_reports: bool = Query(True),
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    try:
        result = await sync_opencti(session, limit=limit, domain=domain, include_reports=include_reports)
        await audit(session, user, "ioc.opencti_sync", "ioc_source", details={"domain": domain, "limit": limit})
        return result
    except OpenCTISyncError as exc:
        logger.warning("OpenCTI sync error: %s", exc)
        raise HTTPException(400, "Operation failed. See server logs.") from exc
    except Exception as exc:
        logger.error("OpenCTI sync failed: %s", exc, exc_info=True)
        raise HTTPException(502, "Operation failed. See server logs.") from exc


@router.post("/sync/threatfox", response_model=SyncOut)
async def sync_threatfox_route(
    days: int = Query(7, ge=1, le=7),
    domain: str = Query("enterprise-attack"),
    ai_enrich: bool = Query(False),
    ai_provider: str = Query("local", pattern="^(local|claude|openai|gemini|minimax)$"),
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    try:
        result = await sync_threatfox(session, days=days, domain=domain, ai_enrich=ai_enrich, ai_provider=ai_provider)
        await audit(session, user, "ioc.sync_threatfox", "ioc_source", details={"days": days, "domain": domain, "inserted": result.inserted, "updated": result.updated})
        return result
    except Exception as exc:
        logger.error("ThreatFox sync failed: %s", exc, exc_info=True)
        status_code = 400 if "THREATFOX_AUTH_KEY" in str(exc) else 502
        raise HTTPException(status_code, "Operation failed. See server logs.") from exc


@router.post("/sync/otx")
async def sync_otx_route(
    domain: str = Query("enterprise-attack"),
    mode: str = Query("subscribed", pattern="^(subscribed|actor-search)$"),
    ai_enrich: bool = Query(False),
    ai_provider: str = Query("local", pattern="^(local|claude|openai|gemini|minimax)$"),
    limit: int = Query(100, ge=1, le=500),
    max_groups: int = Query(220, ge=1, le=500),
    aliases_per_group: int = Query(4, ge=1, le=8),
    pulses_per_alias: int = Query(5, ge=1, le=20),
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    try:
        if mode == "subscribed":
            result = await sync_otx_subscribed_pulses(session, domain=domain, limit=limit, ai_enrich=ai_enrich, ai_provider=ai_provider)
        else:
            result = await sync_otx_actor_pulses(
                session,
                domain=domain,
                max_groups=max_groups,
                aliases_per_group=aliases_per_group,
                pulses_per_alias=pulses_per_alias,
            )
        await audit(session, user, "ioc.sync_otx", "ioc_source", details={"mode": mode, "domain": domain})
        return result
    except Exception as exc:
        logger.error("OTX sync failed: %s", exc, exc_info=True)
        status_code = 400 if "OTX_API_KEY" in str(exc) else 502
        raise HTTPException(status_code, "Operation failed. See server logs.") from exc


@router.post("/sync/malpedia")
async def sync_malpedia_route(
    domain: str = Query("enterprise-attack"),
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    try:
        result = await sync_malpedia_families(session, domain=domain)
        await audit(session, user, "ioc.sync_malpedia", "ioc_source", details={"domain": domain})
        return result
    except Exception as exc:
        logger.error("Malpedia sync failed: %s", exc, exc_info=True)
        raise HTTPException(502, "Operation failed. See server logs.") from exc


@router.post("/sync/{source_id}", response_model=SyncOut)
async def sync_source_route(
    source_id: str,
    domain: str = Query("enterprise-attack"),
    ai_enrich: bool = Query(False),
    ai_provider: str = Query("local", pattern="^(local|claude|openai|gemini|minimax)$"),
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    try:
        result = await sync_custom_source(session, source_id=source_id, domain=domain, ai_enrich=ai_enrich, ai_provider=ai_provider)
        await audit(session, user, "ioc.sync_source", "ioc_source", source_id, {"domain": domain, "inserted": result.inserted, "updated": result.updated})
        return result
    except Exception as exc:
        logger.error("Custom IOC source sync failed: %s", exc, exc_info=True)
        raise HTTPException(400, "Operation failed. See server logs.") from exc


@router.post("/enrich/ttps", response_model=IOCMappingEnrichmentOut)
async def enrich_ioc_ttps_route(
    source_id: list[str] = Query(default_factory=list),
    ai_enrich: bool = Query(False),
    ai_provider: str = Query("local", pattern="^(local|claude|openai|gemini|minimax)$"),
    domain: str = Query("enterprise-attack"),
    limit: int = Query(500, ge=1, le=20000),
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    try:
        result = await enrich_ioc_ttp_mappings(
            session,
            source_ids=source_id or None,
            use_ai=ai_enrich,
            ai_provider=ai_provider,
            domain=domain,
            limit=limit,
        )
        await audit(session, user, "ioc.enrich_ttps", "ioc_source", details={"domain": domain, "checked": result.checked, "updated": result.updated})
        await session.commit()
        return result
    except Exception as exc:
        logger.error("IOC-to-TTP enrichment failed: %s", exc, exc_info=True)
        raise HTTPException(500, "Operation failed. See server logs.") from exc


@router.post("/import", response_model=SyncOut)
async def import_ioc_route(payload: IOCImportRequest, session: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst), _body=Depends(_limit_10mb)):
    items = [
        IOCImportItem(
            value=item.value,
            indicator_type=item.type,
            actor_attack_id=item.actor_attack_id,
            actor_name=item.actor_name,
            malware_family=item.malware_family,
            campaign=item.campaign,
            technique_ids=item.technique_ids,
            source=item.source,
            source_url=item.source_url,
            first_seen=item.first_seen,
            last_seen=item.last_seen,
            confidence=item.confidence,
            tlp=item.tlp,
            tags=item.tags,
            description=item.description,
            raw=item.raw,
        )
        for item in payload.indicators
    ]
    result = await import_iocs(session, items)
    await audit(session, user, "ioc.import", "ioc_source", details={"count": len(items), "inserted": result.get("inserted", 0), "updated": result.get("updated", 0)})
    return {**result, "days": None}


@router.post("/report", response_model=ReportIOCImportOut)
async def import_iocs_from_report(
    actor_attack_id: str | None = Form(default=None),
    actor_name: str | None = Form(default=None),
    source_url: str | None = Form(default=None),
    confidence: int = Form(default=65),
    file: UploadFile = File(...),
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    content = await file.read()
    if not content:
        raise HTTPException(400, "Uploaded report is empty")
    try:
        text = extract_text(content, file.filename or "report.txt")
        report_techniques = sorted({match.upper() for match in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text, flags=re.I)})
        items = extract_iocs_from_text(
            text,
            actor_attack_id=actor_attack_id or "",
            actor_name=actor_name or "",
            source_url=source_url or "",
            confidence=max(0, min(100, confidence)),
        )
        for item in items:
            item.technique_ids = report_techniques
        result = await import_iocs(session, items) if items else {"source": "manual-report-import", "inserted": 0, "updated": 0, "actor_links": 0}
        await audit(session, user, "ioc.import_report", "ioc_source", details={"filename": file.filename, "extracted": len(items), "inserted": result.get("inserted", 0)})
        preview = [
            {
                "value": item.value,
                "type": item.indicator_type,
                "source": item.source,
                "source_url": item.source_url,
                "first_seen": item.first_seen,
                "last_seen": item.last_seen,
                "confidence": item.confidence,
                "tlp": item.tlp,
                "malware_family": item.malware_family,
                "campaign": item.campaign,
                "technique_ids": item.technique_ids or [],
                "tags": item.tags or [],
                "description": item.description,
                "relationship": "attributed-to" if (item.actor_attack_id or item.actor_name) else "extracted-from-report",
                "evidence": item.description,
            }
            for item in items[:25]
        ]
        return {"filename": file.filename or "", "extracted": len(items), "imported": {**result, "days": None}, "preview": preview}
    except Exception as exc:
        logger.error("Report IOC extraction failed: %s", exc, exc_info=True)
        raise HTTPException(400, "Operation failed. See server logs.") from exc


@router.get("/actors/counts", response_model=IOCCountsOut)
async def actor_ioc_counts_route(
    actor_ids: list[str] = Query(default_factory=list),
    days: int = Query(180, ge=1, le=1825),
    active_only: bool = Query(True),
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
):
    return {"counts": await actor_ioc_counts(session, actor_ids=actor_ids, days=days, active_only=active_only)}


@router.get("/actors/{actor_id}", response_model=list[IOCOut])
async def actor_ioc_route(
    actor_id: str,
    days: int = Query(180, ge=1, le=1825),
    active_only: bool = Query(True),
    limit: int = Query(250, ge=1, le=1000),
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
):
    return await actor_iocs(session, actor_id, days=days, active_only=active_only, limit=limit)


@router.post("/actors/{actor_id}/enrich/otx")
async def enrich_actor_otx_route(
    actor_id: str,
    domain: str = Query("enterprise-attack"),
    aliases_per_group: int = Query(6, ge=1, le=10),
    pulses_per_alias: int = Query(5, ge=1, le=20),
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    try:
        result = await enrich_actor_from_otx(
            session,
            actor_id=actor_id,
            domain=domain,
            aliases_per_group=aliases_per_group,
            pulses_per_alias=pulses_per_alias,
        )
        await audit(session, user, "ioc.enrich_actor_otx", "ioc_source", actor_id, {"domain": domain})
        return result
    except Exception as exc:
        logger.error("Actor OTX enrichment failed: %s", exc, exc_info=True)
        status_code = 400 if "OTX_API_KEY" in str(exc) or "not found" in str(exc) else 502
        raise HTTPException(status_code, "Operation failed. See server logs.") from exc


@router.get("/actors/{actor_id}/summary")
async def actor_ioc_summary_route(
    actor_id: str,
    days: int = Query(180, ge=1, le=1825),
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
):
    return await actor_ioc_summary(session, actor_id, days=days)


@router.get("/actors/{actor_id}/export.csv")
async def actor_ioc_csv_route(
    actor_id: str,
    days: int = Query(180, ge=1, le=1825),
    active_only: bool = Query(True),
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
):
    rows = await actor_iocs(session, actor_id, days=days, active_only=active_only, limit=1000)
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "value",
            "type",
            "source",
            "source_url",
            "first_seen",
            "last_seen",
            "confidence",
            "tlp",
            "malware_family",
            "campaign",
            "technique_ids",
            "tags",
            "description",
            "relationship",
            "evidence",
        ],
    )
    writer.writeheader()
    for row in rows:
        writer.writerow({
            **row,
            "technique_ids": ",".join(row.get("technique_ids") or []),
            "tags": ",".join(row.get("tags") or []),
        })
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{actor_id}-iocs.csv"'},
    )
