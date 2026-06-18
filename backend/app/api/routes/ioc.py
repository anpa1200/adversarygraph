from __future__ import annotations

import csv
import io
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.services.file_parser import extract_text
from app.services.ioc_extractor import extract_iocs_from_text
from app.services.ioc_intel import (
    IOCImportItem,
    actor_ioc_counts,
    actor_ioc_summary,
    actor_iocs,
    create_ioc_source,
    enrich_actor_from_otx,
    import_iocs,
    list_ioc_sources,
    sync_custom_source,
    sync_malpedia_families,
    sync_otx_actor_pulses,
    sync_otx_subscribed_pulses,
    sync_threatfox,
)
from app.services.virustotal import lookup_virustotal_ioc

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


class IOCImportIn(BaseModel):
    value: str = Field(..., min_length=1)
    type: str = Field(..., min_length=2)
    actor_attack_id: str | None = None
    actor_name: str | None = None
    malware_family: str = ""
    campaign: str = ""
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


class IOCOut(BaseModel):
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
    tags: list[str]
    description: str
    relationship: str
    evidence: str


class ReportIOCImportOut(BaseModel):
    filename: str
    extracted: int
    imported: SyncOut
    preview: list[IOCOut]


class IOCCountsOut(BaseModel):
    counts: dict[str, int]


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


@router.get("/sources", response_model=list[IOCSourceOut])
async def sources(session: AsyncSession = Depends(get_session)):
    return await list_ioc_sources(session)


@router.post("/virustotal/lookup", response_model=VirusTotalLookupOut)
async def virustotal_lookup(payload: VirusTotalLookupIn, session: AsyncSession = Depends(get_session)):
    try:
        return await lookup_virustotal_ioc(session, payload.indicator, domain=payload.domain)
    except ValueError as exc:
        raise HTTPException(404 if "not found" in str(exc).lower() else 400, str(exc)) from exc
    except RuntimeError as exc:
        status_code = 400 if "VIRUSTOTAL_API_KEY" in str(exc) else 502
        raise HTTPException(status_code, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(502, f"VirusTotal lookup failed: {type(exc).__name__}: {exc}") from exc


@router.post("/sources", response_model=IOCSourceOut)
async def create_source(payload: IOCSourceCreateIn, session: AsyncSession = Depends(get_session)):
    try:
        return await create_ioc_source(
            session,
            label=payload.label,
            url=payload.url,
            kind=payload.kind,
            source_id=payload.source_id,
        )
    except Exception as exc:
        raise HTTPException(400, f"Custom IOC source creation failed: {exc}") from exc


@router.post("/sync/threatfox", response_model=SyncOut)
async def sync_threatfox_route(
    days: int = Query(7, ge=1, le=7),
    domain: str = Query("enterprise-attack"),
    session: AsyncSession = Depends(get_session),
):
    try:
        return await sync_threatfox(session, days=days, domain=domain)
    except Exception as exc:
        status_code = 400 if "THREATFOX_AUTH_KEY" in str(exc) else 502
        raise HTTPException(status_code, f"ThreatFox sync failed: {exc}") from exc


@router.post("/sync/otx")
async def sync_otx_route(
    domain: str = Query("enterprise-attack"),
    mode: str = Query("subscribed", pattern="^(subscribed|actor-search)$"),
    limit: int = Query(100, ge=1, le=500),
    max_groups: int = Query(220, ge=1, le=500),
    aliases_per_group: int = Query(4, ge=1, le=8),
    pulses_per_alias: int = Query(5, ge=1, le=20),
    session: AsyncSession = Depends(get_session),
):
    try:
        if mode == "subscribed":
            return await sync_otx_subscribed_pulses(session, domain=domain, limit=limit)
        return await sync_otx_actor_pulses(
            session,
            domain=domain,
            max_groups=max_groups,
            aliases_per_group=aliases_per_group,
            pulses_per_alias=pulses_per_alias,
        )
    except Exception as exc:
        status_code = 400 if "OTX_API_KEY" in str(exc) else 502
        raise HTTPException(status_code, f"OTX sync failed: {exc}") from exc


@router.post("/sync/malpedia")
async def sync_malpedia_route(
    domain: str = Query("enterprise-attack"),
    session: AsyncSession = Depends(get_session),
):
    try:
        return await sync_malpedia_families(session, domain=domain)
    except Exception as exc:
        raise HTTPException(502, f"Malpedia sync failed: {exc}") from exc


@router.post("/sync/{source_id}", response_model=SyncOut)
async def sync_source_route(
    source_id: str,
    domain: str = Query("enterprise-attack"),
    session: AsyncSession = Depends(get_session),
):
    try:
        return await sync_custom_source(session, source_id=source_id, domain=domain)
    except Exception as exc:
        raise HTTPException(400, f"Custom IOC source sync failed: {exc}") from exc


@router.post("/import", response_model=SyncOut)
async def import_ioc_route(payload: IOCImportRequest, session: AsyncSession = Depends(get_session)):
    items = [
        IOCImportItem(
            value=item.value,
            indicator_type=item.type,
            actor_attack_id=item.actor_attack_id,
            actor_name=item.actor_name,
            malware_family=item.malware_family,
            campaign=item.campaign,
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
    return {**result, "days": None}


@router.post("/report", response_model=ReportIOCImportOut)
async def import_iocs_from_report(
    actor_attack_id: str | None = Form(default=None),
    actor_name: str | None = Form(default=None),
    source_url: str | None = Form(default=None),
    confidence: int = Form(default=65),
    file: UploadFile = File(...),
    session: AsyncSession = Depends(get_session),
):
    content = await file.read()
    if not content:
        raise HTTPException(400, "Uploaded report is empty")
    try:
        text = extract_text(content, file.filename or "report.txt")
        items = extract_iocs_from_text(
            text,
            actor_attack_id=actor_attack_id or "",
            actor_name=actor_name or "",
            source_url=source_url or "",
            confidence=max(0, min(100, confidence)),
        )
        result = await import_iocs(session, items) if items else {"source": "manual-report-import", "inserted": 0, "updated": 0, "actor_links": 0}
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
                "tags": item.tags or [],
                "description": item.description,
                "relationship": "attributed-to" if (item.actor_attack_id or item.actor_name) else "extracted-from-report",
                "evidence": item.description,
            }
            for item in items[:25]
        ]
        return {"filename": file.filename or "", "extracted": len(items), "imported": {**result, "days": None}, "preview": preview}
    except Exception as exc:
        raise HTTPException(400, f"Report IOC extraction failed: {exc}") from exc


@router.get("/actors/counts", response_model=IOCCountsOut)
async def actor_ioc_counts_route(
    actor_ids: list[str] = Query(default_factory=list),
    days: int = Query(180, ge=1, le=1825),
    active_only: bool = Query(True),
    session: AsyncSession = Depends(get_session),
):
    return {"counts": await actor_ioc_counts(session, actor_ids=actor_ids, days=days, active_only=active_only)}


@router.get("/actors/{actor_id}", response_model=list[IOCOut])
async def actor_ioc_route(
    actor_id: str,
    days: int = Query(180, ge=1, le=1825),
    active_only: bool = Query(True),
    limit: int = Query(250, ge=1, le=1000),
    session: AsyncSession = Depends(get_session),
):
    return await actor_iocs(session, actor_id, days=days, active_only=active_only, limit=limit)


@router.post("/actors/{actor_id}/enrich/otx")
async def enrich_actor_otx_route(
    actor_id: str,
    domain: str = Query("enterprise-attack"),
    aliases_per_group: int = Query(6, ge=1, le=10),
    pulses_per_alias: int = Query(5, ge=1, le=20),
    session: AsyncSession = Depends(get_session),
):
    try:
        return await enrich_actor_from_otx(
            session,
            actor_id=actor_id,
            domain=domain,
            aliases_per_group=aliases_per_group,
            pulses_per_alias=pulses_per_alias,
        )
    except Exception as exc:
        status_code = 400 if "OTX_API_KEY" in str(exc) or "not found" in str(exc) else 502
        raise HTTPException(status_code, f"Actor OTX enrichment failed: {exc}") from exc


@router.get("/actors/{actor_id}/summary")
async def actor_ioc_summary_route(
    actor_id: str,
    days: int = Query(180, ge=1, le=1825),
    session: AsyncSession = Depends(get_session),
):
    return await actor_ioc_summary(session, actor_id, days=days)


@router.get("/actors/{actor_id}/export.csv")
async def actor_ioc_csv_route(
    actor_id: str,
    days: int = Query(180, ge=1, le=1825),
    active_only: bool = Query(True),
    session: AsyncSession = Depends(get_session),
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
            "tags",
            "description",
            "relationship",
            "evidence",
        ],
    )
    writer.writeheader()
    for row in rows:
        writer.writerow({**row, "tags": ",".join(row.get("tags") or [])})
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{actor_id}-iocs.csv"'},
    )
