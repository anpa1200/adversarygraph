from __future__ import annotations

import csv
import io
import re
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import Response, StreamingResponse
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
    enrich_ioc_ttp_mappings,
    import_iocs,
    list_ioc_library,
    list_ioc_sources,
    sync_custom_source,
    sync_malpedia_families,
    sync_otx_actor_pulses,
    sync_otx_subscribed_pulses,
    sync_threatfox,
)
from app.services.virustotal import lookup_virustotal_ioc
from app.services.ioc_stix import export_ioc_stix_bundle, import_ioc_stix_bundle, import_taxii_collection

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


class TAXIIImportIn(BaseModel):
    objects_url: str = Field(..., min_length=8)
    token: str = ""
    username: str = ""
    password: str = ""
    source_label: str = "TAXII IOC Import"


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
):
    try:
        return await import_ioc_stix_bundle(session, bundle, source_label=source_label, source_url=source_url)
    except Exception as exc:
        raise HTTPException(400, f"STIX IOC import failed: {exc}") from exc


@router.post("/import/taxii")
async def import_ioc_taxii_route(
    payload: TAXIIImportIn,
    session: AsyncSession = Depends(get_session),
):
    try:
        return await import_taxii_collection(
            session,
            objects_url=payload.objects_url,
            token=payload.token,
            username=payload.username,
            password=payload.password,
            source_label=payload.source_label,
        )
    except Exception as exc:
        raise HTTPException(400, f"TAXII IOC import failed: {exc}") from exc


@router.post("/sync/threatfox", response_model=SyncOut)
async def sync_threatfox_route(
    days: int = Query(7, ge=1, le=7),
    domain: str = Query("enterprise-attack"),
    ai_enrich: bool = Query(False),
    ai_provider: str = Query("local", pattern="^(local|claude|openai|gemini|minimax)$"),
    session: AsyncSession = Depends(get_session),
):
    try:
        return await sync_threatfox(session, days=days, domain=domain, ai_enrich=ai_enrich, ai_provider=ai_provider)
    except Exception as exc:
        status_code = 400 if "THREATFOX_AUTH_KEY" in str(exc) else 502
        raise HTTPException(status_code, f"ThreatFox sync failed: {exc}") from exc


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
):
    try:
        if mode == "subscribed":
            return await sync_otx_subscribed_pulses(session, domain=domain, limit=limit, ai_enrich=ai_enrich, ai_provider=ai_provider)
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
    ai_enrich: bool = Query(False),
    ai_provider: str = Query("local", pattern="^(local|claude|openai|gemini|minimax)$"),
    session: AsyncSession = Depends(get_session),
):
    try:
        return await sync_custom_source(session, source_id=source_id, domain=domain, ai_enrich=ai_enrich, ai_provider=ai_provider)
    except Exception as exc:
        raise HTTPException(400, f"Custom IOC source sync failed: {exc}") from exc


@router.post("/enrich/ttps", response_model=IOCMappingEnrichmentOut)
async def enrich_ioc_ttps_route(
    source_id: list[str] = Query(default_factory=list),
    ai_enrich: bool = Query(False),
    ai_provider: str = Query("local", pattern="^(local|claude|openai|gemini|minimax)$"),
    domain: str = Query("enterprise-attack"),
    limit: int = Query(500, ge=1, le=20000),
    session: AsyncSession = Depends(get_session),
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
        await session.commit()
        return result
    except Exception as exc:
        raise HTTPException(500, f"IOC-to-TTP enrichment failed: {exc}") from exc


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
