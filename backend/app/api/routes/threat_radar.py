from __future__ import annotations

import uuid
import hashlib
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.models.threat_radar import (
    ThreatAction,
    ThreatAuditLog,
    ThreatCase,
    ThreatCaseLink,
    ThreatClaim,
    ThreatCompanySpace,
    ThreatDetectionRequirement,
    ThreatDetectionRule,
    ThreatEntity,
    ThreatEvidence,
    ThreatHuntRequest,
    ThreatIREscalation,
    ThreatMarketplaceListing,
    ThreatProductMapping,
    ThreatPSIRTTask,
    ThreatReport,
    ThreatAlert,
    ThreatSpaceAIStep,
    ThreatSpaceAsset,
    ThreatSpaceDashboard,
    ThreatSpaceMonitor,
    ThreatSignal,
    ThreatScore,
    ThreatSource,
    ThreatSignalEntity,
    ThreatInventoryAsset,
    ThreatInventoryComponent,
    ThreatInventoryDependency,
    ThreatInventoryEdge,
    ThreatInventoryExposure,
    ThreatInventoryProduct,
    ThreatSupplyChainFinding,
)
from app.services.auth import TeamUser, analyst
from app.services.exposure_monitoring import (
    classify_exposure_hit,
    ingest_exposure_hit,
    monitoring_plan,
    provider_readiness,
)
from app.services.threat_radar import (
    LEGAL_SENSITIVE_TYPES,
    audit_log,
    case_to_dict,
    create_action,
    create_case_from_signal,
    generate_report,
    mapping_to_dict,
    mappings_for_signal,
    normalize_signal_type,
    recommended_actions,
    sanitize_evidence_summary,
    sanitize_metadata,
    score_signal,
    signal_to_dict,
)
from app.services.taxonomy import canonical_value, canonical_values, normalize_freeform_tags
from app.services.unified_model import (
    forward_alert_to_unified_model,
    forward_case_to_unified_model,
    forward_signal_to_unified_model,
    forward_space_asset_to_unified_model,
)

router = APIRouter(prefix="/threat-radar", tags=["Threat Radar"])

TLP = Literal["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"]


class ThreatSourceIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    source_type: str = "manual"
    url: str = ""
    reliability: int = Field(3, ge=0, le=5)
    tlp: TLP = "TLP:AMBER"
    legal_sensitive: bool = False
    enabled: bool = True
    notes: str = ""


class ThreatSourceOut(ThreatSourceIn):
    id: str
    created_at: datetime | None = None
    updated_at: datetime | None = None


class EvidenceIn(BaseModel):
    evidence_type: str = "note"
    title: str = ""
    summary: str = ""
    url: str = ""
    observed_at: str = ""
    tlp: TLP = "TLP:AMBER"
    legal_sensitive: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class ClaimIn(BaseModel):
    claim_type: str = "threat-claim"
    statement: str = ""
    credibility: int = Field(3, ge=0, le=5)
    status: str = "unvalidated"
    tlp: TLP = "TLP:AMBER"
    legal_sensitive: bool = False


class ProductMappingIn(BaseModel):
    product: str = Field(..., min_length=1, max_length=255)
    component: str = ""
    dependency: str = ""
    version: str = ""
    exposure: str = "unknown"
    environment: str = "unknown"
    relevance: int = Field(3, ge=0, le=5)
    blast_radius: int = Field(3, ge=0, le=5)
    evidence: str = ""
    tags: list[str] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)


class SignalCreateIn(BaseModel):
    title: str = Field(..., min_length=1, max_length=500)
    signal_type: str
    description: str = ""
    source_id: str | None = None
    source_name: str = ""
    source_url: str = ""
    source: ThreatSourceIn | None = None
    tlp: TLP = "TLP:AMBER"
    legal_sensitive: bool = False
    confidence: int = Field(50, ge=0, le=100)
    severity: str = "unknown"
    cve_ids: list[str] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)
    iocs: list[dict[str, Any]] = Field(default_factory=list)
    actors: list[str] = Field(default_factory=list)
    sectors: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    raw_metadata: dict[str, Any] = Field(default_factory=dict)
    evidence: list[EvidenceIn] = Field(default_factory=list)
    claims: list[ClaimIn] = Field(default_factory=list)
    product_mappings: list[ProductMappingIn] = Field(default_factory=list)
    create_case: bool = True

    @field_validator("signal_type")
    @classmethod
    def _valid_signal_type(cls, value: str) -> str:
        return normalize_signal_type(value)


class SignalTriageIn(BaseModel):
    status: str = "triaged"
    confidence: int | None = Field(None, ge=0, le=100)
    severity: str | None = None
    product_mappings: list[ProductMappingIn] = Field(default_factory=list)
    create_case: bool = True
    analyst_notes: str = ""


class SignalOut(BaseModel):
    id: str
    title: str
    signal_type: str
    description: str
    status: str
    source_id: str | None = None
    source_name: str
    source_url: str
    tlp: str
    legal_sensitive: bool
    confidence: int
    severity: str
    cve_ids: list[str]
    technique_ids: list[str]
    iocs: list[dict[str, Any]]
    actors: list[str]
    sectors: list[str]
    tags: list[str]
    raw_metadata: dict[str, Any]
    created_by: str
    created_at: datetime | None = None
    updated_at: datetime | None = None
    score: dict[str, Any] | None = None
    product_mappings: list[dict[str, Any]] = Field(default_factory=list)
    recommended_actions: list[dict[str, Any]] = Field(default_factory=list)


class CaseOut(BaseModel):
    id: str
    signal_id: str | None = None
    title: str
    summary: str
    status: str
    priority: str
    risk_score: int
    tlp: str
    legal_sensitive: bool
    recommended_actions: list[dict[str, Any]]
    product_context: list[dict[str, Any]]
    tags: list[str]
    created_by: str
    created_at: datetime | None = None
    updated_at: datetime | None = None


class ProductMapIn(BaseModel):
    signal_id: str | None = None
    case_id: str | None = None
    mappings: list[ProductMappingIn]


class ScoreOut(BaseModel):
    score: int
    priority: str
    factors: dict[str, int]
    rationale: list[str]
    recommended_actions: list[dict[str, Any]]


class ReportGenerateIn(BaseModel):
    report_type: str = "flash_note"


class ReportOut(BaseModel):
    id: str
    case_id: str
    report_type: str
    title: str
    markdown: str
    metadata: dict[str, Any]
    created_by: str
    created_at: datetime | None = None


class ExposureWatchTermIn(BaseModel):
    value: str = Field(..., min_length=1, max_length=255)
    type: str = "keyword"
    products: list[str] = Field(default_factory=list)
    components: list[str] = Field(default_factory=list)
    criticality: str = "unknown"
    tags: list[str] = Field(default_factory=list)


class ExposureHitIn(BaseModel):
    provider: str = Field("manual-exposure", min_length=1, max_length=120)
    provider_label: str = ""
    source_type: str = ""
    title: str = Field(..., min_length=1, max_length=500)
    summary: str = Field("", max_length=12000)
    url: str = Field("", max_length=1000)
    observed_at: str = ""
    product: str = ""
    component: str = ""
    supplier: str = ""
    version: str = ""
    exposure: str = "external-monitoring"
    environment: str = "unknown"
    ecosystem: str = ""
    handle: str = ""
    price: str = ""
    currency: str = ""
    confidence: int | None = Field(None, ge=0, le=100)
    severity: str = ""
    cve_ids: list[str] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)
    iocs: list[dict[str, Any]] = Field(default_factory=list)
    actors: list[str] = Field(default_factory=list)
    sectors: list[str] = Field(default_factory=list)
    affected_versions: list[str] = Field(default_factory=list)
    sbom_match: bool = False
    legal_sensitive: bool | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class ExposureMonitorRunIn(BaseModel):
    providers: list[str] = Field(default_factory=list)
    watch_terms: list[ExposureWatchTermIn] = Field(default_factory=list)


class CompanySpaceIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: str = ""
    owner: str = ""
    sector: str = ""
    region: str = ""
    tags: list[str] = Field(default_factory=list)
    settings: dict[str, Any] = Field(default_factory=dict)


class CompanySpaceOut(BaseModel):
    id: str
    name: str
    slug: str
    description: str
    owner: str
    sector: str
    region: str
    tags: list[str]
    settings: dict[str, Any]
    counts: dict[str, int] = Field(default_factory=dict)
    created_by: str
    created_at: datetime | None = None
    updated_at: datetime | None = None


class SpaceAssetIn(BaseModel):
    asset_id: str = ""
    name: str = Field(..., min_length=1, max_length=255)
    asset_type: str = "asset"
    environment: str = "unknown"
    owner: str = ""
    criticality: str = "medium"
    exposure: str = "unknown"
    products: list[str] = Field(default_factory=list)
    components: list[str] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    ip_addresses: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SpaceDashboardIn(BaseModel):
    name: str = "Threat Monitor view"
    dashboard_type: str = "threat-monitor"
    layout: dict[str, Any] = Field(default_factory=dict)
    widgets: list[dict[str, Any]] = Field(default_factory=list)


class SpaceMonitorIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    monitor_type: str = "asset-relevance"
    cadence: str = "daily"
    enabled: bool = True
    query: dict[str, Any] = Field(default_factory=dict)
    alert_threshold: int = Field(70, ge=0, le=100)


class SpaceAIStepIn(BaseModel):
    step: str = Field(..., min_length=1, max_length=120)
    context: dict[str, Any] = Field(default_factory=dict)


class ThreatMonitorSearchIn(BaseModel):
    query: str = "* | stats count by priority"
    timerange: str = "30d"
    limit: int = Field(100, ge=1, le=500)


class AlertStatusIn(BaseModel):
    status: str = Field("triaged", pattern="^(new|triaged|investigating|resolved|false_positive|suppressed)$")
    assignee: str = ""
    case_id: str | None = None


@router.get("/spaces", response_model=list[CompanySpaceOut])
async def list_company_spaces(
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
):
    rows = await session.execute(select(ThreatCompanySpace).order_by(ThreatCompanySpace.updated_at.desc()))
    return [await _space_out(session, row) for row in rows.scalars().all()]


@router.get("/spaces/metrics", response_model=dict[str, Any])
async def company_space_metrics(
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
):
    return {
        "spaces": await _count(session, ThreatCompanySpace),
        "assets": await _count(session, ThreatSpaceAsset),
        "dashboards": await _count(session, ThreatSpaceDashboard),
        "monitors": await _count(session, ThreatSpaceMonitor),
        "enabled_monitors": await _count(session, ThreatSpaceMonitor, ThreatSpaceMonitor.enabled.is_(True)),
        "rules": await _count(session, ThreatDetectionRule),
        "alerts": await _count(session, ThreatAlert),
    }


@router.post("/spaces", response_model=CompanySpaceOut, status_code=status.HTTP_201_CREATED)
async def create_company_space(
    payload: CompanySpaceIn,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    slug = await _unique_space_slug(session, payload.name)
    space = ThreatCompanySpace(
        name=payload.name.strip(),
        slug=slug,
        description=payload.description.strip(),
        owner=payload.owner.strip(),
        sector=canonical_value("sector", payload.sector) if payload.sector else "",
        region=canonical_value("region", payload.region) if payload.region else "",
        tags=normalize_freeform_tags(payload.tags),
        settings=payload.settings,
        created_by=user.name,
    )
    session.add(space)
    await session.flush()
    await _create_default_space_objects(session, space)
    await audit_log(session, user.name, "threat_radar.create_company_space", "threat_company_space", str(space.id), {"name": space.name})
    await session.commit()
    await session.refresh(space)
    return await _space_out(session, space)


@router.get("/spaces/{space_id}", response_model=dict[str, Any])
async def get_company_space(
    space_id: str,
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
):
    space = await _get_space(session, space_id)
    return await _space_detail(session, space)


@router.post("/spaces/{space_id}/assets", response_model=dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_space_asset(
    space_id: str,
    payload: SpaceAssetIn,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    space = await _get_space(session, space_id)
    asset = ThreatSpaceAsset(
        space_id=space.id,
        asset_id=payload.asset_id.strip() or f"asset-{uuid.uuid4().hex[:8]}",
        name=payload.name.strip(),
        asset_type=canonical_value("asset_type", payload.asset_type),
        environment=canonical_value("environment", payload.environment),
        owner=payload.owner.strip(),
        criticality=canonical_value("criticality", payload.criticality),
        exposure=canonical_value("exposure", payload.exposure),
        products=canonical_values("product", payload.products),
        components=canonical_values("dependency", payload.components),
        technologies=canonical_values("technology", payload.technologies),
        ip_addresses=[item.strip() for item in payload.ip_addresses if item.strip()],
        domains=[item.strip().lower() for item in payload.domains if item.strip()],
        tags=normalize_freeform_tags(payload.tags),
        metadata_json=sanitize_metadata("customer_report", payload.metadata),
    )
    session.add(asset)
    await _sync_inventory_graph_for_asset(session, asset)
    await forward_space_asset_to_unified_model(session, space, asset)
    await audit_log(session, user.name, "threat_radar.create_space_asset", "threat_space_asset", "", {"space_id": str(space.id), "asset": asset.name})
    await session.commit()
    await session.refresh(asset)
    return _asset_obj(asset)


@router.post("/spaces/{space_id}/dashboards", response_model=dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_space_dashboard(
    space_id: str,
    payload: SpaceDashboardIn,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    space = await _get_space(session, space_id)
    dashboard = ThreatSpaceDashboard(
        space_id=space.id,
        name=payload.name.strip() or "Threat Monitor view",
        dashboard_type=payload.dashboard_type.strip() or "threat-monitor",
        layout=payload.layout,
        widgets=payload.widgets or _default_dashboard_widgets(),
    )
    session.add(dashboard)
    await audit_log(session, user.name, "threat_radar.create_space_dashboard", "threat_space_dashboard", "", {"space_id": str(space.id), "name": dashboard.name})
    await session.commit()
    await session.refresh(dashboard)
    return _dashboard_obj(dashboard)


@router.post("/spaces/{space_id}/dashboards/generate", response_model=dict[str, Any], status_code=status.HTTP_201_CREATED)
async def generate_space_dashboard(
    space_id: str,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    space = await _get_space(session, space_id)
    generated = await _build_generated_space_dashboard(session, space)
    dashboard = ThreatSpaceDashboard(
        space_id=space.id,
        name=generated["name"],
        dashboard_type="threat-monitor",
        layout=jsonable_encoder(generated["layout"]),
        widgets=jsonable_encoder(generated["widgets"]),
    )
    session.add(dashboard)
    await audit_log(
        session,
        user.name,
        "threat_radar.generate_space_dashboard",
        "threat_space_dashboard",
        "",
        {"space_id": str(space.id), "widget_count": len(generated["widgets"])},
    )
    await session.commit()
    await session.refresh(dashboard)
    return _dashboard_obj(dashboard)


@router.post("/spaces/{space_id}/monitors", response_model=dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_space_monitor(
    space_id: str,
    payload: SpaceMonitorIn,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    space = await _get_space(session, space_id)
    monitor = ThreatSpaceMonitor(
        space_id=space.id,
        name=payload.name.strip(),
        monitor_type=payload.monitor_type,
        cadence=payload.cadence,
        enabled=payload.enabled,
        query=payload.query,
        alert_threshold=payload.alert_threshold,
    )
    session.add(monitor)
    await audit_log(session, user.name, "threat_radar.create_space_monitor", "threat_space_monitor", "", {"space_id": str(space.id), "name": monitor.name})
    await session.commit()
    await session.refresh(monitor)
    return _monitor_obj(monitor)


@router.post("/spaces/{space_id}/monitors/{monitor_id}/run", response_model=dict[str, Any])
async def run_space_monitor(
    space_id: str,
    monitor_id: str,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    space = await _get_space(session, space_id)
    monitor = await session.get(ThreatSpaceMonitor, _uuid_or_400(monitor_id))
    if not monitor or monitor.space_id != space.id:
        raise HTTPException(404, "Threat monitor not found")
    result = await _run_monitor(session, space, monitor)
    monitor.last_status = "alert" if result["max_score"] >= monitor.alert_threshold else "ok"
    monitor.last_result = result
    await audit_log(session, user.name, "threat_radar.run_space_monitor", "threat_space_monitor", str(monitor.id), result)
    await session.commit()
    await session.refresh(monitor)
    return _monitor_obj(monitor)


@router.post("/spaces/{space_id}/search", response_model=dict[str, Any])
async def search_threat_monitor(
    space_id: str,
    payload: ThreatMonitorSearchIn,
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
):
    space = await _get_space(session, space_id)
    alerts = await _alerts_for_space(session, space.id)
    return _run_backend_alert_query(alerts, payload.query, payload.limit)


@router.get("/spaces/{space_id}/alerts", response_model=list[dict[str, Any]])
async def list_space_alerts(
    space_id: str,
    status_filter: str | None = Query(None, alias="status"),
    limit: int = 100,
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
):
    space = await _get_space(session, space_id)
    stmt = select(ThreatAlert).where(ThreatAlert.space_id == space.id)
    if status_filter:
        stmt = stmt.where(ThreatAlert.status == status_filter)
    rows = (await session.execute(stmt.order_by(ThreatAlert.score.desc(), ThreatAlert.last_seen.desc()).limit(min(max(limit, 1), 500)))).scalars().all()
    return [_alert_obj(alert) for alert in rows]


@router.post("/spaces/{space_id}/alerts/{alert_id}/status", response_model=dict[str, Any])
async def update_alert_status(
    space_id: str,
    alert_id: str,
    payload: AlertStatusIn,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    space = await _get_space(session, space_id)
    alert = await session.get(ThreatAlert, _uuid_or_400(alert_id))
    if not alert or alert.space_id != space.id:
        raise HTTPException(404, "Threat alert not found")
    alert.status = payload.status
    alert.assignee = payload.assignee.strip()
    if payload.case_id:
        alert.case_id = _uuid_or_400(payload.case_id)
    await audit_log(session, user.name, "threat_radar.update_alert_status", "threat_alert", str(alert.id), {"status": alert.status, "assignee": alert.assignee})
    await session.commit()
    await session.refresh(alert)
    return _alert_obj(alert)


@router.post("/spaces/{space_id}/ai-assistant", response_model=dict[str, Any])
async def company_space_ai_assistant(
    space_id: str,
    payload: SpaceAIStepIn,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    space = await _get_space(session, space_id)
    detail = await _space_detail(session, space)
    guidance = _ai_step_guidance(payload.step, detail, payload.context)
    step = ThreatSpaceAIStep(
        space_id=space.id,
        step=payload.step,
        title=guidance["title"],
        guidance=guidance["guidance"],
        checklist=guidance["checklist"],
        created_by=user.name,
    )
    session.add(step)
    await audit_log(session, user.name, "threat_radar.company_space_ai_assistant", "threat_space_ai_step", "", {"space_id": str(space.id), "step": payload.step})
    await session.commit()
    await session.refresh(step)
    return _ai_step_obj(step)


@router.get("/sources", response_model=list[ThreatSourceOut])
async def list_sources(
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
):
    rows = await session.execute(select(ThreatSource).order_by(ThreatSource.name))
    return [_source_out(row) for row in rows.scalars().all()]


@router.post("/sources", response_model=ThreatSourceOut, status_code=status.HTTP_201_CREATED)
async def create_source(
    payload: ThreatSourceIn,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    source = ThreatSource(**payload.model_dump())
    session.add(source)
    await session.flush()
    await audit_log(session, user.name, "threat_radar.create_source", "threat_source", str(source.id), {"name": source.name})
    await session.commit()
    await session.refresh(source)
    return _source_out(source)


@router.get("/signals", response_model=list[SignalOut])
async def list_signals(
    signal_type: str | None = None,
    status_filter: str | None = Query(None, alias="status"),
    q: str | None = None,
    limit: int = 100,
    offset: int = 0,
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
):
    limit = min(max(limit, 1), 250)
    stmt = select(ThreatSignal)
    if signal_type:
        stmt = stmt.where(ThreatSignal.signal_type == normalize_signal_type(signal_type))
    if status_filter:
        stmt = stmt.where(ThreatSignal.status == status_filter)
    if q:
        pattern = f"%{q.strip()}%"
        stmt = stmt.where(or_(ThreatSignal.title.ilike(pattern), ThreatSignal.description.ilike(pattern), ThreatSignal.source_name.ilike(pattern)))
    rows = await session.execute(stmt.order_by(ThreatSignal.updated_at.desc()).offset(max(offset, 0)).limit(limit))
    out = []
    for signal in rows.scalars().all():
        mappings = await mappings_for_signal(session, signal.id)
        score = score_signal(signal, mappings)
        out.append(_signal_out(signal, mappings, score))
    return out


@router.post("/signals", response_model=dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_signal(
    payload: SignalCreateIn,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    source_id = await _resolve_source(session, payload, user)
    legal_sensitive = payload.legal_sensitive or payload.signal_type in LEGAL_SENSITIVE_TYPES
    tags = {payload.signal_type, *payload.tags}
    if legal_sensitive:
        tags.add("legal-sensitive")
    signal = ThreatSignal(
        title=payload.title,
        signal_type=payload.signal_type,
        description=payload.description,
        source_id=source_id,
        source_name=payload.source_name or (payload.source.name if payload.source else ""),
        source_url=payload.source_url or (payload.source.url if payload.source else ""),
        tlp=payload.tlp,
        legal_sensitive=legal_sensitive,
        confidence=payload.confidence,
        severity=payload.severity,
        cve_ids=canonical_values("cve", payload.cve_ids),
        technique_ids=canonical_values("ttp", payload.technique_ids),
        iocs=payload.iocs,
        actors=canonical_values("actor", payload.actors),
        sectors=canonical_values("sector", payload.sectors),
        tags=normalize_freeform_tags(tags),
        raw_metadata=sanitize_metadata(payload.signal_type, payload.raw_metadata),
        created_by=user.name,
    )
    session.add(signal)
    await session.flush()
    await _add_claims_evidence_mappings(session, signal, payload.claims, payload.evidence, payload.product_mappings, legal_sensitive)
    await _sync_signal_entities(session, signal)
    mappings = await mappings_for_signal(session, signal.id)
    score = score_signal(signal, mappings)
    recs = recommended_actions(signal, score, mappings)
    case = await create_case_from_signal(session, signal, user.name, mappings) if payload.create_case else None
    await forward_signal_to_unified_model(session, signal, mappings)
    if case:
        await forward_case_to_unified_model(session, case, signal, mappings)
    spaces = (await session.execute(select(ThreatCompanySpace))).scalars().all()
    for space in spaces:
        await _materialize_alerts_for_space(session, space)
    await audit_log(session, user.name, "threat_radar.create_signal", "threat_signal", str(signal.id), {"signal_type": signal.signal_type, "score": score.score})
    await session.commit()
    await session.refresh(signal)
    if case:
        await session.refresh(case)
    return {
        "signal": _signal_out(signal, mappings, score, recs),
        "case": case_to_dict(case) if case else None,
        "score": score.__dict__,
    }


@router.get("/signals/{signal_id}", response_model=SignalOut)
async def get_signal(
    signal_id: str,
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
):
    signal = await _get_signal(session, signal_id)
    mappings = await mappings_for_signal(session, signal.id)
    score = score_signal(signal, mappings)
    return _signal_out(signal, mappings, score)


@router.post("/signals/{signal_id}/triage", response_model=dict[str, Any])
async def triage_signal(
    signal_id: str,
    payload: SignalTriageIn,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    signal = await _get_signal(session, signal_id)
    signal.status = payload.status
    if payload.confidence is not None:
        signal.confidence = payload.confidence
    if payload.severity is not None:
        signal.severity = payload.severity
    if payload.product_mappings:
        await _add_product_mappings(session, signal, None, payload.product_mappings)
    mappings = await mappings_for_signal(session, signal.id)
    score = score_signal(signal, mappings)
    case = await create_case_from_signal(session, signal, user.name, mappings) if payload.create_case else None
    await forward_signal_to_unified_model(session, signal, mappings)
    if case:
        await forward_case_to_unified_model(session, case, signal, mappings)
    await audit_log(session, user.name, "threat_radar.triage_signal", "threat_signal", str(signal.id), {"status": payload.status, "notes": payload.analyst_notes})
    await session.commit()
    return {"signal": _signal_out(signal, mappings, score), "case": case_to_dict(case) if case else None}


@router.get("/cases", response_model=list[CaseOut])
async def list_cases(
    status_filter: str | None = Query(None, alias="status"),
    priority: str | None = None,
    limit: int = 100,
    offset: int = 0,
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
):
    stmt = select(ThreatCase)
    if status_filter:
        stmt = stmt.where(ThreatCase.status == status_filter)
    if priority:
        stmt = stmt.where(ThreatCase.priority.ilike(f"{priority}%"))
    rows = await session.execute(stmt.order_by(ThreatCase.updated_at.desc()).offset(max(offset, 0)).limit(min(max(limit, 1), 250)))
    return [case_to_dict(row) for row in rows.scalars().all()]


@router.get("/cases/{case_id}", response_model=dict[str, Any])
async def get_case(
    case_id: str,
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
):
    case = await _get_case(session, case_id)
    return await _case_detail(session, case)


@router.get("/cases/{case_id}/graph", response_model=dict[str, Any])
async def get_case_graph(
    case_id: str,
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
):
    case = await _get_case(session, case_id)
    links = (await session.execute(select(ThreatCaseLink).where(ThreatCaseLink.case_id == case.id))).scalars().all()
    nodes = [{"id": str(case.id), "type": "case", "label": case.title, "priority": case.priority}]
    edges = []
    if case.signal_id:
        nodes.append({"id": str(case.signal_id), "type": "signal", "label": "Source signal"})
        edges.append({"source": str(case.signal_id), "target": str(case.id), "relationship": "creates-case"})
    for link in links:
        node_id = f"{link.target_type}:{link.target_id}"
        nodes.append({"id": node_id, "type": link.target_type, "label": link.target_id, "confidence": link.confidence})
        edges.append({"source": str(case.id), "target": node_id, "relationship": link.relationship})
    return {"nodes": nodes, "edges": edges}


@router.post("/cases/{case_id}/score", response_model=ScoreOut)
async def rescore_case(
    case_id: str,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    case = await _get_case(session, case_id)
    signal = await session.get(ThreatSignal, case.signal_id) if case.signal_id else None
    if not signal:
        raise HTTPException(404, "Case has no source signal to rescore")
    mappings = await mappings_for_signal(session, signal.id)
    score = score_signal(signal, mappings)
    actions = recommended_actions(signal, score, mappings)
    case.risk_score = score.score
    case.priority = score.priority
    case.recommended_actions = actions
    session.add(ThreatScore(signal_id=signal.id, case_id=case.id, score=score.score, priority=score.priority, factors=score.factors, rationale=score.rationale))
    await audit_log(session, user.name, "threat_radar.rescore_case", "threat_case", str(case.id), {"score": score.score})
    await session.commit()
    return ScoreOut(score=score.score, priority=score.priority, factors=score.factors, rationale=score.rationale, recommended_actions=actions)


@router.post("/cases/{case_id}/escalate", response_model=dict[str, Any])
async def escalate_case(
    case_id: str,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    case = await _get_case(session, case_id)
    case.status = "escalated"
    ir = await create_action(session, case, "ir", user.name)
    await session.commit()
    return {"case": case_to_dict(case), "ir_escalation": _workflow_obj(ir)}


@router.post("/evidence", response_model=dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_evidence(
    payload: EvidenceIn,
    signal_id: str | None = None,
    case_id: str | None = None,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    legal_sensitive = payload.legal_sensitive
    evidence = ThreatEvidence(
        signal_id=_uuid_or_none(signal_id),
        case_id=_uuid_or_none(case_id),
        evidence_type=payload.evidence_type,
        title=payload.title,
        summary=sanitize_evidence_summary(payload.summary, legal_sensitive),
        url=payload.url,
        observed_at=payload.observed_at,
        tlp=payload.tlp,
        legal_sensitive=legal_sensitive,
        sanitized=True,
        metadata_json=sanitize_metadata("darknet_provider_mention" if legal_sensitive else "customer_report", payload.metadata),
    )
    session.add(evidence)
    await audit_log(session, user.name, "threat_radar.create_evidence", "threat_evidence", "", {"signal_id": signal_id, "case_id": case_id})
    await session.commit()
    return _evidence_obj(evidence)


@router.post("/product-map", response_model=list[dict[str, Any]], status_code=status.HTTP_201_CREATED)
async def create_product_map(
    payload: ProductMapIn,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    signal = await _get_signal(session, payload.signal_id) if payload.signal_id else None
    case = await _get_case(session, payload.case_id) if payload.case_id else None
    rows = await _add_product_mappings(session, signal, case, payload.mappings)
    if signal:
        await forward_signal_to_unified_model(session, signal, await mappings_for_signal(session, signal.id))
    if case:
        case_signal = await session.get(ThreatSignal, case.signal_id) if case.signal_id else None
        await forward_case_to_unified_model(session, case, case_signal, await mappings_for_signal(session, case_signal.id) if case_signal else [])
    await audit_log(session, user.name, "threat_radar.product_map", "threat_product_mapping", "", {"count": len(rows)})
    await session.commit()
    return [mapping_to_dict(row) for row in rows]


@router.post("/cases/{case_id}/create-hunt", response_model=dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_hunt(case_id: str, session: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    return await _create_workflow(session, case_id, "hunt", user)


@router.post("/cases/{case_id}/create-psirt-task", response_model=dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_psirt(case_id: str, session: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    return await _create_workflow(session, case_id, "psirt", user)


@router.post("/cases/{case_id}/create-ir-escalation", response_model=dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_ir(case_id: str, session: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    return await _create_workflow(session, case_id, "ir", user)


@router.post("/cases/{case_id}/create-detection-requirement", response_model=dict[str, Any], status_code=status.HTTP_201_CREATED)
async def create_detection(case_id: str, session: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    return await _create_workflow(session, case_id, "detection", user)


@router.post("/cases/{case_id}/generate-report", response_model=ReportOut, status_code=status.HTTP_201_CREATED)
async def generate_case_report(
    case_id: str,
    payload: ReportGenerateIn,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    case = await _get_case(session, case_id)
    report = await generate_report(session, case, payload.report_type, user.name)
    await session.commit()
    return _report_out(report)


@router.get("/product-exposure", response_model=list[dict[str, Any]])
async def product_exposure(session: AsyncSession = Depends(get_session), _: TeamUser = Depends(analyst)):
    rows = await session.execute(select(ThreatProductMapping).order_by(ThreatProductMapping.created_at.desc()).limit(250))
    return [mapping_to_dict(row) for row in rows.scalars().all()]


@router.get("/unified/entities", response_model=list[dict[str, Any]])
async def unified_entities(
    entity_type: str | None = None,
    q: str | None = None,
    limit: int = 250,
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
):
    stmt = select(ThreatEntity)
    if entity_type:
        stmt = stmt.where(ThreatEntity.entity_type == entity_type.strip().lower())
    if q:
        pattern = f"%{q.strip()}%"
        stmt = stmt.where(or_(ThreatEntity.value.ilike(pattern), ThreatEntity.label.ilike(pattern)))
    rows = (await session.execute(stmt.order_by(ThreatEntity.entity_type, ThreatEntity.value).limit(min(max(limit, 1), 1000)))).scalars().all()
    return [_entity_obj(row) for row in rows]


@router.get("/exposure/providers", response_model=list[dict[str, Any]])
async def exposure_providers(_: TeamUser = Depends(analyst)):
    return provider_readiness()


@router.post("/exposure/plan", response_model=dict[str, Any])
async def exposure_monitoring_plan(payload: ExposureMonitorRunIn, _: TeamUser = Depends(analyst)):
    return monitoring_plan(payload.providers, [item.model_dump() for item in payload.watch_terms])


@router.post("/exposure/classify", response_model=dict[str, Any])
async def classify_exposure(payload: ExposureHitIn, _: TeamUser = Depends(analyst)):
    return classify_exposure_hit(payload.model_dump())


@router.post("/exposure/ingest", response_model=dict[str, Any], status_code=status.HTTP_201_CREATED)
async def ingest_exposure(
    payload: ExposureHitIn,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    return await ingest_exposure_hit(session, payload.model_dump(), user.name)


@router.get("/watchlists/{watchlist}", response_model=list[SignalOut])
async def watchlist(
    watchlist: str,
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
):
    mapping = {
        "cve": {"cve_disclosure", "cisa_kev_active_exploitation", "public_poc"},
        "zero-day": {"zero_day_claim", "exploit_sale_claim", "darknet_provider_mention"},
        "supply-chain": {"malicious_package", "critical_dependency_vulnerability", "supplier_breach"},
        "hardware": {"marketplace_hardware_listing", "firmware_dump_claim"},
    }
    if watchlist not in mapping:
        raise HTTPException(404, "Unknown watchlist")
    rows = await session.execute(select(ThreatSignal).where(ThreatSignal.signal_type.in_(mapping[watchlist])).order_by(ThreatSignal.updated_at.desc()).limit(250))
    out = []
    for signal in rows.scalars().all():
        mappings = await mappings_for_signal(session, signal.id)
        out.append(_signal_out(signal, mappings, score_signal(signal, mappings)))
    return out


@router.get("/queues/{queue}", response_model=list[dict[str, Any]])
async def workflow_queue(queue: str, session: AsyncSession = Depends(get_session), _: TeamUser = Depends(analyst)):
    models = {
        "hunts": ThreatHuntRequest,
        "psirt": ThreatPSIRTTask,
        "ir": ThreatIREscalation,
        "detections": ThreatDetectionRequirement,
        "reports": ThreatReport,
        "actions": ThreatAction,
        "marketplace": ThreatMarketplaceListing,
        "supply-chain": ThreatSupplyChainFinding,
        "audit": ThreatAuditLog,
    }
    model = models.get(queue)
    if model is None:
        raise HTTPException(404, "Unknown queue")
    rows = await session.execute(select(model).limit(250))
    return [_workflow_obj(row) for row in rows.scalars().all()]


async def _create_workflow(session: AsyncSession, case_id: str, action_type: str, user: TeamUser) -> dict[str, Any]:
    case = await _get_case(session, case_id)
    obj = await create_action(session, case, action_type, user.name)
    await session.commit()
    return _workflow_obj(obj)


async def _resolve_source(session: AsyncSession, payload: SignalCreateIn, user: TeamUser) -> uuid.UUID | None:
    if payload.source_id:
        source = await session.get(ThreatSource, _uuid_or_400(payload.source_id))
        if not source:
            raise HTTPException(404, "Threat source not found")
        return source.id
    if payload.source:
        source = ThreatSource(**payload.source.model_dump())
        session.add(source)
        await session.flush()
        await audit_log(session, user.name, "threat_radar.create_source", "threat_source", str(source.id), {"name": source.name})
        return source.id
    return None


async def _add_claims_evidence_mappings(
    session: AsyncSession,
    signal: ThreatSignal,
    claims: list[ClaimIn],
    evidence_items: list[EvidenceIn],
    mappings: list[ProductMappingIn],
    legal_sensitive: bool,
) -> None:
    for claim in claims:
        session.add(ThreatClaim(
            signal_id=signal.id,
            claim_type=claim.claim_type,
            statement=sanitize_evidence_summary(claim.statement, legal_sensitive or claim.legal_sensitive),
            credibility=claim.credibility,
            status=claim.status,
            tlp=claim.tlp,
            legal_sensitive=legal_sensitive or claim.legal_sensitive,
        ))
    for evidence in evidence_items:
        session.add(ThreatEvidence(
            signal_id=signal.id,
            source_id=signal.source_id,
            evidence_type=evidence.evidence_type,
            title=evidence.title,
            summary=sanitize_evidence_summary(evidence.summary, legal_sensitive or evidence.legal_sensitive),
            url=evidence.url,
            observed_at=evidence.observed_at,
            tlp=evidence.tlp,
            legal_sensitive=legal_sensitive or evidence.legal_sensitive,
            sanitized=True,
            metadata=sanitize_metadata(signal.signal_type, evidence.metadata),
        ))
    await _add_product_mappings(session, signal, None, mappings)


async def _add_product_mappings(
    session: AsyncSession,
    signal: ThreatSignal | None,
    case: ThreatCase | None,
    mappings: list[ProductMappingIn],
) -> list[ThreatProductMapping]:
    rows = []
    for item in mappings:
        product = canonical_value("product", item.product)
        component = canonical_value("dependency", item.component)
        dependency = canonical_value("dependency", item.dependency)
        exposure = canonical_value("exposure", item.exposure)
        environment = canonical_value("environment", item.environment)
        tags = normalize_freeform_tags(
            [
                *item.tags,
                *[canonical_value("ttp", ttp) for ttp in item.technique_ids],
                f"product:{product}" if product else "",
                f"dependency:{component}" if component else "",
                f"dependency:{dependency}" if dependency else "",
                f"exposure:{exposure}" if exposure else "",
                f"environment:{environment}" if environment else "",
            ]
        )
        mapping = ThreatProductMapping(
            signal_id=signal.id if signal else None,
            case_id=case.id if case else None,
            product=product,
            component=component,
            dependency=dependency,
            version=item.version,
            exposure=exposure,
            environment=environment,
            relevance=item.relevance,
            blast_radius=item.blast_radius,
            evidence=item.evidence,
            tags=tags,
        )
        session.add(mapping)
        rows.append(mapping)
    await session.flush()
    return rows


async def _get_signal(session: AsyncSession, signal_id: str | None) -> ThreatSignal:
    if not signal_id:
        raise HTTPException(400, "Signal ID is required")
    signal = await session.get(ThreatSignal, _uuid_or_400(signal_id))
    if not signal:
        raise HTTPException(404, "Threat signal not found")
    return signal


async def _get_case(session: AsyncSession, case_id: str | None) -> ThreatCase:
    if not case_id:
        raise HTTPException(400, "Case ID is required")
    case = await session.get(ThreatCase, _uuid_or_400(case_id))
    if not case:
        raise HTTPException(404, "Threat case not found")
    return case


async def _case_detail(session: AsyncSession, case: ThreatCase) -> dict[str, Any]:
    links = (await session.execute(select(ThreatAction).where(ThreatAction.case_id == case.id))).scalars().all()
    reports = (await session.execute(select(ThreatReport).where(ThreatReport.case_id == case.id))).scalars().all()
    return {
        "case": case_to_dict(case),
        "actions": [_workflow_obj(row) for row in links],
        "reports": [_report_out(row) for row in reports],
    }


def _signal_out(signal: ThreatSignal, mappings: list[ThreatProductMapping], score=None, actions: list[dict[str, Any]] | None = None) -> SignalOut:
    score = score or score_signal(signal, mappings)
    return SignalOut(
        **signal_to_dict(signal),
        score={"score": score.score, "priority": score.priority, "factors": score.factors, "rationale": score.rationale},
        product_mappings=[mapping_to_dict(row) for row in mappings],
        recommended_actions=actions or recommended_actions(signal, score, mappings),
    )


def _source_out(source: ThreatSource) -> ThreatSourceOut:
    return ThreatSourceOut(
        id=str(source.id),
        name=source.name,
        source_type=source.source_type,
        url=source.url,
        reliability=source.reliability,
        tlp=source.tlp,
        legal_sensitive=source.legal_sensitive,
        enabled=source.enabled,
        notes=source.notes,
        created_at=source.created_at,
        updated_at=source.updated_at,
    )


def _workflow_obj(obj: Any) -> dict[str, Any]:
    data = {}
    for key, value in vars(obj).items():
        if key.startswith("_"):
            continue
        if isinstance(value, uuid.UUID):
            data[key] = str(value)
        else:
            data[key] = value
    return data


def _report_out(report: ThreatReport) -> ReportOut:
    return ReportOut(
        id=str(report.id),
        case_id=str(report.case_id),
        report_type=report.report_type,
        title=report.title,
        markdown=report.markdown,
        metadata=report.metadata_json or {},
        created_by=report.created_by,
        created_at=report.created_at,
    )


def _evidence_obj(evidence: ThreatEvidence) -> dict[str, Any]:
    return {
        "id": str(evidence.id),
        "signal_id": str(evidence.signal_id) if evidence.signal_id else None,
        "case_id": str(evidence.case_id) if evidence.case_id else None,
        "evidence_type": evidence.evidence_type,
        "title": evidence.title,
        "summary": evidence.summary,
        "url": evidence.url,
        "tlp": evidence.tlp,
        "legal_sensitive": evidence.legal_sensitive,
        "sanitized": evidence.sanitized,
        "metadata": evidence.metadata_json or {},
        "created_at": evidence.created_at,
    }


def _entity_obj(entity: ThreatEntity) -> dict[str, Any]:
    return {
        "id": str(entity.id),
        "entity_type": entity.entity_type,
        "value": entity.value,
        "label": entity.label,
        "tags": entity.tags or [],
        "metadata": entity.metadata_json or {},
        "created_at": entity.created_at,
    }


async def _get_space(session: AsyncSession, space_id: str | None) -> ThreatCompanySpace:
    if not space_id:
        raise HTTPException(400, "Company space ID is required")
    space = await session.get(ThreatCompanySpace, _uuid_or_400(space_id))
    if not space:
        raise HTTPException(404, "Company space not found")
    return space


async def _space_out(session: AsyncSession, space: ThreatCompanySpace) -> CompanySpaceOut:
    counts = {
        "assets": await _count(session, ThreatSpaceAsset, ThreatSpaceAsset.space_id == space.id),
        "dashboards": await _count(
            session,
            ThreatSpaceDashboard,
            ThreatSpaceDashboard.space_id == space.id,
            ThreatSpaceDashboard.dashboard_type == "threat-monitor",
        ),
        "monitors": await _count(session, ThreatSpaceMonitor, ThreatSpaceMonitor.space_id == space.id),
        "rules": await _count(session, ThreatDetectionRule, ThreatDetectionRule.space_id == space.id),
        "alerts": await _count(session, ThreatAlert, ThreatAlert.space_id == space.id),
        "ai_steps": await _count(session, ThreatSpaceAIStep, ThreatSpaceAIStep.space_id == space.id),
    }
    return CompanySpaceOut(
        id=str(space.id),
        name=space.name,
        slug=space.slug,
        description=space.description,
        owner=space.owner,
        sector=space.sector,
        region=space.region,
        tags=space.tags or [],
        settings=space.settings or {},
        counts=counts,
        created_by=space.created_by,
        created_at=space.created_at,
        updated_at=space.updated_at,
    )


async def _space_detail(session: AsyncSession, space: ThreatCompanySpace) -> dict[str, Any]:
    assets = (await session.execute(select(ThreatSpaceAsset).where(ThreatSpaceAsset.space_id == space.id).order_by(ThreatSpaceAsset.updated_at.desc()))).scalars().all()
    dashboards = (
        await session.execute(
            select(ThreatSpaceDashboard)
            .where(
                ThreatSpaceDashboard.space_id == space.id,
                ThreatSpaceDashboard.dashboard_type == "threat-monitor",
            )
            .order_by(ThreatSpaceDashboard.updated_at.desc())
        )
    ).scalars().all()
    monitors = (await session.execute(select(ThreatSpaceMonitor).where(ThreatSpaceMonitor.space_id == space.id).order_by(ThreatSpaceMonitor.updated_at.desc()))).scalars().all()
    ai_steps = (await session.execute(select(ThreatSpaceAIStep).where(ThreatSpaceAIStep.space_id == space.id).order_by(ThreatSpaceAIStep.created_at.desc()).limit(20))).scalars().all()
    return {
        "space": (await _space_out(session, space)).model_dump(),
        "assets": [_asset_obj(item) for item in assets],
        "dashboards": [_dashboard_obj(item) for item in dashboards],
        "monitors": [_monitor_obj(item) for item in monitors],
        "ai_steps": [_ai_step_obj(item) for item in ai_steps],
    }


async def _count(session: AsyncSession, model: Any, *criteria: Any) -> int:
    stmt = select(func.count()).select_from(model)
    for criterion in criteria:
        stmt = stmt.where(criterion)
    result = await session.execute(stmt)
    try:
        value = result.scalar_one()
    except Exception:
        value = result.scalar_one_or_none()
    if value is not None:
        return int(value or 0)
    fallback = select(model)
    for criterion in criteria:
        fallback = fallback.where(criterion)
    return len((await session.execute(fallback)).scalars().all())


async def _unique_space_slug(session: AsyncSession, name: str) -> str:
    base = _slug(name) or f"company-{uuid.uuid4().hex[:8]}"
    candidate = base
    suffix = 2
    while (await session.execute(select(ThreatCompanySpace.id).where(ThreatCompanySpace.slug == candidate))).scalar_one_or_none():
        candidate = f"{base}-{suffix}"
        suffix += 1
    return candidate


async def _create_default_space_objects(session: AsyncSession, space: ThreatCompanySpace) -> None:
    dashboard = ThreatSpaceDashboard(space_id=space.id, name="Company threat monitor", dashboard_type="threat-monitor", widgets=_default_dashboard_widgets())
    monitors = [
        ThreatSpaceMonitor(
            space_id=space.id,
            name="Asset-CVE and active exploitation relevance",
            monitor_type="asset-cve-actor-relevance",
            cadence="daily",
            query={"signal_types": ["cisa_kev_active_exploitation", "cve_disclosure", "public_poc"], "asset_scope": "all"},
            alert_threshold=70,
        ),
        ThreatSpaceMonitor(
            space_id=space.id,
            name="Leak, credential and prototype exposure",
            monitor_type="exposure-monitoring",
            cadence="daily",
            query={"signal_types": ["credential_exposure", "source_code_leak_claim", "marketplace_hardware_listing"], "asset_scope": "all"},
            alert_threshold=65,
        ),
    ]
    session.add(dashboard)
    for monitor in monitors:
        session.add(monitor)
    rules = [
        ThreatDetectionRule(
            space_id=space.id,
            name="New high-priority asset alerts",
            query="status:new priority:P1 OR priority:P0 | sort -score | limit 50",
            schedule="hourly",
            severity="high",
            threshold=75,
            suppression={"window": "24h", "dedup_fields": ["signal_id", "matched_entity"]},
        ),
        ThreatDetectionRule(
            space_id=space.id,
            name="Supply-chain and leak exposure",
            query="match_type:supply-chain OR signal_type:supplier_breach OR signal_type:source_code_leak_claim | sort -score | limit 50",
            schedule="daily",
            severity="medium",
            threshold=60,
            suppression={"window": "24h", "dedup_fields": ["signal_id", "asset_id", "match_type"]},
        ),
    ]
    for rule in rules:
        session.add(rule)


def _default_dashboard_widgets() -> list[dict[str, Any]]:
    return [
        {"id": "status-strip", "title": "Alert Status", "kind": "metric-grid", "source": "alerts", "query": "* | stats count by priority"},
        {"id": "alerts", "title": "Alert Triage Queue", "kind": "table", "source": "alerts", "query": "status:new OR status:triaged | sort -score | limit 25"},
        {"id": "alert-asset-match", "title": "CVE / IOC / Attack To Assets", "kind": "donut-alert-table", "source": "alerts", "query": "match_type:asset | stats count by priority"},
        {"id": "alert-technology-match", "title": "CVE / IOC / Attack To Technologies", "kind": "donut-alert-table", "source": "alerts", "query": "match_type:technology | stats count by matched_terms"},
        {"id": "alert-supply-chain-match", "title": "CVE / IOC / Attack To Supply Chain", "kind": "donut-alert-table", "source": "alerts", "query": "match_type:supply-chain | stats count by matched_terms"},
        {"id": "cve-exposure", "title": "CVE / Exploitation Exposure", "kind": "table", "source": "alerts", "query": "cve:* | sort -score | limit 25"},
        {"id": "breach-leak-exposure", "title": "Breaches / Leaks / Darknet Exposure", "kind": "table", "source": "alerts", "query": "supply-chain OR leak OR breach OR credential | sort -score | limit 25"},
        {"id": "signal-mix", "title": "Alert Mix", "kind": "bar", "source": "alerts", "query": "* | stats count by match_type"},
        {"id": "monitor-health", "title": "Rule / Monitor Health", "kind": "status", "source": "rules", "query": "* | stats count by last_status"},
    ]


async def _build_generated_space_dashboard(session: AsyncSession, space: ThreatCompanySpace) -> dict[str, Any]:
    assets = list((await session.execute(select(ThreatSpaceAsset).where(ThreatSpaceAsset.space_id == space.id))).scalars().all())
    monitors = list((await session.execute(select(ThreatSpaceMonitor).where(ThreatSpaceMonitor.space_id == space.id))).scalars().all())
    signals = list((await session.execute(select(ThreatSignal).order_by(ThreatSignal.updated_at.desc()).limit(500))).scalars().all())
    cases = list((await session.execute(select(ThreatCase).order_by(ThreatCase.updated_at.desc()).limit(500))).scalars().all())
    persisted_alert_rows = await _materialize_alerts_for_space(session, space)
    asset_terms = _asset_terms(assets)
    relevant_signals: list[dict[str, Any]] = []
    relevant_signal_ids: set[uuid.UUID] = set()
    asset_alert_rows: list[dict[str, Any]] = []
    technology_alert_rows: list[dict[str, Any]] = []
    supply_chain_alert_rows: list[dict[str, Any]] = []
    for signal in signals:
        mappings = await mappings_for_signal(session, signal.id)
        overlap = _signal_asset_overlap(signal, mappings, asset_terms)
        if not overlap:
            continue
        score = score_signal(signal, mappings)
        relevant_signal_ids.add(signal.id)
        asset_rows, technology_rows, supply_chain_rows = _alert_match_rows(signal, mappings, score, assets)
        asset_alert_rows.extend(asset_rows)
        technology_alert_rows.extend(technology_rows)
        supply_chain_alert_rows.extend(supply_chain_rows)
        relevant_signals.append({
            "id": str(signal.id),
            "title": signal.title,
            "signal_type": signal.signal_type,
            "severity": signal.severity,
            "confidence": signal.confidence,
            "score": score.score,
            "priority": score.priority,
            "cve_ids": signal.cve_ids or [],
            "technique_ids": signal.technique_ids or [],
            "ioc_count": len(signal.iocs or []),
            "actors": signal.actors or [],
            "matched_terms": overlap[:12],
            "route": f"/threat-radar?tab=detail&signal_id={signal.id}",
        })
    relevant_signals.sort(key=lambda item: (int(item["score"]), int(item["confidence"])), reverse=True)
    relevant_cases = [case for case in cases if case.signal_id in relevant_signal_ids]
    open_cases = [case for case in relevant_cases if case.status not in {"closed", "resolved", "dismissed"}]
    signal_types = _count_values([item["signal_type"] for item in relevant_signals])
    cve_rows = [item for item in relevant_signals if item["cve_ids"] or item["signal_type"] in {"cve_disclosure", "cisa_kev_active_exploitation", "public_poc", "zero_day_claim"}]
    breach_rows = [
        item for item in relevant_signals
        if item["signal_type"] in {
            "credential_exposure",
            "source_code_leak_claim",
            "supplier_breach",
            "darknet_provider_mention",
            "marketplace_hardware_listing",
            "firmware_dump_claim",
        }
    ]
    monitor_status = _count_values([monitor.last_status or "not-run" for monitor in monitors])
    persisted_asset_alert_rows = [row for row in persisted_alert_rows if row.get("match_type") == "asset"]
    persisted_technology_alert_rows = [row for row in persisted_alert_rows if row.get("match_type") == "technology"]
    persisted_supply_chain_alert_rows = [row for row in persisted_alert_rows if row.get("match_type") == "supply-chain"]
    if persisted_alert_rows:
        relevant_signals = persisted_alert_rows[:50]
        asset_alert_rows = persisted_asset_alert_rows
        technology_alert_rows = persisted_technology_alert_rows
        supply_chain_alert_rows = persisted_supply_chain_alert_rows
        signal_types = _count_values([str(row.get("match_type") or "alert") for row in persisted_alert_rows])
        cve_rows = [row for row in persisted_alert_rows if any(str(term).lower().startswith("cve-") for term in row.get("matched_terms", []))]
        breach_rows = [row for row in persisted_alert_rows if str(row.get("match_type")) == "supply-chain" or any(term in str(row).lower() for term in ["leak", "breach", "credential", "firmware"])]
    return {
        "name": f"{space.name} threat monitor",
        "layout": {
            "generated_at": datetime.now(UTC).isoformat(),
            "space_id": str(space.id),
            "columns": 12,
            "source": "persisted-alert-store",
        },
        "widgets": [
            {
                "id": "status-strip",
                "title": "Alert Status",
                "kind": "metric-grid",
                "source": "alerts",
                "query": "* | stats count by priority",
                "metrics": [
                    {"label": "Open alerts", "value": len([row for row in persisted_alert_rows if row.get("status") not in {"resolved", "false_positive", "suppressed"}])},
                    {"label": "P0/P1", "value": len([row for row in persisted_alert_rows if str(row.get("priority", "")).startswith(("P0", "P1"))])},
                    {"label": "New", "value": len([row for row in persisted_alert_rows if row.get("status") == "new"])},
                    {"label": "Rules/monitors", "value": len(monitors)},
                ],
                "rows": persisted_alert_rows[:12],
            },
            {
                "id": "alert-asset-match",
                "title": "CVE / IOC / Attack To Assets",
                "kind": "donut-alert-table",
                "source": "alerts",
                "query": "match_type:asset | stats count by priority",
                "metrics": [
                    {"label": "Asset matches", "value": len(asset_alert_rows)},
                    {"label": "Critical/high assets", "value": sum(1 for row in asset_alert_rows if str(row.get("criticality", "")).lower() in {"critical", "high"})},
                    {"label": "CVE-linked", "value": sum(1 for row in asset_alert_rows if _row_has_prefix(row, "cve-"))},
                    {"label": "IOC-linked", "value": sum(1 for row in asset_alert_rows if row.get("ioc_count") or _row_has_ioc(row))},
                ],
                "points": _count_values([str(row.get("severity") or row.get("priority") or "unknown") for row in asset_alert_rows]),
                "rows": asset_alert_rows[:20],
            },
            {
                "id": "alert-technology-match",
                "title": "CVE / IOC / Attack To Technologies",
                "kind": "donut-alert-table",
                "source": "alerts",
                "query": "match_type:technology | stats count by matched_terms",
                "metrics": [
                    {"label": "Technology matches", "value": len(technology_alert_rows)},
                    {"label": "Technologies", "value": len({term for row in technology_alert_rows for term in row.get("matched_terms", [])})},
                    {"label": "Attack/TTP-linked", "value": sum(1 for row in technology_alert_rows if _row_has_prefix(row, "t"))},
                    {"label": "CVE-linked", "value": sum(1 for row in technology_alert_rows if _row_has_prefix(row, "cve-"))},
                ],
                "points": _count_values([term for row in technology_alert_rows for term in row.get("matched_terms", [])]),
                "rows": technology_alert_rows[:20],
            },
            {
                "id": "alert-supply-chain-match",
                "title": "CVE / IOC / Attack To Supply Chain",
                "kind": "donut-alert-table",
                "source": "alerts",
                "query": "match_type:supply-chain | stats count by matched_terms",
                "metrics": [
                    {"label": "Supply-chain matches", "value": len(supply_chain_alert_rows)},
                    {"label": "Components/dependencies", "value": len({term for row in supply_chain_alert_rows for term in row.get("matched_terms", [])})},
                    {"label": "Leak/breach signals", "value": sum(1 for row in supply_chain_alert_rows if row.get("signal_type") in {"supplier_breach", "malicious_package", "critical_dependency_vulnerability", "source_code_leak_claim", "firmware_dump_claim"} or any(term in str(row).lower() for term in ["leak", "breach", "firmware"]))},
                    {"label": "IOC-linked", "value": sum(1 for row in supply_chain_alert_rows if row.get("ioc_count") or _row_has_ioc(row))},
                ],
                "points": _count_values([str(row.get("signal_type") or "unknown") for row in supply_chain_alert_rows]),
                "rows": supply_chain_alert_rows[:20],
            },
            {
                "id": "alerts",
                "title": "Alert Triage Queue",
                "kind": "table",
                "source": "alerts",
                "query": "status:new OR status:triaged | sort -score | limit 25",
                "metrics": [
                    {"label": "Alerts", "value": len(relevant_signals)},
                    {"label": "P0/P1 cases", "value": sum(1 for case in open_cases if case.priority.startswith(("P0", "P1")))},
                    {"label": "Open cases", "value": len(open_cases)},
                ],
                "rows": relevant_signals[:12],
            },
            {
                "id": "cve-exposure",
                "title": "CVE / Exploitation Exposure",
                "kind": "table",
                "source": "alerts",
                "query": "cve:* | sort -score | limit 25",
                "metrics": [
                    {"label": "CVE-linked signals", "value": len(cve_rows)},
                    {"label": "Unique CVEs", "value": len({cve for row in cve_rows for cve in _row_cves(row)})},
                    {"label": "Critical/high rows", "value": sum(1 for row in cve_rows if str(row.get("severity", "")).lower() in {"critical", "high"} or str(row.get("priority", "")).startswith(("P0", "P1")))},
                ],
                "rows": cve_rows[:12],
            },
            {
                "id": "breach-leak-exposure",
                "title": "Breaches / Leaks / Darknet Exposure",
                "kind": "table",
                "source": "alerts",
                "query": "supply-chain OR leak OR breach OR credential | sort -score | limit 25",
                "metrics": [
                    {"label": "Exposure signals", "value": len(breach_rows)},
                    {"label": "Legal-sensitive", "value": sum(1 for signal in signals if signal.id in relevant_signal_ids and signal.legal_sensitive)},
                ],
                "rows": breach_rows[:12],
            },
            {
                "id": "signal-mix",
                "title": "Alert Mix",
                "kind": "bar",
                "source": "alerts",
                "query": "* | stats count by match_type",
                "points": signal_types,
            },
            {
                "id": "monitor-health",
                "title": "Rule / Monitor Health",
                "kind": "status",
                "source": "rules",
                "query": "* | stats count by last_status",
                "points": monitor_status,
                "rows": [_monitor_obj(monitor) for monitor in monitors],
            },
        ],
    }


async def _run_monitor(session: AsyncSession, space: ThreatCompanySpace, monitor: ThreatSpaceMonitor) -> dict[str, Any]:
    assets = (await session.execute(select(ThreatSpaceAsset).where(ThreatSpaceAsset.space_id == space.id))).scalars().all()
    signals = (await session.execute(select(ThreatSignal).order_by(ThreatSignal.updated_at.desc()).limit(250))).scalars().all()
    asset_terms = _asset_terms(assets)
    matches: list[dict[str, Any]] = []
    max_score = 0
    for signal in signals:
        mappings = await mappings_for_signal(session, signal.id)
        score = score_signal(signal, mappings)
        overlap = _signal_asset_overlap(signal, mappings, asset_terms)
        if not overlap:
            continue
        max_score = max(max_score, score.score)
        matches.append({
            "signal_id": str(signal.id),
            "title": signal.title,
            "signal_type": signal.signal_type,
            "score": score.score,
            "priority": score.priority,
            "matched_terms": overlap[:12],
        })
    alert_rows = await _materialize_alerts_for_space(session, space, monitor=monitor)
    return {
        "space_id": str(space.id),
        "asset_count": len(assets),
        "match_count": len(matches),
        "alert_count": len(alert_rows),
        "max_score": max_score,
        "matches": matches[:25],
        "recommendation": "Open a case or create hunt/PSIRT actions for matches above threshold." if matches else "No relevant signals matched this company asset inventory.",
    }


async def _sync_inventory_graph_for_asset(session: AsyncSession, asset: ThreatSpaceAsset) -> None:
    existing = (await session.execute(
        select(ThreatInventoryAsset).where(
            ThreatInventoryAsset.space_id == asset.space_id,
            ThreatInventoryAsset.asset_id == asset.asset_id,
        )
    )).scalar_one_or_none()
    inv_asset = existing or ThreatInventoryAsset(space_id=asset.space_id, legacy_asset_id=asset.id, asset_id=asset.asset_id)
    inv_asset.legacy_asset_id = asset.id
    inv_asset.name = asset.name
    inv_asset.asset_type = asset.asset_type
    inv_asset.environment = asset.environment
    inv_asset.owner = asset.owner
    inv_asset.criticality = asset.criticality
    inv_asset.tags = asset.tags or []
    inv_asset.metadata_json = asset.metadata_json or {}
    session.add(inv_asset)
    await session.flush()

    product_by_name: dict[str, ThreatInventoryProduct] = {}
    for product_name in asset.products or []:
        product = ThreatInventoryProduct(
            space_id=asset.space_id,
            asset_ref_id=inv_asset.id,
            name=product_name,
            vendor=str((asset.metadata_json or {}).get("vendor", "")),
            version=str((asset.metadata_json or {}).get("product_version", "")),
            cpe=str((asset.metadata_json or {}).get("cpe", "")),
            tags=[f"asset:{asset.asset_id}", "compat-ingest"],
        )
        session.add(product)
        await session.flush()
        product_by_name[product_name] = product
        session.add(ThreatInventoryEdge(space_id=asset.space_id, src_id=str(inv_asset.id), src_type="asset", dst_id=str(product.id), dst_type="product", relationship="runs"))

    default_product = next(iter(product_by_name.values()), None)
    for component_name in asset.components or []:
        component = ThreatInventoryComponent(
            space_id=asset.space_id,
            product_id=default_product.id if default_product else None,
            name=component_name,
            component_type=str((asset.metadata_json or {}).get("component_type", "")),
            version=str((asset.metadata_json or {}).get("component_version", "")),
            cpe=str((asset.metadata_json or {}).get("component_cpe", "")),
            purl=str((asset.metadata_json or {}).get("purl", "")),
            tags=[f"asset:{asset.asset_id}", "compat-ingest"],
        )
        session.add(component)
        await session.flush()
        if default_product:
            session.add(ThreatInventoryEdge(space_id=asset.space_id, src_id=str(default_product.id), src_type="product", dst_id=str(component.id), dst_type="component", relationship="contains"))
        dependency_values = _metadata_lookup_values(asset.metadata_json or {}, {"dependency", "dependencies", "package", "packages", "purl"})
        for value in dependency_values:
            dependency = ThreatInventoryDependency(
                space_id=asset.space_id,
                component_id=component.id,
                package_name=str(value),
                purl=str(value) if str(value).startswith("pkg:") else "",
                cpe=str(value) if str(value).startswith("cpe:") else "",
                supplier=str((asset.metadata_json or {}).get("supplier", "")),
                relationship="compat-metadata",
                tags=[f"asset:{asset.asset_id}", "sbom-candidate"],
            )
            session.add(dependency)
            await session.flush()
            session.add(ThreatInventoryEdge(space_id=asset.space_id, src_id=str(component.id), src_type="component", dst_id=str(dependency.id), dst_type="dependency", relationship="depends-on"))

    ports = [str(item) for item in _metadata_lookup_values(asset.metadata_json or {}, {"port", "ports"})]
    for domain in asset.domains or [""]:
        for ip in asset.ip_addresses or [""]:
            exposure = ThreatInventoryExposure(
                space_id=asset.space_id,
                target_id=inv_asset.id,
                target_type="asset",
                kind=asset.exposure,
                ip=ip,
                domain=domain,
                port=ports[0] if ports else "",
                tags=[asset.environment, asset.criticality, "compat-ingest"],
            )
            session.add(exposure)


async def _sync_signal_entities(session: AsyncSession, signal: ThreatSignal) -> list[ThreatSignalEntity]:
    mappings = await mappings_for_signal(session, signal.id)
    entities = _extract_signal_entities(signal, mappings)
    stored: list[ThreatSignalEntity] = []
    for entity_type, value, confidence, source in entities:
        value = value.strip()
        if not value:
            continue
        existing = (await session.execute(
            select(ThreatSignalEntity).where(
                ThreatSignalEntity.signal_id == signal.id,
                ThreatSignalEntity.entity_type == entity_type,
                ThreatSignalEntity.value == value.lower(),
            )
        )).scalar_one_or_none()
        if existing:
            stored.append(existing)
            continue
        row = ThreatSignalEntity(signal_id=signal.id, entity_type=entity_type, value=value.lower(), confidence=confidence, source=source)
        session.add(row)
        stored.append(row)
    return stored


def _extract_signal_entities(signal: ThreatSignal, mappings: list[ThreatProductMapping]) -> list[tuple[str, str, int, str]]:
    entities: list[tuple[str, str, int, str]] = []
    entities.extend(("cve", cve, 95, "signal.cve_ids") for cve in (signal.cve_ids or []))
    entities.extend(("ttp", ttp, 90, "signal.technique_ids") for ttp in (signal.technique_ids or []))
    entities.extend(("actor", actor, 80, "signal.actors") for actor in (signal.actors or []))
    entities.extend(("sector", sector, 70, "signal.sectors") for sector in (signal.sectors or []))
    for ioc in signal.iocs or []:
        if not isinstance(ioc, dict):
            continue
        value = str(ioc.get("value") or ioc.get("indicator") or ioc.get("observable") or ioc.get("ioc") or "")
        ioc_type = str(ioc.get("type") or ioc.get("ioc_type") or _guess_ioc_type(value))
        if value:
            entities.append((ioc_type, value, int(ioc.get("confidence") or 85), "signal.iocs"))
    for mapping in mappings:
        for entity_type, value in [
            ("product", mapping.product),
            ("component", mapping.component),
            ("dependency", mapping.dependency),
            ("cpe", _metadata_scalar(mapping.tags, "cpe")),
            ("purl", _metadata_scalar(mapping.tags, "purl")),
        ]:
            if value:
                entities.append((entity_type, str(value), 80, "product_mapping"))
    metadata = signal.raw_metadata or {}
    for key in ("cpe", "purl", "vendor", "product", "component", "dependency", "package", "domain", "ip", "hash"):
        for value in _metadata_lookup_values(metadata, {key, f"{key}s"}):
            entities.append((key if key != "package" else "dependency", str(value), 70, "signal.metadata"))
    return entities


def _guess_ioc_type(value: str) -> str:
    text = value.strip().lower()
    if text.startswith("http://") or text.startswith("https://"):
        return "url"
    if "." in text and not any(ch in text for ch in "/:@"):
        return "domain"
    if text.count(".") == 3 and all(part.isdigit() for part in text.split(".")):
        return "ip"
    if len(text) in {32, 40, 64} and all(ch in "0123456789abcdef" for ch in text):
        return "hash"
    return "ioc"


def _metadata_scalar(values: list[str], prefix: str) -> str:
    marker = f"{prefix}:"
    for value in values or []:
        if str(value).lower().startswith(marker):
            return str(value)[len(marker):]
    return ""


async def _materialize_alerts_for_space(
    session: AsyncSession,
    space: ThreatCompanySpace,
    monitor: ThreatSpaceMonitor | None = None,
) -> list[dict[str, Any]]:
    assets = list((await session.execute(select(ThreatSpaceAsset).where(ThreatSpaceAsset.space_id == space.id))).scalars().all())
    signals = list((await session.execute(select(ThreatSignal).order_by(ThreatSignal.updated_at.desc()).limit(500))).scalars().all())
    rules = list((await session.execute(select(ThreatDetectionRule).where(ThreatDetectionRule.space_id == space.id, ThreatDetectionRule.enabled.is_(True)))).scalars().all())
    rows: list[dict[str, Any]] = []
    rule = rules[0] if rules else None
    for signal in signals:
        await _sync_signal_entities(session, signal)
        mappings = await mappings_for_signal(session, signal.id)
        score = score_signal(signal, mappings)
        for grouped_rows in _alert_match_rows(signal, mappings, score, assets):
            for row in grouped_rows:
                alert = await _upsert_alert(session, space, signal, row, score, rule, monitor)
                rows.append(_alert_obj(alert))
    return rows


async def _upsert_alert(
    session: AsyncSession,
    space: ThreatCompanySpace,
    signal: ThreatSignal,
    row: dict[str, Any],
    score: Any,
    rule: ThreatDetectionRule | None,
    monitor: ThreatSpaceMonitor | None,
) -> ThreatAlert:
    matched_entity = "|".join(str(item).lower() for item in row.get("matched_terms", [])[:8])
    dedup_basis = f"{space.id}|{rule.id if rule else monitor.id if monitor else 'correlation'}|{signal.id}|{row.get('asset_uuid')}|{row.get('match_type')}|{matched_entity}"
    dedup_key = hashlib.sha256(dedup_basis.encode("utf-8")).hexdigest()
    existing = (await session.execute(
        select(ThreatAlert).where(ThreatAlert.space_id == space.id, ThreatAlert.dedup_key == dedup_key)
    )).scalar_one_or_none()
    match_type = str(row.get("match_type") or "contextual")
    matches = [{
        "signal_entity": item,
        "inventory_entity": row.get("asset_name"),
        "asset_id": row.get("asset_id"),
        "asset_uuid": row.get("asset_uuid"),
        "match_type": match_type,
        "confidence": _match_confidence(match_type, item),
    } for item in row.get("matched_terms", [])]
    alert = existing or ThreatAlert(space_id=space.id, dedup_key=dedup_key, first_seen=datetime.now(UTC))
    alert.status = alert.status or "new"
    alert.rule_id = rule.id if rule else None
    alert.signal_id = signal.id
    alert.title = str(row.get("title") or signal.title)
    alert.description = str(row.get("description") or signal.description)
    alert.priority = score.priority
    alert.severity = signal.severity
    alert.score = score.score
    alert.score_rationale = {
        "factors": score.factors,
        "rationale": score.rationale,
        "match_confidence": max([item["confidence"] for item in matches], default=50),
        "explainability": "Alert persisted from normalized signal entities matched to space-scoped inventory graph compatibility fields.",
    }
    alert.match_type = match_type
    alert.matches = matches
    alert.last_seen = datetime.now(UTC)
    session.add(alert)
    await session.flush()
    await forward_alert_to_unified_model(session, space, alert, signal)
    return alert


def _match_confidence(match_type: str, value: Any) -> int:
    text = str(value).lower()
    if text.startswith(("cve-", "cpe:", "pkg:")) or match_type in {"asset", "supply-chain"}:
        return 90
    if match_type == "technology":
        return 70
    return 55


def _alert_match_rows(
    signal: ThreatSignal,
    mappings: list[ThreatProductMapping],
    score: Any,
    assets: list[ThreatSpaceAsset],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    signal_terms = _signal_match_terms(signal, mappings)
    asset_rows: list[dict[str, Any]] = []
    technology_rows: list[dict[str, Any]] = []
    supply_chain_rows: list[dict[str, Any]] = []
    for asset in assets:
        asset_matches = _field_matches(
            signal_terms,
            [
                asset.name,
                asset.asset_id,
                asset.asset_type,
                asset.exposure,
                asset.environment,
                *asset.products,
                *asset.domains,
                *asset.ip_addresses,
                *asset.tags,
            ],
        )
        technology_matches = _field_matches(signal_terms, [*asset.technologies, *asset.products])
        supply_matches = _field_matches(
            signal_terms,
            [
                *asset.components,
                *_metadata_lookup_values(asset.metadata_json or {}, {"dependency", "dependencies", "package", "packages", "supplier", "suppliers", "purl", "cpe", "sbom_id", "container_image"}),
            ],
        )
        if asset_matches:
            asset_rows.append(_alert_row(signal, score, asset, "asset", asset_matches))
        if technology_matches:
            technology_rows.append(_alert_row(signal, score, asset, "technology", technology_matches))
        if supply_matches:
            supply_chain_rows.append(_alert_row(signal, score, asset, "supply-chain", supply_matches))
    def sort_key(row: dict[str, Any]) -> tuple[int, int, int]:
        return (int(row.get("score", 0)), int(row.get("confidence", 0)), len(row.get("matched_terms", [])))

    return (
        sorted(asset_rows, key=sort_key, reverse=True),
        sorted(technology_rows, key=sort_key, reverse=True),
        sorted(supply_chain_rows, key=sort_key, reverse=True),
    )


def _alert_row(signal: ThreatSignal, score: Any, asset: ThreatSpaceAsset, match_type: str, matches: list[str]) -> dict[str, Any]:
    cve_ids = signal.cve_ids or []
    technique_ids = signal.technique_ids or []
    iocs = _ioc_values(signal.iocs or [])
    title_prefix = {
        "asset": "Asset exposure match",
        "technology": "Technology match",
        "supply-chain": "Supply-chain match",
    }.get(match_type, "Threat match")
    return {
        "id": f"{signal.id}:{asset.id}:{match_type}",
        "title": f"{title_prefix}: {asset.name}",
        "description": (
            f"{signal.title} matches {asset.name} through {', '.join(matches[:6])}. "
            f"Correlation includes {len(cve_ids)} CVE(s), {len(iocs)} IOC(s), and {len(technique_ids)} ATT&CK technique(s)."
        ),
        "match_type": match_type,
        "asset_id": asset.asset_id,
        "asset_name": asset.name,
        "asset_uuid": str(asset.id),
        "criticality": asset.criticality,
        "exposure": asset.exposure,
        "environment": asset.environment,
        "signal_id": str(signal.id),
        "signal_type": signal.signal_type,
        "severity": signal.severity,
        "confidence": signal.confidence,
        "score": score.score,
        "priority": score.priority,
        "cve_ids": cve_ids,
        "technique_ids": technique_ids,
        "actors": signal.actors or [],
        "ioc_count": len(iocs),
        "iocs": iocs[:8],
        "matched_terms": matches[:12],
        "route": f"/threat-radar/assets?space_id={asset.space_id}&asset_id={asset.id}",
    }


def _signal_match_terms(signal: ThreatSignal, mappings: list[ThreatProductMapping]) -> set[str]:
    terms = {
        str(signal.title or "").lower(),
        str(signal.description or "").lower(),
        str(signal.signal_type or "").lower(),
        *[str(item).lower() for item in (signal.cve_ids or [])],
        *[str(item).lower() for item in (signal.technique_ids or [])],
        *[str(item).lower() for item in (signal.actors or [])],
        *[str(item).lower() for item in (signal.sectors or [])],
        *[str(item).lower() for item in (signal.tags or [])],
        *[str(item).lower() for item in _ioc_values(signal.iocs or [])],
    }
    metadata = signal.raw_metadata or {}
    terms.update(str(item).lower() for item in _metadata_lookup_values(metadata, set(metadata.keys())))
    for mapping in mappings:
        terms.update(
            str(item or "").lower()
            for item in [
                mapping.product,
                mapping.component,
                mapping.dependency,
                mapping.version,
                mapping.exposure,
                mapping.environment,
                *mapping.tags,
                *getattr(mapping, "technique_ids", []),
            ]
        )
    return {term for term in terms if term}


def _field_matches(signal_terms: set[str], values: list[str]) -> list[str]:
    matches: list[str] = []
    for raw_value in values:
        value = str(raw_value or "").strip()
        lowered = value.lower()
        if len(lowered) < 3:
            continue
        if any(lowered in term or term in lowered for term in signal_terms if len(term) >= 3):
            matches.append(value)
    return sorted(set(matches), key=str.lower)


def _metadata_lookup_values(metadata: dict[str, Any], keys: set[str]) -> list[str]:
    values: list[str] = []
    for key, value in metadata.items():
        if key not in keys:
            continue
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, list):
            values.extend(str(item) for item in value if item is not None)
        elif isinstance(value, dict):
            values.extend(str(item) for item in value.values() if item is not None)
    return values


def _ioc_values(iocs: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for ioc in iocs:
        if not isinstance(ioc, dict):
            continue
        value = ioc.get("value") or ioc.get("indicator") or ioc.get("observable") or ioc.get("ioc")
        if value:
            values.append(str(value))
    return values


def _asset_terms(assets: list[ThreatSpaceAsset]) -> set[str]:
    terms: set[str] = set()
    for asset in assets:
        for value in [
            asset.name,
            asset.asset_id,
            asset.asset_type,
            asset.environment,
            asset.exposure,
            *asset.products,
            *asset.components,
            *asset.technologies,
            *asset.domains,
            *asset.tags,
        ]:
            value = str(value or "").strip().lower()
            if value:
                terms.add(value)
    return terms


def _signal_asset_overlap(signal: ThreatSignal, mappings: list[ThreatProductMapping], asset_terms: set[str]) -> list[str]:
    if not asset_terms:
        return []
    signal_terms = {
        str(signal.title or "").lower(),
        str(signal.description or "").lower(),
        str(signal.signal_type or "").lower(),
        *[str(item).lower() for item in (signal.cve_ids or [])],
        *[str(item).lower() for item in (signal.technique_ids or [])],
        *[str(item).lower() for item in (signal.actors or [])],
        *[str(item).lower() for item in (signal.sectors or [])],
        *[str(item).lower() for item in (signal.tags or [])],
    }
    for mapping in mappings:
        signal_terms.update(str(item or "").lower() for item in [mapping.product, mapping.component, mapping.dependency, mapping.version, mapping.exposure, mapping.environment, *mapping.tags])
    compact_signal_terms = {item for item in signal_terms if item}
    matches = sorted(term for term in asset_terms if any(term in signal_term or signal_term in term for signal_term in compact_signal_terms if len(signal_term) >= 3))
    return matches


def _ai_step_guidance(step: str, detail: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    normalized = _slug(step).replace("-", "_")
    space = detail.get("space", {})
    counts = space.get("counts", {})
    assets = detail.get("assets", [])
    monitors = detail.get("monitors", [])
    recipes = {
        "create_space": (
            "Create a bounded company space",
            "Define the monitored company boundary first: owner, sector, region, critical products, and legal handling rules. This makes later CVE, actor, IOC, leak, and supply-chain matching explainable.",
            ["Set owner and sector", "Add tags for business unit and region", "Confirm legal-sensitive handling", "Create default dashboards and monitors"],
        ),
        "upload_inventory": (
            "Normalize personal asset inventory",
            "Upload assets using the strict inventory tables. Prioritize product, component, dependency, exposure, owner, telemetry source, and criticality fields so signals can be matched without free-text guessing.",
            ["Add deployed assets", "Add products and components", "Add SBOM dependencies", "Mark internet/customer exposure", "Review high-criticality assets"],
        ),
        "configure_monitors": (
            "Configure threat monitors",
            "Use separate monitors for CVE/KEV relevance, actor/TTP relevance, exposed infrastructure, credentials/leaks, supply-chain packages, and prototype or hardware marketplace claims.",
            ["Enable CVE/KEV monitor", "Enable exposure monitor", "Set alert thresholds", "Run monitor after each feed sync", "Review matched terms"],
        ),
        "triage_signals": (
            "Triage matched threat signals",
            "For each signal, validate evidence quality, product relevance, exploitability, exposure, and blast radius. Create PSIRT, hunt, IR, or detection workflows only when the evidence and asset match are defensible.",
            ["Review source reliability", "Confirm affected product/component", "Check CVE/TTP/actor relationships", "Create case actions", "Generate product-impact report"],
        ),
        "dashboard_review": (
            "Review dashboard evidence",
            "Use dashboards as decision support, not attribution proof. Compare total assets, enabled monitors, high-risk matches, open cases, and AI guidance history to understand operational readiness.",
            ["Check space metrics", "Review latest monitor status", "Open high-score matches", "Update inventory gaps", "Record analyst decision"],
        ),
        "reporting": (
            "Produce executive and technical outputs",
            "Generate reports from cases after validation. Separate executive risk, PSIRT details, hunt hypotheses, detection requirements, and legal-sensitive notes.",
            ["Generate product impact report", "Generate hunt pack", "Include validation gaps", "Link affected assets", "Avoid raw restricted-source material"],
        ),
    }
    title, guidance, checklist = recipes.get(normalized, (
        f"AI guidance for {step}",
        "Use the company space context to connect assets, monitors, matched threat signals, cases, and validation gaps. Keep evidence source-backed and avoid storing restricted raw material.",
        ["Review asset context", "Run relevant monitors", "Validate matches", "Create actions", "Document gaps"],
    ))
    context_note = f"Current space has {counts.get('assets', len(assets))} assets and {counts.get('monitors', len(monitors))} monitors."
    if context:
        context_note += f" Analyst context: {str(context)[:500]}"
    return {"title": title, "guidance": f"{guidance}\n\n{context_note}", "checklist": checklist}


def _space_summary(space: ThreatCompanySpace) -> dict[str, Any]:
    return {"id": str(space.id), "name": space.name, "slug": space.slug}


def _asset_obj(asset: ThreatSpaceAsset) -> dict[str, Any]:
    return {
        "id": str(asset.id),
        "space_id": str(asset.space_id),
        "asset_id": asset.asset_id,
        "name": asset.name,
        "asset_type": asset.asset_type,
        "environment": asset.environment,
        "owner": asset.owner,
        "criticality": asset.criticality,
        "exposure": asset.exposure,
        "products": asset.products or [],
        "components": asset.components or [],
        "technologies": asset.technologies or [],
        "ip_addresses": asset.ip_addresses or [],
        "domains": asset.domains or [],
        "tags": asset.tags or [],
        "metadata": asset.metadata_json or {},
        "created_at": asset.created_at,
        "updated_at": asset.updated_at,
    }


def _asset_dashboard_row(asset: ThreatSpaceAsset) -> dict[str, Any]:
    row = _asset_obj(asset)
    row.update(
        {
            "title": asset.name,
            "description": _asset_description(asset),
            "route": f"/threat-radar/assets?space_id={asset.space_id}&asset_id={asset.id}",
        }
    )
    return row


def _asset_description(asset: ThreatSpaceAsset) -> str:
    products = ", ".join((asset.products or [])[:3]) or "no mapped product"
    components = ", ".join((asset.components or [])[:3]) or "no mapped component"
    technologies = ", ".join((asset.technologies or [])[:4]) or "no mapped technology"
    endpoints = ", ".join([*(asset.domains or [])[:2], *(asset.ip_addresses or [])[:2]]) or "no endpoint recorded"
    return (
        f"{asset.name} is a {asset.criticality or 'unknown'} {asset.asset_type or 'asset'} in "
        f"{asset.environment or 'unknown'} with {asset.exposure or 'unknown'} exposure. "
        f"Products: {products}. Components: {components}. Technologies: {technologies}. Endpoints: {endpoints}."
    )


def _dashboard_obj(dashboard: ThreatSpaceDashboard) -> dict[str, Any]:
    return {
        "id": str(dashboard.id),
        "space_id": str(dashboard.space_id),
        "name": dashboard.name,
        "dashboard_type": dashboard.dashboard_type,
        "layout": dashboard.layout or {},
        "widgets": dashboard.widgets or [],
        "created_at": dashboard.created_at,
        "updated_at": dashboard.updated_at,
    }


def _monitor_obj(monitor: ThreatSpaceMonitor) -> dict[str, Any]:
    return {
        "id": str(monitor.id),
        "space_id": str(monitor.space_id),
        "name": monitor.name,
        "monitor_type": monitor.monitor_type,
        "cadence": monitor.cadence,
        "enabled": monitor.enabled,
        "query": monitor.query or {},
        "alert_threshold": monitor.alert_threshold,
        "last_status": monitor.last_status,
        "last_result": monitor.last_result or {},
        "created_at": monitor.created_at,
        "updated_at": monitor.updated_at,
    }


def _alert_obj(alert: ThreatAlert) -> dict[str, Any]:
    matches = alert.matches or []
    entity_values = [str(match.get("signal_entity") or "") for match in matches if isinstance(match, dict)]
    asset_values = [str(match.get("inventory_entity") or "") for match in matches if isinstance(match, dict)]
    first_match = next((match for match in matches if isinstance(match, dict)), {})
    return {
        "id": str(alert.id),
        "space_id": str(alert.space_id),
        "rule_id": str(alert.rule_id) if alert.rule_id else None,
        "signal_id": str(alert.signal_id) if alert.signal_id else None,
        "case_id": str(alert.case_id) if alert.case_id else None,
        "title": alert.title,
        "description": alert.description,
        "status": alert.status,
        "priority": alert.priority,
        "severity": alert.severity,
        "score": alert.score,
        "score_rationale": alert.score_rationale or {},
        "dedup_key": alert.dedup_key,
        "match_type": alert.match_type,
        "matches": matches,
        "matched_terms": entity_values,
        "asset_name": asset_values[0] if asset_values else "",
        "asset_id": first_match.get("asset_id", "") if isinstance(first_match, dict) else "",
        "asset_uuid": first_match.get("asset_uuid", "") if isinstance(first_match, dict) else "",
        "assignee": alert.assignee,
        "first_seen": alert.first_seen,
        "last_seen": alert.last_seen,
        "created_at": alert.created_at,
        "updated_at": alert.updated_at,
        "route": f"/threat-radar?tab=detail&signal_id={alert.signal_id}" if alert.signal_id else "/threat-radar",
    }


async def _alerts_for_space(session: AsyncSession, space_id: uuid.UUID, limit: int = 1000) -> list[dict[str, Any]]:
    rows = (await session.execute(
        select(ThreatAlert)
        .where(ThreatAlert.space_id == space_id)
        .order_by(ThreatAlert.score.desc(), ThreatAlert.last_seen.desc())
        .limit(limit)
    )).scalars().all()
    return [_alert_obj(row) for row in rows]


def _run_backend_alert_query(alerts: list[dict[str, Any]], query: str, limit: int) -> dict[str, Any]:
    query = (query or "*").strip()
    filter_part, *pipes = [part.strip() for part in query.split("|") if part.strip()]
    filtered = _filter_alert_rows(alerts, filter_part or "*")
    group_by = "priority"
    errors: list[str] = []
    for pipe in pipes:
        lowered = pipe.lower()
        if lowered.startswith("stats count by "):
            group_by = _query_field(pipe[15:].strip())
        elif lowered.startswith("top "):
            group_by = _query_field(pipe[4:].strip())
        elif lowered.startswith("limit "):
            try:
                limit = min(max(int(pipe.split(None, 1)[1]), 1), 500)
            except Exception:
                errors.append(f"Invalid limit pipe: {pipe}")
        elif lowered.startswith("sort "):
            field = pipe.split(None, 1)[1]
            reverse = field.startswith("-")
            field = _query_field(field.lstrip("-"))
            filtered = sorted(filtered, key=lambda row: str(_row_values(row, field)[0] if _row_values(row, field) else ""), reverse=reverse)
        else:
            errors.append(f"Unsupported pipe: {pipe}")
    points = _count_values([value for row in filtered for value in (_row_values(row, group_by) or ["unknown"])])
    return {
        "query": query,
        "total": len(alerts),
        "matched": len(filtered),
        "group_by": group_by,
        "points": points,
        "rows": filtered[:limit],
        "errors": errors,
    }


def _filter_alert_rows(rows: list[dict[str, Any]], filter_part: str) -> list[dict[str, Any]]:
    if not filter_part or filter_part == "*":
        return rows
    groups = [group.strip() for group in filter_part.split(" OR ") if group.strip()]
    return [row for row in rows if any(_match_alert_group(row, group) for group in groups)]


def _match_alert_group(row: dict[str, Any], group: str) -> bool:
    tokens = [token for token in group.split() if token.upper() != "AND"]
    return all(_match_alert_token(row, token) for token in tokens)


def _match_alert_token(row: dict[str, Any], token: str) -> bool:
    if ":" not in token:
        return token.lower() in " ".join(str(value).lower() for value in _flatten(row))
    field, expected = token.split(":", 1)
    expected = expected.lower().strip('"')
    values = [str(value).lower() for value in _row_values(row, _query_field(field))]
    if expected == "*":
        return bool(values)
    return any(expected in value for value in values)


def _query_field(field: str) -> str:
    aliases = {
        "type": "match_type",
        "entity": "matched_terms",
        "match": "matched_terms",
        "asset": "asset_name",
        "rule": "rule_id",
        "signal": "signal_id",
        "cve": "matched_terms",
        "ttp": "matched_terms",
        "ioc": "matched_terms",
    }
    return aliases.get(field.lower(), field.lower())


def _row_values(row: dict[str, Any], field: str) -> list[str]:
    value = row.get(field)
    if value is None and field == "matched_terms":
        value = [match.get("signal_entity") for match in row.get("matches", []) if isinstance(match, dict)]
    return [str(item) for item in _flatten(value) if str(item)]


def _row_cves(row: dict[str, Any]) -> list[str]:
    values = [str(item) for item in row.get("cve_ids", [])] if isinstance(row.get("cve_ids"), list) else []
    values.extend(term for term in row.get("matched_terms", []) if str(term).lower().startswith("cve-"))
    return sorted(set(values))


def _row_has_prefix(row: dict[str, Any], prefix: str) -> bool:
    prefix = prefix.lower()
    return any(str(value).lower().startswith(prefix) for value in _flatten(row.get("matched_terms", [])) + _flatten(row.get("cve_ids", [])) + _flatten(row.get("technique_ids", [])))


def _row_has_ioc(row: dict[str, Any]) -> bool:
    text = " ".join(str(value).lower() for value in _flatten(row))
    return any(marker in text for marker in ["ioc", "domain", "hash", "ip", "url"])


def _flatten(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return [child for item in value for child in _flatten(item)]
    if isinstance(value, dict):
        return [child for item in value.values() for child in _flatten(item)]
    return [value]


def _count_values(values: list[str]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for value in values:
        label = str(value or "unknown").strip() or "unknown"
        counts[label] = counts.get(label, 0) + 1
    return [
        {"label": label, "value": value}
        for label, value in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:20]
    ]


def _ai_step_obj(step: ThreatSpaceAIStep) -> dict[str, Any]:
    return {
        "id": str(step.id),
        "space_id": str(step.space_id),
        "step": step.step,
        "title": step.title,
        "guidance": step.guidance,
        "checklist": step.checklist or [],
        "created_by": step.created_by,
        "created_at": step.created_at,
    }


def _slug(value: str) -> str:
    return "-".join("".join(ch.lower() if ch.isalnum() else " " for ch in value).split())[:120]


def _uuid_or_400(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except (TypeError, ValueError) as exc:
        raise HTTPException(400, "Invalid UUID") from exc


def _uuid_or_none(value: str | None) -> uuid.UUID | None:
    if not value:
        return None
    return _uuid_or_400(value)
