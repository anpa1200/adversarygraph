from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.models.threat_radar import (
    ThreatAction,
    ThreatAuditLog,
    ThreatCase,
    ThreatCaseLink,
    ThreatClaim,
    ThreatDetectionRequirement,
    ThreatEvidence,
    ThreatHuntRequest,
    ThreatIREscalation,
    ThreatMarketplaceListing,
    ThreatProductMapping,
    ThreatPSIRTTask,
    ThreatReport,
    ThreatSignal,
    ThreatScore,
    ThreatSource,
    ThreatSupplyChainFinding,
)
from app.services.auth import TeamUser, analyst
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

router = APIRouter(prefix="/threat-radar", tags=["Threat Radar"])


class ThreatSourceIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    source_type: str = "manual"
    url: str = ""
    reliability: int = Field(3, ge=0, le=5)
    tlp: str = "TLP:AMBER"
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
    tlp: str = "TLP:AMBER"
    legal_sensitive: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class ClaimIn(BaseModel):
    claim_type: str = "threat-claim"
    statement: str = ""
    credibility: int = Field(3, ge=0, le=5)
    status: str = "unvalidated"
    tlp: str = "TLP:AMBER"
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
    tlp: str = "TLP:AMBER"
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
        cve_ids=sorted({cve.upper() for cve in payload.cve_ids}),
        technique_ids=sorted({ttp.upper() for ttp in payload.technique_ids}),
        iocs=payload.iocs,
        actors=payload.actors,
        sectors=payload.sectors,
        tags=sorted(tags),
        raw_metadata=sanitize_metadata(payload.signal_type, payload.raw_metadata),
        created_by=user.name,
    )
    session.add(signal)
    await session.flush()
    await _add_claims_evidence_mappings(session, signal, payload.claims, payload.evidence, payload.product_mappings, legal_sensitive)
    mappings = await mappings_for_signal(session, signal.id)
    score = score_signal(signal, mappings)
    recs = recommended_actions(signal, score, mappings)
    case = await create_case_from_signal(session, signal, user.name, mappings) if payload.create_case else None
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
        tags = sorted({*item.tags, *[ttp.upper() for ttp in item.technique_ids]})
        mapping = ThreatProductMapping(
            signal_id=signal.id if signal else None,
            case_id=case.id if case else None,
            product=item.product,
            component=item.component,
            dependency=item.dependency,
            version=item.version,
            exposure=item.exposure,
            environment=item.environment,
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


def _uuid_or_400(value: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except (TypeError, ValueError) as exc:
        raise HTTPException(400, "Invalid UUID") from exc


def _uuid_or_none(value: str | None) -> uuid.UUID | None:
    if not value:
        return None
    return _uuid_or_400(value)
