"""Durable, deterministic packet-capture analysis routes."""

from __future__ import annotations

import hashlib
import logging
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.routes.analyze import (
    AptMatch,
    TechniqueHit,
    _new_source_provenance,
    _rank_apt_groups,
    _start_review_with_preflight,
    _validate_technique_ids,
)
from app.core.config import settings
from app.core.database import get_session
from app.models.analysis import AnalysisResult, AnalysisSession
from app.models.operations import ReportIntake
from app.models.pcap import PcapAnalysis
from app.services.pcap_context import build_context
from app.services.ai.base import ExtractedTechnique, ExtractionResult, technique_to_record
from app.services.auth import TeamUser, audit, current_user, has_permission, require_permission
from app.services.pcap_analyzer import (
    PcapAnalyzerError,
    analysis_key,
    analyze_capture,
    capture_storage_path,
    get_manifest,
    render_report,
    retain_capture,
    validate_capture_magic,
)


router = APIRouter(prefix="/pcap", tags=["PCAP Analysis"])
run_analysis = require_permission("run_analysis")
logger = logging.getLogger(__name__)


class PcapEvidenceRef(BaseModel):
    frame_number: int
    timestamp_epoch: str = ""
    display_filter: str = ""
    tcp_stream: int | None = None
    udp_stream: int | None = None


class PcapCaptureFacts(BaseModel):
    format: str
    source_sha256: str
    source_size_bytes: int
    packet_count: int
    captured_bytes: int
    first_packet_epoch: str
    last_packet_epoch: str
    duration_seconds: float
    interface_ids: list[int]
    encapsulation_types: list[int]
    protocol_counts: dict[str, int]


class PcapEndpoint(BaseModel):
    endpoint_id: str
    ip: str
    ip_version: int | None
    is_private: bool
    mac_addresses: list[str]
    packets_sent: int
    packets_received: int
    bytes_sent: int
    bytes_received: int
    first_seen_epoch: str
    last_seen_epoch: str
    evidence_frames: list[int]


class PcapFlow(BaseModel):
    flow_id: str
    transport: str
    stream: int
    initiator_ip: str
    initiator_port: int
    responder_ip: str
    responder_port: int
    first_frame: int
    last_frame: int
    first_seen_epoch: str
    last_seen_epoch: str
    packets: int
    bytes: int
    initiator_bytes: int
    responder_bytes: int


class PcapIdentity(BaseModel):
    identity_id: str
    type: str
    value: str
    ip_addresses: list[str]
    mac_addresses: list[str]
    evidence: list[PcapEvidenceRef]


class PcapArtifact(BaseModel):
    artifact_id: str
    type: str
    filename: str
    size_bytes: int
    sha256: str
    media_type: str
    extraction_method: str
    content_retained_by_analyzer: bool


class PcapObservable(BaseModel):
    observable_id: str
    type: str
    value: str
    roles: list[str]
    is_private: bool | None
    first_seen_epoch: str
    last_seen_epoch: str
    evidence: list[PcapEvidenceRef]
    enrichment_state: str


class PcapFinding(BaseModel):
    finding_id: str
    rule_id: str
    rule_version: str
    severity: str
    title: str
    explanation: str
    confidence: float
    status: str
    evidence: list[PcapEvidenceRef]
    metrics: dict[str, Any]


class PcapAttackCandidate(BaseModel):
    attack_id: str
    name: str
    tactic: str
    confidence: float
    status: str
    mapping_basis: str
    finding_ids: list[str]
    evidence: list[PcapEvidenceRef]


class PcapDeterministicResult(BaseModel):
    schema_version: str
    semantic_sha256: str
    analysis_key_material: dict[str, str]
    analyzer_manifest: dict[str, Any]
    capture: PcapCaptureFacts
    endpoints: list[PcapEndpoint]
    identities: list[PcapIdentity]
    flows: list[PcapFlow]
    events: dict[str, list[dict[str, Any]]]
    artifacts: list[PcapArtifact]
    observables: list[PcapObservable]
    findings: list[PcapFinding]
    attack_candidates: list[PcapAttackCandidate]
    actor_leads: list[dict[str, Any]]
    coverage: dict[str, Any]
    summary: str


class PcapAnalysisOut(BaseModel):
    analysis_id: str
    session_id: str
    status: str
    filename: str
    source_sha256: str
    source_size_bytes: int
    schema_version: str
    semantic_sha256: str
    analyzer_manifest: dict[str, Any]
    summary: str
    report: str
    # Hash-covered evidence must be serialized without default insertion or
    # unknown-field removal. Validation belongs at ingestion, not serialization.
    result: dict[str, Any]
    context: dict[str, Any] = Field(default_factory=dict)
    techniques: list[TechniqueHit]
    apt_matches: list[AptMatch]


class PcapAnalysisSummary(BaseModel):
    analysis_id: str
    session_id: str
    status: str
    filename: str
    source_sha256: str
    source_size_bytes: int
    schema_version: str
    semantic_sha256: str
    summary: str
    finding_count: int
    observable_count: int
    technique_count: int
    created_at: str


class PcapCollectionOut(BaseModel):
    items: list[PcapAnalysisSummary]
    limit: int
    offset: int


def _require_upload_permission(user: TeamUser) -> None:
    if settings.auth_enabled and not has_permission(user, "upload_files"):
        raise HTTPException(403, "Permission required: upload_files")


async def _hash_upload(file: UploadFile) -> tuple[str, int]:
    if file.size is not None and file.size > settings.pcap_max_upload_bytes:
        raise HTTPException(413, f"Capture exceeds {settings.pcap_max_upload_bytes} byte limit")
    digest = hashlib.sha256()
    total = 0
    await file.seek(0)
    while True:
        block = await file.read(1024 * 1024)
        if not block:
            break
        total += len(block)
        if total > settings.pcap_max_upload_bytes:
            raise HTTPException(413, f"Capture exceeds {settings.pcap_max_upload_bytes} byte limit")
        digest.update(block)
    await file.seek(0)
    if total < 24:
        raise HTTPException(400, "Capture is empty or truncated")
    try:
        validate_capture_magic(file.file)
    except PcapAnalyzerError as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc
    return digest.hexdigest(), total


def _extraction_result(result: dict[str, Any]) -> ExtractionResult:
    techniques: list[ExtractedTechnique] = []
    for candidate in list(result.get("attack_candidates") or [])[:500]:
        evidence_refs = list(candidate.get("evidence") or [])
        evidence = f"{candidate.get('attack_id')} {candidate.get('name')}"
        if evidence_refs:
            first = evidence_refs[0]
            evidence += f"; frame {first.get('frame_number')}"
        techniques.append(ExtractedTechnique(
            attack_id=str(candidate.get("attack_id") or "").upper(),
            name=str(candidate.get("name") or "")[:255],
            tactic=str(candidate.get("tactic") or "")[:80],
            confidence=float(candidate.get("confidence") or 0.5),
            evidence=evidence[:200],
            review_status="suggested",
            evidence_source="pcap-frame-evidence",
        ))
    return ExtractionResult(
        techniques=techniques,
        summary=str(result.get("summary") or ""),
        raw_response="",
        provider="deterministic",
        model=str(result.get("analyzer_manifest", {}).get("profile_id") or "tshark-evidence-v1"),
    )


def _bind_report_evidence(extraction: ExtractionResult, report: str) -> None:
    lower = report.lower()
    for technique in extraction.techniques:
        needle = f"{technique.attack_id} {technique.name}"
        start = lower.find(needle.lower())
        if start >= 0:
            technique.evidence = report[start:start + len(needle)]
            technique.evidence_start = start
            technique.evidence_end = start + len(needle)
            technique.evidence_source = "source-text"


def _review_indicator_candidates(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Build report-local IOC candidates; canonical creation stays review-gated."""

    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: Any, *, roles: list[str], evidence: list[dict[str, Any]]) -> None:
        clean = str(value or "").strip()
        key = (kind, clean.casefold())
        if not clean or key in seen or len(candidates) >= 200:
            return
        seen.add(key)
        candidates.append({
            "value": clean,
            "type": kind,
            "indicator_type": kind,
            # Confidence describes faithful capture extraction, not a verdict
            # that the observed value is malicious.
            "confidence": 50,
            "roles": roles[:20],
            "evidence": evidence[:20],
            "source": "deterministic-pcap-analysis",
        })

    # Reserve capacity for both transferred-object hashes and network IOCs;
    # the Review Gate deliberately bounds one intake to 200 indicator claims.
    for artifact in list(result.get("artifacts") or [])[:100]:
        add("sha256", artifact.get("sha256"), roles=["exported-object"], evidence=[])
    allowed = {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "ja3", "ja3s", "ja4"}
    for item in list(result.get("observables") or [])[:500]:
        kind = str(item.get("type") or "").lower()
        if kind not in allowed:
            continue
        if kind in {"ipv4", "ipv6"} and item.get("is_private") is not False:
            continue
        add(kind, item.get("value"), roles=list(item.get("roles") or []), evidence=list(item.get("evidence") or []))
    return candidates


def _build_out(row: PcapAnalysis, session: AnalysisSession, result_row: AnalysisResult | None) -> PcapAnalysisOut:
    techniques = [TechniqueHit(**item) for item in (result_row.extracted_techniques if result_row else [])]
    apt_matches = [AptMatch(**item) for item in (result_row.apt_matches if result_row else [])]
    return PcapAnalysisOut(
        analysis_id=str(row.id),
        session_id=str(row.session_id),
        status=row.status,
        filename=row.filename,
        source_sha256=row.source_sha256,
        source_size_bytes=row.source_size_bytes,
        schema_version=row.schema_version,
        semantic_sha256=row.semantic_sha256,
        analyzer_manifest=row.analyzer_manifest or {},
        summary=(result_row.summary if result_row else "") or str((row.result or {}).get("summary") or ""),
        report=row.report_text or session.source_text or "",
        result=row.result or {},
        context=(session.source_provenance or {}).get("pcap_context", {}),
        techniques=techniques,
        apt_matches=apt_matches,
    )


async def _load_out(db: AsyncSession, row: PcapAnalysis) -> PcapAnalysisOut:
    session = await db.get(AnalysisSession, row.session_id)
    result_row = await db.scalar(select(AnalysisResult).where(AnalysisResult.session_id == row.session_id))
    if session is None:
        raise HTTPException(500, "PCAP analysis session is missing")
    return _build_out(row, session, result_row)


@router.post("/analyze", response_model=PcapAnalysisOut)
async def create_analysis(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(run_analysis),
) -> PcapAnalysisOut:
    if not settings.pcap_analyzer_enabled:
        raise HTTPException(503, "Deterministic PCAP analysis is disabled")
    _require_upload_permission(user)
    filename = Path(file.filename or "capture.pcap").name[:500] or "capture.pcap"
    source_sha256, source_size = await _hash_upload(file)
    try:
        manifest = await get_manifest()
    except PcapAnalyzerError as exc:
        raise HTTPException(exc.status_code, str(exc)) from exc
    key = analysis_key(source_sha256, str(manifest["manifest_sha256"]))
    existing = await db.scalar(select(PcapAnalysis).where(PcapAnalysis.analysis_key == key))
    if existing is not None and existing.status == "completed":
        return await _load_out(db, existing)

    if settings.pcap_retain_uploads:
        try:
            storage_path = capture_storage_path(source_sha256)
            if not storage_path.exists():
                retain_capture(file.file, storage_path)
        except OSError as exc:
            logger.error("PCAP acquisition storage failed (%s)", type(exc).__name__)
            raise HTTPException(500, "Capture storage failed. See server logs.") from exc
    else:
        storage_path = Path()

    if existing is None:
        session = AnalysisSession(
            status="processing",
            name=filename,
            input_type="file",
            filename=filename,
            llm_provider="deterministic",
            model=str(manifest.get("profile_id") or "tshark-evidence-v1")[:100],
            domain="enterprise-attack",
            tlp="TLP:AMBER+STRICT",
            source_text="PCAP analysis is processing.",
            source_provenance={},
        )
        db.add(session)
        await db.flush()
        row = PcapAnalysis(
            session_id=session.id,
            status="processing",
            filename=filename,
            source_sha256=source_sha256,
            source_size_bytes=source_size,
            storage_path=str(storage_path) if settings.pcap_retain_uploads else "",
            analysis_key=key,
            analyzer_manifest=manifest,
        )
        db.add(row)
        try:
            await db.flush()
            await db.commit()
        except IntegrityError:
            # A concurrent upload can win the unique analysis-key race after
            # our initial lookup. Roll back the orphan session and reuse the
            # authority record created by the winner.
            await db.rollback()
            winner = await db.scalar(select(PcapAnalysis).where(PcapAnalysis.analysis_key == key))
            if winner is not None and winner.status == "completed":
                return await _load_out(db, winner)
            raise HTTPException(409, "An identical capture analysis is already in progress")
    else:
        row = existing
        session = await db.get(AnalysisSession, row.session_id)
        if session is None:
            raise HTTPException(500, "PCAP analysis session is missing")
        row.status = "processing"
        row.error = None
        session.status = "processing"
        await db.commit()

    try:
        await file.seek(0)
        result = await analyze_capture(file.file, filename)
        capture_facts = result.get("capture", {})
        if capture_facts.get("source_sha256") != source_sha256:
            raise PcapAnalyzerError("PCAP analyzer source digest mismatch")
        if int(capture_facts.get("source_size_bytes") or -1) != source_size:
            raise PcapAnalyzerError("PCAP analyzer source size mismatch")
        if result.get("analyzer_manifest", {}).get("manifest_sha256") != manifest.get("manifest_sha256"):
            raise PcapAnalyzerError("PCAP analyzer manifest changed during analysis", status_code=409)

        extraction = _extraction_result(result)
        await _validate_technique_ids(extraction, "enterprise-attack", db)
        apt_matches = await _rank_apt_groups(extraction, "enterprise-attack", db)
        actor_leads = [
            {
                **match.model_dump(),
                "basis": "technique-overlap-only",
                "attribution_status": "investigation-lead",
            }
            for match in apt_matches
        ]
        context = await build_context(db, result, session_id=str(session.id))
        report = render_report(filename, result, actor_leads, context=context)
        _bind_report_evidence(extraction, report)

        session.status = "completed"
        session.source_text = report
        session.source_provenance = _new_source_provenance(
            report,
            source_kind="pcap",
            filename=filename,
            content_sha256=source_sha256,
            content_size_bytes=source_size,
        )
        session.source_provenance = {**session.source_provenance, "pcap_context": context}
        row.status = "completed"
        row.schema_version = str(result.get("schema_version") or "pcap-analysis-v1")[:80]
        row.semantic_sha256 = str(result.get("semantic_sha256") or "")
        row.analyzer_manifest = result.get("analyzer_manifest") or {}
        row.result = result
        row.report_text = report
        row.error = None
        stored = await db.scalar(select(AnalysisResult).where(AnalysisResult.session_id == session.id))
        if stored is None:
            stored = AnalysisResult(session_id=session.id)
            db.add(stored)
        stored.extracted_techniques = [technique_to_record(item) for item in extraction.techniques]
        stored.apt_matches = [item.model_dump() for item in apt_matches]
        stored.summary = extraction.summary
        stored.raw_response = canonical_result_reference(result)
        indicator_candidates = _review_indicator_candidates(result)
        intake = await db.scalar(
            select(ReportIntake)
            .where(ReportIntake.analysis_session_id == session.id)
            .order_by(ReportIntake.updated_at.desc(), ReportIntake.id.desc())
            .limit(1)
        )
        if intake is None:
            intake = ReportIntake(analysis_session_id=session.id, title=filename)
            db.add(intake)
        intake.title = filename
        intake.url = ""
        intake.publisher = "local packet capture"
        intake.status = "draft"
        intake.summary = extraction.summary[:5000]
        intake.source_reliability = "unknown"
        # Technique overlap never becomes an attribution claim.
        intake.actor_ids = []
        intake.technique_ids = [item.attack_id for item in extraction.techniques]
        intake.indicators = indicator_candidates
        intake.tags = ["report", "source:pcap", "analysis:deterministic"]
        intake.provenance = {
            "source_kind": "pcap",
            "analysis_session_id": str(session.id),
            "pcap_analysis_id": str(row.id),
            "source_sha256": source_sha256,
            "semantic_sha256": row.semantic_sha256,
            "analyzer_manifest_sha256": row.analyzer_manifest.get("manifest_sha256", ""),
        }
        intake.analyst_notes = json_dumps({
            "candidate_indicator_count": len(indicator_candidates),
            "candidate_technique_count": len(extraction.techniques),
            "actor_overlap_status": "investigation-lead-not-attribution",
        })
        await db.flush()
        await _start_review_with_preflight(db, session.id, user, profile="internal_ir")
        await audit(db, user, "pcap.analyze", "pcap_analysis", str(row.id), {
            "session_id": str(session.id),
            "source_sha256": source_sha256,
            "semantic_sha256": row.semantic_sha256,
            "finding_count": len(result.get("findings") or []),
            "technique_count": len(extraction.techniques),
            "candidate_indicator_count": len(indicator_candidates),
        })
        await db.commit()
    except HTTPException:
        raise
    except PcapAnalyzerError as exc:
        row.status = "failed"
        row.error = str(exc)[:1000]
        session.status = "failed"
        session.error = "PCAP analysis failed. See server logs."
        await db.commit()
        raise HTTPException(exc.status_code, str(exc)) from exc
    except Exception as exc:
        logger.error("PCAP analysis failed (%s)", type(exc).__name__, exc_info=True)
        row.status = "failed"
        row.error = "PCAP analysis failed. See server logs."
        session.status = "failed"
        session.error = row.error
        await db.commit()
        raise HTTPException(500, row.error) from exc
    return _build_out(row, session, stored)


def canonical_result_reference(result: dict[str, Any]) -> str:
    reference = {
        "schema_version": result.get("schema_version"),
        "semantic_sha256": result.get("semantic_sha256"),
        "source_sha256": result.get("capture", {}).get("source_sha256"),
        "analyzer_manifest_sha256": result.get("analyzer_manifest", {}).get("manifest_sha256"),
    }
    return json_dumps(reference)


def json_dumps(value: Any) -> str:
    import json

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


@router.get("/analyses", response_model=PcapCollectionOut)
async def list_analyses(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
) -> PcapCollectionOut:
    rows = (
        await db.execute(select(PcapAnalysis).order_by(PcapAnalysis.created_at.desc()).offset(offset).limit(limit))
    ).scalars().all()
    items = [
        PcapAnalysisSummary(
            analysis_id=str(row.id),
            session_id=str(row.session_id),
            status=row.status,
            filename=row.filename,
            source_sha256=row.source_sha256,
            source_size_bytes=row.source_size_bytes,
            schema_version=row.schema_version,
            semantic_sha256=row.semantic_sha256,
            summary=str((row.result or {}).get("summary") or ""),
            finding_count=len((row.result or {}).get("findings") or []),
            observable_count=len((row.result or {}).get("observables") or []),
            technique_count=len((row.result or {}).get("attack_candidates") or []),
            created_at=row.created_at.isoformat() if row.created_at else "",
        )
        for row in rows
    ]
    return PcapCollectionOut(items=items, limit=limit, offset=offset)


@router.get("/analyses/{analysis_id}", response_model=PcapAnalysisOut)
async def get_analysis(
    analysis_id: str,
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
) -> PcapAnalysisOut:
    try:
        parsed = uuid.UUID(analysis_id)
    except ValueError:
        raise HTTPException(400, "Invalid PCAP analysis ID")
    row = await db.get(PcapAnalysis, parsed)
    if row is None:
        raise HTTPException(404, "PCAP analysis not found")
    return await _load_out(db, row)
