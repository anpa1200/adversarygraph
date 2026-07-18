"""
POST /api/analyze          — full analysis (file or text), returns JSON result
POST /api/analyze/stream   — same but streams SSE tokens while the LLM thinks
GET  /api/analyze/{id}     — retrieve a stored result by session UUID
POST /api/analyze/chat     — single-turn LLM chat about a specific technique or selection
"""

from __future__ import annotations

import json
import logging
import re
import uuid
import ipaddress
from dataclasses import asdict
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Annotated, Any, AsyncIterator
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete as sql_delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.core.database import get_session
from app.core.config import settings
from app.core.safe_http import ResponseTooLargeError, async_safe_get
from app.models.analysis import AnalysisResult, AnalysisSession
from app.models.attack import AptGroup, AptGroupTechnique, AttackVersion, Technique
from app.models.ioc import IOCIndicator
from app.models.operations import ReportIntake
from app.services.ai.base import ExtractionResult, bind_evidence_spans, technique_to_record
from app.services.ai.factory import get_adapter
from app.services.auth import TeamUser, audit, current_user, has_permission, require_permission
from app.services.asset_intel import retrohunt_assets
from app.services.file_parser import extract_text
from app.services.ioc_extractor import extract_iocs_from_text
from app.services.taxonomy import TAXONOMY_SYSTEM_INSTRUCTIONS

router = APIRouter(prefix="/analyze", tags=["Analysis"])
run_analysis = require_permission("run_analysis")
manage_reports = require_permission("manage_intel")
logger = logging.getLogger(__name__)

ALLOWED_PROVIDERS = {"claude", "openai", "gemini", "minimax", "local"}
MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_SOURCE_URL_LENGTH = 1000
MAX_CHAT_MESSAGE_CHARS = 12_000
_ANALYSIS_FAILURE = "Analysis processing failed. See server logs."
_STREAM_STORAGE_FAILURE = "Analysis result storage failed. See server logs."
_URL_INGEST_FAILURE = "URL report ingestion failed. See server logs."


def _log_failure(message: str, exc: Exception) -> None:
    """Log failure type without copying untrusted exception text into logs."""
    logger.error("%s (%s)", message, type(exc).__name__)


def _require_upload_permission(user: TeamUser, file: UploadFile | None) -> None:
    if file is not None and settings.auth_enabled and not has_permission(user, "upload_files"):
        raise HTTPException(403, "Permission required: upload_files")


async def _retrohunt_assets_after_report_ingest(session: AsyncSession, *, source: str) -> dict[str, Any] | None:
    try:
        summary = await retrohunt_assets(session)
        logger.info("Asset retrohunt after %s: %s", source, summary)
        return summary
    except Exception as exc:
        logger.warning("Asset retrohunt after %s failed (%s)", source, type(exc).__name__)
        return None


# ── Response schemas ──────────────────────────────────────────────────────────

class TechniqueHit(BaseModel):
    attack_id: str
    name: str
    tactic: str
    confidence: float
    evidence: str
    review_status: str = "suggested"
    evidence_start: int | None = None
    evidence_end: int | None = None
    evidence_source: str = "llm"
    llm_verified: bool = True


class AptMatch(BaseModel):
    group_attack_id: str
    group_name: str
    similarity: float
    shared_count: int
    shared_techniques: list[str]


class AnalysisOut(BaseModel):
    session_id: str
    provider: str
    model: str
    summary: str
    techniques: list[TechniqueHit]
    apt_matches: list[AptMatch]
    apt_hints: list[str]
    raw_response: str = ""


class LinkedReportEntity(BaseModel):
    type: str
    id: str
    label: str
    value: str = ""
    route: str = ""
    aliases: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class LinkedReportImage(BaseModel):
    url: str
    alt: str = ""
    caption: str = ""
    source: str = "remote-report"


class LinkedReportOut(BaseModel):
    session_id: str
    name: str | None
    provider: str
    model: str
    domain: str
    tlp: str
    created_at: str
    source_text: str
    source_text_available: bool
    source_note: str = ""
    summary: str
    techniques: list[TechniqueHit]
    apt_matches: list[AptMatch]
    entities: list[LinkedReportEntity]
    report_images: list[LinkedReportImage] = Field(default_factory=list)
    report_intake: dict[str, Any] | None = None


class ReportCollectionTag(BaseModel):
    type: str
    label: str
    value: str
    route: str = ""
    confidence: int = 50
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReportCollectionItem(BaseModel):
    session_id: str
    title: str
    source_url: str = ""
    publisher: str = ""
    status: str = ""
    provider: str
    model: str
    domain: str
    tlp: str
    created_at: str
    updated_at: str
    summary: str
    source_text_available: bool
    counts: dict[str, int]
    tags: dict[str, list[ReportCollectionTag]]


class ReportCollectionOut(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[ReportCollectionItem]


class StoredResearchOut(BaseModel):
    session_id: str
    status: str
    title: str
    filename: str | None = None
    source_url: str = ""
    source_text_available: bool
    summary: str
    tlp: str


class UrlReportFetch(BaseModel):
    title: str
    source_url: str
    content_type: str
    source_text: str
    report_images: list[LinkedReportImage] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


_MODEL_RE = re.compile(r'^[\w./:@-]{1,100}$')
_MAX_STORED_REPORT_TEXT = 120_000
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_REPORT_TLP_PATTERN = r"^(TLP:CLEAR|TLP:GREEN|TLP:AMBER|TLP:AMBER\+STRICT|TLP:RED)$"


class SessionListItem(BaseModel):
    session_id: str
    name: str | None
    status: str
    provider: str
    model: str
    domain: str
    tlp: str
    filename: str | None
    created_at: str
    technique_count: int


class ChatRequest(BaseModel):
    model_config = {"extra": "forbid"}

    message: str = Field(..., min_length=1, max_length=MAX_CHAT_MESSAGE_CHARS)
    provider: str = Field(default="claude", max_length=20)
    model: str | None = Field(default=None, max_length=100)
    context: str = Field(default="", max_length=8000)
    system_prompt: str | None = Field(default=None, max_length=5000)


class TechniqueReviewUpdate(BaseModel):
    review_status: str = Field(pattern="^(suggested|accepted|rejected|needs-evidence)$")
    evidence: str | None = Field(default=None, max_length=500)
    review_note: str | None = Field(default=None, max_length=1000)
    reviewer: str | None = Field(default=None, max_length=120)


class ReportEditRequest(BaseModel):
    name: str | None = Field(default=None, max_length=255)
    source_text: str | None = Field(default=None, max_length=_MAX_STORED_REPORT_TEXT)
    source_url: str | None = Field(default=None, max_length=1000)
    publisher: str | None = Field(default=None, max_length=255)
    summary: str | None = Field(default=None, max_length=5000)
    tlp: str | None = Field(default=None, pattern=_REPORT_TLP_PATTERN)


class ReportReparseRequest(BaseModel):
    provider: str = "claude"
    model: str | None = Field(default=None, max_length=100)


class LogObservable(BaseModel):
    value: str
    type: str
    confidence: int
    description: str


class SuspiciousFinding(BaseModel):
    severity: str
    category: str
    evidence: str
    reason: str


class LogPcapAnalysisOut(BaseModel):
    provider: str
    model: str
    filename: str | None
    summary: str
    report: str
    observables: list[LogObservable]
    suspicious_findings: list[SuspiciousFinding]
    techniques: list[TechniqueHit]
    apt_matches: list[AptMatch]


# ── Full analysis (JSON response) ─────────────────────────────────────────────

@router.post("", response_model=AnalysisOut)
async def analyze(
    provider: Annotated[str, Form()] = "claude",
    model:    Annotated[str | None, Form()] = None,
    domain:   Annotated[str, Form()] = "enterprise-attack",
    name:     Annotated[str | None, Form()] = None,
    text:     Annotated[str | None, Form()] = None,
    file:     UploadFile | None = File(default=None),
    session:  AsyncSession = Depends(get_session),
    user:     TeamUser = Depends(run_analysis),
):
    _require_upload_permission(user, file)
    body, filename = await _read_input(text, file)
    adapter = _get_adapter(provider, model)

    # Store session record
    db_session = AnalysisSession(
        status="processing",
        name=name or filename,
        input_type="file" if file else "text",
        filename=filename,
        llm_provider=provider,
        model=adapter.model,
        domain=domain,
        tlp="TLP:AMBER+STRICT",
        source_text=body[:_MAX_STORED_REPORT_TEXT],
    )
    session.add(db_session)
    await session.flush()
    session_id = str(db_session.id)

    try:
        result = await adapter.extract(body, domain)
        await _validate_technique_ids(result, domain, session)
        apt_matches = await _rank_apt_groups(result, domain, session)
        await _store_result(db_session, result, apt_matches, session)
        await audit(session, user, "analyze.create_session", "analysis_session", session_id, {"provider": provider, "domain": domain, "technique_count": len(result.techniques)})
        await session.commit()
    except Exception as exc:
        db_session.status = "failed"
        db_session.error = _ANALYSIS_FAILURE
        await session.commit()
        _log_failure("Analysis failed", exc)
        raise HTTPException(500, "Operation failed. See server logs.") from exc

    return _build_out(session_id, adapter.provider, adapter.model, result, apt_matches)


# ── Streaming analysis (SSE) ──────────────────────────────────────────────────

@router.post("/stream")
async def analyze_stream(
    provider: Annotated[str, Form()] = "claude",
    model:    Annotated[str | None, Form()] = None,
    domain:   Annotated[str, Form()] = "enterprise-attack",
    name:     Annotated[str | None, Form()] = None,
    text:     Annotated[str | None, Form()] = None,
    file:     UploadFile | None = File(default=None),
    session:  AsyncSession = Depends(get_session),
    user:     TeamUser = Depends(run_analysis),
):
    """
    Streams SSE events:
      data: {"type":"token","content":"..."}
      data: {"type":"result","data":{...}}   ← final parsed result
      data: {"type":"error","message":"..."}
    """
    _require_upload_permission(user, file)
    body, filename = await _read_input(text, file)
    adapter = _get_adapter(provider, model)

    db_session = AnalysisSession(
        status="processing",
        name=name or filename,
        input_type="file" if file else "text",
        filename=filename,
        llm_provider=provider,
        model=adapter.model,
        domain=domain,
        tlp="TLP:AMBER+STRICT",
        source_text=body[:_MAX_STORED_REPORT_TEXT],
    )

    session.add(db_session)
    await session.flush()
    session_id = str(db_session.id)
    await session.commit()

    async def event_generator() -> AsyncIterator[str]:
        buffer = ""
        try:
            async for token in adapter.stream_extract(body, domain):
                buffer += token
                yield _sse({"type": "token", "content": token})

            from app.services.ai.base import _parse_response
            result = _parse_response(buffer, adapter.provider, adapter.model)
            bind_evidence_spans(result, body)

            # Re-open a fresh session for the post-stream DB writes
            from app.core.database import async_session_factory
            async with async_session_factory() as fresh:
                db_s = await fresh.get(AnalysisSession, db_session.id)
                if db_s:
                    try:
                        await _validate_technique_ids(result, domain, fresh)
                        apt_matches = await _rank_apt_groups(result, domain, fresh)
                        await _store_result(db_s, result, apt_matches, fresh)
                        await audit(fresh, user, "analyze.create_session", "analysis_session", session_id, {"provider": provider, "domain": domain, "technique_count": len(result.techniques)})
                        await fresh.commit()
                    except Exception as store_exc:
                        db_s.status = "failed"
                        db_s.error = _STREAM_STORAGE_FAILURE
                        await fresh.commit()
                        _log_failure("Stream DB write failed", store_exc)
                        yield _sse({"type": "error", "message": "Operation failed. See server logs."})
                        return
                else:
                    apt_matches = []

            out = _build_out(session_id, adapter.provider, adapter.model, result, apt_matches)
            yield _sse({"type": "result", "data": out.model_dump()})

        except Exception as exc:
            _log_failure("Stream failed", exc)
            yield _sse({"type": "error", "message": "Operation failed. See server logs."})

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/log-pcap", response_model=LogPcapAnalysisOut)
async def analyze_log_pcap(
    provider: Annotated[str, Form()] = "local",
    model:    Annotated[str | None, Form()] = None,
    domain:   Annotated[str, Form()] = "enterprise-attack",
    text:     Annotated[str | None, Form()] = None,
    file:     UploadFile | None = File(default=None),
    session:  AsyncSession = Depends(get_session),
    user:     TeamUser = Depends(run_analysis),
):
    _require_upload_permission(user, file)
    body, filename = await _read_log_input(text, file)
    if not body.strip():
        raise HTTPException(400, "Uploaded log/pcap did not contain extractable text")

    observables = _observables_from_text(body)
    suspicious = _suspicious_findings(body)
    adapter = _get_adapter(provider, model)
    analysis_text = _build_log_pcap_prompt(body, observables, suspicious)

    try:
        result = await adapter.extract(analysis_text, domain)
        await _validate_technique_ids(result, domain, session)
        apt_matches = await _rank_apt_groups(result, domain, session)
        await audit(session, user, "analyze.log_pcap", "analysis_session", details={"provider": provider, "domain": domain, "filename": filename, "technique_count": len(result.techniques)})
    except Exception as exc:
        _log_failure("Log/PCAP AI analysis failed", exc)
        raise HTTPException(500, "Operation failed. See server logs.") from exc

    report = _build_log_pcap_report(filename, result, observables, suspicious, apt_matches)
    return LogPcapAnalysisOut(
        provider=adapter.provider,
        model=adapter.model,
        filename=filename,
        summary=result.summary,
        report=report,
        observables=observables,
        suspicious_findings=suspicious,
        techniques=[
            TechniqueHit(
                attack_id=t.attack_id,
                name=t.name,
                tactic=t.tactic,
                confidence=t.confidence,
                evidence=t.evidence,
                review_status=t.review_status,
                evidence_start=t.evidence_start,
                evidence_end=t.evidence_end,
                evidence_source=t.evidence_source,
            )
            for t in result.techniques
        ],
        apt_matches=apt_matches,
    )


@router.post("/sessions/research", response_model=StoredResearchOut)
async def store_research(
    domain:   Annotated[str, Form()] = "enterprise-attack",
    name:     Annotated[str | None, Form()] = None,
    text:     Annotated[str | None, Form()] = None,
    file:     UploadFile | None = File(default=None),
    session:  AsyncSession = Depends(get_session),
    user:     TeamUser = Depends(manage_reports),
):
    """
    Store a research/report document without LLM parsing.

    This keeps the source available in Reports / Research and the linked report
    page while making it explicit that no ATT&CK extraction has been performed.
    """
    _require_upload_permission(user, file)
    body, filename = await _read_input(text, file)
    title = (name or filename or "Unparsed research").strip()[:255]
    source_text = body[:_MAX_STORED_REPORT_TEXT]
    summary = _research_storage_summary(body, filename)

    db_session = AnalysisSession(
        status="completed",
        name=title,
        input_type="file" if file else "text",
        filename=filename,
        llm_provider="none",
        model="not-parsed",
        domain=domain,
        tlp="TLP:AMBER+STRICT",
        source_text=source_text,
    )
    session.add(db_session)
    await session.flush()

    session.add(AnalysisResult(
        session_id=db_session.id,
        extracted_techniques=[],
        apt_matches=[],
        summary=summary,
        raw_response="Research stored without AI parsing. Use Parse with AI to extract ATT&CK mappings.",
    ))
    await audit(session, user, "analyze.store_research", "analysis_session", str(db_session.id), {
        "domain": domain,
        "filename": filename,
        "source_text_bytes": len(source_text.encode("utf-8", errors="ignore")),
    })
    await session.commit()

    return StoredResearchOut(
        session_id=str(db_session.id),
        status="completed",
        title=title,
        filename=filename,
        source_url="",
        source_text_available=bool(source_text.strip()),
        summary=summary,
        tlp=db_session.tlp,
    )


@router.post("/sessions/research-url", response_model=StoredResearchOut)
async def ingest_research_url(
    url:      Annotated[str, Form()],
    provider: Annotated[str, Form()] = "claude",
    model:    Annotated[str | None, Form()] = None,
    domain:   Annotated[str, Form()] = "enterprise-attack",
    name:     Annotated[str | None, Form()] = None,
    parse_with_ai: Annotated[bool, Form()] = True,
    session:  AsyncSession = Depends(get_session),
    user:     TeamUser = Depends(manage_reports),
):
    """Fetch a public report URL, store source text/images, and optionally parse it with AI."""
    fetched = await _fetch_report_url(url)
    source_url = _redact_url_secrets(fetched.source_url)
    report_images = [
        image.model_copy(update={"url": _redact_url_secrets(image.url)})
        for image in fetched.report_images
        if _is_public_http_url(image.url)
    ][:80]
    title = (name or fetched.title or source_url).strip()[:255]
    source_text = fetched.source_text[:_MAX_STORED_REPORT_TEXT]
    if not source_text.strip():
        raise HTTPException(400, "Report URL did not contain extractable text")

    adapter = _get_adapter(provider, model) if parse_with_ai else None
    db_session = AnalysisSession(
        status="processing" if parse_with_ai else "completed",
        name=title,
        input_type="url",
        filename=source_url[:500],
        llm_provider=adapter.provider if adapter else "none",
        model=adapter.model if adapter else "not-parsed",
        domain=domain,
        tlp="TLP:AMBER+STRICT",
        source_text=source_text,
    )
    session.add(db_session)
    await session.flush()

    try:
        if adapter:
            result = await adapter.extract(fetched.source_text, domain)
            await _validate_technique_ids(result, domain, session)
            apt_matches = await _rank_apt_groups(result, domain, session)
            await _store_result(db_session, result, apt_matches, session)
            summary = result.summary
        else:
            summary = _research_storage_summary(fetched.source_text, source_url)
            session.add(AnalysisResult(
                session_id=db_session.id,
                extracted_techniques=[],
                apt_matches=[],
                summary=summary,
                raw_response="URL research stored without AI parsing. Use Parse with AI to extract ATT&CK mappings.",
            ))

        notes = {
            "analysis_session_id": str(db_session.id),
            "source_kind": "url-report",
            "source_url": source_url,
            "content_type": fetched.content_type,
            "report_images": [image.model_dump() for image in report_images],
            "metadata": fetched.metadata,
        }
        session.add(ReportIntake(
            title=title,
            url=source_url,
            publisher=_publisher_from_url(source_url),
            status="analyzed" if parse_with_ai else "stored",
            summary=summary[:5000],
            source_reliability="unknown",
            actor_ids=[],
            technique_ids=[tech.attack_id for tech in result.techniques] if adapter else [],
            indicators=[asdict(item) for item in extract_iocs_from_text(
                fetched.source_text,
                source_id="report-url",
                confidence=70,
            )[:200]],
            analyst_notes=json.dumps(notes, ensure_ascii=False),
        ))
        await _retrohunt_assets_after_report_ingest(session, source="url-report")
        await audit(session, user, "analyze.ingest_research_url", "analysis_session", str(db_session.id), {
            "domain": domain,
            "source_url": source_url,
            "parse_with_ai": parse_with_ai,
            "image_count": len(report_images),
        })
        await session.commit()
    except Exception as exc:
        db_session.status = "failed"
        db_session.error = _URL_INGEST_FAILURE
        await session.commit()
        _log_failure("URL report ingestion failed", exc)
        raise HTTPException(500, "Operation failed. See server logs.") from exc

    return StoredResearchOut(
        session_id=str(db_session.id),
        status="completed",
        title=title,
        filename=None,
        source_url=source_url,
        source_text_available=bool(source_text.strip()),
        summary=summary,
        tlp=db_session.tlp,
    )


# ── List stored report sessions (DB 2) ───────────────────────────────────────
# NOTE: must be defined BEFORE GET /{session_id} to avoid route shadowing

@router.get("/sessions", response_model=list[SessionListItem])
async def list_sessions(
    db: AsyncSession = Depends(get_session),
    limit: int = Query(50, ge=1, le=250),
    offset: int = Query(0, ge=0),
    _: TeamUser = Depends(current_user),
):
    """
    Return all completed analysis sessions (DB 2 — user report mappings),
    newest first.  Used to populate the Reports library.
    """
    rows = await db.execute(
        select(AnalysisSession, AnalysisResult)
        .outerjoin(AnalysisResult, AnalysisResult.session_id == AnalysisSession.id)
        .where(AnalysisSession.status == "completed")
        .order_by(AnalysisSession.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    items = []
    for sess, res in rows:
        technique_count = len(res.extracted_techniques) if res else 0
        items.append(SessionListItem(
            session_id=str(sess.id),
            name=sess.name,
            status=sess.status,
            provider=sess.llm_provider,
            model=sess.model,
            domain=sess.domain,
            tlp=_stored_report_tlp(sess.tlp),
            filename=_redact_url_secrets(sess.filename or "", limit=500) if sess.input_type == "url" else sess.filename,
            created_at=sess.created_at.isoformat(),
            technique_count=technique_count,
        ))
    return items


@router.get("/sessions/collection", response_model=ReportCollectionOut)
async def report_collection(
    db: AsyncSession = Depends(get_session),
    limit: int = Query(100, ge=1, le=250),
    offset: int = Query(0, ge=0),
    _: TeamUser = Depends(current_user),
):
    """
    Return analyzed report/research sessions with deterministic tag buckets.

    Each item includes TTP, IOC, CVE, threat actor, sector, and infrastructure
    tags so analysts can browse the research collection without opening every
    individual linked report.
    """
    total = int(await db.scalar(
        select(func.count(AnalysisSession.id))
        .select_from(AnalysisSession)
        .join(AnalysisResult, AnalysisResult.session_id == AnalysisSession.id)
        .where(AnalysisSession.status == "completed")
    ) or 0)
    rows = await db.execute(
        select(AnalysisSession, AnalysisResult)
        .join(AnalysisResult, AnalysisResult.session_id == AnalysisSession.id)
        .where(AnalysisSession.status == "completed")
        .order_by(AnalysisSession.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    pairs = rows.all()
    items: list[ReportCollectionItem] = []
    for sess, res in pairs:
        intake = await _find_report_intake_for_session(db, str(sess.id))
        source_text = (sess.source_text or "").strip()
        source_text_available = bool(source_text)
        if not source_text:
            source_text = _fallback_report_text(sess, res, intake)
        techniques = [TechniqueHit(**item) for item in res.extracted_techniques]
        apt_matches = [AptMatch(**item) for item in res.apt_matches]
        entities = await _linked_report_entities(db, sess, res, intake, source_text, techniques, apt_matches)
        tags = _report_collection_tags(sess, res, intake, source_text, entities)
        safe_filename = _redact_url_secrets(sess.filename or "", limit=500) if sess.input_type == "url" else (sess.filename or "")
        items.append(ReportCollectionItem(
            session_id=str(sess.id),
            title=sess.name or safe_filename or (intake.title if intake else "") or f"Analysis {str(sess.id)[:8]}",
            source_url=_redact_url_secrets(intake.url) if intake else "",
            publisher=intake.publisher if intake else "",
            status=intake.status if intake else sess.status,
            provider=sess.llm_provider,
            model=sess.model,
            domain=sess.domain,
            tlp=_stored_report_tlp(sess.tlp),
            created_at=sess.created_at.isoformat(),
            updated_at=sess.updated_at.isoformat() if sess.updated_at else sess.created_at.isoformat(),
            summary=res.summary,
            source_text_available=source_text_available,
            counts={key: len(value) for key, value in tags.items()},
            tags=tags,
        ))

    return ReportCollectionOut(total=total, limit=limit, offset=offset, items=items)


# ── Compare a stored report against MITRE actors ──────────────────────────────
# NOTE: must be defined BEFORE GET /{session_id} to avoid route shadowing

@router.post("/sessions/{session_id}/compare", response_model=list)
async def compare_session(
    session_id: str,
    top_n: int = 10,
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(run_analysis),
):
    """
    Re-run Jaccard comparison for a stored report session against all group profiles
    and campaigns for the session's domain.  Returns merged results.
    """
    try:
        sid = uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(400, "Invalid session ID")

    res_row = await db.execute(
        select(AnalysisSession, AnalysisResult)
        .outerjoin(AnalysisResult, AnalysisResult.session_id == AnalysisSession.id)
        .where(AnalysisSession.id == sid, AnalysisSession.status == "completed")
    )
    pair = res_row.first()
    if not pair:
        raise HTTPException(404, "Completed session not found")

    sess, res = pair
    if not res or not res.extracted_techniques:
        return []

    from app.services.ai.base import ExtractionResult, ExtractedTechnique
    ext = ExtractionResult(
        techniques=[ExtractedTechnique(**t) for t in res.extracted_techniques],
    )
    apt_matches = await _rank_apt_groups(ext, sess.domain, db, top_n=top_n)
    return [m.model_dump() for m in apt_matches]


# ── Linked report review page ─────────────────────────────────────────────────
# NOTE: must be defined BEFORE GET /{session_id} to avoid route shadowing

@router.get("/sessions/{session_id}/linked-report", response_model=LinkedReportOut)
async def linked_report(
    session_id: str,
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
):
    """
    Return a stored report analysis with linkable platform entities.

    The frontend renders source text as React text nodes and overlays links to
    ATT&CK techniques, CVEs, IOC library searches, and ATT&CK group pages.
    """
    try:
        sid = uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(400, "Invalid session ID")

    row = await db.execute(
        select(AnalysisSession, AnalysisResult)
        .outerjoin(AnalysisResult, AnalysisResult.session_id == AnalysisSession.id)
        .where(AnalysisSession.id == sid, AnalysisSession.status == "completed")
    )
    pair = row.first()
    if not pair:
        raise HTTPException(404, "Completed session not found")
    sess, res = pair
    if not res:
        raise HTTPException(404, "Result not found")

    intake = await _find_report_intake_for_session(db, session_id)
    source_text = (sess.source_text or "").strip()
    source_text_available = bool(source_text)
    source_note = ""
    if not source_text:
        source_text = _fallback_report_text(sess, res, intake)
        source_note = "Original report text was not stored for this older analysis; showing stored summary and report metadata."

    techniques = [TechniqueHit(**t) for t in res.extracted_techniques]
    apt_matches = [AptMatch(**m) for m in res.apt_matches]
    entities = await _linked_report_entities(db, sess, res, intake, source_text, techniques, apt_matches)

    return LinkedReportOut(
        session_id=session_id,
        name=sess.name,
        provider=sess.llm_provider,
        model=sess.model,
        domain=sess.domain,
        tlp=_stored_report_tlp(sess.tlp),
        created_at=sess.created_at.isoformat(),
        source_text=source_text[:_MAX_STORED_REPORT_TEXT],
        source_text_available=source_text_available,
        source_note=source_note,
        summary=res.summary,
        techniques=techniques,
        apt_matches=apt_matches,
        entities=entities,
        report_images=_report_images_from_intake(intake),
        report_intake=_report_intake_dict(intake) if intake else None,
    )


@router.patch("/sessions/{session_id}/linked-report", response_model=LinkedReportOut)
async def edit_linked_report(
    session_id: str,
    body: ReportEditRequest,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(manage_reports),
):
    """Edit stored report title, source text, source URL, publisher, or analyst summary."""
    try:
        sid = uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(400, "Invalid session ID")

    row = await db.execute(
        select(AnalysisSession, AnalysisResult)
        .outerjoin(AnalysisResult, AnalysisResult.session_id == AnalysisSession.id)
        .where(AnalysisSession.id == sid, AnalysisSession.status == "completed")
    )
    pair = row.first()
    if not pair:
        raise HTTPException(404, "Completed session not found")
    sess, res = pair
    if not res:
        raise HTTPException(404, "Result not found")

    intake = await _find_report_intake_for_session(db, session_id)
    if body.name is not None:
        sess.name = body.name.strip()[:255] or sess.name
        if intake:
            intake.title = sess.name or intake.title
    if body.source_text is not None:
        sess.source_text = body.source_text.strip()[:_MAX_STORED_REPORT_TEXT]
    if body.summary is not None:
        res.summary = body.summary.strip()
        if intake:
            intake.summary = res.summary[:5000]
    if body.source_url is not None:
        source_url = body.source_url.strip()
        if source_url and not _is_public_http_url(source_url):
            raise HTTPException(400, "Source URL must be public http/https")
        safe_source_url = _redact_url_secrets(source_url)
        sess.filename = safe_source_url[:500] or sess.filename
        if intake:
            intake.url = safe_source_url
    if body.publisher is not None and intake:
        intake.publisher = body.publisher.strip()[:255]
    if body.tlp is not None:
        sess.tlp = body.tlp

    await audit(db, user, "analyze.edit_linked_report", "analysis_session", session_id, {
        "tlp": sess.tlp,
    })
    await db.commit()
    return await linked_report(session_id, db, user)


@router.post("/sessions/{session_id}/reparse", response_model=AnalysisOut)
async def reparse_linked_report(
    session_id: str,
    body: ReportReparseRequest,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(manage_reports),
):
    """Run AI extraction again over the stored raw report text."""
    try:
        sid = uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(400, "Invalid session ID")

    row = await db.execute(
        select(AnalysisSession, AnalysisResult)
        .outerjoin(AnalysisResult, AnalysisResult.session_id == AnalysisSession.id)
        .where(AnalysisSession.id == sid, AnalysisSession.status == "completed")
    )
    pair = row.first()
    if not pair:
        raise HTTPException(404, "Completed session not found")
    sess, res = pair
    if not res:
        raise HTTPException(404, "Result not found")

    source_text = (sess.source_text or "").strip()
    if not source_text:
        raise HTTPException(400, "No stored raw report text is available to reparse")

    adapter = _get_adapter(body.provider, body.model)
    try:
        result = await adapter.extract(source_text, sess.domain)
        await _validate_technique_ids(result, sess.domain, db)
        apt_matches = await _rank_apt_groups(result, sess.domain, db)
        sess.llm_provider = adapter.provider
        sess.model = adapter.model
        res.extracted_techniques = [technique_to_record(t) for t in result.techniques]
        res.apt_matches = [m.model_dump() for m in apt_matches]
        res.summary = result.summary
        res.raw_response = result.raw_response[:10_000]
        flag_modified(res, "extracted_techniques")
        flag_modified(res, "apt_matches")
        intake = await _find_report_intake_for_session(db, session_id)
        if intake:
            intake.summary = result.summary[:5000]
            intake.status = "analyzed"
            intake.technique_ids = [tech.attack_id for tech in result.techniques]
            flag_modified(intake, "technique_ids")
        await audit(db, user, "analyze.reparse_linked_report", "analysis_session", session_id, {"provider": adapter.provider, "technique_count": len(result.techniques)})
        await db.commit()
    except HTTPException:
        raise
    except Exception as exc:
        _log_failure("Report reparse failed", exc)
        raise HTTPException(500, "Operation failed. See server logs.") from exc

    return _build_out(session_id, adapter.provider, adapter.model, result, apt_matches)


# ── Delete a stored session ───────────────────────────────────────────────────
# NOTE: must be defined BEFORE GET /{session_id} to avoid route shadowing

@router.delete("/sessions/{session_id}", status_code=204)
async def delete_session(
    session_id: str,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(manage_reports),
):
    try:
        sid = uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(400, "Invalid session ID")

    exists = await db.execute(select(AnalysisSession.id).where(AnalysisSession.id == sid))
    if not exists.scalar_one_or_none():
        raise HTTPException(404, "Session not found")
    intake = await _find_report_intake_for_session(db, session_id)
    if intake:
        await db.delete(intake)
    await audit(db, user, "analyze.delete_session", "analysis_session", session_id)
    await db.execute(sql_delete(AnalysisSession).where(AnalysisSession.id == sid))
    await db.commit()


# ── Review a stored technique mapping ─────────────────────────────────────────

@router.patch("/sessions/{session_id}/techniques/{attack_id}/review", response_model=TechniqueHit)
async def update_technique_review(
    session_id: str,
    attack_id: str,
    body: TechniqueReviewUpdate,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(manage_reports),
):
    try:
        sid = uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(400, "Invalid session ID")

    row = await db.execute(
        select(AnalysisResult).where(AnalysisResult.session_id == sid)
    )
    result = row.scalar_one_or_none()
    if not result:
        raise HTTPException(404, "Result not found")

    updated = update_extracted_technique_review(
        result.extracted_techniques,
        attack_id,
        review_status=body.review_status,
        evidence=body.evidence,
        review_note=body.review_note,
        reviewer=body.reviewer,
    )
    if not updated:
        raise HTTPException(404, "Technique not found")

    flag_modified(result, "extracted_techniques")
    await audit(db, user, "analyze.review_technique", "analysis_session", session_id, {"attack_id": attack_id, "review_status": body.review_status})
    await db.commit()
    return TechniqueHit(**updated)


# ── Retrieve stored result ────────────────────────────────────────────────────

@router.get("/{session_id}", response_model=AnalysisOut)
async def get_result(
    session_id: str,
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
):
    try:
        sid = uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(400, "Invalid session ID")

    row = await db.execute(
        select(AnalysisSession).where(AnalysisSession.id == sid)
    )
    db_session = row.scalar_one_or_none()
    if not db_session:
        raise HTTPException(404, "Session not found")

    if db_session.status != "completed":
        return JSONResponse(
            status_code=202,
            content={"detail": f"Analysis is {db_session.status}"},
        )

    res_row = await db.execute(
        select(AnalysisResult).where(AnalysisResult.session_id == sid)
    )
    res = res_row.scalar_one_or_none()
    if not res:
        raise HTTPException(404, "Result not found")

    techniques = [TechniqueHit(**t) for t in res.extracted_techniques]
    apt_matches = [AptMatch(**m) for m in res.apt_matches]
    return AnalysisOut(
        session_id=session_id,
        provider=db_session.llm_provider,
        model=db_session.model,
        summary=res.summary,
        techniques=techniques,
        apt_matches=apt_matches,
        apt_hints=[],
        raw_response=res.raw_response or "",
    )


# ── Single-turn LLM chat ──────────────────────────────────────────────────────

@router.post("/chat")
async def chat(req: ChatRequest, _: TeamUser = Depends(run_analysis)):
    """
    Analyst asks a free-form question about ATT&CK, a technique, or a TTP set.
    Returns a streaming SSE response of plain text (not JSON).
    """
    adapter = _get_adapter(req.provider, req.model)

    system = req.system_prompt or (
        "You are a senior threat intelligence analyst with deep expertise in the MITRE ATT&CK "
        "framework. Answer the analyst's question clearly and concisely. Reference specific "
        "ATT&CK technique IDs where relevant. Be precise and actionable.\n\n"
        + TAXONOMY_SYSTEM_INSTRUCTIONS
    )
    user = req.message
    if req.context:
        user = f"Context:\n{req.context}\n\n---\n\nQuestion: {req.message}"

    async def direct_stream() -> AsyncIterator[str]:
        try:
            async for token in adapter._stream_complete(system, user):
                yield _sse({"type": "token", "content": token})
            yield _sse({"type": "done"})
        except Exception as exc:
            _log_failure("Chat stream failed", exc)
            yield _sse({"type": "error", "message": "Operation failed. See server logs."})

    return StreamingResponse(
        direct_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _find_report_intake_for_session(db: AsyncSession, session_id: str) -> ReportIntake | None:
    rows = await db.execute(
        select(ReportIntake)
        .where(ReportIntake.analyst_notes.ilike(f"%{session_id}%"))
        .order_by(ReportIntake.updated_at.desc())
        .limit(1)
    )
    return rows.scalar_one_or_none()


def _fallback_report_text(sess: AnalysisSession, res: AnalysisResult, intake: ReportIntake | None) -> str:
    safe_filename = _redact_url_secrets(sess.filename or "", limit=500) if sess.input_type == "url" else (sess.filename or "")
    lines = [
        sess.name or safe_filename or f"Analysis {sess.id}",
        "",
    ]
    if intake:
        lines.extend([
            f"Source URL: {_redact_url_secrets(intake.url) or 'not provided'}",
            f"Publisher: {intake.publisher or 'unknown'}",
            f"Reliability: {intake.source_reliability or 'unknown'}",
            "",
            "Stored report intake summary",
            intake.summary or "No report intake summary is stored.",
            "",
            "Stored report intake metadata",
            intake.analyst_notes or "No analyst metadata is stored.",
            "",
        ])
    lines.extend([
        "AI analysis summary",
        res.summary or "No summary is stored.",
        "",
        "Mapped ATT&CK techniques",
    ])
    for item in res.extracted_techniques[:200]:
        lines.append(f"- {item.get('attack_id', '')} {item.get('name', '')}: {item.get('evidence', '')}")
    if res.apt_matches:
        lines.extend(["", "Possible actor overlap"])
        for item in res.apt_matches[:20]:
            lines.append(f"- {item.get('group_attack_id', '')} {item.get('group_name', '')}")
    return "\n".join(lines)


def _research_storage_summary(text: str, filename: str | None) -> str:
    clean = re.sub(r"\s+", " ", text).strip()
    if not clean:
        return f"{filename or 'Research document'} was stored without AI parsing. No source text was extracted."
    preview = clean[:700].rstrip()
    suffix = "" if len(clean) <= 700 else "..."
    return (
        f"Stored research document {filename or ''} without AI parsing. "
        f"No ATT&CK mappings have been extracted yet. Preview: {preview}{suffix}"
    ).strip()


def _stored_report_tlp(value: str | None) -> str:
    allowed = {"TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"}
    return value if value in allowed else "TLP:AMBER+STRICT"


async def _fetch_report_url(url: str) -> UrlReportFetch:
    source_url = url.strip()
    if len(source_url) > 4096 or not _is_public_http_url(source_url):
        raise HTTPException(400, "Report URL must use http or https and include a host")
    try:
        response = await async_safe_get(
            source_url,
            timeout=30,
            max_bytes=MAX_UPLOAD_BYTES,
            headers={"User-Agent": "AdversaryGraph-ReportIngest/1.0", "Accept": "text/html,application/pdf,text/plain,*/*;q=0.8"},
        )
    except ResponseTooLargeError as exc:
        raise HTTPException(413, "Fetched report exceeds 50 MB limit") from exc
    except ValueError as exc:
        logger.warning("Report URL blocked by outbound policy: %s", type(exc).__name__)
        raise HTTPException(400, "Report URL is not allowed by the outbound network policy") from exc
    except Exception as exc:
        logger.warning("Report URL fetch failed: %s", type(exc).__name__)
        raise HTTPException(502, "Report URL could not be fetched. See server logs.") from exc

    if response.status_code >= 400:
        raise HTTPException(400, f"Report URL returned HTTP {response.status_code}")
    content = response.content
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "Fetched report exceeds 50 MB limit")
    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    raw_final_url = str(response.url) if str(response.url) else source_url
    final_url = _redact_url_secrets(raw_final_url)
    filename = urlparse(raw_final_url).path.rsplit("/", 1)[-1] or "remote-report"

    if content_type == "application/pdf" or filename.lower().endswith(".pdf"):
        text = extract_text(content, filename if filename.lower().endswith(".pdf") else "remote-report.pdf")
        return UrlReportFetch(
            title=filename or final_url,
            source_url=final_url,
            content_type=content_type or "application/pdf",
            source_text=text,
            report_images=[],
            metadata={"parser": "pdf-text", "publisher": _publisher_from_url(final_url)},
        )

    if content_type in {"text/html", "application/xhtml+xml", ""} or filename.lower().endswith((".html", ".htm", "/")):
        decoded = _decode_response_text(response)
        parsed = _extract_html_report(decoded, raw_final_url)
        return UrlReportFetch(
            title=parsed["title"] or filename or final_url,
            source_url=final_url,
            content_type=content_type or "text/html",
            source_text=parsed["text"],
            report_images=parsed["images"],
            metadata={"parser": "html-text-images", "publisher": _publisher_from_url(final_url), "description": parsed["description"]},
        )

    text = extract_text(content, filename or "remote-report.txt")
    return UrlReportFetch(
        title=filename or final_url,
        source_url=final_url,
        content_type=content_type or "application/octet-stream",
        source_text=text,
        report_images=[],
        metadata={"parser": "plain-text", "publisher": _publisher_from_url(final_url)},
    )


class _ReportHTMLParser(HTMLParser):
    _BLOCK_TAGS = {"p", "div", "section", "article", "header", "footer", "li", "tr", "table", "h1", "h2", "h3", "h4", "h5", "h6", "br"}
    _SKIP_TAGS = {"script", "style", "noscript", "svg", "canvas", "iframe", "form", "button"}
    _VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}
    _IRRELEVANT_RE = re.compile(
        r"\b(?:ad|ads|advert|advertisement|banner|breadcrumb|cookie|consent|footer|header|hero|masthead|menu|nav|newsletter|"
        r"promo|recommend|related|share|sidebar|social|sponsor|subscribe|toolbar|widget)\b",
        re.IGNORECASE,
    )
    _CONTENT_RE = re.compile(
        r"\b(?:article|body-content|content-body|entry-content|main-content|markdown|post-content|report|report-body|"
        r"research|rich-text|story|threat-report)\b",
        re.IGNORECASE,
    )
    _IMAGE_NOISE_RE = re.compile(
        r"\b(?:ad|advert|avatar|banner|button|cookie|favicon|hero|icon|logo|pixel|promo|share|social|sponsor|sprite|tracking)\b",
        re.IGNORECASE,
    )

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.text_parts: list[str] = []
        self.content_text_parts: list[str] = []
        self.images: list[LinkedReportImage] = []
        self.content_images: list[LinkedReportImage] = []
        self.title_parts: list[str] = []
        self.description = ""
        self._skip_depth = 0
        self._content_depth = 0
        self._content_stack: list[bool] = []
        self._in_title = False
        self._seen_images: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attr = {key.lower(): value or "" for key, value in attrs}
        if self._skip_depth:
            if tag not in self._VOID_TAGS:
                self._skip_depth += 1
            return
        if tag in self._SKIP_TAGS or self._is_irrelevant_container(tag, attr):
            self._skip_depth = 1
            return
        starts_content = self._is_content_container(tag, attr)
        self._content_stack.append(starts_content)
        if starts_content:
            self._content_depth += 1
        if tag == "title":
            self._in_title = True
        if tag == "meta":
            name = (attr.get("name") or attr.get("property") or "").lower()
            if name in {"description", "og:description", "twitter:description"} and not self.description:
                self.description = attr.get("content", "").strip()[:1000]
        if tag == "img":
            self._add_image(attr)
        if tag in self._BLOCK_TAGS:
            self._append_text("\n")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if self._skip_depth:
            self._skip_depth -= 1
            return
        if tag == "title":
            self._in_title = False
        if tag in self._BLOCK_TAGS:
            self._append_text("\n")
        if self._content_stack:
            started_content = self._content_stack.pop()
            if started_content and self._content_depth:
                self._content_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        clean = re.sub(r"\s+", " ", data).strip()
        if not clean:
            return
        if self._in_title:
            self.title_parts.append(clean)
        self._append_text(clean)
        self._append_text(" ")

    def _append_text(self, value: str) -> None:
        self.text_parts.append(value)
        if self._content_depth:
            self.content_text_parts.append(value)

    def _add_image(self, attr: dict[str, str]) -> None:
        raw_src = attr.get("src") or attr.get("data-src") or attr.get("data-original") or _first_srcset_url(attr.get("srcset", ""))
        if not raw_src:
            return
        raw_image_url = urljoin(self.base_url, raw_src.strip())
        if not _is_public_http_url(raw_image_url):
            return
        image_url = _redact_url_secrets(raw_image_url)
        if image_url in self._seen_images or self._is_noise_image(attr, image_url):
            return
        self._seen_images.add(image_url)
        alt = re.sub(r"\s+", " ", attr.get("alt", "")).strip()[:300]
        image = LinkedReportImage(url=image_url, alt=alt, caption=alt, source="remote-html-img")
        self.images.append(image)
        if self._content_depth:
            self.content_images.append(image)

    def _is_irrelevant_container(self, tag: str, attr: dict[str, str]) -> bool:
        if tag in {"nav", "aside", "footer"}:
            return True
        role = attr.get("role", "").lower()
        if role in {"banner", "navigation", "complementary", "contentinfo", "search"}:
            return True
        haystack = " ".join(attr.get(key, "") for key in ("id", "class", "role", "aria-label", "data-testid", "data-test", "data-component"))
        return bool(self._IRRELEVANT_RE.search(haystack))

    def _is_content_container(self, tag: str, attr: dict[str, str]) -> bool:
        if tag in {"article", "main"}:
            return True
        haystack = " ".join(attr.get(key, "") for key in ("id", "class", "role", "itemprop", "data-testid", "data-test"))
        return bool(self._CONTENT_RE.search(haystack))

    def _is_noise_image(self, attr: dict[str, str], image_url: str) -> bool:
        haystack = " ".join(attr.get(key, "") for key in ("id", "class", "alt", "title", "role", "aria-label")) + " " + image_url
        if self._IMAGE_NOISE_RE.search(haystack):
            return True
        width = _safe_int(attr.get("width", ""))
        height = _safe_int(attr.get("height", ""))
        return (width is not None and width <= 4) or (height is not None and height <= 4)


def _extract_html_report(html: str, base_url: str) -> dict[str, Any]:
    parser = _ReportHTMLParser(base_url)
    parser.feed(html[:5_000_000])
    title = re.sub(r"\s+", " ", " ".join(parser.title_parts)).strip()[:500]
    content_text = _clean_html_text("".join(parser.content_text_parts))
    fallback_text = _clean_html_text("".join(parser.text_parts))
    text = content_text if len(content_text) >= 500 or (content_text and len(content_text) >= len(fallback_text) * 0.25) else fallback_text
    if parser.description and parser.description not in text[:2000]:
        text = f"{parser.description}\n\n{text}".strip()
    images = parser.content_images if content_text and parser.content_images else parser.images
    return {"title": title, "description": parser.description, "text": text[:_MAX_STORED_REPORT_TEXT], "images": images[:80]}


def _clean_html_text(text: str) -> str:
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    lines = [line.strip() for line in text.splitlines()]
    return "\n".join(line for line in lines if line).strip()


def _first_srcset_url(srcset: str) -> str:
    first = srcset.split(",", 1)[0].strip()
    return first.split()[0] if first else ""


def _safe_int(value: str) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _decode_response_text(response) -> str:
    try:
        return response.text
    except UnicodeDecodeError:
        return response.content.decode("utf-8", errors="replace")


def _is_sensitive_query_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    if normalized in {"auth", "authorization", "bearer", "jwt", "key", "sig", "signature"}:
        return True
    return any(
        marker in normalized
        for marker in (
            "accesskey",
            "accesstoken",
            "apikey",
            "assertion",
            "clientsecret",
            "credential",
            "password",
            "privatekey",
            "refreshtoken",
            "samlresponse",
            "secret",
            "secretkey",
            "sessionid",
            "sharedaccesssignature",
            "subscriptionkey",
            "ticket",
            "token",
        )
    )


def _redact_url_secrets(url: str, *, limit: int = MAX_SOURCE_URL_LENGTH) -> str:
    """Remove URL userinfo and redact credential-like query values."""
    value = str(url or "").strip()
    if not value or limit <= 0:
        return ""
    try:
        parsed = urlparse(value)
    except ValueError:
        return ""
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return value[:limit]

    try:
        query_items = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=100)
    except ValueError:
        safe_query = ""
    else:
        safe_query = urlencode(
            [
                (key, "REDACTED" if _is_sensitive_query_key(key) else item_value)
                for key, item_value in query_items
            ],
            doseq=True,
        )
    # The server never needs URL fragments, and OAuth-style fragments may
    # carry access tokens. Removing userinfo also covers legacy embedded basic
    # authentication without ever copying it to storage or API responses.
    safe_netloc = parsed.netloc.rsplit("@", 1)[-1]
    return parsed._replace(netloc=safe_netloc, query=safe_query, fragment="").geturl()[:limit]


def _is_public_http_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    hostname = parsed.hostname.lower().strip("[]")
    if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(".localhost"):
        return False
    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        return True
    return not (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_private
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _publisher_from_url(url: str) -> str:
    return (urlparse(url).hostname or "").removeprefix("www.")[:255]


def _report_intake_dict(intake: ReportIntake) -> dict[str, Any]:
    notes = _safe_json_obj(intake.analyst_notes)
    return {
        "id": str(intake.id),
        "title": intake.title,
        "url": _redact_url_secrets(intake.url),
        "publisher": intake.publisher,
        "status": intake.status,
        "source_reliability": intake.source_reliability,
        "actor_ids": intake.actor_ids or [],
        "technique_ids": intake.technique_ids or [],
        "indicator_count": len(intake.indicators or []),
        "report_images": [image.model_dump() for image in _report_images_from_intake(intake)],
        "content_type": str(notes.get("content_type") or ""),
        "source_kind": str(notes.get("source_kind") or ""),
        "created_at": intake.created_at.isoformat() if intake.created_at else "",
        "updated_at": intake.updated_at.isoformat() if intake.updated_at else "",
    }


def _report_images_from_intake(intake: ReportIntake | None) -> list[LinkedReportImage]:
    if not intake:
        return []
    notes = _safe_json_obj(intake.analyst_notes)
    images = notes.get("report_images")
    if not isinstance(images, list):
        return []
    result: list[LinkedReportImage] = []
    seen: set[str] = set()
    for image in images:
        if not isinstance(image, dict):
            continue
        raw_url = str(image.get("url") or "").strip()
        if not _is_public_http_url(raw_url):
            continue
        url = _redact_url_secrets(raw_url)
        if url in seen:
            continue
        seen.add(url)
        result.append(LinkedReportImage(
            url=url,
            alt=str(image.get("alt") or "")[:300],
            caption=str(image.get("caption") or image.get("alt") or "")[:500],
            source=str(image.get("source") or "remote-report")[:80],
        ))
        if len(result) >= 80:
            break
    return result


def _report_collection_tags(
    sess: AnalysisSession,
    res: AnalysisResult,
    intake: ReportIntake | None,
    source_text: str,
    entities: list[LinkedReportEntity],
) -> dict[str, list[ReportCollectionTag]]:
    tags: dict[str, list[ReportCollectionTag]] = {
        "reports": [],
        "ttps": [],
        "iocs": [],
        "cves": [],
        "threat_actors": [],
        "sectors": [],
        "infrastructure": [],
    }
    safe_filename = _redact_url_secrets(sess.filename or "", limit=500) if sess.input_type == "url" else (sess.filename or "")
    tags["reports"].append(_collection_tag(
        "report",
        sess.name or safe_filename or (intake.title if intake else "") or f"Analysis {str(sess.id)[:8]}",
        str(sess.id),
        f"/analyze/{sess.id}/report",
        100,
        {
            "source_url": _redact_url_secrets(intake.url) if intake else "",
            "publisher": intake.publisher if intake else "",
            "image_count": len(_report_images_from_intake(intake)),
        },
    ))
    for entity in entities:
        if entity.type == "technique":
            tags["ttps"].append(_collection_tag("ttp", entity.label, entity.id, entity.route, 90, entity.metadata))
        elif entity.type == "ioc":
            ioc_type = str(entity.metadata.get("ioc_type") or "indicator")
            tags["iocs"].append(_collection_tag("ioc", entity.label, entity.value or entity.id, entity.route, int(entity.metadata.get("confidence") or 70), {"ioc_type": ioc_type}))
            if _is_infrastructure_ioc_type(ioc_type):
                tags["infrastructure"].append(_collection_tag("infrastructure", entity.label, entity.value or entity.id, entity.route, 80, {"source": "ioc", "ioc_type": ioc_type}))
        elif entity.type == "cve":
            tags["cves"].append(_collection_tag("cve", entity.label, entity.id, entity.route, 90, entity.metadata))
        elif entity.type == "group":
            tags["threat_actors"].append(_collection_tag("threat_actor", entity.label, entity.id, entity.route, 75, entity.metadata))

    if intake:
        notes = _safe_json_obj(intake.analyst_notes)
        for sector in _extract_metadata_list(notes, "sectors", "sector", "target_sectors", "industries"):
            tags["sectors"].append(_collection_tag("sector", sector, sector, "/sector-intel", 85, {"source": "report-intake"}))
        for infra in _extract_metadata_list(notes, "infrastructure", "infra", "platforms", "technologies"):
            tags["infrastructure"].append(_collection_tag("infrastructure", infra, infra, "", 75, {"source": "report-intake"}))

    context = "\n".join([
        sess.name or "",
        sess.filename or "",
        res.summary or "",
        res.raw_response or "",
        intake.summary if intake else "",
        intake.analyst_notes if intake else "",
        source_text[:25_000],
    ])
    for sector in _extract_sector_tags(context):
        tags["sectors"].append(_collection_tag("sector", sector, sector, "/sector-intel", 60, {"source": "keyword"}))
    for infra in _extract_infrastructure_tags(context):
        tags["infrastructure"].append(_collection_tag("infrastructure", infra, infra, "", 60, {"source": "keyword"}))

    return {key: _dedupe_collection_tags(value, limit=_tag_bucket_limit(key)) for key, value in tags.items()}


def _collection_tag(
    tag_type: str,
    label: str,
    value: str,
    route: str = "",
    confidence: int = 50,
    metadata: dict[str, Any] | None = None,
) -> ReportCollectionTag:
    return ReportCollectionTag(
        type=tag_type,
        label=str(label or value).strip(),
        value=str(value or label).strip(),
        route=route,
        confidence=max(0, min(100, int(confidence))),
        metadata=metadata or {},
    )


def _tag_bucket_limit(key: str) -> int:
    return {
        "reports": 50,
        "ttps": 80,
        "iocs": 120,
        "cves": 80,
        "threat_actors": 30,
        "sectors": 30,
        "infrastructure": 80,
    }.get(key, 50)


def _dedupe_collection_tags(tags: list[ReportCollectionTag], limit: int) -> list[ReportCollectionTag]:
    seen: set[tuple[str, str]] = set()
    result: list[ReportCollectionTag] = []
    for tag in tags:
        if not tag.value:
            continue
        key = (tag.type, tag.value.lower())
        if key in seen:
            continue
        seen.add(key)
        result.append(tag)
        if len(result) >= limit:
            break
    return result


def _extract_metadata_list(data: dict[str, Any], *keys: str) -> list[str]:
    values: list[str] = []
    for key in keys:
        raw = data.get(key)
        if isinstance(raw, str):
            values.extend(part.strip() for part in re.split(r"[,;|]", raw) if part.strip())
        elif isinstance(raw, list):
            values.extend(str(item).strip() for item in raw if str(item).strip())
    return values[:50]


def _is_infrastructure_ioc_type(ioc_type: str) -> bool:
    normalized = ioc_type.lower().replace("-", "_")
    return normalized in {
        "ip", "ipv4", "ipv6", "domain", "hostname", "url", "uri", "asn", "cidr",
        "email", "email_address", "mutex", "registry_key", "x509", "certificate",
    }


def _extract_sector_tags(text: str) -> list[str]:
    sector_patterns = {
        "Government": r"\b(government|ministry|public sector|municipal|embassy|diplomatic)\b",
        "Defense": r"\b(defen[cs]e|military|aerospace|army|navy|air force)\b",
        "Energy": r"\b(energy|electric|power grid|oil|gas|utility|utilities)\b",
        "Finance": r"\b(finance|financial|bank|banking|payment|insurance)\b",
        "Telecommunications": r"\b(telecom|telecommunications|mobile operator|isp)\b",
        "Healthcare": r"\b(healthcare|hospital|medical|pharmaceutical|pharma)\b",
        "Technology": r"\b(technology|software|saas|cloud provider|it services)\b",
        "Education": r"\b(education|university|college|research institute)\b",
        "Manufacturing": r"\b(manufacturing|factory|industrial|supply chain)\b",
        "Transportation": r"\b(transport|transportation|aviation|airport|rail|shipping|logistics)\b",
        "Media": r"\b(media|journalist|news|broadcast)\b",
        "Critical Infrastructure": r"\b(critical infrastructure|water treatment|ics|scada|ot environment)\b",
    }
    return [label for label, pattern in sector_patterns.items() if re.search(pattern, text, re.IGNORECASE)]


def _extract_infrastructure_tags(text: str) -> list[str]:
    infrastructure_patterns = {
        "VPN": r"\b(vpn|ssl vpn|globalprotect|forticlient|pulse secure)\b",
        "Firewall": r"\b(firewall|fortigate|palo alto|checkpoint|asa)\b",
        "Email Gateway": r"\b(email gateway|mail gateway|exchange|o365|microsoft 365|outlook web access|owa)\b",
        "Identity Provider": r"\b(adfs|okta|azure ad|entra id|identity provider|sso)\b",
        "Cloud": r"\b(aws|azure|gcp|cloud storage|s3 bucket|blob storage)\b",
        "Web Server": r"\b(nginx|apache|iis|web server|tomcat|jboss)\b",
        "Database": r"\b(sql server|mysql|postgres|oracle database|mongodb|redis)\b",
        "Remote Access": r"\b(rdp|ssh|winrm|vnc|citrix|anydesk|teamviewer)\b",
        "Active Directory": r"\b(active directory|domain controller|kerberos|ldap)\b",
        "Endpoint": r"\b(endpoint|workstation|laptop|windows host|linux host|server)\b",
        "C2 Infrastructure": r"\b(command and control|c2|c&c|beacon|redirector)\b",
        "Proxy": r"\b(proxy|reverse proxy|cdn|cloudflare|akamai)\b",
    }
    return [label for label, pattern in infrastructure_patterns.items() if re.search(pattern, text, re.IGNORECASE)]


async def _linked_report_entities(
    db: AsyncSession,
    sess: AnalysisSession,
    res: AnalysisResult,
    intake: ReportIntake | None,
    source_text: str,
    techniques: list[TechniqueHit],
    apt_matches: list[AptMatch],
) -> list[LinkedReportEntity]:
    entities: list[LinkedReportEntity] = []

    for technique in techniques:
        entities.append(LinkedReportEntity(
            type="technique",
            id=technique.attack_id.upper(),
            label=f"{technique.attack_id.upper()} {technique.name}".strip(),
            value=technique.attack_id.upper(),
            route=f"/navigator?technique={technique.attack_id.upper()}",
            metadata={
                "tactic": technique.tactic,
                "confidence": technique.confidence,
                "review_status": technique.review_status,
                "source": "analysis",
            },
        ))

    if intake:
        for attack_id in intake.technique_ids or []:
            value = str(attack_id).upper()
            if re.match(r"^T\d{4}(?:\.\d{3})?$", value):
                entities.append(LinkedReportEntity(
                    type="technique",
                    id=value,
                    label=value,
                    value=value,
                    route=f"/navigator?technique={value}",
                    metadata={"source": "report-intake"},
                ))

    group_ids = {match.group_attack_id for match in apt_matches if match.group_attack_id}
    if intake:
        group_ids.update(str(item) for item in (intake.actor_ids or []) if str(item).startswith("G"))
    if group_ids:
        group_rows = await db.execute(
            select(AptGroup).where(
                AptGroup.domain == sess.domain,
                AptGroup.attack_id.in_(sorted(group_ids)),
            )
        )
        group_lookup = {group.attack_id: group for group in group_rows.scalars().all()}
        for group_id in sorted(group_ids):
            group = group_lookup.get(group_id)
            match = next((item for item in apt_matches if item.group_attack_id == group_id), None)
            entities.append(LinkedReportEntity(
                type="group",
                id=group_id,
                label=group.name if group else (match.group_name if match else group_id),
                value=group_id,
                route=f"/apt?group={group_id}",
                aliases=[str(alias) for alias in ((group.aliases if group else []) or []) if alias],
                metadata={
                    "source": "analysis-overlap" if match else "report-intake",
                    "similarity": match.similarity if match else None,
                    "shared_count": match.shared_count if match else None,
                },
            ))

    text_blobs = [
        source_text,
        res.summary or "",
        res.raw_response or "",
        intake.analyst_notes if intake else "",
        json.dumps(intake.indicators, ensure_ascii=False) if intake and intake.indicators else "",
    ]
    for cve_id in _extract_cve_ids(*text_blobs):
        entities.append(LinkedReportEntity(
            type="cve",
            id=cve_id,
            label=cve_id,
            value=cve_id,
            route=f"/cve?cve={cve_id}",
            metadata={"source": "source-text"},
        ))

    for item in extract_iocs_from_text(source_text, source_id="linked-report-preview", confidence=70)[:300]:
        entities.append(LinkedReportEntity(
            type="ioc",
            id=item.value,
            label=item.value,
            value=item.value,
            route=f"/ioc-library?search={item.value}",
            metadata={
                "ioc_type": item.indicator_type,
                "confidence": item.confidence,
                "source": "source-text",
            },
        ))

    if intake:
        for item in (intake.indicators or [])[:300]:
            if not isinstance(item, dict):
                continue
            value = str(item.get("value") or item.get("indicator") or item.get("observable") or "").strip()
            if not value:
                continue
            entities.append(LinkedReportEntity(
                type="ioc",
                id=value,
                label=value,
                value=value,
                route=f"/ioc-library?search={value}",
                metadata={
                    "ioc_type": str(item.get("type") or item.get("indicator_type") or "indicator"),
                    "source": "report-intake",
                },
            ))

        notes = _safe_json_obj(intake.analyst_notes)
        ioc_source_id = str(notes.get("ioc_source_id") or "").strip()
        if ioc_source_id:
            rows = await db.execute(
                select(IOCIndicator)
                .where(IOCIndicator.source_id == ioc_source_id)
                .order_by(IOCIndicator.id.asc())
                .limit(300)
            )
            for indicator in rows.scalars().all():
                entities.append(LinkedReportEntity(
                    type="ioc",
                    id=str(indicator.id),
                    label=indicator.value,
                    value=indicator.value,
                    route=f"/ioc-library/{indicator.id}",
                    metadata={
                        "ioc_type": indicator.indicator_type,
                        "confidence": indicator.confidence,
                        "source": indicator.source_id,
                    },
                ))

    return _dedupe_entities(entities, limit=900)


def _extract_cve_ids(*values: str) -> list[str]:
    seen: set[str] = set()
    results: list[str] = []
    for value in values:
        if not value:
            continue
        for match in _CVE_RE.finditer(value):
            cve_id = match.group(0).upper()
            if cve_id not in seen:
                seen.add(cve_id)
                results.append(cve_id)
    return results[:500]


def _safe_json_obj(value: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _dedupe_entities(entities: list[LinkedReportEntity], limit: int) -> list[LinkedReportEntity]:
    seen: set[tuple[str, str]] = set()
    deduped: list[LinkedReportEntity] = []
    for entity in entities:
        key = (entity.type, (entity.value or entity.id or entity.label).lower())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(entity)
        if len(deduped) >= limit:
            break
    return deduped


async def _read_input(
    text: str | None, file: UploadFile | None
) -> tuple[str, str | None]:
    if file:
        # Reject early using Content-Length if the header is present
        if file.size is not None and file.size > MAX_UPLOAD_BYTES:
            raise HTTPException(413, "File exceeds 50 MB limit")
        # Stream with a hard cap so we never buffer more than the limit in RAM
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = await file.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_UPLOAD_BYTES:
                raise HTTPException(413, "File exceeds 50 MB limit")
            chunks.append(chunk)
        raw = b"".join(chunks)
        return extract_text(raw, file.filename or "upload"), file.filename
    if text and text.strip():
        clean_text = text.strip()
        if len(clean_text.encode("utf-8")) > MAX_UPLOAD_BYTES:
            raise HTTPException(413, "Text input exceeds 50 MB limit")
        return clean_text, None
    raise HTTPException(400, "Provide either 'text' or 'file'")


async def _read_log_input(text: str | None, file: UploadFile | None) -> tuple[str, str | None]:
    if file:
        if file.size is not None and file.size > MAX_UPLOAD_BYTES:
            raise HTTPException(413, "File exceeds 50 MB limit")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = await file.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_UPLOAD_BYTES:
                raise HTTPException(413, "File exceeds 50 MB limit")
            chunks.append(chunk)
        raw = b"".join(chunks)
        name = file.filename or "upload"
        if name.lower().endswith((".pcap", ".pcapng", ".cap")):
            return _extract_strings(raw), name
        return extract_text(raw, name), name
    if text and text.strip():
        clean_text = text.strip()
        if len(clean_text.encode("utf-8")) > MAX_UPLOAD_BYTES:
            raise HTTPException(413, "Text input exceeds 50 MB limit")
        return clean_text, None
    raise HTTPException(400, "Provide either 'text' or 'file'")


def _extract_strings(content: bytes) -> str:
    ascii_strings = re.findall(rb"[\x20-\x7e]{4,}", content)
    decoded = [item.decode("latin-1", errors="ignore") for item in ascii_strings[:25_000]]
    return "\n".join(decoded)[:120_000]


def _observables_from_text(text: str) -> list[LogObservable]:
    items = extract_iocs_from_text(text, source_id="log-pcap-analysis", confidence=75)
    powershell = sorted(set(re.findall(r"(?i)\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b[^\r\n]{0,240}", text)))[:40]
    functions = sorted(set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]{2,64}\s*\(", text)))[:80]
    observables = [
        LogObservable(
            value=item.value,
            type=item.indicator_type,
            confidence=item.confidence,
            description=item.description or "Observable extracted from log/pcap input.",
        )
        for item in items[:300]
    ]
    observables.extend(
        LogObservable(value=value.strip(), type="powershell", confidence=80, description="PowerShell command or invocation extracted from input.")
        for value in powershell
    )
    observables.extend(
        LogObservable(value=value.rstrip("("), type="function", confidence=45, description="Function-like token extracted for analyst review.")
        for value in functions
    )
    return observables[:500]


def _suspicious_findings(text: str) -> list[SuspiciousFinding]:
    patterns = [
        ("high", "PowerShell encoded command", r"(?i)powershell[^\r\n]{0,200}\s-(?:enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", "Encoded PowerShell frequently appears in malware execution and defense evasion."),
        ("high", "Credential dumping keyword", r"(?i)\b(?:mimikatz|sekurlsa|lsass|procdump|nanodump)\b[^\r\n]{0,160}", "Credential dumping tooling or LSASS access indicator was present."),
        ("medium", "Suspicious LOLBin", r"(?i)\b(?:rundll32|regsvr32|mshta|wmic|bitsadmin|certutil)\b[^\r\n]{0,180}", "Common living-off-the-land binary appeared in execution context."),
        ("medium", "Persistence keyword", r"(?i)\b(?:schtasks|runonce|startup|services?\.exe|new-service|set-service)\b[^\r\n]{0,180}", "Persistence or service/task modification keyword was present."),
        ("medium", "Remote access keyword", r"(?i)\b(?:rdp|ssh|winrm|psexec|smbexec|remote desktop)\b[^\r\n]{0,180}", "Remote access or lateral movement keyword was present."),
        ("medium", "Archive/exfil keyword", r"(?i)\b(?:7z|rar|zip|rclone|megasync|exfil|upload)\b[^\r\n]{0,180}", "Archiving, transfer, or exfiltration keyword was present."),
        ("low", "Web shell keyword", r"(?i)\b(?:webshell|cmd\.aspx|shell\.php|wso\.php)\b[^\r\n]{0,160}", "Possible web shell naming or description was present."),
    ]
    findings: list[SuspiciousFinding] = []
    seen: set[tuple[str, str]] = set()
    for severity, category, pattern, reason in patterns:
        for match in re.finditer(pattern, text):
            evidence = match.group(0).strip()
            key = (category, evidence.lower())
            if key in seen:
                continue
            seen.add(key)
            findings.append(SuspiciousFinding(severity=severity, category=category, evidence=evidence[:500], reason=reason))
            if len(findings) >= 80:
                return findings
    return findings


def _build_log_pcap_prompt(text: str, observables: list[LogObservable], suspicious: list[SuspiciousFinding]) -> str:
    observable_lines = "\n".join(f"- {item.type}: {item.value}" for item in observables[:120])
    finding_lines = "\n".join(f"- {item.severity} {item.category}: {item.evidence}" for item in suspicious[:50])
    return (
        "Log/PCAP security analysis input. Diagnose suspicious or malicious activity, map behaviors to MITRE ATT&CK, "
        "and use the supplied extracted observables as evidence when relevant.\n\n"
        f"{TAXONOMY_SYSTEM_INSTRUCTIONS}\n\n"
        f"Extracted observables:\n{observable_lines or 'none'}\n\n"
        f"Heuristic suspicious findings:\n{finding_lines or 'none'}\n\n"
        "--- BEGIN LOG/PCAP TEXT ---\n"
        f"{text[:35_000]}\n"
        "--- END LOG/PCAP TEXT ---"
    )


def _build_log_pcap_report(
    filename: str | None,
    result: ExtractionResult,
    observables: list[LogObservable],
    suspicious: list[SuspiciousFinding],
    apt_matches: list[AptMatch],
) -> str:
    lines = [
        "# AdversaryGraph Log / PCAP Analysis Report",
        "",
        f"Source: {filename or 'pasted text'}",
        f"Generated: {datetime.now(timezone.utc).isoformat()}Z",
        "",
        "## Executive Summary",
        "",
        result.summary or "No AI summary was returned.",
        "",
        "## Suspicious / Malicious Activity",
        "",
    ]
    if suspicious:
        lines.extend(f"- **{item.severity.upper()}** {item.category}: {item.reason}\n  Evidence: `{item.evidence}`" for item in suspicious[:30])
    else:
        lines.append("- No suspicious heuristic hits were identified. Review extracted observables and raw evidence manually.")
    lines.extend(["", "## ATT&CK TTPs", ""])
    if result.techniques:
        lines.extend(f"- {item.attack_id} {item.name} ({item.tactic}) confidence={item.confidence:.2f}: {item.evidence}" for item in result.techniques)
    else:
        lines.append("- No ATT&CK mappings were returned by the selected AI provider.")
    lines.extend(["", "## Possible IOCs for Enrichment", ""])
    if observables:
        lines.extend(f"- {item.type}: {item.value} ({item.confidence})" for item in observables[:120])
    else:
        lines.append("- No IOC candidates extracted.")
    lines.extend(["", "## Possible Actor Overlap", ""])
    if apt_matches:
        lines.extend(f"- {item.group_name} ({item.group_attack_id}): {round(item.similarity * 100)}% overlap, {item.shared_count} shared TTPs" for item in apt_matches[:10])
    else:
        lines.append("- No actor overlap calculated.")
    lines.extend(["", "## Analyst Notes", "", "- Treat this as triage output. Validate every IOC and TTP against original telemetry before escalation."])
    return "\n".join(lines)


def _get_adapter(provider: str, model: str | None):
    if provider not in ALLOWED_PROVIDERS:
        raise HTTPException(400, f"provider must be one of {sorted(ALLOWED_PROVIDERS)}")
    if model is not None and not _MODEL_RE.match(model):
        raise HTTPException(400, "Invalid model name")
    try:
        return get_adapter(provider, model)
    except ValueError as exc:
        logger.warning("AI adapter configuration rejected (%s)", type(exc).__name__)
        raise HTTPException(400, "AI provider configuration is invalid") from exc


async def _validate_technique_ids(
    result: ExtractionResult,
    domain: str,
    session: AsyncSession,
) -> None:
    """Mark techniques whose ATT&CK IDs don't exist in the local DB as unverified."""
    if not result.techniques:
        return

    ver_row = await session.execute(
        select(AttackVersion.id).where(
            AttackVersion.domain == domain,
            AttackVersion.is_latest.is_(True),
        )
    )
    ver_id = ver_row.scalar_one_or_none()
    if not ver_id:
        return

    rows = await session.execute(
        select(Technique.attack_id).where(Technique.version_id == ver_id)
    )
    known_ids = {row[0].upper() for row in rows}

    for tech in result.techniques:
        tech.llm_verified = tech.attack_id.upper() in known_ids
        if not tech.llm_verified:
            logger.warning(
                "LLM returned unrecognised ATT&CK ID %r for domain %s — flagging as unverified",
                tech.attack_id,
                domain,
            )


async def _rank_apt_groups(
    result: ExtractionResult,
    domain: str,
    session: AsyncSession,
    top_n: int = 10,
) -> list[AptMatch]:
    """Jaccard-rank all ATT&CK group profiles against the extracted techniques."""
    if not result.techniques:
        return []

    user_ids = {t.attack_id for t in result.techniques}

    ver_row = await session.execute(
        select(AttackVersion.id).where(
            AttackVersion.domain == domain,
            AttackVersion.is_latest.is_(True),
        )
    )
    ver_id = ver_row.scalar_one_or_none()
    if not ver_id:
        return []

    rows = await session.execute(
        select(AptGroup.attack_id, AptGroup.name, Technique.attack_id)
        .join(AptGroupTechnique, AptGroupTechnique.group_id == AptGroup.id)
        .join(Technique, Technique.id == AptGroupTechnique.technique_id)
        .where(AptGroup.version_id == ver_id)
    )

    group_techs: dict[str, dict] = {}
    for g_id, g_name, t_id in rows:
        if g_id not in group_techs:
            group_techs[g_id] = {"name": g_name, "techs": set()}
        group_techs[g_id]["techs"].add(t_id)

    results = []
    for g_id, info in group_techs.items():
        shared = user_ids & info["techs"]
        union = user_ids | info["techs"]
        if not union:
            continue
        jaccard = len(shared) / len(union)
        results.append(AptMatch(
            group_attack_id=g_id,
            group_name=info["name"],
            similarity=round(jaccard, 4),
            shared_count=len(shared),
            shared_techniques=sorted(shared),
        ))

    results.sort(key=lambda r: r.similarity, reverse=True)
    return results[:top_n]


async def _store_result(
    db_session: AnalysisSession,
    result: ExtractionResult,
    apt_matches: list[AptMatch],
    session: AsyncSession,
) -> None:
    db_session.status = "completed"

    res = AnalysisResult(
        session_id=db_session.id,
        extracted_techniques=[technique_to_record(t) for t in result.techniques],
        apt_matches=[m.model_dump() for m in apt_matches],
        summary=result.summary,
        raw_response=result.raw_response[:10_000],
    )
    session.add(res)


def _sse(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


def _build_out(
    session_id: str,
    provider: str,
    model: str,
    result: ExtractionResult,
    apt_matches: list[AptMatch],
) -> AnalysisOut:
    return AnalysisOut(
        session_id=session_id,
        provider=provider,
        model=model,
        summary=result.summary,
        techniques=[
            TechniqueHit(
                attack_id=t.attack_id,
                name=t.name,
                tactic=t.tactic,
                confidence=t.confidence,
                evidence=t.evidence,
                review_status=t.review_status,
                evidence_start=t.evidence_start,
                evidence_end=t.evidence_end,
                evidence_source=t.evidence_source,
            )
            for t in result.techniques
        ],
        apt_matches=apt_matches,
        apt_hints=result.apt_hints,
        raw_response=result.raw_response[:10_000],
    )


def update_extracted_technique_review(
    techniques: list[dict],
    attack_id: str,
    *,
    review_status: str,
    evidence: str | None = None,
    review_note: str | None = None,
    reviewer: str | None = None,
) -> dict | None:
    """Update a stored JSONB technique record with analyst review metadata."""
    normalized_id = attack_id.upper()
    for technique in techniques:
        if str(technique.get("attack_id", "")).upper() != normalized_id:
            continue

        technique["review_status"] = review_status
        if evidence is not None:
            technique["evidence"] = evidence
            technique["evidence_source"] = "analyst"
            technique["evidence_start"] = None
            technique["evidence_end"] = None
        if review_note is not None:
            technique["review_note"] = review_note
        if reviewer is not None:
            technique["reviewer"] = reviewer
        return technique
    return None
