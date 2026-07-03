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
from datetime import datetime, timezone
from typing import Annotated, Any, AsyncIterator

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete as sql_delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.core.database import get_session
from app.models.analysis import AnalysisResult, AnalysisSession
from app.models.attack import AptGroup, AptGroupTechnique, AttackVersion, Technique
from app.models.ioc import IOCIndicator
from app.models.operations import ReportIntake
from app.services.ai.base import ExtractionResult, bind_evidence_spans, technique_to_record
from app.services.ai.factory import get_adapter
from app.services.auth import TeamUser, analyst, audit, current_user
from app.services.file_parser import extract_text
from app.services.ioc_extractor import extract_iocs_from_text

router = APIRouter(prefix="/analyze", tags=["Analysis"])
logger = logging.getLogger(__name__)

ALLOWED_PROVIDERS = {"claude", "openai", "gemini", "minimax", "local"}
MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB


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


class LinkedReportOut(BaseModel):
    session_id: str
    name: str | None
    provider: str
    model: str
    domain: str
    created_at: str
    source_text: str
    source_text_available: bool
    source_note: str = ""
    summary: str
    techniques: list[TechniqueHit]
    apt_matches: list[AptMatch]
    entities: list[LinkedReportEntity]
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
    source_text_available: bool
    summary: str


_MODEL_RE = re.compile(r'^[\w./:@-]{1,100}$')
_MAX_STORED_REPORT_TEXT = 120_000
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


class SessionListItem(BaseModel):
    session_id: str
    name: str | None
    status: str
    provider: str
    model: str
    domain: str
    filename: str | None
    created_at: str
    technique_count: int


class ChatRequest(BaseModel):
    message: str
    provider: str = "claude"
    model: str | None = Field(default=None, max_length=100)
    context: str = Field(default="", max_length=8000)
    system_prompt: str | None = Field(default=None, max_length=5000)


class TechniqueReviewUpdate(BaseModel):
    review_status: str = Field(pattern="^(suggested|accepted|rejected|needs-evidence)$")
    evidence: str | None = Field(default=None, max_length=500)
    review_note: str | None = Field(default=None, max_length=1000)
    reviewer: str | None = Field(default=None, max_length=120)


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
    user:     TeamUser = Depends(analyst),
):
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
        db_session.error = str(exc)
        await session.commit()
        logger.error("Analysis failed: %s", exc, exc_info=True)
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
    user:     TeamUser = Depends(analyst),
):
    """
    Streams SSE events:
      data: {"type":"token","content":"..."}
      data: {"type":"result","data":{...}}   ← final parsed result
      data: {"type":"error","message":"..."}
    """
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
                        db_s.error = str(store_exc)
                        await fresh.commit()
                        logger.error("Stream DB write failed: %s", store_exc, exc_info=True)
                        yield _sse({"type": "error", "message": "Operation failed. See server logs."})
                        return
                else:
                    apt_matches = []

            out = _build_out(session_id, adapter.provider, adapter.model, result, apt_matches)
            yield _sse({"type": "result", "data": out.model_dump()})

        except Exception as exc:
            logger.error("Stream failed: %s", exc, exc_info=True)
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
    user:     TeamUser = Depends(analyst),
):
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
        logger.error("Log/PCAP AI analysis failed: %s", exc, exc_info=True)
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
    user:     TeamUser = Depends(analyst),
):
    """
    Store a research/report document without LLM parsing.

    This keeps the source available in Reports / Research and the linked report
    page while making it explicit that no ATT&CK extraction has been performed.
    """
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
        source_text_available=bool(source_text.strip()),
        summary=summary,
    )


# ── List stored report sessions (DB 2) ───────────────────────────────────────
# NOTE: must be defined BEFORE GET /{session_id} to avoid route shadowing

@router.get("/sessions", response_model=list[SessionListItem])
async def list_sessions(
    db: AsyncSession = Depends(get_session),
    limit: int = 50,
    offset: int = 0,
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
            filename=sess.filename,
            created_at=sess.created_at.isoformat(),
            technique_count=technique_count,
        ))
    return items


@router.get("/sessions/collection", response_model=ReportCollectionOut)
async def report_collection(
    db: AsyncSession = Depends(get_session),
    limit: int = 100,
    offset: int = 0,
    _: TeamUser = Depends(current_user),
):
    """
    Return analyzed report/research sessions with deterministic tag buckets.

    Each item includes TTP, IOC, CVE, threat actor, sector, and infrastructure
    tags so analysts can browse the research collection without opening every
    individual linked report.
    """
    safe_limit = min(max(limit, 1), 250)
    safe_offset = max(offset, 0)
    rows = await db.execute(
        select(AnalysisSession, AnalysisResult)
        .join(AnalysisResult, AnalysisResult.session_id == AnalysisSession.id)
        .where(AnalysisSession.status == "completed")
        .order_by(AnalysisSession.created_at.desc())
        .limit(safe_limit)
        .offset(safe_offset)
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
        items.append(ReportCollectionItem(
            session_id=str(sess.id),
            title=sess.name or sess.filename or (intake.title if intake else "") or f"Analysis {str(sess.id)[:8]}",
            source_url=intake.url if intake else "",
            publisher=intake.publisher if intake else "",
            status=intake.status if intake else sess.status,
            provider=sess.llm_provider,
            model=sess.model,
            domain=sess.domain,
            created_at=sess.created_at.isoformat(),
            updated_at=sess.updated_at.isoformat() if sess.updated_at else sess.created_at.isoformat(),
            summary=res.summary,
            source_text_available=source_text_available,
            counts={key: len(value) for key, value in tags.items()},
            tags=tags,
        ))

    return ReportCollectionOut(total=safe_offset + len(items), limit=safe_limit, offset=safe_offset, items=items)


# ── Compare a stored report against MITRE actors ──────────────────────────────
# NOTE: must be defined BEFORE GET /{session_id} to avoid route shadowing

@router.post("/sessions/{session_id}/compare", response_model=list)
async def compare_session(
    session_id: str,
    top_n: int = 10,
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
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
        created_at=sess.created_at.isoformat(),
        source_text=source_text[:_MAX_STORED_REPORT_TEXT],
        source_text_available=source_text_available,
        source_note=source_note,
        summary=res.summary,
        techniques=techniques,
        apt_matches=apt_matches,
        entities=entities,
        report_intake=_report_intake_dict(intake) if intake else None,
    )


# ── Delete a stored session ───────────────────────────────────────────────────
# NOTE: must be defined BEFORE GET /{session_id} to avoid route shadowing

@router.delete("/sessions/{session_id}", status_code=204)
async def delete_session(
    session_id: str,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
):
    try:
        sid = uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(400, "Invalid session ID")

    exists = await db.execute(select(AnalysisSession.id).where(AnalysisSession.id == sid))
    if not exists.scalar_one_or_none():
        raise HTTPException(404, "Session not found")
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
    user: TeamUser = Depends(analyst),
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
async def chat(req: ChatRequest, _: TeamUser = Depends(analyst)):
    """
    Analyst asks a free-form question about ATT&CK, a technique, or a TTP set.
    Returns a streaming SSE response of plain text (not JSON).
    """
    adapter = _get_adapter(req.provider, req.model)

    system = req.system_prompt or (
        "You are a senior threat intelligence analyst with deep expertise in the MITRE ATT&CK "
        "framework. Answer the analyst's question clearly and concisely. Reference specific "
        "ATT&CK technique IDs where relevant. Be precise and actionable."
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
            logger.error("Chat stream failed: %s", exc, exc_info=True)
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
    lines = [
        sess.name or sess.filename or f"Analysis {sess.id}",
        "",
    ]
    if intake:
        lines.extend([
            f"Source URL: {intake.url or 'not provided'}",
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


def _report_intake_dict(intake: ReportIntake) -> dict[str, Any]:
    return {
        "id": str(intake.id),
        "title": intake.title,
        "url": intake.url,
        "publisher": intake.publisher,
        "status": intake.status,
        "source_reliability": intake.source_reliability,
        "actor_ids": intake.actor_ids or [],
        "technique_ids": intake.technique_ids or [],
        "indicator_count": len(intake.indicators or []),
        "created_at": intake.created_at.isoformat() if intake.created_at else "",
        "updated_at": intake.updated_at.isoformat() if intake.updated_at else "",
    }


def _report_collection_tags(
    sess: AnalysisSession,
    res: AnalysisResult,
    intake: ReportIntake | None,
    source_text: str,
    entities: list[LinkedReportEntity],
) -> dict[str, list[ReportCollectionTag]]:
    tags: dict[str, list[ReportCollectionTag]] = {
        "ttps": [],
        "iocs": [],
        "cves": [],
        "threat_actors": [],
        "sectors": [],
        "infrastructure": [],
    }
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
            for item in rows.scalars().all():
                entities.append(LinkedReportEntity(
                    type="ioc",
                    id=str(item.id),
                    label=item.value,
                    value=item.value,
                    route=f"/ioc-library/{item.id}",
                    metadata={
                        "ioc_type": item.indicator_type,
                        "confidence": item.confidence,
                        "source": item.source_id,
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
        return text.strip(), None
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
        return text.strip(), None
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
        raise HTTPException(400, str(exc)) from exc


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
