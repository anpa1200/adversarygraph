"""
POST /api/analyze          — full analysis (file or text), returns JSON result
POST /api/analyze/stream   — same but streams SSE tokens while the LLM thinks
GET  /api/analyze/{id}     — retrieve a stored result by session UUID
POST /api/analyze/chat     — single-turn LLM chat about a specific technique or selection
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from typing import Annotated, AsyncIterator

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete as sql_delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.core.database import get_session
from app.models.analysis import AnalysisResult, AnalysisSession
from app.models.attack import AptGroup, AptGroupTechnique, AttackVersion, Technique
from app.services.ai.base import ExtractionResult, bind_evidence_spans, technique_to_record
from app.services.ai.factory import get_adapter
from app.services.file_parser import extract_text

router = APIRouter(prefix="/analyze", tags=["Analysis"])
logger = logging.getLogger(__name__)

ALLOWED_PROVIDERS = {"claude", "openai", "gemini"}
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


_MODEL_RE = re.compile(r'^[\w./:@-]{1,100}$')


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


class TechniqueReviewUpdate(BaseModel):
    review_status: str = Field(pattern="^(suggested|accepted|rejected|needs-evidence)$")
    evidence: str | None = Field(default=None, max_length=500)
    review_note: str | None = Field(default=None, max_length=1000)
    reviewer: str | None = Field(default=None, max_length=120)


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
    )
    session.add(db_session)
    await session.flush()
    session_id = str(db_session.id)

    try:
        result = await adapter.extract(body)
        apt_matches = await _rank_apt_groups(result, domain, session)
        await _store_result(db_session, result, apt_matches, session)
        await session.commit()
    except Exception as exc:
        db_session.status = "failed"
        db_session.error = str(exc)
        await session.commit()
        logger.error("Analysis failed: %s", exc, exc_info=True)
        raise HTTPException(500, f"Analysis failed: {exc}") from exc

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
    )
    session.add(db_session)
    await session.flush()
    session_id = str(db_session.id)
    await session.commit()

    async def event_generator() -> AsyncIterator[str]:
        buffer = ""
        try:
            async for token in adapter.stream_extract(body):
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
                        apt_matches = await _rank_apt_groups(result, domain, fresh)
                        await _store_result(db_s, result, apt_matches, fresh)
                        await fresh.commit()
                    except Exception as store_exc:
                        db_s.status = "failed"
                        db_s.error = str(store_exc)
                        await fresh.commit()
                        logger.error("Stream DB write failed: %s", store_exc, exc_info=True)
                        yield _sse({"type": "error", "message": str(store_exc)})
                        return
                else:
                    apt_matches = []

            out = _build_out(session_id, adapter.provider, adapter.model, result, apt_matches)
            yield _sse({"type": "result", "data": out.model_dump()})

        except Exception as exc:
            logger.error("Stream failed: %s", exc, exc_info=True)
            yield _sse({"type": "error", "message": str(exc)})

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── List stored report sessions (DB 2) ───────────────────────────────────────
# NOTE: must be defined BEFORE GET /{session_id} to avoid route shadowing

@router.get("/sessions", response_model=list[SessionListItem])
async def list_sessions(
    db: AsyncSession = Depends(get_session),
    limit: int = 50,
    offset: int = 0,
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


# ── Compare a stored report against MITRE actors ──────────────────────────────
# NOTE: must be defined BEFORE GET /{session_id} to avoid route shadowing

@router.post("/sessions/{session_id}/compare", response_model=list)
async def compare_session(
    session_id: str,
    top_n: int = 10,
    db: AsyncSession = Depends(get_session),
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


# ── Delete a stored session ───────────────────────────────────────────────────
# NOTE: must be defined BEFORE GET /{session_id} to avoid route shadowing

@router.delete("/sessions/{session_id}", status_code=204)
async def delete_session(
    session_id: str,
    db: AsyncSession = Depends(get_session),
):
    try:
        sid = uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(400, "Invalid session ID")

    exists = await db.execute(select(AnalysisSession.id).where(AnalysisSession.id == sid))
    if not exists.scalar_one_or_none():
        raise HTTPException(404, "Session not found")
    await db.execute(sql_delete(AnalysisSession).where(AnalysisSession.id == sid))
    await db.commit()


# ── Review a stored technique mapping ─────────────────────────────────────────

@router.patch("/sessions/{session_id}/techniques/{attack_id}/review", response_model=TechniqueHit)
async def update_technique_review(
    session_id: str,
    attack_id: str,
    body: TechniqueReviewUpdate,
    db: AsyncSession = Depends(get_session),
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
    await db.commit()
    return TechniqueHit(**updated)


# ── Retrieve stored result ────────────────────────────────────────────────────

@router.get("/{session_id}", response_model=AnalysisOut)
async def get_result(
    session_id: str,
    db: AsyncSession = Depends(get_session),
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
    )


# ── Single-turn LLM chat ──────────────────────────────────────────────────────

@router.post("/chat")
async def chat(req: ChatRequest):
    """
    Analyst asks a free-form question about ATT&CK, a technique, or a TTP set.
    Returns a streaming SSE response of plain text (not JSON).
    """
    adapter = _get_adapter(req.provider, req.model)

    system = (
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
            yield _sse({"type": "error", "message": str(exc)})

    return StreamingResponse(
        direct_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

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


def _get_adapter(provider: str, model: str | None):
    if provider not in ALLOWED_PROVIDERS:
        raise HTTPException(400, f"provider must be one of {sorted(ALLOWED_PROVIDERS)}")
    if model is not None and not _MODEL_RE.match(model):
        raise HTTPException(400, "Invalid model name")
    try:
        return get_adapter(provider, model)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


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
