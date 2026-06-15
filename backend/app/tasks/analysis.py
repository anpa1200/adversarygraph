"""
Real Celery task for background LLM analysis.

Architecture:
  • LLM call  → asyncio.run() (creates isolated event loop per task)
  • DB writes → synchronous SQLAlchemy (psycopg2, no loop conflicts)

The streaming endpoint (/api/analyze/stream) still runs inline in the
FastAPI worker; Celery is used only for the non-streaming POST /api/analyze.
"""

from __future__ import annotations

import asyncio
import logging
import uuid

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.analysis import AnalysisResult, AnalysisSession
from app.models.attack import AptGroup, AptGroupTechnique, AttackVersion, Technique
from app.services.ai.base import ExtractionResult, technique_to_record
from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)

_sync_url = settings.database_url.replace("+asyncpg", "+psycopg2")


# ── Public task ───────────────────────────────────────────────────────────────

@celery_app.task(
    bind=True,
    name="analysis.run",
    max_retries=2,
    default_retry_delay=30,
    acks_late=True,
)
def run_analysis_task(
    self,
    session_id: str,
    text: str,
    provider: str,
    model: str | None,
    domain: str,
) -> dict:
    """
    1. Call the LLM adapter (async, isolated event loop).
    2. Compute Jaccard group-similarity ranking (sync SQL).
    3. Persist result to DB (sync SQL).
    """
    logger.info("Analysis task started: session=%s provider=%s", session_id, provider)

    try:
        # Step 1 — LLM extraction (async in isolated loop)
        result: ExtractionResult = asyncio.run(_llm_extract(text, provider, model))

        # Step 2 — group-similarity ranking + DB storage (sync)
        _persist_result(session_id, result, domain)

        logger.info(
            "Analysis task done: session=%s techniques=%d",
            session_id,
            len(result.techniques),
        )
        return {"session_id": session_id, "technique_count": len(result.techniques)}

    except Exception as exc:
        logger.error("Analysis task failed: %s", exc, exc_info=True)
        _mark_failed(session_id, str(exc))
        raise self.retry(exc=exc)


# ── Async LLM call (isolated) ─────────────────────────────────────────────────

async def _llm_extract(text: str, provider: str, model: str | None) -> ExtractionResult:
    from app.services.ai.factory import get_adapter
    adapter = get_adapter(provider, model)
    return await adapter.extract(text)


# ── Sync DB operations ────────────────────────────────────────────────────────

def _persist_result(session_id: str, result: ExtractionResult, domain: str) -> None:
    engine = create_engine(_sync_url, pool_pre_ping=True)
    with Session(engine) as session:
        sid = uuid.UUID(session_id)
        db_s = session.get(AnalysisSession, sid)
        if not db_s:
            logger.error("Session %s not found in DB", session_id)
            return

        apt_matches = _rank_apt_groups_sync(result, domain, session)

        db_s.status = "completed"
        session.add(AnalysisResult(
            session_id=sid,
            extracted_techniques=[technique_to_record(t) for t in result.techniques],
            apt_matches=[m.model_dump() if hasattr(m, "model_dump") else m for m in apt_matches],
            summary=result.summary,
            raw_response=result.raw_response[:10_000],
        ))
        session.commit()


def _rank_apt_groups_sync(
    result: ExtractionResult,
    domain: str,
    session: Session,
    top_n: int = 10,
) -> list[dict]:
    if not result.techniques:
        return []

    user_ids = {t.attack_id for t in result.techniques}

    ver_row = session.execute(
        select(AttackVersion.id).where(
            AttackVersion.domain == domain,
            AttackVersion.is_latest.is_(True),
        )
    ).scalar_one_or_none()
    if not ver_row:
        return []

    rows = session.execute(
        select(AptGroup.attack_id, AptGroup.name, Technique.attack_id)
        .join(AptGroupTechnique, AptGroupTechnique.group_id == AptGroup.id)
        .join(Technique, Technique.id == AptGroupTechnique.technique_id)
        .where(AptGroup.version_id == ver_row)
    ).all()

    group_techs: dict[str, dict] = {}
    for g_id, g_name, t_id in rows:
        if g_id not in group_techs:
            group_techs[g_id] = {"name": g_name, "techs": set()}
        group_techs[g_id]["techs"].add(t_id)

    results = []
    for g_id, info in group_techs.items():
        shared = user_ids & info["techs"]
        union  = user_ids | info["techs"]
        if not union:
            continue
        jaccard = len(shared) / len(union)
        results.append({
            "group_attack_id":   g_id,
            "group_name":        info["name"],
            "similarity":        round(jaccard, 4),
            "shared_count":      len(shared),
            "shared_techniques": sorted(shared),
        })

    results.sort(key=lambda r: r["similarity"], reverse=True)
    return results[:top_n]


def _mark_failed(session_id: str, error: str) -> None:
    try:
        engine = create_engine(_sync_url, pool_pre_ping=True)
        with Session(engine) as session:
            db_s = session.get(AnalysisSession, uuid.UUID(session_id))
            if db_s:
                db_s.status = "failed"
                db_s.error = error[:2000]
                session.commit()
    except Exception as exc:
        logger.error("Could not mark session as failed: %s", exc)
