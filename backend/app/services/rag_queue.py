"""Best-effort immediate RAG reconciliation after authoritative data commits."""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.rag import RAGIndexRun
from app.tasks.rag import acquire_rag_enqueue_lock, rag_index_run_is_stale, reconcile_rag

logger = logging.getLogger(__name__)


async def queue_rag_after_ingest(
    db: AsyncSession,
    source_types: list[str],
    *,
    created_by: str = "ingestion",
) -> dict[str, str | bool | None]:
    """Persist and dispatch a source-scoped run.

    Authoritative source writes are committed before this is called. Broker
    failure therefore cannot roll back intelligence; Celery Beat remains the
    durable retry/reconciliation path.
    """
    if not settings.rag_enabled:
        return {"status": "disabled", "queued": False, "run_id": None}
    selected = list(dict.fromkeys(source_types))
    try:
        await acquire_rag_enqueue_lock(db)
        queued = await db.scalar(
            select(RAGIndexRun)
            .where(RAGIndexRun.status == "queued")
            .order_by(RAGIndexRun.created_at.desc())
            .limit(1)
        )
        if queued is not None:
            queued.source_types = list(dict.fromkeys([*(queued.source_types or []), *selected]))
            await db.commit()
            reconcile_rag.delay(str(queued.id))
            return {
                "status": "queued",
                "queued": True,
                "run_id": str(queued.id),
            }
        running = await db.scalar(
            select(RAGIndexRun)
            .where(RAGIndexRun.status == "running")
            .order_by(RAGIndexRun.created_at.desc())
            .limit(1)
        )
        if running is not None and rag_index_run_is_stale(running):
            await db.commit()
            reconcile_rag.delay(str(running.id))
            return {"status": "running", "queued": True, "run_id": str(running.id)}
        run = RAGIndexRun(
            status="queued",
            source_types=selected,
            include_embeddings=settings.rag_embedding_enabled,
            created_by=created_by[:255],
        )
        db.add(run)
        await db.commit()
        # When another run owns the corpus lock this row is the durable
        # follow-up. The completing worker dispatches it; Celery Beat is a
        # second recovery path if that worker is lost.
        if running is None:
            reconcile_rag.delay(str(run.id))
        return {
            "status": "queued",
            "queued": True,
            "run_id": str(run.id),
            "waiting_for_active_run": running is not None,
        }
    except Exception:
        await db.rollback()
        logger.exception("Immediate RAG queueing failed; scheduled reconciliation will retry")
        return {"status": "deferred", "queued": False, "run_id": None}
