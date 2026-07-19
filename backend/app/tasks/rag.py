"""Celery orchestration for idempotent unified-corpus reconciliation."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import engine
from app.models.rag import RAGIndexRun
from app.services.rag_retention import RAG_CORPUS_ADVISORY_LOCK_ID
from app.tasks.celery_app import celery_app


_ENQUEUE_ADVISORY_LOCK_ID = 1_200_006_001
_STALE_RUN_AFTER = timedelta(hours=2)


async def acquire_rag_enqueue_lock(db: AsyncSession) -> None:
    """Serialize the short active-run check/create transaction.

    This key is deliberately different from the long-lived corpus lock so an
    API request never waits for the reconciliation itself to finish.
    """

    await db.execute(
        text("SELECT pg_advisory_xact_lock(:lock_id)"),
        {"lock_id": _ENQUEUE_ADVISORY_LOCK_ID},
    )


def rag_index_run_is_stale(
    run: RAGIndexRun,
    *,
    now: datetime | None = None,
) -> bool:
    """Return whether a persisted running row has lost its worker heartbeat."""

    if run.status != "running":
        return False
    checked_at = now or datetime.now(timezone.utc)
    last_activity = run.heartbeat_at or run.started_at or run.created_at
    if last_activity is None:
        return True
    if last_activity.tzinfo is None:
        last_activity = last_activity.replace(tzinfo=timezone.utc)
    return last_activity <= checked_at - _STALE_RUN_AFTER


@celery_app.task(
    bind=True,
    name="rag.reconcile",
    acks_late=True,
    reject_on_worker_lost=True,
    max_retries=None,
    default_retry_delay=15,
)
def reconcile_rag(self, run_id: str) -> dict:
    try:
        run_uuid = UUID(run_id)
    except (TypeError, ValueError):
        return {"run_id": str(run_id)[:100], "status": "invalid"}
    worker_task_id = str(self.request.id or "")[:100]

    async def run() -> dict:
        await engine.dispose()
        lock_connection = None
        lock_acquired = False
        try:
            # A run-row lock only serializes retries of the same run. Hold a
            # PostgreSQL session advisory lock on a dedicated connection to
            # prevent UI, scheduler, and redelivered tasks with different run
            # IDs from reconciling the shared corpus concurrently.
            lock_connection = await engine.connect()
            lock_acquired = bool(
                await lock_connection.scalar(
                    text("SELECT pg_try_advisory_lock(:lock_id)"),
                    {"lock_id": RAG_CORPUS_ADVISORY_LOCK_ID},
                )
            )
            await lock_connection.commit()
            if not lock_acquired:
                # Contention is expected when a queued run is redispatched or
                # the previous worker has committed its terminal state but has
                # not yet released the session lock. Never mutate the queued
                # row here; retry after the lock owner finishes.
                return {
                    "run_id": run_id,
                    "status": "deferred",
                    "reason": "active_run",
                }

            # Keep all corpus reads/writes on the same physical PostgreSQL
            # connection that owns the session advisory lock. If that
            # connection is lost, both the lock and the reconciliation session
            # fail together instead of allowing an unlocked worker to continue.
            async with AsyncSession(
                bind=lock_connection,
                expire_on_commit=False,
            ) as db:
                row = await db.execute(
                    select(RAGIndexRun)
                    .where(RAGIndexRun.id == run_uuid)
                    .with_for_update()
                )
                index_run = row.scalar_one_or_none()
                if index_run is None:
                    return {"run_id": run_id, "status": "missing"}
                if index_run.status in {"completed", "degraded", "failed", "skipped"}:
                    return {"run_id": run_id, "status": index_run.status}
                now = datetime.now(timezone.utc)
                # Owning the global corpus lock is the authoritative liveness
                # check. A redelivered task can have a different Celery task ID
                # after a worker loss, so a recent row heartbeat must not block
                # safe takeover once this lock has been acquired.
                index_run.status = "running"
                index_run.worker_task_id = worker_task_id
                index_run.attempt_count = int(index_run.attempt_count or 0) + 1
                index_run.started_at = now
                index_run.heartbeat_at = now
                await db.commit()

                from app.services.rag import reconcile_corpus

                try:
                    result = await reconcile_corpus(
                        db,
                        index_run,
                        source_types=list(index_run.source_types or []),
                        include_embeddings=bool(index_run.include_embeddings),
                    )
                    index_run.heartbeat_at = datetime.now(timezone.utc)
                    await db.commit()
                    return {"run_id": run_id, **result.to_dict()}
                except Exception:
                    await db.rollback()
                    fresh = await db.get(RAGIndexRun, run_uuid)
                    if fresh is not None:
                        fresh.status = "failed"
                        fresh.failure_summary = "Corpus reconciliation failed; inspect bounded worker logs"
                        fresh.completed_at = datetime.now(timezone.utc)
                        fresh.heartbeat_at = fresh.completed_at
                        await db.commit()
                    raise
        finally:
            if lock_connection is not None:
                if lock_acquired:
                    try:
                        await lock_connection.execute(
                            text("SELECT pg_advisory_unlock(:lock_id)"),
                            {"lock_id": RAG_CORPUS_ADVISORY_LOCK_ID},
                        )
                        await lock_connection.commit()
                    except Exception:
                        # Closing the dedicated connection also releases a
                        # session advisory lock; preserve the task outcome.
                        await lock_connection.invalidate()
                await lock_connection.close()
            # Celery creates a fresh event loop for each synchronous task.
            # Never carry asyncpg pooled connections into another loop.
            await engine.dispose()

    result = asyncio.run(run())
    if result.get("status") == "deferred":
        raise self.retry(countdown=15)
    return result
