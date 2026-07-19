"""Celery orchestration for bounded, audited RAG retention."""

from __future__ import annotations

import asyncio

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import engine
from app.services.rag_retention import (
    RAG_CORPUS_ADVISORY_LOCK_ID,
    purge_rag_retention_batch,
)
from app.tasks.celery_app import celery_app


@celery_app.task(
    bind=True,
    name="rag.retention_purge",
    acks_late=True,
    reject_on_worker_lost=True,
    max_retries=4,
    default_retry_delay=900,
)
def purge_rag_retention(self) -> dict:
    """Purge expired derived records without racing corpus reconciliation."""

    run_id = str(self.request.id or "scheduled")[:220]

    async def run() -> dict:
        await engine.dispose()
        lock_connection = None
        lock_acquired = False
        try:
            lock_connection = await engine.connect()
            lock_acquired = bool(
                await lock_connection.scalar(
                    text("SELECT pg_try_advisory_lock(:lock_id)"),
                    {"lock_id": RAG_CORPUS_ADVISORY_LOCK_ID},
                )
            )
            await lock_connection.commit()
            if not lock_acquired:
                return {
                    "status": "deferred",
                    "reason": "corpus_reconciliation_active",
                }

            tombstones_deleted = 0
            assistance_deleted = 0
            batches = 0
            has_more = False
            legal_hold_mode = False
            async with AsyncSession(
                bind=lock_connection,
                expire_on_commit=False,
            ) as db:
                for batch_number in range(
                    1,
                    int(settings.rag_retention_max_batches) + 1,
                ):
                    result = await purge_rag_retention_batch(
                        db,
                        run_id=run_id,
                        batch_number=batch_number,
                    )
                    # Each bounded delete and its audit event share one commit.
                    # A worker loss can therefore replay safely without leaving
                    # a successful deletion unaudited.
                    await db.commit()
                    batches += 1
                    tombstones_deleted += result.tombstoned_documents_deleted
                    assistance_deleted += result.assistance_records_deleted
                    has_more = result.has_more
                    legal_hold_mode = result.legal_hold_mode
                    if not has_more:
                        break

            return {
                "status": "legal_hold" if legal_hold_mode else "completed",
                "tombstoned_documents_deleted": tombstones_deleted,
                "assistance_records_deleted": assistance_deleted,
                "batches": batches,
                "limit_reached": bool(
                    has_more and batches >= int(settings.rag_retention_max_batches)
                ),
                "tombstone_retention_days": int(
                    settings.rag_tombstone_retention_days
                ),
                "assistance_retention_days": int(
                    settings.rag_assistance_retention_days
                ),
            }
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
                        # Closing or invalidating the owning connection also
                        # releases its session-level advisory lock.
                        await lock_connection.invalidate()
                await lock_connection.close()
            await engine.dispose()

    result = asyncio.run(run())
    if result.get("status") == "deferred":
        raise self.retry(countdown=900)
    return result
