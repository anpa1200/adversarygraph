"""Scheduled persistence of bounded Apache SkyWalking runtime topology."""

from __future__ import annotations

import asyncio

from sqlalchemy import text

from app.core.config import settings
from app.core.database import async_session_factory, engine
from app.services import rag as rag_service
from app.services import runtime_intelligence, skywalking
from app.services.rag_retention import RAG_CORPUS_ADVISORY_LOCK_ID
from app.tasks.celery_app import celery_app

_SYNC_LOCK_ID = 1_200_006_502


@celery_app.task(name="runtime_intelligence.sync_skywalking")
def sync_skywalking_runtime() -> dict:
    if not settings.skywalking_enabled:
        return {"status": "disabled"}

    async def run() -> dict:
        await engine.dispose()
        try:
            async with async_session_factory() as db:
                locked = bool(await db.scalar(
                    text("SELECT pg_try_advisory_xact_lock(:lock_id)"),
                    {"lock_id": _SYNC_LOCK_ID},
                ))
                if not locked:
                    return {"status": "deferred", "reason": "active_sync"}
                topology = await skywalking.topology(minutes=max(5, settings.skywalking_sync_interval_minutes * 2))
                persisted = await runtime_intelligence.persist_topology(
                    db,
                    topology,
                    actor="skywalking-scheduler",
                    tlp="TLP:AMBER+STRICT",
                )
                retention = await runtime_intelligence.enforce_retention(
                    db, settings.skywalking_runtime_retention_days
                )
                await db.execute(
                    text("SELECT pg_advisory_xact_lock(:lock_id)"),
                    {"lock_id": RAG_CORPUS_ADVISORY_LOCK_ID},
                )
                rag_result = await rag_service.reconcile_corpus(
                    db,
                    None,
                    source_types=["runtime_service"],
                    include_embeddings=False,
                )
                await db.commit()
                return {
                    "status": "completed",
                    **persisted,
                    "retention": retention,
                    "rag": rag_result.to_dict(),
                    "vector_refresh": (
                        "scheduled" if settings.rag_embedding_enabled else "disabled"
                    ),
                }
        finally:
            await engine.dispose()

    return asyncio.run(run())
