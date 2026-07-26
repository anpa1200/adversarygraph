import asyncio
from datetime import timedelta

from celery import Celery
from celery.schedules import crontab

from app.core.config import settings

celery_app = Celery(
    "adversarygraph",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=[
        "app.tasks.sync",
        "app.tasks.pipeline",
        "app.tasks.retrohunt",
        "app.tasks.rag",
        "app.tasks.rag_retention",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    result_expires=86400,  # 24 h
)

# ── Periodic tasks (celery beat) ──────────────────────────────────────────────
celery_app.conf.beat_schedule = {
    # Check for new ATT&CK releases every day at 03:00 UTC
    "sync-attck-daily": {
        "task": "sync.check_and_sync",
        "schedule": crontab(hour=3, minute=0),
        "options": {"queue": "celery"},
    },
    "sync-dynamic-reference-db-daily": {
        "task": "sync.dynamic_reference_db",
        "schedule": crontab(
            hour=max(0, min(23, settings.dynamic_db_sync_hour)),
            minute=max(0, min(59, settings.dynamic_db_sync_minute)),
        ),
        "args": (max(1, min(7, settings.dynamic_db_ioc_sync_days)), False),
        "options": {"queue": "celery"},
    },
    "discover-enabled-collection-sources": {
        "task": "pipeline.collect_enabled_sources",
        "schedule": crontab(minute="*/15"),
        "options": {"queue": "celery"},
    },
    # RetroHunt: collect new signals every 6 hours
    "retrohunt-collect-6h": {
        "task": "retrohunt.collect_all",
        "schedule": crontab(minute=0, hour="*/6"),
        "args": (7,),  # last 7 days window
        "options": {"queue": "celery"},
    },
    "rag-reconcile-incremental": {
        "task": "rag.queue_reconcile",
        "schedule": timedelta(minutes=settings.rag_reconcile_interval_minutes),
        "options": {"queue": "celery"},
    },
    "rag-retention-daily": {
        "task": "rag.retention_purge",
        "schedule": crontab(
            hour=settings.rag_retention_hour,
            minute=settings.rag_retention_minute,
        ),
        "options": {"queue": "celery"},
    },
}


@celery_app.task(name="rag.queue_reconcile")
def queue_rag_reconcile():
    """Create a persisted scheduled run, then enqueue the worker task."""
    if not settings.rag_enabled:
        return {"run_id": None, "status": "disabled"}

    async def create_run() -> tuple[str, str, bool, bool]:
        from app.core.database import async_session_factory, engine
        from app.models.rag import RAGIndexRun
        from app.services.rag import SUPPORTED_SOURCE_TYPES
        from app.tasks.rag import acquire_rag_enqueue_lock, rag_index_run_is_stale
        from sqlalchemy import select

        await engine.dispose()
        try:
            async with async_session_factory() as db:
                await acquire_rag_enqueue_lock(db)
                active = await db.scalar(
                    select(RAGIndexRun)
                    .where(RAGIndexRun.status.in_(("queued", "running")))
                    .order_by(RAGIndexRun.created_at.desc())
                    .limit(1)
                )
                if active is not None:
                    should_dispatch = (
                        active.status == "queued" or rag_index_run_is_stale(active)
                    )
                    # Release the transaction-scoped enqueue lock before any
                    # broker call. Publishing an existing queued/stale run is
                    # safe because the corpus worker is globally serialized.
                    await db.commit()
                    return (
                        str(active.id),
                        str(active.status),
                        False,
                        should_dispatch,
                    )
                run = RAGIndexRun(
                    status="queued",
                    source_types=list(SUPPORTED_SOURCE_TYPES),
                    include_embeddings=settings.rag_embedding_enabled,
                    created_by="scheduler",
                )
                db.add(run)
                await db.commit()
                return str(run.id), "queued", True, True
        finally:
            await engine.dispose()

    run_id, run_status, created, should_dispatch = asyncio.run(create_run())
    if not should_dispatch:
        return {
            "run_id": run_id,
            "status": run_status,
            "redispatched": False,
        }
    try:
        celery_app.send_task("rag.reconcile", args=(run_id,))
    except Exception:
        # Broker publication is not atomic with the database transaction and
        # can fail ambiguously after acceptance. Preserve the recoverable state
        # so the next API or beat pass can safely redispatch this idempotent run.
        raise
    return {
        "run_id": run_id,
        "status": run_status,
        "redispatched": not created,
    }
