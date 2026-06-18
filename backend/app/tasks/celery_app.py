from celery import Celery
from celery.schedules import crontab

from app.core.config import settings

celery_app = Celery(
    "adversarygraph",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=[
        "app.tasks.analysis",
        "app.tasks.sync",
        "app.tasks.pipeline",
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
    result_expires=86400,           # 24 h
)

# ── Periodic tasks (celery beat) ──────────────────────────────────────────────
celery_app.conf.beat_schedule = {
    # Check for new ATT&CK releases every day at 03:00 UTC
    "sync-attck-daily": {
        "task":     "sync.check_and_sync",
        "schedule": crontab(hour=3, minute=0),
        "options":  {"queue": "celery"},
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
}
