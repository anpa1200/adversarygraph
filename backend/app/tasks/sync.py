"""Celery tasks for periodic MITRE ATT&CK synchronisation."""

from __future__ import annotations

import logging

from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="sync.check_and_sync", ignore_result=False)
def check_and_sync(domains: list[str] | None = None, force: bool = False) -> dict:
    """
    Check GitHub for newer ATT&CK versions and ingest any that are missing.
    Safe to run repeatedly — ingestion is fully idempotent.
    """
    from app.services.attck.version_checker import sync_outdated_domains

    logger.info("ATT&CK sync task started")
    actions = sync_outdated_domains(domains=domains, force=force)
    logger.info("ATT&CK sync task done: %s", actions)
    return {"actions": actions}


@celery_app.task(name="sync.status")
def get_sync_status() -> list[dict]:
    """Return current vs latest versions for all configured domains."""
    from app.services.attck.version_checker import get_status
    return [
        {
            "domain":          s.domain,
            "current_version": s.current_version,
            "latest_version":  s.latest_version,
            "needs_update":    s.needs_update,
            "last_ingested":   s.last_ingested,
        }
        for s in get_status()
    ]
