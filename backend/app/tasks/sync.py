"""Celery tasks for periodic MITRE ATT&CK synchronisation."""

from __future__ import annotations

import asyncio
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


@celery_app.task(name="sync.dynamic_reference_db", ignore_result=False)
def dynamic_reference_db(days: int = 7, force_attack: bool = False) -> dict:
    """
    Refresh the dynamic public CTI database.

    This updates reference/public data only: ATT&CK/ATLAS bundles, MISP Galaxy
    sector observations, ThreatFox/Malpedia/OTX/custom public IOC sources. Private
    report sessions and manually imported/custom records remain in the persistent
    external Postgres data directory.
    """
    from app.services.attck.version_checker import sync_outdated_domains

    logger.info("Dynamic reference DB sync started")
    actions = sync_outdated_domains(force=force_attack)

    async def _run_feed_sync() -> dict:
        from app.core.database import async_session_factory
        from app.services.ioc_intel import sync_all_ioc_sources
        from app.services.sector_intel import sync_misp_galaxy

        results: dict = {"sector": None, "ioc": None}
        async with async_session_factory() as session:
            try:
                results["sector"] = await sync_misp_galaxy(session)
            except Exception as exc:
                results["sector"] = {"status": "error", "error": str(exc)}
            try:
                results["ioc"] = await sync_all_ioc_sources(session, days=days, domain="enterprise-attack")
            except Exception as exc:
                results["ioc"] = {"status": "error", "error": str(exc)}
        return results

    feeds = asyncio.run(_run_feed_sync())
    logger.info("Dynamic reference DB sync done: attack=%s feeds=%s", actions, feeds)
    return {"attack": actions, **feeds}
