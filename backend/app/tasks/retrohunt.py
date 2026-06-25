"""Celery tasks for RetroHunt signal collection."""
from __future__ import annotations

import asyncio
import logging

from app.tasks.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="retrohunt.collect_all", ignore_result=False)
def collect_all(days: int = 30) -> dict:
    from app.core.database import async_session_factory
    from app.services.retrohunt_collector import run_all_collectors

    async def _run() -> list[dict]:
        async with async_session_factory() as db:
            results = await run_all_collectors(db, days=days)
            return [
                {
                    "source": r.source,
                    "inserted": r.inserted,
                    "skipped": r.skipped,
                    "errors": r.errors,
                }
                for r in results
            ]

    results = asyncio.run(_run())
    total = sum(r["inserted"] for r in results)
    logger.info("retrohunt.collect_all done total_inserted=%d", total)
    return {"results": results, "total_inserted": total}
