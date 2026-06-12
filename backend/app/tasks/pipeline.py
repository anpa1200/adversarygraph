import asyncio
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.core.database import async_session_factory, engine
from app.models.operations import ReportIntake
from app.models.pipeline import AuditEvent, CollectionRun, CollectionSource, Observable
from app.services.collection import extract_observables, fetch_rss
from app.tasks.celery_app import celery_app


@celery_app.task(name="pipeline.collect_enabled_sources")
def collect_enabled_sources():
    """Collect due RSS sources into analyst-reviewed intake."""
    async def collect():
        results = []
        # Celery sync tasks create a fresh asyncio loop per invocation. Dispose
        # pooled asyncpg connections before and after use so they never cross loops.
        await engine.dispose()
        try:
            async with async_session_factory() as db:
                rows = await db.execute(select(CollectionSource).where(CollectionSource.enabled.is_(True), CollectionSource.kind == "rss"))
                for source in rows.scalars().all():
                    now = datetime.now(timezone.utc)
                    if source.last_run_at and source.last_run_at + timedelta(minutes=source.interval_minutes) > now:
                        continue
                    run = CollectionRun(source_id=source.id)
                    db.add(run); await db.flush()
                    try:
                        entries = await fetch_rss(source.url)
                        run.items_seen = len(entries)
                        for item in entries:
                            existing = await db.execute(select(ReportIntake).where(ReportIntake.url == item["url"], ReportIntake.title == item["title"]))
                            if existing.scalar_one_or_none():
                                continue
                            indicators = extract_observables(f'{item["title"]} {item.get("summary", "")}')
                            db.add(ReportIntake(
                                title=item["title"], url=item["url"], publisher=source.name, status="pending",
                                summary=item.get("summary", ""), source_reliability="unknown", indicators=indicators,
                                analyst_notes=f"Automated intake from {source.url}. Review before promotion.",
                            ))
                            run.items_created += 1
                            for indicator in indicators:
                                found = await db.execute(select(Observable).where(Observable.type == indicator["type"], Observable.normalized_value == indicator["normalized_value"]))
                                observable = found.scalar_one_or_none()
                                if observable:
                                    observable.last_seen_at = now
                                else:
                                    db.add(Observable(**indicator, source_refs=[item["url"] or source.url]))
                                    run.observables_created += 1
                        run.status = "complete"; source.last_run_at = now
                    except Exception as exc:
                        run.status = "failed"; run.error = str(exc)[:2000]
                    run.completed_at = now
                    db.add(AuditEvent(actor="scheduler", action="source.run", object_type="collection_source", object_id=str(source.id), details={"status": run.status}))
                    results.append({"source_id": str(source.id), "status": run.status, "created": run.items_created})
                await db.commit()
            return results
        finally:
            await engine.dispose()
    return {"runs": asyncio.run(collect())}
