"""
GET  /api/sync/status          — current DB versions vs latest GitHub
POST /api/sync/trigger         — kick off a background sync via Celery
GET  /api/sync/task/{task_id}  — Celery task status
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/sync", tags=["MITRE Sync"])


class DomainStatusOut(BaseModel):
    domain: str
    current_version: str | None
    latest_version: str | None
    needs_update: bool
    last_ingested: str | None


class SyncStatusOut(BaseModel):
    domains: list[DomainStatusOut]
    any_updates_needed: bool


class TriggerOut(BaseModel):
    task_id: str
    status: str


@router.get("/status", response_model=SyncStatusOut)
async def sync_status():
    """
    Check each configured domain: what version is in the DB vs latest on GitHub.
    The GitHub check is a lightweight API call (no download).
    """
    try:
        from app.services.attck.version_checker import get_status

        loop = asyncio.get_event_loop()
        statuses = await loop.run_in_executor(None, get_status)

        domains = [
            DomainStatusOut(
                domain=s.domain,
                current_version=s.current_version,
                latest_version=s.latest_version,
                needs_update=s.needs_update,
                last_ingested=s.last_ingested,
            )
            for s in statuses
        ]
        return SyncStatusOut(
            domains=domains,
            any_updates_needed=any(d.needs_update for d in domains),
        )
    except Exception as exc:
        raise HTTPException(500, f"Status check failed: {exc}") from exc


@router.post("/trigger", response_model=TriggerOut)
async def trigger_sync():
    """
    Submit a Celery task to download and ingest any out-of-date ATT&CK domains.
    Returns immediately; poll GET /sync/task/{task_id} for progress.
    """
    try:
        from app.tasks.sync import check_and_sync
        task = check_and_sync.delay()
        return TriggerOut(task_id=task.id, status="queued")
    except Exception as exc:
        raise HTTPException(503, f"Celery unavailable: {exc}") from exc


@router.get("/task/{task_id}")
async def task_status(task_id: str):
    """Poll a Celery task by ID."""
    try:
        from app.tasks.celery_app import celery_app
        result = celery_app.AsyncResult(task_id)
        return {
            "task_id":  task_id,
            "status":   result.status,
            "result":   result.result if result.ready() else None,
        }
    except Exception as exc:
        raise HTTPException(503, f"Celery unavailable: {exc}") from exc
