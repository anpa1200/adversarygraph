from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

import pytest
from fastapi import FastAPI

import main as main_module


@pytest.mark.asyncio
async def test_lifespan_retains_and_cancels_reference_job(monkeypatch):
    started = asyncio.Event()
    stopped = asyncio.Event()

    async def create_tables() -> None:
        return None

    async def bootstrap_admin(_session) -> bool:
        return False

    async def reference_jobs() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    @asynccontextmanager
    async def session_factory():
        yield object()

    monkeypatch.setattr(main_module, "create_tables", create_tables)
    monkeypatch.setattr(main_module, "bootstrap_admin_if_configured", bootstrap_admin)
    monkeypatch.setattr(main_module, "async_session_factory", session_factory)
    monkeypatch.setattr(main_module, "_startup_reference_jobs", reference_jobs)

    test_app = FastAPI()
    async with main_module.lifespan(test_app):
        await asyncio.wait_for(started.wait(), timeout=1)
        task = test_app.state.reference_jobs_task
        assert isinstance(task, asyncio.Task)
        assert not task.done()

    await asyncio.wait_for(stopped.wait(), timeout=1)
    assert task.cancelled()
    assert test_app.state.reference_jobs_task is None
