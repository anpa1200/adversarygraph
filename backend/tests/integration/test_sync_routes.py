"""Integration tests for /api/sync routes without live feeds or brokers."""

from unittest.mock import MagicMock

import pytest
from httpx import AsyncClient


def _make_domain_status(domain: str):
    s = MagicMock()
    s.domain = domain
    s.current_version = "14.1"
    s.latest_version = "14.1"
    s.needs_update = False
    s.last_ingested = "2026-01-01T00:00:00"
    return s


@pytest.fixture(autouse=True)
def _fail_if_sync_status_reaches_network(monkeypatch):
    async def unexpected_status_call():
        raise AssertionError("Sync route test attempted a real ATT&CK status lookup")

    monkeypatch.setattr(
        "app.api.routes.sync._get_attck_statuses",
        unexpected_status_call,
    )


@pytest.mark.asyncio
async def test_sync_status_returns_200(client: AsyncClient, monkeypatch):
    fake_statuses = [
        _make_domain_status("enterprise-attack"),
        _make_domain_status("mobile-attack"),
    ]
    async def fake_status_lookup():
        return fake_statuses

    monkeypatch.setattr("app.api.routes.sync._get_attck_statuses", fake_status_lookup)
    response = await client.get("/api/sync/status")
    assert response.status_code == 200
    body = response.json()
    assert "sources" in body
    assert "domains" in body
    assert isinstance(body["sources"], list)
    assert isinstance(body["domains"], list)


@pytest.mark.asyncio
async def test_sync_trigger_unknown_source_returns_400(client: AsyncClient):
    response = await client.post("/api/sync/trigger", json={"source": "nonexistent-source"})
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_sync_trigger_queues_via_isolated_celery_contract(
    client: AsyncClient,
    monkeypatch,
):
    from app.tasks import sync as sync_tasks

    calls = []

    class QueuedTask:
        id = "task-isolated-123"

    def fake_delay(*, domains, force):
        calls.append({"domains": domains, "force": force})
        return QueuedTask()

    monkeypatch.setattr(sync_tasks.check_and_sync, "delay", fake_delay)
    response = await client.post(
        "/api/sync/trigger",
        json={
            "source": "mitre-attack",
            "domains": ["enterprise-attack"],
            "force": True,
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "task_id": "task-isolated-123",
        "status": "queued",
        "source": "mitre-attack",
        "domains": ["enterprise-attack"],
        "force": True,
    }
    assert calls == [{"domains": ["enterprise-attack"], "force": True}]
