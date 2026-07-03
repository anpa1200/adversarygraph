"""Integration tests for /api/sync routes."""

from unittest.mock import MagicMock, patch

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


@pytest.mark.asyncio
async def test_sync_status_returns_200(client: AsyncClient):
    fake_statuses = [
        _make_domain_status("enterprise-attack"),
        _make_domain_status("mobile-attack"),
    ]
    with patch("app.services.attck.version_checker.get_status", return_value=fake_statuses):
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
    assert response.status_code in (400, 422)
