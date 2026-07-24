"""Integration tests for /api/retrohunt routes."""
from __future__ import annotations

import pytest
from httpx import AsyncClient

from app.core.config import settings
from app.services.auth import TeamUser, current_user


@pytest.mark.asyncio
async def test_retrohunt_signals_returns_list(client: AsyncClient):
    response = await client.get("/api/retrohunt/signals")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_retrohunt_signals_invalid_limit_returns_422(client: AsyncClient):
    response = await client.get("/api/retrohunt/signals", params={"limit": 9999})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_retrohunt_signals_invalid_days_returns_422(client: AsyncClient):
    response = await client.get("/api/retrohunt/signals", params={"days": 0})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_retrohunt_collection_status_requires_manage_feeds(
    app,
    client: AsyncClient,
    monkeypatch,
):
    async def read_only_user() -> TeamUser:
        return TeamUser(
            name="feed-viewer",
            roles=["viewer"],
            permissions=["read"],
            modules=["retrohunt"],
        )

    previous = app.dependency_overrides.get(current_user)
    monkeypatch.setattr(settings, "auth_enabled", True)
    app.dependency_overrides[current_user] = read_only_user
    try:
        response = await client.get("/api/retrohunt/collect/task-secret")
    finally:
        if previous is None:
            app.dependency_overrides.pop(current_user, None)
        else:
            app.dependency_overrides[current_user] = previous

    assert response.status_code == 403
    assert response.json()["detail"] == "Permission required: manage_feeds"
