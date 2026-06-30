import pytest
from httpx import AsyncClient

from app.core.config import settings


@pytest.mark.asyncio
async def test_native_auth_login_and_admin_user_management(client: AsyncClient, monkeypatch):
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "auth_bootstrap_admin_username", "auth-admin")
    monkeypatch.setattr(settings, "auth_bootstrap_admin_password", "correct-horse-battery")

    blocked = await client.get("/api/attack/versions")
    assert blocked.status_code == 401

    login = await client.post("/api/auth/login", json={"username": "auth-admin", "password": "correct-horse-battery"})
    assert login.status_code == 200
    assert login.json()["user"]["username"] == "auth-admin"

    me = await client.get("/api/auth/me")
    assert me.status_code == 200
    assert "admin" in me.json()["roles"]

    create_viewer = await client.post(
        "/api/auth/users",
        json={"username": "auth-viewer", "password": "viewer-password-1", "role": "viewer", "enabled": True},
    )
    assert create_viewer.status_code == 201
    viewer_id = create_viewer.json()["id"]

    update = await client.patch(f"/api/auth/users/{viewer_id}", json={"role": "analyst", "display_name": "Analyst User"})
    assert update.status_code == 200
    assert update.json()["role"] == "analyst"
    assert update.json()["display_name"] == "Analyst User"

    reset = await client.post(f"/api/auth/users/{viewer_id}/password", json={"password": "new-viewer-password"})
    assert reset.status_code == 200

    logout = await client.post("/api/auth/logout")
    assert logout.status_code == 200

    blocked_after_logout = await client.get("/api/attack/versions")
    assert blocked_after_logout.status_code == 401

    monkeypatch.setattr(settings, "auth_enabled", False)
    monkeypatch.setattr(settings, "auth_bootstrap_admin_password", "")


@pytest.mark.asyncio
async def test_auth_status_shape(client: AsyncClient):
    response = await client.get("/api/auth/status")
    assert response.status_code == 200
    body = response.json()
    assert "auth_enabled" in body
    assert "user_count" in body
    assert body["native_login_enabled"] is True
