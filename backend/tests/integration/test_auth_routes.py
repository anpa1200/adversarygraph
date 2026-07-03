import pytest
from httpx import AsyncClient

from app.core.config import settings


@pytest.mark.asyncio
async def test_openapi_schema_renders_with_auth_routes(client: AsyncClient):
    response = await client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert schema["openapi"].startswith("3.")
    assert "/api/auth/login" in schema["paths"]


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
    auth_headers = {"Authorization": f"Bearer {login.json()['token']}"}

    me = await client.get("/api/auth/me", headers=auth_headers)
    assert me.status_code == 200
    assert "admin" in me.json()["roles"]
    assert "manage_auth" in me.json()["permissions"]

    create_viewer = await client.post(
        "/api/auth/users",
        json={"username": "auth-viewer", "password": "viewer-password-1", "role": "detection_engineer", "permissions": ["view_audit"], "enabled": True},
        headers=auth_headers,
    )
    assert create_viewer.status_code == 201
    viewer_id = create_viewer.json()["id"]
    assert create_viewer.json()["role"] == "detection_engineer"
    assert "view_audit" in create_viewer.json()["effective_permissions"]

    update = await client.patch(f"/api/auth/users/{viewer_id}", json={"role": "analyst", "display_name": "Analyst User", "permissions": ["export_data"]}, headers=auth_headers)
    assert update.status_code == 200
    assert update.json()["role"] == "analyst"
    assert update.json()["display_name"] == "Analyst User"
    assert update.json()["permissions"] == ["export_data"]

    reset = await client.post(f"/api/auth/users/{viewer_id}/password", json={"password": "new-viewer-password"}, headers=auth_headers)
    assert reset.status_code == 200

    sessions = await client.get("/api/auth/sessions", headers=auth_headers)
    assert sessions.status_code == 200
    assert any(item["username"] == "auth-admin" for item in sessions.json())

    revoke = await client.post(f"/api/auth/users/{viewer_id}/sessions/revoke", headers=auth_headers)
    assert revoke.status_code == 200
    assert "revoked" in revoke.json()

    audit = await client.get("/api/auth/audit", headers=auth_headers)
    assert audit.status_code == 200
    actions = {item["action"] for item in audit.json()}
    assert "auth.login" in actions
    assert "auth.user_create" in actions
    assert "auth.password_reset" in actions

    logout = await client.post("/api/auth/logout", headers=auth_headers)
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
    assert "roles" in body
    assert "permissions" in body
    assert "password_policy" in body
    assert "detection_engineer" in body["roles"]
