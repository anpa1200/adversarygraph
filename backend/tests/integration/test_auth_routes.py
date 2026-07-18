import pytest
from httpx import AsyncClient
from uuid import UUID

from app.core.config import settings
from app.models.auth import UserAccount
from app.services.auth import TeamUser, current_user, permissions_for
from tests import conftest


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


@pytest.mark.asyncio
async def test_proxy_identity_headers_are_rejected_without_configured_secret(client: AsyncClient, monkeypatch):
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "proxy_secret", "")

    response = await client.get(
        "/api/attack/versions",
        headers={"X-Auth-User": "forged-admin", "X-Auth-Roles": "admin"},
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_proxy_identity_requires_matching_secret(client: AsyncClient, monkeypatch):
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "proxy_secret", "configured-proxy-secret")
    identity_headers = {"X-Auth-User": "proxy-admin", "X-Auth-Roles": "admin"}

    wrong = await client.get(
        "/api/attack/versions",
        headers={**identity_headers, "X-Internal-Proxy-Secret": "wrong"},
    )
    accepted = await client.get(
        "/api/attack/versions",
        headers={**identity_headers, "X-Internal-Proxy-Secret": "configured-proxy-secret"},
    )

    assert wrong.status_code == 401
    assert accepted.status_code == 200


@pytest.mark.asyncio
async def test_disabled_mfa_blocks_enrollment_but_not_existing_login_enforcement(
    client: AsyncClient,
    monkeypatch,
):
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "auth_mfa_enabled", False)
    monkeypatch.setattr(settings, "auth_bootstrap_admin_username", "mfa-admin")
    monkeypatch.setattr(settings, "auth_bootstrap_admin_password", "correct-horse-battery")

    policy = (await client.get("/api/auth/status")).json()["password_policy"]
    assert policy["mfa_available"] is False
    assert policy["mfa_required"] is False

    login = await client.post(
        "/api/auth/login",
        json={"username": "mfa-admin", "password": "correct-horse-battery"},
    )
    assert login.status_code == 200
    headers = {"Authorization": f"Bearer {login.json()['token']}"}
    assert (await client.post("/api/auth/mfa/setup", headers=headers)).status_code == 403
    assert (
        await client.post("/api/auth/mfa/confirm", headers=headers, json={"code": "123456"})
    ).status_code == 403

    user = next(
        obj
        for (model, _), obj in conftest._mock_session._objects.items()
        if model is UserAccount
    )
    user.mfa_enabled = True
    user.mfa_secret = "JBSWY3DPEHPK3PXP"
    without_code = await client.post(
        "/api/auth/login",
        json={"username": "mfa-admin", "password": "correct-horse-battery"},
    )
    assert without_code.status_code == 401
    assert without_code.json()["detail"] == "Invalid MFA code"


@pytest.mark.asyncio
async def test_user_lifecycle_and_auth_control_permissions_are_separate(
    app,
    client: AsyncClient,
    monkeypatch,
):
    async def security_admin():
        return TeamUser(
            name="security-admin",
            roles=["security_admin", "analyst", "viewer"],
            permissions=permissions_for("security_admin"),
        )

    async def user_manager():
        return TeamUser(
            name="user-manager",
            roles=["viewer"],
            permissions=["read", "manage_users"],
        )

    target = UUID("11111111-1111-4111-8111-111111111111")
    previous = app.dependency_overrides.get(current_user)
    monkeypatch.setattr(settings, "auth_enabled", True)
    try:
        app.dependency_overrides[current_user] = security_admin
        assert (await client.get("/api/auth/users")).status_code == 200
        assert (
            await client.post(
                "/api/auth/users",
                json={
                    "username": "blocked-user",
                    "password": "blocked-user-password",
                    "role": "viewer",
                },
            )
        ).status_code == 403
        assert (await client.patch(f"/api/auth/users/{target}", json={})).status_code == 403
        assert (
            await client.post(
                f"/api/auth/users/{target}/password",
                json={"password": "replacement-password"},
            )
        ).status_code == 403
        assert (await client.delete(f"/api/auth/users/{target}")).status_code == 403
        assert (
            await client.post(f"/api/auth/users/{target}/sessions/revoke")
        ).status_code == 404

        # Session inventory and MFA reset remain manage_auth controls.
        assert (await client.get("/api/auth/sessions")).status_code == 200
        assert (await client.post(f"/api/auth/users/{target}/mfa/disable")).status_code == 404

        app.dependency_overrides[current_user] = user_manager
        assert (await client.get("/api/auth/users")).status_code == 200
        assert (await client.get("/api/auth/sessions")).status_code == 403
        assert (
            await client.post(f"/api/auth/users/{target}/sessions/revoke")
        ).status_code == 403
        assert (await client.post(f"/api/auth/users/{target}/mfa/disable")).status_code == 403
    finally:
        if previous is None:
            app.dependency_overrides.pop(current_user, None)
        else:
            app.dependency_overrides[current_user] = previous


@pytest.mark.asyncio
async def test_delegated_user_manager_cannot_escalate_or_take_over_privileged_users(
    app,
    client: AsyncClient,
    monkeypatch,
):
    manager_id = UUID("21111111-1111-4111-8111-111111111111")
    admin_id = UUID("22222222-2222-4222-8222-222222222222")
    analyst_id = UUID("23333333-3333-4333-8333-333333333333")
    manager = UserAccount(
        id=manager_id,
        username="delegated-manager",
        password_hash="unused",
        role="viewer",
        permissions=["manage_users"],
        enabled=True,
    )
    admin = UserAccount(
        id=admin_id,
        username="protected-admin",
        password_hash="unused",
        role="admin",
        permissions=[],
        enabled=True,
        mfa_enabled=True,
    )
    analyst = UserAccount(
        id=analyst_id,
        username="protected-analyst",
        password_hash="unused",
        role="analyst",
        permissions=[],
        enabled=True,
    )
    conftest._mock_session.add(manager)
    conftest._mock_session.add(admin)
    conftest._mock_session.add(analyst)

    async def delegated_manager():
        return TeamUser(
            name=manager.username,
            roles=["viewer"],
            user_id=str(manager.id),
            permissions=["read", "manage_users"],
        )

    async def security_admin():
        return TeamUser(
            name="security-admin",
            roles=["security_admin", "analyst", "viewer"],
            permissions=permissions_for("security_admin"),
        )

    previous = app.dependency_overrides.get(current_user)
    monkeypatch.setattr(settings, "auth_enabled", True)
    try:
        app.dependency_overrides[current_user] = delegated_manager

        allowed = await client.post(
            "/api/auth/users",
            json={
                "username": "managed-viewer",
                "password": "managed-viewer-password",
                "role": "viewer",
            },
        )
        assert allowed.status_code == 201
        managed_viewer_id = allowed.json()["id"]

        overgrant = await client.post(
            "/api/auth/users",
            json={
                "username": "forbidden-analyst",
                "password": "forbidden-analyst-password",
                "role": "analyst",
            },
        )
        assert overgrant.status_code == 403

        admin_grant = await client.post(
            "/api/auth/users",
            json={
                "username": "forbidden-admin",
                "password": "forbidden-admin-password",
                "role": "admin",
            },
        )
        assert admin_grant.status_code == 403

        auth_grant = await client.patch(
            f"/api/auth/users/{managed_viewer_id}",
            json={"permissions": ["manage_auth"]},
        )
        assert auth_grant.status_code == 403
        assert "manage_auth" in auth_grant.json()["detail"]

        self_escalation = await client.patch(
            f"/api/auth/users/{manager.id}",
            json={"permissions": ["manage_users", "manage_auth"]},
        )
        assert self_escalation.status_code == 403
        assert "own role or explicit permissions" in self_escalation.json()["detail"]

        assert (
            await client.post(
                f"/api/auth/users/{admin.id}/password",
                json={"password": "replacement-admin-password"},
            )
        ).status_code == 403
        assert (
            await client.post(
                f"/api/auth/users/{analyst.id}/password",
                json={"password": "replacement-analyst-password"},
            )
        ).status_code == 403
        assert (
            await client.post(
                f"/api/auth/users/{managed_viewer_id}/password",
                json={"password": "replacement-viewer-password"},
            )
        ).status_code == 200

        # Authentication administrators retain their normal session/MFA remit,
        # but only an administrator may apply those mutations to an admin account.
        app.dependency_overrides[current_user] = security_admin
        assert (
            await client.post(f"/api/auth/users/{admin.id}/sessions/revoke")
        ).status_code == 403
        assert (
            await client.post(f"/api/auth/users/{admin.id}/mfa/disable")
        ).status_code == 403
    finally:
        if previous is None:
            app.dependency_overrides.pop(current_user, None)
        else:
            app.dependency_overrides[current_user] = previous


@pytest.mark.asyncio
async def test_admin_can_delegate_admin_and_manage_privileged_accounts(
    app,
    client: AsyncClient,
    monkeypatch,
):
    admin_id = UUID("31111111-1111-4111-8111-111111111111")
    admin = UserAccount(
        id=admin_id,
        username="primary-admin",
        password_hash="unused",
        role="admin",
        permissions=[],
        enabled=True,
    )
    conftest._mock_session.add(admin)

    async def administrator():
        return TeamUser(
            name=admin.username,
            roles=["admin", "analyst", "viewer"],
            user_id=str(admin.id),
            permissions=permissions_for("admin"),
        )

    previous = app.dependency_overrides.get(current_user)
    monkeypatch.setattr(settings, "auth_enabled", True)
    try:
        app.dependency_overrides[current_user] = administrator
        created = await client.post(
            "/api/auth/users",
            json={
                "username": "secondary-admin",
                "password": "secondary-admin-password",
                "role": "admin",
            },
        )
        assert created.status_code == 201

        updated = await client.patch(
            f"/api/auth/users/{created.json()['id']}",
            json={"role": "security_admin", "permissions": ["manage_users"]},
        )
        assert updated.status_code == 200
        assert updated.json()["role"] == "security_admin"
        assert updated.json()["permissions"] == ["manage_users"]

        self_change = await client.patch(
            f"/api/auth/users/{admin.id}",
            json={"role": "viewer"},
        )
        assert self_change.status_code == 403
    finally:
        if previous is None:
            app.dependency_overrides.pop(current_user, None)
        else:
            app.dependency_overrides[current_user] = previous


@pytest.mark.asyncio
async def test_failed_mfa_does_not_mark_login_and_enabled_mfa_cannot_be_replaced(
    client: AsyncClient,
    monkeypatch,
):
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "auth_mfa_enabled", True)
    monkeypatch.setattr(settings, "auth_bootstrap_admin_username", "mfa-guard-admin")
    monkeypatch.setattr(settings, "auth_bootstrap_admin_password", "correct-horse-battery")

    login = await client.post(
        "/api/auth/login",
        json={"username": "mfa-guard-admin", "password": "correct-horse-battery"},
    )
    assert login.status_code == 200
    token = login.json()["token"]
    user = next(
        obj
        for (model, _), obj in conftest._mock_session._objects.items()
        if model is UserAccount
    )
    previous_login = user.last_login_at
    original_secret = "JBSWY3DPEHPK3PXP"
    user.mfa_enabled = True
    user.mfa_secret = original_secret

    failed = await client.post(
        "/api/auth/login",
        json={"username": "mfa-guard-admin", "password": "correct-horse-battery"},
    )
    assert failed.status_code == 401
    assert user.last_login_at == previous_login

    setup = await client.post(
        "/api/auth/mfa/setup",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert setup.status_code == 409
    assert user.mfa_enabled is True
    assert user.mfa_secret == original_secret


@pytest.mark.asyncio
async def test_bootstrap_admin_must_satisfy_password_policy(
    client: AsyncClient,
    monkeypatch,
):
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "auth_password_require_number", True)
    monkeypatch.setattr(settings, "auth_bootstrap_admin_username", "invalid-bootstrap")
    monkeypatch.setattr(settings, "auth_bootstrap_admin_password", "long-password-without-number")

    response = await client.post(
        "/api/auth/login",
        json={
            "username": "invalid-bootstrap",
            "password": "long-password-without-number",
        },
    )

    assert response.status_code == 422
    assert "one number" in response.json()["detail"]
    assert not any(model is UserAccount for model, _ in conftest._mock_session._objects)


@pytest.mark.asyncio
async def test_trusted_proxy_unions_roles_and_rejects_invalid_identity(
    client: AsyncClient,
    monkeypatch,
):
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "proxy_secret", "trusted-proxy-secret")
    base_headers = {
        "X-Auth-User": "proxy-analyst@example.test",
        "X-Internal-Proxy-Secret": "trusted-proxy-secret",
    }

    me = await client.get(
        "/api/auth/me",
        headers={**base_headers, "X-Auth-Roles": "viewer,security_admin"},
    )
    assert me.status_code == 200
    assert "security_admin" in me.json()["roles"]
    assert "manage_auth" in me.json()["permissions"]

    sessions = await client.get(
        "/api/auth/sessions",
        headers={**base_headers, "X-Auth-Roles": "viewer,security_admin"},
    )
    assert sessions.status_code == 200

    invalid_role = await client.get(
        "/api/auth/me",
        headers={**base_headers, "X-Auth-Roles": "viewer,unknown-idp-role"},
    )
    oversized_user = await client.get(
        "/api/auth/me",
        headers={
            **base_headers,
            "X-Auth-User": "x" * 256,
            "X-Auth-Roles": "viewer",
        },
    )
    assert invalid_role.status_code == 401
    assert oversized_user.status_code == 401


@pytest.mark.asyncio
async def test_native_usernames_are_trimmed_and_last_manager_cannot_self_demote(
    client: AsyncClient,
    monkeypatch,
):
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "auth_bootstrap_admin_username", "continuity-admin")
    monkeypatch.setattr(settings, "auth_bootstrap_admin_password", "correct-horse-battery")

    login = await client.post(
        "/api/auth/login",
        json={"username": "continuity-admin", "password": "correct-horse-battery"},
    )
    assert login.status_code == 200
    headers = {"Authorization": f"Bearer {login.json()['token']}"}

    whitespace = await client.post(
        "/api/auth/users",
        json={"username": "   ", "password": "valid-user-password", "role": "viewer"},
        headers=headers,
    )
    assert whitespace.status_code == 422

    demotion = await client.patch(
        f"/api/auth/users/{login.json()['user']['id']}",
        json={"role": "viewer", "permissions": []},
        headers=headers,
    )
    assert demotion.status_code == 403
    assert "own role or explicit permissions" in demotion.json()["detail"]
    admin = conftest._mock_session._objects[
        (UserAccount, UUID(login.json()["user"]["id"]))
    ]
    assert admin.role == "admin"
    assert admin.enabled is True
