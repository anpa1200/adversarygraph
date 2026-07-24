from __future__ import annotations

import pytest
from httpx import AsyncClient

from app.core.config import settings
from app.services.auth import (
    ALL_MODULES,
    ALL_PERMISSIONS,
    DEFAULT_ACCESS_GROUPS,
    TeamUser,
    current_user,
    permissions_for,
)


def test_builtin_soc_profiles_follow_least_privilege_boundaries():
    manager = DEFAULT_ACCESS_GROUPS["soc-manager"]
    tier_one = DEFAULT_ACCESS_GROUPS["soc-tier-1"]
    platform_admin = DEFAULT_ACCESS_GROUPS["platform-administrators"]

    assert {"ioc_investigation", "reports_research"}.issubset(tier_one["modules"])
    assert "admin" not in tier_one["modules"]
    assert "feeds" not in manager["modules"]
    assert "admin" not in manager["modules"]
    assert "manage_users" not in manager["permissions"]
    assert "manage_auth" not in manager["permissions"]
    assert platform_admin["modules"] == ALL_MODULES


@pytest.mark.asyncio
async def test_group_assignment_controls_me_navigation_and_direct_api_access(
    app,
    client: AsyncClient,
    monkeypatch,
):
    async def administrator():
        return TeamUser(
            name="rbac-admin",
            roles=["admin", "analyst", "viewer"],
            permissions=permissions_for("admin"),
            modules=sorted(ALL_MODULES),
        )

    previous = app.dependency_overrides.get(current_user)
    monkeypatch.setattr(settings, "auth_enabled", True)
    try:
        app.dependency_overrides[current_user] = administrator
        created_group = await client.post(
            "/api/auth/groups",
            json={
                "slug": "triage-test",
                "name": "Triage Test",
                "description": "Integration-test least-privilege profile.",
                "permissions": ["read", "run_analysis"],
                "modules": ["ioc_investigation", "reports_research"],
            },
        )
        assert created_group.status_code == 201
        group_id = created_group.json()["id"]

        created_user = await client.post(
            "/api/auth/users",
            json={
                "username": "triage-operator",
                "password": "triage-operator-password",
                "role": "viewer",
                "group_ids": [group_id],
                "enabled": True,
            },
        )
        assert created_user.status_code == 201
        assert created_user.json()["group_ids"] == [group_id]
        assert created_user.json()["effective_modules"] == [
            "ioc_investigation",
            "reports_research",
        ]

        app.dependency_overrides.pop(current_user, None)
        login = await client.post(
            "/api/auth/login",
            json={
                "username": "triage-operator",
                "password": "triage-operator-password",
            },
        )
        assert login.status_code == 200
        headers = {"Authorization": f"Bearer {login.json()['token']}"}

        me = await client.get("/api/auth/me", headers=headers)
        assert me.status_code == 200
        assert me.json()["groups"] == ["triage-test"]
        assert me.json()["modules"] == ["ioc_investigation", "reports_research"]

        allowed = await client.get("/api/ioc/investigations", headers=headers)
        assert allowed.status_code == 200
        blocked = await client.get("/api/attack/versions", headers=headers)
        assert blocked.status_code == 403
        assert "module" in blocked.json()["detail"].lower()
    finally:
        if previous is None:
            app.dependency_overrides.pop(current_user, None)
        else:
            app.dependency_overrides[current_user] = previous
        monkeypatch.setattr(settings, "auth_enabled", False)


@pytest.mark.asyncio
async def test_group_policy_cannot_remove_the_last_effective_user_manager(
    app,
    client: AsyncClient,
    monkeypatch,
):
    async def administrator():
        return TeamUser(
            name="rbac-admin",
            roles=["admin", "analyst", "viewer"],
            permissions=permissions_for("admin"),
            modules=sorted(ALL_MODULES),
        )

    previous = app.dependency_overrides.get(current_user)
    monkeypatch.setattr(settings, "auth_enabled", True)
    try:
        app.dependency_overrides[current_user] = administrator
        created_group = await client.post(
            "/api/auth/groups",
            json={
                "slug": "delegated-user-managers",
                "name": "Delegated User Managers",
                "permissions": ["manage_users", "read"],
                "modules": ["admin"],
            },
        )
        assert created_group.status_code == 201
        group_id = created_group.json()["id"]

        created_user = await client.post(
            "/api/auth/users",
            json={
                "username": "delegated-manager",
                "password": "delegated-manager-password",
                "role": "viewer",
                "group_ids": [group_id],
            },
        )
        assert created_user.status_code == 201

        removed_admin_module = await client.patch(
            f"/api/auth/groups/{group_id}",
            json={"modules": ["reports_research"]},
        )
        assert removed_admin_module.status_code == 409
        assert "must remain" in removed_admin_module.json()["detail"]
    finally:
        if previous is None:
            app.dependency_overrides.pop(current_user, None)
        else:
            app.dependency_overrides[current_user] = previous
        monkeypatch.setattr(settings, "auth_enabled", False)


@pytest.mark.asyncio
async def test_builtin_group_slug_cannot_be_shadowed(
    app,
    client: AsyncClient,
):
    async def administrator():
        return TeamUser(
            name="rbac-admin",
            roles=["admin", "analyst", "viewer"],
            permissions=permissions_for("admin"),
            modules=sorted(ALL_MODULES),
        )

    previous = app.dependency_overrides.get(current_user)
    try:
        app.dependency_overrides[current_user] = administrator
        shadowed_group = await client.post(
            "/api/auth/groups",
            json={
                "slug": "platform-administrators",
                "name": "Shadow Administrators",
                "permissions": sorted(ALL_PERMISSIONS),
                "modules": sorted(ALL_MODULES),
            },
        )
        assert shadowed_group.status_code == 409
        assert "reserved" in shadowed_group.json()["detail"]
    finally:
        if previous is None:
            app.dependency_overrides.pop(current_user, None)
        else:
            app.dependency_overrides[current_user] = previous
