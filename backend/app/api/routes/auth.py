from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_session
from app.models.pipeline import AuditEvent
from app.models.auth import AccessGroup, AuthSession, UserAccessGroup, UserAccount
from app.services.auth import (
    ALL_MODULES,
    ALL_PERMISSIONS,
    DEFAULT_ACCESS_GROUPS,
    MODULE_CATALOG,
    SESSION_COOKIE,
    TeamUser,
    audit_event,
    authenticate_credentials,
    bootstrap_admin_if_configured,
    create_session,
    current_user,
    effective_team_permissions,
    ensure_group_management_continuity,
    group_modules,
    group_permissions,
    hash_password,
    hash_token,
    load_user_groups,
    module_catalog_out,
    new_totp_secret,
    normalize_group_slug,
    normalize_identity_name,
    normalize_modules,
    normalize_role,
    normalize_permissions,
    password_policy,
    replace_user_groups,
    revoke_session,
    revoke_user_sessions,
    ensure_user_management_continuity,
    require_module_any_permission,
    require_module_permission,
    require_permission,
    user_count,
    user_to_team_user,
    validate_password_policy,
    validate_user_grant_scope,
    validate_user_target_scope,
    verify_totp,
    ROLE_PERMISSIONS,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])
manage_users = require_module_permission("admin", "manage_users")
manage_auth = require_module_permission("admin", "manage_auth")
manage_user_directory = require_module_any_permission("admin", "manage_users", "manage_auth")


class LoginBody(BaseModel):
    username: str = Field(..., min_length=1, max_length=120)
    password: str = Field(..., min_length=1, max_length=500)
    mfa_code: str | None = Field(default=None, max_length=12)


class UserCreateBody(BaseModel):
    username: str = Field(..., min_length=1, max_length=120)
    password: str = Field(..., min_length=10, max_length=500)
    display_name: str = Field(default="", max_length=255)
    role: str = Field(default="viewer", max_length=30)
    permissions: list[str] = Field(default_factory=list, max_length=50)
    group_ids: list[UUID] = Field(default_factory=list, max_length=50)
    enabled: bool = True


class UserUpdateBody(BaseModel):
    display_name: str | None = Field(default=None, max_length=255)
    role: str | None = Field(default=None, max_length=30)
    permissions: list[str] | None = Field(default=None, max_length=50)
    group_ids: list[UUID] | None = Field(default=None, max_length=50)
    enabled: bool | None = None


class GroupCreateBody(BaseModel):
    slug: str = Field(..., min_length=1, max_length=80)
    name: str = Field(..., min_length=1, max_length=160)
    description: str = Field(default="", max_length=2000)
    permissions: list[str] = Field(default_factory=list, max_length=50)
    modules: list[str] = Field(default_factory=list, max_length=100)
    enabled: bool = True


class GroupUpdateBody(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    description: str | None = Field(default=None, max_length=2000)
    permissions: list[str] | None = Field(default=None, max_length=50)
    modules: list[str] | None = Field(default=None, max_length=100)
    enabled: bool | None = None


class PasswordBody(BaseModel):
    password: str = Field(..., min_length=10, max_length=500)


class MfaVerifyBody(BaseModel):
    code: str = Field(..., min_length=6, max_length=12)


async def user_out(db: AsyncSession, user: UserAccount) -> dict:
    assigned_groups = await load_user_groups(db, user.id, include_disabled=True)
    principal = user_to_team_user(user, groups=assigned_groups or None)
    return {
        "id": str(user.id),
        "username": user.username,
        "display_name": user.display_name,
        "role": user.role,
        "permissions": user.permissions or [],
        "effective_permissions": principal.permissions or [],
        "effective_modules": principal.modules or [],
        "group_ids": [str(group.id) for group in assigned_groups],
        "groups": [
            {
                "id": str(group.id),
                "slug": group.slug,
                "name": group.name,
                "enabled": group.enabled,
            }
            for group in assigned_groups
        ],
        "auth_provider": user.auth_provider,
        "external_subject": user.external_subject,
        "mfa_enabled": user.mfa_enabled,
        "enabled": user.enabled,
        "last_login_at": user.last_login_at,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
    }


async def group_out(db: AsyncSession, group: AccessGroup) -> dict:
    memberships = await db.execute(
        select(UserAccessGroup).where(UserAccessGroup.group_id == group.id)
    )
    return {
        "id": str(group.id),
        "slug": group.slug,
        "name": group.name,
        "description": group.description,
        "permissions": normalize_permissions(list(group.permissions or [])),
        "modules": normalize_modules(list(group.modules or [])),
        "system": group.system,
        "enabled": group.enabled,
        "member_count": len(memberships.scalars().all()),
        "created_by": group.created_by,
        "created_at": group.created_at,
        "updated_at": group.updated_at,
    }


def validate_group_grant_scope(
    actor: TeamUser,
    *,
    permissions: list[str],
    modules: list[str],
) -> None:
    if "admin" in actor.roles:
        return
    if not set(permissions).issubset(effective_team_permissions(actor)):
        raise HTTPException(403, "Cannot grant group permissions outside your own authority")
    if not set(modules).issubset(set(actor.modules or [])):
        raise HTTPException(403, "Cannot grant group modules outside your own module access")


async def _lock_user(db: AsyncSession, user_id: UUID) -> UserAccount | None:
    """Lock one account before applying a security-sensitive mutation."""
    result = await db.execute(
        select(UserAccount)
        .where(UserAccount.id == user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    return result.scalar_one_or_none()


async def _lock_user_directory(db: AsyncSession, user_id: UUID) -> UserAccount | None:
    """Lock the directory in stable order for lifecycle/continuity changes."""
    result = await db.execute(
        select(UserAccount)
        .order_by(UserAccount.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    return next((user for user in result.scalars().all() if user.id == user_id), None)


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=max(15, settings.auth_session_minutes) * 60,
        httponly=True,
        secure=settings.secure_cookies,
        samesite="lax",
        path="/",
    )


@router.get("/status")
async def status(db: AsyncSession = Depends(get_session)):
    count = await user_count(db)
    return {
        "auth_enabled": settings.auth_enabled,
        "native_login_enabled": True,
        "sso_mode": settings.auth_sso_mode,
        "trusted_proxy_sso_enabled": bool(settings.proxy_secret),
        "user_count": count,
        "bootstrap_configured": bool(settings.auth_bootstrap_admin_password),
        "bootstrap_required": settings.auth_enabled and count == 0 and not settings.auth_bootstrap_admin_password,
        "roles": sorted(ROLE_PERMISSIONS.keys()),
        "permissions": sorted(ALL_PERMISSIONS),
        "role_permissions": {role: sorted(perms) for role, perms in ROLE_PERMISSIONS.items()},
        "module_catalog": module_catalog_out(),
        "password_policy": password_policy(),
    }


@router.post("/login")
async def login(body: LoginBody, request: Request, response: Response, db: AsyncSession = Depends(get_session)):
    if await user_count(db) == 0:
        await bootstrap_admin_if_configured(db)
    try:
        user = await authenticate_credentials(db, body.username, body.password)
    except HTTPException:
        await audit_event(
            db,
            body.username.strip() or "unknown",
            "auth.login_failed",
            "user_account",
            details={
                "ip": request.client.host if request.client else "",
                "user_agent": request.headers.get("user-agent", "")[:500],
            },
        )
        await db.commit()
        raise
    if user.mfa_enabled and not verify_totp(user.mfa_secret, body.mfa_code or ""):
        await audit_event(db, user.username, "auth.mfa_failed", "user_account", str(user.id), {"ip": request.client.host if request.client else ""})
        await db.commit()
        raise HTTPException(401, "Invalid MFA code")
    user.last_login_at = datetime.now(timezone.utc)
    token, session = await create_session(db, user, request)
    await audit_event(db, user.username, "auth.login", "auth_session", str(session.id), {"ip": session.ip_address, "mfa": user.mfa_enabled})
    await db.commit()
    await db.refresh(user)
    set_session_cookie(response, token)
    return {"token": token, "expires_at": session.expires_at, "user": await user_out(db, user)}


@router.post("/logout")
async def logout(request: Request, response: Response, db: AsyncSession = Depends(get_session)):
    authorization = request.headers.get("authorization", "")
    token = authorization.split(" ", 1)[1].strip() if authorization.lower().startswith("bearer ") else ""
    token = token or request.cookies.get(SESSION_COOKIE, "")
    session = await db.scalar(select(AuthSession).where(AuthSession.token_hash == hash_token(token))) if token else None
    await revoke_session(db, token)
    if session:
        user = await db.get(UserAccount, session.user_id)
        await audit_event(db, user.username if user else "unknown", "auth.logout", "auth_session", str(session.id))
        await db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"status": "ok"}


@router.get("/me")
async def me(user: TeamUser = Depends(current_user)):
    return {
        "name": user.name,
        "roles": user.roles,
        "permissions": user.permissions or [],
        "modules": user.modules or [],
        "groups": user.groups or [],
        "auth_enabled": settings.auth_enabled,
        "user_id": user.user_id,
        "auth_source": user.auth_source,
    }


async def _load_requested_groups(
    db: AsyncSession,
    group_ids: list[UUID],
    actor: TeamUser,
) -> list[AccessGroup]:
    requested_ids = list(dict.fromkeys(group_ids))
    if not requested_ids:
        return []
    rows = await db.execute(select(AccessGroup).where(AccessGroup.id.in_(requested_ids)))
    groups = list(rows.scalars().all())
    found = {group.id for group in groups}
    missing = [str(group_id) for group_id in requested_ids if group_id not in found]
    if missing:
        raise HTTPException(422, f"Unknown access groups: {', '.join(missing)}")
    disabled = [group.name for group in groups if not group.enabled]
    if disabled:
        raise HTTPException(422, f"Disabled access groups cannot be assigned: {', '.join(disabled)}")
    validate_group_grant_scope(
        actor,
        permissions=group_permissions(groups),
        modules=group_modules(groups),
    )
    return groups


async def _validate_target_group_scope(
    db: AsyncSession,
    actor: TeamUser,
    target: UserAccount,
) -> list[AccessGroup]:
    groups = await load_user_groups(db, target.id, include_disabled=True)
    validate_group_grant_scope(
        actor,
        permissions=group_permissions([group for group in groups if group.enabled]),
        modules=group_modules([group for group in groups if group.enabled]),
    )
    return groups


@router.get("/groups")
async def list_groups(
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(manage_user_directory),
):
    rows = await db.execute(select(AccessGroup).order_by(AccessGroup.system.desc(), AccessGroup.name.asc()))
    return [await group_out(db, group) for group in rows.scalars().all()]


@router.post("/groups", status_code=201)
async def create_group(
    body: GroupCreateBody,
    db: AsyncSession = Depends(get_session),
    current: TeamUser = Depends(manage_users),
):
    slug = normalize_group_slug(body.slug)
    if slug in DEFAULT_ACCESS_GROUPS:
        raise HTTPException(
            409,
            "Built-in SOC group slugs are reserved and created by the platform",
        )
    name = body.name.strip()
    permissions = normalize_permissions(body.permissions)
    modules = normalize_modules(body.modules)
    validate_group_grant_scope(current, permissions=permissions, modules=modules)
    existing = await db.scalar(select(AccessGroup).where(AccessGroup.slug == slug))
    if existing:
        raise HTTPException(409, "Access-group slug already exists")
    group = AccessGroup(
        slug=slug,
        name=name,
        description=body.description.strip(),
        permissions=permissions,
        modules=modules,
        system=False,
        enabled=body.enabled,
        created_by=current.name,
    )
    db.add(group)
    await db.flush()
    await audit_event(
        db,
        current.name,
        "auth.group_create",
        "access_group",
        str(group.id),
        {"slug": group.slug, "permissions": permissions, "modules": modules},
    )
    await db.commit()
    await db.refresh(group)
    return await group_out(db, group)


@router.patch("/groups/{group_id}")
async def update_group(
    group_id: UUID,
    body: GroupUpdateBody,
    db: AsyncSession = Depends(get_session),
    current: TeamUser = Depends(manage_users),
):
    group = await db.get(AccessGroup, group_id)
    if not group:
        raise HTTPException(404, "Access group not found")
    if group.system and "admin" not in current.roles:
        raise HTTPException(403, "Only an administrator can change built-in SOC groups")
    permissions = normalize_permissions(body.permissions) if body.permissions is not None else normalize_permissions(group.permissions)
    modules = normalize_modules(body.modules) if body.modules is not None else normalize_modules(group.modules)
    proposed_enabled = body.enabled if body.enabled is not None else group.enabled
    if group.slug == "platform-administrators" and (
        set(permissions) != ALL_PERMISSIONS
        or set(modules) != ALL_MODULES
        or not proposed_enabled
    ):
        raise HTTPException(
            422,
            "The Platform Administrators group must remain enabled with every module and permission",
        )
    validate_group_grant_scope(current, permissions=permissions, modules=modules)
    await ensure_group_management_continuity(
        db,
        group,
        proposed_permissions=permissions,
        proposed_modules=modules,
        proposed_enabled=proposed_enabled,
    )
    if body.name is not None:
        group.name = body.name.strip()
    if body.description is not None:
        group.description = body.description.strip()
    group.permissions = permissions
    group.modules = modules
    if body.enabled is not None:
        group.enabled = body.enabled
    await audit_event(
        db,
        current.name,
        "auth.group_update",
        "access_group",
        str(group.id),
        {"slug": group.slug, "enabled": group.enabled, "permissions": permissions, "modules": modules},
    )
    await db.commit()
    await db.refresh(group)
    return await group_out(db, group)


@router.delete("/groups/{group_id}", status_code=204)
async def delete_group(
    group_id: UUID,
    db: AsyncSession = Depends(get_session),
    current: TeamUser = Depends(manage_users),
):
    group = await db.get(AccessGroup, group_id)
    if not group:
        raise HTTPException(404, "Access group not found")
    if group.system:
        raise HTTPException(409, "Built-in SOC groups cannot be deleted; disable them instead")
    memberships = await db.execute(
        select(UserAccessGroup).where(UserAccessGroup.group_id == group.id)
    )
    if memberships.scalars().all():
        raise HTTPException(409, "Remove all users from this group before deleting it")
    await audit_event(
        db,
        current.name,
        "auth.group_delete",
        "access_group",
        str(group.id),
        {"slug": group.slug},
    )
    await db.delete(group)
    await db.commit()
    return Response(status_code=204)


@router.get("/users")
async def list_users(
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(manage_user_directory),
):
    rows = await db.execute(select(UserAccount).order_by(UserAccount.created_at.asc()))
    return [await user_out(db, row) for row in rows.scalars().all()]


@router.post("/users", status_code=201, summary="Create Native User")
async def create_user(body: UserCreateBody, db: AsyncSession = Depends(get_session), current: TeamUser = Depends(manage_users)):
    """Create a local account after password, grant-scope, and group validation.

    The caller needs the Administration module and ``manage_users``. Delegated
    user managers cannot create an account whose effective authority exceeds
    their own. Successful creation returns the persisted user and writes an
    ``auth.user_create`` audit event.
    """
    username = normalize_identity_name(body.username, max_length=120)
    role = normalize_role(body.role)
    permissions = normalize_permissions(body.permissions)
    validate_user_grant_scope(current, role=role, permissions=permissions)
    requested_groups = await _load_requested_groups(db, body.group_ids, current)
    validate_password_policy(body.password)
    existing = await db.scalar(select(UserAccount).where(UserAccount.username == username))
    if existing:
        raise HTTPException(409, "Username already exists")
    user = UserAccount(
        username=username,
        display_name=body.display_name.strip(),
        password_hash=hash_password(body.password),
        role=role,
        permissions=permissions,
        enabled=body.enabled,
    )
    db.add(user)
    await db.flush()
    await replace_user_groups(
        db,
        user.id,
        [group.id for group in requested_groups],
        assigned_by=current.name,
    )
    await audit_event(db, current.name, "auth.user_create", "user_account", str(user.id), {
        "username": user.username,
        "role": user.role,
        "enabled": user.enabled,
        "groups": [group.slug for group in requested_groups],
    })
    await db.commit()
    await db.refresh(user)
    return await user_out(db, user)


@router.patch("/users/{user_id}")
async def update_user(user_id: UUID, body: UserUpdateBody, db: AsyncSession = Depends(get_session), current: TeamUser = Depends(manage_users)):
    user = await _lock_user_directory(db, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    validate_user_target_scope(current, user)
    existing_groups = await _validate_target_group_scope(db, current, user)
    if str(user.id) == current.user_id and (
        body.role is not None or body.permissions is not None or body.group_ids is not None
    ):
        raise HTTPException(
            403,
            "You cannot change your own role or explicit permissions",
        )
    proposed_role = normalize_role(body.role) if body.role is not None else user.role
    proposed_permissions = (
        normalize_permissions(body.permissions)
        if body.permissions is not None
        else list(user.permissions or [])
    )
    proposed_enabled = body.enabled if body.enabled is not None else user.enabled
    requested_groups = (
        await _load_requested_groups(db, body.group_ids, current)
        if body.group_ids is not None
        else await load_user_groups(db, user.id, include_disabled=True)
    )
    validate_user_grant_scope(
        current,
        role=proposed_role,
        permissions=proposed_permissions,
    )
    await ensure_user_management_continuity(
        db,
        user,
        proposed_role=proposed_role,
        proposed_permissions=proposed_permissions,
        proposed_enabled=proposed_enabled,
        proposed_group_permissions=group_permissions([
            group for group in requested_groups if group.enabled
        ]),
        proposed_group_modules=(
            group_modules([group for group in requested_groups if group.enabled])
            if requested_groups
            else None
        ),
    )
    user.role = proposed_role
    user.permissions = proposed_permissions
    if body.group_ids is not None:
        await replace_user_groups(
            db,
            user.id,
            [group.id for group in requested_groups],
            assigned_by=current.name,
        )
        await audit_event(
            db,
            current.name,
            "auth.user_groups_update",
            "user_account",
            str(user.id),
            {
                "username": user.username,
                "before": sorted(group.slug for group in existing_groups),
                "after": sorted(group.slug for group in requested_groups),
            },
        )
    if body.display_name is not None:
        user.display_name = body.display_name.strip()
    if body.enabled is not None:
        if not body.enabled and str(user.id) == current.user_id:
            raise HTTPException(400, "You cannot disable your own account")
        user.enabled = body.enabled
    await audit_event(db, current.name, "auth.user_update", "user_account", str(user.id), {
        "username": user.username,
        "role": user.role,
        "enabled": user.enabled,
        "groups": [group.slug for group in requested_groups],
    })
    await db.commit()
    await db.refresh(user)
    return await user_out(db, user)


@router.post("/users/{user_id}/password")
async def set_password(user_id: UUID, body: PasswordBody, db: AsyncSession = Depends(get_session), _: TeamUser = Depends(manage_users)):
    user = await _lock_user(db, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    validate_user_target_scope(_, user)
    await _validate_target_group_scope(db, _, user)
    validate_password_policy(body.password)
    user.password_hash = hash_password(body.password)
    rows = await db.execute(select(AuthSession).where(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None)))
    revoked_at = datetime.now(timezone.utc)
    for session in rows.scalars().all():
        session.revoked_at = revoked_at
    await audit_event(db, _.name, "auth.password_reset", "user_account", str(user.id), {"username": user.username, "revoked_sessions": True})
    await db.commit()
    return {"status": "ok"}


@router.delete("/users/{user_id}", status_code=204)
async def disable_user(user_id: UUID, db: AsyncSession = Depends(get_session), current: TeamUser = Depends(manage_users)):
    user = await _lock_user_directory(db, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    validate_user_target_scope(current, user)
    current_groups = await _validate_target_group_scope(db, current, user)
    if str(user.id) == current.user_id:
        raise HTTPException(400, "You cannot disable your own account")
    await ensure_user_management_continuity(
        db,
        user,
        proposed_role=user.role,
        proposed_permissions=list(user.permissions or []),
        proposed_enabled=False,
        proposed_group_permissions=group_permissions([
            group for group in current_groups if group.enabled
        ]),
        proposed_group_modules=(
            group_modules([group for group in current_groups if group.enabled])
            if current_groups
            else None
        ),
    )
    user.enabled = False
    rows = await db.execute(select(AuthSession).where(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None)))
    revoked_at = datetime.now(timezone.utc)
    for session in rows.scalars().all():
        session.revoked_at = revoked_at
    await audit_event(db, current.name, "auth.user_disable", "user_account", str(user.id), {"username": user.username})
    await db.commit()
    return Response(status_code=204)


@router.get("/sessions")
async def list_sessions(db: AsyncSession = Depends(get_session), current: TeamUser = Depends(manage_auth)):
    rows = await db.execute(
        select(AuthSession)
        .order_by(AuthSession.created_at.desc())
        .limit(500)
    )
    now = datetime.now(timezone.utc)
    items = []
    for session in rows.scalars().all():
        user = await db.get(UserAccount, session.user_id)
        if not user:
            continue
        active = session.revoked_at is None and session.expires_at > now
        items.append({
            "id": str(session.id),
            "user_id": str(user.id),
            "username": user.username,
            "auth_provider": user.auth_provider,
            "ip_address": session.ip_address,
            "user_agent": session.user_agent,
            "expires_at": session.expires_at,
            "revoked_at": session.revoked_at,
            "created_at": session.created_at,
            "active": active,
        })
    await audit_event(db, current.name, "auth.sessions_view", "auth_session", details={"count": len(items)})
    await db.commit()
    return items


@router.post("/sessions/revoke-all")
async def revoke_all_my_sessions(request: Request, db: AsyncSession = Depends(get_session), current: TeamUser = Depends(current_user)):
    authorization = request.headers.get("authorization", "")
    token = authorization.split(" ", 1)[1].strip() if authorization.lower().startswith("bearer ") else request.cookies.get(SESSION_COOKIE, "")
    if not current.user_id:
        raise HTTPException(400, "Current user has no local session identity")
    revoked = await revoke_user_sessions(db, UUID(current.user_id), keep_token=token)
    await audit_event(db, current.name, "auth.sessions_revoke_own", "user_account", current.user_id, {"revoked": revoked})
    await db.commit()
    return {"status": "ok", "revoked": revoked}


@router.post("/users/{user_id}/sessions/revoke")
async def revoke_user_session_set(user_id: UUID, db: AsyncSession = Depends(get_session), current: TeamUser = Depends(manage_auth)):
    user = await _lock_user(db, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    validate_user_target_scope(current, user)
    await _validate_target_group_scope(db, current, user)
    revoked = await revoke_user_sessions(db, user_id)
    await audit_event(db, current.name, "auth.sessions_revoke_user", "user_account", str(user_id), {"username": user.username, "revoked": revoked})
    await db.commit()
    return {"status": "ok", "revoked": revoked}


@router.post("/mfa/setup")
async def setup_mfa(db: AsyncSession = Depends(get_session), current: TeamUser = Depends(current_user)):
    if not settings.auth_mfa_enabled:
        raise HTTPException(403, "Local MFA enrollment is disabled by the operator")
    if not current.user_id:
        raise HTTPException(400, "MFA setup requires a local user account")
    user = await db.get(UserAccount, UUID(current.user_id))
    if not user:
        raise HTTPException(404, "User not found")
    if user.mfa_enabled:
        raise HTTPException(
            409,
            "MFA is already enabled; an auth administrator must disable it before re-enrollment",
        )
    user.mfa_secret = new_totp_secret()
    user.mfa_enabled = False
    await audit_event(db, current.name, "auth.mfa_setup_start", "user_account", str(user.id))
    await db.commit()
    return {
        "secret": user.mfa_secret,
        "otpauth_url": f"otpauth://totp/AdversaryGraph:{user.username}?secret={user.mfa_secret}&issuer=AdversaryGraph",
    }


@router.post("/mfa/confirm")
async def confirm_mfa(body: MfaVerifyBody, db: AsyncSession = Depends(get_session), current: TeamUser = Depends(current_user)):
    if not settings.auth_mfa_enabled:
        raise HTTPException(403, "Local MFA enrollment is disabled by the operator")
    if not current.user_id:
        raise HTTPException(400, "MFA confirmation requires a local user account")
    user = await db.get(UserAccount, UUID(current.user_id))
    if not user or not user.mfa_secret:
        raise HTTPException(400, "MFA setup has not been started")
    if not verify_totp(user.mfa_secret, body.code):
        raise HTTPException(401, "Invalid MFA code")
    user.mfa_enabled = True
    await audit_event(db, current.name, "auth.mfa_enable", "user_account", str(user.id))
    await db.commit()
    return {"status": "ok", "mfa_enabled": True}


@router.post("/users/{user_id}/mfa/disable")
async def disable_user_mfa(user_id: UUID, db: AsyncSession = Depends(get_session), current: TeamUser = Depends(manage_auth)):
    user = await _lock_user(db, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    validate_user_target_scope(current, user)
    await _validate_target_group_scope(db, current, user)
    user.mfa_enabled = False
    user.mfa_secret = ""
    await audit_event(db, current.name, "auth.mfa_disable", "user_account", str(user.id), {"username": user.username})
    await db.commit()
    return {"status": "ok", "mfa_enabled": False}


@router.get("/audit")
async def auth_audit_events(
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(require_permission("view_audit")),
):
    rows = await db.execute(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(500))
    return [
        {
            "id": str(row.id),
            "actor": row.actor,
            "action": row.action,
            "object_type": row.object_type,
            "object_id": row.object_id,
            "details": row.details,
            "created_at": row.created_at,
        }
        for row in rows.scalars().all()
        if row.action.startswith("auth.")
    ]
