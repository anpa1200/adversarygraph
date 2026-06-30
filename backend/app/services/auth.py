from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import Cookie, Depends, Header, HTTPException, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_session
from app.models.auth import AuthSession, UserAccount
from app.models.pipeline import AuditEvent

VALID_ROLES = {"viewer", "analyst", "admin"}
SESSION_COOKIE = "ag_session"
PBKDF2_ITERATIONS = 260_000


@dataclass
class TeamUser:
    name: str
    roles: list[str]
    user_id: str = ""
    auth_source: str = "local"


def normalize_role(role: str) -> str:
    normalized = role.strip().lower()
    if normalized not in VALID_ROLES:
        raise HTTPException(422, f"Role must be one of: {', '.join(sorted(VALID_ROLES))}")
    return normalized


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        scheme, iterations, salt_hex, digest_hex = stored_hash.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def new_session_token() -> str:
    return secrets.token_urlsafe(48)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def roles_for(role: str) -> list[str]:
    role = normalize_role(role)
    if role == "admin":
        return ["admin", "analyst", "viewer"]
    if role == "analyst":
        return ["analyst", "viewer"]
    return ["viewer"]


def user_to_team_user(user: UserAccount, auth_source: str = "native") -> TeamUser:
    return TeamUser(
        name=user.username,
        roles=roles_for(user.role),
        user_id=str(user.id),
        auth_source=auth_source,
    )


async def user_count(db: AsyncSession) -> int:
    return int(await db.scalar(select(func.count()).select_from(UserAccount)) or 0)


async def bootstrap_admin_if_configured(db: AsyncSession) -> bool:
    if not settings.auth_enabled or not settings.auth_bootstrap_admin_password:
        return False
    if await user_count(db) > 0:
        return False
    username = settings.auth_bootstrap_admin_username.strip() or "admin"
    db.add(UserAccount(
        username=username,
        display_name="Bootstrap Administrator",
        password_hash=hash_password(settings.auth_bootstrap_admin_password),
        role="admin",
        enabled=True,
    ))
    await db.commit()
    return True


async def authenticate_credentials(db: AsyncSession, username: str, password: str) -> UserAccount:
    row = await db.scalar(select(UserAccount).where(UserAccount.username == username.strip()))
    if not row or not row.enabled or not verify_password(password, row.password_hash):
        raise HTTPException(401, "Invalid username or password")
    row.last_login_at = datetime.now(timezone.utc)
    return row


async def create_session(db: AsyncSession, user: UserAccount, request: Request) -> tuple[str, AuthSession]:
    token = new_session_token()
    session = AuthSession(
        user_id=user.id,
        token_hash=hash_token(token),
        user_agent=request.headers.get("user-agent", "")[:2000],
        ip_address=(request.client.host if request.client else "")[:120],
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=max(15, settings.auth_session_minutes)),
    )
    db.add(session)
    await db.commit()
    await db.refresh(session)
    return token, session


async def authenticate_token(db: AsyncSession, token: str) -> UserAccount | None:
    if not token:
        return None
    now = datetime.now(timezone.utc)
    session = await db.scalar(
        select(AuthSession).where(
            AuthSession.token_hash == hash_token(token),
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > now,
        )
    )
    if not session:
        return None
    user = await db.get(UserAccount, session.user_id)
    if not user or not user.enabled:
        return None
    return user


async def revoke_session(db: AsyncSession, token: str) -> None:
    if not token:
        return
    session = await db.scalar(select(AuthSession).where(AuthSession.token_hash == hash_token(token)))
    if session and not session.revoked_at:
        session.revoked_at = datetime.now(timezone.utc)
        await db.commit()


async def current_user(
    request: Request,
    db: AsyncSession = Depends(get_session),
    authorization: str | None = Header(default=None),
    ag_session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
    x_auth_user: str | None = Header(default=None),
    x_auth_roles: str | None = Header(default=None),
    x_internal_proxy_secret: str | None = Header(default=None),
) -> TeamUser:
    # If a proxy_secret is configured, verify it via constant-time comparison
    # before trusting any X-Auth-* headers. Requests with wrong/missing secret
    # are treated as anonymous unless native bearer/cookie auth succeeds.
    if settings.proxy_secret:
        provided = x_internal_proxy_secret or ""
        if not hmac.compare_digest(provided, settings.proxy_secret):
            x_auth_user = None
            x_auth_roles = None

    if x_auth_user:
        return TeamUser(
            name=x_auth_user,
            roles=[role.strip() for role in (x_auth_roles or settings.auth_default_role).split(",") if role.strip()],
            auth_source="proxy",
        )

    token = ""
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
    token = token or ag_session or ""
    user = await authenticate_token(db, token)
    if user:
        return user_to_team_user(user)

    if settings.auth_enabled:
        raise HTTPException(401, "Authentication required")
    return TeamUser(
        name="local",
        roles=roles_for(settings.auth_default_role),
        auth_source="local",
    )


async def analyst(user: TeamUser = Depends(current_user)) -> TeamUser:
    if settings.auth_enabled and not {"admin", "analyst"}.intersection(user.roles):
        raise HTTPException(403, "Analyst role required")
    return user


async def admin(user: TeamUser = Depends(current_user)) -> TeamUser:
    if settings.auth_enabled and "admin" not in user.roles:
        raise HTTPException(403, "Admin role required")
    return user


async def audit(
    db: AsyncSession,
    user: TeamUser,
    action: str,
    object_type: str,
    object_id: str = "",
    details: dict | None = None,
) -> None:
    db.add(AuditEvent(actor=user.name, action=action, object_type=object_type, object_id=object_id, details=details or {}))
