import hashlib
import hmac
import os
import secrets
import base64
import struct
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import Cookie, Depends, Header, HTTPException, Request
from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_session
from app.models.auth import AuthSession, UserAccount
from app.models.pipeline import AuditEvent

VALID_ROLES = {
    "viewer",
    "analyst",
    "admin",
    "security_admin",
    "threat_intel",
    "detection_engineer",
    "incident_responder",
    "auditor",
    "service_account",
}
SESSION_COOKIE = "ag_session"
PBKDF2_ITERATIONS = 260_000
ALL_PERMISSIONS = {
    "read",
    "run_analysis",
    "manage_intel",
    "manage_detections",
    "run_attack_simulation",
    "manage_feeds",
    "forward_siem",
    "upload_files",
    "export_data",
    "manage_users",
    "manage_auth",
    "view_audit",
}
ROLE_PERMISSIONS = {
    "viewer": {"read"},
    "auditor": {"read", "view_audit", "export_data"},
    "analyst": {"read", "run_analysis", "manage_intel", "upload_files", "export_data"},
    "threat_intel": {"read", "run_analysis", "manage_intel", "manage_feeds", "upload_files", "export_data"},
    "detection_engineer": {"read", "run_analysis", "manage_detections", "run_attack_simulation", "forward_siem", "export_data"},
    "incident_responder": {"read", "run_analysis", "manage_intel", "run_attack_simulation", "forward_siem", "upload_files", "export_data"},
    "service_account": {"read", "run_analysis", "manage_feeds", "forward_siem", "export_data"},
    "security_admin": {"read", "run_analysis", "manage_intel", "manage_detections", "run_attack_simulation", "manage_feeds", "forward_siem", "upload_files", "export_data", "manage_auth", "view_audit"},
    "admin": set(ALL_PERMISSIONS),
}


@dataclass
class TeamUser:
    name: str
    roles: list[str]
    user_id: str = ""
    auth_source: str = "local"
    permissions: list[str] | None = None


def normalize_role(role: str) -> str:
    normalized = role.strip().lower()
    if normalized not in VALID_ROLES:
        raise HTTPException(422, f"Role must be one of: {', '.join(sorted(VALID_ROLES))}")
    return normalized


def normalize_permissions(permissions: list[str] | None) -> list[str]:
    cleaned = sorted({item.strip() for item in permissions or [] if item and item.strip()})
    invalid = [item for item in cleaned if item not in ALL_PERMISSIONS]
    if invalid:
        raise HTTPException(422, f"Unknown permissions: {', '.join(invalid)}")
    return cleaned


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


_DUMMY_PASSWORD_HASH = hash_password(
    "adversarygraph-invalid-account-password",
    salt=b"\x00" * 16,
)


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
    if role == "security_admin":
        return ["security_admin", "analyst", "viewer"]
    if role in {"threat_intel", "detection_engineer", "incident_responder", "service_account"}:
        return [role, "analyst", "viewer"]
    if role == "auditor":
        return ["auditor", "viewer"]
    if role == "analyst":
        return ["analyst", "viewer"]
    return ["viewer"]


def permissions_for(role: str, extra_permissions: list[str] | None = None) -> list[str]:
    normalized = normalize_role(role)
    permissions = set(ROLE_PERMISSIONS.get(normalized, {"read"}))
    permissions.update(normalize_permissions(extra_permissions))
    return sorted(permissions)


def account_has_permission(user: UserAccount, permission: str) -> bool:
    return permission in ROLE_PERMISSIONS.get(user.role, set()) or permission in set(
        user.permissions or []
    )


def effective_account_permissions(
    role: str,
    extra_permissions: list[str] | None = None,
) -> set[str]:
    """Return the effective grant represented by one managed account."""
    return set(ROLE_PERMISSIONS.get(role, set())) | set(extra_permissions or [])


def effective_team_permissions(user: TeamUser) -> set[str]:
    """Return a request principal's effective permissions defensively.

    ``TeamUser.permissions`` normally already contains the expanded role grant,
    but trusted-proxy identities and tests may construct the object directly.
    Including every declared role keeps the authorization ceiling fail-safe.
    """
    if "admin" in user.roles:
        return set(ALL_PERMISSIONS)
    permissions = set(user.permissions or [])
    for role in user.roles:
        permissions.update(ROLE_PERMISSIONS.get(role, set()))
    return permissions


def validate_user_grant_scope(
    actor: TeamUser,
    *,
    role: str,
    permissions: list[str],
) -> None:
    """Prevent delegated user managers from granting authority they do not own."""
    if "admin" in actor.roles:
        return
    if role == "admin":
        raise HTTPException(403, "Only an administrator can assign the admin role")

    proposed = effective_account_permissions(role, permissions)
    actor_permissions = effective_team_permissions(actor)
    if "manage_auth" in proposed and "manage_auth" not in actor_permissions:
        raise HTTPException(
            403,
            "The manage_auth permission can only be granted by a principal that has manage_auth",
        )
    if not proposed.issubset(actor_permissions):
        raise HTTPException(
            403,
            "Cannot grant a role or permission outside your own effective permissions",
        )


def validate_user_target_scope(actor: TeamUser, target: UserAccount) -> None:
    """Prevent lifecycle or authentication takeover of a more privileged user."""
    if "admin" in actor.roles:
        return
    if target.role == "admin":
        raise HTTPException(403, "Only an administrator can manage an admin account")

    target_permissions = effective_account_permissions(
        target.role,
        list(target.permissions or []),
    )
    actor_permissions = effective_team_permissions(actor)
    if "manage_auth" in target_permissions and "manage_auth" not in actor_permissions:
        raise HTTPException(
            403,
            "The target account requires manage_auth authority",
        )
    if not target_permissions.issubset(actor_permissions):
        raise HTTPException(
            403,
            "Cannot manage an account above your own effective permissions",
        )


def normalize_identity_name(
    value: str,
    *,
    max_length: int,
    status_code: int = 422,
    label: str = "Username",
) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > max_length or not normalized.isprintable():
        raise HTTPException(
            status_code,
            f"{label} must be 1-{max_length} printable characters after trimming",
        )
    return normalized


async def ensure_user_management_continuity(
    db: AsyncSession,
    target: UserAccount,
    *,
    proposed_role: str,
    proposed_permissions: list[str],
    proposed_enabled: bool,
) -> None:
    """Prevent concurrent mutations from removing the final user manager."""
    if proposed_enabled and (
        "manage_users" in ROLE_PERMISSIONS.get(proposed_role, set())
        or "manage_users" in proposed_permissions
    ):
        return

    rows = await db.execute(
        select(UserAccount)
        .where(UserAccount.enabled.is_(True))
        .order_by(UserAccount.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    enabled_users = rows.scalars().all()
    locked_target = next((user for user in enabled_users if user.id == target.id), None)
    if locked_target is None or not account_has_permission(locked_target, "manage_users"):
        return
    enabled_managers = [
        user for user in enabled_users if account_has_permission(user, "manage_users")
    ]
    if len(enabled_managers) <= 1:
        raise HTTPException(
            409,
            "At least one enabled account with user-management permission must remain",
        )


def user_to_team_user(user: UserAccount, auth_source: str = "native") -> TeamUser:
    return TeamUser(
        name=user.username,
        roles=roles_for(user.role),
        user_id=str(user.id),
        auth_source=auth_source,
        permissions=permissions_for(user.role, user.permissions),
    )


def password_policy() -> dict:
    return {
        "min_length": settings.auth_password_min_length,
        "require_upper": settings.auth_password_require_upper,
        "require_lower": settings.auth_password_require_lower,
        "require_number": settings.auth_password_require_number,
        "require_special": settings.auth_password_require_special,
        # AUTH_MFA_ENABLED is a feature/enrollment toggle. Per-user
        # ``mfa_enabled`` remains the source of truth for login enforcement.
        "mfa_available": settings.auth_mfa_enabled,
        "mfa_required": False,
    }


def validate_password_policy(password: str) -> None:
    errors: list[str] = []
    if len(password) < settings.auth_password_min_length:
        errors.append(f"at least {settings.auth_password_min_length} characters")
    if settings.auth_password_require_upper and not any(ch.isupper() for ch in password):
        errors.append("one uppercase letter")
    if settings.auth_password_require_lower and not any(ch.islower() for ch in password):
        errors.append("one lowercase letter")
    if settings.auth_password_require_number and not any(ch.isdigit() for ch in password):
        errors.append("one number")
    if settings.auth_password_require_special and not any(not ch.isalnum() for ch in password):
        errors.append("one special character")
    if errors:
        raise HTTPException(422, f"Password must contain {', '.join(errors)}")


async def user_count(db: AsyncSession) -> int:
    return int(await db.scalar(select(func.count()).select_from(UserAccount)) or 0)


async def bootstrap_admin_if_configured(db: AsyncSession) -> bool:
    if not settings.auth_enabled or not settings.auth_bootstrap_admin_password:
        return False
    if await user_count(db) > 0:
        return False
    validate_password_policy(settings.auth_bootstrap_admin_password)
    username = normalize_identity_name(
        settings.auth_bootstrap_admin_username or "admin",
        max_length=120,
        label="Bootstrap username",
    )
    db.add(UserAccount(
        username=username,
        display_name="Bootstrap Administrator",
        password_hash=hash_password(settings.auth_bootstrap_admin_password),
        role="admin",
        permissions=[],
        enabled=True,
    ))
    await db.commit()
    return True


async def authenticate_credentials(db: AsyncSession, username: str, password: str) -> UserAccount:
    try:
        normalized = normalize_identity_name(username, max_length=120)
    except HTTPException:
        normalized = ""
    row = await db.scalar(select(UserAccount).where(UserAccount.username == normalized))
    password_valid = verify_password(
        password,
        row.password_hash if row is not None else _DUMMY_PASSWORD_HASH,
    )
    if not row or not row.enabled or not password_valid:
        raise HTTPException(401, "Invalid username or password")
    return row


def new_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode("ascii").rstrip("=")


def _totp(secret: str, counter: int, digits: int = 6) -> str:
    padded = secret.upper() + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)


def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    if not secret or not code or not code.isdigit():
        return False
    counter = int(time.time() // 30)
    return any(hmac.compare_digest(_totp(secret, counter + shift), code.zfill(6)) for shift in range(-window, window + 1))


async def create_session(db: AsyncSession, user: UserAccount, request: Request) -> tuple[str, AuthSession]:
    now = datetime.now(timezone.utc)
    await cleanup_auth_sessions(db, now=now)
    token = new_session_token()
    session = AuthSession(
        user_id=user.id,
        token_hash=hash_token(token),
        user_agent=request.headers.get("user-agent", "")[:2000],
        ip_address=(request.client.host if request.client else "")[:120],
        expires_at=now + timedelta(minutes=max(15, settings.auth_session_minutes)),
    )
    db.add(session)
    await db.flush()
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
        await db.flush()


async def revoke_user_sessions(db: AsyncSession, user_id: UUID, keep_token: str = "") -> int:
    keep_hash = hash_token(keep_token) if keep_token else ""
    rows = await db.execute(select(AuthSession).where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None)))
    revoked_at = datetime.now(timezone.utc)
    count = 0
    for session in rows.scalars().all():
        if keep_hash and session.token_hash == keep_hash:
            continue
        session.revoked_at = revoked_at
        count += 1
    await db.flush()
    return count


async def cleanup_auth_sessions(
    db: AsyncSession,
    *,
    now: datetime | None = None,
    retention_days: int = 30,
    limit: int = 1000,
) -> None:
    """Delete a bounded batch of long-expired or long-revoked sessions."""
    current = now or datetime.now(timezone.utc)
    cutoff = current - timedelta(days=max(1, retention_days))
    stale_ids = (
        select(AuthSession.id)
        .where(
            or_(
                AuthSession.expires_at < cutoff,
                AuthSession.revoked_at < cutoff,
            )
        )
        .order_by(AuthSession.expires_at.asc())
        .limit(max(1, min(limit, 5000)))
    )
    await db.execute(delete(AuthSession).where(AuthSession.id.in_(stale_ids)))


async def audit_event(
    db: AsyncSession,
    actor: str,
    action: str,
    object_type: str,
    object_id: str = "",
    details: dict | None = None,
) -> None:
    db.add(AuditEvent(actor=actor, action=action, object_type=object_type, object_id=object_id, details=details or {}))


async def current_user(
    request: Request,
    db: AsyncSession = Depends(get_session),
    authorization: str | None = Header(default=None),
    ag_session: str | None = Cookie(default=None, alias=SESSION_COOKIE),
    x_auth_user: str | None = Header(default=None),
    x_auth_roles: str | None = Header(default=None),
    x_internal_proxy_secret: str | None = Header(default=None),
) -> TeamUser:
    # Proxy identity headers are authentication credentials, not hints. Trust
    # them only when the operator configured a shared secret and the proxy
    # supplied it. In particular, an empty PROXY_SECRET must never turn
    # client-controlled X-Auth-* headers into an authentication bypass.
    proxy_identity_verified = bool(
        settings.proxy_secret
        and hmac.compare_digest(x_internal_proxy_secret or "", settings.proxy_secret)
    )
    if not proxy_identity_verified:
        x_auth_user = None
        x_auth_roles = None

    if x_auth_user:
        try:
            identity = normalize_identity_name(
                x_auth_user,
                max_length=255,
                status_code=401,
                label="Trusted proxy username",
            )
            requested_roles = [
                normalize_role(role)
                for role in (x_auth_roles or settings.auth_default_role).split(",")
                if role.strip()
            ]
        except HTTPException as exc:
            raise HTTPException(401, "Invalid trusted proxy identity") from exc
        if not requested_roles:
            try:
                requested_roles = [normalize_role(settings.auth_default_role)]
            except HTTPException as exc:
                raise HTTPException(401, "Invalid trusted proxy identity") from exc
        effective_roles = sorted(
            {effective for role in requested_roles for effective in roles_for(role)}
        )
        effective_permissions = sorted(
            {
                permission
                for role in requested_roles
                for permission in permissions_for(role)
            }
        )
        return TeamUser(
            name=identity,
            roles=effective_roles,
            auth_source=settings.auth_sso_mode,
            permissions=effective_permissions,
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
        permissions=permissions_for(settings.auth_default_role),
    )


def has_permission(user: TeamUser, permission: str) -> bool:
    permissions = set(user.permissions or [])
    return "admin" in user.roles or permission in permissions


def require_permission(permission: str):
    async def dependency(user: TeamUser = Depends(current_user)) -> TeamUser:
        if settings.auth_enabled and not has_permission(user, permission):
            raise HTTPException(403, f"Permission required: {permission}")
        return user
    return dependency


def require_any_permission(*permissions: str):
    required = tuple(dict.fromkeys(permissions))
    if not required:
        raise ValueError("At least one permission is required")

    async def dependency(user: TeamUser = Depends(current_user)) -> TeamUser:
        if settings.auth_enabled and not any(
            has_permission(user, permission) for permission in required
        ):
            raise HTTPException(403, f"One permission required: {', '.join(required)}")
        return user

    return dependency


async def analyst(user: TeamUser = Depends(current_user)) -> TeamUser:
    if settings.auth_enabled and not ({"admin", "analyst"}.intersection(user.roles) or has_permission(user, "run_analysis")):
        raise HTTPException(403, "Analyst role required")
    return user


async def admin(user: TeamUser = Depends(current_user)) -> TeamUser:
    if settings.auth_enabled and not has_permission(user, "manage_auth"):
        raise HTTPException(403, "Auth administrator permission required")
    return user


async def audit(
    db: AsyncSession,
    user: TeamUser,
    action: str,
    object_type: str,
    object_id: str = "",
    details: dict | None = None,
) -> None:
    await audit_event(db, user.name, action, object_type, object_id, details)
