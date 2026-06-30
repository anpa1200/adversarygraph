from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_session
from app.models.auth import AuthSession, UserAccount
from app.services.auth import (
    SESSION_COOKIE,
    TeamUser,
    admin,
    authenticate_credentials,
    bootstrap_admin_if_configured,
    create_session,
    current_user,
    hash_password,
    normalize_role,
    revoke_session,
    user_count,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


class LoginBody(BaseModel):
    username: str = Field(..., min_length=1, max_length=120)
    password: str = Field(..., min_length=1, max_length=500)


class UserCreateBody(BaseModel):
    username: str = Field(..., min_length=1, max_length=120)
    password: str = Field(..., min_length=10, max_length=500)
    display_name: str = Field(default="", max_length=255)
    role: str = Field(default="viewer")
    enabled: bool = True


class UserUpdateBody(BaseModel):
    display_name: str | None = Field(default=None, max_length=255)
    role: str | None = None
    enabled: bool | None = None


class PasswordBody(BaseModel):
    password: str = Field(..., min_length=10, max_length=500)


def user_out(user: UserAccount) -> dict:
    return {
        "id": str(user.id),
        "username": user.username,
        "display_name": user.display_name,
        "role": user.role,
        "enabled": user.enabled,
        "last_login_at": user.last_login_at,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
    }


def set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=max(15, settings.auth_session_minutes) * 60,
        httponly=True,
        secure=False,
        samesite="lax",
        path="/",
    )


@router.get("/status")
async def status(db: AsyncSession = Depends(get_session)):
    count = await user_count(db)
    return {
        "auth_enabled": settings.auth_enabled,
        "native_login_enabled": True,
        "user_count": count,
        "bootstrap_configured": bool(settings.auth_bootstrap_admin_password),
        "bootstrap_required": settings.auth_enabled and count == 0 and not settings.auth_bootstrap_admin_password,
    }


@router.post("/login")
async def login(body: LoginBody, request: Request, response: Response, db: AsyncSession = Depends(get_session)):
    if await user_count(db) == 0:
        await bootstrap_admin_if_configured(db)
    user = await authenticate_credentials(db, body.username, body.password)
    token, session = await create_session(db, user, request)
    await db.refresh(user)
    set_session_cookie(response, token)
    return {"token": token, "expires_at": session.expires_at, "user": user_out(user)}


@router.post("/logout")
async def logout(request: Request, response: Response, db: AsyncSession = Depends(get_session)):
    authorization = request.headers.get("authorization", "")
    token = authorization.split(" ", 1)[1].strip() if authorization.lower().startswith("bearer ") else ""
    token = token or request.cookies.get(SESSION_COOKIE, "")
    await revoke_session(db, token)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"status": "ok"}


@router.get("/me")
async def me(user: TeamUser = Depends(current_user)):
    return {
        "name": user.name,
        "roles": user.roles,
        "auth_enabled": settings.auth_enabled,
        "user_id": user.user_id,
        "auth_source": user.auth_source,
    }


@router.get("/users")
async def list_users(db: AsyncSession = Depends(get_session), _: TeamUser = Depends(admin)):
    rows = await db.execute(select(UserAccount).order_by(UserAccount.created_at.asc()))
    return [user_out(row) for row in rows.scalars().all()]


@router.post("/users", status_code=201)
async def create_user(body: UserCreateBody, db: AsyncSession = Depends(get_session), _: TeamUser = Depends(admin)):
    role = normalize_role(body.role)
    existing = await db.scalar(select(UserAccount).where(UserAccount.username == body.username.strip()))
    if existing:
        raise HTTPException(409, "Username already exists")
    user = UserAccount(
        username=body.username.strip(),
        display_name=body.display_name.strip(),
        password_hash=hash_password(body.password),
        role=role,
        enabled=body.enabled,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user_out(user)


@router.patch("/users/{user_id}")
async def update_user(user_id: UUID, body: UserUpdateBody, db: AsyncSession = Depends(get_session), current: TeamUser = Depends(admin)):
    user = await db.get(UserAccount, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    if body.role is not None:
        user.role = normalize_role(body.role)
    if body.display_name is not None:
        user.display_name = body.display_name.strip()
    if body.enabled is not None:
        if not body.enabled and str(user.id) == current.user_id:
            raise HTTPException(400, "You cannot disable your own account")
        user.enabled = body.enabled
    await db.commit()
    await db.refresh(user)
    return user_out(user)


@router.post("/users/{user_id}/password")
async def set_password(user_id: UUID, body: PasswordBody, db: AsyncSession = Depends(get_session), _: TeamUser = Depends(admin)):
    user = await db.get(UserAccount, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    user.password_hash = hash_password(body.password)
    rows = await db.execute(select(AuthSession).where(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None)))
    revoked_at = datetime.now(timezone.utc)
    for session in rows.scalars().all():
        session.revoked_at = revoked_at
    await db.commit()
    return {"status": "ok"}


@router.delete("/users/{user_id}", status_code=204)
async def disable_user(user_id: UUID, db: AsyncSession = Depends(get_session), current: TeamUser = Depends(admin)):
    user = await db.get(UserAccount, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    if str(user.id) == current.user_id:
        raise HTTPException(400, "You cannot disable your own account")
    user.enabled = False
    rows = await db.execute(select(AuthSession).where(AuthSession.user_id == user.id, AuthSession.revoked_at.is_(None)))
    revoked_at = datetime.now(timezone.utc)
    for session in rows.scalars().all():
        session.revoked_at = revoked_at
    await db.commit()
    return Response(status_code=204)
