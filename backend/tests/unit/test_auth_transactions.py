from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from app.models.auth import AuthSession, UserAccount
from app.services.auth import (
    create_session,
    ensure_user_management_continuity,
    revoke_session,
    revoke_user_sessions,
)


def _db() -> MagicMock:
    db = MagicMock()
    db.execute = AsyncMock()
    db.scalar = AsyncMock()
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    return db


@pytest.mark.asyncio
async def test_auth_session_helpers_flush_without_committing_caller_transaction():
    db = _db()
    cleanup_result = MagicMock()
    session_result = MagicMock()
    session_result.scalars.return_value.all.return_value = []
    db.execute.side_effect = [cleanup_result, session_result]
    user = UserAccount(
        id=uuid4(),
        username="analyst",
        password_hash="unused",
        role="analyst",
        permissions=[],
        enabled=True,
    )
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/auth/login",
            "headers": [],
            "client": ("127.0.0.1", 12345),
        }
    )

    await create_session(db, user, request)

    db.commit.assert_not_awaited()

    auth_session = AuthSession(
        id=uuid4(),
        user_id=user.id,
        token_hash="hash",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    db.scalar.return_value = auth_session
    await revoke_session(db, "token")
    assert auth_session.revoked_at is not None

    other_session = AuthSession(
        id=uuid4(),
        user_id=user.id,
        token_hash="other-hash",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    session_result.scalars.return_value.all.return_value = [other_session]
    assert await revoke_user_sessions(db, user.id) == 1
    assert other_session.revoked_at is not None
    db.commit.assert_not_awaited()


@pytest.mark.asyncio
async def test_manager_continuity_uses_locked_database_state_not_stale_target():
    target_id = uuid4()
    stale_target = UserAccount(
        id=target_id,
        username="manager",
        password_hash="unused",
        role="viewer",
        permissions=[],
        enabled=False,
    )
    locked_target = UserAccount(
        id=target_id,
        username="manager",
        password_hash="unused",
        role="admin",
        permissions=[],
        enabled=True,
    )
    result = MagicMock()
    result.scalars.return_value.all.return_value = [locked_target]
    db = _db()
    empty_result = MagicMock()
    empty_result.scalars.return_value.all.return_value = []
    db.execute.side_effect = [result, empty_result, empty_result]

    with pytest.raises(HTTPException, match="must remain") as exc_info:
        await ensure_user_management_continuity(
            db,
            stale_target,
            proposed_role="viewer",
            proposed_permissions=[],
            proposed_enabled=False,
        )

    assert exc_info.value.status_code == 409
    assert db.execute.await_count == 3
