"""
Shared pytest fixtures.

Unit tests   — no database, no external services needed.
Integration  — FastAPI app with mocked lifespan (no DB startup) and mocked
               DB session (returns empty results, simulating a fresh database).
               This lets us verify API routing, validation, and error-path
               status codes without running PostgreSQL.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
import os
import operator
from uuid import uuid4
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.sql import operators as sa_operators


os.environ.setdefault("DB_PASS", "test-db-password")
os.environ.setdefault("LOG_DIR", "/tmp/adversarygraph-test-logs")

# ── DB mock: returns None / empty for every query ─────────────────────────────

class _MockScalarResult:
    """Mimics the object returned by session.execute(...)."""

    def __init__(self, value=None, rows=None):
        self._value = value
        self._rows  = rows or []

    def scalar_one_or_none(self):
        return self._value

    def scalar_one(self):
        if self._value is None:
            raise Exception("No row found")
        return self._value

    def scalars(self):
        m = MagicMock()
        m.all.return_value = self._rows
        return m

    def all(self):
        return self._rows

    def __iter__(self):
        return iter(self._rows)

    def fetchone(self):
        return self._value

    def first(self):
        return self._value


class _MockSession:
    """Async SQLAlchemy session that always returns empty results."""

    def __init__(self):
        self._objects = {}

    async def execute(self, statement=None, *args, **kwargs):
        statement_text = str(statement)
        statement_lower = statement_text.lower()
        if ("count(" in statement_lower or "count_" in statement_lower) and "user_accounts" in statement_lower:
            from app.models.auth import UserAccount
            count = sum(1 for (obj_model, _), obj in self._objects.items() if obj_model is UserAccount)
            return _MockScalarResult(value=count)
        try:
            model = statement.column_descriptions[0].get("entity")
        except (AttributeError, IndexError, TypeError):
            model = None
        if model is None:
            return _MockScalarResult()

        rows = [
            obj
            for (obj_model, _), obj in self._objects.items()
            if obj_model is model
        ]
        params = statement.compile().params
        for criterion in getattr(statement, "_where_criteria", ()):
            left = getattr(criterion, "left", None)
            right = getattr(criterion, "right", None)
            column_name = getattr(left, "name", None)
            bind_key = getattr(right, "key", None)
            literal_value = getattr(right, "value", None)
            if column_name and (bind_key in params or literal_value is not None):
                expected = params[bind_key] if bind_key in params else literal_value
                op = getattr(criterion, "operator", None)
                if op is operator.gt:
                    rows = [row for row in rows if getattr(row, column_name, None) and getattr(row, column_name) > expected]
                elif op is operator.lt:
                    rows = [row for row in rows if getattr(row, column_name, None) and getattr(row, column_name) < expected]
                elif op is operator.ne:
                    rows = [row for row in rows if getattr(row, column_name, None) != expected]
                elif op is sa_operators.in_op:
                    rows = [row for row in rows if getattr(row, column_name, None) in set(expected or [])]
                elif op is sa_operators.not_in_op:
                    rows = [row for row in rows if getattr(row, column_name, None) not in set(expected or [])]
                else:
                    rows = [row for row in rows if getattr(row, column_name, None) == expected]
            elif column_name and " IS NULL" in str(criterion).upper():
                rows = [row for row in rows if getattr(row, column_name, None) is None]

        return _MockScalarResult(value=rows[0] if rows else None, rows=rows)

    async def scalar(self, statement=None, *args, **kwargs):
        result = await self.execute(statement, *args, **kwargs)
        return result.scalar_one_or_none()

    async def get(self, model, item_id, *args, **kwargs):
        return self._objects.get((model, item_id))

    def add(self, obj):
        if hasattr(obj, "id") and getattr(obj, "id", None) is None:
            obj.id = uuid4()
        if hasattr(obj, "id"):
            self._objects[(type(obj), obj.id)] = obj

    async def flush(self):  pass
    async def commit(self): pass
    async def rollback(self): pass
    async def refresh(self, obj): pass
    async def delete(self, obj):
        if hasattr(obj, "id"):
            self._objects.pop((type(obj), obj.id), None)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


_mock_session = _MockSession()


async def _mock_get_session():
    """Dependency override — yields the mock session."""
    yield _mock_session


# ── No-op lifespan (skip DB startup in tests) ─────────────────────────────────

@asynccontextmanager
async def _test_lifespan(app):
    """Replaces the real lifespan so tests don't need PostgreSQL running."""
    yield


# ── App fixture (session-scoped — one app object for all integration tests) ───

@pytest.fixture(scope="session")
def app():
    import main as _main_module
    from app.core.database import get_session

    # Skip database startup
    _main_module.app.router.lifespan_context = _test_lifespan

    # Return empty results for every DB query
    _main_module.app.dependency_overrides[get_session] = _mock_get_session

    return _main_module.app


# ── Async HTTP client ──────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def client(app):
    """Async HTTP client wired to the FastAPI app (lifespan runs but is a no-op)."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac


@pytest.fixture(autouse=True)
def _reset_mock_session():
    _mock_session._objects.clear()
    yield
    _mock_session._objects.clear()
