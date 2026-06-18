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
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport



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

    async def execute(self, *args, **kwargs):
        return _MockScalarResult()

    async def get(self, *args, **kwargs):
        return None

    def add(self, obj):     pass
    async def flush(self):  pass
    async def commit(self): pass
    async def rollback(self): pass
    async def refresh(self, obj): pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


async def _mock_get_session():
    """Dependency override — yields the mock session."""
    yield _MockSession()


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
