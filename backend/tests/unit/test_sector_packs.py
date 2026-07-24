from __future__ import annotations

import pytest
from sqlalchemy.dialects import postgresql

from app.services.sector_packs import NVIDIA_SECTOR_PACKS, ensure_sector_packs


class _Scalars:
    def all(self):
        return [1, 2, 3]


class _Result:
    def scalars(self):
        return _Scalars()


class _Session:
    def __init__(self):
        self.statement = None
        self.committed = False

    async def execute(self, statement):
        self.statement = statement
        return _Result()

    async def commit(self):
        self.committed = True


@pytest.mark.asyncio
async def test_sector_pack_seed_uses_database_atomic_conflict_handling():
    session = _Session()

    inserted = await ensure_sector_packs(session)

    sql = str(session.statement.compile(dialect=postgresql.dialect()))
    assert "ON CONFLICT (sector_id) DO NOTHING" in sql
    assert len(session.statement.compile().params) >= len(NVIDIA_SECTOR_PACKS)
    assert inserted == 3
    assert session.committed is True
