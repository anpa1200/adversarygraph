"""Exercise the additive CTI migration against real PostgreSQL legacy data."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from uuid import uuid4

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import text

from app.core.database import engine

pytestmark = pytest.mark.skipif(os.getenv("RUN_POSTGRES_TESTS") != "1", reason="disposable PostgreSQL only")


@pytest.mark.asyncio
async def test_cti_column_upgrade_handles_fresh_and_preserves_legacy_rows():
    path = Path(__file__).parents[2] / "alembic/versions/20261014_0005_cti_investigation.py"
    spec = importlib.util.spec_from_file_location("cti_additive_migration", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    schema = "cti_migration_test_" + uuid4().hex
    await engine.dispose()
    async with engine.connect() as connection:
        transaction = await connection.begin()
        try:
            await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
            await connection.execute(text(f'SET LOCAL search_path TO "{schema}"'))

            def apply(sync_connection):
                with Operations.context(MigrationContext.configure(sync_connection)):
                    module.upgrade()

            # Fresh bootstrap has no startup-managed analysis table yet.
            await connection.run_sync(apply)
            await connection.execute(text("CREATE TABLE analysis_results (id INTEGER PRIMARY KEY, summary TEXT NOT NULL)"))
            await connection.execute(text("INSERT INTO analysis_results VALUES (1, 'preserved legacy summary')"))
            await connection.run_sync(apply)
            row = (await connection.execute(text("SELECT summary, investigation FROM analysis_results WHERE id=1"))).one()
            assert tuple(row) == ("preserved legacy summary", {})
            await connection.execute(text("UPDATE analysis_results SET investigation = '{\"coverage\": \"preserved\"}'::jsonb WHERE id=1"))
            await connection.run_sync(apply)
            row = (await connection.execute(text("SELECT summary, investigation FROM analysis_results WHERE id=1"))).one()
            assert tuple(row) == ("preserved legacy summary", {"coverage": "preserved"})
        finally:
            await transaction.rollback()
    await engine.dispose()
