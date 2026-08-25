"""Real-PostgreSQL startup gate for migration-owned schemas."""

from __future__ import annotations

import os

import pytest
from sqlalchemy import text

from app.core.database import (
    REQUIRED_SCHEMA_REVISION,
    create_tables,
    engine,
    verify_migration_owned_schema,
)


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_POSTGRES_TESTS") != "1",
    reason="requires an explicitly authorized disposable PostgreSQL database",
)


@pytest.mark.asyncio
async def test_startup_fails_closed_on_incompatible_schema_revision():
    await engine.dispose()
    try:
        async with engine.begin() as connection:
            await connection.execute(text("UPDATE alembic_version SET version_num = 'outdated-test'"))

        with pytest.raises(RuntimeError, match="schema revision is not compatible"):
            await create_tables()
    finally:
        async with engine.begin() as connection:
            await connection.execute(
                text("UPDATE alembic_version SET version_num = :revision"),
                {"revision": REQUIRED_SCHEMA_REVISION},
            )
        await engine.dispose()


@pytest.mark.asyncio
async def test_startup_fails_closed_on_multiple_alembic_heads():
    await engine.dispose()
    unexpected_head = "unexpected-multi-head-test"
    try:
        async with engine.begin() as connection:
            await connection.execute(
                text("INSERT INTO alembic_version (version_num) VALUES (:revision)"),
                {"revision": unexpected_head},
            )

        with pytest.raises(RuntimeError, match="schema revision is not compatible"):
            await create_tables()
    finally:
        async with engine.begin() as connection:
            await connection.execute(
                text("DELETE FROM alembic_version WHERE version_num = :revision"),
                {"revision": unexpected_head},
            )
        await engine.dispose()


@pytest.mark.asyncio
async def test_startup_fails_closed_when_physical_schema_drifted():
    await engine.dispose()
    try:
        async with engine.begin() as connection:
            await connection.execute(text("DROP INDEX ix_stage_runs_claim_ready"))

        with pytest.raises(RuntimeError, match="ix_stage_runs_claim_ready"):
            await create_tables()
    finally:
        async with engine.begin() as connection:
            await connection.execute(text("DROP INDEX IF EXISTS ix_stage_runs_claim_ready"))
            # Use the canonical migration source. PostgreSQL's deparsed
            # pg_get_indexdef output is not parse-tree-idempotent for this
            # varchar IN predicate and would itself trip the exact fingerprint.
            await connection.execute(
                text("""
                CREATE INDEX ix_stage_runs_claim_ready
                ON stage_runs (next_attempt_at, priority, created_at, id)
                WHERE status IN ('ready', 'retry_wait')
            """)
            )
        await engine.dispose()

    await create_tables()
    await engine.dispose()


@pytest.mark.asyncio
async def test_startup_rejects_same_name_check_constraint_replacement():
    """A matching object name/type cannot conceal a weakened CHECK body."""

    await engine.dispose()
    original_definition = None
    try:
        async with engine.begin() as connection:
            original_definition = await connection.scalar(
                text("""
                SELECT pg_get_constraintdef(constraint_row.oid, TRUE)
                FROM pg_constraint AS constraint_row
                JOIN pg_class AS relation_row
                  ON relation_row.oid = constraint_row.conrelid
                JOIN pg_namespace AS namespace_row
                  ON namespace_row.oid = relation_row.relnamespace
                WHERE namespace_row.nspname = current_schema()
                  AND relation_row.relname = 'stage_attempts'
                  AND constraint_row.conname = 'ck_stage_attempt_state_version'
            """)
            )
            assert original_definition
            await connection.execute(
                text("""
                ALTER TABLE stage_attempts
                DROP CONSTRAINT ck_stage_attempt_state_version
            """)
            )
            await connection.execute(
                text("""
                ALTER TABLE stage_attempts
                ADD CONSTRAINT ck_stage_attempt_state_version
                CHECK (state_version >= 0)
            """)
            )

        with pytest.raises(RuntimeError, match="authority-fingerprint"):
            await create_tables()
    finally:
        if original_definition:
            async with engine.begin() as connection:
                await connection.execute(
                    text("""
                    ALTER TABLE stage_attempts
                    DROP CONSTRAINT IF EXISTS ck_stage_attempt_state_version
                """)
                )
                await connection.exec_driver_sql(
                    "ALTER TABLE stage_attempts ADD CONSTRAINT ck_stage_attempt_state_version " + str(original_definition)
                )
        await engine.dispose()

    await create_tables()
    await engine.dispose()


@pytest.mark.asyncio
async def test_startup_rejects_same_name_guard_function_replacement():
    """The fingerprint binds trigger names to their executable PL/pgSQL body."""

    await engine.dispose()
    original_definition = None
    try:
        async with engine.begin() as connection:
            original_definition = await connection.scalar(
                text("""
                SELECT pg_get_functiondef(procedure_row.oid)
                FROM pg_proc AS procedure_row
                JOIN pg_namespace AS namespace_row
                  ON namespace_row.oid = procedure_row.pronamespace
                WHERE namespace_row.nspname = current_schema()
                  AND procedure_row.proname = 'ag_guard_research_project_authority'
                  AND procedure_row.pronargs = 0
            """)
            )
            assert original_definition
            await connection.execute(
                text("""
                CREATE OR REPLACE FUNCTION ag_guard_research_project_authority()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $function$
                BEGIN
                    IF TG_OP = 'DELETE' THEN
                        RETURN OLD;
                    END IF;
                    RETURN NEW;
                END;
                $function$
            """)
            )

        with pytest.raises(RuntimeError, match="authority-fingerprint"):
            await create_tables()
    finally:
        if original_definition:
            async with engine.begin() as connection:
                await connection.exec_driver_sql(str(original_definition))
        await engine.dispose()

    await create_tables()
    await engine.dispose()


@pytest.mark.asyncio
async def test_verifier_rejects_same_name_outbox_retry_helper_replacement():
    """A helper with matching signature/attributes cannot conceal a weak body."""

    await engine.dispose()
    original_definition = None
    try:
        async with engine.begin() as connection:
            original_definition = await connection.scalar(
                text("""
                SELECT pg_get_functiondef(procedure_row.oid)
                FROM pg_proc AS procedure_row
                JOIN pg_namespace AS namespace_row
                  ON namespace_row.oid = procedure_row.pronamespace
                WHERE namespace_row.nspname = current_schema()
                  AND procedure_row.proname = 'ag_outbox_retry_delay_seconds'
                  AND pg_get_function_identity_arguments(procedure_row.oid) =
                      'message_logical_key text, delivery_attempt integer'
            """)
            )
            assert original_definition
            await connection.execute(
                text("""
                CREATE OR REPLACE FUNCTION ag_outbox_retry_delay_seconds(
                    message_logical_key text,
                    delivery_attempt integer
                )
                RETURNS integer
                LANGUAGE plpgsql
                IMMUTABLE
                STRICT
                PARALLEL SAFE
                SET search_path = pg_catalog
                AS $function$
                BEGIN
                    RETURN 1;
                END;
                $function$
            """)
            )

        async with engine.connect() as connection:
            with pytest.raises(RuntimeError, match="authority-fingerprint"):
                await verify_migration_owned_schema(connection)
    finally:
        if original_definition:
            async with engine.begin() as connection:
                await connection.exec_driver_sql(str(original_definition))
        await engine.dispose()

    async with engine.connect() as connection:
        await verify_migration_owned_schema(connection)
    await engine.dispose()


@pytest.mark.asyncio
async def test_startup_rejects_disabled_internal_foreign_key_trigger():
    """Validated FK metadata cannot conceal disabled enforcement triggers."""

    await engine.dispose()
    trigger_name = None
    try:
        async with engine.begin() as connection:
            trigger_name = await connection.scalar(
                text("""
                SELECT trigger_row.tgname
                FROM pg_trigger AS trigger_row
                JOIN pg_class AS relation_row
                  ON relation_row.oid = trigger_row.tgrelid
                JOIN pg_constraint AS constraint_row
                  ON constraint_row.oid = trigger_row.tgconstraint
                WHERE relation_row.relname = 'stage_attempts'
                  AND constraint_row.conname = 'fk_stage_attempt_stage'
                  AND trigger_row.tgisinternal
                ORDER BY trigger_row.tgname
                LIMIT 1
            """)
            )
            assert trigger_name
            quoted_trigger = connection.dialect.identifier_preparer.quote(str(trigger_name))
            await connection.exec_driver_sql(f"ALTER TABLE stage_attempts DISABLE TRIGGER {quoted_trigger}")

        with pytest.raises(RuntimeError, match="foreign-key-trigger"):
            await create_tables()
    finally:
        if trigger_name:
            async with engine.begin() as connection:
                quoted_trigger = connection.dialect.identifier_preparer.quote(str(trigger_name))
                await connection.exec_driver_sql(f"ALTER TABLE stage_attempts ENABLE TRIGGER {quoted_trigger}")
        await engine.dispose()

    await create_tables()
    await engine.dispose()
