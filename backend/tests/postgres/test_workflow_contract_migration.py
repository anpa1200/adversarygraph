"""Fresh-PostgreSQL acceptance for the 0004 workflow authority contract.

These tests create and destroy uniquely named disposable databases.  They are
kept behind the repository's explicit PostgreSQL opt-in and must only run after
the application cancellation/recovery writers are frozen against 0004.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import subprocess
import sys
from uuid import UUID, uuid4

import asyncpg
import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.database import _inspect_migration_owned_schema
from app.core.migration_policy import (
    MIGRATION_SCHEMA_AUTHORITY_FINGERPRINT,
    REQUIRED_SCHEMA_REVISION,
)
from app.models.research_workflow import StageAttempt, StageRun, WorkflowRun
from app.services import research_projects as projects
from app.services import workflow_runtime as runtime
from app.services.workflow_engine import checksum_json


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_POSTGRES_TESTS") != "1",
    reason="requires an explicitly authorized disposable PostgreSQL database",
)

_EMPTY_OBJECT_CHECKSUM = hashlib.sha256(b"{}").hexdigest()
_EMPTY_LIST_CHECKSUM = hashlib.sha256(b"[]").hexdigest()


def _integrity_constraint(error: IntegrityError) -> str | None:
    candidates = (
        error.orig,
        getattr(error.orig, "__cause__", None),
        getattr(error.orig, "__context__", None),
    )
    for candidate in candidates:
        if candidate is None:
            continue
        constraint_name = getattr(candidate, "constraint_name", None)
        if isinstance(constraint_name, str):
            return constraint_name
        diagnostic = getattr(candidate, "diag", None)
        constraint_name = getattr(diagnostic, "constraint_name", None)
        if isinstance(constraint_name, str):
            return constraint_name
    return None


async def _insert_raw_current_workflow(
    connection: asyncpg.Connection,
    *,
    revision_id: UUID,
) -> None:
    await connection.execute(
        """
        INSERT INTO workflow_runs (
            id, project_revision_id, replay_of_run_id, workflow_type,
            workflow_schema_version, plan_schema_version, status,
            trigger_type, idempotency_key, correlation_id,
            input_manifest, input_checksum, stage_plan, plan_checksum,
            priority, state_version, status_reason_code, status_summary,
            created_by, created_by_id, cancel_requested_by,
            cancel_requested_by_id, cancel_reason, cancel_requested_at,
            started_at, completed_at, cancel_request_id
        ) VALUES (
            $1, $2, NULL, 'cti.report', 'research-workflow-v1',
            'research-workflow-plan-v1', 'queued', 'api', $3, $4,
            '{}'::jsonb, $5, '[]'::jsonb, $6, 5, 1, '', '',
            'Migration Test', 'migration-test', '', '', '', NULL,
            NULL, NULL, NULL
        )
        """,
        uuid4(),
        revision_id,
        uuid4().hex + uuid4().hex,
        uuid4(),
        _EMPTY_OBJECT_CHECKSUM,
        _EMPTY_LIST_CHECKSUM,
    )


def _database_url(database_name: str) -> str:
    return URL.create(
        "postgresql+asyncpg",
        username=os.environ["DB_USER"],
        password=os.environ["DB_PASS"],
        host=os.environ["DB_HOST"],
        port=int(os.environ["DB_PORT"]),
        database=database_name,
    ).render_as_string(hide_password=False)


def _run_alembic(
    database_name: str,
    *arguments: str,
    expect_success: bool = True,
) -> subprocess.CompletedProcess[str]:
    backend_root = Path(__file__).resolve().parents[2]
    environment = os.environ.copy()
    environment["DB_NAME"] = database_name
    result = subprocess.run(
        [sys.executable, "-m", "alembic", *arguments],
        cwd=backend_root,
        env=environment,
        text=True,
        capture_output=True,
        timeout=90,
        check=False,
    )
    if expect_success and result.returncode != 0:
        pytest.fail(result.stdout + result.stderr)
    if not expect_success:
        assert result.returncode != 0
    return result


@pytest_asyncio.fixture
async def contract_database():
    database_name = f"ag_workflow_contract_{uuid4().hex[:16]}"
    admin = await asyncpg.connect(
        host=os.environ["DB_HOST"],
        port=int(os.environ["DB_PORT"]),
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASS"],
        database="postgres",
    )
    try:
        await admin.execute(f'CREATE DATABASE "{database_name}"')
        yield database_name
    finally:
        await admin.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()",
            database_name,
        )
        await admin.execute(f'DROP DATABASE IF EXISTS "{database_name}"')
        await admin.close()


def _stage_definition(
    stage_key: str,
    ordinal: int,
    *,
    depends_on: list[str] | None = None,
) -> dict[str, object]:
    return {
        "stage_key": stage_key,
        "stage_type": f"test.{stage_key}",
        "stage_version": "1.0.0",
        "ordinal": ordinal,
        "depends_on": depends_on or [],
        "required": True,
        "priority": 0,
        "max_attempts": 3,
        "config_schema_version": "research-stage-config-v1",
        "checkpoint_schema_version": "research-stage-checkpoint-v1",
        "config": {"contract_test": True},
        "retry_policy": {
            "base_delay_seconds": 1,
            "max_delay_seconds": 1,
            "jitter_percent": 0,
        },
    }


async def _create_current_workflow(database_name: str) -> tuple[UUID, UUID, UUID]:
    dynamic_engine = create_async_engine(_database_url(database_name))
    sessions = async_sessionmaker(dynamic_engine, expire_on_commit=False)
    actor = projects.ResearchActor("PostgreSQL 0004 Test", "postgres-0004-test")
    try:
        async with sessions() as db:
            _, revision = await projects.create_project(
                db,
                actor,
                project_key=f"contract-{uuid4().hex[:12]}",
                name="Workflow contract migration project",
                description="Disposable 0004 authority validation.",
                spec={
                    "objective": "Validate the contracted workflow authority schema.",
                    "intelligence_requirements": ["Which raw contradictions reach commit?"],
                    "output_targets": ["canonical_intelligence"],
                    "tlp": "TLP:AMBER",
                },
            )
            workflow, created = await runtime.create_workflow(
                db,
                actor,
                project_revision_id=revision.id,
                workflow_type="cti.report",
                idempotency_token=f"contract-{uuid4().hex}",
                input_manifest={},
                stage_plan=[
                    _stage_definition("collect", 1),
                    _stage_definition("analyze", 2, depends_on=["collect"]),
                ],
            )
            assert created is True
            await db.commit()
            stages = tuple(
                (await db.scalars(select(StageRun).where(StageRun.workflow_run_id == workflow.id).order_by(StageRun.ordinal))).all()
            )
            assert len(stages) == 2
            return workflow.id, stages[0].id, stages[1].id
    finally:
        await dynamic_engine.dispose()


async def _seed_active_non_v1_workflow(database_name: str) -> UUID:
    workflow_id = uuid4()
    project_id = uuid4()
    revision_id = uuid4()
    connection = await asyncpg.connect(
        host=os.environ["DB_HOST"],
        port=int(os.environ["DB_PORT"]),
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASS"],
        database=database_name,
    )
    try:
        async with connection.transaction():
            await connection.execute(
                """
                INSERT INTO research_projects (
                    id, project_key, name, description, status, domain, tlp,
                    version, created_by, created_by_id, updated_by,
                    updated_by_id, archive_reason, archived_at
                ) VALUES (
                    $1, $2, 'Legacy active workflow', '0004 preflight sentinel.',
                    'active', 'cti', 'TLP:AMBER', 1, 'Migration Test',
                    'migration-test', 'Migration Test', 'migration-test', '', NULL
                )
                """,
                project_id,
                f"legacy-{uuid4().hex[:12]}",
            )
            await connection.execute(
                """
                INSERT INTO project_revisions (
                    id, project_id, parent_revision_id, revision, status,
                    schema_version, spec, spec_checksum, change_summary,
                    created_by, created_by_id, revoked_by, revoked_by_id, revoked_at
                ) VALUES (
                    $1, $2, NULL, 1, 'current', 'research-project-v1',
                    '{}'::jsonb, $3, 'Initial revision.', 'Migration Test',
                    'migration-test', '', '', NULL
                )
                """,
                revision_id,
                project_id,
                _EMPTY_OBJECT_CHECKSUM,
            )
            await connection.execute(
                """
                INSERT INTO workflow_runs (
                    id, project_revision_id, replay_of_run_id, workflow_type,
                    workflow_schema_version, plan_schema_version, status,
                    trigger_type, idempotency_key, correlation_id,
                    input_manifest, input_checksum, stage_plan, plan_checksum,
                    priority, state_version, status_reason_code, status_summary,
                    created_by, created_by_id, cancel_requested_by,
                    cancel_requested_by_id, cancel_reason, cancel_requested_at,
                    started_at, completed_at
                ) VALUES (
                    $1, $2, NULL, 'cti.report', 'legacy-workflow-v0',
                    'legacy-plan-v0', 'queued', 'api', $3, $4, '{}'::jsonb,
                    $5, '[]'::jsonb, $6, 5, 1, '', '', 'Migration Test',
                    'migration-test', '', '', '', NULL, NULL, NULL
                )
                """,
                workflow_id,
                revision_id,
                uuid4().hex + uuid4().hex,
                uuid4(),
                _EMPTY_OBJECT_CHECKSUM,
                _EMPTY_LIST_CHECKSUM,
            )
        return workflow_id
    finally:
        await connection.close()


@pytest.mark.asyncio
async def test_0004_empty_upgrade_installs_exact_catalog_authority(contract_database):
    _run_alembic(contract_database, "upgrade", "20260823_0003")
    _run_alembic(contract_database, "upgrade", REQUIRED_SCHEMA_REVISION)

    dynamic_engine = create_async_engine(_database_url(contract_database))
    try:
        async with dynamic_engine.connect() as connection:
            heads = tuple((await connection.scalars(text("SELECT version_num FROM alembic_version ORDER BY version_num"))).all())
            assert heads == (REQUIRED_SCHEMA_REVISION,)
            missing, fingerprint = await _inspect_migration_owned_schema(connection)
            assert missing == []
            assert fingerprint == MIGRATION_SCHEMA_AUTHORITY_FINGERPRINT

            trigger_names = tuple(
                (
                    await connection.scalars(
                        text("""
                            SELECT trigger_row.tgname
                            FROM pg_trigger AS trigger_row
                            JOIN pg_class AS relation_row
                              ON relation_row.oid = trigger_row.tgrelid
                            WHERE relation_row.relname = 'stage_attempts'
                              AND NOT trigger_row.tgisinternal
                              AND (trigger_row.tgtype::integer & 4) = 4
                            ORDER BY trigger_row.tgname
                        """)
                    )
                ).all()
            )
            assert trigger_names[0] == "trg_0004_stage_attempt_receipt_contract_guard"
            assert await connection.scalar(text("SELECT to_regprocedure('ag_workflow_contract_valid(uuid)')"))
    finally:
        await dynamic_engine.dispose()


@pytest.mark.asyncio
async def test_0004_upgrade_rejects_active_non_v1_without_partial_ddl(contract_database):
    _run_alembic(contract_database, "upgrade", "20260823_0003")
    workflow_id = await _seed_active_non_v1_workflow(contract_database)

    rejected = _run_alembic(
        contract_database,
        "upgrade",
        REQUIRED_SCHEMA_REVISION,
        expect_success=False,
    )
    assert "cannot contract active workflows with unsupported schema versions" in (rejected.stdout + rejected.stderr)

    connection = await asyncpg.connect(
        host=os.environ["DB_HOST"],
        port=int(os.environ["DB_PORT"]),
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASS"],
        database=contract_database,
    )
    try:
        assert await connection.fetchval("SELECT version_num FROM alembic_version") == "20260823_0003"
        assert (
            await connection.fetchval(
                """
            SELECT count(*)
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'workflow_runs'
              AND column_name = 'cancel_request_id'
            """
            )
            == 0
        )
        assert await connection.fetchval("SELECT to_regprocedure('ag_workflow_contract_valid(uuid)')") is None
        assert (
            await connection.fetchval(
                "SELECT status FROM workflow_runs WHERE id = $1",
                workflow_id,
            )
            == "queued"
        )
    finally:
        await connection.close()


@pytest.mark.asyncio
async def test_0004_workflow_insert_serializes_project_revision_authority(contract_database):
    _run_alembic(contract_database, "upgrade", REQUIRED_SCHEMA_REVISION)
    dynamic_engine = create_async_engine(_database_url(contract_database))
    sessions = async_sessionmaker(dynamic_engine, expire_on_commit=False)
    actor = projects.ResearchActor("PostgreSQL 0004 Test", "postgres-0004-test")
    initial_spec = {
        "objective": "Prove workflow creation cannot race revision authority.",
        "intelligence_requirements": ["Which revision is current at W insertion?"],
        "output_targets": ["canonical_intelligence"],
        "tlp": "TLP:AMBER",
    }
    competing_connection: asyncpg.Connection | None = None
    try:
        async with sessions() as db:
            project, old_revision = await projects.create_project(
                db,
                actor,
                project_key=f"contract-parent-{uuid4().hex[:12]}",
                name="Workflow parent authority contract",
                description="Disposable 0004 project/revision lock validation.",
                spec=initial_spec,
            )
            await db.commit()
            project_id = project.id
            old_revision_id = old_revision.id

        # Hold the canonical project -> current-revision locks while replacing
        # the revision.  The raw W INSERT starts from the previously committed
        # revision snapshot, then must wait on the project and reject after the
        # replacement commits rather than authorizing stale parent authority.
        async with sessions() as revision_db:
            _, new_revision = await projects.create_revision(
                revision_db,
                project_id,
                actor,
                expected_version=1,
                spec={**initial_spec, "objective": "Supersede the old workflow authority revision."},
                change_summary="Supersede the revision during workflow insertion.",
            )
            new_revision_id = new_revision.id
            competing_connection = await asyncpg.connect(
                host=os.environ["DB_HOST"],
                port=int(os.environ["DB_PORT"]),
                user=os.environ["DB_USER"],
                password=os.environ["DB_PASS"],
                database=contract_database,
            )

            async def insert_against_superseded_revision() -> None:
                async with competing_connection.transaction():
                    await _insert_raw_current_workflow(
                        competing_connection,
                        revision_id=old_revision_id,
                    )

            blocked_insert = asyncio.create_task(insert_against_superseded_revision())
            wait_event_type: str | None = None
            for _ in range(100):
                if blocked_insert.done():
                    break
                wait_event_type = await revision_db.scalar(
                    text("SELECT wait_event_type FROM pg_stat_activity WHERE pid = :pid"),
                    {"pid": competing_connection.get_server_pid()},
                )
                if wait_event_type == "Lock":
                    break
                await asyncio.sleep(0.02)
            assert wait_event_type == "Lock"
            assert not blocked_insert.done()
            await revision_db.commit()
            with pytest.raises(asyncpg.CheckViolationError) as exc_info:
                await blocked_insert
            assert exc_info.value.constraint_name == "ck_workflow_run_project_authority"

        # A current revision under an archived project is equally invalid.
        async with sessions() as db:
            await projects.archive_project(
                db,
                project_id,
                actor,
                expected_version=2,
                reason="Exercise the inactive-project workflow guard.",
            )
            await db.commit()
        assert competing_connection is not None
        with pytest.raises(asyncpg.CheckViolationError) as exc_info:
            async with competing_connection.transaction():
                await _insert_raw_current_workflow(
                    competing_connection,
                    revision_id=new_revision_id,
                )
        assert exc_info.value.constraint_name == "ck_workflow_run_project_authority"
    finally:
        if competing_connection is not None:
            await competing_connection.close()
        await dynamic_engine.dispose()


@pytest.mark.asyncio
async def test_0004_rejects_raw_plan_receipt_and_terminalization_gaps(contract_database):
    _run_alembic(contract_database, "upgrade", REQUIRED_SCHEMA_REVISION)
    workflow_id, root_stage_id, dependent_stage_id = await _create_current_workflow(contract_database)
    dynamic_engine = create_async_engine(_database_url(contract_database))
    sessions = async_sessionmaker(dynamic_engine, expire_on_commit=False)
    try:
        async with sessions() as db:
            assert (
                await db.scalar(
                    text("SELECT ag_workflow_contract_valid(:workflow_id)"),
                    {"workflow_id": workflow_id},
                )
                is True
            )

        async with sessions() as db:
            # Build an otherwise legal M-cancelled/all-S-cancelled state, but
            # deliberately leave W running.  The reverse aggregate fixed point
            # must reject the missing W settlement at deferred validation.
            await db.execute(
                text("""
                    UPDATE outbox_messages
                    SET status = 'cancelled',
                        state_version = state_version + 1,
                        available_at = NULL,
                        cancelled_by = 'Migration Test',
                        cancelled_by_id = 'migration-test',
                        cancel_reason = 'Exercise reverse workflow settlement.'
                    WHERE workflow_run_id = :workflow_id
                      AND stage_run_id = :root_stage_id
                      AND status IN ('pending', 'retry_wait')
                """),
                {"workflow_id": workflow_id, "root_stage_id": root_stage_id},
            )
            await db.execute(
                text("""
                    UPDATE stage_runs
                    SET status = 'cancelled',
                        state_version = state_version + 1,
                        next_attempt_at = NULL,
                        completed_at = transaction_timestamp()
                    WHERE workflow_run_id = :workflow_id
                """),
                {"workflow_id": workflow_id},
            )
            await db.execute(
                text("""
                    UPDATE workflow_runs
                    SET status = 'running',
                        state_version = state_version + 1,
                        started_at = transaction_timestamp()
                    WHERE id = :workflow_id
                """),
                {"workflow_id": workflow_id},
            )
            with pytest.raises(IntegrityError) as exc_info:
                await db.commit()
            assert _integrity_constraint(exc_info.value) == "ck_workflow_cross_domain_contract"
            await db.rollback()

        async with sessions() as db:
            dependent = await db.scalar(select(StageRun).where(StageRun.id == dependent_stage_id).with_for_update())
            assert dependent is not None and dependent.status == "pending"
            dependent.status = "ready"
            dependent.state_version += 1
            dependent.next_attempt_at = datetime.now(timezone.utc)
            with pytest.raises(IntegrityError) as exc_info:
                await db.commit()
            assert _integrity_constraint(exc_info.value) == "ck_workflow_cross_domain_contract"
            await db.rollback()

        async with sessions() as db:
            rogue = StageRun(
                id=uuid4(),
                workflow_run_id=workflow_id,
                stage_key="rogue",
                stage_type="test.rogue",
                stage_version="1.0.0",
                ordinal=3,
                status="pending",
                priority=0,
                state_version=1,
                idempotency_key=checksum_json({"workflow_run_id": str(workflow_id), "stage_key": "rogue"}),
                depends_on=["collect"],
                required=True,
                config_schema_version="research-stage-config-v1",
                config={"contract_test": True},
                config_checksum=checksum_json({"contract_test": True}),
                input_manifest={},
                input_checksum=_EMPTY_OBJECT_CHECKSUM,
                output_manifest={},
                output_checksum="",
                checkpoint={},
                checkpoint_schema_version="research-stage-checkpoint-v1",
                checkpoint_version=0,
                checkpoint_checksum=_EMPTY_OBJECT_CHECKSUM,
                attempt_count=0,
                max_attempts=3,
                next_attempt_at=None,
                lease_owner="",
                lease_token=None,
                leased_at=None,
                lease_expires_at=None,
                heartbeat_at=None,
                last_error_code="",
                last_error_summary="",
                last_error_retryable=False,
                first_started_at=None,
                completed_at=None,
            )
            db.add(rogue)
            with pytest.raises(IntegrityError) as exc_info:
                await db.flush([rogue])
            assert _integrity_constraint(exc_info.value) == "ck_stage_run_plan_member"
            await db.rollback()

        async with sessions() as db:
            now = datetime.now(timezone.utc)
            attempt = StageAttempt(
                id=uuid4(),
                stage_run_id=root_stage_id,
                outbox_delivery_attempt_id=None,
                attempt_number=1,
                lease_token=uuid4(),
                lease_owner="raw-worker",
                delivery_id=_EMPTY_OBJECT_CHECKSUM,
                status="running",
                state_version=1,
                input_checksum=_EMPTY_OBJECT_CHECKSUM,
                checkpoint_start_version=0,
                checkpoint_end_version=0,
                output_checksum="",
                error_code="",
                error_class="",
                error_summary="",
                retryable=False,
                started_at=now,
                heartbeat_at=now,
                lease_expires_at=now + timedelta(minutes=5),
                completed_at=None,
            )
            db.add(attempt)
            with pytest.raises(IntegrityError) as exc_info:
                await db.flush([attempt])
            assert _integrity_constraint(exc_info.value) == "ck_stage_attempt_receipt_required"
            await db.rollback()

        cancellation_update = text("""
            UPDATE workflow_runs
            SET status = 'cancelled',
                state_version = state_version + 1,
                completed_at = transaction_timestamp(),
                cancel_requested_at = transaction_timestamp(),
                cancel_requested_by = 'Migration Test',
                cancel_requested_by_id = 'migration-test',
                cancel_reason = 'Raw cancellation must carry request identity.'
            WHERE id = :workflow_id
        """)
        async with sessions() as db:
            with pytest.raises(IntegrityError) as exc_info:
                await db.execute(cancellation_update, {"workflow_id": workflow_id})
            assert _integrity_constraint(exc_info.value) == "ck_workflow_run_cancel_request"
            await db.rollback()

        async with sessions() as db:
            with pytest.raises(IntegrityError) as exc_info:
                await db.execute(
                    text("""
                        UPDATE workflow_runs
                        SET status = 'cancelled',
                            state_version = state_version + 1,
                            completed_at = transaction_timestamp(),
                            cancel_requested_at = transaction_timestamp(),
                            cancel_requested_by = 'Migration Test',
                            cancel_requested_by_id = 'migration-test',
                            cancel_reason = 'Raw terminalization is incomplete.',
                            cancel_request_id = :request_id
                        WHERE id = :workflow_id
                    """),
                    {"workflow_id": workflow_id, "request_id": uuid4()},
                )
                await db.commit()
            assert _integrity_constraint(exc_info.value) == "ck_workflow_cross_domain_contract"
            await db.rollback()

        async with sessions() as db:
            assert (
                await db.scalar(
                    text("SELECT ag_workflow_contract_valid(:workflow_id)"),
                    {"workflow_id": workflow_id},
                )
                is True
            )
    finally:
        await dynamic_engine.dispose()


@pytest.mark.asyncio
async def test_0004_downgrade_is_reversible_only_without_live_authority(contract_database):
    _run_alembic(contract_database, "upgrade", REQUIRED_SCHEMA_REVISION)
    _run_alembic(contract_database, "downgrade", "20260823_0003")

    connection = await asyncpg.connect(
        host=os.environ["DB_HOST"],
        port=int(os.environ["DB_PORT"]),
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASS"],
        database=contract_database,
    )
    try:
        assert await connection.fetchval("SELECT version_num FROM alembic_version") == "20260823_0003"
        assert (
            await connection.fetchval(
                """
            SELECT count(*)
            FROM information_schema.columns
            WHERE table_schema = current_schema()
              AND table_name = 'workflow_runs'
              AND column_name = 'cancel_request_id'
            """
            )
            == 0
        )
    finally:
        await connection.close()

    _run_alembic(contract_database, "upgrade", REQUIRED_SCHEMA_REVISION)
    await _create_current_workflow(contract_database)
    blocked = _run_alembic(
        contract_database,
        "downgrade",
        "20260823_0003",
        expect_success=False,
    )
    assert "Refusing to weaken the contract while workflows remain active" in (blocked.stdout + blocked.stderr)

    connection = await asyncpg.connect(
        host=os.environ["DB_HOST"],
        port=int(os.environ["DB_PORT"]),
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASS"],
        database=contract_database,
    )
    try:
        assert await connection.fetchval("SELECT version_num FROM alembic_version") == REQUIRED_SCHEMA_REVISION
        assert await connection.fetchval("SELECT to_regprocedure('ag_workflow_contract_valid(uuid)')") is not None
    finally:
        await connection.close()
