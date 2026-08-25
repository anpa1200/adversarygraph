"""PostgreSQL acceptance for commit-confirmed receipt-bound heartbeats.

Run only against a disposable database migrated through revision 0004::

    RUN_POSTGRES_TESTS=1 python -m pytest -q -o addopts='' \
      --confcutdir=tests/postgres \
      tests/postgres/test_workflow_heartbeat_receipt.py
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime
import hashlib
import json
import os
import uuid

import pytest
import pytest_asyncio
from sqlalchemy import event, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.database import async_session_factory, engine
from app.models.research_workflow import (
    OutboxDeliveryAttempt,
    OutboxMessage,
    StageAttempt,
    StageRun,
    WorkflowRun,
)
from app.services import outbox_coordinator
from app.services import outbox_runtime
from app.services import research_projects as projects
from app.services import workflow_runtime
from app.services import workflow_worker
from tests.postgres._workflow_authority import cancel_active_workflow


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_POSTGRES_TESTS") != "1",
    reason="requires an explicitly authorized disposable PostgreSQL database",
)

ACTOR = projects.ResearchActor(
    name="PostgreSQL Receipt Heartbeat Test",
    actor_id="postgres-receipt-heartbeat",
)


class _InjectedHeartbeatFailure(RuntimeError):
    """Test-only failure raised after both heartbeat rows reached PostgreSQL."""


class _ImmediateConstraintsSession(AsyncSession):
    immediate_checks = 0

    async def flush(self, objects=None):
        await super().flush(objects)
        if objects and any(type(value) is StageAttempt and value.status == "running" and value.state_version > 1 for value in objects):
            await self.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
            type(self).immediate_checks += 1


class _FailAfterAttemptFlushSession(AsyncSession):
    async def flush(self, objects=None):
        await super().flush(objects)
        if objects and any(type(value) is StageAttempt and value.status == "running" and value.state_version > 1 for value in objects):
            raise _InjectedHeartbeatFailure("rollback after stage and attempt heartbeat flushes")


class _TrackingFactory:
    def __init__(self, maker=async_session_factory):
        self._maker = maker
        self.active = 0
        self.exits = 0

    def __call__(self):
        @asynccontextmanager
        async def scope():
            self.active += 1
            try:
                async with self._maker() as db:
                    yield db
            finally:
                self.active -= 1
                self.exits += 1

        return scope()


class _AsyncBarrier:
    def __init__(self, parties: int):
        self._parties = parties
        self._arrived = 0
        self._lock = asyncio.Lock()
        self._release = asyncio.Event()

    async def wait(self) -> None:
        async with self._lock:
            self._arrived += 1
            if self._arrived == self._parties:
                self._release.set()
        await asyncio.wait_for(self._release.wait(), timeout=10)


class _BarrierFactory:
    def __init__(self, barrier: _AsyncBarrier):
        self._barrier = barrier
        self._calls = 0

    def __call__(self):
        self._calls += 1
        call_number = self._calls

        @asynccontextmanager
        async def scope():
            async with async_session_factory() as db:
                if call_number == 1:
                    await self._barrier.wait()
                yield db

        return scope()


class _CancellationRaceFactory:
    def __init__(self, workflow_run_id: uuid.UUID):
        self._workflow_run_id = workflow_run_id
        self._calls = 0

    def __call__(self):
        self._calls += 1
        call_number = self._calls

        @asynccontextmanager
        async def scope():
            if call_number == 2:
                await _cancel_if_active(
                    self._workflow_run_id,
                    reason="Cancellation won before heartbeat confirmation.",
                )
            async with async_session_factory() as db:
                yield db

        return scope()


class _SameSessionFactory:
    def __init__(self):
        self.session = async_session_factory()

    def __call__(self):
        @asynccontextmanager
        async def scope():
            yield self.session

        return scope()


@pytest_asyncio.fixture(autouse=True)
async def _dispose_engine_pool_between_tests():
    await engine.dispose()
    try:
        yield
    finally:
        await engine.dispose()


def _spec(label: str) -> dict:
    return {
        "objective": f"Validate receipt-bound stage heartbeat: {label}.",
        "intelligence_requirements": [
            "Can only committed delivered receipt authority renew a worker lease?",
        ],
        "output_targets": ["canonical_intelligence"],
        "tlp": "TLP:AMBER",
    }


def _stage_definition() -> dict:
    return {
        "stage_key": "collect",
        "stage_type": "test.collect",
        "stage_version": "1.0.0",
        "ordinal": 1,
        "depends_on": [],
        "required": True,
        "priority": 0,
        "max_attempts": 3,
        "config_schema_version": "research-stage-config-v1",
        "checkpoint_schema_version": "research-stage-checkpoint-v1",
        "config": {"acceptance_test": True, "receipt_heartbeat": True},
        "retry_policy": {
            "base_delay_seconds": 1,
            "max_delay_seconds": 1,
            "jitter_percent": 0,
        },
    }


async def _new_workflow(label: str) -> uuid.UUID:
    async with async_session_factory() as db:
        _, revision = await projects.create_project(
            db,
            ACTOR,
            project_key=f"receipt-heartbeat-{label}-{uuid.uuid4().hex[:10]}",
            name=f"Receipt heartbeat {label}",
            description="Disposable PostgreSQL receipt-heartbeat authority.",
            spec=_spec(label),
        )
        workflow, created = await workflow_runtime.create_workflow(
            db,
            ACTOR,
            project_revision_id=revision.id,
            workflow_type="cti.report",
            idempotency_token=f"receipt-heartbeat-{label}-{uuid.uuid4().hex}",
            input_manifest={"report_id": label, "source_ids": ["source-a"]},
            stage_plan=[_stage_definition()],
            priority=0,
        )
        assert created is True
        workflow_id = uuid.UUID(str(workflow.id))
        await db.commit()
        return workflow_id


async def _root_message_id(workflow_id: uuid.UUID) -> uuid.UUID:
    async with async_session_factory() as db:
        message_id = await db.scalar(
            select(OutboxMessage.id).where(
                OutboxMessage.workflow_run_id == workflow_id,
                OutboxMessage.stage_key == "collect",
                OutboxMessage.emission_kind == "root_ready",
                OutboxMessage.redrive_ordinal == 0,
            )
        )
    assert isinstance(message_id, uuid.UUID)
    return uuid.UUID(str(message_id))


@asynccontextmanager
async def _isolate_outbox_queue(allowed_message_id: uuid.UUID):
    async with async_session_factory() as blocker:
        await blocker.execute(
            select(OutboxMessage.id)
            .where(
                OutboxMessage.status.in_(("pending", "retry_wait")),
                OutboxMessage.id != allowed_message_id,
            )
            .order_by(OutboxMessage.id.asc())
            .with_for_update()
        )
        try:
            yield
        finally:
            await blocker.rollback()


@asynccontextmanager
async def _isolate_recovery_targets(allowed_workflow_id: uuid.UUID):
    async with async_session_factory() as blocker:
        await blocker.execute(
            select(WorkflowRun.id)
            .where(
                WorkflowRun.status.in_(("queued", "running")),
                WorkflowRun.id != allowed_workflow_id,
            )
            .order_by(WorkflowRun.id.asc())
            .with_for_update()
        )
        try:
            yield
        finally:
            await blocker.rollback()


async def _activate(
    label: str,
    *,
    lease_seconds: int = 120,
) -> tuple[uuid.UUID, outbox_runtime.ExecutableStageAuthority]:
    workflow_id = await _new_workflow(label)
    message_id = await _root_message_id(workflow_id)
    async with _isolate_outbox_queue(message_id):
        async with async_session_factory() as db:
            claim = await outbox_runtime.claim_outbox_delivery(
                db,
                publisher_id=f"receipt-heartbeat-publisher-{uuid.uuid4().hex[:8]}",
                lease_seconds=120,
            )
            assert claim is not None and claim.message_id == message_id
            await db.commit()

    command = outbox_runtime.StageReceiptCommand(
        claim=claim,
        broker_name="postgres_test_broker",
        broker_message_id=f"receipt-heartbeat-{label}-{claim.cycle_key}",
        broker_receipt_id=hashlib.sha256(f"receipt-heartbeat:{label}:{claim.cycle_key}".encode()).hexdigest(),
        worker_id=f"receipt-heartbeat-worker-{label}",
        lease_seconds=lease_seconds,
    )
    coordinated = await outbox_coordinator.coordinate_stage_receipt(
        async_session_factory,
        command=command,
    )
    assert coordinated.disposition == "activated"
    assert coordinated.should_execute is True
    assert coordinated.authority is not None
    return workflow_id, coordinated.authority


def _row_snapshot(value: object) -> tuple[tuple[str, object], ...]:
    snapshot: list[tuple[str, object]] = []
    for column in type(value).__table__.columns:
        field_value = getattr(value, column.key)
        if type(field_value) in {dict, list}:
            field_value = json.dumps(
                field_value,
                sort_keys=True,
                separators=(",", ":"),
            )
        snapshot.append((column.key, field_value))
    return tuple(snapshot)


async def _snapshots(authority: outbox_runtime.ExecutableStageAuthority):
    async with async_session_factory() as db:
        rows = (
            await db.get(WorkflowRun, authority.workflow_run_id),
            await db.get(StageRun, authority.stage_run_id),
            await db.get(OutboxMessage, authority.message_id),
            await db.get(OutboxDeliveryAttempt, authority.delivery_attempt_id),
            await db.get(StageAttempt, authority.stage_attempt_id),
        )
        assert all(row is not None for row in rows)
        return tuple(_row_snapshot(row) for row in rows)


async def _message_delivery_snapshots(authority: outbox_runtime.ExecutableStageAuthority):
    snapshots = await _snapshots(authority)
    return snapshots[2], snapshots[3]


async def _cancel_if_active(workflow_id: uuid.UUID, *, reason: str) -> None:
    await cancel_active_workflow(
        async_session_factory,
        workflow_run_id=workflow_id,
        actor=ACTOR,
        reason=reason,
    )


async def _wait_until_db_after(moment: datetime) -> None:
    for _ in range(300):
        async with engine.connect() as connection:
            now = await connection.scalar(select(func.clock_timestamp()))
        if isinstance(now, datetime) and now > moment:
            return
        await asyncio.sleep(0.02)
    raise AssertionError("PostgreSQL clock did not advance past the lease boundary")


async def _wait_for_workflow_lock_wait() -> None:
    for _ in range(200):
        async with engine.connect() as connection:
            waiting = await connection.scalar(
                text(
                    """
                    SELECT EXISTS (
                        SELECT 1
                        FROM pg_stat_activity
                        WHERE datname = current_database()
                          AND pid <> pg_backend_pid()
                          AND wait_event_type = 'Lock'
                          AND query ILIKE '%workflow_runs%'
                    )
                    """
                )
            )
        if waiting is True:
            return
        await asyncio.sleep(0.02)
    raise AssertionError("Heartbeat backend did not enter the workflow lock wait")


async def _assert_nowait_lineage_unlocked(
    authority: outbox_runtime.ExecutableStageAuthority,
) -> None:
    async with async_session_factory() as db:
        async with db.begin():
            for model, row_id in (
                (WorkflowRun, authority.workflow_run_id),
                (StageRun, authority.stage_run_id),
                (OutboxMessage, authority.message_id),
                (OutboxDeliveryAttempt, authority.delivery_attempt_id),
                (StageAttempt, authority.stage_attempt_id),
            ):
                row = await db.scalar(
                    select(model)
                    .where(model.id == row_id)
                    .execution_options(populate_existing=True, autoflush=False)
                    .with_for_update(nowait=True)
                )
                assert row is not None
            await db.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))


async def _recover_one(workflow_id: uuid.UUID):
    async with _isolate_recovery_targets(workflow_id):
        return await workflow_worker.coordinate_one_expired_stage_recovery(
            async_session_factory,
        )


def _locked_table_order(statements: list[str]) -> list[str]:
    ordered: list[str] = []
    for statement in statements:
        if "FOR UPDATE" not in statement:
            continue
        for table in (
            "workflow_runs",
            "stage_runs",
            "outbox_messages",
            "outbox_delivery_attempts",
            "stage_attempts",
        ):
            if f"FROM {table}" in statement:
                ordered.append(table)
                break
    return ordered


@pytest.mark.asyncio
async def test_committed_heartbeat_releases_locks_and_updates_only_stage_attempt():
    workflow_id, authority = await _activate("committed")
    before = await _snapshots(authority)
    statements: list[str] = []

    def capture(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)

    maker = async_sessionmaker(
        engine,
        class_=_ImmediateConstraintsSession,
        expire_on_commit=False,
    )
    factory = _TrackingFactory(maker)
    _ImmediateConstraintsSession.immediate_checks = 0
    event.listen(engine.sync_engine, "before_cursor_execute", capture)
    try:
        heartbeat = await workflow_worker.coordinate_stage_heartbeat(
            factory,
            authority=authority,
            lease_seconds=120,
        )
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", capture)

    assert heartbeat.disposition == "renewed"
    assert heartbeat.should_continue is True
    assert heartbeat.authority is not None
    assert heartbeat.previous_stage_state_version == authority.stage_state_version
    assert heartbeat.stage_state_version == authority.stage_state_version + 1
    assert heartbeat.previous_attempt_state_version == authority.attempt_state_version
    assert heartbeat.attempt_state_version == authority.attempt_state_version + 1
    assert heartbeat.previous_lease_expires_at == authority.lease_expires_at
    assert heartbeat.heartbeat_at is not None
    assert heartbeat.lease_expires_at >= authority.lease_expires_at
    assert heartbeat.authority.stage_state_version == heartbeat.stage_state_version
    assert heartbeat.authority.attempt_state_version == heartbeat.attempt_state_version
    assert heartbeat.authority.lease_expires_at == heartbeat.lease_expires_at
    assert factory.active == 0 and factory.exits == 2
    assert _ImmediateConstraintsSession.immediate_checks == 1

    expected_lock_order = [
        "workflow_runs",
        "stage_runs",
        "outbox_messages",
        "outbox_delivery_attempts",
        "stage_attempts",
    ] * 2
    assert _locked_table_order(statements) == expected_lock_order
    updates = [statement for statement in statements if statement.lstrip().upper().startswith("UPDATE")]
    assert len(updates) == 2
    assert "UPDATE stage_runs" in updates[0]
    assert "UPDATE stage_attempts" in updates[1]

    await _assert_nowait_lineage_unlocked(heartbeat.authority)
    after = await _snapshots(heartbeat.authority)
    assert after[0] == before[0]
    assert after[2:4] == before[2:4]
    async with async_session_factory() as db:
        stage = await db.get(StageRun, authority.stage_run_id)
        attempt = await db.get(StageAttempt, authority.stage_attempt_id)
        assert stage is not None and attempt is not None
        assert stage.state_version == heartbeat.stage_state_version
        assert attempt.state_version == heartbeat.attempt_state_version
        assert stage.heartbeat_at == attempt.heartbeat_at == heartbeat.heartbeat_at
        assert stage.lease_expires_at == attempt.lease_expires_at == heartbeat.lease_expires_at
    await _cancel_if_active(workflow_id, reason="Committed heartbeat acceptance cleanup.")


@pytest.mark.asyncio
async def test_failure_after_both_heartbeat_flushes_rolls_back_every_effect():
    workflow_id, authority = await _activate("rollback")
    before = await _snapshots(authority)
    maker = async_sessionmaker(
        engine,
        class_=_FailAfterAttemptFlushSession,
        expire_on_commit=False,
    )
    with pytest.raises(_InjectedHeartbeatFailure):
        await workflow_worker.coordinate_stage_heartbeat(
            maker,
            authority=authority,
            lease_seconds=120,
        )
    assert await _snapshots(authority) == before
    await _cancel_if_active(workflow_id, reason="Heartbeat rollback acceptance cleanup.")


@pytest.mark.asyncio
async def test_concurrent_same_authority_has_one_winner_and_renews_again():
    workflow_id, authority = await _activate("concurrent")
    before_lineage = await _message_delivery_snapshots(authority)
    barrier = _AsyncBarrier(2)
    results = await asyncio.gather(
        workflow_worker.coordinate_stage_heartbeat(
            _BarrierFactory(barrier),
            authority=authority,
            lease_seconds=120,
        ),
        workflow_worker.coordinate_stage_heartbeat(
            _BarrierFactory(barrier),
            authority=authority,
            lease_seconds=120,
        ),
    )
    assert sorted(result.disposition for result in results) == ["renewed", "stale"]
    renewed = next(result for result in results if result.disposition == "renewed")
    stale = next(result for result in results if result.disposition == "stale")
    assert renewed.authority is not None and renewed.should_continue is True
    assert stale.authority is None and stale.should_continue is False

    old_again = await workflow_worker.coordinate_stage_heartbeat(
        async_session_factory,
        authority=authority,
        lease_seconds=120,
    )
    assert old_again.disposition == "stale"
    assert old_again.heartbeat_at is None
    chained = await workflow_worker.coordinate_stage_heartbeat(
        async_session_factory,
        authority=renewed.authority,
        lease_seconds=120,
    )
    assert chained.disposition == "renewed"
    assert chained.authority is not None
    assert chained.stage_state_version == renewed.stage_state_version + 1
    assert chained.attempt_state_version == renewed.attempt_state_version + 1
    assert await _message_delivery_snapshots(chained.authority) == before_lineage
    await _cancel_if_active(workflow_id, reason="Concurrent heartbeat acceptance cleanup.")


@pytest.mark.asyncio
async def test_expiry_during_workflow_lock_wait_returns_stale_without_mutation():
    workflow_id, authority = await _activate("lock-expiry", lease_seconds=2)
    before = await _snapshots(authority)
    blocker = async_session_factory()
    await blocker.begin()
    await blocker.execute(select(WorkflowRun).where(WorkflowRun.id == workflow_id).with_for_update())
    task = asyncio.create_task(
        workflow_worker.coordinate_stage_heartbeat(
            async_session_factory,
            authority=authority,
            lease_seconds=120,
        )
    )
    try:
        await _wait_for_workflow_lock_wait()
        await _wait_until_db_after(authority.lease_expires_at)
    finally:
        await blocker.rollback()
        await blocker.close()
    result = await asyncio.wait_for(task, timeout=10)
    assert result.disposition == "stale"
    assert result.authority is None
    assert result.heartbeat_at is None
    assert result.stage_state_version == authority.stage_state_version
    assert result.attempt_state_version == authority.attempt_state_version
    assert await _snapshots(authority) == before
    await _cancel_if_active(workflow_id, reason="Lock-expiry heartbeat acceptance cleanup.")


@pytest.mark.asyncio
async def test_recovery_first_and_heartbeat_first_have_single_deterministic_winner():
    recovery_workflow, recovery_authority = await _activate(
        "recovery-first",
        lease_seconds=1,
    )
    await _wait_until_db_after(recovery_authority.lease_expires_at)
    recovered = await _recover_one(recovery_workflow)
    assert recovered is not None
    recovery_loser = await workflow_worker.coordinate_stage_heartbeat(
        async_session_factory,
        authority=recovery_authority,
        lease_seconds=120,
    )
    assert recovery_loser.disposition == "stale"
    assert recovery_loser.authority is None
    assert recovery_loser.heartbeat_at is None

    heartbeat_workflow, heartbeat_authority = await _activate(
        "heartbeat-first",
        lease_seconds=2,
    )
    heartbeat_winner = await workflow_worker.coordinate_stage_heartbeat(
        async_session_factory,
        authority=heartbeat_authority,
        lease_seconds=10,
    )
    assert heartbeat_winner.disposition == "renewed"
    assert heartbeat_winner.authority is not None
    await _wait_until_db_after(heartbeat_authority.lease_expires_at)
    recovery_loser = await _recover_one(heartbeat_workflow)
    assert recovery_loser is None
    async with async_session_factory() as db:
        stage = await db.get(StageRun, heartbeat_authority.stage_run_id)
        attempt = await db.get(StageAttempt, heartbeat_authority.stage_attempt_id)
        assert stage is not None and attempt is not None
        assert stage.status == attempt.status == "running"
        assert stage.lease_expires_at == attempt.lease_expires_at
        assert stage.lease_expires_at == heartbeat_winner.lease_expires_at

    await _cancel_if_active(recovery_workflow, reason="Recovery-first acceptance cleanup.")
    await _cancel_if_active(heartbeat_workflow, reason="Heartbeat-first acceptance cleanup.")


@pytest.mark.asyncio
async def test_cancellation_after_commit_before_confirmation_returns_stale():
    workflow_id, authority = await _activate("cancel-race")
    before_lineage = await _message_delivery_snapshots(authority)
    result = await workflow_worker.coordinate_stage_heartbeat(
        _CancellationRaceFactory(workflow_id),
        authority=authority,
        lease_seconds=120,
    )
    assert result.disposition == "stale"
    assert result.should_continue is False
    assert result.authority is None
    assert result.heartbeat_at is not None
    assert result.stage_state_version == authority.stage_state_version + 1
    assert result.attempt_state_version == authority.attempt_state_version + 1
    assert await _message_delivery_snapshots(authority) == before_lineage
    async with async_session_factory() as db:
        workflow = await db.get(WorkflowRun, workflow_id)
        stage = await db.get(StageRun, authority.stage_run_id)
        attempt = await db.get(StageAttempt, authority.stage_attempt_id)
        assert workflow is not None and workflow.status == "cancelled"
        assert stage is not None and stage.status == "cancelled"
        assert attempt is not None and attempt.status == "cancelled"


@pytest.mark.asyncio
async def test_confirmation_requires_fresh_session_after_committed_mutation():
    workflow_id, authority = await _activate("fresh-session")
    factory = _SameSessionFactory()
    try:
        with pytest.raises(
            workflow_runtime.WorkflowValidation,
            match="distinct fresh session",
        ):
            await workflow_worker.coordinate_stage_heartbeat(
                factory,
                authority=authority,
                lease_seconds=120,
            )
    finally:
        await factory.session.close()

    async with async_session_factory() as db:
        stage = await db.get(StageRun, authority.stage_run_id)
        attempt = await db.get(StageAttempt, authority.stage_attempt_id)
        assert stage is not None and attempt is not None
        assert stage.state_version == authority.stage_state_version + 1
        assert attempt.state_version == authority.attempt_state_version + 1
        assert stage.heartbeat_at == attempt.heartbeat_at
        assert stage.lease_expires_at == attempt.lease_expires_at
    stale = await workflow_worker.coordinate_stage_heartbeat(
        async_session_factory,
        authority=authority,
        lease_seconds=120,
    )
    assert stale.disposition == "stale"
    assert stale.authority is None
    await _cancel_if_active(workflow_id, reason="Fresh-session acceptance cleanup.")


@pytest.mark.asyncio
async def test_direct_workflow_heartbeat_is_fenced_before_sql():
    statements: list[str] = []

    def capture(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", capture)
    try:
        async with async_session_factory() as db:
            with pytest.raises(
                workflow_runtime.WorkflowConflict,
                match="Direct stage heartbeats are disabled",
            ):
                await workflow_runtime.heartbeat_stage(
                    db,
                    uuid.uuid4(),
                    lease_token=uuid.uuid4(),
                    expected_stage_version=1,
                    expected_attempt_version=1,
                    lease_seconds=120,
                )
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", capture)
    assert statements == []


@pytest.mark.asyncio
async def test_database_is_on_exact_contract_phase_revision():
    async with async_session_factory() as db:
        heads = tuple((await db.scalars(text("SELECT version_num FROM alembic_version ORDER BY version_num"))).all())
    assert heads == ("20260824_0004",)
