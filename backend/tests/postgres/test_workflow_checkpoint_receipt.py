"""PostgreSQL acceptance for commit-confirmed receipt-bound checkpoints.

Run only against a disposable database migrated through revision 0004::

    RUN_POSTGRES_TESTS=1 python -m pytest -q -o addopts='' \
      --confcutdir=tests/postgres \
      tests/postgres/test_workflow_checkpoint_receipt.py
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
from app.services.workflow_engine import canonical_json
from tests.postgres._workflow_authority import cancel_active_workflow


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_POSTGRES_TESTS") != "1",
    reason="requires an explicitly authorized disposable PostgreSQL database",
)

ACTOR = projects.ResearchActor(
    name="PostgreSQL Receipt Checkpoint Test",
    actor_id="postgres-receipt-checkpoint",
)


class _InjectedCheckpointFailure(RuntimeError):
    """Test-only failure after both checkpoint rows reached PostgreSQL."""


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
            raise _InjectedCheckpointFailure("rollback after stage and attempt checkpoint flushes")


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
                    reason="Cancellation won before checkpoint confirmation.",
                )
            async with async_session_factory() as db:
                yield db

        return scope()


class _RecoveryRaceFactory:
    def __init__(self, workflow_run_id: uuid.UUID, stage_run_id: uuid.UUID):
        self._workflow_run_id = workflow_run_id
        self._stage_run_id = stage_run_id
        self._calls = 0

    def __call__(self):
        self._calls += 1
        call_number = self._calls

        @asynccontextmanager
        async def scope():
            if call_number == 2:
                async with async_session_factory() as observer:
                    expiry = await observer.scalar(select(StageRun.lease_expires_at).where(StageRun.id == self._stage_run_id))
                assert isinstance(expiry, datetime)
                await _wait_until_db_after(expiry)
                recovered = await _recover_one(self._workflow_run_id)
                assert recovered is not None
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


class _ForbiddenFactory:
    def __init__(self):
        self.calls = 0

    def __call__(self):
        self.calls += 1
        raise AssertionError("hostile checkpoint input opened a database session")


class _HostileCheckpoint(dict):
    """A mapping subclass rejected before the first database statement."""


class _NulHidingString(str):
    def __contains__(self, value: object) -> bool:
        del value
        return False


@pytest_asyncio.fixture(autouse=True)
async def _dispose_engine_pool_between_tests():
    await engine.dispose()
    try:
        yield
    finally:
        await engine.dispose()


def _spec(label: str) -> dict:
    return {
        "objective": f"Validate receipt-bound stage checkpoint: {label}.",
        "intelligence_requirements": [
            "Can only committed delivered receipt authority persist a checkpoint?",
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
        "config": {"acceptance_test": True, "receipt_checkpoint": True},
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
            project_key=f"receipt-checkpoint-{label}-{uuid.uuid4().hex[:10]}",
            name=f"Receipt checkpoint {label}",
            description="Disposable PostgreSQL receipt-checkpoint authority.",
            spec=_spec(label),
        )
        workflow, created = await workflow_runtime.create_workflow(
            db,
            ACTOR,
            project_revision_id=revision.id,
            workflow_type="cti.report",
            idempotency_token=f"receipt-checkpoint-{label}-{uuid.uuid4().hex}",
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
                publisher_id=f"receipt-checkpoint-publisher-{uuid.uuid4().hex[:8]}",
                lease_seconds=120,
            )
            assert claim is not None and claim.message_id == message_id
            await db.commit()

    command = outbox_runtime.StageReceiptCommand(
        claim=claim,
        broker_name="postgres_test_broker",
        broker_message_id=f"receipt-checkpoint-{label}-{claim.cycle_key}",
        broker_receipt_id=hashlib.sha256(f"receipt-checkpoint:{label}:{claim.cycle_key}".encode()).hexdigest(),
        worker_id=f"receipt-checkpoint-worker-{label}",
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
    raise AssertionError("Checkpoint backend did not enter the workflow lock wait")


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


def _checkpoint_checksum(payload: dict) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _changed_columns(
    before: tuple[tuple[str, object], ...],
    after: tuple[tuple[str, object], ...],
) -> set[str]:
    before_values = dict(before)
    after_values = dict(after)
    assert before_values.keys() == after_values.keys()
    return {field_name for field_name, before_value in before_values.items() if after_values[field_name] != before_value}


@pytest.mark.asyncio
async def test_committed_checkpoint_is_canonical_releases_locks_and_updates_s_a():
    workflow_id, authority = await _activate("committed")
    before = await _snapshots(authority)
    payload = {
        "source_cursor": "cursor-9",
        "pages": [3, 1, 2],
        "nested": {"z": True, "a": "source-a"},
    }
    expected_checksum = _checkpoint_checksum(payload)
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
        checkpoint = await workflow_worker.coordinate_stage_checkpoint(
            factory,
            authority=authority,
            checkpoint_schema_version="research-stage-checkpoint-v1",
            checkpoint=payload,
            lease_seconds=120,
        )
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", capture)

    assert checkpoint.disposition == "renewed"
    assert checkpoint.should_continue is True
    assert checkpoint.authority is not None
    assert checkpoint.requested_checkpoint_checksum == expected_checksum
    assert checkpoint.committed_checkpoint_checksum == expected_checksum
    assert checkpoint.previous_checkpoint_version == authority.checkpoint_version == 0
    assert checkpoint.checkpoint_version == 1
    assert checkpoint.stage_state_version == authority.stage_state_version + 1
    assert checkpoint.attempt_state_version == authority.attempt_state_version + 1
    assert checkpoint.heartbeat_at is not None
    assert checkpoint.authority.checkpoint_version == checkpoint.checkpoint_version
    assert checkpoint.authority.lease_expires_at == checkpoint.lease_expires_at
    assert factory.active == 0 and factory.exits == 2
    assert _ImmediateConstraintsSession.immediate_checks == 1
    assert (
        _locked_table_order(statements)
        == [
            "workflow_runs",
            "stage_runs",
            "outbox_messages",
            "outbox_delivery_attempts",
            "stage_attempts",
        ]
        * 2
    )
    updates = [statement for statement in statements if statement.lstrip().upper().startswith("UPDATE")]
    assert len(updates) == 2
    assert "UPDATE stage_runs" in updates[0]
    assert "UPDATE stage_attempts" in updates[1]

    await _assert_nowait_lineage_unlocked(checkpoint.authority)
    after = await _snapshots(checkpoint.authority)
    assert after[0] == before[0]
    assert after[2:4] == before[2:4]
    assert _changed_columns(before[1], after[1]) == {
        "state_version",
        "checkpoint",
        "checkpoint_version",
        "checkpoint_checksum",
        "heartbeat_at",
        "lease_expires_at",
        "updated_at",
    }
    assert _changed_columns(before[4], after[4]) == {
        "state_version",
        "checkpoint_end_version",
        "heartbeat_at",
        "lease_expires_at",
    }
    async with async_session_factory() as db:
        stage = await db.get(StageRun, authority.stage_run_id)
        attempt = await db.get(StageAttempt, authority.stage_attempt_id)
        assert stage is not None and attempt is not None
        assert stage.checkpoint == payload
        assert stage.checkpoint_checksum == expected_checksum
        assert stage.checkpoint_version == attempt.checkpoint_end_version == 1
        assert stage.state_version == checkpoint.stage_state_version
        assert attempt.state_version == checkpoint.attempt_state_version
        assert stage.heartbeat_at == attempt.heartbeat_at == checkpoint.heartbeat_at
        assert stage.lease_expires_at == attempt.lease_expires_at == checkpoint.lease_expires_at
    await _cancel_if_active(workflow_id, reason="Committed checkpoint acceptance cleanup.")


@pytest.mark.asyncio
async def test_failure_after_both_checkpoint_flushes_rolls_back_every_effect():
    workflow_id, authority = await _activate("rollback")
    before = await _snapshots(authority)
    maker = async_sessionmaker(
        engine,
        class_=_FailAfterAttemptFlushSession,
        expire_on_commit=False,
    )
    with pytest.raises(_InjectedCheckpointFailure):
        await workflow_worker.coordinate_stage_checkpoint(
            maker,
            authority=authority,
            checkpoint_schema_version="research-stage-checkpoint-v1",
            checkpoint={"cursor": "must-rollback"},
            lease_seconds=120,
        )
    assert await _snapshots(authority) == before
    await _cancel_if_active(workflow_id, reason="Checkpoint rollback acceptance cleanup.")


@pytest.mark.asyncio
async def test_hostile_input_is_zero_sql_and_wrong_schema_is_zero_mutation():
    workflow_id, authority = await _activate("invalid")
    before = await _snapshots(authority)
    statements: list[str] = []
    forbidden_factory = _ForbiddenFactory()

    def capture(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", capture)
    try:
        with pytest.raises(
            workflow_runtime.WorkflowValidation,
            match="exact JSON object",
        ):
            await workflow_worker.coordinate_stage_checkpoint(
                forbidden_factory,
                authority=authority,
                checkpoint_schema_version="research-stage-checkpoint-v1",
                checkpoint=_HostileCheckpoint(cursor="hostile"),
                lease_seconds=120,
            )
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", capture)
    assert statements == []
    assert forbidden_factory.calls == 0

    with pytest.raises(
        workflow_runtime.WorkflowCheckpointConflict,
        match="schema version",
    ):
        await workflow_worker.coordinate_stage_checkpoint(
            async_session_factory,
            authority=authority,
            checkpoint_schema_version="wrong-checkpoint-v1",
            checkpoint={"cursor": "wrong-schema"},
            lease_seconds=120,
        )
    assert await _snapshots(authority) == before

    event.listen(engine.sync_engine, "before_cursor_execute", capture)
    try:
        for nul_payload in (
            {"value": "\x00"},
            {"\x00key": "value"},
            {"value": _NulHidingString("\x00")},
            {_NulHidingString("\x00key"): "value"},
        ):
            statements.clear()
            with pytest.raises(
                workflow_runtime.WorkflowValidation,
                match=r"U\+0000",
            ):
                await workflow_worker.coordinate_stage_checkpoint(
                    forbidden_factory,
                    authority=authority,
                    checkpoint_schema_version="research-stage-checkpoint-v1",
                    checkpoint=nul_payload,
                    lease_seconds=120,
                )
            assert statements == []
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", capture)
    assert forbidden_factory.calls == 0
    assert await _snapshots(authority) == before
    await _cancel_if_active(workflow_id, reason="Invalid checkpoint acceptance cleanup.")


@pytest.mark.asyncio
async def test_concurrent_same_authority_has_one_winner_and_chains_new_checkpoint():
    workflow_id, authority = await _activate("concurrent")
    before_lineage = await _message_delivery_snapshots(authority)
    payload = {"cursor": "first"}
    barrier = _AsyncBarrier(2)
    results = await asyncio.gather(
        workflow_worker.coordinate_stage_checkpoint(
            _BarrierFactory(barrier),
            authority=authority,
            checkpoint_schema_version="research-stage-checkpoint-v1",
            checkpoint=payload,
            lease_seconds=120,
        ),
        workflow_worker.coordinate_stage_checkpoint(
            _BarrierFactory(barrier),
            authority=authority,
            checkpoint_schema_version="research-stage-checkpoint-v1",
            checkpoint=payload,
            lease_seconds=120,
        ),
    )
    assert sorted(result.disposition for result in results) == ["renewed", "stale"]
    renewed = next(result for result in results if result.disposition == "renewed")
    stale = next(result for result in results if result.disposition == "stale")
    assert renewed.authority is not None and renewed.checkpoint_version == 1
    assert stale.authority is None and stale.committed_checkpoint_checksum is None

    old_again = await workflow_worker.coordinate_stage_checkpoint(
        async_session_factory,
        authority=authority,
        checkpoint_schema_version="research-stage-checkpoint-v1",
        checkpoint={"cursor": "old-stale"},
        lease_seconds=120,
    )
    assert old_again.disposition == "stale"
    assert old_again.heartbeat_at is None
    chained = await workflow_worker.coordinate_stage_checkpoint(
        async_session_factory,
        authority=renewed.authority,
        checkpoint_schema_version="research-stage-checkpoint-v1",
        checkpoint={"cursor": "second"},
        lease_seconds=120,
    )
    assert chained.disposition == "renewed"
    assert chained.authority is not None
    assert chained.checkpoint_version == renewed.checkpoint_version + 1 == 2
    assert chained.stage_state_version == renewed.stage_state_version + 1
    assert chained.attempt_state_version == renewed.attempt_state_version + 1
    assert await _message_delivery_snapshots(chained.authority) == before_lineage
    await _cancel_if_active(workflow_id, reason="Concurrent checkpoint acceptance cleanup.")


@pytest.mark.asyncio
async def test_heartbeat_and_checkpoint_authorities_interoperate_bidirectionally():
    workflow_id, authority = await _activate("interoperate")
    heartbeat_one = await workflow_worker.coordinate_stage_heartbeat(
        async_session_factory,
        authority=authority,
        lease_seconds=120,
    )
    assert heartbeat_one.disposition == "renewed" and heartbeat_one.authority is not None
    checkpoint = await workflow_worker.coordinate_stage_checkpoint(
        async_session_factory,
        authority=heartbeat_one.authority,
        checkpoint_schema_version="research-stage-checkpoint-v1",
        checkpoint={"cursor": "after-heartbeat"},
        lease_seconds=120,
    )
    assert checkpoint.disposition == "renewed" and checkpoint.authority is not None
    assert checkpoint.checkpoint_version == 1
    heartbeat_two = await workflow_worker.coordinate_stage_heartbeat(
        async_session_factory,
        authority=checkpoint.authority,
        lease_seconds=120,
    )
    assert heartbeat_two.disposition == "renewed" and heartbeat_two.authority is not None
    assert heartbeat_two.checkpoint_version == checkpoint.checkpoint_version
    assert heartbeat_two.stage_state_version == checkpoint.stage_state_version + 1
    assert heartbeat_two.attempt_state_version == checkpoint.attempt_state_version + 1
    await _cancel_if_active(workflow_id, reason="Checkpoint interoperability cleanup.")


@pytest.mark.asyncio
async def test_expiry_during_workflow_lock_wait_returns_stale_without_mutation():
    workflow_id, authority = await _activate("lock-expiry", lease_seconds=2)
    before = await _snapshots(authority)
    blocker = async_session_factory()
    await blocker.begin()
    await blocker.execute(select(WorkflowRun).where(WorkflowRun.id == workflow_id).with_for_update())
    task = asyncio.create_task(
        workflow_worker.coordinate_stage_checkpoint(
            async_session_factory,
            authority=authority,
            checkpoint_schema_version="research-stage-checkpoint-v1",
            checkpoint={"cursor": "blocked"},
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
    assert result.committed_checkpoint_checksum is None
    assert result.checkpoint_version == authority.checkpoint_version
    assert await _snapshots(authority) == before
    await _cancel_if_active(workflow_id, reason="Lock-expiry checkpoint cleanup.")


@pytest.mark.asyncio
async def test_cancellation_before_confirmation_returns_stale_without_authority():
    workflow_id, authority = await _activate("cancel-race")
    before_lineage = await _message_delivery_snapshots(authority)
    result = await workflow_worker.coordinate_stage_checkpoint(
        _CancellationRaceFactory(workflow_id),
        authority=authority,
        checkpoint_schema_version="research-stage-checkpoint-v1",
        checkpoint={"cursor": "committed-before-cancel"},
        lease_seconds=120,
    )
    assert result.disposition == "stale"
    assert result.should_continue is False
    assert result.authority is None
    assert result.heartbeat_at is not None
    assert result.committed_checkpoint_checksum == result.requested_checkpoint_checksum
    assert result.checkpoint_version == authority.checkpoint_version + 1
    assert await _message_delivery_snapshots(authority) == before_lineage
    async with async_session_factory() as db:
        workflow = await db.get(WorkflowRun, workflow_id)
        stage = await db.get(StageRun, authority.stage_run_id)
        attempt = await db.get(StageAttempt, authority.stage_attempt_id)
        assert workflow is not None and workflow.status == "cancelled"
        assert stage is not None and stage.status == "cancelled"
        assert attempt is not None and attempt.status == "cancelled"


@pytest.mark.asyncio
async def test_recovery_before_confirmation_returns_stale_without_authority():
    workflow_id, authority = await _activate("recovery-race", lease_seconds=1)
    result = await workflow_worker.coordinate_stage_checkpoint(
        _RecoveryRaceFactory(workflow_id, authority.stage_run_id),
        authority=authority,
        checkpoint_schema_version="research-stage-checkpoint-v1",
        checkpoint={"cursor": "committed-before-recovery"},
        lease_seconds=1,
    )
    assert result.disposition == "stale"
    assert result.should_continue is False
    assert result.authority is None
    assert result.heartbeat_at is not None
    assert result.committed_checkpoint_checksum == result.requested_checkpoint_checksum
    assert result.checkpoint_version == authority.checkpoint_version + 1
    async with async_session_factory() as db:
        stage = await db.get(StageRun, authority.stage_run_id)
        attempt = await db.get(StageAttempt, authority.stage_attempt_id)
        assert stage is not None and stage.status == "retry_wait"
        assert attempt is not None and attempt.status == "abandoned"
        assert attempt.checkpoint_end_version == result.checkpoint_version
    await _cancel_if_active(workflow_id, reason="Recovery-race checkpoint cleanup.")


@pytest.mark.asyncio
async def test_confirmation_requires_fresh_session_after_committed_checkpoint():
    workflow_id, authority = await _activate("fresh-session")
    payload = {"cursor": "fresh-session"}
    factory = _SameSessionFactory()
    try:
        with pytest.raises(
            workflow_runtime.WorkflowValidation,
            match="distinct fresh session",
        ):
            await workflow_worker.coordinate_stage_checkpoint(
                factory,
                authority=authority,
                checkpoint_schema_version="research-stage-checkpoint-v1",
                checkpoint=payload,
                lease_seconds=120,
            )
    finally:
        await factory.session.close()

    async with async_session_factory() as db:
        stage = await db.get(StageRun, authority.stage_run_id)
        attempt = await db.get(StageAttempt, authority.stage_attempt_id)
        assert stage is not None and attempt is not None
        assert stage.checkpoint == payload
        assert stage.checkpoint_checksum == _checkpoint_checksum(payload)
        assert stage.checkpoint_version == attempt.checkpoint_end_version == 1
        assert stage.state_version == authority.stage_state_version + 1
        assert attempt.state_version == authority.attempt_state_version + 1
    stale = await workflow_worker.coordinate_stage_checkpoint(
        async_session_factory,
        authority=authority,
        checkpoint_schema_version="research-stage-checkpoint-v1",
        checkpoint={"cursor": "old-authority"},
        lease_seconds=120,
    )
    assert stale.disposition == "stale"
    assert stale.authority is None
    await _cancel_if_active(workflow_id, reason="Fresh-session checkpoint cleanup.")


@pytest.mark.asyncio
async def test_direct_workflow_checkpoint_is_fenced_before_sql():
    statements: list[str] = []

    def capture(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", capture)
    try:
        async with async_session_factory() as db:
            with pytest.raises(
                workflow_runtime.WorkflowConflict,
                match="Direct stage checkpoints are disabled",
            ):
                await workflow_runtime.checkpoint_stage(
                    db,
                    uuid.uuid4(),
                    lease_token=uuid.uuid4(),
                    expected_stage_version=1,
                    expected_attempt_version=1,
                    expected_checkpoint_version=0,
                    checkpoint_schema_version="research-stage-checkpoint-v1",
                    checkpoint={"cursor": "direct"},
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
