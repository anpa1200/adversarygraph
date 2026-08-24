"""PostgreSQL acceptance for commit-confirmed receipt-bound stage failure.

Run only against a disposable database migrated through revision 0004::

    RUN_POSTGRES_TESTS=1 python -m pytest -q -o addopts='' \
      --confcutdir=tests/postgres \
      tests/postgres/test_workflow_failure_receipt.py
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
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


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_POSTGRES_TESTS") != "1",
    reason="requires an explicitly authorized disposable PostgreSQL database",
)

ACTOR = projects.ResearchActor(
    name="PostgreSQL Receipt Failure Test",
    actor_id="postgres-receipt-failure",
)


class _InjectedFailure(RuntimeError):
    """Test-only failure after the retry message reaches PostgreSQL."""


class _FailAfterRetryMessageSession(AsyncSession):
    async def flush(self, objects=None):
        await super().flush(objects)
        if objects and any(type(value) is OutboxMessage and value.emission_kind == "retry_scheduled" for value in objects):
            raise _InjectedFailure("rollback after failed attempt, stage, and retry message flushed")


class _ImmediateConstraintsSession(AsyncSession):
    immediate_checks = 0

    async def flush(self, objects=None):
        await super().flush(objects)
        terminal_workflow = objects and any(
            type(value) is WorkflowRun and value.status in {"degraded", "failed", "dead_lettered"} for value in objects
        )
        retry_message = objects and any(type(value) is OutboxMessage and value.emission_kind == "retry_scheduled" for value in objects)
        if terminal_workflow or retry_message:
            await self.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
            type(self).immediate_checks += 1


class _PauseAfterStageLockSession(AsyncSession):
    stage_locked: asyncio.Event | None = None
    release: asyncio.Event | None = None
    paused = False

    async def execute(self, statement, params=None, **kwargs):
        result = await super().execute(statement, params=params, **kwargs)
        rendered = str(statement)
        if not type(self).paused and "FROM stage_runs" in rendered and "FOR UPDATE" in rendered:
            stage_locked = type(self).stage_locked
            release = type(self).release
            assert stage_locked is not None and release is not None
            type(self).paused = True
            stage_locked.set()
            await asyncio.wait_for(release.wait(), timeout=10)
        return result


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


class _ForbiddenFactory:
    def __init__(self):
        self.calls = 0

    def __call__(self):
        self.calls += 1
        raise AssertionError("invalid failure input opened a database session")


class _HostileString(str):
    """An exact-type boundary adversary rejected before session construction."""


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

    def __call__(self):
        @asynccontextmanager
        async def scope():
            async with async_session_factory() as db:
                await self._barrier.wait()
                yield db

        return scope()


@dataclass(frozen=True, slots=True)
class _FailureFixture:
    workflow_id: uuid.UUID
    source: outbox_runtime.ExecutableStageAuthority
    running_peer: outbox_runtime.ExecutableStageAuthority | None = None
    idle_message_id: uuid.UUID | None = None
    active_claim: outbox_runtime.ClaimedOutboxDelivery | None = None


@pytest_asyncio.fixture(autouse=True)
async def _dispose_engine_pool_between_tests():
    await engine.dispose()
    try:
        yield
    finally:
        await engine.dispose()


def _spec(label: str) -> dict:
    return {
        "objective": f"Validate receipt-bound stage failure: {label}.",
        "intelligence_requirements": [
            "Can only committed delivered receipt authority fail a stage?",
        ],
        "output_targets": ["canonical_intelligence"],
        "tlp": "TLP:AMBER",
    }


def _stage_definition(
    stage_key: str,
    ordinal: int,
    *,
    depends_on: list[str] | None = None,
    required: bool = True,
    max_attempts: int = 3,
) -> dict:
    return {
        "stage_key": stage_key,
        "stage_type": f"test.{stage_key}",
        "stage_version": "1.0.0",
        "ordinal": ordinal,
        "depends_on": depends_on or [],
        "required": required,
        "priority": 0,
        "max_attempts": max_attempts,
        "config_schema_version": "research-stage-config-v1",
        "checkpoint_schema_version": "research-stage-checkpoint-v1",
        "config": {"acceptance_test": True, "stage": stage_key},
        "retry_policy": {
            "base_delay_seconds": 1,
            "max_delay_seconds": 1,
            "jitter_percent": 0,
        },
    }


def _plan(kind: str) -> list[dict]:
    if kind == "retry":
        return [_stage_definition("source", 1)]
    if kind == "dead_lettered":
        return [_stage_definition("source", 1, max_attempts=1)]
    if kind == "optional":
        return [
            _stage_definition("source", 1, required=False),
            _stage_definition("dependent", 2, depends_on=["source"]),
        ]
    if kind == "required":
        return [
            _stage_definition("source", 1),
            _stage_definition("running_peer", 2),
            _stage_definition("idle_peer", 3),
            _stage_definition("active_peer", 4),
            _stage_definition("dependent", 5, depends_on=["source"]),
        ]
    raise AssertionError(f"unknown failure fixture kind: {kind}")


async def _new_workflow(label: str, *, kind: str) -> uuid.UUID:
    safe_label = label.replace("_", "-")
    async with async_session_factory() as db:
        _, revision = await projects.create_project(
            db,
            ACTOR,
            project_key=f"receipt-failure-{safe_label}-{uuid.uuid4().hex[:10]}",
            name=f"Receipt failure {label}",
            description="Disposable PostgreSQL receipt-failure authority.",
            spec=_spec(label),
        )
        workflow, created = await workflow_runtime.create_workflow(
            db,
            ACTOR,
            project_revision_id=revision.id,
            workflow_type="cti.report",
            idempotency_token=f"receipt-failure-{label}-{uuid.uuid4().hex}",
            input_manifest={"report_id": label, "source_ids": ["source-a"]},
            stage_plan=_plan(kind),
            priority=0,
        )
        assert created is True
        workflow_id = uuid.UUID(str(workflow.id))
        await db.commit()
        return workflow_id


async def _message_id(workflow_id: uuid.UUID, stage_key: str) -> uuid.UUID:
    async with async_session_factory() as db:
        value = await db.scalar(
            select(OutboxMessage.id).where(
                OutboxMessage.workflow_run_id == workflow_id,
                OutboxMessage.stage_key == stage_key,
                OutboxMessage.redrive_ordinal == 0,
            )
        )
    assert isinstance(value, uuid.UUID)
    return uuid.UUID(str(value))


@asynccontextmanager
async def _isolate_outbox_queue(allowed_message_ids: set[uuid.UUID]):
    async with async_session_factory() as blocker:
        await blocker.execute(
            select(OutboxMessage.id)
            .where(
                OutboxMessage.status.in_(("pending", "retry_wait")),
                OutboxMessage.id.not_in(allowed_message_ids),
            )
            .order_by(OutboxMessage.id.asc())
            .with_for_update()
        )
        try:
            yield
        finally:
            await blocker.rollback()


async def _claim_message(message_id: uuid.UUID) -> outbox_runtime.ClaimedOutboxDelivery:
    async with _isolate_outbox_queue({message_id}):
        async with async_session_factory() as db:
            claim = await outbox_runtime.claim_outbox_delivery(
                db,
                publisher_id=f"receipt-failure-publisher-{uuid.uuid4().hex[:8]}",
                lease_seconds=120,
            )
            assert claim is not None and claim.message_id == message_id
            await db.commit()
            return claim


async def _activate_stage(
    workflow_id: uuid.UUID,
    stage_key: str,
    *,
    label: str,
    lease_seconds: int = 120,
) -> outbox_runtime.ExecutableStageAuthority:
    message_id = await _message_id(workflow_id, stage_key)
    claim = await _claim_message(message_id)
    command = outbox_runtime.StageReceiptCommand(
        claim=claim,
        broker_name="postgres_test_broker",
        broker_message_id=f"receipt-failure-{label}-{claim.cycle_key}",
        broker_receipt_id=hashlib.sha256(f"receipt-failure:{label}:{claim.cycle_key}".encode()).hexdigest(),
        worker_id=f"receipt-failure-worker-{label}",
        lease_seconds=lease_seconds,
    )
    coordinated = await outbox_coordinator.coordinate_stage_receipt(
        async_session_factory,
        command=command,
    )
    assert coordinated.disposition == "activated"
    assert coordinated.should_execute is True
    assert coordinated.authority is not None
    return coordinated.authority


async def _failure_fixture(
    label: str,
    *,
    kind: str,
    lease_seconds: int = 120,
) -> _FailureFixture:
    workflow_id = await _new_workflow(label, kind=kind)
    source = await _activate_stage(
        workflow_id,
        "source",
        label=f"{label}-source",
        lease_seconds=lease_seconds,
    )
    if kind != "required":
        return _FailureFixture(workflow_id=workflow_id, source=source)

    running_peer = await _activate_stage(
        workflow_id,
        "running_peer",
        label=f"{label}-running-peer",
        lease_seconds=lease_seconds,
    )
    idle_message_id = await _message_id(workflow_id, "idle_peer")
    active_message_id = await _message_id(workflow_id, "active_peer")
    active_claim = await _claim_message(active_message_id)
    return _FailureFixture(
        workflow_id=workflow_id,
        source=source,
        running_peer=running_peer,
        idle_message_id=idle_message_id,
        active_claim=active_claim,
    )


def _row_snapshot(value: object) -> tuple[tuple[str, object], ...]:
    snapshot: list[tuple[str, object]] = []
    for column in type(value).__table__.columns:
        field_value = getattr(value, column.key)
        if type(field_value) in {dict, list}:
            field_value = json.dumps(field_value, sort_keys=True, separators=(",", ":"))
        snapshot.append((column.key, field_value))
    return tuple(snapshot)


async def _graph_snapshot(workflow_id: uuid.UUID):
    async with async_session_factory() as db:
        workflow = await db.get(WorkflowRun, workflow_id)
        stages = tuple(
            (
                await db.scalars(
                    select(StageRun).where(StageRun.workflow_run_id == workflow_id).order_by(StageRun.ordinal.asc(), StageRun.id.asc())
                )
            ).all()
        )
        messages = tuple(
            (
                await db.scalars(select(OutboxMessage).where(OutboxMessage.workflow_run_id == workflow_id).order_by(OutboxMessage.id.asc()))
            ).all()
        )
        deliveries = tuple(
            (
                await db.scalars(
                    select(OutboxDeliveryAttempt)
                    .join(OutboxMessage, OutboxMessage.id == OutboxDeliveryAttempt.message_id)
                    .where(OutboxMessage.workflow_run_id == workflow_id)
                    .order_by(OutboxDeliveryAttempt.id.asc())
                )
            ).all()
        )
        attempts = tuple(
            (
                await db.scalars(
                    select(StageAttempt)
                    .join(StageRun, StageRun.id == StageAttempt.stage_run_id)
                    .where(StageRun.workflow_run_id == workflow_id)
                    .order_by(StageAttempt.id.asc())
                )
            ).all()
        )
        assert workflow is not None and stages
        return tuple(_row_snapshot(value) for value in (workflow, *stages, *messages, *deliveries, *attempts))


async def _source_lineage_snapshot(authority: outbox_runtime.ExecutableStageAuthority):
    async with async_session_factory() as db:
        message = await db.get(OutboxMessage, authority.message_id)
        delivery = await db.get(OutboxDeliveryAttempt, authority.delivery_attempt_id)
        assert message is not None and delivery is not None
        return _row_snapshot(message), _row_snapshot(delivery)


async def _wait_until_db_after(moment: datetime) -> None:
    for _ in range(300):
        async with engine.connect() as connection:
            now = await connection.scalar(select(func.clock_timestamp()))
        if isinstance(now, datetime) and now > moment:
            return
        await asyncio.sleep(0.02)
    raise AssertionError("PostgreSQL clock did not advance past the lease boundary")


async def _wait_for_workflow_lock_wait() -> None:
    for _ in range(250):
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
    raise AssertionError("Failure backend did not enter the workflow lock wait")


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


async def _assert_nowait_unlocked(
    *,
    workflow_id: uuid.UUID,
    message_ids: tuple[uuid.UUID, ...],
    delivery_ids: tuple[uuid.UUID, ...],
    attempt_ids: tuple[uuid.UUID, ...],
) -> None:
    async with async_session_factory() as db:
        async with db.begin():
            stage_ids = tuple((await db.scalars(select(StageRun.id).where(StageRun.workflow_run_id == workflow_id))).all())
            rows = (
                (WorkflowRun, (workflow_id,)),
                (StageRun, stage_ids),
                (OutboxMessage, message_ids),
                (OutboxDeliveryAttempt, delivery_ids),
                (StageAttempt, attempt_ids),
            )
            for model, identities in rows:
                for row_id in identities:
                    row = await db.scalar(
                        select(model)
                        .where(model.id == row_id)
                        .execution_options(populate_existing=True, autoflush=False)
                        .with_for_update(nowait=True)
                    )
                    assert row is not None
            await db.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kind", "retryable", "expected_decision", "expected_stage", "expected_workflow"),
    [
        ("retry", True, "retry", "retry_wait", "running"),
        ("optional", False, "failed", "failed", "degraded"),
        ("dead_lettered", True, "dead_lettered", "dead_lettered", "dead_lettered"),
    ],
)
async def test_committed_failure_is_exact_atomic_and_releases_every_lock(
    kind: str,
    retryable: bool,
    expected_decision: str,
    expected_stage: str,
    expected_workflow: str,
):
    fixture = await _failure_fixture(
        f"committed-{kind}",
        kind=kind,
    )
    source_lineage = await _source_lineage_snapshot(fixture.source)
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
        recorded = await workflow_worker.coordinate_stage_fail(
            factory,
            authority=fixture.source,
            error_text="Provider timed out while fetching the disposable report"
            if retryable
            else "The disposable report cannot be parsed safely",
            error_code="source.fetch_timeout" if retryable else "source.invalid_report",
            retryable=retryable,
            error_class="TimeoutError" if retryable else "InvalidReport",
        )
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", capture)

    assert recorded.disposition == "recorded"
    assert recorded.should_continue is False
    assert recorded.should_ack is True
    assert recorded.should_retry is (expected_decision == "retry")
    assert recorded.decision == expected_decision
    assert recorded.workflow_status == expected_workflow
    assert recorded.error_code == ("source.fetch_timeout" if retryable else "source.invalid_report")
    assert recorded.error_class == ("TimeoutError" if retryable else "InvalidReport")
    assert recorded.retryable is retryable
    assert recorded.attempt_completed_at is not None
    assert recorded.stage_state_version == fixture.source.stage_state_version + 1
    assert recorded.attempt_state_version == fixture.source.attempt_state_version + 1
    assert factory.active == 0 and factory.exits == 1
    assert _ImmediateConstraintsSession.immediate_checks == 1
    assert _locked_table_order(statements) == [
        "workflow_runs",
        "stage_runs",
        "outbox_messages",
        "outbox_delivery_attempts",
        "stage_attempts",
    ]

    async with async_session_factory() as db:
        workflow = await db.get(WorkflowRun, fixture.workflow_id)
        source = await db.get(StageRun, fixture.source.stage_run_id)
        attempt = await db.get(StageAttempt, fixture.source.stage_attempt_id)
        retry_messages = tuple(
            (
                await db.scalars(
                    select(OutboxMessage).where(
                        OutboxMessage.workflow_run_id == fixture.workflow_id,
                        OutboxMessage.emission_kind == "retry_scheduled",
                    )
                )
            ).all()
        )
        assert workflow is not None and source is not None and attempt is not None
        assert workflow.status == expected_workflow
        assert source.status == expected_stage
        assert attempt.status == "failed"
        assert source.last_error_code == attempt.error_code == recorded.error_code
        assert source.last_error_summary == attempt.error_summary == recorded.error_summary
        assert source.last_error_retryable is attempt.retryable is retryable
        assert source.completed_at == (None if expected_decision == "retry" else recorded.stage_completed_at)
        assert attempt.completed_at == recorded.attempt_completed_at
        assert source.lease_token is None
        if expected_decision == "retry":
            assert recorded.retry_emission is not None
            assert recorded.next_attempt_at is not None
            assert recorded.workflow_state_version == fixture.source.workflow_state_version
            assert len(retry_messages) == 1
            message = retry_messages[0]
            assert message.id == recorded.retry_emission.message_id
            assert message.causation_id == attempt.id
            assert message.aggregate_version == source.state_version
            assert message.target_attempt_number == source.attempt_count + 1
            assert message.available_at == source.next_attempt_at == recorded.next_attempt_at
        else:
            assert recorded.retry_emission is None
            assert recorded.next_attempt_at is None
            assert retry_messages == ()
            assert recorded.workflow_state_version == fixture.source.workflow_state_version + 1
            assert workflow.completed_at == recorded.workflow_completed_at == recorded.attempt_completed_at
            if kind == "optional":
                dependent = await db.scalar(
                    select(StageRun).where(
                        StageRun.workflow_run_id == fixture.workflow_id,
                        StageRun.stage_key == "dependent",
                    )
                )
                assert dependent is not None and dependent.status == "skipped"
                assert recorded.skipped_stage_ids == (uuid.UUID(str(dependent.id)),)

        all_message_ids = tuple(
            (await db.scalars(select(OutboxMessage.id).where(OutboxMessage.workflow_run_id == fixture.workflow_id))).all()
        )
        all_delivery_ids = tuple(
            (
                await db.scalars(
                    select(OutboxDeliveryAttempt.id)
                    .join(OutboxMessage, OutboxMessage.id == OutboxDeliveryAttempt.message_id)
                    .where(OutboxMessage.workflow_run_id == fixture.workflow_id)
                )
            ).all()
        )
        all_attempt_ids = tuple(
            (
                await db.scalars(
                    select(StageAttempt.id)
                    .join(StageRun, StageRun.id == StageAttempt.stage_run_id)
                    .where(StageRun.workflow_run_id == fixture.workflow_id)
                )
            ).all()
        )

    assert await _source_lineage_snapshot(fixture.source) == source_lineage
    await _assert_nowait_unlocked(
        workflow_id=fixture.workflow_id,
        message_ids=tuple(uuid.UUID(str(value)) for value in all_message_ids),
        delivery_ids=tuple(uuid.UUID(str(value)) for value in all_delivery_ids),
        attempt_ids=tuple(uuid.UUID(str(value)) for value in all_attempt_ids),
    )


@pytest.mark.asyncio
async def test_required_failure_cancels_exact_suffix_and_running_peer_atomically():
    fixture = await _failure_fixture(
        "required-terminal",
        kind="required",
    )
    assert fixture.running_peer is not None
    assert fixture.idle_message_id is not None
    assert fixture.active_claim is not None
    source_lineage = await _source_lineage_snapshot(fixture.source)
    peer_lineage = await _source_lineage_snapshot(fixture.running_peer)
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
        recorded = await workflow_worker.coordinate_stage_fail(
            factory,
            authority=fixture.source,
            error_text="Required source evidence is invalid",
            error_code="source.invalid_report",
            retryable=False,
            error_class="InvalidReport",
        )
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", capture)

    assert recorded.disposition == "recorded"
    assert recorded.decision == "failed"
    assert recorded.workflow_status == "failed"
    assert recorded.workflow_state_version == fixture.source.workflow_state_version + 1
    assert recorded.cancelled_message_ids == tuple(
        sorted(
            (fixture.idle_message_id, fixture.active_claim.message_id),
            key=lambda value: value.int,
        )
    )
    assert recorded.cancelled_delivery_ids == (fixture.active_claim.delivery_attempt_id,)
    assert recorded.cancelled_attempt_ids == (fixture.running_peer.stage_attempt_id,)
    assert recorded.retry_emission is None
    assert factory.active == 0 and factory.exits == 1
    assert _ImmediateConstraintsSession.immediate_checks == 1

    locked_order = _locked_table_order(statements)
    assert locked_order[:2] == ["workflow_runs", "stage_runs"]
    message_count = locked_order.count("outbox_messages")
    delivery_count = locked_order.count("outbox_delivery_attempts")
    attempt_count = locked_order.count("stage_attempts")
    assert locked_order == [
        "workflow_runs",
        "stage_runs",
        *("outbox_messages",) * message_count,
        *("outbox_delivery_attempts",) * delivery_count,
        *("stage_attempts",) * attempt_count,
    ]
    updates = [statement for statement in statements if statement.lstrip().upper().startswith("UPDATE")]
    table_order = []
    for statement in updates:
        for table in (
            "outbox_delivery_attempts",
            "outbox_messages",
            "stage_attempts",
            "stage_runs",
            "workflow_runs",
        ):
            if f"UPDATE {table}" in statement:
                table_order.append(table)
                break
    assert table_order == [
        *("outbox_delivery_attempts",) * len(recorded.cancelled_delivery_ids),
        *("outbox_messages",) * len(recorded.cancelled_message_ids),
        *("stage_attempts",) * 2,
        *("stage_runs",) * 5,
        "workflow_runs",
    ]

    async with async_session_factory() as db:
        workflow = await db.get(WorkflowRun, fixture.workflow_id)
        stages = {
            stage.stage_key: stage
            for stage in (await db.scalars(select(StageRun).where(StageRun.workflow_run_id == fixture.workflow_id))).all()
        }
        source_attempt = await db.get(StageAttempt, fixture.source.stage_attempt_id)
        peer_attempt = await db.get(StageAttempt, fixture.running_peer.stage_attempt_id)
        idle_message = await db.get(OutboxMessage, fixture.idle_message_id)
        active_message = await db.get(OutboxMessage, fixture.active_claim.message_id)
        active_delivery = await db.get(
            OutboxDeliveryAttempt,
            fixture.active_claim.delivery_attempt_id,
        )
        assert workflow is not None and workflow.status == "failed"
        assert source_attempt is not None and source_attempt.status == "failed"
        assert peer_attempt is not None and peer_attempt.status == "cancelled"
        assert stages["source"].status == "failed"
        assert {stages[key].status for key in ("running_peer", "idle_peer", "active_peer", "dependent")} == {"cancelled"}
        assert idle_message is not None and idle_message.status == "cancelled"
        assert active_message is not None and active_message.status == "cancelled"
        assert active_delivery is not None and active_delivery.status == "cancelled"
        assert active_delivery.completed_at <= recorded.attempt_completed_at
        assert idle_message.cancelled_at <= recorded.attempt_completed_at
        assert active_message.cancelled_at <= recorded.attempt_completed_at

    assert await _source_lineage_snapshot(fixture.source) == source_lineage
    assert await _source_lineage_snapshot(fixture.running_peer) == peer_lineage


@pytest.mark.asyncio
async def test_failure_after_retry_message_flush_rolls_back_every_effect():
    fixture = await _failure_fixture(
        "rollback",
        kind="retry",
    )
    before = await _graph_snapshot(fixture.workflow_id)
    maker = async_sessionmaker(
        engine,
        class_=_FailAfterRetryMessageSession,
        expire_on_commit=False,
    )
    with pytest.raises(_InjectedFailure):
        await workflow_worker.coordinate_stage_fail(
            maker,
            authority=fixture.source,
            error_text="Provider timed out",
            error_code="source.fetch_timeout",
            retryable=True,
            error_class="TimeoutError",
        )
    assert await _graph_snapshot(fixture.workflow_id) == before
    async with async_session_factory() as db:
        count = await db.scalar(
            select(func.count())
            .select_from(OutboxMessage)
            .where(
                OutboxMessage.workflow_run_id == fixture.workflow_id,
                OutboxMessage.emission_kind == "retry_scheduled",
            )
        )
        assert count == 0


@pytest.mark.asyncio
async def test_concurrent_same_failure_authority_has_one_recording_and_one_stale_result():
    fixture = await _failure_fixture(
        "concurrent",
        kind="retry",
    )
    barrier = _AsyncBarrier(2)
    results = await asyncio.gather(
        workflow_worker.coordinate_stage_fail(
            _BarrierFactory(barrier),
            authority=fixture.source,
            error_text="Concurrent provider timeout",
            error_code="source.fetch_timeout",
            retryable=True,
            error_class="TimeoutError",
        ),
        workflow_worker.coordinate_stage_fail(
            _BarrierFactory(barrier),
            authority=fixture.source,
            error_text="Concurrent provider timeout",
            error_code="source.fetch_timeout",
            retryable=True,
            error_class="TimeoutError",
        ),
    )
    assert sorted(result.disposition for result in results) == ["recorded", "stale"]
    winner = next(result for result in results if result.disposition == "recorded")
    stale = next(result for result in results if result.disposition == "stale")
    assert winner.retry_emission is not None
    assert stale.retry_emission is None
    assert stale.attempt_completed_at is None
    again = await workflow_worker.coordinate_stage_fail(
        async_session_factory,
        authority=fixture.source,
        error_text="Concurrent provider timeout",
        error_code="source.fetch_timeout",
        retryable=True,
        error_class="TimeoutError",
    )
    assert again.disposition == "stale"
    async with async_session_factory() as db:
        count = await db.scalar(
            select(func.count())
            .select_from(OutboxMessage)
            .where(
                OutboxMessage.workflow_run_id == fixture.workflow_id,
                OutboxMessage.emission_kind == "retry_scheduled",
            )
        )
        assert count == 1


@pytest.mark.asyncio
async def test_checkpoint_authority_chains_into_failure_without_changing_source_lineage():
    fixture = await _failure_fixture(
        "checkpoint-chain",
        kind="retry",
    )
    before_lineage = await _source_lineage_snapshot(fixture.source)
    checkpoint = await workflow_worker.coordinate_stage_checkpoint(
        async_session_factory,
        authority=fixture.source,
        checkpoint_schema_version="research-stage-checkpoint-v1",
        checkpoint={"cursor": "before-failure"},
        lease_seconds=120,
    )
    assert checkpoint.disposition == "renewed" and checkpoint.authority is not None
    recorded = await workflow_worker.coordinate_stage_fail(
        async_session_factory,
        authority=checkpoint.authority,
        error_text="Provider failed after the checkpoint",
        error_code="source.fetch_timeout",
        retryable=True,
        error_class="TimeoutError",
    )
    assert recorded.disposition == "recorded"
    assert recorded.checkpoint_version == 1
    assert recorded.previous_stage_state_version == checkpoint.stage_state_version
    assert recorded.previous_attempt_state_version == checkpoint.attempt_state_version
    async with async_session_factory() as db:
        stage = await db.get(StageRun, fixture.source.stage_run_id)
        attempt = await db.get(StageAttempt, fixture.source.stage_attempt_id)
        assert stage is not None and attempt is not None
        assert stage.checkpoint_version == attempt.checkpoint_end_version == 1
        assert stage.status == "retry_wait"
        assert attempt.status == "failed"
    assert await _source_lineage_snapshot(fixture.source) == before_lineage


@pytest.mark.asyncio
async def test_expiry_during_workflow_lock_wait_returns_stale_without_mutation():
    fixture = await _failure_fixture(
        "lock-expiry",
        kind="retry",
        lease_seconds=2,
    )
    before = await _graph_snapshot(fixture.workflow_id)
    blocker = async_session_factory()
    await blocker.begin()
    await blocker.execute(select(WorkflowRun).where(WorkflowRun.id == fixture.workflow_id).with_for_update())
    task = asyncio.create_task(
        workflow_worker.coordinate_stage_fail(
            async_session_factory,
            authority=fixture.source,
            error_text="Provider timed out while blocked",
            error_code="source.fetch_timeout",
            retryable=True,
            error_class="TimeoutError",
        )
    )
    try:
        await _wait_for_workflow_lock_wait()
        await _wait_until_db_after(fixture.source.lease_expires_at)
    finally:
        await blocker.rollback()
        await blocker.close()
    stale = await asyncio.wait_for(task, timeout=10)
    assert stale.disposition == "stale"
    assert stale.attempt_completed_at is None
    assert stale.retry_emission is None
    assert await _graph_snapshot(fixture.workflow_id) == before


@pytest.mark.asyncio
async def test_recovered_attempt_makes_old_failure_authority_stale():
    fixture = await _failure_fixture(
        "recovered-stale",
        kind="retry",
        lease_seconds=1,
    )
    await _wait_until_db_after(fixture.source.lease_expires_at)
    recovered = await _recover_one(fixture.workflow_id)
    assert recovered is not None
    stale = await workflow_worker.coordinate_stage_fail(
        async_session_factory,
        authority=fixture.source,
        error_text="Provider reported after lease recovery",
        error_code="source.fetch_timeout",
        retryable=True,
        error_class="TimeoutError",
    )
    assert stale.disposition == "stale"
    assert stale.attempt_completed_at is None
    assert stale.retry_emission is None
    async with async_session_factory() as db:
        stage = await db.get(StageRun, fixture.source.stage_run_id)
        attempt = await db.get(StageAttempt, fixture.source.stage_attempt_id)
        assert stage is not None and stage.status == "retry_wait"
        assert attempt is not None and attempt.status == "abandoned"


@pytest.mark.asyncio
async def test_publisher_after_failure_start_conflicts_then_fresh_coordinator_succeeds():
    fixture = await _failure_fixture(
        "publisher-race",
        kind="required",
    )
    assert fixture.idle_message_id is not None
    paused = asyncio.Event()
    release = asyncio.Event()
    _PauseAfterStageLockSession.stage_locked = paused
    _PauseAfterStageLockSession.release = release
    _PauseAfterStageLockSession.paused = False
    maker = async_sessionmaker(
        engine,
        class_=_PauseAfterStageLockSession,
        expire_on_commit=False,
    )
    task = asyncio.create_task(
        workflow_worker.coordinate_stage_fail(
            maker,
            authority=fixture.source,
            error_text="Required source evidence is invalid",
            error_code="source.invalid_report",
            retryable=False,
            error_class="InvalidReport",
        )
    )
    await asyncio.wait_for(paused.wait(), timeout=10)
    late_claim = await _claim_message(fixture.idle_message_id)
    release.set()
    with pytest.raises(
        outbox_runtime.OutboxConflict,
        match="newer than this transaction; retry in a fresh transaction",
    ):
        await asyncio.wait_for(task, timeout=10)

    async with async_session_factory() as db:
        message = await db.get(OutboxMessage, late_claim.message_id)
        delivery = await db.get(
            OutboxDeliveryAttempt,
            late_claim.delivery_attempt_id,
        )
        assert message is not None and message.status == "dispatching"
        assert delivery is not None and delivery.status == "dispatching"

    recorded = await workflow_worker.coordinate_stage_fail(
        async_session_factory,
        authority=fixture.source,
        error_text="Required source evidence is invalid",
        error_code="source.invalid_report",
        retryable=False,
        error_class="InvalidReport",
    )
    assert recorded.disposition == "recorded"
    assert late_claim.message_id in recorded.cancelled_message_ids
    assert late_claim.delivery_attempt_id in recorded.cancelled_delivery_ids
    async with async_session_factory() as db:
        message = await db.get(OutboxMessage, late_claim.message_id)
        delivery = await db.get(
            OutboxDeliveryAttempt,
            late_claim.delivery_attempt_id,
        )
        assert message is not None and message.status == "cancelled"
        assert delivery is not None and delivery.status == "cancelled"


@pytest.mark.asyncio
async def test_invalid_failure_evidence_is_zero_session_activity():
    fixture = await _failure_fixture(
        "invalid",
        kind="retry",
    )
    forbidden = _ForbiddenFactory()
    with pytest.raises(workflow_runtime.WorkflowValidation):
        await workflow_worker.coordinate_stage_fail(
            forbidden,
            authority=fixture.source,
            error_text=_HostileString("hostile"),
            error_code="source.fetch_timeout",
            retryable=True,
        )
    with pytest.raises(
        workflow_runtime.WorkflowValidation,
        match="Stage failure evidence is invalid",
    ):
        await workflow_worker.coordinate_stage_fail(
            forbidden,
            authority=fixture.source,
            error_text="Caller cannot forge recovery evidence",
            error_code="workflow.lease_expired",
            retryable=True,
        )
    with pytest.raises(workflow_runtime.WorkflowValidation):
        await workflow_worker.coordinate_stage_fail(
            forbidden,
            authority=fixture.source,
            error_text="Invalid retry flag",
            error_code="source.fetch_timeout",
            retryable=1,
        )
    assert forbidden.calls == 0


@pytest.mark.asyncio
async def test_direct_workflow_failure_is_fenced_before_sql():
    statements: list[str] = []

    def capture(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", capture)
    try:
        async with async_session_factory() as db:
            with pytest.raises(
                workflow_runtime.WorkflowConflict,
                match="Direct stage failures are disabled",
            ):
                await workflow_runtime.fail_stage(
                    db,
                    uuid.uuid4(),
                    lease_token=uuid.uuid4(),
                    expected_stage_version=1,
                    expected_attempt_version=1,
                    expected_checkpoint_version=0,
                    error="Provider failed",
                    error_code="source.failure",
                    retryable=False,
                )
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", capture)
    assert statements == []


@pytest.mark.asyncio
async def test_database_is_on_exact_contract_phase_revision():
    async with async_session_factory() as db:
        heads = tuple((await db.scalars(text("SELECT version_num FROM alembic_version ORDER BY version_num"))).all())
    assert heads == ("20260824_0004",)
