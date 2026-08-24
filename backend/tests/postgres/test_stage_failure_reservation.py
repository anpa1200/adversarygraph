"""PostgreSQL acceptance for receipt-bound stage-failure reservations.

Run only against a disposable database migrated through revision 0003::

    RUN_POSTGRES_TESTS=1 python -m pytest -q -o addopts='' \
      --confcutdir=tests/postgres \
      tests/postgres/test_stage_failure_reservation.py

The reservation/consume phase is read-only.  Retry and required-terminal
children are exercised only inside caller-owned transactions that are rolled
back, so this file never substitutes for the later commit-confirmed failure
writer acceptance.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from datetime import datetime
import hashlib
import json
import os
import uuid

import pytest
import pytest_asyncio
from sqlalchemy import event, func, select, text
from sqlalchemy.exc import IntegrityError

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


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_POSTGRES_TESTS") != "1",
    reason="requires an explicitly authorized disposable PostgreSQL database",
)

ACTOR = projects.ResearchActor(
    name="PostgreSQL Stage Failure Reservation Test",
    actor_id="postgres-stage-failure-reservation",
)


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
        "objective": f"Validate receipt-bound stage failure reservation: {label}.",
        "intelligence_requirements": [
            "Does failure reserve every receipt and outbox cancellation authority before mutation?",
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
    if kind == "optional_terminal":
        return [
            _stage_definition("source", 1, required=False),
            _stage_definition("running_peer", 2),
            _stage_definition("dependent", 3, depends_on=["source"]),
        ]
    if kind == "required_terminal":
        return [
            _stage_definition("source", 1),
            _stage_definition("running_peer", 2),
            _stage_definition("idle_peer", 3),
            _stage_definition("active_peer", 4),
            _stage_definition("dependent", 5, depends_on=["source"]),
        ]
    raise AssertionError(f"unknown failure fixture kind: {kind}")


def _evidence(*, retryable: bool) -> outbox_runtime.StageFailureEvidence:
    return outbox_runtime.StageFailureEvidence(
        code="source.fetch_timeout" if retryable else "source.invalid_report",
        error_class="TimeoutError" if retryable else "InvalidReport",
        summary=("The disposable source provider timed out" if retryable else "The disposable report cannot be parsed safely"),
        retryable=retryable,
    )


async def _new_workflow(label: str, *, kind: str) -> uuid.UUID:
    safe_label = label.replace("_", "-")
    async with async_session_factory() as db:
        _, revision = await projects.create_project(
            db,
            ACTOR,
            project_key=f"failure-reservation-{safe_label}-{uuid.uuid4().hex[:10]}",
            name=f"Failure reservation {label}",
            description="Disposable PostgreSQL failure-reservation authority.",
            spec=_spec(label),
        )
        workflow, created = await workflow_runtime.create_workflow(
            db,
            ACTOR,
            project_revision_id=revision.id,
            workflow_type="cti.report",
            idempotency_token=f"failure-reservation-{label}-{uuid.uuid4().hex}",
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
                publisher_id=f"failure-reservation-publisher-{uuid.uuid4().hex[:8]}",
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
        broker_message_id=f"failure-reservation-{label}-{claim.cycle_key}",
        broker_receipt_id=hashlib.sha256(f"failure-reservation:{label}:{claim.cycle_key}".encode()).hexdigest(),
        worker_id=f"failure-reservation-worker-{label}",
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
    if kind == "retry":
        return _FailureFixture(workflow_id=workflow_id, source=source)

    running_peer = await _activate_stage(
        workflow_id,
        "running_peer",
        label=f"{label}-running-peer",
        lease_seconds=lease_seconds,
    )
    if kind == "optional_terminal":
        return _FailureFixture(
            workflow_id=workflow_id,
            source=source,
            running_peer=running_peer,
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
            field_value = json.dumps(
                field_value,
                sort_keys=True,
                separators=(",", ":"),
            )
        snapshot.append((column.key, field_value))
    return tuple(snapshot)


async def _graph_snapshot(
    workflow_id: uuid.UUID,
) -> tuple[tuple[tuple[str, object], ...], ...]:
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


async def _wait_until_db_after(moment: datetime) -> None:
    for _ in range(300):
        async with engine.connect() as connection:
            now = await connection.scalar(select(func.clock_timestamp()))
        if isinstance(now, datetime) and now > moment:
            return
        await asyncio.sleep(0.02)
    raise AssertionError("PostgreSQL clock did not advance past the lease boundary")


async def _wait_for_backend_lock(pid: int) -> None:
    for _ in range(250):
        async with engine.connect() as connection:
            waiting = await connection.scalar(
                text("SELECT wait_event_type = 'Lock' FROM pg_stat_activity WHERE pid = :pid"),
                {"pid": pid},
            )
        if waiting is True:
            return
        await asyncio.sleep(0.02)
    raise AssertionError(f"PostgreSQL backend {pid} did not enter a lock wait")


def _selected(statements: list[str]) -> list[str]:
    return [statement for statement in statements if statement.lstrip().upper().startswith("SELECT")]


def _locked_table_order(statements: list[str]) -> list[str]:
    order: list[str] = []
    tables = (
        "workflow_runs",
        "stage_runs",
        "outbox_messages",
        "outbox_delivery_attempts",
        "stage_attempts",
    )
    for statement in _selected(statements):
        if "FOR UPDATE" not in statement:
            continue
        table = next((name for name in tables if f"FROM {name}" in statement), None)
        if table is not None:
            order.append(table)
    return order


async def _assert_nowait_unlocked(
    *,
    workflow_id: uuid.UUID,
    stage_ids: tuple[uuid.UUID, ...],
    message_ids: tuple[uuid.UUID, ...],
    delivery_ids: tuple[uuid.UUID, ...],
    attempt_ids: tuple[uuid.UUID, ...],
) -> None:
    async with async_session_factory() as db:
        async with db.begin():
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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kind", "retryable", "expected_decision"),
    [
        ("retry", True, "retry"),
        ("optional_terminal", False, "failed"),
        ("required_terminal", False, "failed"),
    ],
)
async def test_failure_graph_is_read_only_complete_ordered_and_unlocked(
    kind: str,
    retryable: bool,
    expected_decision: str,
):
    fixture = await _failure_fixture(
        f"read-only-{kind}",
        kind=kind,
    )
    evidence = _evidence(retryable=retryable)
    before = await _graph_snapshot(fixture.workflow_id)
    statements: list[str] = []

    def capture(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", capture)
    try:
        async with async_session_factory() as db:
            async with db.begin():
                reservation = await outbox_runtime.reserve_stage_failure_graph(
                    db,
                    authority=fixture.source,
                    evidence=evidence,
                )
                locked = await outbox_runtime.consume_stage_failure_graph(
                    db,
                    reservation=reservation,
                    authority=fixture.source,
                    evidence=evidence,
                )
                stage_ids = tuple(uuid.UUID(str(stage.id)) for stage in locked.stages)
                message_ids = tuple(locked.locked_message_ids)
                delivery_ids = tuple(locked.locked_delivery_ids)
                attempt_ids = tuple(locked.locked_attempt_ids)

                assert locked.decision == expected_decision
                assert locked.source_stage_id == fixture.source.stage_run_id
                assert locked.source_attempt_id == fixture.source.stage_attempt_id
                assert locked.causal_source.stage_run_id == fixture.source.stage_run_id
                assert locked.transaction_at <= locked.observed_at
                assert message_ids == tuple(sorted(message_ids, key=lambda value: value.int))
                assert delivery_ids == tuple(sorted(delivery_ids, key=lambda value: value.int))
                assert attempt_ids == tuple(sorted(attempt_ids, key=lambda value: value.int))
                assert fixture.source.message_id in message_ids
                assert fixture.source.delivery_attempt_id in delivery_ids
                assert fixture.source.stage_attempt_id in attempt_ids

                if kind == "retry":
                    assert locked.stage_ready_reservation is not None
                    assert locked.retry_intent is not None
                    assert locked.retry_intent.emission_kind == "retry_scheduled"
                    assert locked.retry_intent.causal_pre_stage is not None
                    assert locked.retry_intent.causal_pre_stage.stage_run_id == fixture.source.stage_run_id
                    assert locked.next_attempt_at is not None
                    assert locked.outbox_cancellation_reservation is None
                    assert message_ids == (fixture.source.message_id,)
                    assert delivery_ids == (fixture.source.delivery_attempt_id,)
                    assert attempt_ids == (fixture.source.stage_attempt_id,)
                elif kind == "optional_terminal":
                    assert locked.stage_ready_reservation is None
                    assert locked.outbox_cancellation_reservation is None
                    assert locked.next_attempt_at is None
                    assert message_ids == (fixture.source.message_id,)
                    assert delivery_ids == (fixture.source.delivery_attempt_id,)
                    assert attempt_ids == (fixture.source.stage_attempt_id,)
                else:
                    assert fixture.running_peer is not None
                    assert fixture.idle_message_id is not None
                    assert fixture.active_claim is not None
                    assert locked.stage_ready_reservation is None
                    cancellation = locked.outbox_cancellation_reservation
                    assert cancellation is not None
                    assert set(message_ids) == {
                        fixture.source.message_id,
                        fixture.running_peer.message_id,
                        fixture.idle_message_id,
                        fixture.active_claim.message_id,
                    }
                    assert set(delivery_ids) == {
                        fixture.source.delivery_attempt_id,
                        fixture.running_peer.delivery_attempt_id,
                        fixture.active_claim.delivery_attempt_id,
                    }
                    assert set(attempt_ids) == {
                        fixture.source.stage_attempt_id,
                        fixture.running_peer.stage_attempt_id,
                    }
                    assert set(cancellation.message_ids) == {
                        fixture.idle_message_id,
                        fixture.active_claim.message_id,
                    }
                    assert cancellation.delivery_ids == (fixture.active_claim.delivery_attempt_id,)
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", capture)

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
    selected = _selected(statements)
    assert "transaction_timestamp" in selected[-3]
    assert "clock_timestamp" in selected[-2]
    assert "clock_timestamp" in selected[-1]
    assert all(not statement.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE")) for statement in statements)
    assert await _graph_snapshot(fixture.workflow_id) == before
    await _assert_nowait_unlocked(
        workflow_id=fixture.workflow_id,
        stage_ids=stage_ids,
        message_ids=message_ids,
        delivery_ids=delivery_ids,
        attempt_ids=attempt_ids,
    )


@pytest.mark.asyncio
async def test_required_terminal_zero_live_suffix_transfers_one_shot_noop_child():
    fixture = await _failure_fixture(
        "zero-live-required",
        kind="retry",
    )
    evidence = _evidence(retryable=False)
    before = await _graph_snapshot(fixture.workflow_id)

    async with async_session_factory() as db:
        await db.begin()
        reservation = await outbox_runtime.reserve_stage_failure_graph(
            db,
            authority=fixture.source,
            evidence=evidence,
        )
        locked = await outbox_runtime.consume_stage_failure_graph(
            db,
            reservation=reservation,
            authority=fixture.source,
            evidence=evidence,
        )
        child = locked.outbox_cancellation_reservation
        assert locked.decision == "failed"
        assert child is not None
        assert child.messages == child.message_ids == ()
        assert child.deliveries == child.delivery_ids == ()

        statements: list[str] = []

        def capture(_connection, _cursor, statement, _parameters, _context, _many):
            statements.append(statement)

        event.listen(engine.sync_engine, "before_cursor_execute", capture)
        try:
            assert await outbox_runtime.cancel_reserved_outbox_messages(
                db,
                reservation=child,
            ) == ((), ())
        finally:
            event.remove(engine.sync_engine, "before_cursor_execute", capture)
        assert statements == []
        with pytest.raises(outbox_runtime.OutboxConflict, match="not registered"):
            await outbox_runtime.cancel_reserved_outbox_messages(
                db,
                reservation=child,
            )
        await db.rollback()

    assert await _graph_snapshot(fixture.workflow_id) == before


@pytest.mark.asyncio
async def test_retry_child_appends_exact_causal_message_once_without_queries():
    fixture = await _failure_fixture(
        "retry-child",
        kind="retry",
    )
    evidence = _evidence(retryable=True)
    before = await _graph_snapshot(fixture.workflow_id)

    async with async_session_factory() as db:
        await db.begin()
        reservation = await outbox_runtime.reserve_stage_failure_graph(
            db,
            authority=fixture.source,
            evidence=evidence,
        )
        locked = await outbox_runtime.consume_stage_failure_graph(
            db,
            reservation=reservation,
            authority=fixture.source,
            evidence=evidence,
        )
        child = locked.stage_ready_reservation
        assert child is not None
        assert locked.next_attempt_at is not None
        source = locked.stages[locked.source_stage_index]
        attempt = next(value for value in locked.locked_attempts if uuid.UUID(str(value.id)) == fixture.source.stage_attempt_id)

        attempt.status = "failed"
        attempt.state_version += 1
        attempt.checkpoint_end_version = source.checkpoint_version
        attempt.output_checksum = ""
        attempt.error_code = evidence.code
        attempt.error_class = evidence.error_class
        attempt.error_summary = evidence.summary
        attempt.retryable = True
        attempt.heartbeat_at = locked.observed_at
        attempt.completed_at = locked.observed_at
        await db.flush([attempt])

        source.status = "retry_wait"
        source.state_version += 1
        source.output_manifest = {}
        source.output_checksum = ""
        source.last_error_code = evidence.code
        source.last_error_summary = evidence.summary
        source.last_error_retryable = True
        source.completed_at = None
        source.next_attempt_at = locked.next_attempt_at
        source.lease_owner = ""
        source.lease_token = None
        source.leased_at = None
        source.lease_expires_at = None
        source.heartbeat_at = None
        await db.flush([source])

        statements: list[str] = []

        def capture(_connection, _cursor, statement, _parameters, _context, _many):
            statements.append(statement)

        event.listen(engine.sync_engine, "before_cursor_execute", capture)
        try:
            appended = await outbox_runtime.append_reserved_stage_ready(
                db,
                reservation=child,
                workflow=locked.workflow,
                locked_stages=locked.stages,
                causal_attempt=attempt,
            )
        finally:
            event.remove(engine.sync_engine, "before_cursor_execute", capture)

        assert len(appended) == 1
        message, created = appended[0]
        assert created is True
        assert message.id == locked.retry_message_id
        assert message.emission_kind == "retry_scheduled"
        assert message.causation_id == attempt.id
        assert message.available_at == source.next_attempt_at
        assert message.aggregate_version == source.state_version
        assert message.target_attempt_number == source.attempt_count + 1
        assert not _selected(statements)
        assert sum(statement.lstrip().upper().startswith("INSERT INTO OUTBOX_MESSAGES") for statement in statements) == 1
        with pytest.raises(outbox_runtime.OutboxConflict, match="not registered"):
            await outbox_runtime.append_reserved_stage_ready(
                db,
                reservation=child,
                workflow=locked.workflow,
                locked_stages=locked.stages,
                causal_attempt=attempt,
            )
        await db.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
        await db.rollback()

    assert await _graph_snapshot(fixture.workflow_id) == before


@pytest.mark.asyncio
async def test_required_cancellation_child_flushes_delivery_then_message_once_without_queries():
    fixture = await _failure_fixture(
        "required-cancellation-child",
        kind="required_terminal",
    )
    evidence = _evidence(retryable=False)
    before = await _graph_snapshot(fixture.workflow_id)

    async with async_session_factory() as db:
        await db.begin()
        reservation = await outbox_runtime.reserve_stage_failure_graph(
            db,
            authority=fixture.source,
            evidence=evidence,
        )
        locked = await outbox_runtime.consume_stage_failure_graph(
            db,
            reservation=reservation,
            authority=fixture.source,
            evidence=evidence,
        )
        child = locked.outbox_cancellation_reservation
        assert child is not None
        assert child.message_ids
        assert child.delivery_ids
        statements: list[str] = []

        def capture(_connection, _cursor, statement, _parameters, _context, _many):
            statements.append(statement)

        event.listen(engine.sync_engine, "before_cursor_execute", capture)
        try:
            deliveries, messages = await outbox_runtime.cancel_reserved_outbox_messages(
                db,
                reservation=child,
            )
        finally:
            event.remove(engine.sync_engine, "before_cursor_execute", capture)

        assert tuple(uuid.UUID(str(value.id)) for value in deliveries) == child.delivery_ids
        assert tuple(uuid.UUID(str(value.id)) for value in messages) == child.message_ids
        assert all(value.status == "cancelled" for value in deliveries)
        assert all(value.status == "cancelled" for value in messages)
        assert not _selected(statements)
        changed_tables = [
            "outbox_delivery_attempts" if "UPDATE outbox_delivery_attempts" in statement else "outbox_messages"
            for statement in statements
            if statement.lstrip().upper().startswith("UPDATE")
            and ("UPDATE outbox_delivery_attempts" in statement or "UPDATE outbox_messages" in statement)
        ]
        assert changed_tables == [
            *("outbox_delivery_attempts",) * len(child.delivery_ids),
            *("outbox_messages",) * len(child.message_ids),
        ]
        with pytest.raises(outbox_runtime.OutboxConflict, match="not registered"):
            await outbox_runtime.cancel_reserved_outbox_messages(
                db,
                reservation=child,
            )
        with pytest.raises(
            IntegrityError,
            match="workflow W/S/A/M/D contract is inconsistent",
        ):
            await db.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
        await db.rollback()

    assert await _graph_snapshot(fixture.workflow_id) == before


@pytest.mark.asyncio
async def test_failure_capability_forgery_reuse_session_root_savepoint_and_dirty_fences():
    fixture = await _failure_fixture(
        "capability-fences",
        kind="retry",
    )
    evidence = _evidence(retryable=True)
    before = await _graph_snapshot(fixture.workflow_id)
    reservation = None

    async with async_session_factory() as db:
        await db.begin()
        reservation = await outbox_runtime.reserve_stage_failure_graph(
            db,
            authority=fixture.source,
            evidence=evidence,
        )
        forged = replace(reservation)
        with pytest.raises(outbox_runtime.OutboxConflict, match="not registered"):
            await outbox_runtime.consume_stage_failure_graph(
                db,
                reservation=forged,
                authority=fixture.source,
                evidence=evidence,
            )
        with pytest.raises(outbox_runtime.OutboxConflict, match="already reserved"):
            await outbox_runtime.reserve_stage_failure_graph(
                db,
                authority=fixture.source,
                evidence=evidence,
            )
        with pytest.raises(outbox_runtime.OutboxConflict, match="already reserved"):
            await outbox_runtime.reserve_stage_execution_receipt(
                db,
                authority=fixture.source,
            )

        async with async_session_factory() as other:
            async with other.begin():
                with pytest.raises(outbox_runtime.OutboxConflict, match="not registered"):
                    await outbox_runtime.consume_stage_failure_graph(
                        other,
                        reservation=reservation,
                        authority=fixture.source,
                        evidence=evidence,
                    )

        nested = await db.begin_nested()
        with pytest.raises(outbox_runtime.OutboxConflict, match="nested transaction"):
            await outbox_runtime.consume_stage_failure_graph(
                db,
                reservation=reservation,
                authority=fixture.source,
                evidence=evidence,
            )
        await nested.rollback()
        locked = await outbox_runtime.consume_stage_failure_graph(
            db,
            reservation=reservation,
            authority=fixture.source,
            evidence=evidence,
        )
        assert locked.source_attempt_id == fixture.source.stage_attempt_id
        with pytest.raises(outbox_runtime.OutboxConflict, match="not registered"):
            await outbox_runtime.consume_stage_failure_graph(
                db,
                reservation=reservation,
                authority=fixture.source,
                evidence=evidence,
            )
        await db.rollback()

    async with async_session_factory() as db:
        async with db.begin():
            with pytest.raises(outbox_runtime.OutboxConflict, match="not registered"):
                await outbox_runtime.consume_stage_failure_graph(
                    db,
                    reservation=reservation,
                    authority=fixture.source,
                    evidence=evidence,
                )

    statements: list[str] = []

    def capture(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)

    async with async_session_factory() as db:
        await db.begin()
        workflow = await db.get(WorkflowRun, fixture.workflow_id)
        assert workflow is not None
        workflow.status_summary = "dirty failure authority"
        event.listen(engine.sync_engine, "before_cursor_execute", capture)
        try:
            with pytest.raises(outbox_runtime.OutboxConflict, match="entirely clean"):
                await outbox_runtime.reserve_stage_failure_graph(
                    db,
                    authority=fixture.source,
                    evidence=evidence,
                )
        finally:
            event.remove(engine.sync_engine, "before_cursor_execute", capture)
        assert statements == []
        await db.rollback()

    assert await _graph_snapshot(fixture.workflow_id) == before


@pytest.mark.asyncio
async def test_failure_post_attempt_lock_clock_rejects_expiry_while_waiting():
    fixture = await _failure_fixture(
        "post-lock-expiry",
        kind="retry",
        lease_seconds=2,
    )
    evidence = _evidence(retryable=True)
    before = await _graph_snapshot(fixture.workflow_id)
    blocker = async_session_factory()
    await blocker.begin()
    await blocker.execute(select(StageAttempt).where(StageAttempt.id == fixture.source.stage_attempt_id).with_for_update())
    pid_ready: asyncio.Future[int] = asyncio.get_running_loop().create_future()

    async def blocked_reserve():
        try:
            async with async_session_factory() as db:
                async with db.begin():
                    pid = await db.scalar(text("SELECT pg_backend_pid()"))
                    assert isinstance(pid, int)
                    pid_ready.set_result(pid)
                    await outbox_runtime.reserve_stage_failure_graph(
                        db,
                        authority=fixture.source,
                        evidence=evidence,
                    )
        except Exception as exc:
            return exc
        return None

    task = asyncio.create_task(blocked_reserve())
    try:
        pid = await asyncio.wait_for(pid_ready, timeout=5)
        await _wait_for_backend_lock(pid)
        await _wait_until_db_after(fixture.source.lease_expires_at)
    finally:
        await blocker.rollback()
        await blocker.close()
    outcome = await asyncio.wait_for(task, timeout=10)
    assert isinstance(outcome, outbox_runtime.OutboxLeaseLost)
    assert "no longer live" in str(outcome)
    assert await _graph_snapshot(fixture.workflow_id) == before


@pytest.mark.asyncio
async def test_failure_consume_rechecks_expiry_spends_capability_and_writes_nothing():
    fixture = await _failure_fixture(
        "consume-expiry",
        kind="retry",
        lease_seconds=2,
    )
    evidence = _evidence(retryable=True)
    before = await _graph_snapshot(fixture.workflow_id)

    async with async_session_factory() as db:
        await db.begin()
        reservation = await outbox_runtime.reserve_stage_failure_graph(
            db,
            authority=fixture.source,
            evidence=evidence,
        )
        await _wait_until_db_after(fixture.source.lease_expires_at)
        with pytest.raises(outbox_runtime.OutboxLeaseLost, match="no longer live"):
            await outbox_runtime.consume_stage_failure_graph(
                db,
                reservation=reservation,
                authority=fixture.source,
                evidence=evidence,
            )
        with pytest.raises(outbox_runtime.OutboxConflict, match="not registered"):
            await outbox_runtime.consume_stage_failure_graph(
                db,
                reservation=reservation,
                authority=fixture.source,
                evidence=evidence,
            )
        await db.rollback()

    assert await _graph_snapshot(fixture.workflow_id) == before


@pytest.mark.asyncio
async def test_competing_failure_reservations_serialize_on_the_workflow_lock():
    fixture = await _failure_fixture(
        "serialized-reservations",
        kind="required_terminal",
    )
    evidence = _evidence(retryable=False)
    before = await _graph_snapshot(fixture.workflow_id)
    first = async_session_factory()
    await first.begin()
    first_reservation = await outbox_runtime.reserve_stage_failure_graph(
        first,
        authority=fixture.source,
        evidence=evidence,
    )
    pid_ready: asyncio.Future[int] = asyncio.get_running_loop().create_future()

    async def competing_reservation():
        async with async_session_factory() as db:
            await db.begin()
            pid = await db.scalar(text("SELECT pg_backend_pid()"))
            assert isinstance(pid, int)
            pid_ready.set_result(pid)
            reservation = await outbox_runtime.reserve_stage_failure_graph(
                db,
                authority=fixture.source,
                evidence=evidence,
            )
            locked = await outbox_runtime.consume_stage_failure_graph(
                db,
                reservation=reservation,
                authority=fixture.source,
                evidence=evidence,
            )
            await db.rollback()
            return locked

    task = asyncio.create_task(competing_reservation())
    try:
        pid = await asyncio.wait_for(pid_ready, timeout=5)
        await _wait_for_backend_lock(pid)
        assert not task.done()
        first_locked = await outbox_runtime.consume_stage_failure_graph(
            first,
            reservation=first_reservation,
            authority=fixture.source,
            evidence=evidence,
        )
        assert first_locked.outbox_cancellation_reservation is not None
    finally:
        await first.rollback()
        await first.close()

    second_locked = await asyncio.wait_for(task, timeout=10)
    assert second_locked.outbox_cancellation_reservation is not None
    assert await _graph_snapshot(fixture.workflow_id) == before


@pytest.mark.asyncio
async def test_publisher_after_failure_transaction_start_requires_fresh_retry_before_cancellation():
    fixture = await _failure_fixture(
        "publisher-after-start",
        kind="required_terminal",
    )
    assert fixture.idle_message_id is not None
    evidence = _evidence(retryable=False)
    before = await _graph_snapshot(fixture.workflow_id)

    stale = async_session_factory()
    await stale.begin()
    old_transaction_at = await stale.scalar(select(func.transaction_timestamp()))
    assert isinstance(old_transaction_at, datetime)
    await stale.scalar(select(WorkflowRun).where(WorkflowRun.id == fixture.workflow_id).with_for_update())
    await stale.execute(
        select(StageRun)
        .where(StageRun.workflow_run_id == fixture.workflow_id)
        .order_by(StageRun.ordinal.asc(), StageRun.id.asc())
        .with_for_update()
    )

    late_claim = await _claim_message(fixture.idle_message_id)
    assert late_claim.message_id == fixture.idle_message_id
    async with async_session_factory() as observer:
        late_delivery = await observer.get(
            OutboxDeliveryAttempt,
            late_claim.delivery_attempt_id,
        )
        assert late_delivery is not None
        assert late_delivery.created_at > old_transaction_at

    with pytest.raises(
        outbox_runtime.OutboxConflict,
        match="newer than this transaction; retry in a fresh transaction",
    ):
        await outbox_runtime.reserve_stage_failure_graph(
            stale,
            authority=fixture.source,
            evidence=evidence,
        )
    await stale.rollback()
    await stale.close()

    after_first = await _graph_snapshot(fixture.workflow_id)
    assert after_first != before
    async with async_session_factory() as db:
        late_message = await db.get(OutboxMessage, fixture.idle_message_id)
        late_delivery = await db.get(
            OutboxDeliveryAttempt,
            late_claim.delivery_attempt_id,
        )
        assert late_message is not None and late_message.status == "dispatching"
        assert late_delivery is not None and late_delivery.status == "dispatching"

    async with async_session_factory() as db:
        await db.begin()
        reservation = await outbox_runtime.reserve_stage_failure_graph(
            db,
            authority=fixture.source,
            evidence=evidence,
        )
        locked = await outbox_runtime.consume_stage_failure_graph(
            db,
            reservation=reservation,
            authority=fixture.source,
            evidence=evidence,
        )
        child = locked.outbox_cancellation_reservation
        assert child is not None
        assert late_claim.message_id in child.message_ids
        assert late_claim.delivery_attempt_id in child.delivery_ids
        deliveries, messages = await outbox_runtime.cancel_reserved_outbox_messages(
            db,
            reservation=child,
        )
        assert any(value.id == late_claim.delivery_attempt_id for value in deliveries)
        assert any(value.id == late_claim.message_id for value in messages)
        with pytest.raises(
            IntegrityError,
            match="workflow W/S/A/M/D contract is inconsistent",
        ):
            await db.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
        await db.rollback()

    assert await _graph_snapshot(fixture.workflow_id) == after_first
