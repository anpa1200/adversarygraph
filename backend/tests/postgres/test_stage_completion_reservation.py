"""PostgreSQL acceptance for receipt-bound stage-completion reservations.

Run only against a disposable database migrated through revision 0004::

    RUN_POSTGRES_TESTS=1 python -m pytest -q -o addopts='' \
      --confcutdir=tests/postgres \
      tests/postgres/test_stage_completion_reservation.py
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import replace
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
from app.services import workflow_worker
from app.services.workflow_engine import checksum_json
from tests.postgres._workflow_authority import (
    cancel_active_workflow,
    cancellation_command,
)


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_POSTGRES_TESTS") != "1",
    reason="requires an explicitly authorized disposable PostgreSQL database",
)

ACTOR = projects.ResearchActor(
    name="PostgreSQL Stage Completion Reservation Test",
    actor_id="postgres-stage-completion-reservation",
)


@pytest_asyncio.fixture(autouse=True)
async def _dispose_engine_pool_between_tests():
    await engine.dispose()
    try:
        yield
    finally:
        await engine.dispose()


def _spec(label: str) -> dict:
    return {
        "objective": f"Validate receipt-bound stage completion reservation: {label}.",
        "intelligence_requirements": [
            "Does completion reserve the complete immutable receipt lineage before mutation?",
        ],
        "output_targets": ["canonical_intelligence"],
        "tlp": "TLP:AMBER",
    }


def _stage_definition(
    stage_key: str,
    ordinal: int,
    *,
    depends_on: list[str] | None = None,
) -> dict:
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
        "config": {"acceptance_test": True, "stage": stage_key},
        "retry_policy": {
            "base_delay_seconds": 1,
            "max_delay_seconds": 1,
            "jitter_percent": 0,
        },
    }


def _plan(target_count: int, *, sibling_root: bool = False) -> list[dict]:
    plan = [_stage_definition("collect", 1)]
    ordinal = 2
    if sibling_root:
        plan.append(_stage_definition("sibling", ordinal))
        ordinal += 1
    for index in range(target_count):
        plan.append(
            _stage_definition(
                f"target_{index + 1}",
                ordinal + index,
                depends_on=["collect"],
            )
        )
    return plan


async def _new_workflow(
    label: str,
    *,
    target_count: int,
    sibling_root: bool = False,
) -> uuid.UUID:
    async with async_session_factory() as db:
        _, revision = await projects.create_project(
            db,
            ACTOR,
            project_key=f"completion-reservation-{label}-{uuid.uuid4().hex[:10]}",
            name=f"Completion reservation {label}",
            description="Disposable PostgreSQL completion-reservation authority.",
            spec=_spec(label),
        )
        workflow, created = await workflow_runtime.create_workflow(
            db,
            ACTOR,
            project_revision_id=revision.id,
            workflow_type="cti.report",
            idempotency_token=f"completion-reservation-{label}-{uuid.uuid4().hex}",
            input_manifest={"report_id": label, "source_ids": ["source-a"]},
            stage_plan=_plan(target_count, sibling_root=sibling_root),
            priority=0,
        )
        assert created is True
        workflow_id = uuid.UUID(str(workflow.id))
        await db.commit()
        return workflow_id


async def _message_id(
    workflow_id: uuid.UUID,
    stage_key: str,
    *,
    emission_kind: str = "root_ready",
) -> uuid.UUID:
    async with async_session_factory() as db:
        value = await db.scalar(
            select(OutboxMessage.id).where(
                OutboxMessage.workflow_run_id == workflow_id,
                OutboxMessage.stage_key == stage_key,
                OutboxMessage.emission_kind == emission_kind,
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


async def _activate(
    label: str,
    *,
    target_count: int,
    sibling_root: bool = False,
    lease_seconds: int = 120,
) -> tuple[uuid.UUID, outbox_runtime.ExecutableStageAuthority]:
    workflow_id = await _new_workflow(
        label,
        target_count=target_count,
        sibling_root=sibling_root,
    )
    message_id = await _message_id(workflow_id, "collect")
    async with _isolate_outbox_queue({message_id}):
        async with async_session_factory() as db:
            claim = await outbox_runtime.claim_outbox_delivery(
                db,
                publisher_id=f"completion-reservation-publisher-{uuid.uuid4().hex[:8]}",
                lease_seconds=120,
            )
            assert claim is not None and claim.message_id == message_id
            await db.commit()

    command = outbox_runtime.StageReceiptCommand(
        claim=claim,
        broker_name="postgres_test_broker",
        broker_message_id=f"completion-reservation-{label}-{claim.cycle_key}",
        broker_receipt_id=hashlib.sha256(f"completion-reservation:{label}:{claim.cycle_key}".encode()).hexdigest(),
        worker_id=f"completion-reservation-worker-{label}",
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


async def _graph_snapshot(
    authority: outbox_runtime.ExecutableStageAuthority,
) -> tuple[tuple[tuple[str, object], ...], ...]:
    async with async_session_factory() as db:
        workflow = await db.get(WorkflowRun, authority.workflow_run_id)
        stages = tuple(
            (
                await db.scalars(
                    select(StageRun)
                    .where(StageRun.workflow_run_id == authority.workflow_run_id)
                    .order_by(StageRun.ordinal.asc(), StageRun.id.asc())
                )
            ).all()
        )
        message = await db.get(OutboxMessage, authority.message_id)
        delivery = await db.get(
            OutboxDeliveryAttempt,
            authority.delivery_attempt_id,
        )
        attempt = await db.get(StageAttempt, authority.stage_attempt_id)
        assert workflow is not None
        assert stages
        assert message is not None and delivery is not None and attempt is not None
        return tuple(_row_snapshot(value) for value in (workflow, *stages, message, delivery, attempt))


async def _cancel_if_active(workflow_id: uuid.UUID) -> None:
    await cancel_active_workflow(
        async_session_factory,
        workflow_run_id=workflow_id,
        actor=ACTOR,
        reason="Completion-reservation acceptance cleanup.",
    )


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
    raise AssertionError("Cancellation coordinator did not enter the workflow lock wait")


def _selected(statements: list[str]) -> list[str]:
    return [statement for statement in statements if statement.lstrip().upper().startswith("SELECT")]


def _assert_lock_order(
    statements: list[str],
    *,
    target_count: int,
) -> None:
    selected = _selected(statements)
    expected_reserve_count = 1 + 1 + target_count + 1 + 1 + 1 + 1
    assert len(selected) == expected_reserve_count + 1
    cursor = 0
    assert "FROM workflow_runs" in selected[cursor]
    assert "FOR UPDATE" in selected[cursor]
    cursor += 1
    assert "FROM stage_runs" in selected[cursor]
    assert "ORDER BY stage_runs.ordinal ASC, stage_runs.id ASC" in selected[cursor]
    assert "FOR UPDATE" in selected[cursor]
    cursor += 1
    assert all(
        "FROM outbox_messages" in statement and "FOR UPDATE" not in statement for statement in selected[cursor : cursor + target_count]
    )
    cursor += target_count
    assert "FROM outbox_messages" in selected[cursor]
    assert "FOR UPDATE" in selected[cursor]
    cursor += 1
    assert "FROM outbox_delivery_attempts" in selected[cursor]
    assert "FOR UPDATE" in selected[cursor]
    cursor += 1
    assert "FROM stage_attempts" in selected[cursor]
    assert "FOR UPDATE" in selected[cursor]
    cursor += 1
    assert "clock_timestamp" in selected[cursor]
    assert "FOR UPDATE" not in selected[cursor]
    cursor += 1
    assert "clock_timestamp" in selected[cursor]
    assert "FOR UPDATE" not in selected[cursor]
    assert all(not statement.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE")) for statement in statements)


async def _assert_nowait_unlocked(
    *,
    workflow_id: uuid.UUID,
    stage_ids: tuple[uuid.UUID, ...],
    message_ids: tuple[uuid.UUID, ...],
    delivery_ids: tuple[uuid.UUID, ...],
    attempt_id: uuid.UUID,
) -> None:
    async with async_session_factory() as db:
        async with db.begin():
            rows = (
                (WorkflowRun, (workflow_id,)),
                (StageRun, stage_ids),
                (OutboxMessage, message_ids),
                (OutboxDeliveryAttempt, delivery_ids),
                (StageAttempt, (attempt_id,)),
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
@pytest.mark.parametrize("target_count", [0, 1, 2])
async def test_completion_graph_fanout_is_read_only_ordered_and_unlocked(
    target_count: int,
):
    workflow_id, authority = await _activate(
        f"fanout-{target_count}",
        target_count=target_count,
    )
    before = await _graph_snapshot(authority)
    statements: list[str] = []

    def capture(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", capture)
    try:
        async with async_session_factory() as db:
            async with db.begin():
                reservation = await outbox_runtime.reserve_stage_completion_graph(
                    db,
                    authority=authority,
                )
                locked = await outbox_runtime.consume_stage_completion_graph(
                    db,
                    reservation=reservation,
                    authority=authority,
                )
                stage_ids = tuple(uuid.UUID(str(stage.id)) for stage in locked.stages)
                message_ids = tuple(locked.locked_message_ids)
                delivery_ids = tuple(locked.locked_delivery_ids)
                assert len(locked.target_projections) == target_count
                assert len(locked.intents) == target_count
                assert locked.existing_target_messages == (None,) * target_count
                assert locked.active_target_deliveries == (None,) * target_count
                assert all(intent.emission_kind == "dependency_ready" for intent in locked.intents)
                assert all(intent.post_target.next_attempt_at == locked.observed_at for intent in locked.intents)
                assert message_ids == (authority.message_id,)
                assert delivery_ids == (authority.delivery_attempt_id,)
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", capture)

    _assert_lock_order(
        statements,
        target_count=target_count,
    )
    assert await _graph_snapshot(authority) == before
    await _assert_nowait_unlocked(
        workflow_id=workflow_id,
        stage_ids=stage_ids,
        message_ids=message_ids,
        delivery_ids=delivery_ids,
        attempt_id=authority.stage_attempt_id,
    )
    await _cancel_if_active(workflow_id)


@pytest.mark.asyncio
async def test_database_rejects_a_post_start_stage_outside_the_persisted_plan():
    workflow_id, _authority = await _activate(
        "rogue-stage",
        target_count=1,
    )
    async with async_session_factory() as db:
        source = await db.scalar(
            select(StageRun).where(
                StageRun.workflow_run_id == workflow_id,
                StageRun.stage_key == "collect",
            )
        )
        assert source is not None
        rogue = StageRun(
            id=uuid.uuid4(),
            workflow_run_id=workflow_id,
            stage_key="rogue_extra",
            stage_type="test.rogue_extra",
            stage_version="1.0.0",
            ordinal=99,
            status="pending",
            priority=0,
            state_version=1,
            idempotency_key=checksum_json(
                {
                    "workflow_run_id": str(workflow_id),
                    "stage_key": "rogue_extra",
                }
            ),
            depends_on=["collect"],
            required=True,
            config_schema_version="research-stage-config-v1",
            config={"acceptance_test": True, "stage": "rogue_extra"},
            config_checksum=checksum_json({"acceptance_test": True, "stage": "rogue_extra"}),
            input_manifest=source.input_manifest,
            input_checksum=source.input_checksum,
            output_manifest={},
            output_checksum="",
            checkpoint={},
            checkpoint_schema_version="research-stage-checkpoint-v1",
            checkpoint_version=0,
            checkpoint_checksum=checksum_json({}),
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
        rogue_id = uuid.UUID(str(rogue.id))
        db.add(rogue)
        with pytest.raises(
            IntegrityError,
            match="new stages require one locked queued current-v1 workflow",
        ):
            await db.commit()
        await db.rollback()

    async with async_session_factory() as db:
        persisted = await db.get(StageRun, rogue_id)
        assert persisted is None
    await _cancel_if_active(workflow_id)


@pytest.mark.asyncio
async def test_post_attempt_lock_clock_rejects_a_lease_expired_while_waiting():
    workflow_id, authority = await _activate(
        "post-lock-expiry",
        target_count=2,
        lease_seconds=2,
    )
    before = await _graph_snapshot(authority)
    blocker = async_session_factory()
    await blocker.begin()
    await blocker.execute(select(StageAttempt).where(StageAttempt.id == authority.stage_attempt_id).with_for_update())
    pid_ready: asyncio.Future[int] = asyncio.get_running_loop().create_future()

    async def blocked_reserve():
        try:
            async with async_session_factory() as db:
                async with db.begin():
                    pid = await db.scalar(text("SELECT pg_backend_pid()"))
                    assert isinstance(pid, int)
                    pid_ready.set_result(pid)
                    await outbox_runtime.reserve_stage_completion_graph(
                        db,
                        authority=authority,
                    )
        except Exception as exc:
            return exc
        return None

    task = asyncio.create_task(blocked_reserve())
    try:
        pid = await asyncio.wait_for(pid_ready, timeout=5)
        await _wait_for_backend_lock(pid)
        await _wait_until_db_after(authority.lease_expires_at)
    finally:
        await blocker.rollback()
        await blocker.close()
    outcome = await asyncio.wait_for(task, timeout=10)
    assert isinstance(outcome, outbox_runtime.OutboxLeaseLost)
    assert "no longer live" in str(outcome)
    assert await _graph_snapshot(authority) == before
    await _cancel_if_active(workflow_id)


@pytest.mark.asyncio
async def test_consume_rechecks_expiry_spends_capability_and_writes_nothing():
    workflow_id, authority = await _activate(
        "consume-expiry",
        target_count=1,
        lease_seconds=2,
    )
    before = await _graph_snapshot(authority)
    async with async_session_factory() as db:
        await db.begin()
        reservation = await outbox_runtime.reserve_stage_completion_graph(
            db,
            authority=authority,
        )
        await _wait_until_db_after(authority.lease_expires_at)
        with pytest.raises(outbox_runtime.OutboxLeaseLost, match="no longer live"):
            await outbox_runtime.consume_stage_completion_graph(
                db,
                reservation=reservation,
                authority=authority,
            )
        with pytest.raises(outbox_runtime.OutboxConflict, match="not registered"):
            await outbox_runtime.consume_stage_completion_graph(
                db,
                reservation=reservation,
                authority=authority,
            )
        await db.rollback()
    assert await _graph_snapshot(authority) == before
    await _cancel_if_active(workflow_id)


@pytest.mark.asyncio
async def test_completion_capability_forgery_reuse_session_root_savepoint_and_dirty_fences():
    workflow_id, authority = await _activate(
        "capability",
        target_count=1,
    )
    before = await _graph_snapshot(authority)
    reservation = None
    async with async_session_factory() as db:
        await db.begin()
        reservation = await outbox_runtime.reserve_stage_completion_graph(
            db,
            authority=authority,
        )
        forged = replace(reservation)
        with pytest.raises(outbox_runtime.OutboxConflict, match="not registered"):
            await outbox_runtime.consume_stage_completion_graph(
                db,
                reservation=forged,
                authority=authority,
            )
        with pytest.raises(outbox_runtime.OutboxConflict, match="already reserved"):
            await outbox_runtime.reserve_stage_completion_graph(
                db,
                authority=authority,
            )
        with pytest.raises(outbox_runtime.OutboxConflict, match="already reserved"):
            await outbox_runtime.reserve_stage_execution_receipt(
                db,
                authority=authority,
            )

        async with async_session_factory() as other:
            async with other.begin():
                with pytest.raises(outbox_runtime.OutboxConflict, match="not registered"):
                    await outbox_runtime.consume_stage_completion_graph(
                        other,
                        reservation=reservation,
                        authority=authority,
                    )

        nested = await db.begin_nested()
        with pytest.raises(outbox_runtime.OutboxConflict, match="nested transaction"):
            await outbox_runtime.consume_stage_completion_graph(
                db,
                reservation=reservation,
                authority=authority,
            )
        await nested.rollback()
        locked = await outbox_runtime.consume_stage_completion_graph(
            db,
            reservation=reservation,
            authority=authority,
        )
        assert locked.source_attempt.id == authority.stage_attempt_id
        with pytest.raises(outbox_runtime.OutboxConflict, match="not registered"):
            await outbox_runtime.consume_stage_completion_graph(
                db,
                reservation=reservation,
                authority=authority,
            )
        await db.rollback()

    async with async_session_factory() as db:
        async with db.begin():
            with pytest.raises(outbox_runtime.OutboxConflict, match="not registered"):
                await outbox_runtime.consume_stage_completion_graph(
                    db,
                    reservation=reservation,
                    authority=authority,
                )

    statements: list[str] = []

    def capture(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)

    async with async_session_factory() as db:
        await db.begin()
        workflow = await db.get(WorkflowRun, workflow_id)
        assert workflow is not None
        workflow.status_summary = "dirty identity-map authority"
        event.listen(engine.sync_engine, "before_cursor_execute", capture)
        try:
            with pytest.raises(outbox_runtime.OutboxConflict, match="entirely clean"):
                await outbox_runtime.reserve_stage_completion_graph(
                    db,
                    authority=authority,
                )
        finally:
            event.remove(engine.sync_engine, "before_cursor_execute", capture)
        assert statements == []
        await db.rollback()

    assert await _graph_snapshot(authority) == before
    await _cancel_if_active(workflow_id)


@pytest.mark.asyncio
async def test_competing_completion_reservations_serialize_on_the_workflow_lock():
    workflow_id, authority = await _activate(
        "serialized-reservations",
        target_count=2,
    )
    before = await _graph_snapshot(authority)
    first = async_session_factory()
    await first.begin()
    first_reservation = await outbox_runtime.reserve_stage_completion_graph(
        first,
        authority=authority,
    )
    pid_ready: asyncio.Future[int] = asyncio.get_running_loop().create_future()

    async def competing_reservation():
        async with async_session_factory() as db:
            await db.begin()
            pid = await db.scalar(text("SELECT pg_backend_pid()"))
            assert isinstance(pid, int)
            pid_ready.set_result(pid)
            reservation = await outbox_runtime.reserve_stage_completion_graph(
                db,
                authority=authority,
            )
            locked = await outbox_runtime.consume_stage_completion_graph(
                db,
                reservation=reservation,
                authority=authority,
            )
            await db.rollback()
            return locked

    task = asyncio.create_task(competing_reservation())
    try:
        pid = await asyncio.wait_for(pid_ready, timeout=5)
        await _wait_for_backend_lock(pid)
        assert not task.done()
        first_locked = await outbox_runtime.consume_stage_completion_graph(
            first,
            reservation=first_reservation,
            authority=authority,
        )
        assert len(first_locked.intents) == 2
    finally:
        await first.rollback()
        await first.close()

    second_locked = await asyncio.wait_for(task, timeout=10)
    assert len(second_locked.intents) == 2
    assert await _graph_snapshot(authority) == before
    await _cancel_if_active(workflow_id)


@pytest.mark.asyncio
async def test_completion_reservation_does_not_block_an_unrelated_publisher_and_serializes_cancel():
    workflow_id, authority = await _activate(
        "publisher-cancel-competition",
        target_count=1,
        sibling_root=True,
    )
    sibling_message_id = await _message_id(workflow_id, "sibling")
    completion = async_session_factory()
    await completion.begin()
    reservation = await outbox_runtime.reserve_stage_completion_graph(
        completion,
        authority=authority,
    )

    async with _isolate_outbox_queue({sibling_message_id}):
        async with async_session_factory() as publisher:
            claim = await asyncio.wait_for(
                outbox_runtime.claim_outbox_delivery(
                    publisher,
                    publisher_id="completion-reservation-competing-publisher",
                    lease_seconds=120,
                ),
                timeout=5,
            )
            assert claim is not None
            assert claim.message_id == sibling_message_id
            await publisher.rollback()

    async def competing_cancel():
        return await workflow_worker.coordinate_workflow_cancel(
            async_session_factory,
            command=cancellation_command(
                workflow_run_id=workflow_id,
                expected_workflow_state_version=authority.workflow_state_version,
                actor=ACTOR,
                reason="Completion reservation cancellation competition.",
            ),
        )

    task = asyncio.create_task(competing_cancel())
    try:
        await _wait_for_workflow_lock_wait()
        assert not task.done()
        locked = await outbox_runtime.consume_stage_completion_graph(
            completion,
            reservation=reservation,
            authority=authority,
        )
        assert len(locked.intents) == 1
    finally:
        await completion.rollback()
        await completion.close()

    cancelled = await asyncio.wait_for(task, timeout=10)
    assert cancelled.disposition == "applied"
    assert cancelled.workflow_run_id == workflow_id
