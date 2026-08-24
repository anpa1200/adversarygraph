"""Real-PostgreSQL acceptance for receipt-bound stage execution reservations.

Run only against a disposable database migrated through revision 0004::

    RUN_POSTGRES_TESTS=1 python -m pytest -q -o addopts='' \
      --confcutdir=tests/postgres \
      tests/postgres/test_stage_execution_reservation.py
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import datetime, timedelta
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
from tests.postgres._workflow_authority import cancel_active_workflow


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_POSTGRES_TESTS") != "1",
    reason="requires an explicitly authorized disposable PostgreSQL database",
)

ACTOR = projects.ResearchActor(
    name="PostgreSQL Stage Execution Reservation Test",
    actor_id="postgres-stage-execution-reservation",
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
        "objective": f"Validate stage execution receipt reservation: {label}.",
        "intelligence_requirements": [
            "Can only exact committed receipt lineage authorize source execution?",
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
        "config": {"acceptance_test": True, "source_execution": True},
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
            project_key=f"execution-reservation-{label}-{uuid.uuid4().hex[:10]}",
            name=f"Execution reservation {label}",
            description="Disposable PostgreSQL execution-reservation authority.",
            spec=_spec(label),
        )
        workflow, created = await workflow_runtime.create_workflow(
            db,
            ACTOR,
            project_revision_id=revision.id,
            workflow_type="cti.report",
            idempotency_token=f"execution-reservation-{label}-{uuid.uuid4().hex}",
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
        value = await db.scalar(
            select(OutboxMessage.id).where(
                OutboxMessage.workflow_run_id == workflow_id,
                OutboxMessage.stage_key == "collect",
                OutboxMessage.emission_kind == "root_ready",
                OutboxMessage.redrive_ordinal == 0,
            )
        )
    assert isinstance(value, uuid.UUID)
    return uuid.UUID(str(value))


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


async def _claim_root(
    workflow_id: uuid.UUID,
    *,
    lease_seconds: int = 120,
) -> outbox_runtime.ClaimedOutboxDelivery:
    message_id = await _root_message_id(workflow_id)
    return await _claim_message(message_id, lease_seconds=lease_seconds)


async def _claim_message(
    message_id: uuid.UUID,
    *,
    lease_seconds: int = 120,
) -> outbox_runtime.ClaimedOutboxDelivery:
    async with _isolate_outbox_queue(message_id):
        async with async_session_factory() as db:
            claim = await outbox_runtime.claim_outbox_delivery(
                db,
                publisher_id=f"execution-reservation-publisher-{uuid.uuid4().hex[:8]}",
                lease_seconds=lease_seconds,
            )
            assert claim is not None and claim.message_id == message_id
            await db.commit()
            return claim


def _receipt_command(
    claim: outbox_runtime.ClaimedOutboxDelivery,
    *,
    label: str,
    lease_seconds: int,
) -> outbox_runtime.StageReceiptCommand:
    return outbox_runtime.StageReceiptCommand(
        claim=claim,
        broker_name="postgres_test_broker",
        broker_message_id=f"execution-reservation-{label}-{claim.cycle_key}",
        broker_receipt_id=hashlib.sha256(f"execution-reservation:{label}:{claim.cycle_key}".encode()).hexdigest(),
        worker_id=f"execution-reservation-worker-{label}",
        lease_seconds=lease_seconds,
    )


async def _activate(
    label: str,
    *,
    lease_seconds: int = 120,
) -> tuple[uuid.UUID, outbox_runtime.ExecutableStageAuthority]:
    workflow_id = await _new_workflow(label)
    claim = await _claim_root(workflow_id)
    authority = await _coordinate_claim(
        claim,
        label=label,
        lease_seconds=lease_seconds,
    )
    return workflow_id, authority


async def _coordinate_claim(
    claim: outbox_runtime.ClaimedOutboxDelivery,
    *,
    label: str,
    lease_seconds: int = 120,
) -> outbox_runtime.ExecutableStageAuthority:
    coordinated = await outbox_coordinator.coordinate_stage_receipt(
        async_session_factory,
        command=_receipt_command(
            claim,
            label=label,
            lease_seconds=lease_seconds,
        ),
    )
    assert coordinated.disposition == "activated"
    assert coordinated.should_execute is True
    assert coordinated.should_ack is True
    assert coordinated.authority is not None
    return coordinated.authority


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


async def _lineage_snapshots(
    authority: outbox_runtime.ExecutableStageAuthority,
) -> tuple[tuple[tuple[str, object], ...], tuple[tuple[str, object], ...]]:
    async with async_session_factory() as db:
        message = await db.get(OutboxMessage, authority.message_id)
        delivery = await db.get(
            OutboxDeliveryAttempt,
            authority.delivery_attempt_id,
        )
        assert message is not None and delivery is not None
        return _row_snapshot(message), _row_snapshot(delivery)


async def _cancel_if_active(workflow_id: uuid.UUID) -> None:
    await cancel_active_workflow(
        async_session_factory,
        workflow_run_id=workflow_id,
        actor=ACTOR,
        reason="Stage execution reservation acceptance cleanup.",
    )


async def _wait_for_backend_lock(pid: int) -> None:
    for _ in range(150):
        async with engine.connect() as connection:
            waiting = await connection.scalar(
                text("SELECT wait_event_type = 'Lock' FROM pg_stat_activity WHERE pid = :pid"),
                {"pid": pid},
            )
        if waiting is True:
            return
        await asyncio.sleep(0.02)
    raise AssertionError(f"PostgreSQL backend {pid} did not enter a lock wait")


async def _wait_until_db_after(moment: datetime) -> None:
    for _ in range(250):
        async with engine.connect() as connection:
            now = await connection.scalar(select(func.clock_timestamp()))
        if isinstance(now, datetime) and now > moment:
            return
        await asyncio.sleep(0.02)
    raise AssertionError("PostgreSQL clock did not advance past the stage lease")


@pytest.mark.asyncio
async def test_reserve_consume_locks_w_s_m_d_a_and_preserves_delivered_lineage():
    workflow_id, authority = await _activate("lock-order")
    before = await _lineage_snapshots(authority)
    statements: list[str] = []

    def capture(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)

    try:
        event.listen(engine.sync_engine, "before_cursor_execute", capture)
        async with async_session_factory() as db:
            async with db.begin():
                reservation = await outbox_runtime.reserve_stage_execution_receipt(
                    db,
                    authority=authority,
                )
                query_count = len(statements)
                locked = await outbox_runtime.consume_stage_execution_receipt(
                    db,
                    reservation=reservation,
                    authority=authority,
                )
                assert len(statements) == query_count + 1
                assert locked.authority == authority
                assert locked.workflow.id == authority.workflow_run_id
                assert locked.stage.id == authority.stage_run_id
                assert locked.message.id == authority.message_id
                assert locked.delivery.id == authority.delivery_attempt_id
                assert locked.attempt.id == authority.stage_attempt_id
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", capture)

    selected = [statement for statement in statements if statement.lstrip().upper().startswith("SELECT")]
    assert len(selected) == 7
    assert [
        "FROM workflow_runs" in selected[0],
        "FROM stage_runs" in selected[1],
        "FROM outbox_messages" in selected[2],
        "FROM outbox_delivery_attempts" in selected[3],
        "FROM stage_attempts" in selected[4],
        "clock_timestamp" in selected[5],
        "clock_timestamp" in selected[6],
    ] == [True] * 7
    assert all("FOR UPDATE" in statement for statement in selected[:5])
    assert all("FOR UPDATE" not in statement for statement in selected[5:])

    async with async_session_factory() as db:
        attempt = await db.get(StageAttempt, authority.stage_attempt_id)
        message = await db.get(OutboxMessage, authority.message_id)
        delivery = await db.get(
            OutboxDeliveryAttempt,
            authority.delivery_attempt_id,
        )
        assert attempt is not None and message is not None and delivery is not None
        assert message.status == delivery.status == "delivered"
        assert attempt.outbox_delivery_attempt_id == delivery.id
        assert attempt.delivery_id == delivery.cycle_key == message.cycle_key
        assert message.active_delivery_attempt_id is None
        assert delivery.completed_at is not None
        assert attempt.started_at is not None
        assert message.delivered_at == delivery.completed_at
        assert delivery.completed_at <= attempt.started_at
    assert await _lineage_snapshots(authority) == before
    await _cancel_if_active(workflow_id)


@pytest.mark.asyncio
async def test_retry_scheduled_receipt_provenance_can_reserve_and_consume():
    workflow_id, first_authority = await _activate("retry-provenance")
    failed = await workflow_worker.coordinate_stage_fail(
        async_session_factory,
        authority=first_authority,
        error_text="Disposable source provider timed out",
        error_code="source.fetch_timeout",
        retryable=True,
        error_class="TimeoutError",
    )
    assert failed.disposition == "recorded"
    assert failed.decision == "retry"
    assert failed.should_retry is True
    assert failed.retry_emission is not None
    first_attempt_id = failed.stage_attempt_id

    async with async_session_factory() as db:
        message = await db.scalar(
            select(OutboxMessage).where(
                OutboxMessage.workflow_run_id == workflow_id,
                OutboxMessage.stage_run_id == first_authority.stage_run_id,
                OutboxMessage.emission_kind == "retry_scheduled",
                OutboxMessage.target_attempt_number == 2,
                OutboxMessage.redrive_ordinal == 0,
            )
        )
        assert message is not None
        assert message.status == "pending"
        assert message.causation_id == first_attempt_id
        assert message.available_at is not None
        retry_message_id = uuid.UUID(str(message.id))
        retry_available_at = message.available_at

    await _wait_until_db_after(retry_available_at)
    retry_claim = await _claim_message(retry_message_id)
    authority = await _coordinate_claim(
        retry_claim,
        label="retry-provenance",
    )
    assert authority.attempt_number == 2
    assert authority.stage_run_id == first_authority.stage_run_id
    before = await _lineage_snapshots(authority)

    async with async_session_factory() as db:
        async with db.begin():
            reservation = await outbox_runtime.reserve_stage_execution_receipt(
                db,
                authority=authority,
            )
            locked = await outbox_runtime.consume_stage_execution_receipt(
                db,
                reservation=reservation,
                authority=authority,
            )
            assert locked.authority == authority
            assert locked.message.emission_kind == "retry_scheduled"
            assert locked.message.causation_id == first_attempt_id
            assert locked.message.target_attempt_number == 2
            assert locked.attempt.attempt_number == 2
            assert locked.attempt.outbox_delivery_attempt_id == locked.delivery.id

    assert await _lineage_snapshots(authority) == before
    await _cancel_if_active(workflow_id)


@pytest.mark.asyncio
async def test_reservation_rollback_forgery_reuse_and_savepoint_are_fail_closed():
    workflow_id, authority = await _activate("capability")
    before = await _lineage_snapshots(authority)
    reservation = None
    async with async_session_factory() as db:
        await db.begin()
        nested = await db.begin_nested()
        with pytest.raises(outbox_runtime.OutboxConflict, match="nested transaction"):
            await outbox_runtime.reserve_stage_execution_receipt(
                db,
                authority=authority,
            )
        await nested.rollback()

        reservation = await outbox_runtime.reserve_stage_execution_receipt(
            db,
            authority=authority,
        )
        with pytest.raises(outbox_runtime.OutboxConflict, match="already reserved"):
            await outbox_runtime.reserve_stage_execution_receipt(
                db,
                authority=authority,
            )
        forged = replace(reservation)
        with pytest.raises(outbox_runtime.OutboxConflict, match="not registered"):
            await outbox_runtime.consume_stage_execution_receipt(
                db,
                reservation=forged,
                authority=authority,
            )

        nested = await db.begin_nested()
        with pytest.raises(outbox_runtime.OutboxConflict, match="nested transaction"):
            await outbox_runtime.consume_stage_execution_receipt(
                db,
                reservation=reservation,
                authority=authority,
            )
        await nested.rollback()

        locked = await outbox_runtime.consume_stage_execution_receipt(
            db,
            reservation=reservation,
            authority=authority,
        )
        assert locked.attempt.id == authority.stage_attempt_id
        with pytest.raises(outbox_runtime.OutboxConflict, match="not registered"):
            await outbox_runtime.consume_stage_execution_receipt(
                db,
                reservation=reservation,
                authority=authority,
            )
        await db.rollback()

    async with async_session_factory() as other:
        async with other.begin():
            with pytest.raises(outbox_runtime.OutboxConflict, match="not registered"):
                await outbox_runtime.consume_stage_execution_receipt(
                    other,
                    reservation=reservation,
                    authority=authority,
                )
    assert await _lineage_snapshots(authority) == before
    await _cancel_if_active(workflow_id)


@pytest.mark.asyncio
async def test_forged_and_wrong_executable_authority_cannot_reserve():
    workflow_id, authority = await _activate("forged-authority")

    forged = object.__new__(outbox_runtime.ExecutableStageAuthority)
    for field_name in authority.__dataclass_fields__:
        object.__setattr__(forged, field_name, getattr(authority, field_name))
    object.__setattr__(forged, "broker_receipt_id", "raw-secret-receipt-handle")

    statements: list[str] = []

    def capture(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", capture)
    try:
        async with async_session_factory() as db:
            async with db.begin():
                with pytest.raises(outbox_runtime.OutboxValidation):
                    await outbox_runtime.reserve_stage_execution_receipt(
                        db,
                        authority=forged,
                    )
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", capture)
    assert statements == []

    stale = replace(
        authority,
        attempt_state_version=authority.attempt_state_version + 1,
    )
    async with async_session_factory() as db:
        async with db.begin():
            with pytest.raises(outbox_runtime.OutboxLeaseLost, match="no longer matches"):
                await outbox_runtime.reserve_stage_execution_receipt(
                    db,
                    authority=stale,
                )

    statements.clear()
    event.listen(engine.sync_engine, "before_cursor_execute", capture)
    try:
        async with async_session_factory() as db:
            await db.begin()
            workflow = await db.get(WorkflowRun, authority.workflow_run_id)
            assert workflow is not None
            workflow.status_summary = "hostile pending identity-map mutation"
            statements.clear()
            with pytest.raises(outbox_runtime.OutboxConflict, match="entirely clean session"):
                await outbox_runtime.reserve_stage_execution_receipt(
                    db,
                    authority=authority,
                )
            assert statements == []
            await db.rollback()
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", capture)
    await _cancel_if_active(workflow_id)


async def _raw_null_link_authority(
    label: str,
) -> tuple[uuid.UUID, outbox_runtime.ExecutableStageAuthority]:
    """Attempt to create forbidden current-v1 running A authority with a NULL D link."""

    workflow_id = await _new_workflow(label)
    claim = await _claim_root(workflow_id)
    broker_name = "postgres_test_broker"
    broker_message_id = f"raw-expand-{claim.cycle_key}"
    broker_receipt_id = hashlib.sha256(f"raw-expand-receipt:{claim.cycle_key}".encode()).hexdigest()
    async with async_session_factory() as db:
        dispatched = await outbox_runtime.mark_outbox_dispatched(
            db,
            message_id=claim.message_id,
            delivery_attempt_id=claim.delivery_attempt_id,
            delivery_token=claim.delivery_token,
            expected_message_version=claim.message_state_version,
            expected_delivery_version=claim.delivery_state_version,
            broker_name=broker_name,
            broker_message_id=broker_message_id,
            receipt_timeout_seconds=120,
        )
        await db.commit()

    async with async_session_factory() as db:
        workflow = await db.scalar(select(WorkflowRun).where(WorkflowRun.id == workflow_id).with_for_update())
        assert workflow is not None
        stage = await db.scalar(
            select(StageRun)
            .where(
                StageRun.workflow_run_id == workflow.id,
                StageRun.stage_key == "collect",
            )
            .with_for_update()
        )
        message = await db.scalar(select(OutboxMessage).where(OutboxMessage.id == claim.message_id).with_for_update())
        delivery = await db.scalar(
            select(OutboxDeliveryAttempt).where(OutboxDeliveryAttempt.id == claim.delivery_attempt_id).with_for_update()
        )
        assert stage is not None and message is not None and delivery is not None
        assert message.status == delivery.status == "awaiting_receipt"
        assert message.state_version == dispatched.message.state_version
        assert delivery.state_version == dispatched.delivery.state_version
        now = await db.scalar(select(func.transaction_timestamp()))
        assert isinstance(now, datetime) and now.tzinfo is not None

        delivery.status = "delivered"
        delivery.state_version += 1
        delivery.broker_receipt_id = broker_receipt_id
        delivery.receipt_deadline_at = None
        delivery.receipt_received_at = now
        delivery.completed_at = now
        await db.flush([delivery])

        message.status = "delivered"
        message.state_version += 1
        message.active_delivery_attempt_id = None
        message.receipt_deadline_at = None
        message.delivered_at = now
        await db.flush([message])

        stage_token = uuid.uuid4()
        lease_expires_at = now + timedelta(minutes=2)
        workflow.status = "running"
        workflow.state_version += 1
        workflow.started_at = now
        stage.status = "running"
        stage.state_version += 1
        stage.attempt_count += 1
        stage.next_attempt_at = None
        stage.lease_owner = "raw-expand-worker"
        stage.lease_token = stage_token
        stage.leased_at = now
        stage.heartbeat_at = now
        stage.lease_expires_at = lease_expires_at
        stage.first_started_at = now
        await db.flush([workflow, stage])

        attempt = StageAttempt(
            id=uuid.uuid4(),
            stage_run_id=stage.id,
            outbox_delivery_attempt_id=None,
            attempt_number=stage.attempt_count,
            lease_token=stage_token,
            lease_owner=stage.lease_owner,
            delivery_id=delivery.cycle_key,
            status="running",
            state_version=1,
            input_checksum=stage.input_checksum,
            checkpoint_start_version=stage.checkpoint_version,
            checkpoint_end_version=stage.checkpoint_version,
            output_checksum="",
            error_code="",
            error_class="",
            error_summary="",
            retryable=False,
            started_at=now,
            heartbeat_at=now,
            lease_expires_at=lease_expires_at,
            completed_at=None,
        )
        db.add(attempt)
        await db.flush([attempt])
        authority = outbox_runtime.ExecutableStageAuthority(
            workflow_run_id=uuid.UUID(str(workflow.id)),
            stage_run_id=uuid.UUID(str(stage.id)),
            stage_attempt_id=uuid.UUID(str(attempt.id)),
            message_id=uuid.UUID(str(message.id)),
            delivery_attempt_id=uuid.UUID(str(delivery.id)),
            stage_lease_token=uuid.UUID(str(stage_token)),
            workflow_state_version=workflow.state_version,
            stage_state_version=stage.state_version,
            attempt_state_version=attempt.state_version,
            attempt_number=attempt.attempt_number,
            delivery_cycle=delivery.delivery_cycle,
            cycle_key=delivery.cycle_key,
            stage_key=stage.stage_key,
            input_checksum=stage.input_checksum,
            checkpoint_version=stage.checkpoint_version,
            lease_owner=stage.lease_owner,
            lease_expires_at=lease_expires_at,
            broker_receipt_id=broker_receipt_id,
        )
        await db.commit()
    return workflow_id, authority


@pytest.mark.asyncio
async def test_contract_phase_rejects_null_or_wrong_attempt_delivery_link():
    with pytest.raises(IntegrityError, match="delivered receipt evidence"):
        await _raw_null_link_authority("null-attempt-link")

    workflow_id, authority = await _activate("wrong-attempt-link")
    wrong_delivery = replace(
        authority,
        delivery_attempt_id=uuid.uuid4(),
    )
    async with async_session_factory() as db:
        async with db.begin():
            with pytest.raises(outbox_runtime.OutboxLeaseLost, match="delivery authority"):
                await outbox_runtime.reserve_stage_execution_receipt(
                    db,
                    authority=wrong_delivery,
                )
    await _cancel_if_active(workflow_id)


@pytest.mark.asyncio
async def test_post_lock_wall_clock_rejects_lease_that_expires_while_waiting():
    workflow_id, authority = await _activate(
        "expired-after-lock",
        lease_seconds=2,
    )
    blocker = async_session_factory()
    await blocker.begin()
    await blocker.execute(select(StageRun).where(StageRun.id == authority.stage_run_id).with_for_update())
    pid_ready: asyncio.Future[int] = asyncio.get_running_loop().create_future()

    async def blocked_reservation():
        try:
            async with async_session_factory() as db:
                async with db.begin():
                    pid = await db.scalar(text("SELECT pg_backend_pid()"))
                    assert isinstance(pid, int)
                    pid_ready.set_result(pid)
                    await outbox_runtime.reserve_stage_execution_receipt(
                        db,
                        authority=authority,
                    )
        except Exception as exc:  # return exact runtime outcome to the controller
            return exc
        return None

    task = asyncio.create_task(blocked_reservation())
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
    await _cancel_if_active(workflow_id)


@pytest.mark.asyncio
async def test_consume_uses_a_fresh_wall_clock_and_spends_expired_reservation():
    workflow_id, authority = await _activate(
        "expired-before-consume",
        lease_seconds=2,
    )
    async with async_session_factory() as db:
        await db.begin()
        reservation = await outbox_runtime.reserve_stage_execution_receipt(
            db,
            authority=authority,
        )
        await _wait_until_db_after(authority.lease_expires_at)
        with pytest.raises(outbox_runtime.OutboxLeaseLost, match="no longer live"):
            await outbox_runtime.consume_stage_execution_receipt(
                db,
                reservation=reservation,
                authority=authority,
            )
        with pytest.raises(outbox_runtime.OutboxConflict, match="not registered"):
            await outbox_runtime.consume_stage_execution_receipt(
                db,
                reservation=reservation,
                authority=authority,
            )
        await db.rollback()
    await _cancel_if_active(workflow_id)


@pytest.mark.asyncio
async def test_concurrent_reservations_serialize_without_mutating_message_or_delivery():
    workflow_id, authority = await _activate("concurrent-reservation")
    before = await _lineage_snapshots(authority)
    first = async_session_factory()
    await first.begin()
    first_reservation = await outbox_runtime.reserve_stage_execution_receipt(
        first,
        authority=authority,
    )
    pid_ready: asyncio.Future[int] = asyncio.get_running_loop().create_future()

    async def second_reservation():
        async with async_session_factory() as db:
            async with db.begin():
                pid = await db.scalar(text("SELECT pg_backend_pid()"))
                assert isinstance(pid, int)
                pid_ready.set_result(pid)
                reservation = await outbox_runtime.reserve_stage_execution_receipt(
                    db,
                    authority=authority,
                )
                locked = await outbox_runtime.consume_stage_execution_receipt(
                    db,
                    reservation=reservation,
                    authority=authority,
                )
                return locked.observed_at

    task = asyncio.create_task(second_reservation())
    pid = await asyncio.wait_for(pid_ready, timeout=5)
    await _wait_for_backend_lock(pid)
    first_locked = await outbox_runtime.consume_stage_execution_receipt(
        first,
        reservation=first_reservation,
        authority=authority,
    )
    await first.commit()
    await first.close()
    second_observed = await asyncio.wait_for(task, timeout=10)

    assert second_observed >= first_locked.observed_at
    assert await _lineage_snapshots(authority) == before
    await _cancel_if_active(workflow_id)


@pytest.mark.asyncio
async def test_database_is_on_exact_contract_phase_revision():
    async with async_session_factory() as db:
        heads = tuple((await db.scalars(text("SELECT version_num FROM alembic_version ORDER BY version_num"))).all())
    assert heads == ("20260824_0004",)
