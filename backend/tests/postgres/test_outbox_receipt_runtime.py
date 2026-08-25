"""Real-PostgreSQL acceptance tests for receipt-bound stage activation.

The receipt service is deliberately flush-only.  These tests exercise its
public command and confirmation APIs across real transactions and database
locks; cleanup terminalizes authority instead of deleting audit evidence.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import os
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.database import async_session_factory, engine
from app.models.research_workflow import (
    OutboxDeliveryAttempt,
    OutboxMessage,
    StageAttempt,
    StageRun,
    WorkflowRun,
)
from app.services import outbox_coordinator as coordinator
from app.services import outbox_runtime as runtime
from app.services import research_projects as projects
from app.services import workflow_runtime
from app.services import workflow_worker
from app.services.outbox_engine import sanitize_outbox_error
from app.services.workflow_engine import checksum_json, normalize_stage_plan
from tests.postgres._workflow_authority import (
    cancel_active_workflow,
    cancellation_command,
)


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_POSTGRES_TESTS") != "1",
    reason="requires an explicitly authorized disposable PostgreSQL database",
)

EMPTY_OBJECT_CHECKSUM = hashlib.sha256(b"{}").hexdigest()
EMPTY_LIST_CHECKSUM = hashlib.sha256(b"[]").hexdigest()
ANCIENT_DUE_AT = datetime(2000, 1, 1, tzinfo=timezone.utc)
ACTOR = projects.ResearchActor(
    "PostgreSQL Receipt Runtime Test",
    "postgres-receipt-runtime",
)


def _spec() -> dict:
    return {
        "objective": "Validate receipt-bound stage activation against PostgreSQL.",
        "intelligence_requirements": ["Which receipt races remain safely fenced?"],
        "output_targets": ["canonical_intelligence"],
        "tlp": "TLP:AMBER",
    }


def _stage_plan(stage_key: str) -> list[dict]:
    return [
        {
            "stage_key": stage_key,
            "stage_type": "deterministic.receipt.test",
            "stage_version": "v1",
            "ordinal": 1,
            "depends_on": [],
            "required": True,
            "priority": 5,
            "max_attempts": 3,
            "config_schema_version": "research-stage-config-v1",
            "checkpoint_schema_version": "research-stage-checkpoint-v1",
            "config": {},
        }
    ]


def _workflow(revision_id: UUID, *, stage_key: str) -> WorkflowRun:
    normalized = normalize_stage_plan(_stage_plan(stage_key))
    return WorkflowRun(
        id=uuid4(),
        project_revision_id=revision_id,
        workflow_type="cti.report",
        status="queued",
        trigger_type="api",
        idempotency_key=uuid4().hex + uuid4().hex,
        correlation_id=uuid4(),
        input_manifest={},
        input_checksum=EMPTY_OBJECT_CHECKSUM,
        stage_plan=normalized.as_payload(),
        plan_checksum=normalized.checksum,
        priority=5,
        state_version=1,
        created_by=ACTOR.name,
        created_by_id=ACTOR.actor_id,
    )


def _ready_stage(workflow: WorkflowRun, *, stage_key: str) -> StageRun:
    return StageRun(
        id=uuid4(),
        workflow_run_id=workflow.id,
        stage_key=stage_key,
        stage_type="deterministic.receipt.test",
        stage_version="v1",
        ordinal=1,
        status="ready",
        priority=5,
        state_version=1,
        idempotency_key=checksum_json(
            {"workflow_run_id": str(workflow.id), "stage_key": stage_key},
        ),
        depends_on=[],
        required=True,
        config_schema_version="research-stage-config-v1",
        config={},
        config_checksum=EMPTY_OBJECT_CHECKSUM,
        input_manifest={},
        input_checksum=EMPTY_OBJECT_CHECKSUM,
        output_manifest={},
        output_checksum="",
        checkpoint={},
        checkpoint_schema_version="research-stage-checkpoint-v1",
        checkpoint_version=0,
        checkpoint_checksum=EMPTY_OBJECT_CHECKSUM,
        attempt_count=0,
        max_attempts=3,
        next_attempt_at=ANCIENT_DUE_AT,
    )


async def _create_ready_authority(*, label: str) -> tuple[UUID, UUID]:
    async with async_session_factory() as db:
        _, revision = await projects.create_project(
            db,
            ACTOR,
            project_key=f"receipt-{label}-{uuid4().hex[:12]}",
            name=f"{label} Receipt Project",
            description="Disposable PostgreSQL receipt runtime test.",
            spec=_spec(),
        )
        await db.commit()

        stage_key = f"receipt.{uuid4().hex[:12]}"
        workflow = _workflow(revision.id, stage_key=stage_key)
        db.add(workflow)
        await db.flush([workflow])
        stage = _ready_stage(workflow, stage_key=stage_key)
        db.add(stage)
        await db.flush([stage])
        message, created = await runtime.emit_stage_ready(
            db,
            workflow_run_id=workflow.id,
            stage_run_id=stage.id,
            emission_kind="root_ready",
        )
        assert created is True and message.stage_run_id == stage.id
        await db.commit()
        return UUID(str(workflow.id)), UUID(str(stage.id))


async def _emit_and_claim(
    *,
    label: str,
    lease_seconds: int = 60,
) -> tuple[UUID, UUID, UUID, runtime.ClaimedOutboxDelivery]:
    workflow_id, stage_id = await _create_ready_authority(label=label)
    async with async_session_factory() as db:
        await db.begin()
        message, created = await runtime.emit_stage_ready(
            db,
            workflow_run_id=workflow_id,
            stage_run_id=stage_id,
            emission_kind="root_ready",
        )
        assert created is False
        await db.commit()
        message_id = UUID(str(message.id))

    async with _isolate_outbox_queue({message_id}):
        async with async_session_factory() as db:
            claim = await runtime.claim_outbox_delivery(
                db,
                publisher_id=f"publisher-{label}",
                lease_seconds=lease_seconds,
            )
            assert claim is not None and claim.message_id == message_id
            await db.commit()
    return workflow_id, stage_id, message_id, claim


@asynccontextmanager
async def _isolate_outbox_queue(allowed_message_ids: set[UUID]):
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


def _receipt_command(
    claim: runtime.ClaimedOutboxDelivery,
    *,
    label: str,
    broker_message_id: str | None = None,
    worker_id: str | None = None,
    lease_seconds: int = 120,
) -> runtime.StageReceiptCommand:
    return runtime.StageReceiptCommand(
        claim=claim,
        broker_name="test.broker",
        broker_message_id=broker_message_id or f"broker-{label}-{uuid4().hex}",
        broker_receipt_id=hashlib.sha256(f"receipt:{label}".encode()).hexdigest(),
        worker_id=worker_id or f"worker-{label}",
        lease_seconds=lease_seconds,
    )


async def _cancel_authority(workflow_id: UUID) -> None:
    """Terminalize unresolved receipt authority through the coordinator."""

    await cancel_active_workflow(
        async_session_factory,
        workflow_run_id=workflow_id,
        actor=ACTOR,
        reason="PostgreSQL receipt test cleanup.",
    )


async def _wait_for_backend_lock(pid: int) -> None:
    for _ in range(100):
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
    for _ in range(200):
        async with engine.connect() as connection:
            now = await connection.scalar(select(func.clock_timestamp()))
        if now is not None and now > moment:
            return
        await asyncio.sleep(0.02)
    raise AssertionError("PostgreSQL clock did not advance past the authority deadline")


async def _assert_coordinator_released_authority_locks(
    result: coordinator.CoordinatedStageReceipt,
) -> None:
    """Acquire the complete authority chain immediately with NOWAIT."""

    assert result.stage_attempt_id is not None
    async with async_session_factory() as db:
        workflow = await db.scalar(select(WorkflowRun).where(WorkflowRun.id == result.workflow_run_id).with_for_update(nowait=True))
        stage = await db.scalar(select(StageRun).where(StageRun.id == result.stage_run_id).with_for_update(nowait=True))
        message = await db.scalar(select(OutboxMessage).where(OutboxMessage.id == result.message_id).with_for_update(nowait=True))
        delivery = await db.scalar(
            select(OutboxDeliveryAttempt).where(OutboxDeliveryAttempt.id == result.delivery_attempt_id).with_for_update(nowait=True)
        )
        attempt = await db.scalar(select(StageAttempt).where(StageAttempt.id == result.stage_attempt_id).with_for_update(nowait=True))
        assert all(value is not None for value in (workflow, stage, message, delivery, attempt))
        await db.rollback()


@pytest.mark.asyncio
async def test_direct_receipt_is_flush_only_then_confirms_after_commit():
    await engine.dispose()
    workflow_id = None
    try:
        workflow_id, stage_id, message_id, claim = await _emit_and_claim(label="direct-confirm")
        command = _receipt_command(claim, label="direct-confirm")
        async with async_session_factory() as receipt_db:
            pending = await runtime.receipt_and_claim_stage(
                receipt_db,
                command=command,
            )
            assert pending.disposition == "activated"
            assert pending.should_execute is False
            assert pending.commit_ticket is not None
            assert pending.stage_attempt_id is not None
            assert all(
                type(value) is UUID
                for value in (
                    pending.workflow_run_id,
                    pending.stage_run_id,
                    pending.stage_attempt_id,
                    pending.message_id,
                    pending.delivery_attempt_id,
                )
            )

            async with async_session_factory() as observer:
                observed_stage = await observer.get(StageRun, stage_id)
                observed_message = await observer.get(OutboxMessage, message_id)
                attempt_count = await observer.scalar(
                    select(func.count()).select_from(StageAttempt).where(StageAttempt.stage_run_id == stage_id)
                )
                assert observed_stage.status == "ready"
                assert observed_message.status == "dispatching"
                assert attempt_count == 0

            with pytest.raises(runtime.OutboxConflict, match="commit"):
                await runtime.confirm_committed_activation(
                    receipt_db,
                    commit_ticket=pending.commit_ticket,
                )
            await receipt_db.commit()

        async with async_session_factory() as confirm_db:
            authority = await runtime.confirm_committed_activation(
                confirm_db,
                commit_ticket=pending.commit_ticket,
            )
            assert isinstance(authority, runtime.ExecutableStageAuthority)
            assert authority.workflow_run_id == workflow_id
            assert authority.stage_run_id == stage_id
            assert authority.stage_attempt_id == pending.stage_attempt_id
            assert authority.delivery_attempt_id == claim.delivery_attempt_id
            assert authority.broker_receipt_id == command.broker_receipt_id
            await confirm_db.rollback()

        async with async_session_factory() as db:
            workflow = await db.get(WorkflowRun, workflow_id)
            stage = await db.get(StageRun, stage_id)
            message = await db.get(OutboxMessage, message_id)
            delivery = await db.get(
                OutboxDeliveryAttempt,
                claim.delivery_attempt_id,
            )
            attempt = await db.get(StageAttempt, pending.stage_attempt_id)
            assert workflow.status == stage.status == attempt.status == "running"
            assert message.status == delivery.status == "delivered"
            assert attempt.outbox_delivery_attempt_id == delivery.id
            assert attempt.delivery_id == delivery.cycle_key
            assert attempt.lease_token == stage.lease_token
            assert attempt.lease_token != delivery.delivery_token
            assert message.delivered_at == delivery.completed_at
            assert delivery.receipt_received_at == delivery.completed_at
            assert delivery.broker_receipt_id == command.broker_receipt_id

        async with async_session_factory() as replay_db:
            replay = await runtime.receipt_and_claim_stage(
                replay_db,
                command=command,
            )
            assert replay.disposition == "replayed"
            assert replay.should_execute is False
            assert replay.commit_ticket is None
            assert replay.stage_attempt_id == pending.stage_attempt_id
            await replay_db.rollback()
    finally:
        if workflow_id is not None:
            await _cancel_authority(workflow_id)
        await engine.dispose()


@pytest.mark.asyncio
async def test_awaiting_receipt_preserves_broker_identity_and_confirms():
    await engine.dispose()
    workflow_id = None
    try:
        workflow_id, stage_id, message_id, claim = await _emit_and_claim(label="awaiting-receipt")
        broker_message_id = f"broker-awaiting-{uuid4().hex}"
        async with async_session_factory() as db:
            marked = await runtime.mark_outbox_dispatched(
                db,
                message_id=claim.message_id,
                delivery_attempt_id=claim.delivery_attempt_id,
                delivery_token=claim.delivery_token,
                expected_message_version=claim.message_state_version,
                expected_delivery_version=claim.delivery_state_version,
                broker_name="test.broker",
                broker_message_id=broker_message_id,
                receipt_timeout_seconds=60,
            )
            assert marked.message.status == "awaiting_receipt"
            await db.commit()

        command = _receipt_command(
            claim,
            label="awaiting-receipt",
            broker_message_id=broker_message_id,
        )
        async with async_session_factory() as db:
            pending = await runtime.receipt_and_claim_stage(db, command=command)
            assert pending.disposition == "activated"
            await db.commit()

        async with async_session_factory() as db:
            authority = await runtime.confirm_committed_activation(
                db,
                commit_ticket=pending.commit_ticket,
            )
            assert authority is not None and authority.stage_run_id == stage_id
            await db.rollback()

        async with async_session_factory() as db:
            message = await db.get(OutboxMessage, message_id)
            delivery = await db.get(
                OutboxDeliveryAttempt,
                claim.delivery_attempt_id,
            )
            assert message.status == delivery.status == "delivered"
            assert delivery.broker_name == "test.broker"
            assert delivery.broker_message_id == broker_message_id
            assert delivery.broker_receipt_id == command.broker_receipt_id
    finally:
        if workflow_id is not None:
            await _cancel_authority(workflow_id)
        await engine.dispose()


@pytest.mark.asyncio
async def test_rolled_back_receipt_ticket_never_confirms():
    await engine.dispose()
    workflow_id = None
    try:
        workflow_id, stage_id, message_id, claim = await _emit_and_claim(label="receipt-rollback")
        command = _receipt_command(claim, label="receipt-rollback")
        async with async_session_factory() as db:
            pending = await runtime.receipt_and_claim_stage(db, command=command)
            assert pending.commit_ticket is not None
            await db.rollback()

        async with async_session_factory() as db:
            assert (
                await runtime.confirm_committed_activation(
                    db,
                    commit_ticket=pending.commit_ticket,
                )
                is None
            )
            await db.rollback()

        async with async_session_factory() as db:
            stage = await db.get(StageRun, stage_id)
            message = await db.get(OutboxMessage, message_id)
            delivery = await db.get(
                OutboxDeliveryAttempt,
                claim.delivery_attempt_id,
            )
            attempts = await db.scalar(select(func.count()).select_from(StageAttempt).where(StageAttempt.stage_run_id == stage_id))
            assert stage.status == "ready"
            assert message.status == delivery.status == "dispatching"
            assert attempts == 0
    finally:
        if workflow_id is not None:
            await _cancel_authority(workflow_id)
        await engine.dispose()


@pytest.mark.asyncio
async def test_concurrent_duplicate_receipt_has_one_activation_and_one_replay():
    await engine.dispose()
    workflow_id = None
    try:
        workflow_id, stage_id, _, claim = await _emit_and_claim(label="duplicate-receipt")
        command = _receipt_command(claim, label="duplicate-receipt")
        start = asyncio.Event()

        async def receipt_once():
            async with async_session_factory() as db:
                await db.execute(text("SET LOCAL lock_timeout = '5s'"))
                await start.wait()
                result = await runtime.receipt_and_claim_stage(db, command=command)
                await db.commit()
                return result

        tasks = [asyncio.create_task(receipt_once()) for _ in range(2)]
        await asyncio.sleep(0)
        start.set()
        outcomes = await asyncio.wait_for(asyncio.gather(*tasks), timeout=8)
        assert sorted(item.disposition for item in outcomes) == [
            "activated",
            "replayed",
        ]
        activated = next(item for item in outcomes if item.disposition == "activated")
        replayed = next(item for item in outcomes if item.disposition == "replayed")
        assert activated.commit_ticket is not None
        assert replayed.commit_ticket is None
        assert replayed.stage_attempt_id == activated.stage_attempt_id

        async with async_session_factory() as db:
            attempts = list((await db.scalars(select(StageAttempt).where(StageAttempt.stage_run_id == stage_id))).all())
            assert len(attempts) == 1
            authority = await runtime.confirm_committed_activation(
                db,
                commit_ticket=activated.commit_ticket,
            )
            assert authority is not None
            await db.rollback()
    finally:
        if workflow_id is not None:
            await _cancel_authority(workflow_id)
        await engine.dispose()


@pytest.mark.asyncio
async def test_stale_and_cancelled_receipts_never_mint_execution():
    await engine.dispose()
    workflow_ids: list[UUID] = []
    try:
        stale_workflow, _, _, stale_claim = await _emit_and_claim(label="stale-receipt")
        workflow_ids.append(stale_workflow)
        error = sanitize_outbox_error(
            "Publisher permanently rejected the delivery.",
            code="outbox.publisher_rejected",
            retryable=False,
            error_class="PublisherRejected",
        )
        async with async_session_factory() as db:
            await runtime.fail_outbox_delivery(
                db,
                message_id=stale_claim.message_id,
                delivery_attempt_id=stale_claim.delivery_attempt_id,
                delivery_token=stale_claim.delivery_token,
                expected_message_version=stale_claim.message_state_version,
                expected_delivery_version=stale_claim.delivery_state_version,
                error=error,
            )
            await db.commit()
        async with async_session_factory() as db:
            stale = await runtime.receipt_and_claim_stage(
                db,
                command=_receipt_command(stale_claim, label="stale-receipt"),
            )
            assert stale.disposition == "stale"
            assert stale.should_execute is False
            assert stale.commit_ticket is None
            assert stale.stage_attempt_id is None
            await db.rollback()

        cancelled_workflow, _, _, cancelled_claim = await _emit_and_claim(label="cancelled-receipt")
        workflow_ids.append(cancelled_workflow)
        await _cancel_authority(cancelled_workflow)
        async with async_session_factory() as db:
            cancelled = await runtime.receipt_and_claim_stage(
                db,
                command=_receipt_command(
                    cancelled_claim,
                    label="cancelled-receipt",
                ),
            )
            assert cancelled.disposition == "cancelled"
            assert cancelled.should_execute is False
            assert cancelled.commit_ticket is None
            assert cancelled.stage_attempt_id is None
            await db.rollback()
    finally:
        for workflow_id in workflow_ids:
            await _cancel_authority(workflow_id)
        await engine.dispose()


@pytest.mark.asyncio
async def test_populate_existing_refreshes_stale_receipt_and_confirmation_state():
    await engine.dispose()
    workflow_id = None
    try:
        workflow_id, stage_id, message_id, claim = await _emit_and_claim(label="stale-identity-map")
        command = _receipt_command(claim, label="stale-identity-map")
        async with async_session_factory() as stale_db:
            workflow_ref = await stale_db.get(WorkflowRun, workflow_id)
            stage_ref = await stale_db.get(StageRun, stage_id)
            message_ref = await stale_db.get(OutboxMessage, message_id)
            delivery_ref = await stale_db.get(
                OutboxDeliveryAttempt,
                claim.delivery_attempt_id,
            )
            assert workflow_ref.status == "queued"
            assert stage_ref.status == "ready"
            assert message_ref.status == delivery_ref.status == "dispatching"

            async with async_session_factory() as external_db:
                pending = await runtime.receipt_and_claim_stage(
                    external_db,
                    command=command,
                )
                await external_db.commit()

            # Every W -> S -> M -> D authority read must suppress autoflush.
            # These deliberately invalid dirty values would be rejected by the
            # database if any lock query flushed them before populate_existing
            # refreshed that row from the externally committed activation.
            workflow_ref.status = "invalid"
            stage_ref.status = "invalid"
            message_ref.status = "invalid"
            delivery_ref.status = "invalid"
            replay = await runtime.receipt_and_claim_stage(
                stale_db,
                command=command,
            )
            assert replay.disposition == "replayed"
            assert workflow_ref.status == stage_ref.status == "running"
            assert message_ref.status == delivery_ref.status == "delivered"
            await stale_db.rollback()

            workflow_ref = await stale_db.get(WorkflowRun, workflow_id)
            stage_ref = await stale_db.get(StageRun, stage_id)
            message_ref = await stale_db.get(OutboxMessage, message_id)
            delivery_ref = await stale_db.get(
                OutboxDeliveryAttempt,
                claim.delivery_attempt_id,
            )
            attempt_ref = await stale_db.get(
                StageAttempt,
                pending.stage_attempt_id,
            )
            assert attempt_ref.status == "running"

            async with async_session_factory() as external_db:
                workflow = await external_db.get(WorkflowRun, workflow_id)
                assert workflow is not None
                command = cancellation_command(
                    workflow_run_id=workflow_id,
                    expected_workflow_state_version=workflow.state_version,
                    actor=ACTOR,
                    reason="Cancel after stale identity-map preload.",
                )
            cancelled = await workflow_worker.coordinate_workflow_cancel(
                async_session_factory,
                command=command,
            )
            assert cancelled.disposition == "applied"

            workflow_ref.status = "invalid"
            stage_ref.status = "invalid"
            message_ref.status = "invalid"
            delivery_ref.status = "invalid"
            attempt_ref.status = "invalid"
            assert (
                await runtime.confirm_committed_activation(
                    stale_db,
                    commit_ticket=pending.commit_ticket,
                )
                is None
            )
            assert workflow_ref.status == "cancelled"
            assert stage_ref.status == "cancelled"
            assert attempt_ref.status == "cancelled"
            assert message_ref.status == delivery_ref.status == "delivered"
            await stale_db.rollback()
    finally:
        if workflow_id is not None:
            await _cancel_authority(workflow_id)
        await engine.dispose()


@pytest.mark.asyncio
async def test_receipt_waits_on_workflow_before_locking_message_or_delivery():
    await engine.dispose()
    workflow_id = None
    try:
        workflow_id, _, message_id, claim = await _emit_and_claim(label="receipt-lock-order")
        command = _receipt_command(claim, label="receipt-lock-order")
        async with (
            async_session_factory() as holder,
            async_session_factory() as receipt_db,
        ):
            await receipt_db.execute(text("SET LOCAL lock_timeout = '5s'"))
            receipt_pid = await receipt_db.scalar(text("SELECT pg_backend_pid()"))
            await holder.execute(select(WorkflowRun).where(WorkflowRun.id == workflow_id).with_for_update())
            receipt_task = asyncio.create_task(runtime.receipt_and_claim_stage(receipt_db, command=command))
            try:
                await _wait_for_backend_lock(receipt_pid)
                async with async_session_factory() as suffix_db:
                    message = await suffix_db.scalar(
                        select(OutboxMessage).where(OutboxMessage.id == message_id).with_for_update(nowait=True)
                    )
                    delivery = await suffix_db.scalar(
                        select(OutboxDeliveryAttempt)
                        .where(OutboxDeliveryAttempt.id == claim.delivery_attempt_id)
                        .with_for_update(nowait=True)
                    )
                    assert message is not None and delivery is not None
                    await suffix_db.rollback()
            finally:
                await holder.rollback()

            pending = await asyncio.wait_for(receipt_task, timeout=3)
            assert pending.disposition == "activated"
            await receipt_db.commit()
    finally:
        if workflow_id is not None:
            await _cancel_authority(workflow_id)
        await engine.dispose()


@pytest.mark.asyncio
async def test_post_lock_clock_rejects_receipt_that_waited_past_expiry():
    await engine.dispose()
    workflow_id = None
    try:
        workflow_id, stage_id, message_id, claim = await _emit_and_claim(
            label="receipt-post-lock-expiry",
            lease_seconds=2,
        )
        command = _receipt_command(claim, label="receipt-post-lock-expiry")
        async with async_session_factory() as observer:
            delivery = await observer.get(
                OutboxDeliveryAttempt,
                claim.delivery_attempt_id,
            )
            expires_at = delivery.lease_expires_at

        async with (
            async_session_factory() as holder,
            async_session_factory() as receipt_db,
        ):
            await receipt_db.execute(text("SET LOCAL lock_timeout = '5s'"))
            receipt_pid = await receipt_db.scalar(text("SELECT pg_backend_pid()"))
            await holder.execute(select(WorkflowRun).where(WorkflowRun.id == workflow_id).with_for_update())
            receipt_task = asyncio.create_task(runtime.receipt_and_claim_stage(receipt_db, command=command))
            try:
                await _wait_for_backend_lock(receipt_pid)
                await _wait_until_db_after(expires_at)
            finally:
                await holder.rollback()

            with pytest.raises(runtime.OutboxLeaseLost, match="live lease"):
                await asyncio.wait_for(receipt_task, timeout=3)
            await receipt_db.rollback()

        async with async_session_factory() as observer:
            stage = await observer.get(StageRun, stage_id)
            message = await observer.get(OutboxMessage, message_id)
            delivery = await observer.get(
                OutboxDeliveryAttempt,
                claim.delivery_attempt_id,
            )
            attempt_count = await observer.scalar(
                select(func.count()).select_from(StageAttempt).where(StageAttempt.stage_run_id == stage_id)
            )
            assert stage.status == "ready"
            assert message.status == delivery.status == "dispatching"
            assert attempt_count == 0

        async with async_session_factory() as recovery_db:
            recovered = await runtime.recover_expired_outbox_deliveries(
                recovery_db,
                limit=100,
            )
            assert any(item.message_id == message_id for item in recovered)
            await recovery_db.commit()
    finally:
        if workflow_id is not None:
            await _cancel_authority(workflow_id)
        await engine.dispose()


@pytest.mark.asyncio
async def test_receipt_transaction_started_before_publisher_mark_converges_without_deadlock():
    await engine.dispose()
    workflow_id = None
    try:
        workflow_id, stage_id, message_id, claim = await _emit_and_claim(label="receipt-publisher-race")
        broker_message_id = f"broker-publisher-race-{uuid4().hex}"
        command = _receipt_command(
            claim,
            label="receipt-publisher-race",
            broker_message_id=broker_message_id,
        )
        async with (
            async_session_factory() as holder,
            async_session_factory() as receipt_db,
        ):
            await receipt_db.execute(text("SET LOCAL lock_timeout = '5s'"))
            receipt_started_at = await receipt_db.scalar(
                select(func.transaction_timestamp()),
            )
            receipt_pid = await receipt_db.scalar(text("SELECT pg_backend_pid()"))
            assert receipt_started_at is not None
            assert type(receipt_pid) is int

            locked_workflow = await holder.scalar(select(WorkflowRun).where(WorkflowRun.id == workflow_id).with_for_update())
            assert locked_workflow is not None
            receipt_task = asyncio.create_task(
                runtime.receipt_and_claim_stage(
                    receipt_db,
                    command=command,
                )
            )
            try:
                await _wait_for_backend_lock(receipt_pid)
                async with async_session_factory() as marker:
                    await marker.execute(text("SET LOCAL lock_timeout = '5s'"))
                    marked = await runtime.mark_outbox_dispatched(
                        marker,
                        message_id=claim.message_id,
                        delivery_attempt_id=claim.delivery_attempt_id,
                        delivery_token=claim.delivery_token,
                        expected_message_version=claim.message_state_version,
                        expected_delivery_version=claim.delivery_state_version,
                        broker_name=command.broker_name,
                        broker_message_id=command.broker_message_id,
                        receipt_timeout_seconds=30,
                    )
                    assert marked.replayed is False
                    await marker.commit()

                async with async_session_factory() as observer:
                    marked_delivery = await observer.get(
                        OutboxDeliveryAttempt,
                        claim.delivery_attempt_id,
                    )
                    assert marked_delivery is not None
                    assert marked_delivery.dispatched_at is not None
                    assert marked_delivery.dispatched_at > receipt_started_at

                await holder.rollback()
                pending = await asyncio.wait_for(receipt_task, timeout=5)
                await receipt_db.commit()
            finally:
                await holder.rollback()
                if not receipt_task.done():
                    receipt_task.cancel()
                    await asyncio.gather(receipt_task, return_exceptions=True)

        assert pending.disposition == "activated"

        async with async_session_factory() as db:
            message = await db.get(OutboxMessage, message_id)
            delivery = await db.get(
                OutboxDeliveryAttempt,
                claim.delivery_attempt_id,
            )
            attempts = list((await db.scalars(select(StageAttempt).where(StageAttempt.stage_run_id == stage_id))).all())
            assert message.status == delivery.status == "delivered"
            assert delivery.broker_name == command.broker_name
            assert delivery.broker_message_id == command.broker_message_id
            assert delivery.broker_receipt_id == command.broker_receipt_id
            assert len(attempts) == 1
            assert delivery.dispatched_at is not None
            assert delivery.receipt_received_at is not None
            assert delivery.completed_at is not None
            assert message.delivered_at is not None
            assert attempts[0].started_at is not None
            assert (
                delivery.dispatched_at
                <= delivery.receipt_received_at
                == delivery.completed_at
                == message.delivered_at
                <= attempts[0].started_at
            )
            authority = await runtime.confirm_committed_activation(
                db,
                commit_ticket=pending.commit_ticket,
            )
            assert authority is not None
            await db.rollback()
    finally:
        if workflow_id is not None:
            await _cancel_authority(workflow_id)
        await engine.dispose()


@pytest.mark.asyncio
async def test_coordinator_releases_both_session_scopes_before_returning_authority():
    await engine.dispose()
    workflow_id = None
    application_name = f"ag-receipt-coordinator-{uuid4().hex[:16]}"
    coordinator_engine = create_async_engine(
        engine.url,
        pool_size=2,
        max_overflow=0,
        connect_args={
            "server_settings": {"application_name": application_name},
        },
    )
    coordinator_sessions = async_sessionmaker(
        coordinator_engine,
        expire_on_commit=False,
    )
    try:
        workflow_id, _, _, claim = await _emit_and_claim(label="coordinator-release")
        result = await coordinator.coordinate_stage_receipt(
            coordinator_sessions,
            command=_receipt_command(claim, label="coordinator-release"),
        )
        assert result.disposition == "activated"
        assert result.should_execute is True
        assert result.should_ack is True
        assert isinstance(result.authority, runtime.ExecutableStageAuthority)
        assert not hasattr(result, "commit_ticket")

        # A separate connection can immediately lock W -> S -> M -> D -> A,
        # proving neither coordinator-owned transaction retained authority.
        await _assert_coordinator_released_authority_locks(result)

        # The uniquely tagged coordinator pool may retain idle connections,
        # but none may retain a transaction after the public result escapes.
        async with async_session_factory() as observer:
            activity = (
                await observer.execute(
                    text(
                        """
                        SELECT state, xact_start
                        FROM pg_stat_activity
                        WHERE datname = current_database()
                          AND application_name = :application_name
                        """
                    ),
                    {"application_name": application_name},
                )
            ).all()
        assert activity
        assert all(state == "idle" and xact_start is None for state, xact_start in activity)
    finally:
        await coordinator_engine.dispose()
        if workflow_id is not None:
            await _cancel_authority(workflow_id)
        await engine.dispose()


@pytest.mark.asyncio
async def test_coordinator_sequential_duplicate_is_ticket_free_nonexecution():
    await engine.dispose()
    workflow_id = None
    try:
        workflow_id, _, _, claim = await _emit_and_claim(label="coordinator-replay")
        command = _receipt_command(claim, label="coordinator-replay")
        activated = await coordinator.coordinate_stage_receipt(
            async_session_factory,
            command=command,
        )
        replayed = await coordinator.coordinate_stage_receipt(
            async_session_factory,
            command=command,
        )

        assert activated.disposition == "activated"
        assert activated.should_execute is True
        assert activated.authority is not None
        assert replayed.disposition == "replayed"
        assert replayed.should_execute is False
        assert replayed.should_ack is True
        assert replayed.authority is None
        assert replayed.stage_attempt_id == activated.stage_attempt_id
        assert not hasattr(activated, "commit_ticket")
        assert not hasattr(replayed, "commit_ticket")
        await _assert_coordinator_released_authority_locks(activated)
    finally:
        if workflow_id is not None:
            await _cancel_authority(workflow_id)
        await engine.dispose()


@pytest.mark.asyncio
async def test_concurrent_coordinators_yield_exactly_one_executable_result():
    await engine.dispose()
    workflow_id = None
    try:
        workflow_id, stage_id, _, claim = await _emit_and_claim(
            label="coordinator-concurrent",
        )
        command = _receipt_command(claim, label="coordinator-concurrent")
        start = asyncio.Event()

        async def coordinate_once():
            await start.wait()
            return await coordinator.coordinate_stage_receipt(
                async_session_factory,
                command=command,
            )

        calls = [asyncio.create_task(coordinate_once()) for _ in range(2)]
        await asyncio.sleep(0)
        start.set()
        outcomes = await asyncio.wait_for(asyncio.gather(*calls), timeout=10)

        assert sorted(item.disposition for item in outcomes) == [
            "activated",
            "replayed",
        ]
        assert sum(item.should_execute for item in outcomes) == 1
        assert sum(item.authority is not None for item in outcomes) == 1
        assert all(item.should_ack for item in outcomes)
        assert all(not hasattr(item, "commit_ticket") for item in outcomes)
        activated = next(item for item in outcomes if item.should_execute)
        replayed = next(item for item in outcomes if not item.should_execute)
        assert replayed.stage_attempt_id == activated.stage_attempt_id

        async with async_session_factory() as db:
            attempt_count = await db.scalar(select(func.count()).select_from(StageAttempt).where(StageAttempt.stage_run_id == stage_id))
        assert attempt_count == 1
        await _assert_coordinator_released_authority_locks(activated)
    finally:
        if workflow_id is not None:
            await _cancel_authority(workflow_id)
        await engine.dispose()


@pytest.mark.asyncio
async def test_coordinator_stale_and_cancelled_results_are_ack_safe_noexecute():
    await engine.dispose()
    workflow_ids: list[UUID] = []
    try:
        stale_workflow, _, _, stale_claim = await _emit_and_claim(
            label="coordinator-stale",
        )
        workflow_ids.append(stale_workflow)
        error = sanitize_outbox_error(
            "Publisher permanently rejected the coordinator delivery.",
            code="outbox.publisher_rejected",
            retryable=False,
            error_class="PublisherRejected",
        )
        async with async_session_factory() as db:
            await runtime.fail_outbox_delivery(
                db,
                message_id=stale_claim.message_id,
                delivery_attempt_id=stale_claim.delivery_attempt_id,
                delivery_token=stale_claim.delivery_token,
                expected_message_version=stale_claim.message_state_version,
                expected_delivery_version=stale_claim.delivery_state_version,
                error=error,
            )
            await db.commit()
        stale = await coordinator.coordinate_stage_receipt(
            async_session_factory,
            command=_receipt_command(stale_claim, label="coordinator-stale"),
        )

        cancelled_workflow, _, _, cancelled_claim = await _emit_and_claim(
            label="coordinator-cancelled",
        )
        workflow_ids.append(cancelled_workflow)
        await _cancel_authority(cancelled_workflow)
        cancelled = await coordinator.coordinate_stage_receipt(
            async_session_factory,
            command=_receipt_command(
                cancelled_claim,
                label="coordinator-cancelled",
            ),
        )

        assert stale.disposition == "stale"
        assert cancelled.disposition == "cancelled"
        for result in (stale, cancelled):
            assert result.should_ack is True
            assert result.should_execute is False
            assert result.authority is None
            assert result.stage_attempt_id is None
            assert not hasattr(result, "commit_ticket")
    finally:
        for workflow_id in workflow_ids:
            await _cancel_authority(workflow_id)
        await engine.dispose()
