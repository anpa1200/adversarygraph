"""Real-PostgreSQL acceptance tests for the flush-only outbox runtime.

These tests call the public runtime service directly.  They deliberately use
authority-safe terminal cleanup instead of deleting rows, because outbox
history is immutable in production.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import os
from uuid import UUID, uuid4

import pytest
from sqlalchemy import func, select, text

from app.core.database import async_session_factory, engine
from app.models.research_workflow import (
    OutboxDeliveryAttempt,
    OutboxMessage,
    StageRun,
    WorkflowRun,
)
from app.services import outbox_runtime as runtime
from app.services import outbox_coordinator
from app.services import research_projects as projects
from app.services import workflow_runtime
from app.services import workflow_worker
from app.services.outbox_engine import (
    delivery_cycle_idempotency_key,
    deterministic_delivery_retry_delay_seconds,
    sanitize_outbox_error,
)
from app.services.workflow_engine import checksum_json, normalize_stage_plan
from tests.postgres._workflow_authority import cancellation_command
from tests.postgres._workflow_authority import cancel_active_workflow


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_POSTGRES_TESTS") != "1",
    reason="requires an explicitly authorized disposable PostgreSQL database",
)

EMPTY_OBJECT_CHECKSUM = hashlib.sha256(b"{}").hexdigest()
EMPTY_LIST_CHECKSUM = hashlib.sha256(b"[]").hexdigest()
ANCIENT_DUE_AT = datetime(2000, 1, 1, tzinfo=timezone.utc)


def _spec() -> dict:
    return {
        "objective": "Validate the durable outbox runtime against PostgreSQL.",
        "intelligence_requirements": ["Which delivery races remain safe under database fencing?"],
        "output_targets": ["canonical_intelligence"],
        "tlp": "TLP:AMBER",
    }


def _stage_plan(stage_key: str) -> list[dict]:
    return [
        {
            "stage_key": stage_key,
            "stage_type": "deterministic.runtime.test",
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
        created_by="PostgreSQL Outbox Runtime Test",
        created_by_id="postgres-outbox-runtime",
    )


def _ready_stage(
    workflow: WorkflowRun,
    *,
    due_at: datetime,
    stage_key: str,
) -> StageRun:
    return StageRun(
        id=uuid4(),
        workflow_run_id=workflow.id,
        stage_key=stage_key,
        stage_type="deterministic.runtime.test",
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
        next_attempt_at=due_at,
    )


async def _create_ready_authority(
    *,
    label: str,
    due_at: datetime = ANCIENT_DUE_AT,
) -> tuple[UUID, UUID]:
    actor = projects.ResearchActor(
        "PostgreSQL Outbox Runtime Test",
        "postgres-outbox-runtime",
    )
    async with async_session_factory() as db:
        _, revision = await projects.create_project(
            db,
            actor,
            project_key=f"{label}-{uuid4().hex[:12]}",
            name=f"{label} Project",
            description="Disposable PostgreSQL outbox runtime test.",
            spec=_spec(),
        )
        await db.commit()
        stage_key = f"runtime.{uuid4().hex[:12]}"
        workflow = _workflow(revision.id, stage_key=stage_key)
        db.add(workflow)
        await db.flush([workflow])
        stage = _ready_stage(
            workflow,
            due_at=due_at,
            stage_key=stage_key,
        )
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


async def _emit_committed(
    *,
    label: str,
    due_at: datetime = ANCIENT_DUE_AT,
) -> tuple[UUID, UUID, UUID]:
    workflow_id, stage_id = await _create_ready_authority(
        label=label,
        due_at=due_at,
    )
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
        return workflow_id, stage_id, message.id


async def _claim_committed(
    *,
    publisher_id: str,
    lease_seconds: int = 60,
) -> runtime.ClaimedOutboxDelivery | None:
    async with async_session_factory() as db:
        claim = await runtime.claim_outbox_delivery(
            db,
            publisher_id=publisher_id,
            lease_seconds=lease_seconds,
        )
        await db.commit()
        return claim


async def _fail_committed(
    claim: runtime.ClaimedOutboxDelivery,
    *,
    retryable: bool,
    expected_message_version: int | None = None,
    expected_delivery_version: int | None = None,
) -> runtime.OutboxDeliveryMutation:
    error = sanitize_outbox_error(
        "Publisher could not deliver the envelope.",
        code="outbox.publisher_failed",
        retryable=retryable,
        error_class="PublisherDeliveryError",
    )
    async with async_session_factory() as db:
        result = await runtime.fail_outbox_delivery(
            db,
            message_id=claim.message_id,
            delivery_attempt_id=claim.delivery_attempt_id,
            delivery_token=claim.delivery_token,
            expected_message_version=(claim.message_state_version if expected_message_version is None else expected_message_version),
            expected_delivery_version=(claim.delivery_state_version if expected_delivery_version is None else expected_delivery_version),
            error=error,
        )
        await db.commit()
        return result


async def _cancel_idle_messages(*message_ids: UUID) -> None:
    """Terminalize each owning workflow through exact cancellation authority."""

    actor = projects.ResearchActor(
        "PostgreSQL Outbox Runtime Test",
        "postgres-outbox-runtime",
    )
    async with async_session_factory() as db:
        workflow_ids = tuple(
            (await db.scalars(select(OutboxMessage.workflow_run_id).where(OutboxMessage.id.in_(message_ids)).distinct())).all()
        )
    for workflow_id in workflow_ids:
        await cancel_active_workflow(
            async_session_factory,
            workflow_run_id=UUID(str(workflow_id)),
            actor=actor,
            reason="Test authority cleanup.",
        )


async def _direct_deliver_receipt(
    claim: runtime.ClaimedOutboxDelivery,
    *,
    broker_name: str,
    broker_message_id: str,
) -> None:
    """Commit the exact receipt graph through the frozen coordinator."""

    command = runtime.StageReceiptCommand(
        claim=claim,
        broker_name=broker_name,
        broker_message_id=broker_message_id,
        broker_receipt_id=hashlib.sha256(uuid4().bytes).hexdigest(),
        worker_id="postgres-outbox-runtime",
    )
    result = await outbox_coordinator.coordinate_stage_receipt(
        async_session_factory,
        command=command,
    )
    assert result.disposition == "activated"
    assert result.should_execute is True


async def _wait_until_due(available_at: datetime) -> None:
    async with engine.connect() as connection:
        seconds = await connection.scalar(
            select(
                func.greatest(
                    0.0,
                    func.extract(
                        "epoch",
                        available_at - func.clock_timestamp(),
                    ),
                )
            )
        )
    await asyncio.sleep(float(seconds or 0) + 0.1)


@pytest.mark.asyncio
async def test_emit_replay_is_mutation_free_idempotent_and_concurrent():
    await engine.dispose()
    message_ids: list[UUID] = []
    try:
        workflow_id, stage_id = await _create_ready_authority(label="emit-no-commit")
        async with async_session_factory() as writer:
            await writer.begin()
            message, created = await runtime.emit_stage_ready(
                writer,
                workflow_run_id=workflow_id,
                stage_run_id=stage_id,
                emission_kind="root_ready",
            )
            assert created is False
            message_ids.append(message.id)
            async with async_session_factory() as observer:
                observed = await observer.get(OutboxMessage, message.id)
                assert observed is not None
                assert observed.state_version == message.state_version
            await writer.rollback()

        async with async_session_factory() as db:
            await db.begin()
            replay, created = await runtime.emit_stage_ready(
                db,
                workflow_run_id=workflow_id,
                stage_run_id=stage_id,
                emission_kind="root_ready",
            )
            assert created is False
            assert replay.id == message_ids[0]
            await db.commit()

        concurrent_workflow, concurrent_stage = await _create_ready_authority(label="emit-concurrent")

        async def emit_once():
            async with async_session_factory() as db:
                await db.begin()
                result = await runtime.emit_stage_ready(
                    db,
                    workflow_run_id=concurrent_workflow,
                    stage_run_id=concurrent_stage,
                    emission_kind="root_ready",
                )
                await db.commit()
                return result[0].id, result[1]

        outcomes = await asyncio.wait_for(
            asyncio.gather(emit_once(), emit_once()),
            timeout=5,
        )
        assert outcomes[0][0] == outcomes[1][0]
        assert [created for _, created in outcomes] == [False, False]
        message_ids.append(outcomes[0][0])
    finally:
        await _cancel_idle_messages(*message_ids)
        await engine.dispose()


@pytest.mark.asyncio
async def test_claim_skip_locked_is_flush_only_and_persists_exact_pair_state():
    await engine.dispose()
    first_id = second_id = None
    try:
        _, _, first_id = await _emit_committed(
            label="claim-locked-first",
            due_at=ANCIENT_DUE_AT - timedelta(days=1),
        )
        _, _, second_id = await _emit_committed(
            label="claim-locked-second",
            due_at=ANCIENT_DUE_AT,
        )

        async with async_session_factory() as holder:
            await holder.execute(select(OutboxMessage).where(OutboxMessage.id == first_id).with_for_update())
            async with async_session_factory() as publisher:
                await publisher.execute(text("SET LOCAL lock_timeout = '1s'"))
                claim = await runtime.claim_outbox_delivery(
                    publisher,
                    publisher_id="publisher-skip-locked",
                    lease_seconds=90,
                )
                assert claim is not None and claim.message_id == second_id

                async with async_session_factory() as observer:
                    observed = await observer.get(OutboxMessage, second_id)
                    assert observed is not None and observed.status == "pending"
                    assert (
                        await observer.get(
                            OutboxDeliveryAttempt,
                            claim.delivery_attempt_id,
                        )
                        is None
                    )
                await publisher.commit()
            await holder.rollback()

        async with async_session_factory() as db:
            message = await db.get(OutboxMessage, second_id)
            delivery = await db.get(
                OutboxDeliveryAttempt,
                claim.delivery_attempt_id,
            )
            assert message is not None and delivery is not None
            assert message.status == delivery.status == "dispatching"
            assert message.state_version == claim.message_state_version == 2
            assert delivery.state_version == claim.delivery_state_version == 1
            assert message.attempt_count == delivery.attempt_number == 1
            assert message.delivery_cycle == delivery.delivery_cycle == 1
            assert message.cycle_key == delivery.cycle_key == claim.cycle_key
            assert message.active_delivery_attempt_id == delivery.id
            assert message.lease_token == delivery.delivery_token == claim.delivery_token
            assert message.lease_owner == delivery.publisher_id
            assert message.leased_at == delivery.leased_at
            assert message.heartbeat_at == delivery.heartbeat_at
            assert message.lease_expires_at == delivery.lease_expires_at
            assert claim.cycle_key == delivery_cycle_idempotency_key(
                message.logical_key,
                delivery_cycle=1,
            )
            assert claim.logical_key == message.logical_key
            assert claim.envelope["payload"]["stage_run_id"] == str(message.stage_run_id)

        await _fail_committed(claim, retryable=False)
    finally:
        await _cancel_idle_messages(*(item for item in (first_id, second_id) if item))
        await engine.dispose()


@pytest.mark.asyncio
async def test_claim_has_exactly_one_concurrent_winner():
    await engine.dispose()
    message_id = None
    try:
        _, _, message_id = await _emit_committed(label="claim-one-winner")

        async def claim_once(publisher_id: str):
            async with async_session_factory() as db:
                result = await runtime.claim_outbox_delivery(
                    db,
                    publisher_id=publisher_id,
                )
                await db.commit()
                return result

        results = await asyncio.wait_for(
            asyncio.gather(
                claim_once("publisher-race-one"),
                claim_once("publisher-race-two"),
            ),
            timeout=5,
        )
        winners = [result for result in results if result is not None]
        assert len(winners) == 1
        assert winners[0].message_id == message_id
        await _fail_committed(winners[0], retryable=False)
    finally:
        if message_id is not None:
            await _cancel_idle_messages(message_id)
        await engine.dispose()


@pytest.mark.asyncio
async def test_claim_skips_stale_cancelled_authority_without_starving_valid_work():
    await engine.dispose()
    stale_id = valid_id = None
    try:
        stale_workflow_id, _, stale_id = await _emit_committed(
            label="claim-stale-cancelled-authority",
            due_at=ANCIENT_DUE_AT - timedelta(days=2),
        )
        async with async_session_factory() as db:
            workflow = await db.get(WorkflowRun, stale_workflow_id)
            assert workflow is not None
            actor = projects.ResearchActor(
                "PostgreSQL Outbox Runtime Test",
                "postgres-outbox-runtime",
            )
            command = cancellation_command(
                workflow_run_id=workflow.id,
                expected_workflow_state_version=workflow.state_version,
                actor=actor,
                reason="Invalidate the upstream authority before publication.",
            )
        cancelled = await workflow_worker.coordinate_workflow_cancel(
            async_session_factory,
            command=command,
        )
        assert cancelled.disposition == "applied"

        _, _, valid_id = await _emit_committed(
            label="claim-valid-after-stale",
            due_at=ANCIENT_DUE_AT - timedelta(days=1),
        )
        claim = await asyncio.wait_for(
            _claim_committed(
                publisher_id="publisher-skips-stale-authority",
                lease_seconds=60,
            ),
            timeout=2,
        )
        assert claim is not None
        assert claim.message_id == valid_id

        async with async_session_factory() as db:
            stale = await db.get(OutboxMessage, stale_id)
            valid = await db.get(OutboxMessage, valid_id)
            stale_workflow = await db.get(WorkflowRun, stale_workflow_id)
            assert stale is not None and valid is not None
            assert stale_workflow is not None
            stale_stage = await db.get(StageRun, stale.stage_run_id)
            assert stale_stage is not None
            assert stale_workflow.status == "cancelled"
            assert stale_stage.status == "cancelled"
            assert stale.status == "cancelled"
            assert stale.attempt_count == stale.delivery_cycle == 0
            assert stale.active_delivery_attempt_id is None
            assert valid.status == "dispatching"

        await _fail_committed(claim, retryable=False)
    finally:
        await _cancel_idle_messages(*(item for item in (stale_id, valid_id) if item))
        await engine.dispose()


@pytest.mark.asyncio
async def test_claim_does_not_wait_for_or_reverse_lock_workflow_or_stage_authority():
    await engine.dispose()
    message_id = None
    claim = None
    try:
        workflow_id, stage_id, message_id = await _emit_committed(
            label="claim-stage-lock-order",
            due_at=ANCIENT_DUE_AT - timedelta(days=3),
        )
        async with async_session_factory() as stage_holder:
            locked_workflow = await stage_holder.scalar(select(WorkflowRun).where(WorkflowRun.id == workflow_id).with_for_update())
            locked_stage = await stage_holder.scalar(select(StageRun).where(StageRun.id == stage_id).with_for_update())
            assert locked_workflow is not None and locked_stage is not None

            async with async_session_factory() as publisher:
                await publisher.execute(text("SET LOCAL lock_timeout = '500ms'"))
                claim = await asyncio.wait_for(
                    runtime.claim_outbox_delivery(
                        publisher,
                        publisher_id="publisher-stage-lock-order",
                        lease_seconds=60,
                    ),
                    timeout=2,
                )
                assert claim is not None
                assert claim.message_id == message_id
                await publisher.commit()
            await stage_holder.rollback()

        await _fail_committed(claim, retryable=False)
    finally:
        if message_id is not None:
            await _cancel_idle_messages(message_id)
        await engine.dispose()


@pytest.mark.asyncio
async def test_fenced_lifecycle_retry_schedule_replay_and_latest_cycle():
    await engine.dispose()
    message_id = None
    try:
        _, _, message_id = await _emit_committed(label="fenced-lifecycle")
        first = await _claim_committed(
            publisher_id="publisher-lifecycle",
            lease_seconds=120,
        )
        assert first is not None and first.message_id == message_id

        async with async_session_factory() as db:
            heartbeat = await runtime.heartbeat_outbox_delivery(
                db,
                message_id=first.message_id,
                delivery_attempt_id=first.delivery_attempt_id,
                delivery_token=first.delivery_token,
                expected_message_version=first.message_state_version,
                expected_delivery_version=first.delivery_state_version,
                lease_seconds=180,
            )
            await db.commit()
            heartbeat_message_version = heartbeat.message.state_version
            heartbeat_delivery_version = heartbeat.delivery.state_version
            assert heartbeat.message.heartbeat_at == heartbeat.delivery.heartbeat_at
            assert heartbeat.message.lease_expires_at == heartbeat.delivery.lease_expires_at

        async with async_session_factory() as db:
            with pytest.raises(runtime.OutboxLeaseLost, match="version"):
                await runtime.heartbeat_outbox_delivery(
                    db,
                    message_id=first.message_id,
                    delivery_attempt_id=first.delivery_attempt_id,
                    delivery_token=first.delivery_token,
                    expected_message_version=first.message_state_version,
                    expected_delivery_version=first.delivery_state_version,
                )
            await db.rollback()

        async with async_session_factory() as db:
            dispatched = await runtime.mark_outbox_dispatched(
                db,
                message_id=first.message_id,
                delivery_attempt_id=first.delivery_attempt_id,
                delivery_token=first.delivery_token,
                expected_message_version=heartbeat_message_version,
                expected_delivery_version=heartbeat_delivery_version,
                broker_name="test.broker",
                broker_message_id="broker-lifecycle-1",
                receipt_timeout_seconds=120,
            )
            await db.commit()
            assert dispatched.message.status == "awaiting_receipt"
            assert dispatched.delivery.status == "awaiting_receipt"
            dispatched_message_version = dispatched.message.state_version
            dispatched_delivery_version = dispatched.delivery.state_version

        async with async_session_factory() as db:
            replay = await runtime.mark_outbox_dispatched(
                db,
                message_id=first.message_id,
                delivery_attempt_id=first.delivery_attempt_id,
                delivery_token=first.delivery_token,
                expected_message_version=heartbeat_message_version,
                expected_delivery_version=heartbeat_delivery_version,
                broker_name="test.broker",
                broker_message_id="broker-lifecycle-1",
                receipt_timeout_seconds=120,
            )
            assert replay.replayed is True
            await db.rollback()

        async with async_session_factory() as db:
            with pytest.raises(runtime.OutboxLeaseLost):
                await runtime.mark_outbox_dispatched(
                    db,
                    message_id=first.message_id,
                    delivery_attempt_id=first.delivery_attempt_id,
                    delivery_token=first.delivery_token,
                    expected_message_version=heartbeat_message_version,
                    expected_delivery_version=heartbeat_delivery_version,
                    broker_name="test.broker",
                    broker_message_id="broker-lifecycle-1",
                    receipt_timeout_seconds=121,
                )
            await db.rollback()

        for token, message_version, delivery_version in (
            (
                first.delivery_token,
                first.message_state_version,
                first.delivery_state_version,
            ),
            (
                uuid4(),
                heartbeat_message_version,
                heartbeat_delivery_version,
            ),
        ):
            async with async_session_factory() as db:
                with pytest.raises(runtime.OutboxLeaseLost):
                    await runtime.mark_outbox_dispatched(
                        db,
                        message_id=first.message_id,
                        delivery_attempt_id=first.delivery_attempt_id,
                        delivery_token=token,
                        expected_message_version=message_version,
                        expected_delivery_version=delivery_version,
                        broker_name="test.broker",
                        broker_message_id="broker-lifecycle-1",
                        receipt_timeout_seconds=120,
                    )
                await db.rollback()

        retry_error = sanitize_outbox_error(
            "Broker receipt path became unavailable.",
            code="outbox.broker_unavailable",
            retryable=True,
            error_class="BrokerUnavailable",
        )
        async with async_session_factory() as db:
            failed = await runtime.fail_outbox_delivery(
                db,
                message_id=first.message_id,
                delivery_attempt_id=first.delivery_attempt_id,
                delivery_token=first.delivery_token,
                expected_message_version=dispatched_message_version,
                expected_delivery_version=dispatched_delivery_version,
                error=retry_error,
            )
            await db.commit()
            assert failed.message.status == "retry_wait"
            assert failed.delivery.status == "failed"
            retry_available_at = failed.message.available_at
            retry_message_version = failed.message.state_version
            retry_delivery_version = failed.delivery.state_version

        async with async_session_factory() as db:
            message = await db.get(OutboxMessage, first.message_id)
            delivery = await db.get(
                OutboxDeliveryAttempt,
                first.delivery_attempt_id,
            )
            delay = deterministic_delivery_retry_delay_seconds(
                1,
                logical_key=message.logical_key,
            )
            assert message.available_at == message.updated_at + timedelta(seconds=delay)
            assert message.available_at == delivery.completed_at + timedelta(seconds=delay)

        async with async_session_factory() as db:
            replay = await runtime.fail_outbox_delivery(
                db,
                message_id=first.message_id,
                delivery_attempt_id=first.delivery_attempt_id,
                delivery_token=first.delivery_token,
                expected_message_version=dispatched_message_version,
                expected_delivery_version=dispatched_delivery_version,
                error=retry_error,
            )
            assert replay.replayed is True
            await db.rollback()

        for token, message_version, delivery_version in (
            (
                first.delivery_token,
                dispatched_message_version - 1,
                dispatched_delivery_version - 1,
            ),
            (
                uuid4(),
                dispatched_message_version,
                dispatched_delivery_version,
            ),
        ):
            async with async_session_factory() as db:
                with pytest.raises(runtime.OutboxLeaseLost):
                    await runtime.fail_outbox_delivery(
                        db,
                        message_id=first.message_id,
                        delivery_attempt_id=first.delivery_attempt_id,
                        delivery_token=token,
                        expected_message_version=message_version,
                        expected_delivery_version=delivery_version,
                        error=retry_error,
                    )
                await db.rollback()

        await _wait_until_due(retry_available_at)
        second = await _claim_committed(publisher_id="publisher-lifecycle-redelivery")
        assert second is not None and second.message_id == first.message_id
        assert second.delivery_cycle == first.delivery_cycle + 1
        assert second.delivery_attempt_id != first.delivery_attempt_id

        async with async_session_factory() as db:
            with pytest.raises(runtime.OutboxLeaseLost):
                await runtime.fail_outbox_delivery(
                    db,
                    message_id=first.message_id,
                    delivery_attempt_id=first.delivery_attempt_id,
                    delivery_token=first.delivery_token,
                    expected_message_version=dispatched_message_version,
                    expected_delivery_version=dispatched_delivery_version,
                    error=retry_error,
                )
            await db.rollback()

        terminal = await _fail_committed(second, retryable=False)
        assert terminal.message.status == "dead_lettered"
        assert terminal.delivery.status == "failed"
        assert terminal.message.attempt_count == 2
        assert terminal.message.dead_lettered_at == terminal.delivery.completed_at
        assert retry_message_version + 2 == terminal.message.state_version
        assert retry_delivery_version > first.delivery_state_version
    finally:
        if message_id is not None:
            await _cancel_idle_messages(message_id)
        await engine.dispose()


@pytest.mark.asyncio
async def test_delivered_mark_replay_accepts_only_exact_delta_one_or_two():
    await engine.dispose()
    message_ids: list[UUID] = []
    try:
        _, _, direct_id = await _emit_committed(label="direct-delivered-replay")
        message_ids.append(direct_id)
        direct = await _claim_committed(publisher_id="publisher-direct-receipt")
        assert direct is not None and direct.message_id == direct_id
        await _direct_deliver_receipt(
            direct,
            broker_name="test.broker",
            broker_message_id="broker-direct-receipt",
        )
        async with async_session_factory() as db:
            replay = await runtime.mark_outbox_dispatched(
                db,
                message_id=direct.message_id,
                delivery_attempt_id=direct.delivery_attempt_id,
                delivery_token=direct.delivery_token,
                expected_message_version=direct.message_state_version,
                expected_delivery_version=direct.delivery_state_version,
                broker_name="test.broker",
                broker_message_id="broker-direct-receipt",
                receipt_timeout_seconds=999,
            )
            assert replay.replayed is True
            await db.rollback()

        for message_version, delivery_version in (
            (direct.message_state_version - 1, direct.delivery_state_version),
            (direct.message_state_version + 1, direct.delivery_state_version + 1),
            (direct.message_state_version + 2, direct.delivery_state_version + 2),
        ):
            async with async_session_factory() as db:
                with pytest.raises(runtime.OutboxLeaseLost):
                    await runtime.mark_outbox_dispatched(
                        db,
                        message_id=direct.message_id,
                        delivery_attempt_id=direct.delivery_attempt_id,
                        delivery_token=direct.delivery_token,
                        expected_message_version=message_version,
                        expected_delivery_version=delivery_version,
                        broker_name="test.broker",
                        broker_message_id="broker-direct-receipt",
                        receipt_timeout_seconds=999,
                    )
                await db.rollback()

        _, _, marked_id = await _emit_committed(label="marked-delivered-replay")
        message_ids.append(marked_id)
        marked = await _claim_committed(publisher_id="publisher-marked-receipt")
        assert marked is not None and marked.message_id == marked_id
        async with async_session_factory() as db:
            await runtime.mark_outbox_dispatched(
                db,
                message_id=marked.message_id,
                delivery_attempt_id=marked.delivery_attempt_id,
                delivery_token=marked.delivery_token,
                expected_message_version=marked.message_state_version,
                expected_delivery_version=marked.delivery_state_version,
                broker_name="test.broker",
                broker_message_id="broker-marked-receipt",
                receipt_timeout_seconds=999,
            )
            await db.commit()
        await _direct_deliver_receipt(
            marked,
            broker_name="test.broker",
            broker_message_id="broker-marked-receipt",
        )
        async with async_session_factory() as db:
            replay = await runtime.mark_outbox_dispatched(
                db,
                message_id=marked.message_id,
                delivery_attempt_id=marked.delivery_attempt_id,
                delivery_token=marked.delivery_token,
                expected_message_version=marked.message_state_version,
                expected_delivery_version=marked.delivery_state_version,
                broker_name="test.broker",
                broker_message_id="broker-marked-receipt",
                receipt_timeout_seconds=60,
            )
            assert replay.replayed is True
            assert replay.message.state_version - marked.message_state_version == 2
            assert replay.delivery.state_version - marked.delivery_state_version == 2
            await db.rollback()
    finally:
        await _cancel_idle_messages(*message_ids)
        await engine.dispose()


@pytest.mark.asyncio
async def test_mark_wins_dispatch_expiry_race_then_receipt_timeout_recovers():
    await engine.dispose()
    message_id = None
    try:
        _, _, message_id = await _emit_committed(label="mark-recovery-race")
        claim = await _claim_committed(
            publisher_id="publisher-mark-recovery-race",
            lease_seconds=3,
        )
        assert claim is not None and claim.message_id == message_id

        async with async_session_factory() as mark_db:
            marked = await runtime.mark_outbox_dispatched(
                mark_db,
                message_id=claim.message_id,
                delivery_attempt_id=claim.delivery_attempt_id,
                delivery_token=claim.delivery_token,
                expected_message_version=claim.message_state_version,
                expected_delivery_version=claim.delivery_state_version,
                broker_name="test.broker",
                broker_message_id="broker-mark-recovery-race",
                receipt_timeout_seconds=1,
            )
            assert marked.message.status == marked.delivery.status == "awaiting_receipt"

            async with async_session_factory() as observer:
                observed_message = await observer.get(OutboxMessage, message_id)
                observed_delivery = await observer.get(
                    OutboxDeliveryAttempt,
                    claim.delivery_attempt_id,
                )
                assert observed_message.status == observed_delivery.status == "dispatching"

            await _wait_until_due(marked.delivery.lease_expires_at)
            async with async_session_factory() as recovery_db:
                await recovery_db.execute(text("SET LOCAL lock_timeout = '1s'"))
                recovered = await asyncio.wait_for(
                    runtime.recover_expired_outbox_deliveries(
                        recovery_db,
                        limit=1,
                    ),
                    timeout=2,
                )
                assert recovered == []
                await recovery_db.rollback()
            await mark_db.commit()

        async with async_session_factory() as db:
            recovered = await runtime.recover_expired_outbox_deliveries(db, limit=1)
            assert len(recovered) == 1
            assert recovered[0].message_id == message_id
            await db.commit()

        async with async_session_factory() as db:
            message = await db.get(OutboxMessage, message_id)
            delivery = await db.get(
                OutboxDeliveryAttempt,
                claim.delivery_attempt_id,
            )
            assert message is not None and delivery is not None
            assert message.status == "retry_wait"
            assert delivery.status == "abandoned"
            assert message.last_error_code == delivery.error_code == "outbox.receipt_timeout"
            assert message.last_error_class == delivery.error_class == "DeliveryReceiptTimeout"
            delay = deterministic_delivery_retry_delay_seconds(
                message.attempt_count,
                logical_key=message.logical_key,
            )
            assert message.available_at == message.updated_at + timedelta(seconds=delay)
            assert message.available_at == delivery.completed_at + timedelta(seconds=delay)

        async with async_session_factory() as db:
            with pytest.raises(runtime.OutboxLeaseLost):
                await runtime.mark_outbox_dispatched(
                    db,
                    message_id=claim.message_id,
                    delivery_attempt_id=claim.delivery_attempt_id,
                    delivery_token=claim.delivery_token,
                    expected_message_version=claim.message_state_version,
                    expected_delivery_version=claim.delivery_state_version,
                    broker_name="test.broker",
                    broker_message_id="broker-mark-recovery-race",
                    receipt_timeout_seconds=1,
                )
            await db.rollback()
    finally:
        if message_id is not None:
            await _cancel_idle_messages(message_id)
        await engine.dispose()


@pytest.mark.asyncio
async def test_heartbeat_and_recovery_races_are_fenced_without_deadlock():
    await engine.dispose()
    message_ids: list[UUID] = []
    try:
        _, _, heartbeat_id = await _emit_committed(label="heartbeat-wins-recovery")
        message_ids.append(heartbeat_id)
        heartbeat_claim = await _claim_committed(
            publisher_id="publisher-heartbeat-winner",
            lease_seconds=1,
        )
        assert heartbeat_claim is not None and heartbeat_claim.message_id == heartbeat_id

        async with async_session_factory() as heartbeat_db:
            heartbeat = await runtime.heartbeat_outbox_delivery(
                heartbeat_db,
                message_id=heartbeat_claim.message_id,
                delivery_attempt_id=heartbeat_claim.delivery_attempt_id,
                delivery_token=heartbeat_claim.delivery_token,
                expected_message_version=heartbeat_claim.message_state_version,
                expected_delivery_version=heartbeat_claim.delivery_state_version,
                lease_seconds=60,
            )
            await asyncio.sleep(1.1)
            async with async_session_factory() as recovery_db:
                await recovery_db.execute(text("SET LOCAL lock_timeout = '1s'"))
                recovered = await asyncio.wait_for(
                    runtime.recover_expired_outbox_deliveries(
                        recovery_db,
                        limit=1,
                    ),
                    timeout=2,
                )
                assert recovered == []
                await recovery_db.rollback()
            await heartbeat_db.commit()

        async with async_session_factory() as db:
            message = await db.get(OutboxMessage, heartbeat_id)
            delivery = await db.get(
                OutboxDeliveryAttempt,
                heartbeat_claim.delivery_attempt_id,
            )
            assert message.status == delivery.status == "dispatching"
            assert message.heartbeat_at == delivery.heartbeat_at
            assert message.lease_expires_at == delivery.lease_expires_at

        heartbeat_terminal = await _fail_committed(
            heartbeat_claim,
            retryable=False,
            expected_message_version=heartbeat.message.state_version,
            expected_delivery_version=heartbeat.delivery.state_version,
        )
        assert heartbeat_terminal.message.status == "dead_lettered"

        _, _, recovery_id = await _emit_committed(label="recovery-wins-heartbeat")
        message_ids.append(recovery_id)
        recovery_claim = await _claim_committed(
            publisher_id="publisher-recovery-winner",
            lease_seconds=1,
        )
        assert recovery_claim is not None and recovery_claim.message_id == recovery_id
        await asyncio.sleep(1.1)
        async with async_session_factory() as db:
            recovered = await runtime.recover_expired_outbox_deliveries(db, limit=1)
            assert len(recovered) == 1
            assert recovered[0].message_id == recovery_id
            await db.commit()

        async with async_session_factory() as db:
            with pytest.raises(runtime.OutboxLeaseLost):
                await runtime.heartbeat_outbox_delivery(
                    db,
                    message_id=recovery_claim.message_id,
                    delivery_attempt_id=recovery_claim.delivery_attempt_id,
                    delivery_token=recovery_claim.delivery_token,
                    expected_message_version=recovery_claim.message_state_version,
                    expected_delivery_version=recovery_claim.delivery_state_version,
                )
            await db.rollback()

        await _cancel_idle_messages(recovery_id)
    finally:
        await _cancel_idle_messages(*message_ids)
        await engine.dispose()


@pytest.mark.asyncio
async def test_recovery_limit_is_exact_and_uses_db_time_retry_authority():
    await engine.dispose()
    message_ids: list[UUID] = []
    try:
        for index in range(3):
            _, _, message_id = await _emit_committed(
                label=f"recovery-limit-{index}",
                due_at=ANCIENT_DUE_AT + timedelta(seconds=index),
            )
            message_ids.append(message_id)
        claims = []
        for index in range(3):
            claim = await _claim_committed(
                publisher_id=f"publisher-recovery-limit-{index}",
                lease_seconds=1,
            )
            assert claim is not None and claim.message_id in message_ids
            claims.append(claim)
        assert {claim.message_id for claim in claims} == set(message_ids)

        await asyncio.sleep(1.1)
        async with async_session_factory() as first_batch:
            recovered = await runtime.recover_expired_outbox_deliveries(
                first_batch,
                limit=2,
            )
            assert len(recovered) == 2
            async with async_session_factory() as observer:
                visible_active = (
                    await observer.scalars(select(OutboxMessage).where(OutboxMessage.id.in_([item.message_id for item in recovered])))
                ).all()
                assert all(item.status == "dispatching" for item in visible_active)
            await first_batch.commit()

        async with async_session_factory() as second_batch:
            remaining = await runtime.recover_expired_outbox_deliveries(
                second_batch,
                limit=2,
            )
            assert len(remaining) == 1
            await second_batch.commit()
        assert {item.message_id for item in recovered + remaining} == set(message_ids)

        async with async_session_factory() as db:
            messages = (await db.scalars(select(OutboxMessage).where(OutboxMessage.id.in_(message_ids)))).all()
            deliveries = (
                await db.scalars(
                    select(OutboxDeliveryAttempt).where(OutboxDeliveryAttempt.id.in_([claim.delivery_attempt_id for claim in claims]))
                )
            ).all()
            assert all(message.status == "retry_wait" for message in messages)
            assert all(delivery.status == "abandoned" for delivery in deliveries)
            delivery_by_message = {delivery.message_id: delivery for delivery in deliveries}
            for message in messages:
                delivery = delivery_by_message[message.id]
                delay = deterministic_delivery_retry_delay_seconds(
                    message.attempt_count,
                    logical_key=message.logical_key,
                )
                assert message.available_at == message.updated_at + timedelta(seconds=delay)
                assert message.available_at == delivery.completed_at + timedelta(seconds=delay)

        async with async_session_factory() as db:
            with pytest.raises(runtime.OutboxValidation):
                await runtime.recover_expired_outbox_deliveries(db, limit=0)
            with pytest.raises(runtime.OutboxValidation):
                await runtime.recover_expired_outbox_deliveries(db, limit=501)
            await db.rollback()
    finally:
        await _cancel_idle_messages(*message_ids)
        await engine.dispose()


@pytest.mark.asyncio
async def test_heartbeat_vs_failure_has_one_winner_and_no_deadlock():
    await engine.dispose()
    message_id = None
    try:
        _, _, message_id = await _emit_committed(label="heartbeat-failure-race")
        claim = await _claim_committed(
            publisher_id="publisher-heartbeat-failure",
            lease_seconds=120,
        )
        assert claim is not None and claim.message_id == message_id
        failure = sanitize_outbox_error(
            "Publisher rejected the delivery.",
            code="outbox.publisher_rejected",
            retryable=False,
            error_class="PublisherRejected",
        )
        start = asyncio.Event()

        async def heartbeat_once():
            async with async_session_factory() as db:
                await db.execute(text("SET LOCAL lock_timeout = '2s'"))
                await start.wait()
                try:
                    result = await runtime.heartbeat_outbox_delivery(
                        db,
                        message_id=claim.message_id,
                        delivery_attempt_id=claim.delivery_attempt_id,
                        delivery_token=claim.delivery_token,
                        expected_message_version=claim.message_state_version,
                        expected_delivery_version=claim.delivery_state_version,
                        lease_seconds=180,
                    )
                    await db.commit()
                    return "heartbeat", result
                except runtime.OutboxLeaseLost:
                    await db.rollback()
                    return "lost", None

        async def fail_once():
            async with async_session_factory() as db:
                await db.execute(text("SET LOCAL lock_timeout = '2s'"))
                await start.wait()
                try:
                    result = await runtime.fail_outbox_delivery(
                        db,
                        message_id=claim.message_id,
                        delivery_attempt_id=claim.delivery_attempt_id,
                        delivery_token=claim.delivery_token,
                        expected_message_version=claim.message_state_version,
                        expected_delivery_version=claim.delivery_state_version,
                        error=failure,
                    )
                    await db.commit()
                    return "failure", result
                except runtime.OutboxLeaseLost:
                    await db.rollback()
                    return "lost", None

        tasks = [asyncio.create_task(heartbeat_once()), asyncio.create_task(fail_once())]
        await asyncio.sleep(0)
        start.set()
        outcomes = await asyncio.wait_for(asyncio.gather(*tasks), timeout=5)
        labels = [label for label, _ in outcomes]
        assert labels.count("lost") == 1
        assert sum(label in {"heartbeat", "failure"} for label in labels) == 1

        async with async_session_factory() as db:
            message = await db.get(OutboxMessage, message_id)
            delivery = await db.get(
                OutboxDeliveryAttempt,
                claim.delivery_attempt_id,
            )
            if message.status == "dispatching":
                assert delivery.status == "dispatching"
                cleanup_claim = runtime.ClaimedOutboxDelivery(
                    message_id=UUID(str(message.id)),
                    delivery_attempt_id=UUID(str(delivery.id)),
                    delivery_token=UUID(str(delivery.delivery_token)),
                    message_state_version=message.state_version,
                    delivery_state_version=delivery.state_version,
                    delivery_cycle=message.delivery_cycle,
                    cycle_key=message.cycle_key,
                    correlation_id=UUID(str(message.correlation_id)),
                    topic=message.topic,
                    schema_version=message.schema_version,
                    envelope_checksum=message.envelope_checksum,
                    logical_key=message.logical_key,
                    envelope_canonical=message.envelope_canonical,
                )
            else:
                assert message.status == "dead_lettered"
                assert delivery.status == "failed"
                cleanup_claim = None
        if cleanup_claim is not None:
            await _fail_committed(cleanup_claim, retryable=False)
    finally:
        if message_id is not None:
            await _cancel_idle_messages(message_id)
        await engine.dispose()
