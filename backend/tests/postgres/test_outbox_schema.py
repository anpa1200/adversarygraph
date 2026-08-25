"""Real-PostgreSQL authority tests for the 0003 outbox expansion.

Run only against a disposable database.  Authority rows deliberately remain
because production guards reject physical deletion.
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

from app.core.database import async_session_factory, engine
from app.models.research_workflow import (
    OutboxDeliveryAttempt,
    OutboxMessage,
    StageRun,
    WorkflowRun,
)
from app.services import research_projects as projects
from app.services.outbox_engine import (
    delivery_cycle_idempotency_key,
    deterministic_delivery_retry_delay_seconds,
    normalize_outbox_envelope,
)


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_POSTGRES_TESTS") != "1",
    reason="requires an explicitly authorized disposable PostgreSQL database",
)

EMPTY_OBJECT_CHECKSUM = hashlib.sha256(b"{}").hexdigest()
EMPTY_LIST_CHECKSUM = hashlib.sha256(b"[]").hexdigest()


@pytest_asyncio.fixture
async def _require_exact_outbox_expand_revision():
    await engine.dispose()
    async with engine.connect() as connection:
        revision = await connection.scalar(
            text("SELECT version_num FROM alembic_version"),
        )
    if revision != "20260823_0003":
        pytest.skip(
            "raw outbox guard paths require exact revision 0003; revision 0004 fixed-point paths have dedicated acceptance",
        )
    try:
        yield
    finally:
        await engine.dispose()


def _spec() -> dict:
    return {
        "objective": "Validate durable outbox authority.",
        "intelligence_requirements": ["Which outbox state contradictions does PostgreSQL reject?"],
        "output_targets": ["canonical_intelligence"],
        "tlp": "TLP:AMBER",
    }


def _workflow(revision_id: UUID) -> WorkflowRun:
    return WorkflowRun(
        project_revision_id=revision_id,
        workflow_type="cti.report",
        status="queued",
        trigger_type="api",
        idempotency_key=uuid4().hex + uuid4().hex,
        correlation_id=uuid4(),
        input_manifest={},
        input_checksum=EMPTY_OBJECT_CHECKSUM,
        stage_plan=[],
        plan_checksum=EMPTY_LIST_CHECKSUM,
        priority=5,
        state_version=1,
        created_by="PostgreSQL Outbox Test",
        created_by_id="postgres-outbox-test",
    )


async def _insert_pre_contract_workflow(db, revision_id: UUID) -> UUID:
    """Insert exact 0002 authority without projecting the 0004-only column."""

    workflow_id = uuid4()
    await db.execute(
        text("""
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
                :workflow_id, :revision_id, NULL, 'cti.report',
                'research-workflow-v1', 'research-workflow-plan-v1',
                'queued', 'api', :idempotency_key, :correlation_id,
                '{}'::jsonb, :input_checksum, '[]'::jsonb, :plan_checksum,
                5, 1, '', '', 'PostgreSQL Outbox Test',
                'postgres-outbox-test', '', '', '', NULL, NULL, NULL
            )
        """),
        {
            "workflow_id": workflow_id,
            "revision_id": revision_id,
            "idempotency_key": uuid4().hex + uuid4().hex,
            "correlation_id": uuid4(),
            "input_checksum": EMPTY_OBJECT_CHECKSUM,
            "plan_checksum": EMPTY_LIST_CHECKSUM,
        },
    )
    await db.commit()
    return workflow_id


def _ready_stage(workflow_id: UUID, *, stage_key: str | None = None) -> StageRun:
    return StageRun(
        workflow_run_id=workflow_id,
        stage_key=stage_key or f"stage.{uuid4().hex[:12]}",
        stage_type="deterministic.test",
        stage_version="v1",
        ordinal=1,
        status="ready",
        priority=5,
        state_version=1,
        idempotency_key=uuid4().hex + uuid4().hex,
        depends_on=[],
        required=True,
        config={},
        config_checksum=EMPTY_OBJECT_CHECKSUM,
        input_manifest={},
        input_checksum=EMPTY_OBJECT_CHECKSUM,
        output_manifest={},
        output_checksum="",
        checkpoint={},
        checkpoint_version=0,
        checkpoint_checksum=EMPTY_OBJECT_CHECKSUM,
        attempt_count=0,
        max_attempts=3,
        next_attempt_at=datetime.now(timezone.utc),
    )


async def _create_ready_authority(*, label: str):
    actor = projects.ResearchActor("PostgreSQL Outbox Test", "postgres-outbox-test")
    async with async_session_factory() as db:
        _, revision = await projects.create_project(
            db,
            actor,
            project_key=f"{label}-{uuid4().hex[:12]}",
            name=f"{label} Project",
            description="Disposable PostgreSQL outbox authority test.",
            spec=_spec(),
        )
        await db.commit()
        workflow = _workflow(revision.id)
        db.add(workflow)
        await db.commit()
        stage = _ready_stage(workflow.id)
        db.add(stage)
        await db.commit()
        return workflow.id, stage.id


def _normalized(workflow: WorkflowRun, stage: StageRun):
    return normalize_outbox_envelope(
        {
            "topic": "workflow.stage.ready",
            "schema_version": "workflow-stage-ready-v1",
            "payload": {
                "workflow_run_id": str(workflow.id),
                "stage_run_id": str(stage.id),
                "stage_key": stage.stage_key,
                "target_attempt_number": stage.attempt_count + 1,
                "input_checksum": stage.input_checksum,
                "plan_checksum": workflow.plan_checksum,
            },
        }
    )


def _root_message(
    workflow: WorkflowRun,
    stage: StageRun,
) -> OutboxMessage:
    normalized = _normalized(workflow, stage)
    return OutboxMessage(
        workflow_run_id=workflow.id,
        stage_run_id=stage.id,
        aggregate_type="workflow_stage",
        aggregate_id=stage.id,
        aggregate_version=stage.state_version,
        emission_kind="root_ready",
        topic="workflow.stage.ready",
        schema_version="workflow-stage-ready-v1",
        correlation_id=workflow.correlation_id,
        causation_id=None,
        stage_key=stage.stage_key,
        target_attempt_number=stage.attempt_count + 1,
        input_checksum=stage.input_checksum,
        plan_checksum=workflow.plan_checksum,
        envelope_canonical=normalized.canonical,
        envelope_checksum=normalized.checksum,
        envelope_bytes=len(normalized.canonical.encode("utf-8")),
        logical_key=normalized.logical_key,
        max_attempts=8,
        available_at=stage.next_attempt_at,
    )


async def _create_message(*, label: str):
    workflow_id, stage_id = await _create_ready_authority(label=label)
    async with async_session_factory() as db:
        workflow = await db.get(WorkflowRun, workflow_id)
        stage = await db.get(StageRun, stage_id)
        message = _root_message(workflow, stage)
        db.add(message)
        await db.commit()
        await db.refresh(message)
        return workflow_id, stage_id, message.id


async def _claim_message(
    message_id: UUID,
    *,
    publisher: str = "publisher-a",
    lock_timeout: str | None = None,
):
    async with async_session_factory() as db:
        if lock_timeout is not None:
            if lock_timeout != "500ms":
                raise ValueError("test lock timeout must use the bounded 500ms sentinel")
            await db.execute(text("SET LOCAL lock_timeout = '500ms'"))
        message = await db.scalar(
            select(OutboxMessage)
            .where(
                OutboxMessage.id == message_id,
                OutboxMessage.status.in_(("pending", "retry_wait")),
            )
            .with_for_update(skip_locked=True)
        )
        if message is None:
            return None
        attempt_id = uuid4()
        token = uuid4()
        now = datetime.now(timezone.utc)
        message.status = "dispatching"
        message.state_version += 1
        message.attempt_count += 1
        message.delivery_cycle += 1
        message.cycle_key = delivery_cycle_idempotency_key(
            message.logical_key,
            delivery_cycle=message.delivery_cycle,
        )
        message.active_delivery_attempt_id = attempt_id
        message.available_at = None
        message.lease_owner = publisher
        message.lease_token = token
        message.leased_at = now
        message.heartbeat_at = now
        message.lease_expires_at = now + timedelta(minutes=5)
        await db.flush([message])
        await db.refresh(message)
        delivery = OutboxDeliveryAttempt(
            id=attempt_id,
            message_id=message.id,
            delivery_cycle=message.delivery_cycle,
            attempt_number=message.attempt_count,
            cycle_key=message.cycle_key,
            delivery_token=message.lease_token,
            publisher_id=publisher,
            status="dispatching",
            state_version=1,
            leased_at=message.leased_at,
            heartbeat_at=message.heartbeat_at,
            lease_expires_at=message.lease_expires_at,
        )
        db.add(delivery)
        await db.commit()
        return delivery.id


async def _await_receipt(message_id: UUID, delivery_id: UUID):
    async with async_session_factory() as db:
        message = await db.scalar(select(OutboxMessage).where(OutboxMessage.id == message_id).with_for_update())
        delivery = await db.scalar(select(OutboxDeliveryAttempt).where(OutboxDeliveryAttempt.id == delivery_id).with_for_update())
        deadline = datetime.now(timezone.utc) + timedelta(minutes=5)
        delivery.status = "awaiting_receipt"
        delivery.state_version += 1
        delivery.broker_name = "test.broker"
        delivery.broker_message_id = f"broker-{uuid4().hex}"
        delivery.receipt_deadline_at = deadline
        await db.flush([delivery])
        message.status = "awaiting_receipt"
        message.state_version += 1
        message.lease_owner = ""
        message.lease_token = None
        message.leased_at = None
        message.heartbeat_at = None
        message.lease_expires_at = None
        message.receipt_deadline_at = deadline
        await db.commit()


async def _deliver(message_id: UUID, delivery_id: UUID, *, direct: bool):
    async with async_session_factory() as db:
        message = await db.scalar(select(OutboxMessage).where(OutboxMessage.id == message_id).with_for_update())
        delivery = await db.scalar(select(OutboxDeliveryAttempt).where(OutboxDeliveryAttempt.id == delivery_id).with_for_update())
        delivery.status = "delivered"
        delivery.state_version += 1
        if direct:
            delivery.broker_name = "test.broker"
            delivery.broker_message_id = f"broker-{uuid4().hex}"
        delivery.broker_receipt_id = f"receipt-{uuid4().hex}"
        delivery.receipt_deadline_at = None
        await db.flush([delivery])
        message.status = "delivered"
        message.state_version += 1
        message.active_delivery_attempt_id = None
        message.lease_owner = ""
        message.lease_token = None
        message.leased_at = None
        message.heartbeat_at = None
        message.lease_expires_at = None
        message.receipt_deadline_at = None
        await db.commit()


async def _fail_delivery(
    message_id: UUID,
    delivery_id: UUID,
    *,
    retryable: bool,
):
    async with async_session_factory() as db:
        message = await db.scalar(select(OutboxMessage).where(OutboxMessage.id == message_id).with_for_update())
        delivery = await db.scalar(select(OutboxDeliveryAttempt).where(OutboxDeliveryAttempt.id == delivery_id).with_for_update())
        code = "broker.unavailable" if retryable else "broker.rejected"
        error_class = "BrokerUnavailable" if retryable else "BrokerRejected"
        summary = "Sanitized broker delivery failure."
        delivery.status = "failed"
        delivery.state_version += 1
        delivery.error_code = code
        delivery.error_class = error_class
        delivery.error_summary = summary
        delivery.retryable = retryable
        delivery.receipt_deadline_at = None
        await db.flush([delivery])
        exhausted = message.attempt_count >= message.max_attempts
        message.status = "retry_wait" if retryable and not exhausted else "dead_lettered"
        message.state_version += 1
        message.active_delivery_attempt_id = None
        message.lease_owner = ""
        message.lease_token = None
        message.leased_at = None
        message.heartbeat_at = None
        message.lease_expires_at = None
        message.receipt_deadline_at = None
        # The database guard replaces this deliberately arbitrary caller value
        # with the frozen v1 delay derived from transaction time and logical key.
        message.available_at = datetime.now(timezone.utc) + timedelta(days=30) if message.status == "retry_wait" else None
        message.last_error_code = code
        message.last_error_class = error_class
        message.last_error_summary = summary
        message.last_error_retryable = retryable
        await db.commit()
        return message.status


@pytest.mark.asyncio
@pytest.mark.usefixtures("_require_exact_outbox_expand_revision")
async def test_sql_helpers_match_pure_contract_and_reject_fabricated_root_facts():
    await engine.dispose()
    try:
        workflow_id, stage_id = await _create_ready_authority(label="key-parity")
        async with async_session_factory() as db:
            workflow = await db.get(WorkflowRun, workflow_id)
            stage = await db.get(StageRun, stage_id)
            normalized = _normalized(workflow, stage)
            sql_values = (
                await db.execute(
                    text("""
                        SELECT ag_outbox_stage_ready_envelope(
                                   :workflow_id, :stage_id, :stage_key,
                                   :target_attempt, :input_checksum, :plan_checksum
                               ),
                               ag_outbox_stage_ready_logical_key(
                                   :workflow_id, :stage_id, :stage_key,
                                   :target_attempt
                               ),
                               ag_outbox_delivery_cycle_key(:logical_key, 1)
                    """),
                    {
                        "workflow_id": workflow.id,
                        "stage_id": stage.id,
                        "stage_key": stage.stage_key,
                        "target_attempt": 1,
                        "input_checksum": stage.input_checksum,
                        "plan_checksum": workflow.plan_checksum,
                        "logical_key": normalized.logical_key,
                    },
                )
            ).one()
            assert sql_values[0] == normalized.canonical
            assert sql_values[1] == normalized.logical_key
            assert sql_values[2] == delivery_cycle_idempotency_key(normalized.logical_key, delivery_cycle=1)
            retry_rows = (
                await db.execute(
                    text("""
                        SELECT delivery_attempt,
                               ag_outbox_retry_delay_seconds(
                                   :logical_key,
                                   delivery_attempt
                               )
                        FROM generate_series(1, 32) AS delivery_attempt
                        ORDER BY delivery_attempt
                    """),
                    {"logical_key": normalized.logical_key},
                )
            ).all()
            assert retry_rows == [
                (
                    attempt,
                    deterministic_delivery_retry_delay_seconds(
                        attempt,
                        logical_key=normalized.logical_key,
                    ),
                )
                for attempt in range(1, 33)
            ]

            fabricated = _root_message(workflow, stage)
            fabricated.emission_kind = "dependency_ready"
            db.add(fabricated)
            with pytest.raises(IntegrityError, match="emission kind"):
                await db.flush()
            await db.rollback()

        async with async_session_factory() as db:
            workflow = await db.get(WorkflowRun, workflow_id)
            stage = await db.get(StageRun, stage_id)
            fabricated = _root_message(workflow, stage)
            fabricated.last_error_code = "fabricated.error"
            fabricated.last_error_class = "FabricatedError"
            fabricated.last_error_summary = "Not real."
            fabricated.last_error_retryable = True
            db.add(fabricated)
            with pytest.raises(IntegrityError, match="unclaimed pending"):
                await db.flush()
            await db.rollback()

        async with async_session_factory() as db:
            workflow = await db.get(WorkflowRun, workflow_id)
            stage = await db.get(StageRun, stage_id)
            wrong_policy = _root_message(workflow, stage)
            wrong_policy.max_attempts = 7
            db.add(wrong_policy)
            with pytest.raises(IntegrityError, match="ck_outbox_message_delivery_counts"):
                await db.flush()
            await db.rollback()

        async with async_session_factory() as db:
            workflow = await db.get(WorkflowRun, workflow_id)
            stage = await db.get(StageRun, stage_id)
            message = _root_message(workflow, stage)
            db.add(message)
            await db.commit()
            index_definition = (
                await db.execute(
                    text("""
                        SELECT pg_get_indexdef(index_row.indexrelid),
                               pg_get_expr(
                                   index_row.indpred,
                                   index_row.indrelid,
                                   TRUE
                               )
                        FROM pg_index AS index_row
                        JOIN pg_class AS index_relation
                          ON index_relation.oid = index_row.indexrelid
                        WHERE index_relation.relname =
                              'ix_outbox_messages_stage_active'
                    """),
                )
            ).one()
            assert "(stage_run_id, target_attempt_number, id)" in index_definition[0]
            assert all(
                status in index_definition[1]
                for status in (
                    "pending",
                    "dispatching",
                    "awaiting_receipt",
                    "retry_wait",
                )
            )
    finally:
        await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize("direct", [False, True])
@pytest.mark.usefixtures("_require_exact_outbox_expand_revision")
async def test_legal_delivery_receipt_paths_and_terminal_immutability(direct: bool):
    await engine.dispose()
    try:
        _, _, message_id = await _create_message(label=f"receipt-{direct}")
        delivery_id = await _claim_message(message_id)
        assert delivery_id is not None
        if not direct:
            await _await_receipt(message_id, delivery_id)
        await _deliver(message_id, delivery_id, direct=direct)
        async with async_session_factory() as db:
            message = await db.get(OutboxMessage, message_id)
            delivery = await db.get(OutboxDeliveryAttempt, delivery_id)
            assert message.status == delivery.status == "delivered"
            assert message.active_delivery_attempt_id is None
            assert delivery.broker_name == "test.broker"
            assert delivery.broker_message_id
            assert delivery.receipt_received_at is not None

            message.last_error_summary = "Forbidden terminal rewrite."
            message.state_version += 1
            with pytest.raises(IntegrityError):
                await db.flush()
            await db.rollback()

        async with async_session_factory() as db:
            delivery = await db.get(OutboxDeliveryAttempt, delivery_id)
            await db.delete(delivery)
            with pytest.raises(IntegrityError, match="cannot be deleted"):
                await db.flush()
            await db.rollback()

        async with async_session_factory() as db:
            message = await db.get(OutboxMessage, message_id)
            await db.delete(message)
            with pytest.raises(IntegrityError, match="cannot be deleted"):
                await db.flush()
            await db.rollback()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.usefixtures("_require_exact_outbox_expand_revision")
async def test_deterministic_retry_dead_letter_redrive_and_cancelled_lineage():
    await engine.dispose()
    try:
        _, _, retry_message_id = await _create_message(label="retry-schedule")
        first_delivery = await _claim_message(retry_message_id)
        assert first_delivery is not None
        assert await _fail_delivery(retry_message_id, first_delivery, retryable=True) == "retry_wait"
        async with async_session_factory() as db:
            retry_message = await db.get(OutboxMessage, retry_message_id)
            retry_delay = deterministic_delivery_retry_delay_seconds(
                retry_message.attempt_count,
                logical_key=retry_message.logical_key,
            )
            assert retry_message.available_at == retry_message.updated_at + timedelta(seconds=retry_delay)
            assert retry_message.max_attempts == 8

        _, stage_id, message_id = await _create_message(label="dead-letter-redrive")
        rejected_delivery = await _claim_message(message_id)
        assert rejected_delivery is not None
        assert await _fail_delivery(message_id, rejected_delivery, retryable=False) == "dead_lettered"

        async with async_session_factory() as db:
            parent = await db.get(OutboxMessage, message_id)
            stage = await db.get(StageRun, stage_id)
            assert parent.status == "dead_lettered"
            assert stage.status == "ready"
            child = OutboxMessage(
                workflow_run_id=parent.workflow_run_id,
                stage_run_id=parent.stage_run_id,
                aggregate_type=parent.aggregate_type,
                aggregate_id=parent.aggregate_id,
                aggregate_version=parent.aggregate_version,
                emission_kind="manual_redrive",
                topic=parent.topic,
                schema_version=parent.schema_version,
                correlation_id=parent.correlation_id,
                causation_id=parent.id,
                stage_key=parent.stage_key,
                target_attempt_number=parent.target_attempt_number,
                input_checksum=parent.input_checksum,
                plan_checksum=parent.plan_checksum,
                envelope_canonical=parent.envelope_canonical,
                envelope_checksum=parent.envelope_checksum,
                envelope_bytes=parent.envelope_bytes,
                logical_key=parent.logical_key,
                redrive_of_message_id=parent.id,
                redrive_ordinal=1,
                redrive_requested_by="Outbox Operator",
                redrive_requested_by_id="outbox-operator",
                redrive_reason="Authorized retry after broker recovery.",
                max_attempts=parent.max_attempts,
                delivery_cycle=parent.delivery_cycle,
                cycle_key=parent.cycle_key,
                available_at=datetime.now(timezone.utc),
            )
            db.add(child)
            await db.commit()
            await db.refresh(child)
            assert child.status == "pending"
            assert child.attempt_count == 0
            assert child.delivery_cycle == parent.delivery_cycle

            child.status = "cancelled"
            child.state_version += 1
            child.available_at = None
            child.cancelled_by = "Outbox Operator"
            child.cancelled_by_id = "outbox-operator"
            child.cancel_reason = "Stage was cancelled."
            await db.commit()
            child_id = child.id

        async with async_session_factory() as db:
            cancelled = await db.get(OutboxMessage, child_id)
            grandchild = OutboxMessage(
                **{
                    column.name: getattr(cancelled, column.name)
                    for column in OutboxMessage.__table__.columns
                    if column.name
                    in {
                        "workflow_run_id",
                        "stage_run_id",
                        "aggregate_type",
                        "aggregate_id",
                        "aggregate_version",
                        "topic",
                        "schema_version",
                        "correlation_id",
                        "stage_key",
                        "target_attempt_number",
                        "input_checksum",
                        "plan_checksum",
                        "envelope_canonical",
                        "envelope_checksum",
                        "envelope_bytes",
                        "logical_key",
                        "max_attempts",
                        "delivery_cycle",
                        "cycle_key",
                    }
                },
                emission_kind="manual_redrive",
                redrive_of_message_id=cancelled.id,
                redrive_ordinal=2,
                redrive_requested_by="Outbox Operator",
                redrive_requested_by_id="outbox-operator",
                redrive_reason="Forbidden cancelled redrive.",
                available_at=datetime.now(timezone.utc),
            )
            db.add(grandchild)
            with pytest.raises(IntegrityError, match="dead-letter lineage"):
                await db.flush()
            await db.rollback()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.usefixtures("_require_exact_outbox_expand_revision")
async def test_error_regex_broker_history_and_message_error_binding_fail_closed():
    await engine.dispose()
    try:
        _, _, message_id = await _create_message(label="error-binding")
        delivery_id = await _claim_message(message_id)
        async with async_session_factory() as db:
            message = await db.scalar(select(OutboxMessage).where(OutboxMessage.id == message_id).with_for_update())
            delivery = await db.scalar(select(OutboxDeliveryAttempt).where(OutboxDeliveryAttempt.id == delivery_id).with_for_update())
            delivery.status = "failed"
            delivery.state_version += 1
            delivery.error_code = "broker.failed"
            delivery.error_class = "1InvalidClass"
            delivery.error_summary = "Rejected invalid class."
            delivery.retryable = False
            with pytest.raises(IntegrityError):
                await db.flush([delivery])
            await db.rollback()

        async with async_session_factory() as db:
            message = await db.scalar(select(OutboxMessage).where(OutboxMessage.id == message_id).with_for_update())
            delivery = await db.scalar(select(OutboxDeliveryAttempt).where(OutboxDeliveryAttempt.id == delivery_id).with_for_update())
            delivery.status = "failed"
            delivery.state_version += 1
            delivery.error_code = "broker.failed"
            delivery.error_class = "BrokerFailed"
            delivery.error_summary = "Exact sanitized failure."
            delivery.retryable = False
            await db.flush([delivery])
            message.status = "dead_lettered"
            message.state_version += 1
            message.active_delivery_attempt_id = None
            message.lease_owner = ""
            message.lease_token = None
            message.leased_at = None
            message.heartbeat_at = None
            message.lease_expires_at = None
            message.last_error_code = delivery.error_code
            message.last_error_class = delivery.error_class
            message.last_error_summary = "Fabricated different failure."
            message.last_error_retryable = delivery.retryable
            with pytest.raises(IntegrityError, match="must match latest"):
                await db.flush([message])
            await db.rollback()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.usefixtures("_require_exact_outbox_expand_revision")
async def test_concurrent_claim_has_one_winner_and_guards_do_not_reverse_lock():
    await engine.dispose()
    try:
        _, _, message_id = await _create_message(label="claim-race")
        winners = await asyncio.gather(
            _claim_message(message_id, publisher="publisher-one"),
            _claim_message(message_id, publisher="publisher-two"),
        )
        assert sum(item is not None for item in winners) == 1
        delivery_id = next(item for item in winners if item is not None)

        # Holding the upstream stage must not block the actual pending->dispatching
        # publisher claim branch: its trigger validates an MVCC snapshot without
        # acquiring Stage/Workflow row locks in reverse suffix order.
        _, claim_stage_id, claim_message_id = await _create_message(label="claim-lock-order")
        async with async_session_factory() as upstream:
            await upstream.execute(select(StageRun).where(StageRun.id == claim_stage_id).with_for_update())
            claim_delivery_id = await _claim_message(
                claim_message_id,
                publisher="publisher-lock-order",
                lock_timeout="500ms",
            )
            assert claim_delivery_id is not None
            await upstream.rollback()

        # Holding Message must not block Delivery's trigger by reverse-locking
        # its parent.  Roll back before deferred pair consistency is evaluated.
        async with async_session_factory() as parent, async_session_factory() as child:
            await parent.execute(select(OutboxMessage).where(OutboxMessage.id == message_id).with_for_update())
            await child.execute(text("SET LOCAL lock_timeout = '500ms'"))
            delivery = await child.get(OutboxDeliveryAttempt, delivery_id)
            delivery.state_version += 1
            delivery.heartbeat_at = datetime.now(timezone.utc)
            delivery.lease_expires_at = delivery.lease_expires_at + timedelta(seconds=1)
            await child.flush([delivery])
            await child.rollback()
            await parent.rollback()
    finally:
        await engine.dispose()


def _database_url(database_name: str) -> str:
    return URL.create(
        "postgresql+asyncpg",
        username=os.environ["DB_USER"],
        password=os.environ["DB_PASS"],
        host=os.environ["DB_HOST"],
        port=int(os.environ["DB_PORT"]),
        database=database_name,
    ).render_as_string(hide_password=False)


def _run_alembic(database_name: str, *arguments: str, expect_success: bool = True):
    backend_root = Path(__file__).resolve().parents[2]
    environment = os.environ.copy()
    environment["DB_NAME"] = database_name
    result = subprocess.run(
        [sys.executable, "-m", "alembic", *arguments],
        cwd=backend_root,
        env=environment,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )
    if expect_success and result.returncode != 0:
        pytest.fail(result.stdout + result.stderr)
    if not expect_success:
        assert result.returncode != 0
    return result


@pytest.mark.asyncio
async def test_0003_upgrade_rejects_runnable_stage_under_inactive_workflow():
    database_name = f"ag_outbox_inactive_{uuid4().hex[:16]}"
    admin = await asyncpg.connect(
        host=os.environ["DB_HOST"],
        port=int(os.environ["DB_PORT"]),
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASS"],
        database="postgres",
    )
    try:
        await admin.execute(f'CREATE DATABASE "{database_name}"')
        _run_alembic(database_name, "upgrade", "20260823_0002")
        dynamic_engine = create_async_engine(_database_url(database_name))
        sessions = async_sessionmaker(dynamic_engine, expire_on_commit=False)
        try:
            actor = projects.ResearchActor(
                "PostgreSQL Outbox Inactive Test",
                "postgres-outbox-inactive",
            )
            async with sessions() as db:
                _, revision = await projects.create_project(
                    db,
                    actor,
                    project_key=f"outbox-inactive-{uuid4().hex[:12]}",
                    name="Outbox inactive workflow project",
                    description="Disposable migration preflight sentinel.",
                    spec=_spec(),
                )
                await db.commit()
                workflow_id = await _insert_pre_contract_workflow(
                    db,
                    revision.id,
                )
                stage = _ready_stage(workflow_id, stage_key="inactive.ready")
                db.add(stage)
                await db.commit()
                stage_id = stage.id
            async with dynamic_engine.begin() as connection:
                await connection.execute(
                    text("""
                        UPDATE workflow_runs
                        SET status = 'cancelled',
                            state_version = state_version + 1,
                            completed_at = transaction_timestamp(),
                            cancel_requested_at = transaction_timestamp(),
                            cancel_reason = 'Migration preflight sentinel.',
                            cancel_requested_by = 'Migration Test',
                            cancel_requested_by_id = 'migration-test',
                            updated_at = transaction_timestamp()
                        WHERE id = :workflow_id
                    """),
                    {"workflow_id": workflow_id},
                )
        finally:
            await dynamic_engine.dispose()

        rejected = _run_alembic(
            database_name,
            "upgrade",
            "20260823_0003",
            expect_success=False,
        )
        assert "ck_outbox_backfill_workflow" in rejected.stdout + rejected.stderr

        connection = await asyncpg.connect(
            host=os.environ["DB_HOST"],
            port=int(os.environ["DB_PORT"]),
            user=os.environ["DB_USER"],
            password=os.environ["DB_PASS"],
            database=database_name,
        )
        try:
            assert await connection.fetchval("SELECT version_num FROM alembic_version") == "20260823_0002"
            assert await connection.fetchval("SELECT to_regclass('outbox_messages')") is None
            assert (
                await connection.fetchval(
                    "SELECT status FROM workflow_runs WHERE id = $1",
                    workflow_id,
                )
                == "cancelled"
            )
            assert (
                await connection.fetchval(
                    "SELECT status FROM stage_runs WHERE id = $1",
                    stage_id,
                )
                == "ready"
            )
        finally:
            await connection.close()
    finally:
        await admin.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()",
            database_name,
        )
        await admin.execute(f'DROP DATABASE IF EXISTS "{database_name}"')
        await admin.close()


@pytest.mark.asyncio
async def test_0002_upgrade_backfill_exactness_and_downgrade_policy():
    database_name = f"ag_outbox_migration_{uuid4().hex[:16]}"
    admin = await asyncpg.connect(
        host=os.environ["DB_HOST"],
        port=int(os.environ["DB_PORT"]),
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASS"],
        database="postgres",
    )
    try:
        await admin.execute(f'CREATE DATABASE "{database_name}"')
        _run_alembic(database_name, "upgrade", "20260823_0002")
        dynamic_engine = create_async_engine(_database_url(database_name))
        sessions = async_sessionmaker(dynamic_engine, expire_on_commit=False)
        try:
            actor = projects.ResearchActor("PostgreSQL Outbox Migration Test", "postgres-outbox-migration")
            async with sessions() as db:
                _, revision = await projects.create_project(
                    db,
                    actor,
                    project_key=f"outbox-migration-{uuid4().hex[:12]}",
                    name="Outbox migration project",
                    description="Disposable migration sentinel.",
                    spec=_spec(),
                )
                await db.commit()
                workflow_id = await _insert_pre_contract_workflow(
                    db,
                    revision.id,
                )
                stage = _ready_stage(workflow_id, stage_key="migration.ready")
                db.add(stage)
                await db.commit()
                stage_id = stage.id
        finally:
            await dynamic_engine.dispose()

        _run_alembic(database_name, "upgrade", "20260823_0003")
        connection = await asyncpg.connect(
            host=os.environ["DB_HOST"],
            port=int(os.environ["DB_PORT"]),
            user=os.environ["DB_USER"],
            password=os.environ["DB_PASS"],
            database=database_name,
        )
        try:
            row = await connection.fetchrow(
                """
                SELECT message.*, workflow.plan_checksum
                FROM outbox_messages AS message
                JOIN workflow_runs AS workflow ON workflow.id = message.workflow_run_id
                WHERE message.stage_run_id = $1
                """,
                stage_id,
            )
            assert row is not None
            normalized = normalize_outbox_envelope(
                {
                    "topic": "workflow.stage.ready",
                    "schema_version": "workflow-stage-ready-v1",
                    "payload": {
                        "workflow_run_id": str(workflow_id),
                        "stage_run_id": str(stage_id),
                        "stage_key": "migration.ready",
                        "target_attempt_number": 1,
                        "input_checksum": EMPTY_OBJECT_CHECKSUM,
                        "plan_checksum": row["plan_checksum"],
                    },
                }
            )
            assert row["emission_kind"] == "migration_backfill"
            assert row["status"] == "pending"
            assert row["attempt_count"] == row["delivery_cycle"] == 0
            assert row["max_attempts"] == 8
            assert row["envelope_canonical"] == normalized.canonical
            assert row["envelope_checksum"] == normalized.checksum
            assert row["logical_key"] == normalized.logical_key
        finally:
            await connection.close()

        _run_alembic(database_name, "downgrade", "20260823_0002")
        _run_alembic(database_name, "upgrade", "20260823_0003")
        connection = await asyncpg.connect(
            host=os.environ["DB_HOST"],
            port=int(os.environ["DB_PORT"]),
            user=os.environ["DB_USER"],
            password=os.environ["DB_PASS"],
            database=database_name,
        )
        try:
            await connection.execute(
                """
                UPDATE outbox_messages
                SET status = 'cancelled',
                    state_version = state_version + 1,
                    available_at = NULL,
                    cancelled_by = 'Migration Test',
                    cancelled_by_id = 'migration-test',
                    cancel_reason = 'Make downgrade intentionally unsafe.'
                WHERE stage_run_id = $1
                """,
                stage_id,
            )
        finally:
            await connection.close()
        blocked = _run_alembic(
            database_name,
            "downgrade",
            "20260823_0002",
            expect_success=False,
        )
        assert "only untouched migration_backfill messages" in (blocked.stdout + blocked.stderr)
    finally:
        await admin.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()",
            database_name,
        )
        await admin.execute(f'DROP DATABASE IF EXISTS "{database_name}"')
        await admin.close()
