"""PostgreSQL acceptance for commit-owning lease recovery coordination.

Run only against a disposable database migrated through revision 0004::

    RUN_POSTGRES_TESTS=1 python -m pytest -q -o addopts='' \
      --confcutdir=tests/postgres \
      tests/postgres/test_workflow_recovery_emission.py

Execution authority is obtained only through workflow creation, the real
outbox publisher claim, and the real receipt coordinator. Recovery is invoked
only through the commit-owning worker coordinator; tests never manufacture
replacement authority.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import uuid
from contextlib import asynccontextmanager
from datetime import timedelta

import pytest
import pytest_asyncio
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError

from app.core.database import async_session_factory, engine
from app.models.research_workflow import (
    OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1,
    OUTBOX_TOPIC_WORKFLOW_STAGE_READY,
    OUTBOX_V1_MAX_ATTEMPTS,
    OutboxMessage,
    StageAttempt,
    StageRun,
    WorkflowRun,
)
from app.services import outbox_coordinator
from app.services import outbox_runtime
from app.services import research_projects as projects
from app.services import workflow_runtime as runtime
from app.services import workflow_worker
from app.services.outbox_engine import normalize_outbox_envelope
from app.services.workflow_engine import (
    checksum_json,
    deterministic_retry_backoff_seconds,
    normalize_stage_plan,
)
from tests.postgres._workflow_authority import cancel_active_workflow


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_POSTGRES_TESTS") != "1",
    reason="requires an explicitly authorized disposable PostgreSQL database",
)

ACTOR = projects.ResearchActor(
    name="PostgreSQL Workflow Recovery Emission Test",
    actor_id="postgres-workflow-recovery-emission",
)


class _AsyncBarrier:
    """Bounded barrier for deterministic concurrent transaction starts."""

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


@pytest_asyncio.fixture(autouse=True)
async def _dispose_engine_pool_between_tests():
    await engine.dispose()
    try:
        yield
    finally:
        await engine.dispose()


def _spec(label: str) -> dict:
    return {
        "objective": f"Validate native lease-recovery workflow emission: {label}.",
        "intelligence_requirements": [
            "Does exact abandoned-attempt evidence atomically authorize deterministic recovery?",
        ],
        "output_targets": ["canonical_intelligence"],
        "tlp": "TLP:AMBER",
    }


def _stage_definition(*, max_attempts: int = 3) -> dict:
    return {
        "stage_key": "collect",
        "stage_type": "test.collect",
        "stage_version": "1.0.0",
        "ordinal": 1,
        "depends_on": [],
        "required": True,
        "priority": 0,
        "max_attempts": max_attempts,
        "config_schema_version": "research-stage-config-v1",
        "checkpoint_schema_version": "research-stage-checkpoint-v1",
        "config": {"acceptance_test": True, "stage": "collect"},
        "retry_policy": {
            "base_delay_seconds": 1,
            "max_delay_seconds": 1,
            "jitter_percent": 0,
        },
    }


async def _new_workflow(label: str, *, max_attempts: int = 3) -> uuid.UUID:
    project_label = label.replace("_", "-")
    async with async_session_factory() as db:
        _, revision = await projects.create_project(
            db,
            ACTOR,
            project_key=f"recovery-emission-{project_label}-{uuid.uuid4().hex[:12]}",
            name=f"Recovery emission {label}",
            description="Disposable PostgreSQL native recovery-emission acceptance authority.",
            spec=_spec(label),
        )
        workflow, created = await runtime.create_workflow(
            db,
            ACTOR,
            project_revision_id=revision.id,
            workflow_type="cti.report",
            idempotency_token=f"recovery-{label}-{uuid.uuid4().hex}",
            input_manifest={"report_id": label, "source_ids": ["source-a", "source-b"]},
            stage_plan=[_stage_definition(max_attempts=max_attempts)],
            priority=0,
        )
        assert created is True
        workflow_id = uuid.UUID(str(workflow.id))
        await db.commit()
        return workflow_id


@asynccontextmanager
async def _isolate_outbox_queue(allowed_message_ids: set[uuid.UUID]):
    """Make the global SKIP LOCKED publisher scan select only test authority."""

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


@asynccontextmanager
async def _isolate_recovery_targets(allowed_workflow_ids: set[uuid.UUID]):
    """Keep unrelated shared-DB workflows outside the recovery scan."""

    async with async_session_factory() as blocker:
        await blocker.execute(
            select(WorkflowRun.id)
            .where(
                WorkflowRun.status.in_(("queued", "running")),
                WorkflowRun.id.not_in(allowed_workflow_ids),
            )
            .order_by(WorkflowRun.id.asc())
            .with_for_update()
        )
        try:
            yield
        finally:
            await blocker.rollback()


def _broker_receipt_id(cycle_key: str) -> str:
    return hashlib.sha256(f"recovery-emission-receipt:{cycle_key}".encode()).hexdigest()


async def _activate_message(
    message_id: uuid.UUID,
    *,
    worker_id: str,
    lease_seconds: int,
) -> outbox_runtime.ExecutableStageAuthority:
    async with _isolate_outbox_queue({message_id}):
        async with async_session_factory() as db:
            claim = await outbox_runtime.claim_outbox_delivery(
                db,
                publisher_id=f"recovery-emission-publisher-{worker_id}",
                lease_seconds=120,
            )
            assert claim is not None
            assert claim.message_id == message_id
            await db.commit()

    command = outbox_runtime.StageReceiptCommand(
        claim=claim,
        broker_name="postgres_test_broker",
        broker_message_id=f"recovery-emission-{claim.cycle_key}",
        broker_receipt_id=_broker_receipt_id(claim.cycle_key),
        worker_id=worker_id,
        lease_seconds=lease_seconds,
    )
    coordinated = await outbox_coordinator.coordinate_stage_receipt(
        async_session_factory,
        command=command,
    )
    assert coordinated.disposition == "activated"
    assert coordinated.should_execute is True
    assert coordinated.should_ack is True
    assert coordinated.authority is not None
    return coordinated.authority


async def _activate_root(
    workflow_id: uuid.UUID,
    *,
    lease_seconds: int = 1,
) -> outbox_runtime.ExecutableStageAuthority:
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
    return await _activate_message(
        message_id,
        worker_id=f"root-{workflow_id}",
        lease_seconds=lease_seconds,
    )


async def _cancel_if_active(workflow_id: uuid.UUID) -> None:
    await cancel_active_workflow(
        async_session_factory,
        workflow_run_id=workflow_id,
        actor=ACTOR,
        reason="Recovery-emission acceptance cleanup.",
    )


def _expected_recovery_envelope(workflow: WorkflowRun, stage: StageRun):
    return normalize_outbox_envelope(
        {
            "topic": OUTBOX_TOPIC_WORKFLOW_STAGE_READY,
            "schema_version": OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1,
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


def _assert_exact_recovery_message(
    message: OutboxMessage,
    *,
    workflow: WorkflowRun,
    stage: StageRun,
    cause: StageAttempt,
) -> None:
    expected = _expected_recovery_envelope(workflow, stage)
    normalized_plan = normalize_stage_plan(workflow.stage_plan)
    definition = next(item for item in normalized_plan.stages if item.stage_key == stage.stage_key)
    expected_delay = deterministic_retry_backoff_seconds(
        cause.attempt_number,
        seed=str(stage.id),
        policy=definition.retry_policy,
    )

    assert message.workflow_run_id == workflow.id
    assert message.stage_run_id == stage.id
    assert message.aggregate_type == "workflow_stage"
    assert message.aggregate_id == stage.id
    assert message.aggregate_version == stage.state_version == 3
    assert message.emission_kind == "lease_recovered"
    assert message.topic == OUTBOX_TOPIC_WORKFLOW_STAGE_READY
    assert message.schema_version == OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1
    assert message.correlation_id == workflow.correlation_id
    assert message.causation_id == cause.id
    assert message.stage_key == stage.stage_key == "collect"
    assert message.target_attempt_number == stage.attempt_count + 1 == 2
    assert message.input_checksum == stage.input_checksum == cause.input_checksum
    assert message.input_checksum == checksum_json(stage.input_manifest)
    assert message.plan_checksum == workflow.plan_checksum == normalized_plan.checksum
    assert message.envelope_canonical == expected.canonical
    assert json.loads(message.envelope_canonical) == expected.as_payload()
    assert message.envelope_checksum == expected.checksum
    assert message.envelope_bytes == len(expected.canonical.encode("utf-8"))
    assert message.logical_key == expected.logical_key
    assert message.redrive_of_message_id is None
    assert message.redrive_ordinal == 0
    assert message.status == "pending"
    assert message.state_version == 1
    assert message.attempt_count == 0
    assert message.max_attempts == OUTBOX_V1_MAX_ATTEMPTS == 8
    assert message.delivery_cycle == 0
    assert message.cycle_key is None
    assert message.available_at == stage.next_attempt_at
    assert message.available_at == cause.completed_at + timedelta(seconds=expected_delay)
    assert (message.available_at - cause.completed_at).total_seconds() == expected_delay
    assert message.active_delivery_attempt_id is None
    assert message.lease_owner == ""
    assert message.lease_token is None
    assert message.leased_at is None
    assert message.lease_expires_at is None
    assert message.heartbeat_at is None
    assert message.receipt_deadline_at is None
    assert message.last_error_code == ""
    assert message.last_error_class == ""
    assert message.last_error_summary == ""
    assert message.last_error_retryable is False
    assert message.delivered_at is None
    assert message.dead_lettered_at is None
    assert message.cancelled_at is None


@pytest.mark.asyncio
async def test_recovery_atomically_emits_exact_message_and_persisted_message_reclaims_with_old_token_fenced():
    workflow_id = await _new_workflow("exact-recovery")
    try:
        authority = await _activate_root(workflow_id)
        await asyncio.sleep(1.2)

        async with _isolate_recovery_targets({workflow_id}):
            result = await workflow_worker.coordinate_one_expired_stage_recovery(
                async_session_factory,
            )
        assert result is not None
        assert result.workflow_run_id == workflow_id
        assert result.stage_run_id == authority.stage_run_id
        assert result.stage_attempt_id == authority.stage_attempt_id
        assert result.message_id == authority.message_id
        assert result.delivery_attempt_id == authority.delivery_attempt_id
        assert result.decision == "retry"
        assert result.stage_status == "retry_wait"
        assert result.attempt_status == "abandoned"
        assert result.next_attempt_at is not None
        assert result.retry_emission is not None
        assert result.retry_emission.stage_run_id == authority.stage_run_id
        assert result.should_retry is True
        assert result.should_continue is False

        async with async_session_factory() as db:
            workflow = await db.get(WorkflowRun, workflow_id)
            stage = await db.get(StageRun, authority.stage_run_id)
            cause = await db.get(StageAttempt, authority.stage_attempt_id)
            messages = tuple(
                (
                    await db.scalars(
                        select(OutboxMessage).where(
                            OutboxMessage.workflow_run_id == workflow_id,
                            OutboxMessage.emission_kind == "lease_recovered",
                        )
                    )
                ).all()
            )
            assert workflow is not None and workflow.status == "running"
            assert stage is not None and stage.status == "retry_wait"
            assert stage.state_version == authority.stage_state_version + 1 == 3
            assert stage.attempt_count == authority.attempt_number == 1
            assert stage.last_error_code == "workflow.lease_expired"
            assert stage.last_error_retryable is True
            assert stage.lease_token is None
            assert cause is not None and cause.status == "abandoned"
            assert cause.state_version == authority.attempt_state_version + 1 == 2
            assert cause.lease_token == authority.stage_lease_token
            assert cause.checkpoint_end_version == authority.checkpoint_version
            assert cause.error_code == stage.last_error_code
            assert cause.error_class == "LeaseExpired"
            assert cause.error_summary == stage.last_error_summary
            assert cause.retryable is True
            assert cause.output_checksum == ""
            assert len(messages) == 1
            _assert_exact_recovery_message(messages[0], workflow=workflow, stage=stage, cause=cause)
            recovery_message_id = uuid.UUID(str(messages[0].id))

        await asyncio.sleep(1.2)
        reclaimed = await _activate_message(
            recovery_message_id,
            worker_id="replacement-worker",
            lease_seconds=120,
        )
        assert reclaimed.workflow_run_id == workflow_id
        assert reclaimed.stage_run_id == authority.stage_run_id
        assert reclaimed.attempt_number == 2
        assert reclaimed.stage_lease_token != authority.stage_lease_token

        stale_heartbeat = await workflow_worker.coordinate_stage_heartbeat(
            async_session_factory,
            authority=authority,
            lease_seconds=120,
        )
        assert stale_heartbeat.disposition == "stale"
        assert stale_heartbeat.should_continue is False
        assert stale_heartbeat.authority is None

        async with async_session_factory() as db:
            attempts = tuple(
                (
                    await db.scalars(
                        select(StageAttempt)
                        .where(StageAttempt.stage_run_id == authority.stage_run_id)
                        .order_by(StageAttempt.attempt_number.asc())
                    )
                ).all()
            )
            assert [attempt.attempt_number for attempt in attempts] == [1, 2]
            assert [attempt.status for attempt in attempts] == ["abandoned", "running"]
    finally:
        await _cancel_if_active(workflow_id)


@pytest.mark.asyncio
async def test_two_concurrent_recoverers_serialize_to_one_result_and_one_message():
    workflow_id = await _new_workflow("concurrent-recovery")
    try:
        authority = await _activate_root(workflow_id)
        await asyncio.sleep(1.2)
        start = _AsyncBarrier(2)

        async def recover_after_barrier():
            await start.wait()
            return await workflow_worker.coordinate_one_expired_stage_recovery(
                async_session_factory,
            )

        async with _isolate_recovery_targets({workflow_id}):
            results = await asyncio.wait_for(
                asyncio.gather(recover_after_barrier(), recover_after_barrier()),
                timeout=20,
            )

        assert sum(result is not None for result in results) == 1
        winner = next(result for result in results if result is not None)
        assert winner.workflow_run_id == workflow_id
        assert winner.stage_run_id == authority.stage_run_id

        async with async_session_factory() as db:
            stage = await db.get(StageRun, authority.stage_run_id)
            attempts = tuple((await db.scalars(select(StageAttempt).where(StageAttempt.stage_run_id == authority.stage_run_id))).all())
            messages = tuple(
                (
                    await db.scalars(
                        select(OutboxMessage).where(
                            OutboxMessage.workflow_run_id == workflow_id,
                            OutboxMessage.emission_kind == "lease_recovered",
                        )
                    )
                ).all()
            )
            assert stage is not None and stage.status == "retry_wait"
            assert len(attempts) == 1 and attempts[0].status == "abandoned"
            assert len(messages) == 1
            assert messages[0].causation_id == attempts[0].id
    finally:
        await _cancel_if_active(workflow_id)


@pytest.mark.asyncio
async def test_each_recovery_transaction_returns_one_workflow_and_skips_a_locked_peer():
    workflow_ids = [
        await _new_workflow("independent-recovery-alpha"),
        await _new_workflow("independent-recovery-bravo"),
    ]
    try:
        authorities = [await _activate_root(workflow_id) for workflow_id in workflow_ids]
        authority_by_workflow = {authority.workflow_run_id: authority for authority in authorities}
        await asyncio.sleep(1.2)

        async with async_session_factory() as db:
            ordered_ids = tuple(
                (
                    await db.scalars(
                        select(WorkflowRun.id)
                        .where(WorkflowRun.id.in_(workflow_ids))
                        .order_by(WorkflowRun.created_at.asc(), WorkflowRun.id.asc())
                    )
                ).all()
            )
        locked_id, available_id = ordered_ids

        async with _isolate_recovery_targets(set(workflow_ids)):
            async with async_session_factory() as blocker:
                locked = await blocker.scalar(select(WorkflowRun).where(WorkflowRun.id == locked_id).with_for_update())
                assert locked is not None

                first = await asyncio.wait_for(
                    workflow_worker.coordinate_one_expired_stage_recovery(
                        async_session_factory,
                    ),
                    timeout=5,
                )
                assert first is not None
                assert first.workflow_run_id == available_id
                assert (
                    await workflow_worker.coordinate_one_expired_stage_recovery(
                        async_session_factory,
                    )
                    is None
                )

                async with async_session_factory() as observer:
                    blocked_stage = await observer.get(
                        StageRun,
                        authority_by_workflow[locked_id].stage_run_id,
                    )
                    recovered_stage = await observer.get(
                        StageRun,
                        authority_by_workflow[available_id].stage_run_id,
                    )
                    assert blocked_stage is not None and blocked_stage.status == "running"
                    assert recovered_stage is not None and recovered_stage.status == "retry_wait"
                await blocker.rollback()

            second = await workflow_worker.coordinate_one_expired_stage_recovery(
                async_session_factory,
            )
            assert second is not None
            assert second.workflow_run_id == locked_id

        async with async_session_factory() as db:
            messages = tuple(
                (
                    await db.scalars(
                        select(OutboxMessage).where(
                            OutboxMessage.workflow_run_id.in_(workflow_ids),
                            OutboxMessage.emission_kind == "lease_recovered",
                        )
                    )
                ).all()
            )
            assert len(messages) == 2
            assert {message.workflow_run_id for message in messages} == set(workflow_ids)
            for authority in authorities:
                stage = await db.get(StageRun, authority.stage_run_id)
                assert stage is not None and stage.status == "retry_wait"
    finally:
        for workflow_id in workflow_ids:
            await _cancel_if_active(workflow_id)


@pytest.mark.asyncio
async def test_late_failure_after_recovery_message_flush_rolls_back_live_authority(monkeypatch):
    workflow_id = await _new_workflow("late-rollback")
    try:
        authority = await _activate_root(workflow_id)
        await asyncio.sleep(1.2)
        real_append = workflow_worker._append_reserved_stage_ready
        captured_message_ids: set[uuid.UUID] = set()

        async def append_then_abort(db, **kwargs):
            results = await real_append(db, **kwargs)
            captured_message_ids.update(uuid.UUID(str(message.id)) for message, _created in results)
            await db.execute(text("SELECT 1 / 0"))
            return results

        monkeypatch.setattr(
            workflow_worker,
            "_append_reserved_stage_ready",
            append_then_abort,
        )
        async with _isolate_recovery_targets({workflow_id}):
            with pytest.raises(DBAPIError):
                await workflow_worker.coordinate_one_expired_stage_recovery(
                    async_session_factory,
                )

        assert len(captured_message_ids) == 1
        async with async_session_factory() as db:
            workflow = await db.get(WorkflowRun, workflow_id)
            stage = await db.get(StageRun, authority.stage_run_id)
            attempt = await db.get(StageAttempt, authority.stage_attempt_id)
            recovery_count = await db.scalar(
                select(func.count())
                .select_from(OutboxMessage)
                .where(
                    OutboxMessage.workflow_run_id == workflow_id,
                    OutboxMessage.emission_kind == "lease_recovered",
                )
            )
            captured_count = await db.scalar(
                select(func.count()).select_from(OutboxMessage).where(OutboxMessage.id.in_(captured_message_ids))
            )
            assert workflow is not None and workflow.status == "running"
            assert stage is not None and stage.status == "running"
            assert stage.state_version == authority.stage_state_version
            assert stage.lease_owner == authority.lease_owner
            assert stage.lease_token == authority.stage_lease_token
            assert stage.lease_expires_at == authority.lease_expires_at
            assert attempt is not None and attempt.status == "running"
            assert attempt.state_version == authority.attempt_state_version
            assert attempt.lease_owner == authority.lease_owner
            assert attempt.lease_token == authority.stage_lease_token
            assert attempt.lease_expires_at == authority.lease_expires_at
            assert attempt.error_code == attempt.error_class == attempt.error_summary == ""
            assert attempt.retryable is False
            assert attempt.completed_at is None
            assert recovery_count == captured_count == 0
    finally:
        await _cancel_if_active(workflow_id)


@pytest.mark.asyncio
async def test_exhausted_recovery_dead_letters_without_recovery_message():
    workflow_id = await _new_workflow("exhausted-recovery", max_attempts=1)
    authority = await _activate_root(workflow_id)
    await asyncio.sleep(1.2)

    async with _isolate_recovery_targets({workflow_id}):
        result = await workflow_worker.coordinate_one_expired_stage_recovery(
            async_session_factory,
        )
    assert result is not None
    assert result.workflow_run_id == workflow_id
    assert result.stage_run_id == authority.stage_run_id
    assert result.stage_attempt_id == authority.stage_attempt_id
    assert result.decision == "dead_lettered"
    assert result.stage_status == "dead_lettered"
    assert result.next_attempt_at is None
    assert result.retry_emission is None
    assert result.should_retry is False

    async with async_session_factory() as db:
        workflow = await db.get(WorkflowRun, workflow_id)
        stage = await db.get(StageRun, authority.stage_run_id)
        attempt = await db.get(StageAttempt, authority.stage_attempt_id)
        recovery_count = await db.scalar(
            select(func.count())
            .select_from(OutboxMessage)
            .where(
                OutboxMessage.workflow_run_id == workflow_id,
                OutboxMessage.emission_kind == "lease_recovered",
            )
        )
        assert workflow is not None and workflow.status == "dead_lettered"
        assert stage is not None and stage.status == "dead_lettered"
        assert stage.last_error_code == "workflow.lease_expired"
        assert stage.next_attempt_at is None
        assert attempt is not None and attempt.status == "abandoned"
        assert attempt.error_code == "workflow.lease_expired"
        assert attempt.retryable is True
        assert recovery_count == 0
