"""PostgreSQL acceptance for native retry-scheduled workflow emission.

Run only against a disposable database migrated through revision 0004::

    RUN_POSTGRES_TESTS=1 python -m pytest -q -o addopts='' \
      --confcutdir=tests/postgres \
      tests/postgres/test_workflow_retry_emission.py

Execution authority is obtained only through workflow creation, the real
outbox publisher claim, and the real receipt coordinator.  Tests never call a
stage-ready emitter; ``workflow_worker.coordinate_stage_fail`` must append retries.
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
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.database import async_session_factory, engine
from app.models.research_workflow import (
    OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1,
    OUTBOX_TOPIC_WORKFLOW_STAGE_READY,
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
    name="PostgreSQL Workflow Retry Emission Test",
    actor_id="postgres-workflow-retry-emission",
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


class _InjectedRetryFailure(RuntimeError):
    """Test-only failure after the retry root reaches PostgreSQL."""


class _FailAfterRetryMessageSession(AsyncSession):
    async def flush(self, objects=None):
        await super().flush(objects)
        if objects and any(type(value) is OutboxMessage and value.emission_kind == "retry_scheduled" for value in objects):
            raise _InjectedRetryFailure("rollback after retry message flush")


@pytest_asyncio.fixture(autouse=True)
async def _dispose_engine_pool_between_tests():
    await engine.dispose()
    try:
        yield
    finally:
        await engine.dispose()


def _spec(label: str) -> dict:
    return {
        "objective": f"Validate native retry-scheduled workflow emission: {label}.",
        "intelligence_requirements": [
            "Does exact failed-attempt evidence atomically authorize a deterministic retry?",
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
            "base_delay_seconds": 11,
            "max_delay_seconds": 90,
            "jitter_percent": 20,
        },
    }


async def _new_workflow(label: str, *, max_attempts: int = 3) -> uuid.UUID:
    project_label = label.replace("_", "-")
    async with async_session_factory() as db:
        _, revision = await projects.create_project(
            db,
            ACTOR,
            project_key=f"retry-emission-{project_label}-{uuid.uuid4().hex[:12]}",
            name=f"Retry emission {label}",
            description="Disposable PostgreSQL native retry-emission acceptance authority.",
            spec=_spec(label),
        )
        workflow, created = await runtime.create_workflow(
            db,
            ACTOR,
            project_revision_id=revision.id,
            workflow_type="cti.report",
            idempotency_token=f"retry-{label}-{uuid.uuid4().hex}",
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


def _broker_receipt_id(cycle_key: str) -> str:
    return hashlib.sha256(f"retry-emission-receipt:{cycle_key}".encode()).hexdigest()


async def _activate_root(workflow_id: uuid.UUID) -> outbox_runtime.ExecutableStageAuthority:
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

    async with _isolate_outbox_queue({message_id}):
        async with async_session_factory() as db:
            claim = await outbox_runtime.claim_outbox_delivery(
                db,
                publisher_id="retry-emission-publisher",
                lease_seconds=120,
            )
            assert claim is not None
            assert claim.message_id == message_id
            await db.commit()

    command = outbox_runtime.StageReceiptCommand(
        claim=claim,
        broker_name="postgres_test_broker",
        broker_message_id=f"retry-emission-{claim.cycle_key}",
        broker_receipt_id=_broker_receipt_id(claim.cycle_key),
        worker_id="retry-emission-worker",
        lease_seconds=120,
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


async def _fail(
    authority: outbox_runtime.ExecutableStageAuthority,
    *,
    retryable: bool = True,
    error_code: str = "source.timeout",
):
    return await workflow_worker.coordinate_stage_fail(
        async_session_factory,
        authority=authority,
        error_text="Provider timed out while fetching the source report",
        error_code=error_code,
        retryable=retryable,
        error_class="TimeoutError",
    )


async def _cancel_if_active(workflow_id: uuid.UUID) -> None:
    await cancel_active_workflow(
        async_session_factory,
        workflow_run_id=workflow_id,
        actor=ACTOR,
        reason="Retry-emission acceptance cleanup.",
    )


def _expected_retry_envelope(workflow: WorkflowRun, stage: StageRun):
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


def _assert_exact_retry_message(
    message: OutboxMessage,
    *,
    workflow: WorkflowRun,
    stage: StageRun,
    cause: StageAttempt,
) -> None:
    expected = _expected_retry_envelope(workflow, stage)
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
    assert message.emission_kind == "retry_scheduled"
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


@pytest.mark.asyncio
async def test_retryable_failure_atomically_emits_exact_deterministic_retry():
    workflow_id = await _new_workflow("exact-retry")
    try:
        authority = await _activate_root(workflow_id)

        recorded = await workflow_worker.coordinate_stage_fail(
            async_session_factory,
            authority=authority,
            error_text="Provider timed out while fetching the source report",
            error_code="source.timeout",
            retryable=True,
            error_class="TimeoutError",
        )
        assert recorded.disposition == "recorded"
        assert recorded.decision == "retry"
        assert recorded.retry_emission is not None
        cause_id = recorded.stage_attempt_id

        async with async_session_factory() as db:
            workflow = await db.get(WorkflowRun, workflow_id)
            stage = await db.get(StageRun, authority.stage_run_id)
            cause = await db.get(StageAttempt, cause_id)
            messages = tuple(
                (
                    await db.scalars(
                        select(OutboxMessage).where(
                            OutboxMessage.workflow_run_id == workflow_id,
                            OutboxMessage.emission_kind == "retry_scheduled",
                        )
                    )
                ).all()
            )
            assert workflow is not None and workflow.status == "running"
            assert stage is not None and stage.status == "retry_wait"
            assert stage.last_error_code == "source.timeout"
            assert stage.last_error_retryable is True
            assert stage.lease_token is None
            assert cause is not None and cause.status == "failed"
            assert cause.retryable is True
            assert cause.error_code == stage.last_error_code
            assert cause.error_summary == stage.last_error_summary
            assert cause.error_class == "TimeoutError"
            assert cause.output_checksum == ""
            assert cause.heartbeat_at == cause.completed_at
            assert len(messages) == 1
            _assert_exact_retry_message(messages[0], workflow=workflow, stage=stage, cause=cause)
    finally:
        await _cancel_if_active(workflow_id)


@pytest.mark.asyncio
async def test_late_failure_after_retry_message_flush_rolls_back_live_stage_attempt_and_message():
    workflow_id = await _new_workflow("late-rollback")
    try:
        authority = await _activate_root(workflow_id)
        maker = async_sessionmaker(
            engine,
            class_=_FailAfterRetryMessageSession,
            expire_on_commit=False,
        )
        with pytest.raises(_InjectedRetryFailure):
            await workflow_worker.coordinate_stage_fail(
                maker,
                authority=authority,
                error_text="Provider timed out",
                error_code="source.timeout",
                retryable=True,
                error_class="TimeoutError",
            )
        async with async_session_factory() as db:
            workflow = await db.get(WorkflowRun, workflow_id)
            stage = await db.get(StageRun, authority.stage_run_id)
            attempt = await db.get(StageAttempt, authority.stage_attempt_id)
            retry_count = await db.scalar(
                select(func.count())
                .select_from(OutboxMessage)
                .where(
                    OutboxMessage.workflow_run_id == workflow_id,
                    OutboxMessage.emission_kind == "retry_scheduled",
                )
            )
            assert workflow is not None and workflow.status == "running"
            assert stage is not None and stage.status == "running"
            assert stage.state_version == authority.stage_state_version
            assert stage.lease_token == authority.stage_lease_token
            assert attempt is not None and attempt.status == "running"
            assert attempt.state_version == authority.attempt_state_version
            assert attempt.completed_at is None
            assert retry_count == 0
    finally:
        await _cancel_if_active(workflow_id)


@pytest.mark.asyncio
async def test_committed_retry_fences_idempotent_stale_failure_without_duplicate_message():
    workflow_id = await _new_workflow("stale-replay")
    try:
        authority = await _activate_root(workflow_id)
        await _fail(authority)

        stale = await workflow_worker.coordinate_stage_fail(
            async_session_factory,
            authority=authority,
            error_text="Repeated stale failure",
            error_code="source.timeout",
            retryable=True,
            error_class="TimeoutError",
        )
        assert stale.disposition == "stale"
        assert stale.should_retry is False
        assert stale.retry_emission is None

        async with async_session_factory() as db:
            stage = await db.get(StageRun, authority.stage_run_id)
            count = await db.scalar(
                select(func.count())
                .select_from(OutboxMessage)
                .where(
                    OutboxMessage.workflow_run_id == workflow_id,
                    OutboxMessage.emission_kind == "retry_scheduled",
                )
            )
            assert stage is not None and stage.status == "retry_wait"
            assert stage.state_version == authority.stage_state_version + 1
            assert count == 1
    finally:
        await _cancel_if_active(workflow_id)


@pytest.mark.asyncio
async def test_concurrent_failures_have_one_winner_and_one_retry_message():
    workflow_id = await _new_workflow("concurrent-failure")
    try:
        authority = await _activate_root(workflow_id)
        start = _AsyncBarrier(2)

        async def fail_after_barrier(label: str) -> str:
            await start.wait()
            result = await workflow_worker.coordinate_stage_fail(
                async_session_factory,
                authority=authority,
                error_text=f"Concurrent provider timeout {label}",
                error_code="source.timeout",
                retryable=True,
                error_class="TimeoutError",
            )
            return result.disposition

        results = await asyncio.wait_for(
            asyncio.gather(fail_after_barrier("alpha"), fail_after_barrier("bravo")),
            timeout=20,
        )
        assert sorted(results) == ["recorded", "stale"]

        async with async_session_factory() as db:
            stage = await db.get(StageRun, authority.stage_run_id)
            attempts = tuple(
                (
                    await db.scalars(
                        select(StageAttempt)
                        .where(StageAttempt.stage_run_id == authority.stage_run_id)
                        .order_by(StageAttempt.attempt_number.asc())
                    )
                ).all()
            )
            messages = tuple(
                (
                    await db.scalars(
                        select(OutboxMessage).where(
                            OutboxMessage.workflow_run_id == workflow_id,
                            OutboxMessage.emission_kind == "retry_scheduled",
                        )
                    )
                ).all()
            )
            assert stage is not None and stage.status == "retry_wait"
            assert len(attempts) == 1 and attempts[0].status == "failed"
            assert len(messages) == 1
            assert messages[0].causation_id == attempts[0].id
    finally:
        await _cancel_if_active(workflow_id)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("max_attempts", "retryable", "expected_stage", "expected_workflow"),
    [
        (3, False, "failed", "failed"),
        (1, True, "dead_lettered", "dead_lettered"),
    ],
)
async def test_nonretryable_and_exhausted_failures_emit_no_retry(
    max_attempts: int,
    retryable: bool,
    expected_stage: str,
    expected_workflow: str,
):
    workflow_id = await _new_workflow(
        f"terminal-{expected_stage}",
        max_attempts=max_attempts,
    )
    authority = await _activate_root(workflow_id)
    recorded = await _fail(authority, retryable=retryable)
    assert recorded.disposition == "recorded"
    assert recorded.decision == expected_stage
    assert recorded.workflow_status == expected_workflow

    async with async_session_factory() as db:
        stage = await db.get(StageRun, authority.stage_run_id)
        attempt = await db.get(StageAttempt, authority.stage_attempt_id)
        retry_count = await db.scalar(
            select(func.count())
            .select_from(OutboxMessage)
            .where(
                OutboxMessage.workflow_run_id == workflow_id,
                OutboxMessage.emission_kind == "retry_scheduled",
            )
        )
        assert stage is not None and stage.status == expected_stage
        assert attempt is not None and attempt.status == "failed"
        assert attempt.retryable is retryable
        assert retry_count == 0


@pytest.mark.asyncio
async def test_fail_stage_rejects_reserved_lease_expired_code_before_mutation_or_message():
    workflow_id = await _new_workflow("reserved-lease-expired")
    try:
        authority = await _activate_root(workflow_id)
        with pytest.raises(
            runtime.WorkflowValidation,
            match="Stage failure evidence is invalid",
        ):
            await workflow_worker.coordinate_stage_fail(
                async_session_factory,
                authority=authority,
                error_text="Caller cannot claim lease recovery",
                error_code="workflow.lease_expired",
                retryable=True,
                error_class="TimeoutError",
            )

        async with async_session_factory() as db:
            stage = await db.get(StageRun, authority.stage_run_id)
            attempt = await db.get(StageAttempt, authority.stage_attempt_id)
            retry_count = await db.scalar(
                select(func.count())
                .select_from(OutboxMessage)
                .where(
                    OutboxMessage.workflow_run_id == workflow_id,
                    OutboxMessage.emission_kind == "retry_scheduled",
                )
            )
            assert stage is not None and stage.status == "running"
            assert stage.state_version == authority.stage_state_version
            assert stage.lease_token == authority.stage_lease_token
            assert attempt is not None and attempt.status == "running"
            assert attempt.state_version == authority.attempt_state_version
            assert retry_count == 0
    finally:
        await _cancel_if_active(workflow_id)
