"""Real-PostgreSQL validation for the fenced workflow runtime.

Run only against a disposable, fully migrated database:

    RUN_POSTGRES_TESTS=1 python -m pytest -q \
      -o addopts='' --confcutdir=tests/postgres \
      tests/postgres/test_workflow_runtime.py

Authority rows intentionally remain in that database.  The production guards
reject physical deletion, so isolation is provided by unique project and
idempotency identities plus explicit terminal cleanup through the runtime.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import timedelta

import pytest
from sqlalchemy import event, func, select

from app.core.database import async_session_factory, engine
from app.models.research_workflow import (
    OutboxMessage,
    ProjectRevision,
    ResearchProject,
    StageAttempt,
    StageRun,
    WorkflowRun,
)
from app.services import outbox_runtime
from app.services import research_projects as projects
from app.services import workflow_runtime as runtime
from app.services import workflow_worker
from app.services.workflow_engine import deterministic_retry_backoff_seconds, normalize_stage_plan
from tests.postgres._workflow_authority import (
    cancel_active_workflow,
    cancellation_command,
)


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_POSTGRES_TESTS") != "1",
    reason="requires an explicitly authorized disposable PostgreSQL database",
)

ACTOR = projects.ResearchActor(
    name="PostgreSQL Workflow Runtime Test",
    actor_id="postgres-workflow-runtime-test",
)


@dataclass(frozen=True)
class _ClaimFacts:
    workflow_run_id: uuid.UUID
    stage_run_id: uuid.UUID
    attempt_id: uuid.UUID
    lease_token: uuid.UUID
    stage_version: int
    attempt_version: int
    checkpoint_version: int
    authority: outbox_runtime.ExecutableStageAuthority


class _AsyncBarrier:
    """Small bounded barrier that fails instead of hanging a concurrency test."""

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


def _spec(objective: str) -> dict:
    return {
        "objective": objective,
        "intelligence_requirements": ["Which report claims remain source-bound through deterministic workflow execution?"],
        "output_targets": ["canonical_intelligence"],
        "tlp": "TLP:AMBER",
    }


def _stage_definition(
    key: str,
    ordinal: int,
    *,
    depends_on: list[str] | None = None,
    required: bool = True,
    max_attempts: int = 3,
) -> dict:
    return {
        "stage_key": key,
        "stage_type": f"test.{key}",
        "stage_version": "1.0.0",
        "ordinal": ordinal,
        "depends_on": depends_on or [],
        "required": required,
        "priority": 0,
        "max_attempts": max_attempts,
        "config_schema_version": "research-stage-config-v1",
        "checkpoint_schema_version": "research-stage-checkpoint-v1",
        "config": {"test": True},
        "retry_policy": {
            "base_delay_seconds": 1,
            "max_delay_seconds": 1,
            "jitter_percent": 0,
        },
    }


def _single_stage_plan(*, max_attempts: int = 3) -> list[dict]:
    return [_stage_definition("collect", 1, max_attempts=max_attempts)]


async def _new_project(label: str) -> tuple[uuid.UUID, uuid.UUID]:
    async with async_session_factory() as db:
        project, revision = await projects.create_project(
            db,
            ACTOR,
            project_key=f"runtime-{label}-{uuid.uuid4().hex[:12]}",
            name=f"Workflow Runtime {label}",
            description="Disposable PostgreSQL fenced-runtime validation.",
            spec=_spec(f"Validate {label} with durable deterministic workflow authority."),
        )
        await db.commit()
        return project.id, revision.id


async def _new_workflow(
    revision_id: uuid.UUID,
    label: str,
    *,
    plan: list[dict] | None = None,
    idempotency_token: str | None = None,
    trigger_type: str = "api",
    replay_of_run_id: uuid.UUID | None = None,
) -> uuid.UUID:
    async with async_session_factory() as db:
        workflow, created = await runtime.create_workflow(
            db,
            ACTOR,
            project_revision_id=revision_id,
            workflow_type="cti.report",
            idempotency_token=idempotency_token or f"{label}-{uuid.uuid4().hex}",
            input_manifest={"report_id": label},
            stage_plan=plan or _single_stage_plan(),
            trigger_type=trigger_type,
            priority=0,
            replay_of_run_id=replay_of_run_id,
        )
        assert created is True
        await db.commit()
        return workflow.id


async def _claim_one(
    worker_id: str,
    *,
    workflow_run_id: uuid.UUID,
    lease_seconds: int = 30,
) -> _ClaimFacts | None:
    command = await _prepare_receipt_command(
        worker_id,
        workflow_run_id=workflow_run_id,
        lease_seconds=lease_seconds,
    )
    if command is None:
        return None
    return await _activate_receipt(command)


def _claim_facts(claimed: outbox_runtime.ExecutableStageAuthority) -> _ClaimFacts:
    return _ClaimFacts(
        workflow_run_id=claimed.workflow_run_id,
        stage_run_id=claimed.stage_run_id,
        attempt_id=claimed.stage_attempt_id,
        lease_token=claimed.stage_lease_token,
        stage_version=claimed.stage_state_version,
        attempt_version=claimed.attempt_state_version,
        checkpoint_version=claimed.checkpoint_version,
        authority=claimed,
    )


async def _next_claimable_stage(workflow_run_id: uuid.UUID) -> StageRun | None:
    async with async_session_factory() as db:
        return await db.scalar(
            select(StageRun)
            .where(
                StageRun.workflow_run_id == workflow_run_id,
                StageRun.status.in_(("ready", "retry_wait")),
                StageRun.next_attempt_at.is_not(None),
                StageRun.next_attempt_at <= func.transaction_timestamp(),
                StageRun.attempt_count < StageRun.max_attempts,
            )
            .order_by(
                StageRun.priority.desc(),
                StageRun.next_attempt_at.asc(),
                StageRun.ordinal.asc(),
                StageRun.id.asc(),
            )
            .limit(1)
        )


def _emission_kind(stage: StageRun) -> str:
    if stage.status == "ready":
        return "root_ready" if not stage.depends_on else "dependency_ready"
    assert stage.status == "retry_wait"
    return "lease_recovered" if stage.last_error_code == "workflow.lease_expired" else "retry_scheduled"


async def _next_stage_ready_message_id(workflow_run_id: uuid.UUID) -> uuid.UUID | None:
    """Return only stage-ready authority already appended by the runtime."""

    stage = await _next_claimable_stage(workflow_run_id)
    if stage is None:
        return None
    stage_id = uuid.UUID(str(stage.id))
    async with async_session_factory() as db:
        message = await db.scalar(
            select(OutboxMessage).where(
                OutboxMessage.workflow_run_id == workflow_run_id,
                OutboxMessage.stage_run_id == stage_id,
                OutboxMessage.aggregate_version == stage.state_version,
                OutboxMessage.emission_kind == _emission_kind(stage),
                OutboxMessage.target_attempt_number == stage.attempt_count + 1,
                OutboxMessage.redrive_ordinal == 0,
            )
        )
        if message is None:
            return None
        assert message.status in {"pending", "retry_wait"}
        assert message.input_checksum == stage.input_checksum
        return uuid.UUID(str(message.id))


def _broker_receipt_fingerprint(claim: outbox_runtime.ClaimedOutboxDelivery) -> str:
    return hashlib.sha256(f"postgres-workflow-receipt:{claim.cycle_key}".encode()).hexdigest()


async def _prepare_receipt_command(
    worker_id: str,
    *,
    workflow_run_id: uuid.UUID,
    lease_seconds: int = 30,
) -> outbox_runtime.StageReceiptCommand | None:
    message_id = await _next_stage_ready_message_id(workflow_run_id)
    if message_id is None:
        return None
    async with _isolate_outbox_queue({message_id}):
        async with async_session_factory() as db:
            claim = await outbox_runtime.claim_outbox_delivery(
                db,
                publisher_id=f"postgres-publisher-{worker_id}",
                lease_seconds=60,
            )
            assert claim is not None
            assert claim.message_id == message_id
            assert claim.envelope["payload"]["workflow_run_id"] == str(workflow_run_id)
            await db.commit()
    return outbox_runtime.StageReceiptCommand(
        claim=claim,
        broker_name="postgres_test_broker",
        broker_message_id=f"postgres-{claim.cycle_key}",
        broker_receipt_id=_broker_receipt_fingerprint(claim),
        worker_id=worker_id,
        lease_seconds=lease_seconds,
    )


async def _activate_receipt(command: outbox_runtime.StageReceiptCommand) -> _ClaimFacts | None:
    async with async_session_factory() as db:
        pending = await outbox_runtime.receipt_and_claim_stage(
            db,
            command=command,
        )
        await db.commit()
    if pending.disposition != "activated":
        assert pending.disposition == "replayed"
        assert pending.commit_ticket is None
        return None
    assert pending.commit_ticket is not None
    async with async_session_factory() as db:
        claimed = await outbox_runtime.confirm_committed_activation(
            db,
            commit_ticket=pending.commit_ticket,
        )
        await db.commit()
    assert claimed is not None
    return _claim_facts(claimed)


async def _cancel_if_active(workflow_run_id: uuid.UUID, *, reason: str) -> None:
    await cancel_active_workflow(
        async_session_factory,
        workflow_run_id=workflow_run_id,
        actor=ACTOR,
        reason=reason,
    )


@asynccontextmanager
async def _isolate_workflow_queue(allowed_workflow_ids: set[uuid.UUID]):
    """Lock foreign active workflows so a shared disposable DB cannot leak work.

    Authority guards forbid cleanup by deletion and other PostgreSQL test files
    intentionally leave rows behind.  Holding their workflow rows makes the
    runtime's SKIP LOCKED scan ignore them while preserving the real claim and
    recovery SQL exercised for the workflows under test.
    """

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


@asynccontextmanager
async def _isolate_outbox_queue(allowed_message_ids: set[uuid.UUID]):
    """Lock foreign due messages so the global publisher scan is deterministic."""

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


async def _claim_concurrently(
    worker_ids: list[str],
    *,
    workflow_run_ids: set[uuid.UUID],
) -> list[_ClaimFacts | None]:
    workflows = sorted(workflow_run_ids, key=str)
    if len(workflows) == 1:
        base = await _prepare_receipt_command(
            worker_ids[0],
            workflow_run_id=workflows[0],
        )
        assert base is not None
        commands = [
            outbox_runtime.StageReceiptCommand(
                claim=base.claim,
                broker_name=base.broker_name,
                broker_message_id=base.broker_message_id,
                broker_receipt_id=base.broker_receipt_id,
                worker_id=worker_id,
                lease_seconds=base.lease_seconds,
            )
            for worker_id in worker_ids
        ]
    else:
        assert len(workflows) == len(worker_ids)
        prepared = [
            await _prepare_receipt_command(
                worker_id,
                workflow_run_id=workflow_id,
            )
            for worker_id, workflow_id in zip(worker_ids, workflows, strict=True)
        ]
        assert all(command is not None for command in prepared)
        commands = [command for command in prepared if command is not None]
    start = _AsyncBarrier(len(worker_ids))

    async def claim(command: outbox_runtime.StageReceiptCommand) -> _ClaimFacts | None:
        await start.wait()
        return await _activate_receipt(command)

    return await asyncio.wait_for(
        asyncio.gather(*(claim(command) for command in commands)),
        timeout=20,
    )


@pytest.mark.asyncio
async def test_concurrent_identical_create_persists_one_content_bound_workflow():
    await engine.dispose()
    workflow_id: uuid.UUID | None = None
    try:
        _, revision_id = await _new_project("idempotent-create")
        token = f"identical-{uuid.uuid4().hex}"
        plan = _single_stage_plan()
        start = _AsyncBarrier(2)

        async def create() -> tuple[uuid.UUID, bool]:
            await start.wait()
            async with async_session_factory() as db:
                workflow, created = await runtime.create_workflow(
                    db,
                    ACTOR,
                    project_revision_id=revision_id,
                    workflow_type="cti.report",
                    idempotency_token=token,
                    input_manifest={"report_id": "same-report"},
                    stage_plan=plan,
                    priority=0,
                )
                await db.commit()
                return workflow.id, created

        results = await asyncio.wait_for(asyncio.gather(create(), create()), timeout=20)
        workflow_ids = {result[0] for result in results}
        assert len(workflow_ids) == 1
        assert sorted(result[1] for result in results) == [False, True]
        workflow_id = workflow_ids.pop()

        async with async_session_factory() as db:
            count = await db.scalar(
                select(func.count())
                .select_from(WorkflowRun)
                .where(
                    WorkflowRun.project_revision_id == revision_id,
                    WorkflowRun.workflow_type == "cti.report",
                )
            )
            stage_count = await db.scalar(select(func.count()).select_from(StageRun).where(StageRun.workflow_run_id == workflow_id))
            assert count == 1
            assert stage_count == 1
        await _cancel_if_active(workflow_id, reason="Concurrent create test completed.")
    finally:
        if workflow_id is not None:
            await _cancel_if_active(workflow_id, reason="Concurrent create cleanup.")
        await engine.dispose()


@pytest.mark.asyncio
async def test_two_claimers_for_same_stage_have_exactly_one_winner():
    await engine.dispose()
    workflow_id: uuid.UUID | None = None
    try:
        _, revision_id = await _new_project("single-winner")
        workflow_id = await _new_workflow(revision_id, "single-winner")

        claims = await _claim_concurrently(
            ["same-stage-a", "same-stage-b"],
            workflow_run_ids={workflow_id},
        )
        winners = [claim for claim in claims if claim is not None]
        assert len(winners) == 1
        assert winners[0].workflow_run_id == workflow_id

        async with async_session_factory() as db:
            running_attempts = await db.scalar(
                select(func.count())
                .select_from(StageAttempt)
                .where(
                    StageAttempt.stage_run_id == winners[0].stage_run_id,
                    StageAttempt.status == "running",
                )
            )
            stage = await db.get(StageRun, winners[0].stage_run_id)
            assert running_attempts == 1
            assert stage.status == "running"
            assert stage.attempt_count == 1
        await _cancel_if_active(workflow_id, reason="Single-winner claim test completed.")
    finally:
        if workflow_id is not None:
            await _cancel_if_active(workflow_id, reason="Single-winner cleanup.")
        await engine.dispose()


@pytest.mark.asyncio
async def test_parallel_claimers_can_claim_distinct_workflows_without_global_serialization():
    await engine.dispose()
    workflow_ids: list[uuid.UUID] = []
    try:
        _, revision_id = await _new_project("parallel-workflows")
        workflow_ids = [
            await _new_workflow(revision_id, "parallel-alpha"),
            await _new_workflow(revision_id, "parallel-bravo"),
        ]

        claims = await _claim_concurrently(
            ["parallel-a", "parallel-b"],
            workflow_run_ids=set(workflow_ids),
        )
        assert all(claim is not None for claim in claims)
        assert {claim.workflow_run_id for claim in claims if claim is not None} == set(workflow_ids)
        assert len({claim.lease_token for claim in claims if claim is not None}) == 2

        for workflow_id in workflow_ids:
            await _cancel_if_active(workflow_id, reason="Parallel claim test completed.")
    finally:
        for workflow_id in workflow_ids:
            await _cancel_if_active(workflow_id, reason="Parallel claim cleanup.")
        await engine.dispose()


@pytest.mark.asyncio
async def test_coordinated_heartbeat_checkpoint_fence_and_completion_survive_commit():
    await engine.dispose()
    workflow_id: uuid.UUID | None = None
    try:
        _, revision_id = await _new_project("live-mutations")
        workflow_id = await _new_workflow(revision_id, "live-mutations")
        claimed = await _claim_one("live-worker", workflow_run_id=workflow_id)
        assert claimed is not None
        assert claimed.workflow_run_id == workflow_id

        heartbeat = await workflow_worker.coordinate_stage_heartbeat(
            async_session_factory,
            authority=claimed.authority,
            lease_seconds=120,
        )
        assert heartbeat.disposition == "renewed"
        assert heartbeat.should_continue is True
        assert heartbeat.authority is not None
        assert heartbeat.heartbeat_at is not None
        heartbeat_stage_version = heartbeat.stage_state_version
        heartbeat_attempt_version = heartbeat.attempt_state_version

        statements: list[str] = []

        def capture(_connection, _cursor, statement, _parameters, _context, _many):
            statements.append(statement)

        event.listen(engine.sync_engine, "before_cursor_execute", capture)
        try:
            async with async_session_factory() as db:
                with pytest.raises(runtime.WorkflowConflict, match="Direct stage checkpoints are disabled"):
                    await runtime.checkpoint_stage(
                        db,
                        claimed.stage_run_id,
                        lease_token=claimed.lease_token,
                        expected_stage_version=heartbeat_stage_version,
                        expected_attempt_version=heartbeat_attempt_version,
                        expected_checkpoint_version=0,
                        checkpoint_schema_version="research-stage-checkpoint-v1",
                        checkpoint={"page": 3, "source_cursor": "cursor-3"},
                        lease_seconds=120,
                    )
        finally:
            event.remove(engine.sync_engine, "before_cursor_execute", capture)
        assert statements == []

        completed = await workflow_worker.coordinate_stage_complete(
            async_session_factory,
            authority=heartbeat.authority,
            output_manifest={"claims": 7, "review_ready": True},
        )
        assert completed.disposition == "completed"
        assert completed.should_continue is False
        assert completed.should_ack is True

        async with async_session_factory() as db:
            stage = await db.get(StageRun, claimed.stage_run_id)
            attempt = await db.get(StageAttempt, claimed.attempt_id)
            workflow = await db.get(WorkflowRun, workflow_id)
            assert stage.output_checksum == attempt.output_checksum
            assert attempt.checkpoint_end_version == stage.checkpoint_version == 0
            assert workflow.status == "succeeded"
    finally:
        if workflow_id is not None:
            await _cancel_if_active(workflow_id, reason="Live mutation cleanup.")
        await engine.dispose()


@pytest.mark.asyncio
async def test_expired_attempt_is_recovered_and_old_token_is_fenced_after_reclaim():
    await engine.dispose()
    workflow_id: uuid.UUID | None = None
    try:
        _, revision_id = await _new_project("lease-recovery")
        workflow_id = await _new_workflow(revision_id, "lease-recovery")
        old_claim = await _claim_one(
            "expired-worker",
            workflow_run_id=workflow_id,
            lease_seconds=1,
        )
        assert old_claim is not None
        assert old_claim.workflow_run_id == workflow_id

        await asyncio.sleep(1.2)
        async with _isolate_workflow_queue({workflow_id}):
            recovered = await workflow_worker.coordinate_one_expired_stage_recovery(
                async_session_factory,
            )
            assert recovered is not None
            assert recovered.stage_run_id == old_claim.stage_run_id

        await asyncio.sleep(1.2)
        reclaimed = await _claim_one("replacement-worker", workflow_run_id=workflow_id)
        assert reclaimed is not None
        assert reclaimed.workflow_run_id == workflow_id
        assert reclaimed.stage_run_id == old_claim.stage_run_id
        assert reclaimed.lease_token != old_claim.lease_token

        stale_heartbeat = await workflow_worker.coordinate_stage_heartbeat(
            async_session_factory,
            authority=old_claim.authority,
            lease_seconds=120,
        )
        assert stale_heartbeat.disposition == "stale"
        assert stale_heartbeat.should_continue is False
        assert stale_heartbeat.authority is None

        async with async_session_factory() as db:
            attempts = list(
                (
                    await db.execute(
                        select(StageAttempt)
                        .where(StageAttempt.stage_run_id == old_claim.stage_run_id)
                        .order_by(StageAttempt.attempt_number.asc())
                    )
                )
                .scalars()
                .all()
            )
            assert [attempt.status for attempt in attempts] == ["abandoned", "running"]
            assert [attempt.attempt_number for attempt in attempts] == [1, 2]
        await _cancel_if_active(workflow_id, reason="Lease recovery test completed.")
    finally:
        if workflow_id is not None:
            await _cancel_if_active(workflow_id, reason="Lease recovery cleanup.")
        await engine.dispose()


@pytest.mark.asyncio
async def test_retry_exhaustion_dead_letters_stage_and_required_workflow():
    await engine.dispose()
    workflow_id: uuid.UUID | None = None
    try:
        _, revision_id = await _new_project("retry-exhaustion")
        workflow_id = await _new_workflow(
            revision_id,
            "retry-exhaustion",
            plan=_single_stage_plan(max_attempts=2),
        )
        first = await _claim_one("retry-worker-1", workflow_run_id=workflow_id)
        assert first is not None
        assert first.workflow_run_id == workflow_id

        failed = await workflow_worker.coordinate_stage_fail(
            async_session_factory,
            authority=first.authority,
            error_text="Transient source timeout",
            error_code="source.timeout",
            retryable=True,
        )
        assert failed.disposition == "recorded"
        assert failed.decision == "retry"
        assert failed.should_retry is True

        async with async_session_factory() as db:
            workflow = await db.get(WorkflowRun, workflow_id)
            stage = await db.get(StageRun, first.stage_run_id)
            failed_attempt = await db.get(StageAttempt, first.attempt_id)
            retry_message = await db.scalar(
                select(OutboxMessage).where(
                    OutboxMessage.workflow_run_id == workflow_id,
                    OutboxMessage.stage_run_id == first.stage_run_id,
                    OutboxMessage.emission_kind == "retry_scheduled",
                    OutboxMessage.redrive_ordinal == 0,
                )
            )
            assert workflow is not None
            assert stage is not None
            assert failed_attempt is not None
            assert retry_message is not None
            normalized = normalize_stage_plan(workflow.stage_plan)
            definition = next(item for item in normalized.stages if item.stage_key == stage.stage_key)
            delay = deterministic_retry_backoff_seconds(
                failed_attempt.attempt_number,
                seed=str(stage.id),
                policy=definition.retry_policy,
            )
            assert failed_attempt.status == "failed"
            assert failed_attempt.retryable is True
            assert retry_message.causation_id == failed_attempt.id == first.attempt_id
            assert retry_message.aggregate_version == stage.state_version
            assert retry_message.target_attempt_number == stage.attempt_count + 1 == 2
            assert retry_message.available_at == stage.next_attempt_at
            assert retry_message.available_at == failed_attempt.completed_at + timedelta(seconds=delay)

        await asyncio.sleep(1.2)
        second = await _claim_one("retry-worker-2", workflow_run_id=workflow_id)
        assert second is not None
        assert second.workflow_run_id == workflow_id
        assert second.stage_run_id == first.stage_run_id

        exhausted = await workflow_worker.coordinate_stage_fail(
            async_session_factory,
            authority=second.authority,
            error_text="Source remained unavailable",
            error_code="source.timeout",
            retryable=True,
        )
        assert exhausted.disposition == "recorded"
        assert exhausted.decision == "dead_lettered"
        assert exhausted.workflow_status == "dead_lettered"

        async with async_session_factory() as db:
            stage = await db.get(StageRun, first.stage_run_id)
            workflow = await db.get(WorkflowRun, workflow_id)
            attempts = list(
                (
                    await db.execute(
                        select(StageAttempt).where(StageAttempt.stage_run_id == stage.id).order_by(StageAttempt.attempt_number.asc())
                    )
                )
                .scalars()
                .all()
            )
            assert stage.status == "dead_lettered"
            assert stage.attempt_count == stage.max_attempts == 2
            assert workflow.status == "dead_lettered"
            assert workflow.status_reason_code == "workflow.required_stage_dead_lettered"
            assert [attempt.status for attempt in attempts] == ["failed", "failed"]
    finally:
        if workflow_id is not None:
            await _cancel_if_active(workflow_id, reason="Retry exhaustion cleanup.")
        await engine.dispose()


@pytest.mark.asyncio
async def test_cancellation_fences_running_attempt_and_cancels_unstarted_stages():
    await engine.dispose()
    workflow_id: uuid.UUID | None = None
    try:
        _, revision_id = await _new_project("cancellation")
        plan = [
            _stage_definition("collect", 1),
            _stage_definition("review", 2),
        ]
        workflow_id = await _new_workflow(revision_id, "cancellation", plan=plan)
        claimed = await _claim_one("cancelled-worker", workflow_run_id=workflow_id)
        assert claimed is not None
        assert claimed.workflow_run_id == workflow_id

        async with async_session_factory() as db:
            workflow = await db.get(WorkflowRun, workflow_id)
            assert workflow is not None
            command = cancellation_command(
                workflow_run_id=workflow.id,
                expected_workflow_state_version=workflow.state_version,
                actor=ACTOR,
                reason="Analyst revoked the report source during review.",
            )
        cancelled = await workflow_worker.coordinate_workflow_cancel(
            async_session_factory,
            command=command,
        )
        assert cancelled.disposition == "applied"
        assert cancelled.should_apply is True
        assert cancelled.workflow_run_id == workflow_id
        assert cancelled.actor_id == ACTOR.actor_id
        assert cancelled.cancelled_attempt_ids == (claimed.attempt_id,)

        async with async_session_factory() as db:
            stages = list(
                (await db.execute(select(StageRun).where(StageRun.workflow_run_id == workflow_id).order_by(StageRun.ordinal.asc())))
                .scalars()
                .all()
            )
            attempt = await db.get(StageAttempt, claimed.attempt_id)
            workflow = await db.get(WorkflowRun, workflow_id)
            assert [stage.status for stage in stages] == ["cancelled", "cancelled"]
            assert all(stage.next_attempt_at is None for stage in stages)
            assert attempt.status == "cancelled"
            assert workflow.status == "cancelled"
            assert workflow.cancel_requested_by_id == ACTOR.actor_id
            assert workflow.cancel_reason == "Analyst revoked the report source during review."
    finally:
        if workflow_id is not None:
            await _cancel_if_active(workflow_id, reason="Cancellation cleanup.")
        await engine.dispose()


@pytest.mark.asyncio
async def test_replay_can_target_newer_current_revision_of_same_project():
    await engine.dispose()
    origin_id: uuid.UUID | None = None
    replay_id: uuid.UUID | None = None
    try:
        project_id, revision_one_id = await _new_project("newer-revision-replay")
        plan = _single_stage_plan()
        origin_id = await _new_workflow(
            revision_one_id,
            "replay-report",
            plan=plan,
        )
        claimed = await _claim_one("replay-origin-worker", workflow_run_id=origin_id)
        assert claimed is not None
        assert claimed.workflow_run_id == origin_id
        completed = await workflow_worker.coordinate_stage_complete(
            async_session_factory,
            authority=claimed.authority,
            output_manifest={"origin": "complete"},
        )
        assert completed.disposition == "completed"
        assert completed.should_ack is True

        async with async_session_factory() as db:
            project = await db.get(ResearchProject, project_id)
            _, revision_two = await projects.create_revision(
                db,
                project.id,
                ACTOR,
                expected_version=project.version,
                spec=_spec("Validate a replay against the newer current project revision."),
                change_summary="Create a newer target revision for workflow replay.",
            )
            await db.commit()
            revision_two_id = revision_two.id

        replay_id = await _new_workflow(
            revision_two_id,
            "replay-report",
            plan=plan,
            trigger_type="replay",
            replay_of_run_id=origin_id,
        )
        async with async_session_factory() as db:
            replay = await db.get(WorkflowRun, replay_id)
            origin = await db.get(WorkflowRun, origin_id)
            revision_one = await db.get(ProjectRevision, revision_one_id)
            revision_two = await db.get(ProjectRevision, revision_two_id)
            assert replay.replay_of_run_id == origin.id
            assert replay.project_revision_id == revision_two.id
            assert origin.project_revision_id == revision_one.id
            assert revision_one.status == "superseded"
            assert revision_two.status == "current"
        await _cancel_if_active(replay_id, reason="Newer-revision replay test completed.")
    finally:
        if replay_id is not None:
            await _cancel_if_active(replay_id, reason="Newer-revision replay cleanup.")
        if origin_id is not None:
            await _cancel_if_active(origin_id, reason="Replay origin cleanup.")
        await engine.dispose()
