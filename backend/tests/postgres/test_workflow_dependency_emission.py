"""PostgreSQL acceptance for native dependency-ready workflow emission.

Run only against a disposable database migrated through revision 0004::

    RUN_POSTGRES_TESTS=1 python -m pytest -q -o addopts='' \
      --confcutdir=tests/postgres \
      tests/postgres/test_workflow_dependency_emission.py

Root stages enter running state only through the real outbox claim and receipt
coordinator.  Tests never call the public stage-ready emitter for a dependent;
The commit-confirmed worker completion coordinator must create that authority
itself.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import uuid
from contextlib import asynccontextmanager

import pytest
import pytest_asyncio
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError

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
from app.services.workflow_engine import checksum_json
from tests.postgres._workflow_authority import cancel_active_workflow


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_POSTGRES_TESTS") != "1",
    reason="requires an explicitly authorized disposable PostgreSQL database",
)

ACTOR = projects.ResearchActor(
    name="PostgreSQL Workflow Dependency Emission Test",
    actor_id="postgres-workflow-dependency-emission",
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
        "objective": f"Validate native dependency-ready workflow emission: {label}.",
        "intelligence_requirements": [
            "Does terminal attempt evidence atomically authorize every newly ready dependent?",
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


async def _new_workflow(label: str, stage_plan: list[dict]) -> uuid.UUID:
    async with async_session_factory() as db:
        _, revision = await projects.create_project(
            db,
            ACTOR,
            project_key=f"dependency-emission-{label}-{uuid.uuid4().hex[:12]}",
            name=f"Dependency emission {label}",
            description="Disposable PostgreSQL native dependency-emission acceptance authority.",
            spec=_spec(label),
        )
        workflow, created = await runtime.create_workflow(
            db,
            ACTOR,
            project_revision_id=revision.id,
            workflow_type="cti.report",
            idempotency_token=f"dependency-{label}-{uuid.uuid4().hex}",
            input_manifest={"report_id": label, "source_ids": ["source-a", "source-b"]},
            stage_plan=stage_plan,
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
    return hashlib.sha256(f"dependency-emission-receipt:{cycle_key}".encode()).hexdigest()


async def _activate_root(workflow_id: uuid.UUID, stage_key: str) -> outbox_runtime.ExecutableStageAuthority:
    async with async_session_factory() as db:
        message_id = await db.scalar(
            select(OutboxMessage.id).where(
                OutboxMessage.workflow_run_id == workflow_id,
                OutboxMessage.stage_key == stage_key,
                OutboxMessage.emission_kind == "root_ready",
                OutboxMessage.redrive_ordinal == 0,
            )
        )
    assert isinstance(message_id, uuid.UUID)

    async with _isolate_outbox_queue({message_id}):
        async with async_session_factory() as db:
            claim = await outbox_runtime.claim_outbox_delivery(
                db,
                publisher_id=f"dependency-emission-publisher-{stage_key}",
                lease_seconds=120,
            )
            assert claim is not None
            assert claim.message_id == message_id
            await db.commit()

    command = outbox_runtime.StageReceiptCommand(
        claim=claim,
        broker_name="postgres_test_broker",
        broker_message_id=f"dependency-emission-{claim.cycle_key}",
        broker_receipt_id=_broker_receipt_id(claim.cycle_key),
        worker_id=f"dependency-emission-worker-{stage_key}",
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


async def _complete(
    authority: outbox_runtime.ExecutableStageAuthority,
    *,
    output_manifest: dict,
):
    completion = await workflow_worker.coordinate_stage_complete(
        async_session_factory,
        authority=authority,
        output_manifest=output_manifest,
    )
    assert completion.disposition == "completed"
    assert completion.should_continue is False
    assert completion.should_ack is True
    return completion


async def _cancel_if_active(workflow_id: uuid.UUID) -> None:
    await cancel_active_workflow(
        async_session_factory,
        workflow_run_id=workflow_id,
        actor=ACTOR,
        reason="Dependency-emission acceptance cleanup.",
    )


def _expected_envelope(workflow: WorkflowRun, target: StageRun):
    return normalize_outbox_envelope(
        {
            "topic": OUTBOX_TOPIC_WORKFLOW_STAGE_READY,
            "schema_version": OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1,
            "payload": {
                "workflow_run_id": str(workflow.id),
                "stage_run_id": str(target.id),
                "stage_key": target.stage_key,
                "target_attempt_number": 1,
                "input_checksum": target.input_checksum,
                "plan_checksum": workflow.plan_checksum,
            },
        }
    )


def _assert_exact_dependency_message(
    message: OutboxMessage,
    *,
    workflow: WorkflowRun,
    target: StageRun,
    cause: StageAttempt,
) -> None:
    expected = _expected_envelope(workflow, target)
    assert message.workflow_run_id == workflow.id
    assert message.stage_run_id == target.id
    assert message.aggregate_type == "workflow_stage"
    assert message.aggregate_id == target.id
    assert message.aggregate_version == target.state_version == 2
    assert message.emission_kind == "dependency_ready"
    assert message.topic == OUTBOX_TOPIC_WORKFLOW_STAGE_READY
    assert message.schema_version == OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1
    assert message.correlation_id == workflow.correlation_id
    assert message.causation_id == cause.id
    assert message.stage_key == target.stage_key
    assert message.target_attempt_number == target.attempt_count + 1 == 1
    assert message.input_checksum == target.input_checksum == checksum_json(target.input_manifest)
    assert message.plan_checksum == workflow.plan_checksum
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
    assert message.available_at == target.next_attempt_at == cause.completed_at
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
async def test_one_completion_atomically_emits_exact_multi_target_dependency_fanout():
    workflow_id = await _new_workflow(
        "multi-target",
        [
            _stage_definition("collect", 1),
            _stage_definition("extract", 2, depends_on=["collect"]),
            _stage_definition("enrich", 3, depends_on=["collect"]),
        ],
    )
    try:
        authority = await _activate_root(workflow_id, "collect")
        completion = await _complete(
            authority,
            output_manifest={"sources": 4, "source_bound": True},
        )
        assert completion.disposition == "completed"
        cause_id = authority.stage_attempt_id

        async with async_session_factory() as db:
            workflow = await db.get(WorkflowRun, workflow_id)
            cause = await db.get(StageAttempt, cause_id)
            assert workflow is not None
            assert cause is not None
            assert cause.status == "succeeded"
            assert cause.stage_run_id == authority.stage_run_id
            targets = tuple(
                (
                    await db.scalars(
                        select(StageRun)
                        .where(
                            StageRun.workflow_run_id == workflow_id,
                            StageRun.stage_key.in_(("extract", "enrich")),
                        )
                        .order_by(StageRun.stage_key.asc())
                    )
                ).all()
            )
            messages = tuple(
                (
                    await db.scalars(
                        select(OutboxMessage)
                        .where(
                            OutboxMessage.workflow_run_id == workflow_id,
                            OutboxMessage.emission_kind == "dependency_ready",
                        )
                        .order_by(OutboxMessage.stage_key.asc())
                    )
                ).all()
            )
            assert len(targets) == len(messages) == 2
            assert {message.causation_id for message in messages} == {cause.id}
            assert len({message.logical_key for message in messages}) == 2
            for target, message in zip(targets, messages, strict=True):
                assert target.status == "ready"
                assert target.next_attempt_at is not None
                _assert_exact_dependency_message(message, workflow=workflow, target=target, cause=cause)
    finally:
        await _cancel_if_active(workflow_id)


@pytest.mark.asyncio
async def test_multi_prerequisite_emits_none_for_first_and_exactly_one_for_last_completion():
    workflow_id = await _new_workflow(
        "last-prerequisite",
        [
            _stage_definition("collect", 1),
            _stage_definition("enrich", 2),
            _stage_definition("review", 3, depends_on=["collect", "enrich"]),
        ],
    )
    try:
        collect = await _activate_root(workflow_id, "collect")
        enrich = await _activate_root(workflow_id, "enrich")

        await _complete(collect, output_manifest={"claims": 3})
        async with async_session_factory() as db:
            review = await db.scalar(
                select(StageRun).where(
                    StageRun.workflow_run_id == workflow_id,
                    StageRun.stage_key == "review",
                )
            )
            count = await db.scalar(
                select(func.count())
                .select_from(OutboxMessage)
                .where(
                    OutboxMessage.workflow_run_id == workflow_id,
                    OutboxMessage.emission_kind == "dependency_ready",
                )
            )
            assert review is not None and review.status == "pending"
            assert review.state_version == 1
            assert review.next_attempt_at is None
            assert count == 0

        await _complete(enrich, output_manifest={"entities": 5})
        async with async_session_factory() as db:
            workflow = await db.get(WorkflowRun, workflow_id)
            review = await db.scalar(
                select(StageRun).where(
                    StageRun.workflow_run_id == workflow_id,
                    StageRun.stage_key == "review",
                )
            )
            cause = await db.get(StageAttempt, enrich.stage_attempt_id)
            messages = tuple(
                (
                    await db.scalars(
                        select(OutboxMessage).where(
                            OutboxMessage.workflow_run_id == workflow_id,
                            OutboxMessage.emission_kind == "dependency_ready",
                        )
                    )
                ).all()
            )
            assert workflow is not None
            assert review is not None
            assert cause is not None
            assert len(messages) == 1
            _assert_exact_dependency_message(messages[0], workflow=workflow, target=review, cause=cause)
    finally:
        await _cancel_if_active(workflow_id)


@pytest.mark.asyncio
async def test_concurrent_last_prerequisite_completions_serialize_to_one_emission():
    workflow_id = await _new_workflow(
        "concurrent-prerequisites",
        [
            _stage_definition("collect", 1),
            _stage_definition("enrich", 2),
            _stage_definition("review", 3, depends_on=["collect", "enrich"]),
        ],
    )
    try:
        collect = await _activate_root(workflow_id, "collect")
        enrich = await _activate_root(workflow_id, "enrich")
        start = _AsyncBarrier(2)

        async def complete_after_barrier(authority, output_manifest: dict) -> uuid.UUID:
            await start.wait()
            await _complete(authority, output_manifest=output_manifest)
            return authority.stage_attempt_id

        completed_attempt_ids = set(
            await asyncio.wait_for(
                asyncio.gather(
                    complete_after_barrier(collect, {"claims": 3}),
                    complete_after_barrier(enrich, {"entities": 5}),
                ),
                timeout=20,
            )
        )
        assert completed_attempt_ids == {collect.stage_attempt_id, enrich.stage_attempt_id}

        async with async_session_factory() as db:
            workflow = await db.get(WorkflowRun, workflow_id)
            review = await db.scalar(
                select(StageRun).where(
                    StageRun.workflow_run_id == workflow_id,
                    StageRun.stage_key == "review",
                )
            )
            messages = tuple(
                (
                    await db.scalars(
                        select(OutboxMessage).where(
                            OutboxMessage.workflow_run_id == workflow_id,
                            OutboxMessage.emission_kind == "dependency_ready",
                        )
                    )
                ).all()
            )
            assert workflow is not None
            assert review is not None
            assert review.status == "ready"
            assert review.state_version == 2
            assert len(messages) == 1
            assert messages[0].causation_id in completed_attempt_ids
            cause = await db.get(StageAttempt, messages[0].causation_id)
            assert cause is not None
            _assert_exact_dependency_message(messages[0], workflow=workflow, target=review, cause=cause)
    finally:
        await _cancel_if_active(workflow_id)


@pytest.mark.asyncio
async def test_late_failure_after_dependency_message_flush_rolls_back_source_target_attempt_and_message(monkeypatch):
    workflow_id = await _new_workflow(
        "late-rollback",
        [
            _stage_definition("collect", 1),
            _stage_definition("review", 2, depends_on=["collect"]),
        ],
    )
    try:
        authority = await _activate_root(workflow_id, "collect")
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

        with pytest.raises(DBAPIError):
            await workflow_worker.coordinate_stage_complete(
                async_session_factory,
                authority=authority,
                output_manifest={"sources": 4},
            )

        assert len(captured_message_ids) == 1
        async with async_session_factory() as db:
            workflow = await db.get(WorkflowRun, workflow_id)
            source = await db.get(StageRun, authority.stage_run_id)
            attempt = await db.get(StageAttempt, authority.stage_attempt_id)
            target = await db.scalar(
                select(StageRun).where(
                    StageRun.workflow_run_id == workflow_id,
                    StageRun.stage_key == "review",
                )
            )
            dependency_count = await db.scalar(
                select(func.count())
                .select_from(OutboxMessage)
                .where(
                    OutboxMessage.workflow_run_id == workflow_id,
                    OutboxMessage.emission_kind == "dependency_ready",
                )
            )
            captured_count = await db.scalar(
                select(func.count()).select_from(OutboxMessage).where(OutboxMessage.id.in_(captured_message_ids))
            )
            assert workflow is not None and workflow.status == "running"
            assert source is not None and source.status == "running"
            assert source.state_version == authority.stage_state_version
            assert source.lease_token == authority.stage_lease_token
            assert attempt is not None and attempt.status == "running"
            assert attempt.state_version == authority.attempt_state_version
            assert attempt.completed_at is None
            assert target is not None and target.status == "pending"
            assert target.state_version == 1
            assert target.next_attempt_at is None
            assert dependency_count == captured_count == 0
    finally:
        await _cancel_if_active(workflow_id)


@pytest.mark.asyncio
async def test_leaf_completion_finalizes_workflow_without_dependency_emission():
    workflow_id = await _new_workflow(
        "leaf-finalization",
        [_stage_definition("collect", 1)],
    )
    authority = await _activate_root(workflow_id, "collect")
    completion = await _complete(authority, output_manifest={"claims": 7})
    assert completion.disposition == "completed"

    async with async_session_factory() as db:
        workflow = await db.get(WorkflowRun, workflow_id)
        source = await db.get(StageRun, authority.stage_run_id)
        attempt = await db.get(StageAttempt, authority.stage_attempt_id)
        dependency_count = await db.scalar(
            select(func.count())
            .select_from(OutboxMessage)
            .where(
                OutboxMessage.workflow_run_id == workflow_id,
                OutboxMessage.emission_kind == "dependency_ready",
            )
        )
        total_messages = await db.scalar(
            select(func.count()).select_from(OutboxMessage).where(OutboxMessage.workflow_run_id == workflow_id)
        )
        assert workflow is not None and workflow.status == "succeeded"
        assert workflow.completed_at is not None
        assert source is not None and source.status == "succeeded"
        assert source.completed_at == workflow.completed_at
        assert attempt is not None and attempt.status == "succeeded"
        assert attempt.completed_at == source.completed_at
        assert dependency_count == 0
        assert total_messages == 1
