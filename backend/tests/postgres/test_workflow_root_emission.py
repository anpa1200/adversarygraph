"""PostgreSQL acceptance for atomic root-ready emission at workflow creation.

Run only against a disposable database migrated through revision 0003::

    RUN_POSTGRES_TESTS=1 python -m pytest -q -o addopts='' \
      --confcutdir=tests/postgres \
      tests/postgres/test_workflow_root_emission.py

This suite deliberately invokes only ``workflow_runtime.create_workflow``.
It must never manufacture a missing root-ready message through a test helper.
Authority rows intentionally remain in the disposable database because the
production guards reject physical deletion.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from dataclasses import dataclass, field

import pytest
import pytest_asyncio
from sqlalchemy import event, func, select
from sqlalchemy.exc import DBAPIError

from app.core.database import async_session_factory, engine
from app.models.research_workflow import (
    OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1,
    OUTBOX_TOPIC_WORKFLOW_STAGE_READY,
    OUTBOX_V1_MAX_ATTEMPTS,
    WORKFLOW_PLAN_SCHEMA_VERSION,
    WORKFLOW_SCHEMA_VERSION,
    OutboxDeliveryAttempt,
    OutboxMessage,
    StageAttempt,
    StageRun,
    WorkflowRun,
)
from app.services import research_projects as projects
from app.services import workflow_runtime as runtime
from app.services.outbox_engine import normalize_outbox_envelope
from app.services.workflow_engine import checksum_json, normalize_stage_plan


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_POSTGRES_TESTS") != "1",
    reason="requires an explicitly authorized disposable PostgreSQL database",
)

ACTOR = projects.ResearchActor(
    name="PostgreSQL Workflow Root Emission Test",
    actor_id="postgres-workflow-root-emission",
)


class _AsyncBarrier:
    """A bounded async barrier that fails instead of hanging a PG test."""

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


@dataclass
class _CapturedNewAuthority:
    workflow_ids: set[uuid.UUID] = field(default_factory=set)
    stage_ids: set[uuid.UUID] = field(default_factory=set)
    message_ids: set[uuid.UUID] = field(default_factory=set)
    corrupted_message_id: uuid.UUID | None = None

    def corrupt_first_outbox_insert(self, session, flush_context, instances) -> None:
        del flush_context, instances
        new_values = tuple(session.new)
        for value in new_values:
            if isinstance(value, WorkflowRun):
                self.workflow_ids.add(uuid.UUID(str(value.id)))
            elif isinstance(value, StageRun):
                self.stage_ids.add(uuid.UUID(str(value.id)))
            elif isinstance(value, OutboxMessage):
                self.message_ids.add(uuid.UUID(str(value.id)))
        if self.corrupted_message_id is not None:
            return
        messages = sorted(
            (value for value in new_values if isinstance(value, OutboxMessage)),
            key=lambda value: (value.stage_key, str(value.id)),
        )
        if messages:
            message = messages[0]
            self.corrupted_message_id = uuid.UUID(str(message.id))
            message.topic = "invalid.workflow.topic"


@pytest_asyncio.fixture(autouse=True)
async def _dispose_engine_pool_between_tests():
    await engine.dispose()
    try:
        yield
    finally:
        await engine.dispose()


def _spec(label: str) -> dict:
    return {
        "objective": f"Validate native root-ready workflow emission: {label}.",
        "intelligence_requirements": [
            "Does workflow creation atomically persist exact root execution authority?",
        ],
        "output_targets": ["canonical_intelligence"],
        "tlp": "TLP:AMBER",
    }


def _stage_definition(
    stage_key: str,
    ordinal: int,
    *,
    depends_on: list[str] | None = None,
    priority: int = 0,
    input_manifest: dict | None = None,
) -> dict:
    definition = {
        "stage_key": stage_key,
        "stage_type": f"test.{stage_key}",
        "stage_version": "1.0.0",
        "ordinal": ordinal,
        "depends_on": depends_on or [],
        "required": True,
        "priority": priority,
        "max_attempts": 3,
        "config_schema_version": "research-stage-config-v1",
        "checkpoint_schema_version": "research-stage-checkpoint-v1",
        "config": {"acceptance_test": True, "stage": stage_key},
        "retry_policy": {
            "base_delay_seconds": 2,
            "max_delay_seconds": 30,
            "jitter_percent": 0,
        },
    }
    if input_manifest is not None:
        definition["input_manifest"] = input_manifest
    return definition


def _multi_root_plan() -> list[dict]:
    return [
        _stage_definition("collect", 1, priority=8),
        _stage_definition(
            "enrich",
            2,
            priority=7,
            input_manifest={"source_ids": ["source-b", "source-a"], "scope": "override"},
        ),
        _stage_definition("correlate", 3, depends_on=["collect", "enrich"], priority=6),
    ]


async def _new_project(label: str) -> uuid.UUID:
    async with async_session_factory() as db:
        _, revision = await projects.create_project(
            db,
            ACTOR,
            project_key=f"root-emission-{label}-{uuid.uuid4().hex[:12]}",
            name=f"Root emission {label}",
            description="Disposable PostgreSQL native root-emission acceptance authority.",
            spec=_spec(label),
        )
        revision_id = uuid.UUID(str(revision.id))
        await db.commit()
        return revision_id


async def _create(
    db,
    *,
    revision_id: uuid.UUID,
    token: str,
    input_manifest: dict,
    stage_plan: list[dict],
) -> tuple[WorkflowRun, bool]:
    return await runtime.create_workflow(
        db,
        ACTOR,
        project_revision_id=revision_id,
        workflow_type="cti.report",
        idempotency_token=token,
        input_manifest=input_manifest,
        stage_plan=stage_plan,
        trigger_type="api",
        priority=4,
    )


async def _workflow_counts(db, workflow_id: uuid.UUID) -> tuple[int, int, int, int, int]:
    stage_ids = select(StageRun.id).where(StageRun.workflow_run_id == workflow_id)
    message_ids = select(OutboxMessage.id).where(OutboxMessage.workflow_run_id == workflow_id)
    values = []
    for statement in (
        select(func.count()).select_from(WorkflowRun).where(WorkflowRun.id == workflow_id),
        select(func.count()).select_from(StageRun).where(StageRun.workflow_run_id == workflow_id),
        select(func.count()).select_from(OutboxMessage).where(OutboxMessage.workflow_run_id == workflow_id),
        select(func.count()).select_from(StageAttempt).where(StageAttempt.stage_run_id.in_(stage_ids)),
        select(func.count()).select_from(OutboxDeliveryAttempt).where(OutboxDeliveryAttempt.message_id.in_(message_ids)),
    ):
        values.append(int(await db.scalar(statement) or 0))
    return tuple(values)  # type: ignore[return-value]


def _expected_envelope(workflow: WorkflowRun, stage: StageRun):
    return normalize_outbox_envelope(
        {
            "topic": OUTBOX_TOPIC_WORKFLOW_STAGE_READY,
            "schema_version": OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1,
            "payload": {
                "workflow_run_id": str(workflow.id),
                "stage_run_id": str(stage.id),
                "stage_key": stage.stage_key,
                "target_attempt_number": 1,
                "input_checksum": stage.input_checksum,
                "plan_checksum": workflow.plan_checksum,
            },
        }
    )


def _assert_exact_root_message(message: OutboxMessage, workflow: WorkflowRun, stage: StageRun) -> None:
    expected = _expected_envelope(workflow, stage)
    assert message.workflow_run_id == workflow.id
    assert message.stage_run_id == stage.id
    assert message.aggregate_type == "workflow_stage"
    assert message.aggregate_id == stage.id
    assert message.aggregate_version == stage.state_version == 1
    assert message.emission_kind == "root_ready"
    assert message.topic == OUTBOX_TOPIC_WORKFLOW_STAGE_READY
    assert message.schema_version == OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1
    assert message.correlation_id == workflow.correlation_id
    assert message.causation_id is None
    assert message.stage_key == stage.stage_key
    assert message.target_attempt_number == 1
    assert message.input_checksum == stage.input_checksum == checksum_json(stage.input_manifest)
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
    assert message.max_attempts == OUTBOX_V1_MAX_ATTEMPTS == 8
    assert message.delivery_cycle == 0
    assert message.cycle_key is None
    assert message.available_at == stage.next_attempt_at
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
async def test_create_atomically_persists_exact_multi_root_fanout_before_any_receipt():
    revision_id = await _new_project("atomic-fanout")
    input_manifest = {
        "report_id": f"report-{uuid.uuid4().hex}",
        "source_urls": ["https://example.test/advisory"],
    }
    stage_plan = _multi_root_plan()
    normalized_plan = normalize_stage_plan(stage_plan)

    async with async_session_factory() as creator, async_session_factory() as observer:
        workflow, created = await _create(
            creator,
            revision_id=revision_id,
            token=f"atomic-{uuid.uuid4().hex}",
            input_manifest=input_manifest,
            stage_plan=stage_plan,
        )
        assert created is True
        workflow_id = uuid.UUID(str(workflow.id))

        # The creator sees the complete graph, but an independent transaction
        # must see none of W/S/M until the caller commits.
        assert await _workflow_counts(creator, workflow_id) == (1, 3, 2, 0, 0)
        assert await _workflow_counts(observer, workflow_id) == (0, 0, 0, 0, 0)

        await creator.commit()
        assert await _workflow_counts(observer, workflow_id) == (1, 3, 2, 0, 0)

        persisted_workflow = await observer.get(WorkflowRun, workflow_id)
        assert persisted_workflow is not None
        stages = tuple(
            (
                await observer.scalars(
                    select(StageRun).where(StageRun.workflow_run_id == workflow_id).order_by(StageRun.ordinal.asc(), StageRun.id.asc())
                )
            ).all()
        )
        messages = tuple(
            (
                await observer.scalars(
                    select(OutboxMessage)
                    .where(OutboxMessage.workflow_run_id == workflow_id)
                    .order_by(OutboxMessage.stage_key.asc(), OutboxMessage.id.asc())
                )
            ).all()
        )

        assert persisted_workflow.status == "queued"
        assert persisted_workflow.state_version == 1
        assert persisted_workflow.workflow_schema_version == WORKFLOW_SCHEMA_VERSION
        assert persisted_workflow.plan_schema_version == WORKFLOW_PLAN_SCHEMA_VERSION
        assert persisted_workflow.input_manifest == input_manifest
        assert persisted_workflow.input_checksum == checksum_json(input_manifest)
        assert persisted_workflow.stage_plan == normalized_plan.as_payload()
        assert persisted_workflow.plan_checksum == normalized_plan.checksum

        by_key = {stage.stage_key: stage for stage in stages}
        assert set(by_key) == {"collect", "enrich", "correlate"}
        assert by_key["collect"].status == "ready"
        assert by_key["enrich"].status == "ready"
        assert by_key["correlate"].status == "pending"
        assert by_key["collect"].next_attempt_at is not None
        assert by_key["enrich"].next_attempt_at == by_key["collect"].next_attempt_at
        assert by_key["correlate"].next_attempt_at is None
        assert by_key["collect"].input_manifest == input_manifest
        assert by_key["enrich"].input_manifest == {
            "source_ids": ["source-b", "source-a"],
            "scope": "override",
        }
        assert by_key["correlate"].input_manifest == input_manifest

        assert {message.stage_key for message in messages} == {"collect", "enrich"}
        assert "correlate" not in {message.stage_key for message in messages}
        assert len({message.logical_key for message in messages}) == 2
        for message in messages:
            _assert_exact_root_message(message, persisted_workflow, by_key[message.stage_key])

        # Root messages are durable execution authority before a publisher or
        # worker creates any delivery receipt or stage attempt.
        stage_ids = select(StageRun.id).where(StageRun.workflow_run_id == workflow_id)
        message_ids = select(OutboxMessage.id).where(OutboxMessage.workflow_run_id == workflow_id)
        assert (
            await observer.scalar(
                select(func.count()).select_from(OutboxDeliveryAttempt).where(OutboxDeliveryAttempt.message_id.in_(message_ids))
            )
            == 0
        )
        assert await observer.scalar(select(func.count()).select_from(StageAttempt).where(StageAttempt.stage_run_id.in_(stage_ids))) == 0


@pytest.mark.asyncio
async def test_outbox_constraint_failure_rolls_back_new_workflow_stages_and_messages():
    revision_id = await _new_project("constraint-rollback")
    captured = _CapturedNewAuthority()

    async with async_session_factory() as db:
        event.listen(db.sync_session, "before_flush", captured.corrupt_first_outbox_insert)
        try:
            with pytest.raises(DBAPIError):
                await _create(
                    db,
                    revision_id=revision_id,
                    token=f"rollback-{uuid.uuid4().hex}",
                    input_manifest={"report_id": f"rollback-{uuid.uuid4().hex}"},
                    stage_plan=_multi_root_plan(),
                )
                await db.commit()
        finally:
            event.remove(db.sync_session, "before_flush", captured.corrupt_first_outbox_insert)
            await db.rollback()

    assert len(captured.workflow_ids) == 1
    assert len(captured.stage_ids) == 3
    assert captured.corrupted_message_id is not None
    assert captured.message_ids

    async with async_session_factory() as observer:
        assert (
            int(await observer.scalar(select(func.count()).select_from(WorkflowRun).where(WorkflowRun.id.in_(captured.workflow_ids))) or 0)
            == 0
        )
        assert int(await observer.scalar(select(func.count()).select_from(StageRun).where(StageRun.id.in_(captured.stage_ids))) or 0) == 0
        assert (
            int(
                await observer.scalar(select(func.count()).select_from(OutboxMessage).where(OutboxMessage.id.in_(captured.message_ids)))
                or 0
            )
            == 0
        )


@pytest.mark.asyncio
async def test_idempotent_create_replay_does_not_duplicate_stages_or_root_messages():
    revision_id = await _new_project("idempotent-replay")
    token = f"replay-{uuid.uuid4().hex}"
    input_manifest = {"report_id": f"replay-report-{uuid.uuid4().hex}"}
    stage_plan = _multi_root_plan()

    async with async_session_factory() as db:
        first, first_created = await _create(
            db,
            revision_id=revision_id,
            token=token,
            input_manifest=input_manifest,
            stage_plan=stage_plan,
        )
        assert first_created is True
        workflow_id = uuid.UUID(str(first.id))
        await db.commit()

    async with async_session_factory() as db:
        replayed, replay_created = await _create(
            db,
            revision_id=revision_id,
            token=token,
            input_manifest=input_manifest,
            stage_plan=stage_plan,
        )
        assert replay_created is False
        assert replayed.id == workflow_id
        await db.commit()

    async with async_session_factory() as observer:
        assert await _workflow_counts(observer, workflow_id) == (1, 3, 2, 0, 0)
        messages = tuple(
            (
                await observer.scalars(
                    select(OutboxMessage)
                    .where(OutboxMessage.workflow_run_id == workflow_id)
                    .order_by(OutboxMessage.stage_key.asc(), OutboxMessage.id.asc())
                )
            ).all()
        )
        assert [message.stage_key for message in messages] == ["collect", "enrich"]
        assert len({message.logical_key for message in messages}) == 2


@pytest.mark.asyncio
async def test_concurrent_identical_create_has_one_workflow_and_one_message_per_root():
    revision_id = await _new_project("concurrent-idempotency")
    token = f"concurrent-{uuid.uuid4().hex}"
    input_manifest = {"report_id": f"concurrent-report-{uuid.uuid4().hex}"}
    stage_plan = _multi_root_plan()
    start = _AsyncBarrier(2)

    async def create_once() -> tuple[uuid.UUID, bool]:
        await start.wait()
        async with async_session_factory() as db:
            workflow, created = await _create(
                db,
                revision_id=revision_id,
                token=token,
                input_manifest=input_manifest,
                stage_plan=stage_plan,
            )
            workflow_id = uuid.UUID(str(workflow.id))
            await db.commit()
            return workflow_id, created

    results = await asyncio.wait_for(asyncio.gather(create_once(), create_once()), timeout=20)
    workflow_ids = {workflow_id for workflow_id, _ in results}
    assert len(workflow_ids) == 1
    assert sorted(created for _, created in results) == [False, True]
    workflow_id = workflow_ids.pop()

    async with async_session_factory() as observer:
        assert await _workflow_counts(observer, workflow_id) == (1, 3, 2, 0, 0)
        messages = tuple(
            (
                await observer.scalars(
                    select(OutboxMessage)
                    .where(OutboxMessage.workflow_run_id == workflow_id)
                    .order_by(OutboxMessage.stage_key.asc(), OutboxMessage.id.asc())
                )
            ).all()
        )
        assert [message.stage_key for message in messages] == ["collect", "enrich"]
        assert len({message.logical_key for message in messages}) == 2
