"""Fresh-0004 black-box acceptance for cancellation and lease recovery.

The public worker coordinators own every mutation transaction in this module.
Direct runtime entry points appear only in the explicit pre-SQL fence test.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime
import hashlib
import json
import os
import uuid

import pytest
import pytest_asyncio
from sqlalchemy import event, func, inspect, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

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
from tests.postgres._workflow_authority import (
    cancel_active_workflow,
    cancellation_command,
)


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_POSTGRES_TESTS") != "1",
    reason="requires an explicitly authorized disposable PostgreSQL database",
)

ACTOR = projects.ResearchActor(
    name="PostgreSQL Workflow Authority Test",
    actor_id="postgres-workflow-authority",
)


class _InjectedCancellationFailure(RuntimeError):
    """Test-only abort after the full D/M/A/S/W mutation reached PostgreSQL."""


class _FailAfterCancelledWorkflowFlush(AsyncSession):
    async def flush(self, objects=None):
        await super().flush(objects)
        if objects and any(type(value) is WorkflowRun and value.status == "cancelled" for value in objects):
            raise _InjectedCancellationFailure(
                "rollback after cancellation workflow flush",
            )


class _CommitCountingSessionFactory:
    def __init__(self) -> None:
        self.sessions: list[AsyncSession] = []
        self.commit_count = 0

    def __call__(self) -> AsyncSession:
        session = async_session_factory()
        self.sessions.append(session)
        event.listen(session.sync_session, "after_commit", self._after_commit)
        return session

    def _after_commit(self, _session) -> None:
        self.commit_count += 1


@pytest_asyncio.fixture(autouse=True)
async def _require_fresh_contract_head_and_dispose_pool():
    await engine.dispose()
    async with engine.connect() as connection:
        revision = await connection.scalar(text("SELECT version_num FROM alembic_version"))
    assert revision == "20260824_0004"
    try:
        yield
    finally:
        await engine.dispose()


def _spec(label: str) -> dict:
    return {
        "objective": f"Validate receipt-bound workflow authority: {label}.",
        "intelligence_requirements": [
            "Do commit-confirmed cancellation and recovery preserve exact authority?",
        ],
        "output_targets": ["canonical_intelligence"],
        "tlp": "TLP:AMBER",
    }


def _stage_definition(
    stage_key: str,
    ordinal: int,
    *,
    required: bool = True,
    depends_on: list[str] | None = None,
    max_attempts: int = 3,
) -> dict:
    return {
        "stage_key": stage_key,
        "stage_type": f"test.{stage_key}",
        "stage_version": "1.0.0",
        "ordinal": ordinal,
        "depends_on": depends_on or [],
        "required": required,
        "priority": 0,
        "max_attempts": max_attempts,
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
            project_key=f"authority-{label}-{uuid.uuid4().hex[:12]}",
            name=f"Workflow authority {label}",
            description="Disposable fresh-0004 PostgreSQL workflow authority.",
            spec=_spec(label),
        )
        workflow, created = await workflow_runtime.create_workflow(
            db,
            ACTOR,
            project_revision_id=revision.id,
            workflow_type="cti.report",
            idempotency_token=f"authority-{label}-{uuid.uuid4().hex}",
            input_manifest={"report_id": label, "source_ids": ["source-a"]},
            stage_plan=stage_plan,
            priority=0,
        )
        assert created is True
        workflow_id = uuid.UUID(str(workflow.id))
        await db.commit()
        return workflow_id


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


@asynccontextmanager
async def _isolate_recovery_targets(allowed_workflow_ids: set[uuid.UUID]):
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


async def _root_message_ids(workflow_id: uuid.UUID) -> dict[str, uuid.UUID]:
    async with async_session_factory() as db:
        rows = await db.execute(
            select(OutboxMessage.stage_key, OutboxMessage.id).where(
                OutboxMessage.workflow_run_id == workflow_id,
                OutboxMessage.emission_kind == "root_ready",
            )
        )
    return {stage_key: uuid.UUID(str(message_id)) for stage_key, message_id in rows}


async def _claim_message(
    message_id: uuid.UUID,
    *,
    publisher_id: str,
) -> outbox_runtime.ClaimedOutboxDelivery:
    async with _isolate_outbox_queue({message_id}):
        async with async_session_factory() as db:
            claim = await outbox_runtime.claim_outbox_delivery(
                db,
                publisher_id=publisher_id,
                lease_seconds=120,
            )
            assert claim is not None and claim.message_id == message_id
            await db.commit()
            return claim


async def _activate_message(
    message_id: uuid.UUID,
    *,
    worker_id: str,
    lease_seconds: int = 120,
) -> outbox_runtime.ExecutableStageAuthority:
    claim = await _claim_message(
        message_id,
        publisher_id=f"authority-publisher-{worker_id}",
    )
    command = outbox_runtime.StageReceiptCommand(
        claim=claim,
        broker_name="postgres_test_broker",
        broker_message_id=f"authority-{claim.cycle_key}",
        broker_receipt_id=hashlib.sha256(
            f"authority-receipt:{claim.cycle_key}".encode(),
        ).hexdigest(),
        worker_id=worker_id,
        lease_seconds=lease_seconds,
    )
    coordinated = await outbox_coordinator.coordinate_stage_receipt(
        async_session_factory,
        command=command,
    )
    assert coordinated.disposition == "activated"
    assert coordinated.authority is not None
    return coordinated.authority


def _row_snapshot(row: object) -> tuple[tuple[str, object], ...]:
    snapshot: list[tuple[str, object]] = []
    for column in inspect(type(row)).mapper.column_attrs:
        value = getattr(row, column.key)
        if isinstance(value, (dict, list)):
            value = json.dumps(value, sort_keys=True, separators=(",", ":"))
        snapshot.append((column.key, value))
    return tuple(snapshot)


async def _workflow_graph_snapshot(workflow_id: uuid.UUID):
    async with async_session_factory() as db:
        workflow = await db.get(WorkflowRun, workflow_id)
        stages = tuple(
            (
                await db.scalars(
                    select(StageRun).where(StageRun.workflow_run_id == workflow_id).order_by(StageRun.ordinal.asc(), StageRun.id.asc())
                )
            ).all()
        )
        messages = tuple(
            (
                await db.scalars(select(OutboxMessage).where(OutboxMessage.workflow_run_id == workflow_id).order_by(OutboxMessage.id.asc()))
            ).all()
        )
        deliveries = tuple(
            (
                await db.scalars(
                    select(OutboxDeliveryAttempt)
                    .join(
                        OutboxMessage,
                        OutboxDeliveryAttempt.message_id == OutboxMessage.id,
                    )
                    .where(OutboxMessage.workflow_run_id == workflow_id)
                    .order_by(OutboxDeliveryAttempt.id.asc())
                )
            ).all()
        )
        attempts = tuple(
            (
                await db.scalars(
                    select(StageAttempt).join(StageRun).where(StageRun.workflow_run_id == workflow_id).order_by(StageAttempt.id.asc())
                )
            ).all()
        )
        assert workflow is not None and stages
        return tuple(_row_snapshot(row) for row in (workflow, *stages, *messages, *deliveries, *attempts))


async def _assert_graph_nowait_unlocked(workflow_id: uuid.UUID) -> None:
    async with async_session_factory() as db:
        async with db.begin():
            workflow = await db.scalar(select(WorkflowRun).where(WorkflowRun.id == workflow_id).with_for_update(nowait=True))
            assert workflow is not None
            for model, statement in (
                (
                    StageRun,
                    select(StageRun).where(StageRun.workflow_run_id == workflow_id).order_by(StageRun.ordinal.asc(), StageRun.id.asc()),
                ),
                (
                    OutboxMessage,
                    select(OutboxMessage).where(OutboxMessage.workflow_run_id == workflow_id).order_by(OutboxMessage.id.asc()),
                ),
                (
                    OutboxDeliveryAttempt,
                    select(OutboxDeliveryAttempt)
                    .join(
                        OutboxMessage,
                        OutboxDeliveryAttempt.message_id == OutboxMessage.id,
                    )
                    .where(OutboxMessage.workflow_run_id == workflow_id)
                    .order_by(OutboxDeliveryAttempt.id.asc()),
                ),
                (
                    StageAttempt,
                    select(StageAttempt).join(StageRun).where(StageRun.workflow_run_id == workflow_id).order_by(StageAttempt.id.asc()),
                ),
            ):
                rows = tuple((await db.scalars(statement.with_for_update(nowait=True))).all())
                assert all(type(row) is model for row in rows)
            await db.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))


def _ordered_update_tables(statements: list[str]) -> list[str]:
    ordered: list[str] = []
    for statement in statements:
        normalized = " ".join(statement.lower().split())
        for table in (
            "outbox_delivery_attempts",
            "outbox_messages",
            "stage_attempts",
            "stage_runs",
            "workflow_runs",
        ):
            if normalized.startswith(f"update {table}"):
                ordered.append(table)
                break
    return ordered


@pytest.mark.asyncio
async def test_cancellation_applies_d_m_a_s_w_then_exactly_replays_and_releases_locks():
    workflow_id = await _new_workflow(
        "cancel-replay",
        [
            _stage_definition("collect", 1),
            _stage_definition("enrich", 2),
        ],
    )
    try:
        messages = await _root_message_ids(workflow_id)
        authority = await _activate_message(
            messages["collect"],
            worker_id="cancel-running-worker",
        )
        competing_claim = await _claim_message(
            messages["enrich"],
            publisher_id="cancel-competing-publisher",
        )
        command = cancellation_command(
            workflow_run_id=workflow_id,
            expected_workflow_state_version=authority.workflow_state_version,
            actor=ACTOR,
            reason="Analyst revoked the source while delivery was active.",
            request_id=uuid.uuid4(),
        )
        statements: list[str] = []

        def capture(_connection, _cursor, statement, _parameters, _context, _many):
            statements.append(statement)

        event.listen(engine.sync_engine, "before_cursor_execute", capture)
        try:
            applied = await workflow_worker.coordinate_workflow_cancel(
                async_session_factory,
                command=command,
            )
        finally:
            event.remove(engine.sync_engine, "before_cursor_execute", capture)

        assert applied.disposition == "applied"
        assert applied.should_apply is True
        assert applied.workflow_run_id == workflow_id
        assert applied.previous_workflow_state_version == authority.workflow_state_version
        assert applied.workflow_state_version == authority.workflow_state_version + 1
        competing_stage_id = uuid.UUID(
            json.loads(competing_claim.envelope_canonical)["payload"]["stage_run_id"],
        )
        assert applied.cancelled_stage_ids == (
            authority.stage_run_id,
            competing_stage_id,
        )
        assert applied.cancelled_attempt_ids == (authority.stage_attempt_id,)
        assert applied.cancelled_message_ids == (competing_claim.message_id,)
        assert applied.cancelled_delivery_ids == (competing_claim.delivery_attempt_id,)
        update_order = _ordered_update_tables(statements)
        assert update_order == [
            "outbox_delivery_attempts",
            "outbox_messages",
            "stage_attempts",
            "stage_runs",
            "stage_runs",
            "workflow_runs",
        ]

        async with async_session_factory() as db:
            workflow = await db.get(WorkflowRun, workflow_id)
            stages = tuple(
                (await db.scalars(select(StageRun).where(StageRun.workflow_run_id == workflow_id).order_by(StageRun.ordinal.asc()))).all()
            )
            attempt = await db.get(StageAttempt, authority.stage_attempt_id)
            live_message = await db.get(OutboxMessage, competing_claim.message_id)
            live_delivery = await db.get(
                OutboxDeliveryAttempt,
                competing_claim.delivery_attempt_id,
            )
            receipt_message = await db.get(OutboxMessage, authority.message_id)
            receipt_delivery = await db.get(
                OutboxDeliveryAttempt,
                authority.delivery_attempt_id,
            )
            assert workflow is not None and workflow.status == "cancelled"
            assert workflow.cancel_request_id == command.request_id
            assert [stage.status for stage in stages] == ["cancelled", "cancelled"]
            assert attempt is not None and attempt.status == "cancelled"
            assert attempt.error_code == "workflow.cancelled"
            assert live_message is not None and live_message.status == "cancelled"
            assert live_delivery is not None and live_delivery.status == "cancelled"
            assert live_message.cancelled_at is not None
            assert live_delivery.completed_at is not None
            assert live_message.cancelled_at == live_delivery.completed_at
            assert receipt_message is not None and receipt_message.status == "delivered"
            assert receipt_delivery is not None and receipt_delivery.status == "delivered"

        before_replay = await _workflow_graph_snapshot(workflow_id)
        replayed = await workflow_worker.coordinate_workflow_cancel(
            async_session_factory,
            command=command,
        )
        assert replayed.disposition == "replayed"
        assert replayed.should_apply is False
        assert replayed.request_id == applied.request_id
        assert replayed.workflow_state_version == applied.workflow_state_version
        assert replayed.cancelled_at == applied.cancelled_at
        assert replayed.cancelled_stage_ids == replayed.cancelled_attempt_ids == ()
        assert replayed.cancelled_message_ids == replayed.cancelled_delivery_ids == ()
        assert await _workflow_graph_snapshot(workflow_id) == before_replay
        await _assert_graph_nowait_unlocked(workflow_id)

        with pytest.raises(outbox_runtime.OutboxConflict, match="replay does not match"):
            await workflow_worker.coordinate_workflow_cancel(
                async_session_factory,
                command=cancellation_command(
                    workflow_run_id=workflow_id,
                    expected_workflow_state_version=command.expected_workflow_state_version,
                    actor=ACTOR,
                    reason="A different request cannot replay durable authority.",
                ),
            )
        assert await _workflow_graph_snapshot(workflow_id) == before_replay
    finally:
        await cancel_active_workflow(
            async_session_factory,
            workflow_run_id=workflow_id,
            actor=ACTOR,
            reason="Cancellation acceptance cleanup.",
        )


@pytest.mark.asyncio
async def test_cancellation_late_failure_rolls_back_the_complete_graph():
    workflow_id = await _new_workflow(
        "cancel-rollback",
        [_stage_definition("collect", 1)],
    )
    try:
        message_id = (await _root_message_ids(workflow_id))["collect"]
        authority = await _activate_message(
            message_id,
            worker_id="cancel-rollback-worker",
        )
        before = await _workflow_graph_snapshot(workflow_id)
        maker = async_sessionmaker(
            engine,
            class_=_FailAfterCancelledWorkflowFlush,
            expire_on_commit=False,
        )
        with pytest.raises(
            _InjectedCancellationFailure,
            match="rollback after cancellation workflow flush",
        ):
            await workflow_worker.coordinate_workflow_cancel(
                maker,
                command=cancellation_command(
                    workflow_run_id=workflow_id,
                    expected_workflow_state_version=authority.workflow_state_version,
                    actor=ACTOR,
                    reason="Injected cancellation rollback.",
                ),
            )
        assert await _workflow_graph_snapshot(workflow_id) == before
        await _assert_graph_nowait_unlocked(workflow_id)
    finally:
        await cancel_active_workflow(
            async_session_factory,
            workflow_run_id=workflow_id,
            actor=ACTOR,
            reason="Cancellation rollback cleanup.",
        )


@pytest.mark.asyncio
async def test_optional_exhausted_recovery_skips_dependant_and_degrades_workflow():
    workflow_id = await _new_workflow(
        "optional-recovery",
        [
            _stage_definition(
                "collect",
                1,
                required=False,
                max_attempts=1,
            ),
            _stage_definition(
                "publish",
                2,
                depends_on=["collect"],
            ),
        ],
    )
    try:
        message_id = (await _root_message_ids(workflow_id))["collect"]
        authority = await _activate_message(
            message_id,
            worker_id="optional-expired-worker",
            lease_seconds=1,
        )
        async with _isolate_recovery_targets({workflow_id}):
            before_expiry = await workflow_worker.coordinate_one_expired_stage_recovery(
                async_session_factory,
            )
        assert before_expiry is None
        await asyncio.sleep(1.2)
        async with _isolate_recovery_targets({workflow_id}):
            recovered = await workflow_worker.coordinate_one_expired_stage_recovery(
                async_session_factory,
            )
        assert recovered is not None
        assert recovered.workflow_run_id == workflow_id
        assert recovered.stage_run_id == authority.stage_run_id
        assert recovered.stage_attempt_id == authority.stage_attempt_id
        assert recovered.decision == "dead_lettered"
        assert recovered.stage_status == "dead_lettered"
        assert recovered.attempt_status == "abandoned"
        assert recovered.workflow_status == "degraded"
        assert len(recovered.skipped_stage_ids) == 1
        assert recovered.cancelled_stage_ids == ()
        assert recovered.cancelled_attempt_ids == ()
        assert recovered.cancelled_message_ids == ()
        assert recovered.cancelled_delivery_ids == ()
        assert recovered.retry_emission is None
        assert recovered.should_retry is False

        async with async_session_factory() as db:
            workflow = await db.get(WorkflowRun, workflow_id)
            stages = tuple(
                (await db.scalars(select(StageRun).where(StageRun.workflow_run_id == workflow_id).order_by(StageRun.ordinal.asc()))).all()
            )
            attempt = await db.get(StageAttempt, authority.stage_attempt_id)
            assert workflow is not None and workflow.status == "degraded"
            assert workflow.status_reason_code == "workflow.degraded_stages"
            assert [stage.status for stage in stages] == [
                "dead_lettered",
                "skipped",
            ]
            assert stages[1].id == recovered.skipped_stage_ids[0]
            assert attempt is not None and attempt.status == "abandoned"
            assert attempt.error_code == "workflow.lease_expired"
        await _assert_graph_nowait_unlocked(workflow_id)
    finally:
        await cancel_active_workflow(
            async_session_factory,
            workflow_run_id=workflow_id,
            actor=ACTOR,
            reason="Optional recovery cleanup.",
        )


@pytest.mark.asyncio
async def test_legacy_cancel_and_recovery_entrypoints_fail_before_sql():
    statements: list[str] = []

    def capture(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", capture)
    try:
        async with async_session_factory() as db:
            with pytest.raises(
                workflow_runtime.WorkflowConflict,
                match="coordinate_workflow_cancel",
            ):
                await workflow_runtime.cancel_workflow(
                    db,
                    uuid.uuid4(),
                    ACTOR,
                    expected_state_version=1,
                    reason="Legacy cancellation must remain fenced.",
                )
            with pytest.raises(
                workflow_runtime.WorkflowConflict,
                match="coordinate_one_expired_stage_recovery",
            ):
                await workflow_runtime.recover_one_expired_stage(db)
            with pytest.raises(
                workflow_runtime.WorkflowConflict,
                match="coordinate_expired_stage_recovery_pass",
            ):
                await workflow_runtime.recover_expired_stages(db, limit=10)
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", capture)
    assert statements == []


@pytest.mark.asyncio
async def test_recovery_pass_uses_distinct_commits_and_stops_at_empty_scan():
    workflow_ids = (
        await _new_workflow(
            "batch-alpha",
            [_stage_definition("collect", 1, max_attempts=2)],
        ),
        await _new_workflow(
            "batch-bravo",
            [_stage_definition("collect", 1, max_attempts=2)],
        ),
    )
    try:
        authorities = []
        for workflow_id in workflow_ids:
            message_id = (await _root_message_ids(workflow_id))["collect"]
            authorities.append(
                await _activate_message(
                    message_id,
                    worker_id=f"batch-{workflow_id}",
                    lease_seconds=1,
                )
            )
        await asyncio.sleep(1.2)
        recovery_sessions = _CommitCountingSessionFactory()
        async with _isolate_recovery_targets(set(workflow_ids)):
            results = await workflow_worker.coordinate_expired_stage_recovery_pass(
                recovery_sessions,
                limit=5,
            )
        assert len(results) == 2
        assert len(recovery_sessions.sessions) == 3
        assert len({id(session) for session in recovery_sessions.sessions}) == 3
        assert recovery_sessions.commit_count == 3
        assert {result.workflow_run_id for result in results} == set(workflow_ids)
        assert all(result.decision == "retry" for result in results)
        assert all(result.retry_emission is not None for result in results)
        async with _isolate_recovery_targets(set(workflow_ids)):
            assert (
                await workflow_worker.coordinate_one_expired_stage_recovery(
                    async_session_factory,
                )
                is None
            )
        for authority in authorities:
            async with async_session_factory() as db:
                stage = await db.get(StageRun, authority.stage_run_id)
                attempt = await db.get(StageAttempt, authority.stage_attempt_id)
                assert stage is not None and stage.status == "retry_wait"
                assert attempt is not None and attempt.status == "abandoned"
    finally:
        for workflow_id in workflow_ids:
            await cancel_active_workflow(
                async_session_factory,
                workflow_run_id=workflow_id,
                actor=ACTOR,
                reason="Batch recovery cleanup.",
            )
