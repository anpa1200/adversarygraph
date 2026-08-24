"""PostgreSQL acceptance for commit-confirmed receipt-bound completion.

Run only against a disposable database migrated through revision 0004::

    RUN_POSTGRES_TESTS=1 python -m pytest -q -o addopts='' \
      --confcutdir=tests/postgres \
      tests/postgres/test_workflow_completion_receipt.py
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
from sqlalchemy import event, func, select, text
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
from tests.postgres._workflow_authority import cancel_active_workflow
from app.services.workflow_engine import checksum_json


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_POSTGRES_TESTS") != "1",
    reason="requires an explicitly authorized disposable PostgreSQL database",
)

ACTOR = projects.ResearchActor(
    name="PostgreSQL Receipt Completion Test",
    actor_id="postgres-receipt-completion",
)


class _InjectedCompletionFailure(RuntimeError):
    """Test-only failure after the dependency-ready messages reach PostgreSQL."""


class _ImmediateConstraintsSession(AsyncSession):
    immediate_checks = 0

    async def flush(self, objects=None):
        await super().flush(objects)
        message_cutover = objects and any(type(value) is OutboxMessage for value in objects)
        workflow_cutover = objects and any(type(value) is WorkflowRun and value.status in {"succeeded", "degraded"} for value in objects)
        if message_cutover or workflow_cutover:
            await self.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))
            type(self).immediate_checks += 1


class _FailAfterMessageFlushSession(AsyncSession):
    async def flush(self, objects=None):
        await super().flush(objects)
        if objects and any(type(value) is OutboxMessage for value in objects):
            raise _InjectedCompletionFailure("rollback after attempt, stages, and dependency messages flushed")


class _TrackingFactory:
    def __init__(self, maker=async_session_factory):
        self._maker = maker
        self.active = 0
        self.exits = 0

    def __call__(self):
        @asynccontextmanager
        async def scope():
            self.active += 1
            try:
                async with self._maker() as db:
                    yield db
            finally:
                self.active -= 1
                self.exits += 1

        return scope()


class _AsyncBarrier:
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


class _BarrierFactory:
    def __init__(self, barrier: _AsyncBarrier):
        self._barrier = barrier

    def __call__(self):
        @asynccontextmanager
        async def scope():
            async with async_session_factory() as db:
                await self._barrier.wait()
                yield db

        return scope()


class _ForbiddenFactory:
    def __init__(self):
        self.calls = 0

    def __call__(self):
        self.calls += 1
        raise AssertionError("invalid completion input opened a database session")


class _HostileOutput(dict):
    """A mapping subclass rejected before session construction."""


@pytest_asyncio.fixture(autouse=True)
async def _dispose_engine_pool_between_tests():
    await engine.dispose()
    try:
        yield
    finally:
        await engine.dispose()


def _spec(label: str) -> dict:
    return {
        "objective": f"Validate receipt-bound stage completion: {label}.",
        "intelligence_requirements": [
            "Can only committed delivered receipt authority terminate a stage?",
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


async def _new_workflow(label: str, *, target_count: int) -> uuid.UUID:
    plan = [_stage_definition("collect", 1)]
    plan.extend(
        _stage_definition(
            f"target_{index + 1}",
            index + 2,
            depends_on=["collect"],
        )
        for index in range(target_count)
    )
    async with async_session_factory() as db:
        _, revision = await projects.create_project(
            db,
            ACTOR,
            project_key=f"receipt-completion-{label}-{uuid.uuid4().hex[:10]}",
            name=f"Receipt completion {label}",
            description="Disposable PostgreSQL receipt-completion authority.",
            spec=_spec(label),
        )
        workflow, created = await workflow_runtime.create_workflow(
            db,
            ACTOR,
            project_revision_id=revision.id,
            workflow_type="cti.report",
            idempotency_token=f"receipt-completion-{label}-{uuid.uuid4().hex}",
            input_manifest={"report_id": label, "source_ids": ["source-a"]},
            stage_plan=plan,
            priority=0,
        )
        assert created is True
        workflow_id = uuid.UUID(str(workflow.id))
        await db.commit()
        return workflow_id


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


@asynccontextmanager
async def _isolate_recovery_targets(allowed_workflow_id: uuid.UUID):
    async with async_session_factory() as blocker:
        await blocker.execute(
            select(WorkflowRun.id)
            .where(
                WorkflowRun.status.in_(("queued", "running")),
                WorkflowRun.id != allowed_workflow_id,
            )
            .order_by(WorkflowRun.id.asc())
            .with_for_update()
        )
        try:
            yield
        finally:
            await blocker.rollback()


async def _activate(
    label: str,
    *,
    target_count: int,
    lease_seconds: int = 120,
) -> tuple[uuid.UUID, outbox_runtime.ExecutableStageAuthority]:
    workflow_id = await _new_workflow(label, target_count=target_count)
    async with async_session_factory() as db:
        message_id = await db.scalar(
            select(OutboxMessage.id).where(
                OutboxMessage.workflow_run_id == workflow_id,
                OutboxMessage.stage_key == "collect",
                OutboxMessage.emission_kind == "root_ready",
            )
        )
    assert isinstance(message_id, uuid.UUID)
    async with _isolate_outbox_queue(message_id):
        async with async_session_factory() as db:
            claim = await outbox_runtime.claim_outbox_delivery(
                db,
                publisher_id=f"receipt-completion-publisher-{uuid.uuid4().hex[:8]}",
                lease_seconds=120,
            )
            assert claim is not None and claim.message_id == message_id
            await db.commit()

    command = outbox_runtime.StageReceiptCommand(
        claim=claim,
        broker_name="postgres_test_broker",
        broker_message_id=f"receipt-completion-{label}-{claim.cycle_key}",
        broker_receipt_id=hashlib.sha256(f"receipt-completion:{label}:{claim.cycle_key}".encode()).hexdigest(),
        worker_id=f"receipt-completion-worker-{label}",
        lease_seconds=lease_seconds,
    )
    coordinated = await outbox_coordinator.coordinate_stage_receipt(
        async_session_factory,
        command=command,
    )
    assert coordinated.disposition == "activated"
    assert coordinated.should_execute is True
    assert coordinated.authority is not None
    return workflow_id, coordinated.authority


def _row_snapshot(value: object) -> tuple[tuple[str, object], ...]:
    snapshot: list[tuple[str, object]] = []
    for column in type(value).__table__.columns:
        field_value = getattr(value, column.key)
        if type(field_value) in {dict, list}:
            field_value = json.dumps(field_value, sort_keys=True, separators=(",", ":"))
        snapshot.append((column.key, field_value))
    return tuple(snapshot)


async def _graph_snapshot(authority: outbox_runtime.ExecutableStageAuthority):
    async with async_session_factory() as db:
        workflow = await db.get(WorkflowRun, authority.workflow_run_id)
        stages = tuple(
            (
                await db.scalars(
                    select(StageRun)
                    .where(StageRun.workflow_run_id == authority.workflow_run_id)
                    .order_by(StageRun.ordinal.asc(), StageRun.id.asc())
                )
            ).all()
        )
        message = await db.get(OutboxMessage, authority.message_id)
        delivery = await db.get(OutboxDeliveryAttempt, authority.delivery_attempt_id)
        attempt = await db.get(StageAttempt, authority.stage_attempt_id)
        assert workflow is not None and stages
        assert message is not None and delivery is not None and attempt is not None
        return tuple(_row_snapshot(value) for value in (workflow, *stages, message, delivery, attempt))


async def _source_lineage_snapshot(
    authority: outbox_runtime.ExecutableStageAuthority,
):
    async with async_session_factory() as db:
        message = await db.get(OutboxMessage, authority.message_id)
        delivery = await db.get(OutboxDeliveryAttempt, authority.delivery_attempt_id)
        assert message is not None and delivery is not None
        return _row_snapshot(message), _row_snapshot(delivery)


async def _cancel_if_active(workflow_id: uuid.UUID, *, reason: str) -> None:
    await cancel_active_workflow(
        async_session_factory,
        workflow_run_id=workflow_id,
        actor=ACTOR,
        reason=reason,
    )


async def _wait_until_db_after(moment: datetime) -> None:
    for _ in range(300):
        async with engine.connect() as connection:
            now = await connection.scalar(select(func.clock_timestamp()))
        if isinstance(now, datetime) and now > moment:
            return
        await asyncio.sleep(0.02)
    raise AssertionError("PostgreSQL clock did not advance past the lease boundary")


async def _wait_for_workflow_lock_wait() -> None:
    for _ in range(250):
        async with engine.connect() as connection:
            waiting = await connection.scalar(
                text(
                    """
                    SELECT EXISTS (
                        SELECT 1
                        FROM pg_stat_activity
                        WHERE datname = current_database()
                          AND pid <> pg_backend_pid()
                          AND wait_event_type = 'Lock'
                          AND query ILIKE '%workflow_runs%'
                    )
                    """
                )
            )
        if waiting is True:
            return
        await asyncio.sleep(0.02)
    raise AssertionError("Completion backend did not enter the workflow lock wait")


async def _recover_one(workflow_id: uuid.UUID):
    async with _isolate_recovery_targets(workflow_id):
        return await workflow_worker.coordinate_one_expired_stage_recovery(
            async_session_factory,
        )


def _locked_table_order(statements: list[str]) -> list[str]:
    ordered: list[str] = []
    for statement in statements:
        if "FOR UPDATE" not in statement:
            continue
        for table in (
            "workflow_runs",
            "stage_runs",
            "outbox_messages",
            "outbox_delivery_attempts",
            "stage_attempts",
        ):
            if f"FROM {table}" in statement:
                ordered.append(table)
                break
    return ordered


async def _assert_nowait_unlocked(
    authority: outbox_runtime.ExecutableStageAuthority,
    *,
    emission_message_ids: tuple[uuid.UUID, ...],
) -> None:
    async with async_session_factory() as db:
        async with db.begin():
            stage_ids = tuple((await db.scalars(select(StageRun.id).where(StageRun.workflow_run_id == authority.workflow_run_id))).all())
            rows = (
                (WorkflowRun, (authority.workflow_run_id,)),
                (StageRun, stage_ids),
                (OutboxMessage, (authority.message_id, *emission_message_ids)),
                (OutboxDeliveryAttempt, (authority.delivery_attempt_id,)),
                (StageAttempt, (authority.stage_attempt_id,)),
            )
            for model, identities in rows:
                for row_id in identities:
                    row = await db.scalar(
                        select(model)
                        .where(model.id == row_id)
                        .execution_options(populate_existing=True, autoflush=False)
                        .with_for_update(nowait=True)
                    )
                    assert row is not None
            await db.execute(text("SET CONSTRAINTS ALL IMMEDIATE"))


@pytest.mark.asyncio
@pytest.mark.parametrize("target_count", [0, 1, 2])
async def test_committed_completion_is_exact_native_fanout_and_releases_every_lock(
    target_count: int,
):
    workflow_id, authority = await _activate(
        f"committed-{target_count}",
        target_count=target_count,
    )
    before_lineage = await _source_lineage_snapshot(authority)
    output = {"claims": target_count + 1, "source_bound": True}
    outcome = "degraded" if target_count == 1 else "succeeded"
    statements: list[str] = []

    def capture(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)

    maker = async_sessionmaker(
        engine,
        class_=_ImmediateConstraintsSession,
        expire_on_commit=False,
    )
    factory = _TrackingFactory(maker)
    _ImmediateConstraintsSession.immediate_checks = 0
    event.listen(engine.sync_engine, "before_cursor_execute", capture)
    try:
        completed = await workflow_worker.coordinate_stage_complete(
            factory,
            authority=authority,
            output_manifest=output,
            outcome=outcome,
        )
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", capture)

    assert completed.disposition == "completed"
    assert completed.should_continue is False
    assert completed.should_ack is True
    assert completed.outcome == outcome
    assert completed.committed_output_checksum == completed.requested_output_checksum
    assert completed.requested_output_checksum == checksum_json(output)
    assert completed.completed_at is not None
    assert completed.stage_state_version == authority.stage_state_version + 1
    assert completed.attempt_state_version == authority.attempt_state_version + 1
    assert len(completed.emissions) == target_count
    assert [item.stage_key for item in completed.emissions] == [f"target_{index + 1}" for index in range(target_count)]
    assert all(item.available_at == completed.completed_at for item in completed.emissions)
    assert factory.active == 0 and factory.exits == 1
    assert _ImmediateConstraintsSession.immediate_checks == 1
    assert _locked_table_order(statements) == [
        "workflow_runs",
        "stage_runs",
        "outbox_messages",
        "outbox_delivery_attempts",
        "stage_attempts",
    ]

    async with async_session_factory() as db:
        workflow = await db.get(WorkflowRun, workflow_id)
        source = await db.get(StageRun, authority.stage_run_id)
        attempt = await db.get(StageAttempt, authority.stage_attempt_id)
        targets = tuple(
            (
                await db.scalars(
                    select(StageRun)
                    .where(
                        StageRun.workflow_run_id == workflow_id,
                        StageRun.stage_key != "collect",
                    )
                    .order_by(StageRun.ordinal.asc())
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
        assert workflow is not None and source is not None and attempt is not None
        assert source.status == attempt.status == outcome
        assert source.output_manifest == output
        assert source.output_checksum == attempt.output_checksum == checksum_json(output)
        assert source.completed_at == attempt.completed_at == completed.completed_at
        assert all(target.status == "ready" for target in targets)
        assert all(target.next_attempt_at == completed.completed_at for target in targets)
        assert len(messages) == target_count
        assert {message.id for message in messages} == {item.message_id for item in completed.emissions}
        assert all(message.causation_id == authority.stage_attempt_id for message in messages)
        assert all(message.available_at == completed.completed_at for message in messages)
        if target_count:
            assert workflow.status == "running"
            assert workflow.state_version == authority.workflow_state_version
            assert workflow.completed_at is None
        else:
            assert workflow.status == outcome
            assert workflow.state_version == authority.workflow_state_version + 1
            assert workflow.completed_at == completed.completed_at

    assert await _source_lineage_snapshot(authority) == before_lineage
    await _assert_nowait_unlocked(
        authority,
        emission_message_ids=tuple(item.message_id for item in completed.emissions),
    )
    await _cancel_if_active(workflow_id, reason="Committed completion cleanup.")


@pytest.mark.asyncio
async def test_failure_after_dependency_message_flush_rolls_back_every_effect():
    workflow_id, authority = await _activate("rollback", target_count=1)
    before = await _graph_snapshot(authority)
    maker = async_sessionmaker(
        engine,
        class_=_FailAfterMessageFlushSession,
        expire_on_commit=False,
    )
    with pytest.raises(_InjectedCompletionFailure):
        await workflow_worker.coordinate_stage_complete(
            maker,
            authority=authority,
            output_manifest={"must": "rollback"},
        )
    assert await _graph_snapshot(authority) == before
    async with async_session_factory() as db:
        count = await db.scalar(
            select(func.count())
            .select_from(OutboxMessage)
            .where(
                OutboxMessage.workflow_run_id == workflow_id,
                OutboxMessage.emission_kind == "dependency_ready",
            )
        )
        assert count == 0
    await _cancel_if_active(workflow_id, reason="Completion rollback cleanup.")


@pytest.mark.asyncio
async def test_concurrent_same_authority_has_one_completion_and_one_stale_result():
    workflow_id, authority = await _activate("concurrent", target_count=1)
    barrier = _AsyncBarrier(2)
    results = await asyncio.gather(
        workflow_worker.coordinate_stage_complete(
            _BarrierFactory(barrier),
            authority=authority,
            output_manifest={"winner": True},
        ),
        workflow_worker.coordinate_stage_complete(
            _BarrierFactory(barrier),
            authority=authority,
            output_manifest={"winner": True},
        ),
    )
    assert sorted(result.disposition for result in results) == ["completed", "stale"]
    winner = next(result for result in results if result.disposition == "completed")
    stale = next(result for result in results if result.disposition == "stale")
    assert len(winner.emissions) == 1
    assert stale.emissions == ()
    assert stale.committed_output_checksum is None
    old_again = await workflow_worker.coordinate_stage_complete(
        async_session_factory,
        authority=authority,
        output_manifest={"winner": True},
    )
    assert old_again.disposition == "stale"
    async with async_session_factory() as db:
        count = await db.scalar(
            select(func.count())
            .select_from(OutboxMessage)
            .where(
                OutboxMessage.workflow_run_id == workflow_id,
                OutboxMessage.emission_kind == "dependency_ready",
            )
        )
        assert count == 1
    await _cancel_if_active(workflow_id, reason="Concurrent completion cleanup.")


@pytest.mark.asyncio
async def test_checkpoint_authority_chains_into_completion_without_changing_source_lineage():
    workflow_id, authority = await _activate("checkpoint-chain", target_count=0)
    before_lineage = await _source_lineage_snapshot(authority)
    checkpoint = await workflow_worker.coordinate_stage_checkpoint(
        async_session_factory,
        authority=authority,
        checkpoint_schema_version="research-stage-checkpoint-v1",
        checkpoint={"cursor": "before-completion"},
        lease_seconds=120,
    )
    assert checkpoint.disposition == "renewed" and checkpoint.authority is not None
    completed = await workflow_worker.coordinate_stage_complete(
        async_session_factory,
        authority=checkpoint.authority,
        output_manifest={"checkpoint_consumed": True},
    )
    assert completed.disposition == "completed"
    assert completed.checkpoint_version == 1
    assert completed.previous_stage_state_version == checkpoint.stage_state_version
    assert completed.previous_attempt_state_version == checkpoint.attempt_state_version
    async with async_session_factory() as db:
        stage = await db.get(StageRun, authority.stage_run_id)
        attempt = await db.get(StageAttempt, authority.stage_attempt_id)
        assert stage is not None and attempt is not None
        assert stage.checkpoint_version == attempt.checkpoint_end_version == 1
        assert stage.status == attempt.status == "succeeded"
    assert await _source_lineage_snapshot(authority) == before_lineage


@pytest.mark.asyncio
async def test_expiry_during_workflow_lock_wait_returns_stale_without_mutation():
    workflow_id, authority = await _activate(
        "lock-expiry",
        target_count=1,
        lease_seconds=2,
    )
    before = await _graph_snapshot(authority)
    blocker = async_session_factory()
    await blocker.begin()
    await blocker.execute(select(WorkflowRun).where(WorkflowRun.id == workflow_id).with_for_update())
    task = asyncio.create_task(
        workflow_worker.coordinate_stage_complete(
            async_session_factory,
            authority=authority,
            output_manifest={"blocked": True},
        )
    )
    try:
        await _wait_for_workflow_lock_wait()
        await _wait_until_db_after(authority.lease_expires_at)
    finally:
        await blocker.rollback()
        await blocker.close()
    stale = await asyncio.wait_for(task, timeout=10)
    assert stale.disposition == "stale"
    assert stale.completed_at is None
    assert stale.committed_output_checksum is None
    assert stale.emissions == ()
    assert await _graph_snapshot(authority) == before
    await _cancel_if_active(workflow_id, reason="Completion expiry cleanup.")


@pytest.mark.asyncio
async def test_recovered_attempt_makes_old_completion_authority_stale():
    workflow_id, authority = await _activate(
        "recovered-stale",
        target_count=1,
        lease_seconds=1,
    )
    await _wait_until_db_after(authority.lease_expires_at)
    recovered = await _recover_one(workflow_id)
    assert recovered is not None
    stale = await workflow_worker.coordinate_stage_complete(
        async_session_factory,
        authority=authority,
        output_manifest={"too_late": True},
    )
    assert stale.disposition == "stale"
    assert stale.completed_at is None
    assert stale.emissions == ()
    async with async_session_factory() as db:
        stage = await db.get(StageRun, authority.stage_run_id)
        attempt = await db.get(StageAttempt, authority.stage_attempt_id)
        assert stage is not None and stage.status == "retry_wait"
        assert attempt is not None and attempt.status == "abandoned"
    await _cancel_if_active(workflow_id, reason="Recovered completion cleanup.")


@pytest.mark.asyncio
async def test_invalid_completion_payload_and_outcome_are_zero_session_activity():
    workflow_id, authority = await _activate("invalid", target_count=0)
    forbidden = _ForbiddenFactory()
    with pytest.raises(workflow_runtime.WorkflowValidation, match="exact JSON object"):
        await workflow_worker.coordinate_stage_complete(
            forbidden,
            authority=authority,
            output_manifest=_HostileOutput(value="hostile"),
        )
    with pytest.raises(workflow_runtime.WorkflowValidation, match=r"U\+0000"):
        await workflow_worker.coordinate_stage_complete(
            forbidden,
            authority=authority,
            output_manifest={"value": "\x00"},
        )
    with pytest.raises(workflow_runtime.WorkflowValidation, match="outcome"):
        await workflow_worker.coordinate_stage_complete(
            forbidden,
            authority=authority,
            output_manifest={},
            outcome="failed",
        )
    assert forbidden.calls == 0
    await _cancel_if_active(workflow_id, reason="Invalid completion cleanup.")


@pytest.mark.asyncio
async def test_direct_workflow_completion_is_fenced_before_sql():
    statements: list[str] = []

    def capture(_connection, _cursor, statement, _parameters, _context, _many):
        statements.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", capture)
    try:
        async with async_session_factory() as db:
            with pytest.raises(
                workflow_runtime.WorkflowConflict,
                match="Direct stage completions are disabled",
            ):
                await workflow_runtime.complete_stage(
                    db,
                    uuid.uuid4(),
                    lease_token=uuid.uuid4(),
                    expected_stage_version=1,
                    expected_attempt_version=1,
                    expected_checkpoint_version=0,
                    output_manifest={},
                )
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", capture)
    assert statements == []


@pytest.mark.asyncio
async def test_database_is_on_exact_contract_phase_revision():
    async with async_session_factory() as db:
        heads = tuple((await db.scalars(text("SELECT version_num FROM alembic_version ORDER BY version_num"))).all())
    assert heads == ("20260824_0004",)
