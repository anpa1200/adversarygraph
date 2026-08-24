"""PostgreSQL acceptance tests for atomic stage-ready reservations.

Run only against a disposable database migrated through revision 0003::

    RUN_POSTGRES_TESTS=1 python -m pytest -q -o addopts='' \
      --confcutdir=tests/postgres \
      tests/postgres/test_outbox_emission_reservation.py

The fixtures create workflow authority directly rather than through
``create_workflow``.  That keeps this primitive-level suite valid after the
workflow service starts atomically emitting its own root-ready fan-out.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import datetime, timedelta
import os
import uuid

import pytest
import pytest_asyncio
from sqlalchemy import event, func, inspect as sa_inspect, select, text

from app.core.database import async_session_factory, engine
from app.models.research_workflow import (
    OutboxDeliveryAttempt,
    OutboxMessage,
    StageAttempt,
    StageRun,
    WorkflowRun,
)
from app.services import outbox_runtime as runtime
from app.services import research_projects as projects
from app.services.workflow_engine import (
    checksum_json,
    deterministic_retry_backoff_seconds,
    normalize_stage_plan,
)


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_POSTGRES_TESTS") != "1",
    reason="requires an explicitly authorized disposable PostgreSQL database",
)

ACTOR = projects.ResearchActor(
    name="PostgreSQL Outbox Emission Reservation Test",
    actor_id="postgres-outbox-emission-reservation",
)


@pytest_asyncio.fixture(autouse=True)
async def _dispose_engine_pool_between_tests():
    await engine.dispose()
    async with engine.connect() as connection:
        revision = await connection.scalar(
            text("SELECT version_num FROM alembic_version"),
        )
    if revision != "20260823_0003":
        pytest.skip(
            "expand-phase reservation primitives require exact revision 0003; revision 0004 requires atomic public workflow coordinators",
        )
    try:
        yield
    finally:
        await engine.dispose()


def _spec(label: str) -> dict:
    return {
        "objective": f"Validate atomic outbox emission reservation: {label}.",
        "intelligence_requirements": ["Does each durable stage transition have exact broker authority?"],
        "output_targets": ["canonical_intelligence"],
        "tlp": "TLP:AMBER",
    }


def _stage_definition(
    stage_key: str,
    ordinal: int,
    *,
    depends_on: list[str] | None = None,
    max_attempts: int = 3,
) -> dict:
    return {
        "stage_key": stage_key,
        "stage_type": f"test.{stage_key}",
        "stage_version": "1.0.0",
        "ordinal": ordinal,
        "depends_on": depends_on or [],
        "required": True,
        "priority": 0,
        "max_attempts": max_attempts,
        "config_schema_version": "research-stage-config-v1",
        "checkpoint_schema_version": "research-stage-checkpoint-v1",
        "config": {"acceptance_test": True},
        "retry_policy": {
            "base_delay_seconds": 1,
            "max_delay_seconds": 1,
            "jitter_percent": 0,
        },
    }


async def _new_workflow(label: str, stage_plan: list[dict]) -> uuid.UUID:
    """Insert pristine W/S authority without invoking future emission wiring."""

    normalized = normalize_stage_plan(stage_plan)
    input_manifest = {"report_id": label}
    input_checksum = checksum_json(input_manifest)
    empty_checksum = checksum_json({})
    async with async_session_factory() as db:
        _, revision = await projects.create_project(
            db,
            ACTOR,
            project_key=f"emission-{label.replace('_', '-')}-{uuid.uuid4().hex[:12]}",
            name=f"Outbox emission {label}",
            description="Disposable PostgreSQL outbox emission acceptance authority.",
            spec=_spec(label),
        )
        workflow = WorkflowRun(
            id=uuid.uuid4(),
            project_revision_id=revision.id,
            replay_of_run_id=None,
            workflow_type="cti.report",
            status="queued",
            trigger_type="api",
            idempotency_key=checksum_json({"label": label, "nonce": uuid.uuid4().hex}),
            correlation_id=uuid.uuid4(),
            input_manifest=input_manifest,
            input_checksum=input_checksum,
            stage_plan=normalized.as_payload(),
            plan_checksum=normalized.checksum,
            priority=0,
            state_version=1,
            status_reason_code="",
            status_summary="",
            created_by=ACTOR.name,
            created_by_id=ACTOR.actor_id,
            cancel_requested_by="",
            cancel_requested_by_id="",
            cancel_reason="",
            cancel_requested_at=None,
            started_at=None,
            completed_at=None,
        )
        db.add(workflow)
        await db.flush([workflow])
        now = await db.scalar(select(func.transaction_timestamp()))
        assert isinstance(now, datetime) and now.tzinfo is not None
        for definition in normalized.stages:
            stage_input = definition.input_manifest if definition.input_manifest is not None else input_manifest
            stage = StageRun(
                id=uuid.uuid4(),
                workflow_run_id=workflow.id,
                stage_key=definition.stage_key,
                stage_type=definition.stage_type,
                stage_version=definition.stage_version,
                ordinal=definition.ordinal,
                status="ready" if not definition.depends_on else "pending",
                priority=definition.priority,
                state_version=1,
                idempotency_key=checksum_json({"workflow_run_id": str(workflow.id), "stage_key": definition.stage_key}),
                depends_on=list(definition.depends_on),
                required=definition.required,
                config_schema_version=definition.config_schema_version,
                config=dict(definition.config),
                config_checksum=checksum_json(definition.config),
                input_manifest=dict(stage_input),
                input_checksum=checksum_json(stage_input),
                output_manifest={},
                output_checksum="",
                checkpoint={},
                checkpoint_schema_version=definition.checkpoint_schema_version,
                checkpoint_version=0,
                checkpoint_checksum=empty_checksum,
                attempt_count=0,
                max_attempts=definition.max_attempts,
                next_attempt_at=now if not definition.depends_on else None,
                lease_owner="",
                lease_token=None,
                leased_at=None,
                lease_expires_at=None,
                heartbeat_at=None,
                last_error_code="",
                last_error_summary="",
                last_error_retryable=False,
                first_started_at=None,
                completed_at=None,
            )
            db.add(stage)
        await db.flush()
        workflow_id = uuid.UUID(str(workflow.id))
        await db.commit()
        return workflow_id


async def _lock_graph(db, workflow_id: uuid.UUID) -> tuple[WorkflowRun, tuple[StageRun, ...]]:
    workflow = await db.scalar(
        select(WorkflowRun)
        .where(WorkflowRun.id == workflow_id)
        .execution_options(populate_existing=True, autoflush=False)
        .with_for_update()
    )
    assert workflow is not None
    stages = tuple(
        (
            await db.scalars(
                select(StageRun)
                .where(StageRun.workflow_run_id == workflow.id)
                .order_by(StageRun.ordinal.asc(), StageRun.id.asc())
                .execution_options(populate_existing=True, autoflush=False)
                .with_for_update()
            )
        ).all()
    )
    assert len(stages) == len(workflow.stage_plan)
    return workflow, stages


def _root_intents(workflow: WorkflowRun, stages: tuple[StageRun, ...]) -> tuple[runtime.StageReadyIntent, ...]:
    roots = tuple(stage for stage in stages if not stage.depends_on)
    return tuple(
        runtime.project_stage_ready_intent(
            workflow,
            stage,
            emission_kind="root_ready",
            post_status="ready",
            post_state_version=stage.state_version,
            post_next_attempt_at=stage.next_attempt_at,
            target_attempt_number=1,
        )
        for stage in roots
    )


async def _reserve_roots(db, workflow_id: uuid.UUID):
    workflow, stages = await _lock_graph(db, workflow_id)
    targets = tuple(stage for stage in stages if not stage.depends_on)
    reservation = await runtime.reserve_stage_ready_intents(
        db,
        workflow=workflow,
        locked_stages=stages,
        target_stages=targets,
        intents=_root_intents(workflow, stages),
    )
    return workflow, stages, reservation


async def _message_count(workflow_id: uuid.UUID) -> int:
    async with async_session_factory() as db:
        value = await db.scalar(select(func.count()).select_from(OutboxMessage).where(OutboxMessage.workflow_run_id == workflow_id))
        return int(value or 0)


async def _activate_stage(
    workflow_id: uuid.UUID,
    stage_key: str,
    *,
    lease_duration: timedelta = timedelta(minutes=5),
) -> tuple[uuid.UUID, datetime]:
    """Create expand-phase running A authority without an outbox receipt link."""

    async with async_session_factory() as db:
        workflow, stages = await _lock_graph(db, workflow_id)
        stage = next(candidate for candidate in stages if candidate.stage_key == stage_key)
        assert stage.status == "ready"
        now = await db.scalar(select(func.transaction_timestamp()))
        assert isinstance(now, datetime) and now.tzinfo is not None
        lease_expires_at = now + lease_duration
        lease_token = uuid.uuid4()
        if workflow.status == "queued":
            workflow.status = "running"
            workflow.state_version += 1
            workflow.started_at = now
        stage.status = "running"
        stage.state_version += 1
        stage.attempt_count += 1
        stage.next_attempt_at = None
        stage.lease_owner = "postgres-emission-worker"
        stage.lease_token = lease_token
        stage.leased_at = now
        stage.heartbeat_at = now
        stage.lease_expires_at = lease_expires_at
        stage.first_started_at = now
        await db.flush([workflow, stage])
        attempt = StageAttempt(
            id=uuid.uuid4(),
            stage_run_id=stage.id,
            outbox_delivery_attempt_id=None,
            attempt_number=1,
            lease_token=lease_token,
            lease_owner=stage.lease_owner,
            delivery_id=f"expand-phase-{uuid.uuid4().hex}",
            status="running",
            state_version=1,
            input_checksum=stage.input_checksum,
            checkpoint_start_version=0,
            checkpoint_end_version=0,
            output_checksum="",
            error_code="",
            error_class="",
            error_summary="",
            retryable=False,
            started_at=now,
            heartbeat_at=now,
            lease_expires_at=lease_expires_at,
            completed_at=None,
        )
        db.add(attempt)
        await db.flush([attempt])
        attempt_id = uuid.UUID(str(attempt.id))
        await db.commit()
        return attempt_id, lease_expires_at


def _clear_stage_lease(stage: StageRun) -> None:
    stage.lease_owner = ""
    stage.lease_token = None
    stage.leased_at = None
    stage.lease_expires_at = None
    stage.heartbeat_at = None


async def _wait_for_backend_lock(pid: int) -> None:
    for _ in range(200):
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
        if isinstance(now, datetime) and now > moment:
            return
        await asyncio.sleep(0.02)
    raise AssertionError("PostgreSQL clock did not advance past the stage lease")


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


async def _claim_exact_messages(message_ids: set[uuid.UUID]) -> dict[uuid.UUID, runtime.ClaimedOutboxDelivery]:
    claims: dict[uuid.UUID, runtime.ClaimedOutboxDelivery] = {}
    async with _isolate_outbox_queue(message_ids):
        for ordinal in range(len(message_ids)):
            async with async_session_factory() as db:
                claim = await runtime.claim_outbox_delivery(
                    db,
                    publisher_id=f"postgres-emission-publisher-{ordinal}",
                    lease_seconds=120,
                )
                assert claim is not None and claim.message_id in message_ids - claims.keys()
                claims[claim.message_id] = claim
                await db.commit()
    assert set(claims) == message_ids
    return claims


@pytest.mark.asyncio
async def test_root_full_fanout_commit_rollback_and_uncommitted_invisibility():
    await engine.dispose()
    plan = [
        _stage_definition("collect_alpha", 1),
        _stage_definition("collect_bravo", 2),
        _stage_definition("merge", 3, depends_on=["collect_alpha", "collect_bravo"]),
    ]
    committed_id = await _new_workflow("root-fanout-commit", plan)
    rolled_back_id = await _new_workflow("root-fanout-rollback", plan)

    async with async_session_factory() as writer:
        workflow, stages, reservation = await _reserve_roots(writer, committed_id)
        results = await runtime.append_reserved_stage_ready(
            writer,
            reservation=reservation,
            workflow=workflow,
            locked_stages=stages,
        )
        assert len(results) == 2 and all(created for _, created in results)
        message_ids = {uuid.UUID(str(message.id)) for message, _ in results}
        async with async_session_factory() as observer:
            visible = await observer.scalar(select(func.count()).select_from(OutboxMessage).where(OutboxMessage.id.in_(message_ids)))
            assert visible == 0
        await writer.commit()

    async with async_session_factory() as db:
        messages = tuple(
            (
                await db.scalars(
                    select(OutboxMessage).where(OutboxMessage.workflow_run_id == committed_id).order_by(OutboxMessage.logical_key.asc())
                )
            ).all()
        )
        assert len(messages) == 2
        assert {message.emission_kind for message in messages} == {"root_ready"}
        assert {message.causation_id for message in messages} == {None}
        assert {message.status for message in messages} == {"pending"}
        assert {message.aggregate_version for message in messages} == {1}

    async with async_session_factory() as writer:
        workflow, stages, reservation = await _reserve_roots(writer, rolled_back_id)
        results = await runtime.append_reserved_stage_ready(
            writer,
            reservation=reservation,
            workflow=workflow,
            locked_stages=stages,
        )
        assert len(results) == 2
        await writer.rollback()
    assert await _message_count(rolled_back_id) == 0
    await engine.dispose()


@pytest.mark.asyncio
async def test_forged_and_second_append_are_rejected_without_duplicate_effect():
    await engine.dispose()
    workflow_id = await _new_workflow("single-use-capability", [_stage_definition("collect", 1)])
    async with async_session_factory() as db:
        workflow, stages, reservation = await _reserve_roots(db, workflow_id)
        forged = replace(reservation)
        with pytest.raises(runtime.OutboxConflict, match="capability"):
            await runtime.append_reserved_stage_ready(
                db,
                reservation=forged,
                workflow=workflow,
                locked_stages=stages,
            )
        assert not db.new

        ((message, created),) = await runtime.append_reserved_stage_ready(
            db,
            reservation=reservation,
            workflow=workflow,
            locked_stages=stages,
        )
        assert created is True
        with pytest.raises(runtime.OutboxConflict, match="capability"):
            await runtime.append_reserved_stage_ready(
                db,
                reservation=reservation,
                workflow=workflow,
                locked_stages=stages,
            )
        assert message in db.identity_map.values()
        same_transaction_count = await db.scalar(
            select(func.count()).select_from(OutboxMessage).where(OutboxMessage.workflow_run_id == workflow_id)
        )
        assert same_transaction_count == 1
        await db.commit()
    assert await _message_count(workflow_id) == 1
    await engine.dispose()


@pytest.mark.asyncio
async def test_nested_savepoint_rejection_and_root_rollback_lose_reservation_fence():
    await engine.dispose()
    workflow_id = await _new_workflow("transaction-fence", [_stage_definition("collect", 1)])
    async with async_session_factory() as db:
        workflow, stages = await _lock_graph(db, workflow_id)
        roots = tuple(stage for stage in stages if not stage.depends_on)
        intents = _root_intents(workflow, stages)
        nested = await db.begin_nested()
        with pytest.raises(runtime.OutboxConflict, match="nested transaction"):
            await runtime.reserve_stage_ready_intents(
                db,
                workflow=workflow,
                locked_stages=stages,
                target_stages=roots,
                intents=intents,
            )
        await nested.rollback()

        reservation = await runtime.reserve_stage_ready_intents(
            db,
            workflow=workflow,
            locked_stages=stages,
            target_stages=roots,
            intents=intents,
        )
        await db.rollback()

        next_workflow, next_stages = await _lock_graph(db, workflow_id)
        with pytest.raises(runtime.OutboxConflict, match="capability|transaction"):
            await runtime.append_reserved_stage_ready(
                db,
                reservation=reservation,
                workflow=next_workflow,
                locked_stages=next_stages,
            )
        await db.rollback()
    assert await _message_count(workflow_id) == 0
    await engine.dispose()


@pytest.mark.asyncio
async def test_second_fanout_member_tamper_has_no_partial_session_or_database_message():
    await engine.dispose()
    workflow_id = await _new_workflow(
        "fanout-tamper",
        [_stage_definition("collect_alpha", 1), _stage_definition("collect_bravo", 2)],
    )
    async with async_session_factory() as db:
        workflow, stages, reservation = await _reserve_roots(db, workflow_id)
        by_id = {uuid.UUID(str(stage.id)): stage for stage in stages}
        second_target = by_id[reservation.intents[1].post_target.stage_run_id]
        second_target.__dict__["next_attempt_at"] += timedelta(seconds=1)
        with pytest.raises(runtime.OutboxConflict, match="post projection"):
            await runtime.append_reserved_stage_ready(
                db,
                reservation=reservation,
                workflow=workflow,
                locked_stages=stages,
            )
        assert not any(isinstance(item, OutboxMessage) for item in db.new)
        async with async_session_factory() as observer:
            observed = await observer.scalar(
                select(func.count()).select_from(OutboxMessage).where(OutboxMessage.workflow_run_id == workflow_id)
            )
            assert observed == 0
        await db.rollback()
    assert await _message_count(workflow_id) == 0
    await engine.dispose()


@pytest.mark.asyncio
async def test_append_rejects_expired_sealed_stage_field_without_message_effect():
    await engine.dispose()
    workflow_id = await _new_workflow("expired-sealed-field", [_stage_definition("collect", 1)])
    async with async_session_factory() as db:
        workflow, stages, reservation = await _reserve_roots(db, workflow_id)
        stage = stages[0]
        db.sync_session.expire(stage, ["status"])
        assert "status" in sa_inspect(stage).expired_attributes

        with pytest.raises(runtime.OutboxConflict, match="clean persistent"):
            await runtime.append_reserved_stage_ready(
                db,
                reservation=reservation,
                workflow=workflow,
                locked_stages=stages,
            )
        assert not any(isinstance(item, OutboxMessage) for item in db.new)
        await db.rollback()
    assert await _message_count(workflow_id) == 0
    await engine.dispose()


@pytest.mark.asyncio
async def test_exact_dependency_fanout_is_atomic_and_shares_terminal_causation():
    await engine.dispose()
    workflow_id = await _new_workflow(
        "dependency-fanout",
        [
            _stage_definition("collect", 1),
            _stage_definition("extract", 2, depends_on=["collect"]),
            _stage_definition("enrich", 3, depends_on=["collect"]),
        ],
    )
    attempt_id, _ = await _activate_stage(workflow_id, "collect")
    output_manifest = {"observables": ["example.test"]}
    output_checksum = checksum_json(output_manifest)

    async with async_session_factory() as db:
        workflow, stages = await _lock_graph(db, workflow_id)
        source = next(stage for stage in stages if stage.stage_key == "collect")
        targets = tuple(stage for stage in stages if stage.stage_key in {"extract", "enrich"})
        available_at = await db.scalar(select(func.transaction_timestamp()))
        assert isinstance(available_at, datetime) and available_at.tzinfo is not None
        intents = tuple(
            runtime.project_stage_ready_intent(
                workflow,
                target,
                emission_kind="dependency_ready",
                post_status="ready",
                post_state_version=target.state_version + 1,
                post_next_attempt_at=available_at,
                target_attempt_number=1,
                causal_stage=source,
            )
            for target in targets
        )
        reservation = await runtime.reserve_stage_ready_intents(
            db,
            workflow=workflow,
            locked_stages=stages,
            target_stages=targets,
            intents=intents,
        )
        attempt = await db.scalar(
            select(StageAttempt)
            .where(StageAttempt.id == attempt_id)
            .execution_options(populate_existing=True, autoflush=False)
            .with_for_update()
        )
        assert attempt is not None
        attempt.status = "succeeded"
        attempt.state_version += 1
        attempt.output_checksum = output_checksum
        attempt.heartbeat_at = available_at
        attempt.completed_at = available_at
        await db.flush([attempt])

        source.status = "succeeded"
        source.state_version += 1
        source.output_manifest = output_manifest
        source.output_checksum = output_checksum
        source.completed_at = available_at
        _clear_stage_lease(source)
        for target in targets:
            target.status = "ready"
            target.state_version += 1
            target.next_attempt_at = available_at
        await db.flush([source, *targets])
        for stage in (source, *targets):
            state = sa_inspect(stage)
            assert state.modified is False
            assert "updated_at" in state.expired_attributes

        append_sql: list[str] = []

        def capture_append_sql(_connection, _cursor, statement, _parameters, _context, _executemany):
            append_sql.append(statement)

        event.listen(engine.sync_engine, "before_cursor_execute", capture_append_sql)
        try:
            results = await runtime.append_reserved_stage_ready(
                db,
                reservation=reservation,
                workflow=workflow,
                locked_stages=stages,
                causal_attempt=attempt,
            )
        finally:
            event.remove(engine.sync_engine, "before_cursor_execute", capture_append_sql)
        assert append_sql
        assert not any(statement.lstrip().upper().startswith("SELECT") for statement in append_sql)
        assert len(results) == 2 and all(created for _, created in results)
        await db.commit()

    async with async_session_factory() as db:
        messages = tuple(
            (
                await db.scalars(
                    select(OutboxMessage).where(OutboxMessage.workflow_run_id == workflow_id).order_by(OutboxMessage.logical_key.asc())
                )
            ).all()
        )
        assert len(messages) == 2
        assert {message.stage_key for message in messages} == {"extract", "enrich"}
        assert {message.causation_id for message in messages} == {attempt_id}
        assert {message.available_at for message in messages} == {available_at}
        assert {message.aggregate_version for message in messages} == {2}
    await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("emission_kind", "attempt_status", "error_code", "error_class", "error_summary", "lease_duration"),
    [
        (
            "retry_scheduled",
            "failed",
            "stage.retryable",
            "RetryableTestError",
            "Retryable deterministic stage failure",
            timedelta(minutes=5),
        ),
        (
            "lease_recovered",
            "abandoned",
            "workflow.lease_expired",
            "LeaseExpired",
            "Worker lease expired before the attempt reached a terminal outcome",
            timedelta(milliseconds=50),
        ),
    ],
)
async def test_retry_and_recovery_bind_exact_schedule_and_terminal_cause(
    emission_kind: str,
    attempt_status: str,
    error_code: str,
    error_class: str,
    error_summary: str,
    lease_duration: timedelta,
):
    await engine.dispose()
    workflow_id = await _new_workflow(f"{emission_kind}-schedule", [_stage_definition("collect", 1)])
    attempt_id, lease_expires_at = await _activate_stage(
        workflow_id,
        "collect",
        lease_duration=lease_duration,
    )
    if emission_kind == "lease_recovered":
        await _wait_until_db_after(lease_expires_at)

    async with async_session_factory() as db:
        workflow, stages = await _lock_graph(db, workflow_id)
        stage = stages[0]
        transaction_now = await db.scalar(select(func.transaction_timestamp()))
        assert isinstance(transaction_now, datetime) and transaction_now.tzinfo is not None
        definition = next(
            definition for definition in normalize_stage_plan(workflow.stage_plan).stages if definition.stage_key == stage.stage_key
        )
        retry_delay = deterministic_retry_backoff_seconds(
            stage.attempt_count,
            seed=str(stage.id),
            policy=definition.retry_policy,
        )
        available_at = transaction_now + timedelta(seconds=retry_delay)
        intent = runtime.project_stage_ready_intent(
            workflow,
            stage,
            emission_kind=emission_kind,
            post_status="retry_wait",
            post_state_version=stage.state_version + 1,
            post_next_attempt_at=available_at,
            target_attempt_number=2,
            post_error_code=error_code,
            post_error_summary=error_summary,
            post_error_retryable=True,
            causal_stage=stage,
        )
        reservation = await runtime.reserve_stage_ready_intents(
            db,
            workflow=workflow,
            locked_stages=stages,
            target_stages=(stage,),
            intents=(intent,),
        )
        attempt = await db.scalar(
            select(StageAttempt)
            .where(StageAttempt.id == attempt_id)
            .execution_options(populate_existing=True, autoflush=False)
            .with_for_update()
        )
        assert attempt is not None
        attempt.status = attempt_status
        attempt.state_version += 1
        attempt.output_checksum = ""
        attempt.error_code = error_code
        attempt.error_class = error_class
        attempt.error_summary = error_summary
        attempt.retryable = True
        if emission_kind == "retry_scheduled":
            attempt.heartbeat_at = transaction_now
        attempt.completed_at = transaction_now
        await db.flush([attempt])

        stage.status = "retry_wait"
        stage.state_version += 1
        stage.output_manifest = {}
        stage.output_checksum = ""
        stage.last_error_code = error_code
        stage.last_error_summary = error_summary
        stage.last_error_retryable = True
        stage.next_attempt_at = available_at
        stage.completed_at = None
        _clear_stage_lease(stage)
        await db.flush([stage])
        ((message, created),) = await runtime.append_reserved_stage_ready(
            db,
            reservation=reservation,
            workflow=workflow,
            locked_stages=stages,
            causal_attempt=attempt,
        )
        assert created is True
        message_id = uuid.UUID(str(message.id))
        await db.commit()

    async with async_session_factory() as db:
        message = await db.get(OutboxMessage, message_id)
        assert message is not None
        assert message.emission_kind == emission_kind
        assert message.causation_id == attempt_id
        assert message.available_at == available_at
        assert message.target_attempt_number == 2
        assert message.aggregate_version == 3
    await engine.dispose()


@pytest.mark.asyncio
async def test_two_concurrent_root_reservations_serialize_to_one_atomic_fanout():
    await engine.dispose()
    workflow_id = await _new_workflow(
        "concurrent-root-reserve",
        [_stage_definition("collect_alpha", 1), _stage_definition("collect_bravo", 2)],
    )
    first_flushed = asyncio.Event()
    release_first = asyncio.Event()
    pid_queue: asyncio.Queue[int] = asyncio.Queue()

    async def first_writer() -> tuple[uuid.UUID, ...]:
        async with async_session_factory() as db:
            workflow, stages, reservation = await _reserve_roots(db, workflow_id)
            results = await runtime.append_reserved_stage_ready(
                db,
                reservation=reservation,
                workflow=workflow,
                locked_stages=stages,
            )
            first_flushed.set()
            await asyncio.wait_for(release_first.wait(), timeout=10)
            await db.commit()
            return tuple(uuid.UUID(str(message.id)) for message, _ in results)

    async def second_writer() -> str:
        await asyncio.wait_for(first_flushed.wait(), timeout=10)
        async with async_session_factory() as db:
            pid = await db.scalar(text("SELECT pg_backend_pid()"))
            assert isinstance(pid, int)
            await pid_queue.put(pid)
            try:
                workflow, stages, reservation = await _reserve_roots(db, workflow_id)
                await runtime.append_reserved_stage_ready(
                    db,
                    reservation=reservation,
                    workflow=workflow,
                    locked_stages=stages,
                )
            except runtime.OutboxConflict:
                await db.rollback()
                return "conflict"
            await db.commit()
            return "unexpected-success"

    first_task = asyncio.create_task(first_writer())
    second_task = asyncio.create_task(second_writer())
    pid = await asyncio.wait_for(pid_queue.get(), timeout=10)
    await _wait_for_backend_lock(pid)
    release_first.set()
    first_ids, second_result = await asyncio.wait_for(asyncio.gather(first_task, second_task), timeout=15)
    assert len(first_ids) == 2
    assert second_result == "conflict"
    assert await _message_count(workflow_id) == 2
    await engine.dispose()


@pytest.mark.asyncio
async def test_reservation_locks_all_messages_before_any_active_delivery():
    await engine.dispose()
    workflow_id = await _new_workflow(
        "message-before-delivery-locks",
        [_stage_definition("collect_alpha", 1), _stage_definition("collect_bravo", 2)],
    )
    async with async_session_factory() as db:
        workflow, stages, reservation = await _reserve_roots(db, workflow_id)
        results = await runtime.append_reserved_stage_ready(
            db,
            reservation=reservation,
            workflow=workflow,
            locked_stages=stages,
        )
        message_ids = {uuid.UUID(str(message.id)) for message, _ in results}
        await db.commit()
    claims = await _claim_exact_messages(message_ids)

    async with async_session_factory() as db:
        ordered_messages = tuple(
            (
                await db.scalars(select(OutboxMessage).where(OutboxMessage.id.in_(message_ids)).order_by(OutboxMessage.logical_key.asc()))
            ).all()
        )
        assert len(ordered_messages) == 2
        first_message, second_message = ordered_messages
        first_delivery_id = claims[uuid.UUID(str(first_message.id))].delivery_attempt_id

    pid_queue: asyncio.Queue[int] = asyncio.Queue()

    async def reserve_replay() -> tuple[bool, ...]:
        async with async_session_factory() as db:
            pid = await db.scalar(text("SELECT pg_backend_pid()"))
            assert isinstance(pid, int)
            await pid_queue.put(pid)
            workflow, stages = await _lock_graph(db, workflow_id)
            targets = tuple(stage for stage in stages if not stage.depends_on)
            intents = tuple(replace(intent, projection_mode="current") for intent in _root_intents(workflow, stages))
            reservation = await runtime.reserve_stage_ready_intents(
                db,
                workflow=workflow,
                locked_stages=stages,
                target_stages=targets,
                intents=intents,
            )
            results = await runtime.append_reserved_stage_ready(
                db,
                reservation=reservation,
                workflow=workflow,
                locked_stages=stages,
            )
            await db.commit()
            return tuple(created for _, created in results)

    async with async_session_factory() as holder:
        locked_second = await holder.scalar(select(OutboxMessage).where(OutboxMessage.id == second_message.id).with_for_update())
        assert locked_second is not None
        reserve_task = asyncio.create_task(reserve_replay())
        pid = await asyncio.wait_for(pid_queue.get(), timeout=10)
        await _wait_for_backend_lock(pid)

        async with async_session_factory() as probe:
            first_delivery = await probe.scalar(
                select(OutboxDeliveryAttempt).where(OutboxDeliveryAttempt.id == first_delivery_id).with_for_update(nowait=True)
            )
            assert first_delivery is not None
            await probe.rollback()
        await holder.rollback()

    created_flags = await asyncio.wait_for(reserve_task, timeout=10)
    assert created_flags == (False, False)
    await engine.dispose()
