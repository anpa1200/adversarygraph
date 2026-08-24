from __future__ import annotations

import ast
import asyncio
import copy
import inspect
import uuid
from collections import deque
from dataclasses import FrozenInstanceError, fields, replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.models.research_workflow import (
    OutboxDeliveryAttempt,
    OutboxMessage,
    StageAttempt,
    StageRun,
    WorkflowRun,
)
from app.services import workflow_worker as worker
from app.services.outbox_runtime import (
    ExecutableStageAuthority,
    LockedStageExecutionReceipt,
    OutboxLeaseLost,
    OutboxStoredContractError,
    OutboxValidation,
    StageFailureEvidence,
)
from app.services.workflow_engine import checksum_json, sanitize_workflow_error
from app.services.workflow_runtime import (
    WorkflowCheckpointConflict,
    WorkflowStoredContractError,
    WorkflowValidation,
)


NOW = datetime(2026, 8, 23, 15, 0, tzinfo=timezone.utc)
CHECKPOINT_SCHEMA = "research-stage-checkpoint-v1"


class _ForeignCompletionReceiptLeaseLost(OutboxLeaseLost):
    """Hostile lookalike for the retired module-global completion tag."""


class _PersistedUUID(uuid.UUID):
    """Stand-in for asyncpg's UUID subtype on ORM-loaded columns."""


def _case(*, lease_expires_at: datetime | None = None):
    expiry = lease_expires_at or NOW + timedelta(seconds=30)
    workflow = WorkflowRun(id=uuid.uuid4(), state_version=2)
    stage = StageRun(
        id=uuid.uuid4(),
        workflow_run_id=workflow.id,
        stage_key="collect",
        state_version=2,
        lease_token=uuid.uuid4(),
        lease_owner="worker-1",
        input_checksum="b" * 64,
        checkpoint_version=0,
        checkpoint_schema_version="research-stage-checkpoint-v1",
        checkpoint={},
        checkpoint_checksum=checksum_json({}),
        heartbeat_at=NOW - timedelta(seconds=10),
        lease_expires_at=expiry,
    )
    message = OutboxMessage(id=uuid.uuid4())
    delivery = OutboxDeliveryAttempt(
        id=uuid.uuid4(),
        delivery_cycle=1,
        cycle_key="a" * 64,
        broker_receipt_id="c" * 64,
    )
    attempt = StageAttempt(
        id=uuid.uuid4(),
        stage_run_id=stage.id,
        outbox_delivery_attempt_id=delivery.id,
        attempt_number=1,
        lease_token=stage.lease_token,
        lease_owner=stage.lease_owner,
        state_version=1,
        checkpoint_start_version=0,
        checkpoint_end_version=0,
        heartbeat_at=stage.heartbeat_at,
        lease_expires_at=expiry,
    )
    authority = ExecutableStageAuthority(
        workflow_run_id=workflow.id,
        stage_run_id=stage.id,
        stage_attempt_id=attempt.id,
        message_id=message.id,
        delivery_attempt_id=delivery.id,
        stage_lease_token=stage.lease_token,
        workflow_state_version=workflow.state_version,
        stage_state_version=stage.state_version,
        attempt_state_version=attempt.state_version,
        attempt_number=1,
        delivery_cycle=1,
        cycle_key="a" * 64,
        stage_key=stage.stage_key,
        input_checksum="b" * 64,
        checkpoint_version=0,
        lease_owner=stage.lease_owner,
        lease_expires_at=expiry,
        broker_receipt_id="c" * 64,
    )
    return workflow, stage, message, delivery, attempt, authority


def _column_snapshot(value: object) -> tuple[tuple[str, object], ...]:
    return tuple((column.key, copy.deepcopy(getattr(value, column.key))) for column in type(value).__table__.columns)


def _restore(value: object, snapshot: tuple[tuple[str, object], ...]) -> None:
    for key, field_value in snapshot:
        setattr(value, key, copy.deepcopy(field_value))


def _changed_columns(
    before: tuple[tuple[str, object], ...],
    after: tuple[tuple[str, object], ...],
) -> set[str]:
    return {before_item[0] for before_item, after_item in zip(before, after, strict=True) if before_item != after_item}


class _TransactionContext:
    def __init__(self, session: _Session):
        self.session = session
        self.root = object()
        self.snapshots = [(value, _column_snapshot(value)) for value in session.tracked]
        self.initial_flush_count = len(session.flushes)

    async def __aenter__(self):
        self.session.root_transaction = self.root
        self.session.events.append(f"{self.session.name}:tx_enter")
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        del exc, traceback
        failure = exc_type is not None or self.session.commit_error is not None
        if failure and len(self.session.flushes) > self.initial_flush_count:
            for value, snapshot in self.snapshots:
                _restore(value, snapshot)
        if failure:
            self.session.events.append(f"{self.session.name}:rollback")
        else:
            self.session.events.append(f"{self.session.name}:commit")
            if self.session.on_commit is not None:
                self.session.on_commit(self.session)
        self.session.root_transaction = None
        self.session.events.append(f"{self.session.name}:tx_exit")
        if self.session.on_transaction_exit is not None:
            self.session.on_transaction_exit(self.session)
        if exc_type is None and self.session.commit_error is not None:
            raise self.session.commit_error
        return False


class _Session:
    def __init__(
        self,
        name: str,
        events: list[str],
        tracked: tuple[object, ...],
        *,
        flush_error_at: int | None = None,
        commit_error: Exception | None = None,
        enter_error: Exception | None = None,
        exit_error: Exception | None = None,
        on_commit=None,
        on_transaction_exit=None,
    ):
        self.name = name
        self.events = events
        self.tracked = tracked
        self.flush_error_at = flush_error_at
        self.commit_error = commit_error
        self.enter_error = enter_error
        self.exit_error = exit_error
        self.on_commit = on_commit
        self.on_transaction_exit = on_transaction_exit
        self.sync_session = self
        self.root_transaction = None
        self.nested_transaction = None
        self.flushes: list[tuple[tuple[str, object], ...]] = []
        self.commit_calls = 0

    async def __aenter__(self):
        self.events.append(f"{self.name}:session_enter")
        if self.enter_error is not None:
            raise self.enter_error
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        del exc_type, exc, traceback
        self.events.append(f"{self.name}:session_exit")
        if self.exit_error is not None:
            raise self.exit_error
        return False

    def begin(self):
        return _TransactionContext(self)

    def get_transaction(self):
        return self.root_transaction

    def get_nested_transaction(self):
        return self.nested_transaction

    def in_nested_transaction(self):
        return self.nested_transaction is not None

    async def flush(self, objects=None):
        values = tuple(objects or ())
        self.events.append(f"{self.name}:flush:{type(values[0]).__name__}")
        self.flushes.append(tuple(_column_snapshot(value) for value in values))
        if self.flush_error_at == len(self.flushes):
            raise RuntimeError(f"{self.name} flush failed")

    async def commit(self):  # pragma: no cover - failure sentinel
        self.commit_calls += 1
        raise AssertionError("workflow worker must never manually commit")


class _Factory:
    def __init__(self, sessions=(), *, error: Exception | None = None):
        self.sessions = deque(sessions)
        self.error = error
        self.calls = 0

    def __call__(self):
        self.calls += 1
        if self.error is not None:
            raise self.error
        assert self.sessions, "unexpected session factory call"
        return self.sessions.popleft()


def _sessions(
    rows: tuple[object, ...],
    *,
    events: list[str] | None = None,
    mutation_options: dict | None = None,
    confirmation_options: dict | None = None,
):
    ordered_events = [] if events is None else events
    mutation = _Session(
        "mutation",
        ordered_events,
        rows,
        **(mutation_options or {}),
    )
    confirmation = _Session(
        "confirmation",
        ordered_events,
        rows,
        **(confirmation_options or {}),
    )
    return _Factory([mutation, confirmation]), mutation, confirmation, ordered_events


def _install_receipt_runtime(
    monkeypatch,
    rows: tuple[WorkflowRun, StageRun, OutboxMessage, OutboxDeliveryAttempt, StageAttempt],
    *,
    observed=(NOW, NOW + timedelta(microseconds=1)),
    reserve_effects=(),
):
    workflow, stage, message, delivery, attempt = rows
    observed_values = deque(observed)
    effects = deque(reserve_effects)
    calls: list[tuple[str, object, ExecutableStageAuthority]] = []
    reservations: dict[int, object] = {}

    async def reserve(db, *, authority):
        calls.append(("reserve", db, authority))
        if effects:
            effect = effects.popleft()
            if isinstance(effect, Exception):
                raise effect
        reservation = object()
        reservations[id(reservation)] = reservation
        return reservation

    async def consume(db, *, reservation, authority):
        calls.append(("consume", db, authority))
        assert reservations.pop(id(reservation)) is reservation
        assert observed_values
        return LockedStageExecutionReceipt(
            authority=authority,
            workflow=workflow,
            stage=stage,
            message=message,
            delivery=delivery,
            attempt=attempt,
            observed_at=observed_values.popleft(),
        )

    monkeypatch.setattr(worker, "_reserve_stage_execution_receipt", reserve)
    monkeypatch.setattr(worker, "_consume_stage_execution_receipt", consume)
    return calls


class _CompletionReservation:
    pass


class _CompletionLocked:
    def __init__(
        self,
        *,
        authority,
        workflow,
        stages,
        source_stage_index,
        source_attempt,
        intents,
        target_message_ids,
        stage_ready_reservation,
        observed_at,
    ):
        self.authority = authority
        self.workflow = workflow
        self.stages = stages
        self.source_stage_index = source_stage_index
        self.source_attempt = source_attempt
        self.intents = intents
        self.target_message_ids = target_message_ids
        self.stage_ready_reservation = stage_ready_reservation
        self.observed_at = observed_at


def _completion_case(*, target_count: int = 1):
    workflow, source, message, delivery, attempt, authority = _case()
    workflow.status = "running"
    workflow.status_reason_code = ""
    workflow.status_summary = ""
    workflow.completed_at = None
    source.ordinal = 1
    source.status = "running"
    source.output_manifest = {}
    source.output_checksum = ""
    source.last_error_code = ""
    source.last_error_summary = ""
    source.last_error_retryable = False
    source.leased_at = NOW - timedelta(minutes=1)
    source.completed_at = None
    attempt.status = "running"
    attempt.input_checksum = source.input_checksum
    attempt.output_checksum = ""
    attempt.error_code = ""
    attempt.error_class = ""
    attempt.error_summary = ""
    attempt.retryable = False
    attempt.started_at = source.leased_at
    attempt.completed_at = None
    targets = tuple(
        StageRun(
            id=uuid.uuid4(),
            workflow_run_id=workflow.id,
            stage_key=f"target_{index + 1}",
            ordinal=index + 2,
            status="pending",
            state_version=1,
            attempt_count=0,
            next_attempt_at=None,
            lease_owner="",
            lease_token=None,
            leased_at=None,
            lease_expires_at=None,
            heartbeat_at=None,
            output_manifest={},
            output_checksum="",
            last_error_code="",
            last_error_summary="",
            last_error_retryable=False,
            completed_at=None,
        )
        for index in range(target_count)
    )
    return (workflow, source, *targets, message, delivery, attempt), authority


def _install_completion_runtime(
    monkeypatch,
    rows,
    authority,
    *,
    observed_at=NOW,
    reserve_error: Exception | None = None,
    consume_error: Exception | None = None,
    append_error: Exception | None = None,
    swap_message_ids: bool = False,
):
    workflow = rows[0]
    source = rows[1]
    targets = rows[2:-3]
    attempt = rows[-1]
    reservation = object()
    target_message_ids = tuple(uuid.uuid4() for _ in targets)
    intents = tuple(
        SimpleNamespace(
            pre_target=SimpleNamespace(
                stage_run_id=target.id,
                stage_key=target.stage_key,
                status="pending",
                state_version=target.state_version,
            ),
            post_target=SimpleNamespace(
                stage_run_id=target.id,
                stage_key=target.stage_key,
                status="ready",
                state_version=target.state_version + 1,
                next_attempt_at=observed_at,
                input_checksum=target.input_checksum,
            ),
            target_attempt_number=1,
            envelope_canonical=f"envelope-{index + 1}",
            envelope_checksum=checksum_json({"index": index + 1}),
            logical_key=f"{index + 1:064x}",
        )
        for index, target in enumerate(targets)
    )
    child = _CompletionReservation() if targets else None
    if child is not None:
        ordered = tuple(sorted(zip(intents, target_message_ids, strict=True), key=lambda item: item[0].logical_key))
        child.intents = tuple(intent for intent, _message_id in ordered)
        child.message_ids = tuple(message_id for _intent, message_id in ordered)
    locked = _CompletionLocked(
        authority=authority,
        workflow=workflow,
        stages=(source, *targets),
        source_stage_index=0,
        source_attempt=attempt,
        intents=intents,
        target_message_ids=target_message_ids,
        stage_ready_reservation=child,
        observed_at=observed_at,
    )
    calls = []

    async def reserve(db, *, authority):
        calls.append(("reserve", db, authority))
        if reserve_error is not None:
            raise reserve_error
        return reservation

    async def consume(db, *, reservation: object, authority):
        calls.append(("consume", db, authority))
        assert reservation is not None
        if consume_error is not None:
            raise consume_error
        return locked

    async def append(db, *, reservation, workflow, locked_stages, causal_attempt):
        calls.append(("append", db, reservation))
        if append_error is not None:
            raise append_error
        assert reservation is child
        assert workflow is rows[0]
        assert locked_stages == (source, *targets)
        assert causal_attempt is attempt
        append_message_ids = tuple(reversed(target_message_ids)) if swap_message_ids else target_message_ids
        messages = tuple(
            OutboxMessage(
                id=message_id,
                workflow_run_id=workflow.id,
                stage_run_id=intent.post_target.stage_run_id,
                aggregate_type="workflow_stage",
                aggregate_id=intent.post_target.stage_run_id,
                aggregate_version=intent.post_target.state_version,
                emission_kind="dependency_ready",
                topic=worker.OUTBOX_TOPIC_WORKFLOW_STAGE_READY,
                schema_version=worker.OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1,
                correlation_id=workflow.correlation_id,
                causation_id=causal_attempt.id,
                stage_key=intent.post_target.stage_key,
                target_attempt_number=intent.target_attempt_number,
                input_checksum=intent.post_target.input_checksum,
                plan_checksum=workflow.plan_checksum,
                envelope_canonical=intent.envelope_canonical,
                envelope_checksum=intent.envelope_checksum,
                envelope_bytes=len(intent.envelope_canonical.encode("utf-8")),
                logical_key=intent.logical_key,
                redrive_of_message_id=None,
                redrive_ordinal=0,
                redrive_requested_by="",
                redrive_requested_by_id="",
                redrive_reason="",
                redrive_requested_at=None,
                status="pending",
                state_version=1,
                attempt_count=0,
                max_attempts=worker.OUTBOX_V1_MAX_ATTEMPTS,
                delivery_cycle=0,
                cycle_key=None,
                available_at=observed_at,
                active_delivery_attempt_id=None,
                lease_owner="",
                lease_token=None,
                leased_at=None,
                lease_expires_at=None,
                heartbeat_at=None,
                receipt_deadline_at=None,
                last_error_code="",
                last_error_class="",
                last_error_summary="",
                last_error_retryable=False,
                delivered_at=None,
                dead_lettered_at=None,
                cancelled_at=None,
                cancelled_by="",
                cancelled_by_id="",
                cancel_reason="",
            )
            for intent, message_id in zip(intents, append_message_ids, strict=True)
        )
        if messages:
            await db.flush(list(messages))
        return tuple((message, True) for message in messages)

    monkeypatch.setattr(worker, "LockedStageCompletionGraph", _CompletionLocked)
    monkeypatch.setattr(worker, "StageReadyReservation", _CompletionReservation)
    monkeypatch.setattr(worker, "_reserve_stage_completion_graph", reserve)
    monkeypatch.setattr(worker, "_consume_stage_completion_graph", consume)
    monkeypatch.setattr(worker, "_append_reserved_stage_ready", append)
    return calls, locked


class _FailureReservation:
    pass


class _FailureReadyReservation:
    pass


class _FailureCancellationReservation:
    pass


class _FailureLocked:
    pass


def _failure_case(*, branch: str):
    base_rows, authority = _completion_case(target_count=0)
    workflow, source, source_message, source_delivery, source_attempt = base_rows
    source.required = branch != "optional"
    source.attempt_count = 1
    source.max_attempts = 3 if branch == "retry" else 1
    source.first_started_at = source.leased_at
    source_message.workflow_run_id = workflow.id
    source_message.stage_run_id = source.id
    source_message.status = "delivered"
    source_message.state_version = 3
    source_message.active_delivery_attempt_id = None
    source_message.available_at = None
    source_message.delivered_at = NOW - timedelta(seconds=1)
    source_delivery.message_id = source_message.id
    source_delivery.status = "delivered"
    source_delivery.state_version = 3
    source_delivery.leased_at = NOW - timedelta(minutes=2)
    source_delivery.heartbeat_at = NOW - timedelta(minutes=1)
    source_delivery.lease_expires_at = NOW + timedelta(minutes=1)
    source_delivery.completed_at = NOW - timedelta(seconds=1)

    stages = [source]
    messages = [source_message]
    deliveries = [source_delivery]
    attempts = [source_attempt]
    if branch == "required":
        source_attempt.id = uuid.UUID("ffffffff-ffff-ffff-ffff-fffffffffff1")
        authority = replace(authority, stage_attempt_id=source_attempt.id)
        peer = StageRun(
            id=uuid.uuid4(),
            workflow_run_id=workflow.id,
            stage_key="review",
            ordinal=2,
            required=True,
            status="running",
            state_version=2,
            attempt_count=1,
            max_attempts=3,
            input_checksum="d" * 64,
            checkpoint_version=0,
            checkpoint_schema_version=CHECKPOINT_SCHEMA,
            checkpoint={},
            checkpoint_checksum=checksum_json({}),
            next_attempt_at=None,
            lease_owner="worker-2",
            lease_token=uuid.uuid4(),
            leased_at=NOW - timedelta(minutes=1),
            lease_expires_at=NOW + timedelta(minutes=1),
            heartbeat_at=NOW - timedelta(seconds=10),
            output_manifest={},
            output_checksum="",
            last_error_code="",
            last_error_summary="",
            last_error_retryable=False,
            first_started_at=NOW - timedelta(minutes=1),
            completed_at=None,
        )
        peer_message = OutboxMessage(
            id=uuid.uuid4(),
            workflow_run_id=workflow.id,
            stage_run_id=peer.id,
            status="awaiting_receipt",
            state_version=2,
            available_at=None,
            active_delivery_attempt_id=uuid.uuid4(),
            lease_owner="",
            lease_token=None,
            leased_at=None,
            lease_expires_at=None,
            heartbeat_at=None,
            receipt_deadline_at=NOW + timedelta(minutes=1),
            delivered_at=None,
            dead_lettered_at=None,
            cancelled_at=None,
            cancelled_by="",
            cancelled_by_id="",
            cancel_reason="",
        )
        peer_delivery = OutboxDeliveryAttempt(
            id=peer_message.active_delivery_attempt_id,
            message_id=peer_message.id,
            status="awaiting_receipt",
            state_version=2,
            leased_at=NOW - timedelta(minutes=1),
            heartbeat_at=NOW - timedelta(seconds=10),
            lease_expires_at=NOW + timedelta(minutes=1),
            receipt_deadline_at=NOW + timedelta(seconds=30),
            receipt_received_at=None,
            completed_at=None,
            error_code="",
            error_class="",
            error_summary="",
            retryable=False,
        )
        peer_attempt = StageAttempt(
            id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
            stage_run_id=peer.id,
            outbox_delivery_attempt_id=peer_delivery.id,
            attempt_number=1,
            lease_token=peer.lease_token,
            lease_owner=peer.lease_owner,
            status="running",
            state_version=1,
            input_checksum=peer.input_checksum,
            checkpoint_start_version=0,
            checkpoint_end_version=0,
            output_checksum="",
            error_code="",
            error_class="",
            error_summary="",
            retryable=False,
            started_at=peer.leased_at,
            heartbeat_at=peer.heartbeat_at,
            lease_expires_at=peer.lease_expires_at,
            completed_at=None,
        )
        stages.append(peer)
        messages.append(peer_message)
        deliveries.append(peer_delivery)
        attempts.append(peer_attempt)
    elif branch == "optional":
        target = StageRun(
            id=uuid.uuid4(),
            workflow_run_id=workflow.id,
            stage_key="publish",
            ordinal=2,
            depends_on=[source.stage_key],
            required=True,
            status="pending",
            state_version=1,
            attempt_count=0,
            max_attempts=3,
            input_checksum="e" * 64,
            checkpoint_version=0,
            checkpoint_schema_version=CHECKPOINT_SCHEMA,
            checkpoint={},
            checkpoint_checksum=checksum_json({}),
            next_attempt_at=None,
            lease_owner="",
            lease_token=None,
            leased_at=None,
            lease_expires_at=None,
            heartbeat_at=None,
            output_manifest={},
            output_checksum="",
            last_error_code="",
            last_error_summary="",
            last_error_retryable=False,
            first_started_at=None,
            completed_at=None,
        )
        stages.append(target)
    return SimpleNamespace(
        workflow=workflow,
        source=source,
        stages=tuple(stages),
        messages=tuple(messages),
        deliveries=tuple(deliveries),
        attempts=tuple(attempts),
        authority=authority,
        rows=(workflow, *stages, *messages, *deliveries, *attempts),
        branch=branch,
    )


def _install_failure_runtime(
    monkeypatch,
    case,
    *,
    observed_at=NOW,
    reserve_error: Exception | None = None,
    consume_error: Exception | None = None,
    cancel_error: Exception | None = None,
    append_error: Exception | None = None,
    orm_uuid_subtypes: bool = False,
):
    calls: list[tuple[str, object]] = []
    reservation = _FailureReservation()
    locked = _FailureLocked()
    source = case.source
    if orm_uuid_subtypes:
        source.id = _PersistedUUID(str(source.id))
        for value in (*case.messages, *case.deliveries):
            value.id = _PersistedUUID(str(value.id))
    decision = "retry" if case.branch == "retry" else "dead_lettered" if case.branch == "dead_lettered" else "failed"
    next_attempt_at = observed_at + timedelta(seconds=10) if decision == "retry" else None
    retry_message_id = uuid.uuid4() if decision == "retry" else None
    retry_intent = None
    ready_child = None
    if decision == "retry":
        retry_intent = SimpleNamespace(
            pre_target=SimpleNamespace(
                stage_run_id=source.id,
                stage_key=source.stage_key,
                status="running",
                state_version=source.state_version,
            ),
            post_target=SimpleNamespace(
                stage_run_id=source.id,
                stage_key=source.stage_key,
                status="retry_wait",
                state_version=source.state_version + 1,
                next_attempt_at=next_attempt_at,
                input_checksum=source.input_checksum,
                last_error_code="source.timeout",
                last_error_summary="upstream timeout",
                last_error_retryable=True,
            ),
            target_attempt_number=source.attempt_count + 1,
            envelope_canonical="failure-retry-envelope",
            envelope_checksum=checksum_json({"retry": 2}),
            logical_key="7" * 64,
        )
        ready_child = _FailureReadyReservation()
        ready_child.intents = (retry_intent,)
        ready_child.message_ids = (retry_message_id,)

    if case.branch in {"required", "dead_lettered"}:
        peer_messages = tuple(sorted(case.messages[1:], key=lambda message: message.id.int))
        peer_deliveries = tuple(sorted(case.deliveries[1:], key=lambda delivery: delivery.id.int))
        cancellation_child = _FailureCancellationReservation()
        cancellation_child.workflow_run_id = case.workflow.id
        cancellation_child.messages = peer_messages
        cancellation_child.message_ids = tuple(uuid.UUID(bytes=message.id.bytes) for message in peer_messages)
        cancellation_child.deliveries = peer_deliveries
        cancellation_child.delivery_ids = tuple(uuid.UUID(bytes=delivery.id.bytes) for delivery in peer_deliveries)
        cancellation_child.error_code = (
            "workflow.required_stage_dead_lettered" if decision == "dead_lettered" else "workflow.required_stage_failed"
        )
        cancellation_child.error_class = "WorkflowCancelled"
        cancellation_child.error_summary = "Workflow stopped after a required stage failed"
        cancellation_child.cancelled_by = "AdversaryGraph workflow runtime"
        cancellation_child.cancelled_by_id = "workflow.runtime"
        cancellation_child.cancel_reason = "Workflow stopped after a required stage failed"
        cancellation_child.transaction_at = observed_at - timedelta(microseconds=1)
    else:
        cancellation_child = None

    if case.branch == "retry":
        post_statuses = ("retry_wait",)
        workflow_post_status = "running"
        workflow_reason = workflow_summary = ""
        skipped = cancelled = cancelled_attempts = ()
    elif case.branch == "required":
        post_statuses = ("failed", "cancelled")
        workflow_post_status = "failed"
        workflow_reason = "workflow.required_stage_failed"
        workflow_summary = "Required stage failure: collect"
        skipped = ()
        cancelled = (case.stages[1].id,)
        cancelled_attempts = (case.attempts[1].id,)
    elif case.branch == "dead_lettered":
        post_statuses = ("dead_lettered",)
        workflow_post_status = "dead_lettered"
        workflow_reason = "workflow.required_stage_dead_lettered"
        workflow_summary = "Required stage failure: collect"
        skipped = cancelled = cancelled_attempts = ()
    else:
        post_statuses = ("failed", "skipped")
        workflow_post_status = "degraded"
        workflow_reason = "workflow.degraded_stages"
        workflow_summary = "Workflow completed with degraded or unavailable stages: collect, publish"
        skipped = (case.stages[1].id,)
        cancelled = cancelled_attempts = ()
    locked.authority = case.authority
    locked.evidence = None
    locked.workflow = case.workflow
    locked.stages = case.stages
    locked.source_stage_id = source.id
    locked.source_stage_index = 0
    locked.decision = decision
    locked.settlement = SimpleNamespace(
        decision=decision,
        post_stage_statuses=post_statuses,
        skipped_stage_ids=skipped,
        cancelled_stage_ids=cancelled,
        cancelled_attempt_ids=cancelled_attempts,
        workflow_post_status=workflow_post_status,
        workflow_reason_code=workflow_reason,
        workflow_summary=workflow_summary,
    )
    locked.retry_intent = retry_intent
    locked.retry_message_id = retry_message_id
    locked.next_attempt_at = next_attempt_at
    locked.stage_ready_reservation = ready_child
    locked.outbox_cancellation_reservation = cancellation_child
    locked.locked_messages = case.messages
    locked.locked_deliveries = case.deliveries
    locked.locked_attempts = tuple(sorted(case.attempts, key=lambda attempt: attempt.id.int))
    locked.source_attempt_id = case.attempts[0].id
    locked.observed_at = observed_at

    async def reserve(db, *, authority, evidence):
        calls.append(("reserve", db))
        assert authority == case.authority
        if reserve_error is not None:
            raise reserve_error
        locked.evidence = evidence
        return reservation

    async def consume(db, *, reservation, authority, evidence):
        calls.append(("consume", db))
        assert reservation is not None and authority == case.authority
        if consume_error is not None:
            raise consume_error
        locked.evidence = evidence
        return locked

    async def cancel(db, *, reservation):
        calls.append(("cancel", db))
        if cancel_error is not None:
            raise cancel_error
        assert reservation is cancellation_child
        for delivery in reservation.deliveries:
            delivery.status = "cancelled"
            delivery.state_version += 1
            delivery.receipt_deadline_at = None
            delivery.receipt_received_at = None
            delivery.completed_at = reservation.transaction_at
            delivery.error_code = reservation.error_code
            delivery.error_class = reservation.error_class
            delivery.error_summary = reservation.error_summary
            delivery.retryable = False
            await db.flush([delivery])
        for message in reservation.messages:
            message.status = "cancelled"
            message.state_version += 1
            message.available_at = None
            message.active_delivery_attempt_id = None
            message.lease_owner = ""
            message.lease_token = None
            message.leased_at = None
            message.heartbeat_at = None
            message.lease_expires_at = None
            message.receipt_deadline_at = None
            message.cancelled_at = reservation.transaction_at
            message.cancelled_by = reservation.cancelled_by
            message.cancelled_by_id = reservation.cancelled_by_id
            message.cancel_reason = reservation.cancel_reason
            await db.flush([message])
        return reservation.deliveries, reservation.messages

    async def append(db, *, reservation, workflow, locked_stages, causal_attempt):
        calls.append(("append", db))
        if append_error is not None:
            raise append_error
        assert reservation is ready_child
        assert workflow is case.workflow and locked_stages == case.stages
        assert causal_attempt is case.attempts[0]
        intent = retry_intent
        message = OutboxMessage(
            id=(_PersistedUUID(str(retry_message_id)) if orm_uuid_subtypes else retry_message_id),
            workflow_run_id=workflow.id,
            stage_run_id=source.id,
            aggregate_type="workflow_stage",
            aggregate_id=source.id,
            aggregate_version=source.state_version,
            emission_kind="retry_scheduled",
            topic=worker.OUTBOX_TOPIC_WORKFLOW_STAGE_READY,
            schema_version=worker.OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1,
            correlation_id=workflow.correlation_id,
            causation_id=causal_attempt.id,
            stage_key=source.stage_key,
            target_attempt_number=intent.target_attempt_number,
            input_checksum=source.input_checksum,
            plan_checksum=workflow.plan_checksum,
            envelope_canonical=intent.envelope_canonical,
            envelope_checksum=intent.envelope_checksum,
            envelope_bytes=len(intent.envelope_canonical.encode("utf-8")),
            logical_key=intent.logical_key,
            redrive_of_message_id=None,
            redrive_ordinal=0,
            redrive_requested_by="",
            redrive_requested_by_id="",
            redrive_reason="",
            redrive_requested_at=None,
            status="pending",
            state_version=1,
            attempt_count=0,
            max_attempts=worker.OUTBOX_V1_MAX_ATTEMPTS,
            delivery_cycle=0,
            cycle_key=None,
            available_at=next_attempt_at,
            active_delivery_attempt_id=None,
            lease_owner="",
            lease_token=None,
            leased_at=None,
            lease_expires_at=None,
            heartbeat_at=None,
            receipt_deadline_at=None,
            last_error_code="",
            last_error_class="",
            last_error_summary="",
            last_error_retryable=False,
            delivered_at=None,
            dead_lettered_at=None,
            cancelled_at=None,
            cancelled_by="",
            cancelled_by_id="",
            cancel_reason="",
        )
        await db.flush([message])
        return ((message, True),)

    monkeypatch.setattr(worker, "LockedStageFailureGraph", _FailureLocked)
    monkeypatch.setattr(worker, "StageReadyReservation", _FailureReadyReservation)
    monkeypatch.setattr(worker, "OutboxCancellationReservation", _FailureCancellationReservation)
    monkeypatch.setattr(worker, "_reserve_stage_failure_graph", reserve)
    monkeypatch.setattr(worker, "_consume_stage_failure_graph", consume)
    monkeypatch.setattr(worker, "_cancel_reserved_outbox_messages", cancel)
    monkeypatch.setattr(worker, "_append_reserved_stage_ready", append)
    return calls, locked


class _CancellationReservation:
    pass


class _CancellationLocked:
    pass


class _RecoveryReservation:
    pass


class _RecoveryLocked:
    pass


def _cancellation_command(case):
    return worker.WorkflowCancellationCommand(
        request_id=uuid.uuid4(),
        workflow_run_id=case.workflow.id,
        expected_workflow_state_version=case.workflow.state_version,
        actor="Incident Commander",
        actor_id="incident.commander",
        reason="Operator stopped this workflow after scope changed",
    )


def _fake_cancellation_child(case, *, command=None, required_failure=False):
    child = _FailureCancellationReservation()
    messages = tuple(sorted(case.messages[1:], key=lambda value: value.id.int))
    deliveries = tuple(sorted(case.deliveries[1:], key=lambda value: value.id.int))
    child.workflow_run_id = case.workflow.id
    child.messages = messages
    child.message_ids = tuple(message.id for message in messages)
    child.deliveries = deliveries
    child.delivery_ids = tuple(delivery.id for delivery in deliveries)
    child.transaction_at = NOW - timedelta(microseconds=1)
    child.error_class = "WorkflowCancelled"
    if required_failure:
        child.error_code = "workflow.required_stage_dead_lettered"
        child.error_summary = "Workflow stopped after a required stage failed"
        child.cancelled_by = "AdversaryGraph workflow runtime"
        child.cancelled_by_id = "workflow.runtime"
        child.cancel_reason = child.error_summary
    else:
        assert command is not None
        child.error_code = "workflow.cancelled"
        child.error_summary = command.reason
        child.cancelled_by = command.actor
        child.cancelled_by_id = command.actor_id
        child.cancel_reason = command.reason
    return child


async def _apply_fake_cancellation_child(db, child):
    for delivery in child.deliveries:
        delivery.status = "cancelled"
        delivery.state_version += 1
        delivery.receipt_deadline_at = None
        delivery.receipt_received_at = None
        delivery.completed_at = child.transaction_at
        delivery.error_code = child.error_code
        delivery.error_class = child.error_class
        delivery.error_summary = child.error_summary
        delivery.retryable = False
        await db.flush([delivery])
    for message in child.messages:
        message.status = "cancelled"
        message.state_version += 1
        message.available_at = None
        message.active_delivery_attempt_id = None
        message.lease_owner = ""
        message.lease_token = None
        message.leased_at = None
        message.lease_expires_at = None
        message.heartbeat_at = None
        message.receipt_deadline_at = None
        message.cancelled_at = child.transaction_at
        message.cancelled_by = child.cancelled_by
        message.cancelled_by_id = child.cancelled_by_id
        message.cancel_reason = child.cancel_reason
        await db.flush([message])
    return child.deliveries, child.messages


def _install_cancellation_runtime(monkeypatch, case, command, *, consume_error=None, cancel_error=None):
    reservation = _CancellationReservation()
    child = _fake_cancellation_child(case, command=command)
    locked = _CancellationLocked()
    locked.command = command
    locked.decision = "apply"
    locked.workflow = case.workflow
    locked.stages = case.stages
    locked.locked_attempts = tuple(sorted(case.attempts, key=lambda value: value.id.int))
    locked.locked_messages = case.messages
    locked.locked_deliveries = case.deliveries
    locked.projection = SimpleNamespace(
        decision="apply",
        post_stage_statuses=tuple("cancelled" for _stage in case.stages),
        cancelled_stage_ids=tuple(stage.id for stage in case.stages),
        cancelled_attempt_ids=tuple(attempt.id for attempt in locked.locked_attempts),
    )
    locked.outbox_cancellation_reservation = child
    locked.observed_at = NOW
    calls = []

    async def reserve(db, *, command):
        calls.append(("reserve", db))
        assert command == locked.command
        return reservation

    async def consume(db, *, reservation, command):
        calls.append(("consume", db))
        assert reservation is not None and command == locked.command
        if consume_error is not None:
            raise consume_error
        return locked

    async def cancel(db, *, reservation):
        calls.append(("cancel", db))
        assert reservation is child
        if cancel_error is not None:
            raise cancel_error
        return await _apply_fake_cancellation_child(db, child)

    monkeypatch.setattr(worker, "LockedWorkflowTerminalizationGraph", _CancellationLocked)
    monkeypatch.setattr(worker, "OutboxCancellationReservation", _FailureCancellationReservation)
    monkeypatch.setattr(worker, "_reserve_workflow_terminalization_graph", reserve)
    monkeypatch.setattr(worker, "_consume_workflow_terminalization_graph", consume)
    monkeypatch.setattr(worker, "_cancel_reserved_outbox_messages", cancel)
    return calls, locked


def _recovery_case(*, branch: str):
    case = _failure_case(branch=branch)
    expired_at = NOW - timedelta(seconds=1)
    heartbeat_at = expired_at - timedelta(seconds=10)
    case.source.lease_expires_at = expired_at
    case.source.heartbeat_at = heartbeat_at
    case.attempts[0].lease_expires_at = expired_at
    case.attempts[0].heartbeat_at = heartbeat_at
    case.authority = replace(case.authority, lease_expires_at=expired_at)
    return case


def _install_recovery_runtime(monkeypatch, case, *, reserve_none=False, consume_error=None, append_error=None):
    calls = []
    reservation = _RecoveryReservation()
    locked = _RecoveryLocked()
    decision = "retry" if case.branch == "retry" else "dead_lettered"
    next_attempt_at = NOW + timedelta(seconds=10) if decision == "retry" else None
    retry_message_id = uuid.uuid4() if decision == "retry" else None
    retry_intent = None
    ready_child = None
    if decision == "retry":
        retry_intent = SimpleNamespace(
            pre_target=SimpleNamespace(
                stage_run_id=case.source.id,
                stage_key=case.source.stage_key,
                status="running",
                state_version=case.source.state_version,
            ),
            post_target=SimpleNamespace(
                stage_run_id=case.source.id,
                stage_key=case.source.stage_key,
                status="retry_wait",
                state_version=case.source.state_version + 1,
                next_attempt_at=next_attempt_at,
                input_checksum=case.source.input_checksum,
                last_error_code="workflow.lease_expired",
                last_error_summary="Worker lease expired before the attempt reached a terminal outcome",
                last_error_retryable=True,
            ),
            target_attempt_number=case.source.attempt_count + 1,
            envelope_canonical="lease-recovery-envelope",
            envelope_checksum=checksum_json({"lease_recovery": 2}),
            logical_key="8" * 64,
        )
        ready_child = _FailureReadyReservation()
        ready_child.intents = (retry_intent,)
        ready_child.message_ids = (retry_message_id,)

    if case.branch == "required":
        cancellation_child = _fake_cancellation_child(case, required_failure=True)
        post_statuses = ("dead_lettered", "cancelled")
        workflow_post_status = "dead_lettered"
        workflow_reason = "workflow.required_stage_dead_lettered"
        workflow_summary = "Required stage failure: collect"
        skipped = ()
        cancelled = (case.stages[1].id,)
        cancelled_attempts = (case.attempts[1].id,)
    elif case.branch == "optional":
        cancellation_child = None
        post_statuses = ("dead_lettered", "skipped", *("running" for _stage in case.stages[2:]))
        workflow_post_status = "running" if len(case.stages) > 2 else "degraded"
        workflow_reason = "" if workflow_post_status == "running" else "workflow.degraded_stages"
        workflow_summary = (
            "" if workflow_post_status == "running" else "Workflow completed with degraded or unavailable stages: collect, publish"
        )
        skipped = (case.stages[1].id,)
        cancelled = cancelled_attempts = ()
    else:
        cancellation_child = None
        post_statuses = ("retry_wait",)
        workflow_post_status = "running"
        workflow_reason = workflow_summary = ""
        skipped = cancelled = cancelled_attempts = ()

    locked.source_authority = case.authority
    locked.workflow = case.workflow
    locked.stages = case.stages
    locked.source_stage_id = case.source.id
    locked.source_stage_index = 0
    locked.source_attempt_id = case.attempts[0].id
    locked.locked_attempts = tuple(sorted(case.attempts, key=lambda value: value.id.int))
    locked.locked_messages = case.messages
    locked.locked_deliveries = case.deliveries
    locked.decision = decision
    locked.settlement = SimpleNamespace(
        decision=decision,
        post_stage_statuses=post_statuses,
        skipped_stage_ids=skipped,
        cancelled_stage_ids=cancelled,
        cancelled_attempt_ids=cancelled_attempts,
        workflow_post_status=workflow_post_status,
        workflow_reason_code=workflow_reason,
        workflow_summary=workflow_summary,
    )
    locked.retry_intent = retry_intent
    locked.retry_message_id = retry_message_id
    locked.next_attempt_at = next_attempt_at
    locked.stage_ready_reservation = ready_child
    locked.outbox_cancellation_reservation = cancellation_child
    locked.observed_at = NOW

    async def reserve(db):
        calls.append(("reserve", db))
        return None if reserve_none else reservation

    async def consume(db, *, reservation):
        calls.append(("consume", db))
        assert reservation is not None
        if consume_error is not None:
            raise consume_error
        return locked

    async def cancel(db, *, reservation):
        calls.append(("cancel", db))
        assert reservation is cancellation_child
        return await _apply_fake_cancellation_child(db, cancellation_child)

    async def append(db, *, reservation, workflow, locked_stages, causal_attempt):
        calls.append(("append", db))
        if append_error is not None:
            raise append_error
        assert reservation is ready_child
        assert workflow is case.workflow and locked_stages == case.stages
        assert causal_attempt is case.attempts[0]
        message = OutboxMessage(
            id=retry_message_id,
            workflow_run_id=workflow.id,
            stage_run_id=case.source.id,
            aggregate_type="workflow_stage",
            aggregate_id=case.source.id,
            aggregate_version=case.source.state_version,
            emission_kind="lease_recovered",
            topic=worker.OUTBOX_TOPIC_WORKFLOW_STAGE_READY,
            schema_version=worker.OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1,
            correlation_id=workflow.correlation_id,
            causation_id=causal_attempt.id,
            stage_key=case.source.stage_key,
            target_attempt_number=retry_intent.target_attempt_number,
            input_checksum=case.source.input_checksum,
            plan_checksum=workflow.plan_checksum,
            envelope_canonical=retry_intent.envelope_canonical,
            envelope_checksum=retry_intent.envelope_checksum,
            envelope_bytes=len(retry_intent.envelope_canonical.encode("utf-8")),
            logical_key=retry_intent.logical_key,
            redrive_of_message_id=None,
            redrive_ordinal=0,
            redrive_requested_by="",
            redrive_requested_by_id="",
            redrive_reason="",
            redrive_requested_at=None,
            status="pending",
            state_version=1,
            attempt_count=0,
            max_attempts=worker.OUTBOX_V1_MAX_ATTEMPTS,
            delivery_cycle=0,
            cycle_key=None,
            available_at=next_attempt_at,
            active_delivery_attempt_id=None,
            lease_owner="",
            lease_token=None,
            leased_at=None,
            lease_expires_at=None,
            heartbeat_at=None,
            receipt_deadline_at=None,
            last_error_code="",
            last_error_class="",
            last_error_summary="",
            last_error_retryable=False,
            delivered_at=None,
            dead_lettered_at=None,
            cancelled_at=None,
            cancelled_by="",
            cancelled_by_id="",
            cancel_reason="",
        )
        await db.flush([message])
        return ((message, True),)

    monkeypatch.setattr(worker, "LockedStageRecoveryGraph", _RecoveryLocked)
    monkeypatch.setattr(worker, "StageReadyReservation", _FailureReadyReservation)
    monkeypatch.setattr(worker, "OutboxCancellationReservation", _FailureCancellationReservation)
    monkeypatch.setattr(worker, "_reserve_one_expired_stage_recovery", reserve)
    monkeypatch.setattr(worker, "_consume_stage_recovery_graph", consume)
    monkeypatch.setattr(worker, "_cancel_reserved_outbox_messages", cancel)
    monkeypatch.setattr(worker, "_append_reserved_stage_ready", append)
    return calls, locked


@pytest.mark.asyncio
async def test_explicit_cancellation_commits_d_m_a_s_w_and_preserves_attempt_heartbeat(monkeypatch):
    case = _failure_case(branch="required")
    command = _cancellation_command(case)
    before = {id(value): _column_snapshot(value) for value in case.rows}
    heartbeats = {attempt.id: attempt.heartbeat_at for attempt in case.attempts}
    events: list[str] = []
    session = _Session("cancel", events, case.rows)
    calls, _locked = _install_cancellation_runtime(monkeypatch, case, command)
    build_result = worker._build_public_cancellation_result

    def build_after_exit(facts):
        assert events[-1] == "cancel:session_exit"
        events.append("public_result")
        return build_result(facts)

    monkeypatch.setattr(worker, "_build_public_cancellation_result", build_after_exit)
    result = await worker.coordinate_workflow_cancel(_Factory([session]), command=command)

    assert result.disposition == "applied" and result.should_apply is True
    assert result.request_id == command.request_id
    assert result.workflow_state_version == command.expected_workflow_state_version + 1
    assert result.cancelled_stage_ids == tuple(stage.id for stage in case.stages)
    assert result.cancelled_attempt_ids == tuple(attempt.id for attempt in sorted(case.attempts, key=lambda x: x.id.int))
    assert result.cancelled_message_ids == (case.messages[1].id,)
    assert result.cancelled_delivery_ids == (case.deliveries[1].id,)
    assert [call[0] for call in calls] == ["reserve", "consume", "cancel"]
    flushed_ids = [dict(item[0])["id"] for item in session.flushes]
    assert flushed_ids == [
        case.deliveries[1].id,
        case.messages[1].id,
        *[attempt.id for attempt in sorted(case.attempts, key=lambda value: value.id.int)],
        *[stage.id for stage in case.stages],
        case.workflow.id,
    ]
    assert {attempt.id: attempt.heartbeat_at for attempt in case.attempts} == heartbeats
    assert case.workflow.cancel_request_id == command.request_id
    with pytest.raises(OutboxValidation, match="at least one cancelled stage"):
        replace(
            result,
            cancelled_stage_ids=(),
            cancelled_attempt_ids=(),
            cancelled_message_ids=(),
            cancelled_delivery_ids=(),
        )
    assert _changed_columns(before[id(case.messages[0])], _column_snapshot(case.messages[0])) == set()
    assert _changed_columns(before[id(case.deliveries[0])], _column_snapshot(case.deliveries[0])) == set()
    assert events[-4:] == ["cancel:commit", "cancel:tx_exit", "cancel:session_exit", "public_result"]
    assert session.commit_calls == 0


@pytest.mark.asyncio
async def test_cancellation_replay_is_commit_confirmed_zero_write(monkeypatch):
    case = _failure_case(branch="dead_lettered")
    command = _cancellation_command(case)
    facts = worker._WorkflowCancellationMutationFacts(
        command=command,
        decision="replay",
        workflow_state_version=command.expected_workflow_state_version + 1,
        cancelled_at=NOW,
        cancelled_stage_ids=(),
        cancelled_attempt_ids=(),
        cancelled_message_ids=(),
        cancelled_delivery_ids=(),
    )
    events: list[str] = []
    session = _Session("replay", events, ())

    async def replay_writer(db, *, command):
        assert db is session and command == facts.command
        return facts

    monkeypatch.setattr(worker, "_reserve_consume_and_cancel", replay_writer)
    result = await worker.coordinate_workflow_cancel(_Factory([session]), command=command)

    assert result.disposition == "replayed" and result.should_apply is False
    assert result.cancelled_stage_ids == result.cancelled_attempt_ids == ()
    assert result.cancelled_message_ids == result.cancelled_delivery_ids == ()
    assert session.flushes == []
    assert events[-3:] == ["replay:commit", "replay:tx_exit", "replay:session_exit"]


@pytest.mark.asyncio
@pytest.mark.parametrize("branch", ["retry", "required", "optional"])
async def test_receipt_bound_recovery_records_exact_branch_and_flush_order(monkeypatch, branch):
    case = _recovery_case(branch=branch)
    source_heartbeat = case.attempts[0].heartbeat_at
    events: list[str] = []
    session = _Session("recovery", events, case.rows)
    calls, locked = _install_recovery_runtime(monkeypatch, case)
    result = await worker.coordinate_one_expired_stage_recovery(_Factory([session]))

    assert result is not None
    assert result.decision == ("retry" if branch == "retry" else "dead_lettered")
    assert result.stage_status == ("retry_wait" if branch == "retry" else "dead_lettered")
    assert result.attempt_status == "abandoned"
    assert result.lease_expires_at == case.authority.lease_expires_at <= result.recovered_at
    assert result.stage_lease_token == case.authority.stage_lease_token
    assert result.message_id == case.authority.message_id
    assert result.delivery_attempt_id == case.authority.delivery_attempt_id
    assert result.should_retry is (branch == "retry") and result.should_continue is False
    assert case.attempts[0].heartbeat_at == source_heartbeat
    assert [call[0] for call in calls] == (
        ["reserve", "consume", "append"]
        if branch == "retry"
        else ["reserve", "consume", "cancel"]
        if branch == "required"
        else ["reserve", "consume"]
    )
    flushed_ids = [dict(item[0])["id"] for item in session.flushes]
    if branch == "retry":
        assert result.retry_emission is not None
        assert result.retry_emission.message_id == locked.retry_message_id
        assert result.next_attempt_at == NOW + timedelta(seconds=10)
        assert flushed_ids == [case.attempts[0].id, case.source.id, locked.retry_message_id]
    elif branch == "required":
        assert result.workflow_status == "dead_lettered"
        assert result.cancelled_stage_ids == (case.stages[1].id,)
        assert flushed_ids == [
            case.deliveries[1].id,
            case.messages[1].id,
            *[attempt.id for attempt in sorted(case.attempts, key=lambda value: value.id.int)],
            case.source.id,
            case.stages[1].id,
            case.workflow.id,
        ]
    else:
        assert result.workflow_status == "degraded"
        assert result.skipped_stage_ids == (case.stages[1].id,)
        assert flushed_ids == [case.attempts[0].id, case.source.id, case.stages[1].id, case.workflow.id]
    assert events[-3:] == ["recovery:commit", "recovery:tx_exit", "recovery:session_exit"]
    assert session.commit_calls == 0


@pytest.mark.asyncio
async def test_optional_exhausted_recovery_preserves_independent_running_stage_and_attempt(monkeypatch):
    case = _recovery_case(branch="optional")
    peer_case = _failure_case(branch="required")
    independent = copy.deepcopy(peer_case.stages[1])
    independent.workflow_run_id = case.workflow.id
    independent.ordinal = 3
    independent.stage_key = "independent"
    independent.depends_on = []
    independent_message = copy.deepcopy(peer_case.messages[1])
    independent_message.workflow_run_id = case.workflow.id
    independent_message.stage_run_id = independent.id
    independent_attempt = copy.deepcopy(peer_case.attempts[1])
    independent_attempt.stage_run_id = independent.id
    independent_delivery = copy.deepcopy(peer_case.deliveries[1])
    independent_message.active_delivery_attempt_id = independent_delivery.id
    independent_delivery.message_id = independent_message.id
    independent_attempt.outbox_delivery_attempt_id = independent_delivery.id
    case.stages = (*case.stages, independent)
    case.messages = (*case.messages, independent_message)
    case.deliveries = (*case.deliveries, independent_delivery)
    case.attempts = (*case.attempts, independent_attempt)
    case.rows = (case.workflow, *case.stages, *case.messages, *case.deliveries, *case.attempts)
    independent_stage_before = _column_snapshot(independent)
    independent_attempt_before = _column_snapshot(independent_attempt)
    session = _Session("optional-independent", [], case.rows)
    _install_recovery_runtime(monkeypatch, case)

    result = await worker.coordinate_one_expired_stage_recovery(_Factory([session]))

    assert result is not None and result.decision == "dead_lettered"
    assert result.workflow_status == "running"
    assert result.workflow_state_version == result.previous_workflow_state_version
    assert result.cancelled_stage_ids == result.cancelled_attempt_ids == ()
    assert _column_snapshot(independent) == independent_stage_before
    assert _column_snapshot(independent_attempt) == independent_attempt_before
    assert [dict(item[0])["id"] for item in session.flushes] == [
        case.attempts[0].id,
        case.source.id,
        case.stages[1].id,
    ]


@pytest.mark.asyncio
async def test_recovery_none_and_commit_failure_publish_no_result(monkeypatch):
    empty_case = _recovery_case(branch="retry")
    empty_session = _Session("empty", [], empty_case.rows)
    calls, _locked = _install_recovery_runtime(monkeypatch, empty_case, reserve_none=True)
    assert await worker.coordinate_one_expired_stage_recovery(_Factory([empty_session])) is None
    assert [call[0] for call in calls] == ["reserve"]
    assert empty_session.flushes == []

    failed_case = _recovery_case(branch="retry")
    failed_session = _Session(
        "failed",
        [],
        failed_case.rows,
        commit_error=RuntimeError("recovery commit failed"),
    )
    _install_recovery_runtime(monkeypatch, failed_case)

    def forbidden_result(_facts):
        pytest.fail("A failed recovery commit cannot publish facts")

    monkeypatch.setattr(worker, "_build_public_recovery_result", forbidden_result)
    with pytest.raises(RuntimeError, match="recovery commit failed"):
        await worker.coordinate_one_expired_stage_recovery(_Factory([failed_session]))


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["cancel_consume", "cancel_child", "recovery_consume", "recovery_append"])
async def test_cancellation_and_recovery_never_translate_authority_or_late_errors(monkeypatch, operation):
    error = OutboxLeaseLost(f"{operation} must propagate")
    if operation.startswith("cancel"):
        case = _failure_case(branch="required")
        command = _cancellation_command(case)
        session = _Session("cancel-error", [], case.rows)
        _install_cancellation_runtime(
            monkeypatch,
            case,
            command,
            consume_error=error if operation == "cancel_consume" else None,
            cancel_error=error if operation == "cancel_child" else None,
        )
        with pytest.raises(OutboxLeaseLost) as caught:
            await worker.coordinate_workflow_cancel(_Factory([session]), command=command)
    else:
        case = _recovery_case(branch="retry")
        session = _Session("recovery-error", [], case.rows)
        _install_recovery_runtime(
            monkeypatch,
            case,
            consume_error=error if operation == "recovery_consume" else None,
            append_error=error if operation == "recovery_append" else None,
        )
        with pytest.raises(OutboxLeaseLost) as caught:
            await worker.coordinate_one_expired_stage_recovery(_Factory([session]))
    assert caught.value is error


@pytest.mark.asyncio
async def test_cancellation_and_recovery_validate_public_boundary_before_factory_or_reserve(monkeypatch):
    factory = _Factory(error=AssertionError("factory must not be called"))
    with pytest.raises(OutboxValidation, match="exact workflow cancellation"):
        await worker.coordinate_workflow_cancel(factory, command=object())
    assert factory.calls == 0

    reserve_calls = []

    async def forbidden_reserve(*_args, **_kwargs):
        reserve_calls.append(True)
        raise AssertionError("invalid direct helper input reached reservation")

    monkeypatch.setattr(worker, "_reserve_workflow_terminalization_graph", forbidden_reserve)
    with pytest.raises(OutboxValidation, match="exact workflow cancellation"):
        await worker._reserve_consume_and_cancel(object(), command=object())
    assert reserve_calls == []

    with pytest.raises(WorkflowValidation, match="session_factory"):
        await worker.coordinate_one_expired_stage_recovery(None)
    with pytest.raises(WorkflowValidation, match="session_factory"):
        await worker.coordinate_workflow_cancel(None, command=_cancellation_command(_failure_case(branch="required")))


@pytest.mark.asyncio
async def test_recovery_pass_is_bounded_stops_on_none_and_propagates_item_failure(monkeypatch):
    marker = object()
    results = deque([marker, marker, None])
    calls = []

    async def one(factory):
        calls.append(factory)
        return results.popleft()

    monkeypatch.setattr(worker, "coordinate_one_expired_stage_recovery", one)
    factory = _Factory(error=AssertionError("the item coordinator owns factory use"))
    assert await worker.coordinate_expired_stage_recovery_pass(factory, limit=5) == (marker, marker)
    assert calls == [factory, factory, factory]
    assert factory.calls == 0

    for invalid in (True, 0, 501):
        with pytest.raises(WorkflowValidation, match="limit"):
            await worker.coordinate_expired_stage_recovery_pass(factory, limit=invalid)
    assert factory.calls == 0

    failure = RuntimeError("second recovery failed")
    sequence = deque([marker, failure])

    async def fail_second(_factory):
        value = sequence.popleft()
        if isinstance(value, Exception):
            raise value
        return value

    monkeypatch.setattr(worker, "coordinate_one_expired_stage_recovery", fail_second)
    with pytest.raises(RuntimeError, match="second recovery failed"):
        await worker.coordinate_expired_stage_recovery_pass(factory, limit=2)


def test_recovery_private_facts_reject_collateral_that_public_result_cannot_represent():
    case = _recovery_case(branch="optional")
    terminal = worker._StageRecoveryMutationFacts(
        workflow_run_id=case.authority.workflow_run_id,
        stage_run_id=case.authority.stage_run_id,
        stage_attempt_id=case.authority.stage_attempt_id,
        message_id=case.authority.message_id,
        delivery_attempt_id=case.authority.delivery_attempt_id,
        stage_lease_token=case.authority.stage_lease_token,
        attempt_number=case.authority.attempt_number,
        delivery_cycle=case.authority.delivery_cycle,
        cycle_key=case.authority.cycle_key,
        broker_receipt_id=case.authority.broker_receipt_id,
        stage_key=case.authority.stage_key,
        input_checksum=case.authority.input_checksum,
        checkpoint_version=case.authority.checkpoint_version,
        lease_owner=case.authority.lease_owner,
        lease_expires_at=case.authority.lease_expires_at,
        decision="dead_lettered",
        previous_workflow_state_version=case.authority.workflow_state_version,
        workflow_state_version=case.authority.workflow_state_version + 1,
        workflow_status="degraded",
        previous_stage_state_version=case.authority.stage_state_version,
        stage_state_version=case.authority.stage_state_version + 1,
        previous_attempt_state_version=case.authority.attempt_state_version,
        attempt_state_version=case.authority.attempt_state_version + 1,
        recovered_at=NOW,
        next_attempt_at=None,
        skipped_stage_ids=(case.stages[1].id,),
        cancelled_stage_ids=(),
        cancelled_attempt_ids=(),
        cancelled_message_ids=(),
        cancelled_delivery_ids=(),
        retry_emission=None,
    )
    with pytest.raises(WorkflowStoredContractError, match="include the source"):
        replace(terminal, skipped_stage_ids=(case.source.id,))
    with pytest.raises(WorkflowStoredContractError, match="overlap"):
        replace(
            terminal,
            workflow_status="dead_lettered",
            skipped_stage_ids=(case.stages[1].id,),
            cancelled_stage_ids=(case.stages[1].id,),
        )
    with pytest.raises(WorkflowStoredContractError, match="lack a cancelled stage"):
        replace(terminal, workflow_status="dead_lettered", skipped_stage_ids=(), cancelled_attempt_ids=(uuid.uuid4(),))


@pytest.mark.asyncio
async def test_heartbeat_commits_then_confirms_in_distinct_scopes_and_mutates_only_s_a(monkeypatch):
    *rows, authority = _case()
    rows = tuple(rows)
    before = tuple(_column_snapshot(value) for value in rows)
    factory, mutation, confirmation, events = _sessions(rows)
    calls = _install_receipt_runtime(monkeypatch, rows)
    build_public_result = worker._build_public_result

    def build_after_context_exit(*args, **kwargs):
        assert events[-1] == "confirmation:session_exit"
        events.append("public_result")
        return build_public_result(*args, **kwargs)

    monkeypatch.setattr(worker, "_build_public_result", build_after_context_exit)

    result = await worker.coordinate_stage_heartbeat(
        factory,
        authority=authority,
        lease_seconds=120,
    )

    workflow, stage, message, delivery, attempt = rows
    after = tuple(_column_snapshot(value) for value in rows)
    assert result.disposition == "renewed"
    assert result.should_continue is True
    assert result.authority is not None and result.authority is not authority
    assert result.stage_state_version == authority.stage_state_version + 1
    assert result.attempt_state_version == authority.attempt_state_version + 1
    assert result.heartbeat_at == NOW
    assert result.lease_expires_at == NOW + timedelta(seconds=120)
    assert stage.heartbeat_at == attempt.heartbeat_at == NOW
    assert stage.lease_expires_at == attempt.lease_expires_at == result.lease_expires_at
    assert _changed_columns(before[0], after[0]) == set()
    assert _changed_columns(before[1], after[1]) == {
        "heartbeat_at",
        "lease_expires_at",
        "state_version",
    }
    assert _changed_columns(before[2], after[2]) == set()
    assert _changed_columns(before[3], after[3]) == set()
    assert _changed_columns(before[4], after[4]) == {
        "heartbeat_at",
        "lease_expires_at",
        "state_version",
    }
    assert confirmation.flushes == []
    assert mutation.commit_calls == confirmation.commit_calls == 0
    assert factory.calls == 2
    assert calls[0][2] == authority and calls[0][2] is not authority
    assert [call[0] for call in calls] == ["reserve", "consume", "reserve", "consume"]
    assert events == [
        "mutation:session_enter",
        "mutation:tx_enter",
        "mutation:flush:StageRun",
        "mutation:flush:StageAttempt",
        "mutation:commit",
        "mutation:tx_exit",
        "mutation:session_exit",
        "confirmation:session_enter",
        "confirmation:tx_enter",
        "confirmation:commit",
        "confirmation:tx_exit",
        "confirmation:session_exit",
        "public_result",
    ]


@pytest.mark.asyncio
async def test_heartbeat_never_shortens_an_existing_lease(monkeypatch):
    old_expiry = NOW + timedelta(minutes=10)
    *rows, authority = _case(lease_expires_at=old_expiry)
    rows = tuple(rows)
    factory, *_ = _sessions(rows)
    _install_receipt_runtime(monkeypatch, rows)

    result = await worker.coordinate_stage_heartbeat(
        factory,
        authority=authority,
        lease_seconds=60,
    )

    assert result.previous_lease_expires_at == old_expiry
    assert result.lease_expires_at == old_expiry
    assert result.authority is not None
    assert result.authority.lease_expires_at == old_expiry


@pytest.mark.asyncio
async def test_heartbeat_revalidates_authority_and_duration_before_factory_or_sql(monkeypatch):
    *rows, authority = _case()
    rows = tuple(rows)
    calls = _install_receipt_runtime(monkeypatch, rows)

    class AuthoritySubclass(ExecutableStageAuthority):
        pass

    subclass = object.__new__(AuthoritySubclass)
    for field_name in authority.__dataclass_fields__:
        object.__setattr__(subclass, field_name, getattr(authority, field_name))
    forged = object.__new__(ExecutableStageAuthority)
    for field_name in authority.__dataclass_fields__:
        object.__setattr__(forged, field_name, getattr(authority, field_name))
    object.__setattr__(forged, "broker_receipt_id", "raw-receipt")

    for hostile_authority, duration in (
        (subclass, 300),
        (forged, 300),
        (authority, True),
        (authority, 0),
        (authority, 3_601),
    ):
        factory = _Factory([])
        with pytest.raises((OutboxValidation, WorkflowValidation)):
            await worker.coordinate_stage_heartbeat(
                factory,
                authority=hostile_authority,
                lease_seconds=duration,
            )
        assert factory.calls == 0
    with pytest.raises(WorkflowValidation, match="session_factory"):
        await worker.coordinate_stage_heartbeat(
            None,
            authority=authority,
        )
    assert calls == []


@pytest.mark.asyncio
async def test_initial_lease_loss_rolls_back_and_returns_stale_after_session_exit(monkeypatch):
    *rows, authority = _case()
    rows = tuple(rows)
    events: list[str] = []
    mutation = _Session("mutation", events, rows)
    factory = _Factory([mutation])
    _install_receipt_runtime(
        monkeypatch,
        rows,
        reserve_effects=[OutboxLeaseLost("stale")],
    )
    build_public_result = worker._build_public_result

    def build_after_context_exit(*args, **kwargs):
        assert events[-1] == "mutation:session_exit"
        return build_public_result(*args, **kwargs)

    monkeypatch.setattr(worker, "_build_public_result", build_after_context_exit)

    result = await worker.coordinate_stage_heartbeat(factory, authority=authority)

    assert result.disposition == "stale"
    assert result.should_continue is False
    assert result.authority is None
    assert result.heartbeat_at is None
    assert result.stage_state_version == authority.stage_state_version
    assert result.attempt_state_version == authority.attempt_state_version
    assert result.lease_expires_at == authority.lease_expires_at
    assert mutation.flushes == []
    assert factory.calls == 1
    assert events == [
        "mutation:session_enter",
        "mutation:tx_enter",
        "mutation:rollback",
        "mutation:tx_exit",
        "mutation:session_exit",
    ]


@pytest.mark.asyncio
async def test_confirmation_lease_loss_returns_stale_only_after_committed_heartbeat(monkeypatch):
    *rows, authority = _case()
    rows = tuple(rows)
    factory, mutation, confirmation, events = _sessions(rows)
    _install_receipt_runtime(
        monkeypatch,
        rows,
        reserve_effects=[None, OutboxLeaseLost("cancelled after commit")],
        observed=(NOW,),
    )
    build_public_result = worker._build_public_result

    def build_after_context_exit(*args, **kwargs):
        assert events[-1] == "confirmation:session_exit"
        return build_public_result(*args, **kwargs)

    monkeypatch.setattr(worker, "_build_public_result", build_after_context_exit)

    result = await worker.coordinate_stage_heartbeat(factory, authority=authority)

    assert result.disposition == "stale"
    assert result.should_continue is False
    assert result.authority is None
    assert result.heartbeat_at == NOW
    assert result.stage_state_version == authority.stage_state_version + 1
    assert result.attempt_state_version == authority.attempt_state_version + 1
    assert len(mutation.flushes) == 2
    assert confirmation.flushes == []
    assert events[-3:] == [
        "confirmation:rollback",
        "confirmation:tx_exit",
        "confirmation:session_exit",
    ]
    assert events[-1] == "confirmation:session_exit"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        "flush",
        "mutation_commit",
        "mutation_session_exit",
        "confirmation_commit",
        "confirmation_session_exit",
    ],
)
async def test_flush_and_commit_failures_propagate_without_public_result(monkeypatch, failure):
    *rows, authority = _case()
    rows = tuple(rows)
    before = tuple(_column_snapshot(value) for value in rows)
    mutation_options = {}
    confirmation_options = {}
    if failure == "flush":
        mutation_options["flush_error_at"] = 1
    elif failure == "mutation_commit":
        mutation_options["commit_error"] = RuntimeError("mutation commit failed")
    elif failure == "mutation_session_exit":
        mutation_options["exit_error"] = RuntimeError("mutation session exit failed")
    elif failure == "confirmation_commit":
        confirmation_options["commit_error"] = RuntimeError("confirmation commit failed")
    else:
        confirmation_options["exit_error"] = RuntimeError("confirmation session exit failed")
    factory, *_ = _sessions(
        rows,
        mutation_options=mutation_options,
        confirmation_options=confirmation_options,
    )
    _install_receipt_runtime(monkeypatch, rows)

    with pytest.raises(RuntimeError, match="failed"):
        await worker.coordinate_stage_heartbeat(factory, authority=authority)

    after = tuple(_column_snapshot(value) for value in rows)
    if failure in {"flush", "mutation_commit"}:
        assert after == before
        assert factory.calls == 1
    elif failure == "mutation_session_exit":
        assert _changed_columns(before[1], after[1]) == {
            "heartbeat_at",
            "lease_expires_at",
            "state_version",
        }
        assert factory.calls == 1
    else:
        assert _changed_columns(before[1], after[1]) == {
            "heartbeat_at",
            "lease_expires_at",
            "state_version",
        }
        assert factory.calls == 2


@pytest.mark.asyncio
async def test_lease_lost_from_commit_or_foreign_sentinel_is_not_mapped_to_stale(monkeypatch):
    *rows, authority = _case()
    rows = tuple(rows)
    commit_factory, *_ = _sessions(
        rows,
        mutation_options={"commit_error": OutboxLeaseLost("commit failed")},
    )
    _install_receipt_runtime(monkeypatch, rows)
    with pytest.raises(OutboxLeaseLost, match="commit failed"):
        await worker.coordinate_stage_heartbeat(commit_factory, authority=authority)

    foreign = worker._ReceiptAuthorityStale()
    exit_factory, *_ = _sessions(
        rows,
        mutation_options={"exit_error": foreign},
    )
    _install_receipt_runtime(monkeypatch, rows)
    with pytest.raises(worker._ReceiptAuthorityStale) as captured:
        await worker.coordinate_stage_heartbeat(exit_factory, authority=authority)
    assert captured.value is foreign


@pytest.mark.asyncio
async def test_rollback_leaves_old_authority_usable_if_still_live(monkeypatch):
    *rows, authority = _case()
    rows = tuple(rows)
    failing_factory, *_ = _sessions(
        rows,
        mutation_options={"commit_error": RuntimeError("mutation commit failed")},
    )
    _install_receipt_runtime(monkeypatch, rows)
    with pytest.raises(RuntimeError, match="mutation commit failed"):
        await worker.coordinate_stage_heartbeat(failing_factory, authority=authority)

    retry_factory, *_ = _sessions(rows)
    _install_receipt_runtime(monkeypatch, rows)
    result = await worker.coordinate_stage_heartbeat(
        retry_factory,
        authority=authority,
    )
    assert result.disposition == "renewed"
    assert result.authority is not None


@pytest.mark.asyncio
async def test_factory_and_same_session_failures_never_return_authority(monkeypatch):
    *rows, authority = _case()
    rows = tuple(rows)
    calls = _install_receipt_runtime(monkeypatch, rows)
    factory_error = _Factory(error=RuntimeError("factory failed"))
    with pytest.raises(RuntimeError, match="factory failed"):
        await worker.coordinate_stage_heartbeat(factory_error, authority=authority)
    assert calls == []

    events: list[str] = []
    reused = _Session("reused", events, rows)
    reused_factory = _Factory([reused, reused])
    _install_receipt_runtime(monkeypatch, rows, observed=(NOW,))
    with pytest.raises(WorkflowValidation, match="distinct fresh session"):
        await worker.coordinate_stage_heartbeat(
            reused_factory,
            authority=authority,
        )
    assert reused_factory.calls == 2
    assert events[-1] == "reused:session_exit"


@pytest.mark.asyncio
async def test_stored_corruption_and_hostile_locked_result_propagate(monkeypatch):
    *rows, authority = _case()
    rows = tuple(rows)
    events: list[str] = []
    factory = _Factory([_Session("mutation", events, rows)])
    _install_receipt_runtime(
        monkeypatch,
        rows,
        reserve_effects=[OutboxStoredContractError("corrupt")],
    )
    with pytest.raises(OutboxStoredContractError, match="corrupt"):
        await worker.coordinate_stage_heartbeat(factory, authority=authority)
    assert events[-1] == "mutation:session_exit"

    async def reserve(_db, *, authority):
        del authority
        return object()

    async def consume(_db, *, reservation, authority):
        del reservation, authority
        return object()

    monkeypatch.setattr(worker, "_reserve_stage_execution_receipt", reserve)
    monkeypatch.setattr(worker, "_consume_stage_execution_receipt", consume)
    factory = _Factory([_Session("mutation-2", [], rows)])
    with pytest.raises(OutboxStoredContractError, match="invalid locked"):
        await worker.coordinate_stage_heartbeat(factory, authority=authority)


@pytest.mark.asyncio
async def test_hostile_exact_locked_result_cannot_redirect_the_mutation(monkeypatch):
    *rows, authority = _case()
    rows = tuple(rows)
    attempt = rows[-1]
    attempt.outbox_delivery_attempt_id = uuid.uuid4()
    session = _Session("mutation", [], rows)
    factory = _Factory([session])
    _install_receipt_runtime(monkeypatch, rows)

    with pytest.raises(WorkflowStoredContractError, match="contradict"):
        await worker.coordinate_stage_heartbeat(factory, authority=authority)

    assert factory.calls == 1
    assert session.flushes == []


@pytest.mark.asyncio
async def test_old_authority_is_stale_after_commit_while_new_authority_remains_usable(monkeypatch):
    *rows, authority = _case()
    rows = tuple(rows)
    first_factory, *_ = _sessions(rows)
    _install_receipt_runtime(monkeypatch, rows)
    first = await worker.coordinate_stage_heartbeat(first_factory, authority=authority)
    assert first.authority is not None
    current = first.authority

    observed = deque([NOW + timedelta(seconds=1), NOW + timedelta(seconds=1, microseconds=1)])

    async def reserve(_db, *, authority):
        if authority != current:
            raise OutboxLeaseLost("old authority")
        return object()

    async def consume(_db, *, reservation, authority):
        del reservation
        workflow, stage, message, delivery, attempt = rows
        return LockedStageExecutionReceipt(
            authority=authority,
            workflow=workflow,
            stage=stage,
            message=message,
            delivery=delivery,
            attempt=attempt,
            observed_at=observed.popleft(),
        )

    monkeypatch.setattr(worker, "_reserve_stage_execution_receipt", reserve)
    monkeypatch.setattr(worker, "_consume_stage_execution_receipt", consume)
    stale_factory = _Factory([_Session("stale", [], rows)])
    stale = await worker.coordinate_stage_heartbeat(
        stale_factory,
        authority=authority,
    )
    assert stale.disposition == "stale"

    def promote_current(_session):
        nonlocal current
        _workflow, stage, _message, _delivery, attempt = rows
        current = worker._renewed_authority(
            current,
            stage_state_version=stage.state_version,
            attempt_state_version=attempt.state_version,
            lease_expires_at=stage.lease_expires_at,
        )

    next_factory, *_ = _sessions(
        rows,
        mutation_options={"on_commit": promote_current},
    )
    presented_current = current
    renewed = await worker.coordinate_stage_heartbeat(
        next_factory,
        authority=presented_current,
    )
    assert renewed.disposition == "renewed"
    assert renewed.authority is not None
    assert renewed.stage_state_version == presented_current.stage_state_version + 1


@pytest.mark.asyncio
async def test_concurrent_same_authority_exactly_one_renews(monkeypatch):
    *rows, authority = _case()
    rows = tuple(rows)
    state = {"authority": authority}
    row_lock = asyncio.Lock()
    first_lock_acquired = asyncio.Event()
    let_first_continue = asyncio.Event()
    reserve_count = 0
    clock_count = 0
    session_count = 0

    def on_commit(session):
        if not session.flushes:
            return
        _workflow, stage, _message, _delivery, attempt = rows
        state["authority"] = worker._renewed_authority(
            state["authority"],
            stage_state_version=stage.state_version,
            attempt_state_version=attempt.state_version,
            lease_expires_at=stage.lease_expires_at,
        )

    def on_transaction_exit(_session):
        if row_lock.locked():
            row_lock.release()

    def session_factory():
        nonlocal session_count
        session_count += 1
        return _Session(
            f"concurrent-{session_count}",
            [],
            rows,
            on_commit=on_commit,
            on_transaction_exit=on_transaction_exit,
        )

    async def reserve(_db, *, authority):
        nonlocal reserve_count
        reserve_count += 1
        await row_lock.acquire()
        if reserve_count == 1:
            first_lock_acquired.set()
            await let_first_continue.wait()
        if authority != state["authority"]:
            raise OutboxLeaseLost("concurrent authority lost")
        return object()

    async def consume(_db, *, reservation, authority):
        nonlocal clock_count
        del reservation
        clock_count += 1
        workflow, stage, message, delivery, attempt = rows
        return LockedStageExecutionReceipt(
            authority=authority,
            workflow=workflow,
            stage=stage,
            message=message,
            delivery=delivery,
            attempt=attempt,
            observed_at=NOW + timedelta(microseconds=clock_count),
        )

    monkeypatch.setattr(worker, "_reserve_stage_execution_receipt", reserve)
    monkeypatch.setattr(worker, "_consume_stage_execution_receipt", consume)

    first_task = asyncio.create_task(worker.coordinate_stage_heartbeat(session_factory, authority=authority))
    await asyncio.wait_for(first_lock_acquired.wait(), timeout=1)
    second_task = asyncio.create_task(worker.coordinate_stage_heartbeat(session_factory, authority=authority))
    await asyncio.sleep(0)
    let_first_continue.set()
    first, second = await asyncio.gather(first_task, second_task)

    assert {first.disposition, second.disposition} == {"renewed", "stale"}
    renewed = first if first.disposition == "renewed" else second
    stale = second if renewed is first else first
    assert renewed.authority is not None and renewed.should_continue is True
    assert stale.authority is None and stale.should_continue is False
    assert state["authority"] == renewed.authority
    assert state["authority"].stage_state_version == authority.stage_state_version + 1
    assert state["authority"].attempt_state_version == authority.attempt_state_version + 1


@pytest.mark.asyncio
async def test_private_mutation_entry_always_reserves_and_consumes_and_accepts_no_locked_dto(monkeypatch):
    *rows, authority = _case()
    rows = tuple(rows)
    session = _Session("direct", [], rows)
    calls = _install_receipt_runtime(monkeypatch, rows, observed=(NOW,))
    forged_locked = LockedStageExecutionReceipt(
        authority=authority,
        workflow=rows[0],
        stage=rows[1],
        message=rows[2],
        delivery=rows[3],
        attempt=rows[4],
        observed_at=NOW,
    )

    with pytest.raises(TypeError, match="locked"):
        await worker._reserve_consume_and_heartbeat(
            session,
            authority=authority,
            duration=60,
            locked=forged_locked,
        )
    assert calls == []
    assert session.flushes == []

    async with session.begin():
        pending = await worker._reserve_consume_and_heartbeat(
            session,
            authority=authority,
            duration=60,
        )

    assert pending._candidate.stage_state_version == authority.stage_state_version + 1
    assert [call[0] for call in calls] == ["reserve", "consume"]
    assert [type(item).__name__ for item in (rows[1], rows[4])] == ["StageRun", "StageAttempt"]
    assert len(session.flushes) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("duration", [True, 0, 3_601])
async def test_private_mutation_entry_rejects_hostile_duration_before_receipt_or_write(monkeypatch, duration):
    *rows, authority = _case()
    rows = tuple(rows)
    session = _Session("direct", [], rows)
    calls = _install_receipt_runtime(monkeypatch, rows, observed=(NOW,))

    async with session.begin():
        with pytest.raises(WorkflowValidation, match="lease_seconds"):
            await worker._reserve_consume_and_heartbeat(
                session,
                authority=authority,
                duration=duration,
            )

    assert calls == []
    assert session.flushes == []


@pytest.mark.asyncio
async def test_checkpoint_commits_then_confirms_and_mutates_only_exact_s_a_fields(monkeypatch):
    *rows, authority = _case()
    rows = tuple(rows)
    before = tuple(_column_snapshot(value) for value in rows)
    factory, mutation, confirmation, events = _sessions(rows)
    calls = _install_receipt_runtime(monkeypatch, rows)
    checkpoint = {"z": [2, 1], "e\u0301": "value-e\u0301"}
    expected_checkpoint = {"z": [2, 1], "é": "value-é"}
    expected_checksum = checksum_json(expected_checkpoint)
    build_public_result = worker._build_public_checkpoint_result

    def build_after_context_exit(*args, **kwargs):
        assert events[-1] == "confirmation:session_exit"
        events.append("public_checkpoint_result")
        return build_public_result(*args, **kwargs)

    monkeypatch.setattr(worker, "_build_public_checkpoint_result", build_after_context_exit)

    result = await worker.coordinate_stage_checkpoint(
        factory,
        authority=authority,
        checkpoint_schema_version=CHECKPOINT_SCHEMA,
        checkpoint=checkpoint,
        lease_seconds=120,
    )

    workflow, stage, message, delivery, attempt = rows
    after = tuple(_column_snapshot(value) for value in rows)
    assert result.disposition == "renewed"
    assert result.should_continue is True
    assert result.authority is not None and result.authority is not authority
    assert result.previous_checkpoint_version == authority.checkpoint_version
    assert result.checkpoint_version == authority.checkpoint_version + 1
    assert result.stage_state_version == authority.stage_state_version + 1
    assert result.attempt_state_version == authority.attempt_state_version + 1
    assert result.requested_checkpoint_checksum == expected_checksum
    assert result.committed_checkpoint_checksum == expected_checksum
    assert result.heartbeat_at == NOW
    assert result.lease_expires_at == NOW + timedelta(seconds=120)
    assert stage.checkpoint == expected_checkpoint and stage.checkpoint is not checkpoint
    assert stage.checkpoint_checksum == expected_checksum
    assert stage.checkpoint_version == attempt.checkpoint_end_version == 1
    assert stage.heartbeat_at == attempt.heartbeat_at == NOW
    assert stage.lease_expires_at == attempt.lease_expires_at == result.lease_expires_at
    assert _changed_columns(before[0], after[0]) == set()
    assert _changed_columns(before[1], after[1]) == {
        "checkpoint",
        "checkpoint_checksum",
        "checkpoint_version",
        "heartbeat_at",
        "lease_expires_at",
        "state_version",
    }
    assert _changed_columns(before[2], after[2]) == set()
    assert _changed_columns(before[3], after[3]) == set()
    assert _changed_columns(before[4], after[4]) == {
        "checkpoint_end_version",
        "heartbeat_at",
        "lease_expires_at",
        "state_version",
    }
    assert confirmation.flushes == []
    assert mutation.commit_calls == confirmation.commit_calls == 0
    assert factory.calls == 2
    assert [call[0] for call in calls] == ["reserve", "consume", "reserve", "consume"]
    assert events == [
        "mutation:session_enter",
        "mutation:tx_enter",
        "mutation:flush:StageRun",
        "mutation:flush:StageAttempt",
        "mutation:commit",
        "mutation:tx_exit",
        "mutation:session_exit",
        "confirmation:session_enter",
        "confirmation:tx_enter",
        "confirmation:commit",
        "confirmation:tx_exit",
        "confirmation:session_exit",
        "public_checkpoint_result",
    ]


@pytest.mark.asyncio
async def test_checkpoint_uses_prevalidated_clone_when_caller_mutates_original_at_factory_boundary(monkeypatch):
    *rows, authority = _case()
    rows = tuple(rows)
    base_factory, *_ = _sessions(rows)
    _install_receipt_runtime(monkeypatch, rows)
    checkpoint = {"cursor": 7, "nested": {"value": "before"}}
    expected = copy.deepcopy(checkpoint)

    def mutating_factory():
        checkpoint.clear()
        checkpoint["attacker"] = "after-validation"
        return base_factory()

    result = await worker.coordinate_stage_checkpoint(
        mutating_factory,
        authority=authority,
        checkpoint_schema_version=CHECKPOINT_SCHEMA,
        checkpoint=checkpoint,
    )

    assert result.requested_checkpoint_checksum == checksum_json(expected)
    assert result.committed_checkpoint_checksum == checksum_json(expected)
    assert rows[1].checkpoint == expected
    assert rows[1].checkpoint is not checkpoint


@pytest.mark.asyncio
async def test_checkpoint_never_shortens_existing_lease(monkeypatch):
    old_expiry = NOW + timedelta(minutes=10)
    *rows, authority = _case(lease_expires_at=old_expiry)
    rows = tuple(rows)
    factory, *_ = _sessions(rows)
    _install_receipt_runtime(monkeypatch, rows)

    result = await worker.coordinate_stage_checkpoint(
        factory,
        authority=authority,
        checkpoint_schema_version=CHECKPOINT_SCHEMA,
        checkpoint={"cursor": 1},
        lease_seconds=60,
    )

    assert result.previous_lease_expires_at == old_expiry
    assert result.lease_expires_at == old_expiry
    assert result.authority is not None
    assert result.authority.lease_expires_at == old_expiry


@pytest.mark.asyncio
async def test_checkpoint_rejects_hostile_schema_payload_and_bounds_before_factory_or_sql(monkeypatch):
    *rows, authority = _case()
    rows = tuple(rows)
    calls = _install_receipt_runtime(monkeypatch, rows)

    class DictSubclass(dict):
        pass

    class StringSubclass(str):
        pass

    class NulHidingString(str):
        def __contains__(self, _item):
            return False

    class SpoofedString:
        @property
        def __class__(self):
            return str

    class RaisingClass:
        @property
        def __class__(self):
            raise RuntimeError("hostile class dispatch")

    class HostileMeta(type):
        def __getattribute__(cls, name):
            if name == "__name__":
                raise RuntimeError("hostile metaclass name dispatch")
            return super().__getattribute__(name)

    class HostileName(metaclass=HostileMeta):
        pass

    deep: dict[str, object] = {}
    cursor = deep
    for _ in range(22):
        child: dict[str, object] = {}
        cursor["child"] = child
        cursor = child
    hostile_cases = (
        (StringSubclass(CHECKPOINT_SCHEMA), {}, 300),
        ("", {}, 300),
        (f"v{'x' * 80}", {}, 300),
        (CHECKPOINT_SCHEMA, DictSubclass(ok=True), 300),
        (CHECKPOINT_SCHEMA, {"value": float("nan")}, 300),
        (CHECKPOINT_SCHEMA, {"value": "before\x00after"}, 300),
        (CHECKPOINT_SCHEMA, {"key\x00nul": "value"}, 300),
        (CHECKPOINT_SCHEMA, {"value": NulHidingString("before\x00after")}, 300),
        (CHECKPOINT_SCHEMA, {NulHidingString("key\x00nul"): "value"}, 300),
        (CHECKPOINT_SCHEMA, {"value": SpoofedString()}, 300),
        (CHECKPOINT_SCHEMA, {SpoofedString(): "value"}, 300),
        (CHECKPOINT_SCHEMA, {"value": RaisingClass()}, 300),
        (CHECKPOINT_SCHEMA, {RaisingClass(): "value"}, 300),
        (CHECKPOINT_SCHEMA, {"value": HostileName()}, 300),
        (CHECKPOINT_SCHEMA, {HostileName(): "value"}, 300),
        (CHECKPOINT_SCHEMA, {"value": "\ud800"}, 300),
        (CHECKPOINT_SCHEMA, {"value": "x" * (256 * 1024 + 1)}, 300),
        (CHECKPOINT_SCHEMA, deep, 300),
        (CHECKPOINT_SCHEMA, {"items": list(range(2_001))}, 300),
        (CHECKPOINT_SCHEMA, {}, True),
        (CHECKPOINT_SCHEMA, {}, 0),
        (CHECKPOINT_SCHEMA, {}, 3_601),
    )
    for schema_version, checkpoint, duration in hostile_cases:
        factory = _Factory([])
        with pytest.raises(WorkflowValidation):
            await worker.coordinate_stage_checkpoint(
                factory,
                authority=authority,
                checkpoint_schema_version=schema_version,
                checkpoint=checkpoint,
                lease_seconds=duration,
            )
        assert factory.calls == 0
    with pytest.raises(WorkflowValidation, match="exact JSON object"):
        await worker.coordinate_stage_checkpoint(
            _Factory([]),
            authority=authority,
            checkpoint_schema_version=CHECKPOINT_SCHEMA,
            checkpoint=[],
        )
    invalid_authority_factory = _Factory([])
    with pytest.raises(OutboxValidation, match="exact executable"):
        await worker.coordinate_stage_checkpoint(
            invalid_authority_factory,
            authority=object(),
            checkpoint_schema_version=CHECKPOINT_SCHEMA,
            checkpoint={},
        )
    assert invalid_authority_factory.calls == 0
    with pytest.raises(WorkflowValidation, match="session_factory"):
        await worker.coordinate_stage_checkpoint(
            None,
            authority=authority,
            checkpoint_schema_version=CHECKPOINT_SCHEMA,
            checkpoint={},
        )
    assert calls == []


@pytest.mark.asyncio
async def test_checkpoint_initial_and_confirmation_lease_loss_return_distinct_safe_stale_facts(monkeypatch):
    *initial_rows, initial_authority = _case()
    initial_rows = tuple(initial_rows)
    initial_events: list[str] = []
    initial_factory = _Factory([_Session("initial", initial_events, initial_rows)])
    _install_receipt_runtime(
        monkeypatch,
        initial_rows,
        reserve_effects=[OutboxLeaseLost("initial stale")],
    )
    requested_checksum = checksum_json({"cursor": 1})
    initial = await worker.coordinate_stage_checkpoint(
        initial_factory,
        authority=initial_authority,
        checkpoint_schema_version=CHECKPOINT_SCHEMA,
        checkpoint={"cursor": 1},
    )
    assert initial_events[-1] == "initial:session_exit"
    assert initial.disposition == "stale" and initial.should_continue is False
    assert initial.authority is None and initial.heartbeat_at is None
    assert initial.requested_checkpoint_checksum == requested_checksum
    assert initial.committed_checkpoint_checksum is None
    assert initial.checkpoint_version == initial.previous_checkpoint_version == 0
    assert initial.stage_state_version == initial.previous_stage_state_version
    assert initial.attempt_state_version == initial.previous_attempt_state_version

    *confirmation_rows, confirmation_authority = _case()
    confirmation_rows = tuple(confirmation_rows)
    confirmation_factory, _, _, confirmation_events = _sessions(confirmation_rows)
    _install_receipt_runtime(
        monkeypatch,
        confirmation_rows,
        observed=(NOW,),
        reserve_effects=[None, OutboxLeaseLost("cancelled after commit")],
    )
    confirmation = await worker.coordinate_stage_checkpoint(
        confirmation_factory,
        authority=confirmation_authority,
        checkpoint_schema_version=CHECKPOINT_SCHEMA,
        checkpoint={"cursor": 1},
    )
    assert confirmation_events[-1] == "confirmation:session_exit"
    assert confirmation.disposition == "stale" and confirmation.should_continue is False
    assert confirmation.authority is None and confirmation.heartbeat_at == NOW
    assert confirmation.committed_checkpoint_checksum == requested_checksum
    assert confirmation.checkpoint_version == confirmation.previous_checkpoint_version + 1
    assert confirmation.stage_state_version == confirmation.previous_stage_state_version + 1
    assert confirmation.attempt_state_version == confirmation.previous_attempt_state_version + 1


@pytest.mark.asyncio
async def test_checkpoint_schema_mismatch_and_locked_version_corruption_propagate_without_flush(monkeypatch):
    *rows, authority = _case()
    rows = tuple(rows)
    schema_session = _Session("schema", [], rows)
    _install_receipt_runtime(monkeypatch, rows, observed=(NOW,))
    with pytest.raises(WorkflowCheckpointConflict, match="schema version"):
        await worker.coordinate_stage_checkpoint(
            _Factory([schema_session]),
            authority=authority,
            checkpoint_schema_version="research-stage-checkpoint-v2",
            checkpoint={"cursor": 1},
        )
    assert schema_session.flushes == []

    rows[-1].checkpoint_end_version = 1
    corrupt_session = _Session("corrupt", [], rows)
    _install_receipt_runtime(monkeypatch, rows, observed=(NOW,))
    with pytest.raises(WorkflowStoredContractError, match="contradict"):
        await worker.coordinate_stage_checkpoint(
            _Factory([corrupt_session]),
            authority=authority,
            checkpoint_schema_version=CHECKPOINT_SCHEMA,
            checkpoint={"cursor": 1},
        )
    assert corrupt_session.flushes == []


@pytest.mark.asyncio
async def test_private_checkpoint_writer_revalidates_every_input_before_receipt_or_write(monkeypatch):
    *rows, authority = _case()
    rows = tuple(rows)
    session = _Session("direct", [], rows)
    calls = _install_receipt_runtime(monkeypatch, rows, observed=(NOW,))

    class DictSubclass(dict):
        pass

    class StringSubclass(str):
        pass

    class NulHidingString(str):
        def __contains__(self, _item):
            return False

    class SpoofedString:
        @property
        def __class__(self):
            return str

    class RaisingClass:
        @property
        def __class__(self):
            raise RuntimeError("hostile class dispatch")

    class HostileMeta(type):
        def __getattribute__(cls, name):
            if name == "__name__":
                raise RuntimeError("hostile metaclass name dispatch")
            return super().__getattribute__(name)

    class HostileName(metaclass=HostileMeta):
        pass

    hostile_cases = (
        (StringSubclass(CHECKPOINT_SCHEMA), {}, 60),
        ("", {}, 60),
        (CHECKPOINT_SCHEMA, DictSubclass(ok=True), 60),
        (CHECKPOINT_SCHEMA, {"value": float("nan")}, 60),
        (CHECKPOINT_SCHEMA, {"value": "before\x00after"}, 60),
        (CHECKPOINT_SCHEMA, {"key\x00nul": "value"}, 60),
        (CHECKPOINT_SCHEMA, {"value": NulHidingString("before\x00after")}, 60),
        (CHECKPOINT_SCHEMA, {NulHidingString("key\x00nul"): "value"}, 60),
        (CHECKPOINT_SCHEMA, {"value": SpoofedString()}, 60),
        (CHECKPOINT_SCHEMA, {SpoofedString(): "value"}, 60),
        (CHECKPOINT_SCHEMA, {"value": RaisingClass()}, 60),
        (CHECKPOINT_SCHEMA, {RaisingClass(): "value"}, 60),
        (CHECKPOINT_SCHEMA, {"value": HostileName()}, 60),
        (CHECKPOINT_SCHEMA, {HostileName(): "value"}, 60),
        (CHECKPOINT_SCHEMA, {"value": "\ud800"}, 60),
        (CHECKPOINT_SCHEMA, {}, True),
        (CHECKPOINT_SCHEMA, {}, 0),
        (CHECKPOINT_SCHEMA, {}, 3_601),
    )
    for schema_version, checkpoint, duration in hostile_cases:
        async with session.begin():
            with pytest.raises(WorkflowValidation):
                await worker._reserve_consume_and_checkpoint(
                    session,
                    authority=authority,
                    checkpoint_schema_version=schema_version,
                    checkpoint=checkpoint,
                    duration=duration,
                )
        assert calls == []
        assert session.flushes == []


@pytest.mark.asyncio
async def test_private_checkpoint_writer_cannot_accept_forged_future_locked_dto(monkeypatch):
    *rows, authority = _case()
    rows = tuple(rows)
    session = _Session("direct", [], rows)
    calls = _install_receipt_runtime(monkeypatch, rows, observed=(NOW,))
    forged_locked = LockedStageExecutionReceipt(
        authority=authority,
        workflow=rows[0],
        stage=rows[1],
        message=rows[2],
        delivery=rows[3],
        attempt=rows[4],
        observed_at=NOW + timedelta(days=365),
    )

    with pytest.raises(TypeError, match="locked"):
        await worker._reserve_consume_and_checkpoint(
            session,
            authority=authority,
            checkpoint_schema_version=CHECKPOINT_SCHEMA,
            checkpoint={"cursor": 1},
            duration=60,
            locked=forged_locked,
        )
    assert calls == []
    assert session.flushes == []

    async with session.begin():
        mutation_facts = await worker._reserve_consume_and_checkpoint(
            session,
            authority=authority,
            checkpoint_schema_version=CHECKPOINT_SCHEMA,
            checkpoint={"cursor": 1},
            duration=60,
        )
    assert [call[0] for call in calls] == ["reserve", "consume"]
    assert mutation_facts.heartbeat_at == NOW
    assert mutation_facts.lease_expires_at == NOW + timedelta(seconds=60)
    assert mutation_facts.lease_expires_at < forged_locked.observed_at
    assert not hasattr(mutation_facts, "authority")
    assert not hasattr(mutation_facts, "candidate")
    assert not hasattr(mutation_facts, "_candidate")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        "flush",
        "mutation_commit",
        "mutation_session_exit",
        "confirmation_commit",
        "confirmation_session_exit",
    ],
)
async def test_checkpoint_flush_commit_and_context_failures_propagate_without_public_result(monkeypatch, failure):
    *rows, authority = _case()
    rows = tuple(rows)
    before = tuple(_column_snapshot(value) for value in rows)
    mutation_options: dict[str, object] = {}
    confirmation_options: dict[str, object] = {}
    if failure == "flush":
        mutation_options["flush_error_at"] = 1
    elif failure == "mutation_commit":
        mutation_options["commit_error"] = RuntimeError("mutation commit failed")
    elif failure == "mutation_session_exit":
        mutation_options["exit_error"] = RuntimeError("mutation session exit failed")
    elif failure == "confirmation_commit":
        confirmation_options["commit_error"] = RuntimeError("confirmation commit failed")
    else:
        confirmation_options["exit_error"] = RuntimeError("confirmation session exit failed")
    factory, *_ = _sessions(
        rows,
        mutation_options=mutation_options,
        confirmation_options=confirmation_options,
    )
    _install_receipt_runtime(monkeypatch, rows)

    def forbid_public_result(*_args, **_kwargs):
        pytest.fail("Failed checkpoint coordination cannot construct a public result")

    monkeypatch.setattr(worker, "_build_public_checkpoint_result", forbid_public_result)
    with pytest.raises(RuntimeError, match="failed"):
        await worker.coordinate_stage_checkpoint(
            factory,
            authority=authority,
            checkpoint_schema_version=CHECKPOINT_SCHEMA,
            checkpoint={"cursor": 1},
        )

    after = tuple(_column_snapshot(value) for value in rows)
    if failure in {"flush", "mutation_commit"}:
        assert after == before
        assert factory.calls == 1
    elif failure == "mutation_session_exit":
        assert _changed_columns(before[1], after[1]) == {
            "checkpoint",
            "checkpoint_checksum",
            "checkpoint_version",
            "heartbeat_at",
            "lease_expires_at",
            "state_version",
        }
        assert factory.calls == 1
    else:
        assert _changed_columns(before[1], after[1]) == {
            "checkpoint",
            "checkpoint_checksum",
            "checkpoint_version",
            "heartbeat_at",
            "lease_expires_at",
            "state_version",
        }
        assert factory.calls == 2


@pytest.mark.asyncio
async def test_checkpoint_factory_same_session_and_commit_lease_loss_fail_closed(monkeypatch):
    *rows, authority = _case()
    rows = tuple(rows)
    calls = _install_receipt_runtime(monkeypatch, rows)
    factory_error = _Factory(error=RuntimeError("factory failed"))
    with pytest.raises(RuntimeError, match="factory failed"):
        await worker.coordinate_stage_checkpoint(
            factory_error,
            authority=authority,
            checkpoint_schema_version=CHECKPOINT_SCHEMA,
            checkpoint={"cursor": 1},
        )
    assert calls == []

    commit_factory, *_ = _sessions(
        rows,
        mutation_options={"commit_error": OutboxLeaseLost("commit failed")},
    )
    _install_receipt_runtime(monkeypatch, rows)
    with pytest.raises(OutboxLeaseLost, match="commit failed"):
        await worker.coordinate_stage_checkpoint(
            commit_factory,
            authority=authority,
            checkpoint_schema_version=CHECKPOINT_SCHEMA,
            checkpoint={"cursor": 1},
        )

    events: list[str] = []
    reused = _Session("reused", events, rows)
    reused_factory = _Factory([reused, reused])
    _install_receipt_runtime(monkeypatch, rows, observed=(NOW,))
    with pytest.raises(WorkflowValidation, match="distinct fresh session"):
        await worker.coordinate_stage_checkpoint(
            reused_factory,
            authority=authority,
            checkpoint_schema_version=CHECKPOINT_SCHEMA,
            checkpoint={"cursor": 1},
        )
    assert reused_factory.calls == 2
    assert events[-1] == "reused:session_exit"


@pytest.mark.asyncio
async def test_checkpoint_rollback_leaves_old_authority_usable(monkeypatch):
    *rows, authority = _case()
    rows = tuple(rows)
    failing_factory, *_ = _sessions(
        rows,
        mutation_options={"commit_error": RuntimeError("mutation commit failed")},
    )
    _install_receipt_runtime(monkeypatch, rows)
    with pytest.raises(RuntimeError, match="mutation commit failed"):
        await worker.coordinate_stage_checkpoint(
            failing_factory,
            authority=authority,
            checkpoint_schema_version=CHECKPOINT_SCHEMA,
            checkpoint={"cursor": 1},
        )

    assert rows[1].checkpoint_version == authority.checkpoint_version
    assert rows[1].state_version == authority.stage_state_version
    assert rows[-1].state_version == authority.attempt_state_version
    retry_factory, *_ = _sessions(rows)
    _install_receipt_runtime(monkeypatch, rows)
    retry = await worker.coordinate_stage_checkpoint(
        retry_factory,
        authority=authority,
        checkpoint_schema_version=CHECKPOINT_SCHEMA,
        checkpoint={"cursor": 1},
    )
    assert retry.disposition == "renewed"
    assert retry.authority is not None


@pytest.mark.asyncio
async def test_checkpoint_confirmation_detects_committed_content_corruption(monkeypatch):
    *rows, authority = _case()
    rows = tuple(rows)

    def corrupt_after_commit(_session):
        rows[1].checkpoint_checksum = "0" * 64

    factory, *_ = _sessions(
        rows,
        mutation_options={"on_commit": corrupt_after_commit},
    )
    _install_receipt_runtime(monkeypatch, rows)
    with pytest.raises(WorkflowStoredContractError, match="Committed checkpoint contradicts"):
        await worker.coordinate_stage_checkpoint(
            factory,
            authority=authority,
            checkpoint_schema_version=CHECKPOINT_SCHEMA,
            checkpoint={"cursor": 1},
        )
    assert factory.calls == 2


@pytest.mark.asyncio
async def test_concurrent_same_checkpoint_authority_exactly_one_commits(monkeypatch):
    *rows, authority = _case()
    rows = tuple(rows)
    state = {"authority": authority}
    row_lock = asyncio.Lock()
    first_lock_acquired = asyncio.Event()
    let_first_continue = asyncio.Event()
    reserve_count = 0
    clock_count = 0
    session_count = 0

    def on_commit(session):
        if not session.flushes:
            return
        _workflow, stage, _message, _delivery, attempt = rows
        state["authority"] = worker._renewed_authority(
            state["authority"],
            stage_state_version=stage.state_version,
            attempt_state_version=attempt.state_version,
            checkpoint_version=stage.checkpoint_version,
            lease_expires_at=stage.lease_expires_at,
        )

    def on_transaction_exit(_session):
        if row_lock.locked():
            row_lock.release()

    def session_factory():
        nonlocal session_count
        session_count += 1
        return _Session(
            f"checkpoint-concurrent-{session_count}",
            [],
            rows,
            on_commit=on_commit,
            on_transaction_exit=on_transaction_exit,
        )

    async def reserve(_db, *, authority):
        nonlocal reserve_count
        reserve_count += 1
        await row_lock.acquire()
        if reserve_count == 1:
            first_lock_acquired.set()
            await let_first_continue.wait()
        if authority != state["authority"]:
            raise OutboxLeaseLost("concurrent checkpoint authority lost")
        return object()

    async def consume(_db, *, reservation, authority):
        nonlocal clock_count
        del reservation
        clock_count += 1
        workflow, stage, message, delivery, attempt = rows
        return LockedStageExecutionReceipt(
            authority=authority,
            workflow=workflow,
            stage=stage,
            message=message,
            delivery=delivery,
            attempt=attempt,
            observed_at=NOW + timedelta(microseconds=clock_count),
        )

    monkeypatch.setattr(worker, "_reserve_stage_execution_receipt", reserve)
    monkeypatch.setattr(worker, "_consume_stage_execution_receipt", consume)
    first_task = asyncio.create_task(
        worker.coordinate_stage_checkpoint(
            session_factory,
            authority=authority,
            checkpoint_schema_version=CHECKPOINT_SCHEMA,
            checkpoint={"winner": "same"},
        )
    )
    await asyncio.wait_for(first_lock_acquired.wait(), timeout=1)
    second_task = asyncio.create_task(
        worker.coordinate_stage_checkpoint(
            session_factory,
            authority=authority,
            checkpoint_schema_version=CHECKPOINT_SCHEMA,
            checkpoint={"winner": "same"},
        )
    )
    await asyncio.sleep(0)
    let_first_continue.set()
    first, second = await asyncio.gather(first_task, second_task)

    assert {first.disposition, second.disposition} == {"renewed", "stale"}
    renewed = first if first.disposition == "renewed" else second
    stale = second if renewed is first else first
    assert renewed.authority is not None and renewed.should_continue is True
    assert stale.authority is None and stale.should_continue is False
    assert state["authority"] == renewed.authority
    assert state["authority"].checkpoint_version == authority.checkpoint_version + 1
    assert rows[1].checkpoint == {"winner": "same"}


@pytest.mark.asyncio
async def test_checkpoint_and_heartbeat_authorities_interoperate_without_replay_heuristics(monkeypatch):
    *rows, initial_authority = _case()
    rows = tuple(rows)
    state = {"authority": initial_authority}
    clock_count = 0
    session_count = 0

    def on_commit(session):
        if not session.flushes:
            return
        _workflow, stage, _message, _delivery, attempt = rows
        state["authority"] = worker._renewed_authority(
            state["authority"],
            stage_state_version=stage.state_version,
            attempt_state_version=attempt.state_version,
            checkpoint_version=stage.checkpoint_version,
            lease_expires_at=stage.lease_expires_at,
        )

    def session_factory():
        nonlocal session_count
        session_count += 1
        return _Session(
            f"interop-{session_count}",
            [],
            rows,
            on_commit=on_commit,
        )

    async def reserve(_db, *, authority):
        if authority != state["authority"]:
            raise OutboxLeaseLost("old authority")
        return object()

    async def consume(_db, *, reservation, authority):
        nonlocal clock_count
        del reservation
        clock_count += 1
        workflow, stage, message, delivery, attempt = rows
        return LockedStageExecutionReceipt(
            authority=authority,
            workflow=workflow,
            stage=stage,
            message=message,
            delivery=delivery,
            attempt=attempt,
            observed_at=NOW + timedelta(microseconds=clock_count),
        )

    monkeypatch.setattr(worker, "_reserve_stage_execution_receipt", reserve)
    monkeypatch.setattr(worker, "_consume_stage_execution_receipt", consume)

    first_checkpoint = await worker.coordinate_stage_checkpoint(
        session_factory,
        authority=initial_authority,
        checkpoint_schema_version=CHECKPOINT_SCHEMA,
        checkpoint={"cursor": 1},
    )
    assert first_checkpoint.authority == state["authority"]
    assert first_checkpoint.checkpoint_version == 1

    heartbeat = await worker.coordinate_stage_heartbeat(
        session_factory,
        authority=first_checkpoint.authority,
    )
    assert heartbeat.authority == state["authority"]
    assert heartbeat.authority is not None and heartbeat.authority.checkpoint_version == 1

    second_checkpoint = await worker.coordinate_stage_checkpoint(
        session_factory,
        authority=heartbeat.authority,
        checkpoint_schema_version=CHECKPOINT_SCHEMA,
        checkpoint={"cursor": 2},
    )
    assert second_checkpoint.authority == state["authority"]
    assert second_checkpoint.checkpoint_version == 2
    assert rows[1].checkpoint == {"cursor": 2}

    stale_old = await worker.coordinate_stage_checkpoint(
        session_factory,
        authority=initial_authority,
        checkpoint_schema_version=CHECKPOINT_SCHEMA,
        checkpoint={"cursor": 99},
    )
    assert stale_old.disposition == "stale"
    assert stale_old.authority is None
    assert rows[1].checkpoint == {"cursor": 2}


def test_checkpoint_public_result_is_frozen_fixed_point_without_payload_or_pending_capability():
    *_, authority = _case()
    requested_checksum = checksum_json({"cursor": 1})
    renewed = worker._renewed_authority(
        authority,
        stage_state_version=authority.stage_state_version + 1,
        attempt_state_version=authority.attempt_state_version + 1,
        checkpoint_version=authority.checkpoint_version + 1,
        lease_expires_at=NOW + timedelta(minutes=5),
    )
    result = worker.CoordinatedStageCheckpoint(
        workflow_run_id=authority.workflow_run_id,
        stage_run_id=authority.stage_run_id,
        stage_attempt_id=authority.stage_attempt_id,
        message_id=authority.message_id,
        delivery_attempt_id=authority.delivery_attempt_id,
        stage_lease_token=authority.stage_lease_token,
        attempt_number=authority.attempt_number,
        delivery_cycle=authority.delivery_cycle,
        cycle_key=authority.cycle_key,
        broker_receipt_id=authority.broker_receipt_id,
        stage_key=authority.stage_key,
        input_checksum=authority.input_checksum,
        checkpoint_schema_version=CHECKPOINT_SCHEMA,
        requested_checkpoint_checksum=requested_checksum,
        committed_checkpoint_checksum=requested_checksum,
        lease_owner=authority.lease_owner,
        workflow_state_version=authority.workflow_state_version,
        previous_checkpoint_version=authority.checkpoint_version,
        checkpoint_version=renewed.checkpoint_version,
        previous_stage_state_version=authority.stage_state_version,
        stage_state_version=renewed.stage_state_version,
        previous_attempt_state_version=authority.attempt_state_version,
        attempt_state_version=renewed.attempt_state_version,
        previous_lease_expires_at=authority.lease_expires_at,
        heartbeat_at=NOW,
        lease_expires_at=renewed.lease_expires_at,
        disposition="renewed",
        authority=renewed,
        should_continue=True,
    )
    assert result.authority == renewed and result.authority is not renewed
    with pytest.raises(OutboxValidation, match="exact monotonic write"):
        replace(result, committed_checkpoint_checksum=None)
    with pytest.raises(OutboxValidation, match="contradicts"):
        replace(result, authority=replace(renewed, stage_key="different_stage"))
    with pytest.raises((FrozenInstanceError, AttributeError)):
        result.disposition = "stale"
    assert "_PendingStageCheckpoint" not in worker.__all__
    assert "_CheckpointMutationFacts" not in worker.__all__
    assert "_reserve_consume_and_checkpoint" not in worker.__all__
    public_fields = {item.name for item in fields(worker.CoordinatedStageCheckpoint)}
    assert not public_fields.intersection({"checkpoint", "reservation", "pending", "workflow", "stage", "message", "delivery", "attempt"})


def test_public_result_is_frozen_fixed_point_and_exposes_no_pending_capability():
    *_, authority = _case()
    renewed = worker._renewed_authority(
        authority,
        stage_state_version=authority.stage_state_version + 1,
        attempt_state_version=authority.attempt_state_version + 1,
        lease_expires_at=NOW + timedelta(minutes=5),
    )
    result = worker.CoordinatedStageHeartbeat(
        workflow_run_id=authority.workflow_run_id,
        stage_run_id=authority.stage_run_id,
        stage_attempt_id=authority.stage_attempt_id,
        message_id=authority.message_id,
        delivery_attempt_id=authority.delivery_attempt_id,
        stage_lease_token=authority.stage_lease_token,
        attempt_number=authority.attempt_number,
        delivery_cycle=authority.delivery_cycle,
        cycle_key=authority.cycle_key,
        broker_receipt_id=authority.broker_receipt_id,
        stage_key=authority.stage_key,
        input_checksum=authority.input_checksum,
        checkpoint_version=authority.checkpoint_version,
        lease_owner=authority.lease_owner,
        workflow_state_version=authority.workflow_state_version,
        previous_stage_state_version=authority.stage_state_version,
        stage_state_version=renewed.stage_state_version,
        previous_attempt_state_version=authority.attempt_state_version,
        attempt_state_version=renewed.attempt_state_version,
        previous_lease_expires_at=authority.lease_expires_at,
        heartbeat_at=NOW,
        lease_expires_at=renewed.lease_expires_at,
        disposition="renewed",
        authority=renewed,
        should_continue=True,
    )
    assert result.authority == renewed and result.authority is not renewed
    with pytest.raises(OutboxValidation, match="contradicts"):
        replace(
            result,
            authority=replace(renewed, stage_key="different_stage"),
        )
    with pytest.raises((FrozenInstanceError, AttributeError)):
        result.disposition = "stale"
    assert "_PendingStageHeartbeat" not in worker.__all__
    assert "_reserve_and_consume_execution_receipt" not in worker.__all__
    assert "_reserve_consume_and_heartbeat" not in worker.__all__
    public_fields = {item.name for item in fields(worker.CoordinatedStageHeartbeat)}
    assert not public_fields.intersection({"reservation", "pending", "workflow", "stage", "message", "delivery", "attempt"})


@pytest.mark.asyncio
async def test_completion_commits_after_a_s_m_order_and_returns_only_safe_facts(monkeypatch):
    rows, authority = _completion_case(target_count=2)
    before = tuple(_column_snapshot(value) for value in rows)
    events: list[str] = []
    session = _Session("completion", events, rows)
    factory = _Factory([session])
    calls, _locked = _install_completion_runtime(monkeypatch, rows, authority)
    build_result = worker._build_public_completion_result

    def build_after_context_exit(*args, **kwargs):
        assert events[-1] == "completion:session_exit"
        events.append("public_result")
        return build_result(*args, **kwargs)

    monkeypatch.setattr(worker, "_build_public_completion_result", build_after_context_exit)
    result = await worker.coordinate_stage_complete(
        factory,
        authority=authority,
        output_manifest={"claims": [{"id": 2}, {"id": 1}]},
    )

    workflow, source, target_one, target_two, message, delivery, attempt = rows
    after = tuple(_column_snapshot(value) for value in rows)
    assert result.disposition == "completed"
    assert result.should_continue is False and result.should_ack is True
    assert result.committed_output_checksum == result.requested_output_checksum
    assert result.workflow_status == "running"
    assert result.workflow_state_version == authority.workflow_state_version
    assert result.stage_state_version == authority.stage_state_version + 1
    assert result.attempt_state_version == authority.attempt_state_version + 1
    assert result.lease_expires_at == authority.lease_expires_at
    assert result.completed_at == NOW and result.workflow_completed_at is None
    assert tuple(item.stage_run_id for item in result.emissions) == (target_one.id, target_two.id)
    assert all(item.available_at == NOW for item in result.emissions)
    assert source.output_manifest == {"claims": [{"id": 2}, {"id": 1}]}
    assert source.output_manifest is not result
    assert [call[0] for call in calls] == ["reserve", "consume", "append"]
    assert events == [
        "completion:session_enter",
        "completion:tx_enter",
        "completion:flush:StageAttempt",
        "completion:flush:StageRun",
        "completion:flush:OutboxMessage",
        "completion:commit",
        "completion:tx_exit",
        "completion:session_exit",
        "public_result",
    ]
    assert _changed_columns(before[0], after[0]) == set()
    assert _changed_columns(before[1], after[1]) == {
        "status",
        "state_version",
        "output_manifest",
        "output_checksum",
        "lease_owner",
        "lease_token",
        "leased_at",
        "lease_expires_at",
        "heartbeat_at",
        "completed_at",
    }
    assert _changed_columns(before[2], after[2]) == {"status", "state_version", "next_attempt_at"}
    assert _changed_columns(before[3], after[3]) == {"status", "state_version", "next_attempt_at"}
    assert _changed_columns(before[4], after[4]) == set()
    assert _changed_columns(before[5], after[5]) == set()
    assert _changed_columns(before[6], after[6]) == {
        "status",
        "state_version",
        "output_checksum",
        "heartbeat_at",
        "completed_at",
    }
    assert session.commit_calls == 0 and factory.calls == 1


@pytest.mark.asyncio
async def test_zero_fanout_completion_flushes_terminal_workflow_last(monkeypatch):
    rows, authority = _completion_case(target_count=0)
    events: list[str] = []
    session = _Session("completion", events, rows)
    factory = _Factory([session])
    calls, _locked = _install_completion_runtime(monkeypatch, rows, authority)

    result = await worker.coordinate_stage_complete(
        factory,
        authority=authority,
        output_manifest={"quality": "partial"},
        outcome="degraded",
    )

    workflow = rows[0]
    assert result.workflow_status == workflow.status == "degraded"
    assert result.workflow_state_version == authority.workflow_state_version + 1
    assert result.workflow_completed_at == result.completed_at == NOW
    assert result.emissions == ()
    assert [call[0] for call in calls] == ["reserve", "consume"]
    assert [item for item in events if ":flush:" in item] == [
        "completion:flush:StageAttempt",
        "completion:flush:StageRun",
        "completion:flush:WorkflowRun",
    ]
    assert workflow.status_reason_code == "workflow.degraded_stages"
    assert workflow.status_summary.endswith("collect")


@pytest.mark.asyncio
@pytest.mark.parametrize("loss_phase", ["reserve", "consume"])
async def test_completion_lease_loss_is_stale_only_after_rollback_and_session_exit(monkeypatch, loss_phase):
    rows, authority = _completion_case()
    events: list[str] = []
    session = _Session("completion", events, rows)
    factory = _Factory([session])
    _install_completion_runtime(
        monkeypatch,
        rows,
        authority,
        reserve_error=OutboxLeaseLost("already completed") if loss_phase == "reserve" else None,
        consume_error=OutboxLeaseLost("already consumed") if loss_phase == "consume" else None,
    )
    build_result = worker._build_public_completion_result

    def build_after_exit(*args, **kwargs):
        assert events[-1] == "completion:session_exit"
        return build_result(*args, **kwargs)

    monkeypatch.setattr(worker, "_build_public_completion_result", build_after_exit)
    result = await worker.coordinate_stage_complete(
        factory,
        authority=authority,
        output_manifest={"claims": 1},
    )

    assert result.disposition == "stale"
    assert result.should_ack is True and result.should_continue is False
    assert result.committed_output_checksum is None
    assert result.completed_at is None and result.emissions == ()
    assert result.stage_state_version == result.previous_stage_state_version
    assert events == [
        "completion:session_enter",
        "completion:tx_enter",
        "completion:rollback",
        "completion:tx_exit",
        "completion:session_exit",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("error_type", [OutboxLeaseLost, _ForeignCompletionReceiptLeaseLost])
async def test_completion_append_lease_loss_propagates_without_public_ack(monkeypatch, error_type):
    rows, authority = _completion_case()
    before = tuple(_column_snapshot(value) for value in rows)
    events: list[str] = []
    session = _Session("completion", events, rows)
    factory = _Factory([session])
    append_error = error_type("append capability lost")
    _install_completion_runtime(
        monkeypatch,
        rows,
        authority,
        append_error=append_error,
    )

    def forbidden_result(*_args, **_kwargs):
        pytest.fail("append authority loss cannot construct a public ACK")

    monkeypatch.setattr(worker, "_build_public_completion_result", forbidden_result)
    with pytest.raises(OutboxLeaseLost) as caught:
        await worker.coordinate_stage_complete(
            factory,
            authority=authority,
            output_manifest={"claims": 1},
        )
    assert caught.value is append_error
    assert tuple(_column_snapshot(value) for value in rows) == before
    assert "completion:rollback" in events


@pytest.mark.asyncio
async def test_completion_direct_writer_propagates_lease_loss(monkeypatch):
    rows, authority = _completion_case()
    receipt_stale = worker._ReceiptAuthorityStale()

    async def lease_lost(*_args, **_kwargs):
        raise OutboxLeaseLost("direct helper lease loss")

    monkeypatch.setattr(worker, "_reserve_stage_completion_graph", lease_lost)
    with pytest.raises(worker._ReceiptAuthorityStale) as caught:
        await worker._reserve_consume_and_complete(
            object(),
            authority=authority,
            output_manifest={"claims": 1},
            outcome="succeeded",
            receipt_stale=receipt_stale,
        )
    assert caught.value is receipt_stale
    assert isinstance(caught.value.__cause__, OutboxLeaseLost)
    assert str(caught.value.__cause__) == "direct helper lease loss"


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_point", ["enter", "exit"])
@pytest.mark.parametrize(
    "error_type",
    [
        worker._ReceiptAuthorityStale,
        _ForeignCompletionReceiptLeaseLost,
        OutboxLeaseLost,
    ],
)
async def test_completion_foreign_stale_sentinel_cannot_forge_public_ack(monkeypatch, failure_point, error_type):
    rows, authority = _completion_case(target_count=0)
    foreign = error_type("foreign sentinel")
    session = _Session(
        "completion",
        [],
        rows,
        enter_error=foreign if failure_point == "enter" else None,
        exit_error=foreign if failure_point == "exit" else None,
    )
    factory = _Factory([session])
    _install_completion_runtime(monkeypatch, rows, authority)

    def forbidden_result(*_args, **_kwargs):
        pytest.fail("foreign sentinel cannot construct a public ACK")

    monkeypatch.setattr(worker, "_build_public_completion_result", forbidden_result)
    with pytest.raises(error_type) as caught:
        await worker.coordinate_stage_complete(
            factory,
            authority=authority,
            output_manifest={"claims": 1},
        )
    assert caught.value is foreign


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error_type",
    [
        OutboxLeaseLost,
        _ForeignCompletionReceiptLeaseLost,
        worker._ReceiptAuthorityStale,
    ],
)
async def test_completion_commit_lease_loss_propagates_without_public_ack(monkeypatch, error_type):
    rows, authority = _completion_case(target_count=0)
    commit_error = error_type("commit outcome is unknown")
    session = _Session(
        "completion",
        [],
        rows,
        commit_error=commit_error,
    )
    factory = _Factory([session])
    _install_completion_runtime(monkeypatch, rows, authority)

    def forbidden_result(*_args, **_kwargs):
        pytest.fail("commit failure cannot construct a public ACK")

    monkeypatch.setattr(worker, "_build_public_completion_result", forbidden_result)
    with pytest.raises(error_type) as caught:
        await worker.coordinate_stage_complete(
            factory,
            authority=authority,
            output_manifest={"claims": 1},
        )
    assert caught.value is commit_error


@pytest.mark.asyncio
async def test_completion_rejects_swapped_preallocated_target_message_ids(monkeypatch):
    rows, authority = _completion_case(target_count=2)
    before = tuple(_column_snapshot(value) for value in rows)
    session = _Session("completion", [], rows)
    factory = _Factory([session])
    _install_completion_runtime(
        monkeypatch,
        rows,
        authority,
        swap_message_ids=True,
    )

    with pytest.raises(WorkflowStoredContractError, match="message fixed point"):
        await worker.coordinate_stage_complete(
            factory,
            authority=authority,
            output_manifest={"claims": 1},
        )
    assert tuple(_column_snapshot(value) for value in rows) == before


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("output_manifest", "outcome"),
    [
        ([], "succeeded"),
        ({"value": float("nan")}, "succeeded"),
        ({"value": "bad\x00value"}, "succeeded"),
        ({"bad\x00key": "value"}, "succeeded"),
        ({"value": object()}, "succeeded"),
        ({"value": 1}, "failed"),
        ({"value": 1}, str("succeeded")),
    ],
)
async def test_completion_rejects_hostile_request_before_factory(
    output_manifest,
    outcome,
):
    *_, authority = _case()

    class OutcomeSubclass(str):
        pass

    selected_outcome = OutcomeSubclass(outcome) if output_manifest == {"value": 1} and outcome == "succeeded" else outcome
    factory = _Factory(error=AssertionError("factory must not be called"))
    with pytest.raises(WorkflowValidation):
        await worker.coordinate_stage_complete(
            factory,
            authority=authority,
            output_manifest=output_manifest,
            outcome=selected_outcome,
        )
    assert factory.calls == 0


@pytest.mark.asyncio
async def test_completion_direct_writer_revalidates_before_reserve(monkeypatch):
    *_, authority = _case()
    calls = 0
    receipt_stale = worker._ReceiptAuthorityStale()

    async def forbidden_reserve(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("invalid direct request reached receipt reservation")

    monkeypatch.setattr(worker, "_reserve_stage_completion_graph", forbidden_reserve)
    for payload, outcome in (([], "succeeded"), ({"nul": "\x00"}, "succeeded"), ({}, "failed")):
        with pytest.raises(WorkflowValidation):
            await worker._reserve_consume_and_complete(
                object(),
                authority=authority,
                output_manifest=payload,
                outcome=outcome,
                receipt_stale=receipt_stale,
            )
    assert calls == 0


@pytest.mark.asyncio
async def test_completion_direct_writer_requires_exact_local_stale_sentinel_before_reserve(monkeypatch):
    *_, authority = _case()
    calls = 0

    async def forbidden_reserve(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("invalid sentinel reached receipt reservation")

    class SentinelSubclass(worker._ReceiptAuthorityStale):
        pass

    monkeypatch.setattr(worker, "_reserve_stage_completion_graph", forbidden_reserve)
    with pytest.raises(TypeError, match="receipt_stale"):
        await worker._reserve_consume_and_complete(
            object(),
            authority=authority,
            output_manifest={},
            outcome="succeeded",
        )
    for hostile in (object(), SentinelSubclass()):
        with pytest.raises(WorkflowValidation, match="coordinator-local sentinel"):
            await worker._reserve_consume_and_complete(
                object(),
                authority=authority,
                output_manifest={},
                outcome="succeeded",
                receipt_stale=hostile,
            )
    assert calls == 0


@pytest.mark.asyncio
async def test_completion_commit_failure_returns_no_result_and_restores_rows(monkeypatch):
    rows, authority = _completion_case(target_count=0)
    before = tuple(_column_snapshot(value) for value in rows)
    session = _Session(
        "completion",
        [],
        rows,
        commit_error=RuntimeError("commit failed"),
    )
    factory = _Factory([session])
    _install_completion_runtime(monkeypatch, rows, authority)

    with pytest.raises(RuntimeError, match="commit failed"):
        await worker.coordinate_stage_complete(
            factory,
            authority=authority,
            output_manifest={"claims": 1},
        )
    assert tuple(_column_snapshot(value) for value in rows) == before


@pytest.mark.asyncio
async def test_completion_detaches_output_before_factory_can_mutate_caller_value(monkeypatch):
    rows, authority = _completion_case(target_count=0)
    session = _Session("completion", [], rows)
    caller_output = {"claims": [{"id": 1}]}
    expected_checksum = checksum_json(caller_output)

    class MutatingFactory(_Factory):
        def __call__(self):
            caller_output["claims"].append({"id": 999})
            return super().__call__()

    factory = MutatingFactory([session])
    _install_completion_runtime(monkeypatch, rows, authority)
    result = await worker.coordinate_stage_complete(
        factory,
        authority=authority,
        output_manifest=caller_output,
    )

    assert caller_output == {"claims": [{"id": 1}, {"id": 999}]}
    assert rows[1].output_manifest == {"claims": [{"id": 1}]}
    assert result.requested_output_checksum == expected_checksum


@pytest.mark.asyncio
@pytest.mark.parametrize("flush_error_at", [1, 2, 3])
async def test_completion_flush_failures_propagate_and_rollback_every_row(monkeypatch, flush_error_at):
    rows, authority = _completion_case(target_count=1)
    before = tuple(_column_snapshot(value) for value in rows)
    session = _Session(
        "completion",
        [],
        rows,
        flush_error_at=flush_error_at,
    )
    factory = _Factory([session])
    _install_completion_runtime(monkeypatch, rows, authority)

    with pytest.raises(RuntimeError, match="flush failed"):
        await worker.coordinate_stage_complete(
            factory,
            authority=authority,
            output_manifest={"claims": 1},
        )
    assert tuple(_column_snapshot(value) for value in rows) == before


@pytest.mark.asyncio
async def test_completion_private_lease_lookalike_from_flush_propagates_without_ack(monkeypatch):
    rows, authority = _completion_case(target_count=1)
    before = tuple(_column_snapshot(value) for value in rows)
    session = _Session("completion", [], rows)
    factory = _Factory([session])
    _install_completion_runtime(monkeypatch, rows, authority)
    flush_error = _ForeignCompletionReceiptLeaseLost("foreign flush lease loss")
    original_flush = session.flush

    async def hostile_flush(objects=None):
        await original_flush(objects)
        raise flush_error

    def forbidden_result(*_args, **_kwargs):
        pytest.fail("flush failure cannot construct a public ACK")

    monkeypatch.setattr(session, "flush", hostile_flush)
    monkeypatch.setattr(worker, "_build_public_completion_result", forbidden_result)
    with pytest.raises(_ForeignCompletionReceiptLeaseLost) as caught:
        await worker.coordinate_stage_complete(
            factory,
            authority=authority,
            output_manifest={"claims": 1},
        )
    assert caught.value is flush_error
    assert tuple(_column_snapshot(value) for value in rows) == before


@pytest.mark.asyncio
async def test_completion_context_exit_failure_propagates_without_public_result(monkeypatch):
    rows, authority = _completion_case(target_count=0)
    session = _Session(
        "completion",
        [],
        rows,
        exit_error=RuntimeError("session exit failed"),
    )
    factory = _Factory([session])
    _install_completion_runtime(monkeypatch, rows, authority)

    def forbidden_result(*_args, **_kwargs):
        pytest.fail("context failure cannot construct a public ACK result")

    monkeypatch.setattr(worker, "_build_public_completion_result", forbidden_result)
    with pytest.raises(RuntimeError, match="session exit failed"):
        await worker.coordinate_stage_complete(
            factory,
            authority=authority,
            output_manifest={"claims": 1},
        )


@pytest.mark.asyncio
async def test_completion_same_authority_concurrency_has_one_commit_and_one_stale(monkeypatch):
    rows, authority = _completion_case(target_count=1)
    first = _Session("first", [], rows)
    second = _Session("second", [], rows)
    factory = _Factory([first, second])
    _calls, locked = _install_completion_runtime(monkeypatch, rows, authority)
    first_reserved = asyncio.Event()
    second_rejected = asyncio.Event()
    reservation = object()
    reserve_count = 0

    async def reserve(_db, *, authority):
        nonlocal reserve_count
        reserve_count += 1
        if reserve_count == 1:
            first_reserved.set()
            await second_rejected.wait()
            return reservation
        await first_reserved.wait()
        second_rejected.set()
        raise OutboxLeaseLost("coordinate already consumed")

    async def consume(_db, *, reservation: object, authority):
        assert reservation is not None
        return locked

    monkeypatch.setattr(worker, "_reserve_stage_completion_graph", reserve)
    monkeypatch.setattr(worker, "_consume_stage_completion_graph", consume)
    task_one = asyncio.create_task(
        worker.coordinate_stage_complete(
            factory,
            authority=authority,
            output_manifest={"claims": 1},
        )
    )
    task_two = asyncio.create_task(
        worker.coordinate_stage_complete(
            factory,
            authority=authority,
            output_manifest={"claims": 1},
        )
    )
    results = await asyncio.gather(task_one, task_two)

    assert sorted(result.disposition for result in results) == ["completed", "stale"]
    assert all(result.should_ack and not result.should_continue for result in results)
    assert reserve_count == 2


@pytest.mark.asyncio
async def test_completion_rollback_leaves_presented_authority_reusable(monkeypatch):
    rows, authority = _completion_case(target_count=1)
    before = tuple(_column_snapshot(value) for value in rows)
    failed_session = _Session("failed", [], rows)
    _install_completion_runtime(
        monkeypatch,
        rows,
        authority,
        append_error=RuntimeError("append failed"),
    )
    with pytest.raises(RuntimeError, match="append failed"):
        await worker.coordinate_stage_complete(
            _Factory([failed_session]),
            authority=authority,
            output_manifest={"claims": 1},
        )
    assert tuple(_column_snapshot(value) for value in rows) == before

    success_session = _Session("success", [], rows)
    _install_completion_runtime(monkeypatch, rows, authority)
    result = await worker.coordinate_stage_complete(
        _Factory([success_session]),
        authority=authority,
        output_manifest={"claims": 1},
    )
    assert result.disposition == "completed"


@pytest.mark.asyncio
@pytest.mark.parametrize("branch", ["retry", "required", "optional", "dead_lettered"])
async def test_failure_records_exact_branch_and_flush_order_after_receipt_consumption(monkeypatch, branch):
    case = _failure_case(branch=branch)
    before = {id(value): _column_snapshot(value) for value in case.rows}
    attempt_heartbeats_before = {attempt.id: attempt.heartbeat_at for attempt in case.attempts}
    events: list[str] = []
    session = _Session("failure", events, case.rows)
    factory = _Factory([session])
    calls, locked = _install_failure_runtime(monkeypatch, case)
    build_result = worker._build_public_failure_result

    def build_after_context_exit(*args, **kwargs):
        assert events[-1] == "failure:session_exit"
        events.append("public_result")
        return build_result(*args, **kwargs)

    monkeypatch.setattr(worker, "_build_public_failure_result", build_after_context_exit)
    result = await worker.coordinate_stage_fail(
        factory,
        authority=case.authority,
        error_text="upstream timeout",
        error_code="source.timeout",
        retryable=branch in {"retry", "dead_lettered"},
    )

    assert result.disposition == "recorded"
    assert result.should_ack is True and result.should_continue is False
    assert result.should_retry is (branch == "retry")
    assert result.error_summary == "upstream timeout"
    assert result.stage_state_version == case.authority.stage_state_version + 1
    assert result.attempt_state_version == case.authority.attempt_state_version + 1
    assert result.lease_expires_at == case.authority.lease_expires_at
    assert result.attempt_completed_at == NOW
    assert case.attempts[0].heartbeat_at == case.attempts[0].completed_at == NOW
    assert {attempt.id: attempt.heartbeat_at for attempt in case.attempts[1:]} == {
        attempt.id: attempt_heartbeats_before[attempt.id] for attempt in case.attempts[1:]
    }
    assert [call[0] for call in calls] == (
        ["reserve", "consume", "append"]
        if branch == "retry"
        else ["reserve", "consume", "cancel"]
        if branch in {"required", "dead_lettered"}
        else ["reserve", "consume"]
    )
    assert events[-3:] == ["failure:tx_exit", "failure:session_exit", "public_result"]
    assert session.commit_calls == 0 and factory.calls == 1

    if branch == "retry":
        assert result.decision == "retry"
        assert result.workflow_status == "running"
        assert result.workflow_state_version == case.authority.workflow_state_version
        assert result.stage_completed_at is None and result.workflow_completed_at is None
        assert result.next_attempt_at == NOW + timedelta(seconds=10)
        assert result.retry_emission is not None
        assert result.retry_emission.message_id == locked.retry_message_id
        assert result.retry_emission.available_at == result.next_attempt_at
        assert [item for item in events if ":flush:" in item] == [
            "failure:flush:StageAttempt",
            "failure:flush:StageRun",
            "failure:flush:OutboxMessage",
        ]
    elif branch == "required":
        assert result.decision == "failed"
        assert result.workflow_status == "failed"
        assert result.workflow_state_version == case.authority.workflow_state_version + 1
        assert result.stage_completed_at == result.workflow_completed_at == NOW
        assert result.cancelled_stage_ids == (case.stages[1].id,)
        assert result.cancelled_attempt_ids == (case.attempts[1].id,)
        assert result.cancelled_message_ids == (case.messages[1].id,)
        assert result.cancelled_delivery_ids == (case.deliveries[1].id,)
        flushes = session.flushes
        flush_types = [dict(item[0])["id"] if len(item) == 1 else None for item in flushes]
        expected_attempt_ids = [attempt.id for attempt in sorted(case.attempts, key=lambda attempt: attempt.id.int)]
        assert flush_types[:2] == [case.deliveries[1].id, case.messages[1].id]
        assert flush_types[2:4] == expected_attempt_ids
        assert flush_types[4:6] == [case.source.id, case.stages[1].id]
        assert flush_types[6:] == [case.workflow.id]
        assert _changed_columns(before[id(case.messages[0])], _column_snapshot(case.messages[0])) == set()
        assert _changed_columns(before[id(case.deliveries[0])], _column_snapshot(case.deliveries[0])) == set()
    elif branch == "optional":
        assert result.decision == "failed"
        assert result.workflow_status == "degraded"
        assert result.workflow_state_version == case.authority.workflow_state_version + 1
        assert result.skipped_stage_ids == (case.stages[1].id,)
        assert result.cancelled_stage_ids == result.cancelled_attempt_ids == ()
        assert result.cancelled_message_ids == result.cancelled_delivery_ids == ()
        assert [item for item in events if ":flush:" in item] == [
            "failure:flush:StageAttempt",
            "failure:flush:StageRun",
            "failure:flush:StageRun",
            "failure:flush:WorkflowRun",
        ]
    else:
        assert result.decision == "dead_lettered"
        assert result.retryable is True and result.should_retry is False
        assert result.workflow_status == "dead_lettered"
        assert result.workflow_state_version == case.authority.workflow_state_version + 1
        assert result.stage_completed_at == result.workflow_completed_at == NOW
        assert result.cancelled_stage_ids == result.cancelled_attempt_ids == ()
        assert result.cancelled_message_ids == result.cancelled_delivery_ids == ()
        assert [item for item in events if ":flush:" in item] == [
            "failure:flush:StageAttempt",
            "failure:flush:StageRun",
            "failure:flush:WorkflowRun",
        ]


@pytest.mark.asyncio
async def test_failure_retry_proves_terminal_source_heartbeat_before_causal_append(monkeypatch):
    case = _failure_case(branch="retry")
    assert case.attempts[0].heartbeat_at < NOW
    session = _Session("failure", [], case.rows)
    _install_failure_runtime(monkeypatch, case)
    append = worker._append_reserved_stage_ready

    async def append_after_terminal_fixed_point(
        db,
        *,
        reservation,
        workflow,
        locked_stages,
        causal_attempt,
    ):
        assert causal_attempt is case.attempts[0]
        assert causal_attempt.status == "failed"
        assert causal_attempt.heartbeat_at == causal_attempt.completed_at == NOW
        assert causal_attempt.completed_at < causal_attempt.lease_expires_at
        return await append(
            db,
            reservation=reservation,
            workflow=workflow,
            locked_stages=locked_stages,
            causal_attempt=causal_attempt,
        )

    monkeypatch.setattr(worker, "_append_reserved_stage_ready", append_after_terminal_fixed_point)
    result = await worker.coordinate_stage_fail(
        _Factory([session]),
        authority=case.authority,
        error_text="upstream timeout",
        error_code="source.timeout",
        retryable=True,
    )

    assert result.decision == "retry"
    assert result.retry_emission is not None


@pytest.mark.asyncio
async def test_failure_detaches_persisted_uuid_subtypes_from_retry_public_facts(monkeypatch):
    case = _failure_case(branch="retry")
    session = _Session("failure", [], case.rows)
    factory = _Factory([session])
    _install_failure_runtime(monkeypatch, case, orm_uuid_subtypes=True)

    result = await worker.coordinate_stage_fail(
        factory,
        authority=case.authority,
        error_text="upstream timeout",
        error_code="source.timeout",
        retryable=True,
    )

    assert result.retry_emission is not None
    assert type(result.stage_run_id) is uuid.UUID
    assert type(result.retry_emission.stage_run_id) is uuid.UUID
    assert type(result.retry_emission.message_id) is uuid.UUID


@pytest.mark.asyncio
async def test_failure_detaches_multi_cancellation_uuid_subtypes_from_public_facts(monkeypatch):
    case = _failure_case(branch="required")
    second_message = copy.deepcopy(case.messages[1])
    second_delivery = copy.deepcopy(case.deliveries[1])
    second_message.id = uuid.uuid4()
    second_delivery.id = uuid.uuid4()
    second_message.active_delivery_attempt_id = second_delivery.id
    second_delivery.message_id = second_message.id
    case.messages = (*case.messages, second_message)
    case.deliveries = (*case.deliveries, second_delivery)
    case.rows = (case.workflow, *case.stages, *case.messages, *case.deliveries, *case.attempts)
    session = _Session("failure", [], case.rows)
    factory = _Factory([session])
    _install_failure_runtime(monkeypatch, case, orm_uuid_subtypes=True)

    result = await worker.coordinate_stage_fail(
        factory,
        authority=case.authority,
        error_text="terminal failure",
        error_code="source.invalid",
        retryable=False,
    )

    assert len(result.cancelled_message_ids) == len(result.cancelled_delivery_ids) == 2
    assert all(type(value) is uuid.UUID for value in result.cancelled_message_ids)
    assert all(type(value) is uuid.UUID for value in result.cancelled_delivery_ids)
    assert result.cancelled_message_ids == tuple(
        uuid.UUID(bytes=value.id.bytes) for value in sorted(case.messages[1:], key=lambda message: message.id.int)
    )
    assert result.cancelled_delivery_ids == tuple(
        uuid.UUID(bytes=value.id.bytes) for value in sorted(case.deliveries[1:], key=lambda delivery: delivery.id.int)
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("loss_phase", ["reserve", "consume"])
async def test_failure_receipt_lease_loss_is_stale_only_after_rollback_and_session_exit(monkeypatch, loss_phase):
    case = _failure_case(branch="retry")
    before = tuple(_column_snapshot(value) for value in case.rows)
    events: list[str] = []
    session = _Session("failure", events, case.rows)
    factory = _Factory([session])
    _install_failure_runtime(
        monkeypatch,
        case,
        reserve_error=OutboxLeaseLost("stale reserve") if loss_phase == "reserve" else None,
        consume_error=OutboxLeaseLost("stale consume") if loss_phase == "consume" else None,
    )
    build_result = worker._build_public_failure_result

    def build_after_exit(*args, **kwargs):
        assert events[-1] == "failure:session_exit"
        return build_result(*args, **kwargs)

    monkeypatch.setattr(worker, "_build_public_failure_result", build_after_exit)
    result = await worker.coordinate_stage_fail(
        factory,
        authority=case.authority,
        error_text="password=hunter2",
        error_code="source.timeout",
        retryable=True,
    )
    assert result.disposition == "stale"
    assert result.should_ack is True and result.should_retry is result.should_continue is False
    assert result.error_summary == "password=[REDACTED]"
    assert result.decision is None and result.retry_emission is None
    assert result.stage_state_version == result.previous_stage_state_version
    assert tuple(_column_snapshot(value) for value in case.rows) == before
    assert events == [
        "failure:session_enter",
        "failure:tx_enter",
        "failure:rollback",
        "failure:tx_exit",
        "failure:session_exit",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error_text", "error_code", "retryable", "error_class"),
    [
        (object(), "source.timeout", True, "ExternalError"),
        ("failure", "workflow.lease_expired", True, "ExternalError"),
        ("failure", "Source Timeout", True, "ExternalError"),
        ("failure", "source.timeout", 1, "ExternalError"),
        ("failure", "source.timeout", True, "bad class"),
    ],
)
async def test_failure_rejects_non_string_or_reserved_evidence_before_factory(
    error_text,
    error_code,
    retryable,
    error_class,
):
    case = _failure_case(branch="retry")
    factory = _Factory(error=AssertionError("factory must not be called"))
    with pytest.raises(WorkflowValidation, match="evidence"):
        await worker.coordinate_stage_fail(
            factory,
            authority=case.authority,
            error_text=error_text,
            error_code=error_code,
            retryable=retryable,
            error_class=error_class,
        )
    assert factory.calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_point", ["cancel", "append", "flush", "commit", "enter", "exit"])
async def test_failure_late_or_foreign_errors_propagate_without_public_ack(monkeypatch, failure_point):
    branch = "required" if failure_point == "cancel" else "retry"
    case = _failure_case(branch=branch)
    error = OutboxLeaseLost(f"{failure_point} outcome unknown")
    options = {
        "flush_error_at": 1 if failure_point == "flush" else None,
        "commit_error": error if failure_point == "commit" else None,
        "enter_error": error if failure_point == "enter" else None,
        "exit_error": error if failure_point == "exit" else None,
    }
    if failure_point == "flush":
        error = RuntimeError("failure flush failed")
    session = _Session("failure", [], case.rows, **options)
    factory = _Factory([session])
    _install_failure_runtime(
        monkeypatch,
        case,
        cancel_error=error if failure_point == "cancel" else None,
        append_error=error if failure_point == "append" else None,
    )

    def forbidden_result(*_args, **_kwargs):
        pytest.fail("late failure cannot construct a public ACK")

    monkeypatch.setattr(worker, "_build_public_failure_result", forbidden_result)
    expected = RuntimeError if failure_point == "flush" else OutboxLeaseLost
    with pytest.raises(expected):
        await worker.coordinate_stage_fail(
            factory,
            authority=case.authority,
            error_text="upstream timeout",
            error_code="source.timeout",
            retryable=branch == "retry",
        )


@pytest.mark.asyncio
async def test_failure_direct_writer_revalidates_evidence_and_local_sentinel_before_reserve(monkeypatch):
    case = _failure_case(branch="retry")
    calls = 0

    async def forbidden_reserve(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("invalid direct request reached reservation")

    monkeypatch.setattr(worker, "_reserve_stage_failure_graph", forbidden_reserve)
    safe = sanitize_workflow_error("upstream timeout", code="source.timeout", retryable=True)
    evidence = StageFailureEvidence(
        code=safe.code,
        error_class=safe.error_class,
        summary=safe.summary,
        retryable=safe.retryable,
    )
    with pytest.raises(WorkflowValidation, match="receipt_stale"):
        await worker._reserve_consume_and_fail(
            object(),
            authority=case.authority,
            evidence=evidence,
            receipt_stale=object(),
        )
    with pytest.raises(WorkflowValidation, match="evidence"):
        await worker._reserve_consume_and_fail(
            object(),
            authority=case.authority,
            evidence=safe,
            receipt_stale=worker._ReceiptAuthorityStale(),
        )
    assert calls == 0


@pytest.mark.asyncio
async def test_failure_direct_writer_maps_only_reserve_consume_loss_to_its_passed_identity(monkeypatch):
    case = _failure_case(branch="retry")
    stale = worker._ReceiptAuthorityStale()
    source_loss = OutboxLeaseLost("receipt graph is stale")
    safe = sanitize_workflow_error("upstream timeout", code="source.timeout", retryable=True)
    evidence = StageFailureEvidence(
        code=safe.code,
        error_class=safe.error_class,
        summary=safe.summary,
        retryable=safe.retryable,
    )

    async def lease_lost(*_args, **_kwargs):
        raise source_loss

    monkeypatch.setattr(worker, "_reserve_stage_failure_graph", lease_lost)
    with pytest.raises(worker._ReceiptAuthorityStale) as caught:
        await worker._reserve_consume_and_fail(
            object(),
            authority=case.authority,
            evidence=evidence,
            receipt_stale=stale,
        )
    assert caught.value is stale and caught.value.__cause__ is source_loss


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_point", ["enter", "exit", "commit"])
async def test_failure_foreign_same_class_sentinel_cannot_forge_stale_ack(monkeypatch, failure_point):
    case = _failure_case(branch="retry")
    foreign = worker._ReceiptAuthorityStale("foreign")
    session = _Session(
        "failure",
        [],
        case.rows,
        enter_error=foreign if failure_point == "enter" else None,
        exit_error=foreign if failure_point == "exit" else None,
        commit_error=foreign if failure_point == "commit" else None,
    )
    factory = _Factory([session])
    _install_failure_runtime(monkeypatch, case)

    def forbidden_result(*_args, **_kwargs):
        pytest.fail("foreign sentinel cannot construct a public ACK")

    monkeypatch.setattr(worker, "_build_public_failure_result", forbidden_result)
    with pytest.raises(worker._ReceiptAuthorityStale) as caught:
        await worker.coordinate_stage_fail(
            factory,
            authority=case.authority,
            error_text="upstream timeout",
            error_code="source.timeout",
            retryable=True,
        )
    assert caught.value is foreign


def test_failure_public_result_is_frozen_capability_free_fixed_point():
    with pytest.raises(TypeError, match="sealed and cannot be subclassed"):

        class ForgedCoordinatedStageFailure(worker.CoordinatedStageFailure):
            def __post_init__(self):
                pass

    case = _failure_case(branch="retry")
    result = worker.CoordinatedStageFailure(
        workflow_run_id=case.authority.workflow_run_id,
        stage_run_id=case.authority.stage_run_id,
        stage_attempt_id=case.authority.stage_attempt_id,
        message_id=case.authority.message_id,
        delivery_attempt_id=case.authority.delivery_attempt_id,
        stage_lease_token=case.authority.stage_lease_token,
        attempt_number=case.authority.attempt_number,
        delivery_cycle=case.authority.delivery_cycle,
        cycle_key=case.authority.cycle_key,
        broker_receipt_id=case.authority.broker_receipt_id,
        stage_key=case.authority.stage_key,
        input_checksum=case.authority.input_checksum,
        checkpoint_version=case.authority.checkpoint_version,
        lease_owner=case.authority.lease_owner,
        lease_expires_at=case.authority.lease_expires_at,
        error_code="source.timeout",
        error_class="ExternalError",
        error_summary="upstream timeout",
        retryable=True,
        decision="retry",
        previous_workflow_state_version=case.authority.workflow_state_version,
        workflow_state_version=case.authority.workflow_state_version,
        workflow_status="running",
        previous_stage_state_version=case.authority.stage_state_version,
        stage_state_version=case.authority.stage_state_version + 1,
        previous_attempt_state_version=case.authority.attempt_state_version,
        attempt_state_version=case.authority.attempt_state_version + 1,
        attempt_completed_at=NOW,
        stage_completed_at=None,
        workflow_completed_at=None,
        next_attempt_at=NOW + timedelta(seconds=10),
        skipped_stage_ids=(),
        cancelled_stage_ids=(),
        cancelled_attempt_ids=(),
        cancelled_message_ids=(),
        cancelled_delivery_ids=(),
        retry_emission=worker.CoordinatedStageEmission(
            stage_run_id=case.source.id,
            stage_key=case.source.stage_key,
            stage_state_version=case.authority.stage_state_version + 1,
            message_id=uuid.uuid4(),
            logical_key="7" * 64,
            available_at=NOW + timedelta(seconds=10),
        ),
        disposition="recorded",
        should_retry=True,
        should_continue=False,
        should_ack=True,
    )
    with pytest.raises((FrozenInstanceError, AttributeError)):
        result.should_ack = False
    with pytest.raises(OutboxValidation, match="Stale failure"):
        replace(result, disposition="stale", should_retry=False)
    with pytest.raises(OutboxValidation, match="lease_expires_at"):
        replace(result, lease_expires_at=result.lease_expires_at.replace(tzinfo=None))
    cancelled_stage_id = uuid.uuid4()
    with pytest.raises(OutboxValidation, match="attempts cannot outnumber cancelled stages"):
        replace(
            result,
            cancelled_stage_ids=(cancelled_stage_id,),
            cancelled_attempt_ids=tuple(sorted((uuid.uuid4(), uuid.uuid4()), key=lambda value: value.int)),
        )
    with pytest.raises(OutboxValidation, match="deliveries cannot outnumber cancelled messages"):
        replace(
            result,
            cancelled_stage_ids=(cancelled_stage_id,),
            cancelled_message_ids=(uuid.uuid4(),),
            cancelled_delivery_ids=tuple(sorted((uuid.uuid4(), uuid.uuid4()), key=lambda value: value.int)),
        )
    with pytest.raises(OutboxValidation, match="cannot include the source stage"):
        replace(result, skipped_stage_ids=(result.stage_run_id,))
    with pytest.raises(OutboxValidation, match="cannot include the source stage"):
        replace(result, cancelled_stage_ids=(result.stage_run_id,))
    with pytest.raises(OutboxValidation, match="cannot include the source attempt"):
        replace(
            result,
            cancelled_stage_ids=(uuid.uuid4(),),
            cancelled_attempt_ids=(result.stage_attempt_id,),
        )
    with pytest.raises(OutboxValidation, match="cannot include the source message"):
        replace(result, cancelled_message_ids=(result.message_id,))
    with pytest.raises(OutboxValidation, match="cannot include the source delivery"):
        replace(
            result,
            cancelled_message_ids=(uuid.uuid4(),),
            cancelled_delivery_ids=(result.delivery_attempt_id,),
        )
    for field_name in ("cancelled_attempt_ids", "cancelled_message_ids", "cancelled_delivery_ids"):
        low = uuid.UUID(int=1)
        high = uuid.UUID(int=2)
        replacements = {
            "cancelled_stage_ids": (cancelled_stage_id, uuid.uuid4()),
            field_name: (high, low),
        }
        if field_name == "cancelled_delivery_ids":
            replacements["cancelled_message_ids"] = (low, high)
        with pytest.raises(OutboxValidation, match="canonical UUID order"):
            replace(result, **replacements)
    for field_name in ("cancelled_attempt_ids", "cancelled_message_ids"):
        with pytest.raises(OutboxValidation, match="require at least one cancelled stage"):
            replace(result, **{field_name: (uuid.uuid4(),)})
    with pytest.raises(OutboxValidation, match="require at least one cancelled stage"):
        related_id = uuid.uuid4()
        replace(
            result,
            cancelled_message_ids=(related_id,),
            cancelled_delivery_ids=(uuid.uuid4(),),
        )
    with pytest.raises(OutboxValidation, match="cannot reuse the delivered source message"):
        replace(
            result,
            retry_emission=replace(result.retry_emission, message_id=result.message_id),
        )
    overlapping_stage_id = uuid.uuid4()
    with pytest.raises(OutboxValidation, match="must be disjoint"):
        replace(
            result,
            skipped_stage_ids=(overlapping_stage_id,),
            cancelled_stage_ids=(overlapping_stage_id,),
        )
    for invalid_retry_time in (
        result.attempt_completed_at,
        result.attempt_completed_at - timedelta(microseconds=1),
        result.attempt_completed_at + timedelta(seconds=1, microseconds=1),
        result.attempt_completed_at + timedelta(seconds=86_401),
    ):
        with pytest.raises(OutboxValidation, match="invalid bounded retry delay"):
            replace(
                result,
                next_attempt_at=invalid_retry_time,
                retry_emission=replace(result.retry_emission, available_at=invalid_retry_time),
            )
    public_fields = {item.name for item in fields(worker.CoordinatedStageFailure)}
    assert not public_fields.intersection({"authority", "evidence", "reservation", "locked", "workflow", "stage", "attempt", "payload"})
    assert "_StageFailureMutationFacts" not in worker.__all__
    assert "_reserve_consume_and_fail" not in worker.__all__


def test_failure_private_mutation_facts_require_exact_bounded_retry_delay():
    evidence = worker._canonical_failure_request(
        "upstream timeout",
        error_code="source.timeout",
        retryable=True,
        error_class="ExternalError",
    )
    next_attempt_at = NOW + timedelta(seconds=10)
    emission = worker._StageFailureRetryEmissionFacts(
        stage_run_id=uuid.uuid4(),
        stage_key="collect",
        stage_state_version=2,
        message_id=uuid.uuid4(),
        logical_key="7" * 64,
        available_at=next_attempt_at,
    )
    facts = worker._StageFailureMutationFacts(
        evidence=evidence,
        decision="retry",
        workflow_state_version=1,
        workflow_status="running",
        stage_state_version=2,
        attempt_state_version=2,
        attempt_completed_at=NOW,
        stage_completed_at=None,
        workflow_completed_at=None,
        next_attempt_at=next_attempt_at,
        skipped_stage_ids=(),
        cancelled_stage_ids=(),
        cancelled_attempt_ids=(),
        cancelled_message_ids=(),
        cancelled_delivery_ids=(),
        retry_emission=emission,
    )
    for invalid_retry_time in (
        NOW,
        NOW - timedelta(microseconds=1),
        NOW + timedelta(seconds=1, microseconds=1),
        NOW + timedelta(seconds=86_401),
    ):
        with pytest.raises(WorkflowStoredContractError, match="invalid bounded retry delay"):
            replace(
                facts,
                next_attempt_at=invalid_retry_time,
                retry_emission=replace(emission, available_at=invalid_retry_time),
            )
    terminal_evidence = worker._canonical_failure_request(
        "invalid source",
        error_code="source.invalid",
        retryable=False,
        error_class="ExternalError",
    )
    terminal = replace(
        facts,
        evidence=terminal_evidence,
        decision="failed",
        workflow_status="failed",
        stage_completed_at=NOW,
        workflow_completed_at=NOW,
        next_attempt_at=None,
        retry_emission=None,
    )
    for field_name in ("cancelled_attempt_ids", "cancelled_message_ids", "cancelled_delivery_ids"):
        low = uuid.UUID(int=1)
        high = uuid.UUID(int=2)
        replacements = {
            "cancelled_stage_ids": (uuid.uuid4(), uuid.uuid4()),
            field_name: (high, low),
        }
        if field_name == "cancelled_delivery_ids":
            replacements["cancelled_message_ids"] = (low, high)
        with pytest.raises(WorkflowStoredContractError, match="canonical UUID order"):
            replace(terminal, **replacements)
    for field_name in ("cancelled_attempt_ids", "cancelled_message_ids"):
        with pytest.raises(WorkflowStoredContractError, match="lack a cancelled stage"):
            replace(terminal, **{field_name: (uuid.uuid4(),)})
    with pytest.raises(WorkflowStoredContractError, match="lack a cancelled stage"):
        replace(
            terminal,
            cancelled_message_ids=(uuid.uuid4(),),
            cancelled_delivery_ids=(uuid.uuid4(),),
        )


def test_completion_public_result_is_frozen_capability_free_fixed_point():
    rows, authority = _completion_case(target_count=0)
    checksum = checksum_json({"claims": 1})
    result = worker.CoordinatedStageCompletion(
        workflow_run_id=authority.workflow_run_id,
        stage_run_id=authority.stage_run_id,
        stage_attempt_id=authority.stage_attempt_id,
        message_id=authority.message_id,
        delivery_attempt_id=authority.delivery_attempt_id,
        stage_lease_token=authority.stage_lease_token,
        attempt_number=authority.attempt_number,
        delivery_cycle=authority.delivery_cycle,
        cycle_key=authority.cycle_key,
        broker_receipt_id=authority.broker_receipt_id,
        stage_key=authority.stage_key,
        input_checksum=authority.input_checksum,
        checkpoint_version=authority.checkpoint_version,
        lease_owner=authority.lease_owner,
        lease_expires_at=authority.lease_expires_at,
        outcome="succeeded",
        requested_output_checksum=checksum,
        committed_output_checksum=checksum,
        previous_workflow_state_version=authority.workflow_state_version,
        workflow_state_version=authority.workflow_state_version + 1,
        workflow_status="succeeded",
        previous_stage_state_version=authority.stage_state_version,
        stage_state_version=authority.stage_state_version + 1,
        previous_attempt_state_version=authority.attempt_state_version,
        attempt_state_version=authority.attempt_state_version + 1,
        completed_at=NOW,
        workflow_completed_at=NOW,
        emissions=(),
        disposition="completed",
        should_continue=False,
        should_ack=True,
    )
    with pytest.raises((FrozenInstanceError, AttributeError)):
        result.should_ack = False
    with pytest.raises(OutboxValidation, match="must acknowledge"):
        replace(result, should_ack=False)
    with pytest.raises(OutboxValidation, match="lease_expires_at"):
        replace(result, lease_expires_at=result.lease_expires_at.replace(tzinfo=None))
    with pytest.raises(OutboxValidation, match="cannot claim"):
        replace(
            result,
            disposition="stale",
            committed_output_checksum=None,
        )
    public_fields = {item.name for item in fields(worker.CoordinatedStageCompletion)}
    assert not public_fields.intersection(
        {
            "authority",
            "output_manifest",
            "payload",
            "reservation",
            "locked",
            "workflow",
            "stage",
            "attempt",
        }
    )
    assert "_StageCompletionMutationFacts" not in worker.__all__
    assert "_reserve_consume_and_complete" not in worker.__all__


def test_worker_has_no_local_clock_network_commit_or_public_low_level_escape():
    source = inspect.getsource(worker)
    assert "_CompletionReceiptLeaseLost" not in source
    assert "datetime.now(" not in source
    assert "datetime.utcnow(" not in source
    assert "time.time(" not in source
    assert ".commit(" not in source
    assert "requests" not in source
    assert "httpx" not in source

    tree = ast.parse(source)
    callers: dict[str, set[str]] = {
        "_PendingStageCheckpoint": set(),
        "_reserve_and_consume_execution_receipt": set(),
        "_reserve_consume_and_complete": set(),
        "_reserve_consume_and_fail": set(),
        "_reserve_consume_and_cancel": set(),
        "_reserve_consume_and_recover_one": set(),
        "_reserve_consume_and_checkpoint": set(),
        "_reserve_consume_and_heartbeat": set(),
    }
    mutation_entries: dict[str, ast.AsyncFunctionDef] = {}
    checkpoint_attribute_writers: set[str] = set()
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name in {
            "_reserve_consume_and_heartbeat",
            "_reserve_consume_and_checkpoint",
            "_reserve_consume_and_complete",
            "_reserve_consume_and_fail",
            "_reserve_consume_and_cancel",
            "_reserve_consume_and_recover_one",
        }:
            assert isinstance(node, ast.AsyncFunctionDef)
            mutation_entries[node.name] = node
        for descendant in ast.walk(node):
            if isinstance(descendant, ast.Call) and isinstance(descendant.func, ast.Name):
                if descendant.func.id in callers:
                    callers[descendant.func.id].add(node.name)
            targets: tuple[ast.expr, ...] = ()
            if isinstance(descendant, ast.Assign):
                targets = tuple(descendant.targets)
            elif isinstance(descendant, (ast.AnnAssign, ast.AugAssign)):
                targets = (descendant.target,)
            if any(
                isinstance(target, ast.Attribute)
                and target.attr in {"checkpoint", "checkpoint_checksum", "checkpoint_version", "checkpoint_end_version"}
                for target in targets
            ):
                checkpoint_attribute_writers.add(node.name)
    assert callers == {
        "_PendingStageCheckpoint": {"coordinate_stage_checkpoint"},
        "_reserve_and_consume_execution_receipt": {
            "coordinate_stage_checkpoint",
            "coordinate_stage_heartbeat",
            "_reserve_consume_and_checkpoint",
            "_reserve_consume_and_heartbeat",
        },
        "_reserve_consume_and_checkpoint": {"coordinate_stage_checkpoint"},
        "_reserve_consume_and_heartbeat": {"coordinate_stage_heartbeat"},
        "_reserve_consume_and_complete": {"coordinate_stage_complete"},
        "_reserve_consume_and_fail": {"coordinate_stage_fail"},
        "_reserve_consume_and_cancel": {"coordinate_workflow_cancel"},
        "_reserve_consume_and_recover_one": {"coordinate_one_expired_stage_recovery"},
    }
    assert checkpoint_attribute_writers == {
        "_reserve_consume_and_checkpoint",
        "_reserve_consume_and_complete",
        "_reserve_consume_and_fail",
        "_reserve_consume_and_cancel",
        "_reserve_consume_and_recover_one",
    }
    assert set(mutation_entries) == {
        "_reserve_consume_and_complete",
        "_reserve_consume_and_fail",
        "_reserve_consume_and_cancel",
        "_reserve_consume_and_recover_one",
        "_reserve_consume_and_checkpoint",
        "_reserve_consume_and_heartbeat",
    }
    expected_parameters = {
        "_reserve_consume_and_heartbeat": {"db", "authority", "duration"},
        "_reserve_consume_and_checkpoint": {
            "db",
            "authority",
            "checkpoint_schema_version",
            "checkpoint",
            "duration",
        },
        "_reserve_consume_and_complete": {
            "db",
            "authority",
            "output_manifest",
            "outcome",
            "receipt_stale",
        },
        "_reserve_consume_and_fail": {
            "db",
            "authority",
            "evidence",
            "receipt_stale",
        },
        "_reserve_consume_and_cancel": {"db", "command"},
        "_reserve_consume_and_recover_one": {"db"},
    }
    for name, mutation_entry in mutation_entries.items():
        mutation_parameters = {
            argument.arg
            for argument in (
                *mutation_entry.args.posonlyargs,
                *mutation_entry.args.args,
                *mutation_entry.args.kwonlyargs,
            )
        }
        assert mutation_parameters == expected_parameters[name]
        assert "locked" not in mutation_parameters

    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        annotation_values = {
            ast.unparse(argument.annotation)
            for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)
            if argument.annotation is not None
        }
        assert "LockedStageCompletionGraph" not in annotation_values
        assert "LockedStageFailureGraph" not in annotation_values
        assert "LockedWorkflowTerminalizationGraph" not in annotation_values
        assert "LockedStageRecoveryGraph" not in annotation_values
