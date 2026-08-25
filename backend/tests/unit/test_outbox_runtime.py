from __future__ import annotations

import inspect
import uuid
from collections import deque
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql

from app.models.research_workflow import (
    OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1,
    OUTBOX_TOPIC_WORKFLOW_STAGE_READY,
    OUTBOX_V1_MAX_ATTEMPTS,
    OutboxDeliveryAttempt,
    OutboxMessage,
    StageAttempt,
    StageRun,
    WorkflowRun,
)
from app.services import outbox_runtime as runtime
from app.services.outbox_engine import (
    OutboxContractError,
    SanitizedOutboxError,
    delivery_cycle_idempotency_key,
    deterministic_delivery_retry_delay_seconds,
    normalize_outbox_envelope,
    sanitize_outbox_error,
)
from app.services.workflow_engine import (
    checksum_json,
    deterministic_retry_backoff_seconds,
    normalize_stage_plan,
)


NOW = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)
_REAL_OBJECT_SESSION = runtime.object_session
_REAL_SA_INSPECT = runtime.sa_inspect


class _UnitApp:
    def __init__(self) -> None:
        self.dependency_overrides = {}


@pytest.fixture
def app():
    """Keep global auth fixtures from importing the unrelated FastAPI surface."""

    return _UnitApp()


@pytest.fixture(autouse=True)
def _unit_object_session(monkeypatch):
    """Model SQLAlchemy attachment without weakening the production check."""

    def object_session(value):
        return getattr(value, "_unit_sync_session", _REAL_OBJECT_SESSION(value))

    def sa_inspect(value):
        if getattr(value, "_unit_persistent", False):
            return SimpleNamespace(
                persistent=True,
                deleted=False,
                detached=False,
                modified=getattr(value, "_unit_modified", False),
                expired=getattr(value, "_unit_expired", False),
                expired_attributes=set(getattr(value, "_unit_expired_attributes", set())),
                unloaded=set(getattr(value, "_unit_unloaded", set())),
            )
        return _REAL_SA_INSPECT(value)

    monkeypatch.setattr(runtime, "object_session", object_session)
    monkeypatch.setattr(runtime, "sa_inspect", sa_inspect)


def _workflow(*, status: str = "running") -> WorkflowRun:
    return WorkflowRun(
        id=uuid.uuid4(),
        status=status,
        plan_checksum="a" * 64,
        correlation_id=uuid.uuid4(),
        state_version=1 if status == "queued" else 2,
        stage_plan=[],
    )


def _stage(
    workflow: WorkflowRun,
    *,
    status: str = "ready",
    stage_key: str = "extract_claims",
    ordinal: int = 1,
    depends_on: list[str] | None = None,
    attempt_count: int = 0,
    state_version: int = 1,
    last_error_code: str = "",
) -> StageRun:
    running = status == "running"
    terminal = status in {"succeeded", "degraded", "skipped", "failed", "cancelled", "dead_lettered"}
    if status in {"running", "retry_wait", "succeeded", "degraded", "failed", "dead_lettered"} and attempt_count == 0:
        attempt_count = 1
    started = attempt_count > 0
    retry_wait = status == "retry_wait"
    if retry_wait and not last_error_code:
        last_error_code = "stage.retryable"
    has_error = status in {"retry_wait", "failed", "dead_lettered"}
    success = status in {"succeeded", "degraded"}
    lease_token = uuid.uuid4() if running else None
    return StageRun(
        id=uuid.uuid4(),
        workflow_run_id=workflow.id,
        stage_key=stage_key,
        stage_type=f"{stage_key}.worker",
        stage_version="1.0.0",
        ordinal=ordinal,
        status=status,
        priority=5,
        state_version=state_version,
        idempotency_key="c" * 64,
        depends_on=[] if depends_on is None else depends_on,
        required=True,
        config_schema_version="research-stage-config-v1",
        config={},
        config_checksum="d" * 64,
        input_manifest={},
        input_checksum="b" * 64,
        output_manifest={} if not success else {"ok": True},
        output_checksum="e" * 64 if success else "",
        checkpoint={},
        checkpoint_schema_version="research-stage-checkpoint-v1",
        checkpoint_version=0,
        checkpoint_checksum=checksum_json({}),
        attempt_count=attempt_count,
        max_attempts=3,
        next_attempt_at=NOW if status in {"ready", "retry_wait"} else None,
        lease_owner="worker-1" if running else "",
        lease_token=lease_token,
        leased_at=NOW - timedelta(minutes=2) if running else None,
        lease_expires_at=NOW + timedelta(minutes=2) if running else None,
        heartbeat_at=NOW - timedelta(seconds=10) if running else None,
        last_error_code=last_error_code,
        last_error_summary="retryable stage failure" if has_error else "",
        last_error_retryable=status in {"retry_wait", "dead_lettered"},
        first_started_at=NOW - timedelta(minutes=3) if started else None,
        completed_at=NOW if terminal else None,
        created_at=NOW - timedelta(minutes=10),
        updated_at=NOW if terminal else NOW - timedelta(minutes=1),
    )


def _bind_plan(workflow: WorkflowRun, *stages: StageRun) -> None:
    definitions = [
        {
            "stage_key": stage.stage_key,
            "stage_type": stage.stage_type,
            "stage_version": stage.stage_version,
            "ordinal": stage.ordinal,
            "depends_on": list(stage.depends_on),
            "required": stage.required,
            "priority": stage.priority,
            "max_attempts": stage.max_attempts,
            "config_schema_version": stage.config_schema_version,
            "checkpoint_schema_version": stage.checkpoint_schema_version,
            "config": dict(stage.config),
        }
        for stage in stages
    ]
    normalized = normalize_stage_plan(definitions)
    workflow.stage_plan = normalized.as_payload()
    workflow.plan_checksum = normalized.checksum
    workflow.input_manifest = {}
    workflow.input_checksum = checksum_json(workflow.input_manifest)
    by_key = {stage.stage_key: stage for stage in stages}
    for definition in workflow.stage_plan:
        stage = by_key[definition["stage_key"]]
        stage.config = dict(definition["config"])
        stage.config_checksum = checksum_json(stage.config)
        expected_input = definition["input_manifest"] or workflow.input_manifest
        stage.input_manifest = dict(expected_input)
        stage.input_checksum = checksum_json(stage.input_manifest)


def _retry_available_at(
    workflow: WorkflowRun,
    stage: StageRun,
    *,
    completed_at: datetime,
    attempt_number: int,
) -> datetime:
    definition = next(candidate for candidate in normalize_stage_plan(workflow.stage_plan).stages if candidate.stage_key == stage.stage_key)
    delay = deterministic_retry_backoff_seconds(
        attempt_number,
        seed=str(stage.id),
        policy=definition.retry_policy,
    )
    return completed_at + timedelta(seconds=delay)


def _normalized(workflow: WorkflowRun, stage: StageRun):
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


def _message(
    workflow: WorkflowRun,
    stage: StageRun,
    *,
    status: str = "pending",
    emission_kind: str = "root_ready",
    attempt_count: int = 0,
    delivery_cycle: int | None = None,
    state_version: int = 1,
    delivery_id: uuid.UUID | None = None,
    token: uuid.UUID | None = None,
    causation_id: uuid.UUID | None = None,
) -> OutboxMessage:
    normalized = _normalized(workflow, stage)
    cycle = attempt_count if delivery_cycle is None else delivery_cycle
    cycle_key = delivery_cycle_idempotency_key(normalized.logical_key, delivery_cycle=cycle) if cycle else None
    active = status in {"dispatching", "awaiting_receipt"}
    dispatching = status == "dispatching"
    awaiting = status == "awaiting_receipt"
    terminal = status in {"delivered", "dead_lettered", "cancelled"}
    delivery_token = token or uuid.uuid4()
    return OutboxMessage(
        id=uuid.uuid4(),
        workflow_run_id=workflow.id,
        stage_run_id=stage.id,
        aggregate_type="workflow_stage",
        aggregate_id=stage.id,
        aggregate_version=stage.state_version,
        emission_kind=emission_kind,
        topic=OUTBOX_TOPIC_WORKFLOW_STAGE_READY,
        schema_version=OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1,
        correlation_id=workflow.correlation_id,
        causation_id=causation_id,
        stage_key=stage.stage_key,
        target_attempt_number=stage.attempt_count + 1,
        input_checksum=stage.input_checksum,
        plan_checksum=workflow.plan_checksum,
        envelope_canonical=normalized.canonical,
        envelope_checksum=normalized.checksum,
        envelope_bytes=len(normalized.canonical.encode("utf-8")),
        logical_key=normalized.logical_key,
        redrive_of_message_id=None,
        redrive_ordinal=0,
        redrive_requested_by="",
        redrive_requested_by_id="",
        redrive_reason="",
        redrive_requested_at=None,
        status=status,
        state_version=state_version,
        attempt_count=attempt_count,
        max_attempts=OUTBOX_V1_MAX_ATTEMPTS,
        delivery_cycle=cycle,
        cycle_key=cycle_key,
        available_at=NOW if status in {"pending", "retry_wait"} else None,
        active_delivery_attempt_id=delivery_id if active else None,
        lease_owner="publisher-1" if dispatching else "",
        lease_token=delivery_token if dispatching else None,
        leased_at=NOW - timedelta(seconds=30) if dispatching else None,
        heartbeat_at=NOW - timedelta(seconds=30) if dispatching else None,
        lease_expires_at=NOW + timedelta(seconds=30) if dispatching else None,
        receipt_deadline_at=NOW + timedelta(seconds=30) if awaiting else None,
        last_error_code="",
        last_error_class="",
        last_error_summary="",
        last_error_retryable=False,
        delivered_at=NOW if status == "delivered" else None,
        dead_lettered_at=NOW if status == "dead_lettered" else None,
        cancelled_at=NOW if status == "cancelled" else None,
        cancelled_by="actor" if status == "cancelled" else "",
        cancelled_by_id="actor-1" if status == "cancelled" else "",
        cancel_reason="cancelled" if status == "cancelled" else "",
        created_at=NOW - timedelta(minutes=2),
        updated_at=NOW - timedelta(minutes=1) if terminal else NOW - timedelta(minutes=2),
    )


def _active_pair(
    *,
    status: str = "dispatching",
    attempt_count: int = 1,
    message_state_version: int | None = None,
    delivery_state_version: int | None = None,
) -> tuple[OutboxMessage, OutboxDeliveryAttempt, uuid.UUID]:
    workflow = _workflow()
    stage = _stage(workflow)
    delivery_id = uuid.uuid4()
    token = uuid.uuid4()
    message = _message(
        workflow,
        stage,
        status=status,
        attempt_count=attempt_count,
        state_version=message_state_version or (2 if status == "dispatching" else 3),
        delivery_id=delivery_id,
        token=token,
    )
    dispatched_at = NOW if status == "awaiting_receipt" else None
    delivery = OutboxDeliveryAttempt(
        id=delivery_id,
        message_id=message.id,
        delivery_cycle=message.delivery_cycle,
        attempt_number=message.attempt_count,
        cycle_key=message.cycle_key,
        delivery_token=token,
        publisher_id="publisher-1",
        status=status,
        state_version=delivery_state_version or (1 if status == "dispatching" else 2),
        leased_at=NOW - timedelta(seconds=30),
        heartbeat_at=NOW - timedelta(seconds=30),
        lease_expires_at=NOW + timedelta(seconds=30),
        broker_name="test_broker" if status == "awaiting_receipt" else "",
        broker_message_id="broker-message-1" if status == "awaiting_receipt" else "",
        broker_receipt_id="",
        dispatched_at=dispatched_at,
        receipt_deadline_at=message.receipt_deadline_at,
        receipt_received_at=None,
        completed_at=None,
        error_code="",
        error_class="",
        error_summary="",
        retryable=False,
        created_at=NOW - timedelta(seconds=30),
        updated_at=NOW - timedelta(seconds=30),
    )
    return message, delivery, token


def _claim_authority() -> runtime.ClaimedOutboxDelivery:
    message, delivery, token = _active_pair()
    return runtime.ClaimedOutboxDelivery(
        message_id=message.id,
        delivery_attempt_id=delivery.id,
        delivery_token=token,
        message_state_version=message.state_version,
        delivery_state_version=delivery.state_version,
        delivery_cycle=message.delivery_cycle,
        cycle_key=message.cycle_key,
        correlation_id=message.correlation_id,
        topic=message.topic,
        schema_version=message.schema_version,
        envelope_checksum=message.envelope_checksum,
        logical_key=message.logical_key,
        envelope_canonical=message.envelope_canonical,
    )


def _receipt_case(
    *,
    delivery_status: str = "dispatching",
    workflow_status: str = "queued",
) -> tuple[
    WorkflowRun,
    StageRun,
    OutboxMessage,
    OutboxDeliveryAttempt,
    runtime.StageReceiptCommand,
]:
    workflow = _workflow(status=workflow_status)
    workflow.state_version = 1 if workflow_status == "queued" else 2
    workflow.started_at = None if workflow_status == "queued" else NOW - timedelta(minutes=1)
    stage = _stage(workflow, status="ready", state_version=1)
    stage.stage_type = "extract.worker"
    stage.stage_version = "1.0.0"
    stage.ordinal = 1
    stage.priority = 5
    stage.idempotency_key = "c" * 64
    stage.required = True
    stage.config_schema_version = "research-stage-config-v1"
    stage.config = {}
    stage.config_checksum = "d" * 64
    stage.input_manifest = {}
    stage.output_manifest = {}
    stage.output_checksum = ""
    stage.checkpoint = {}
    stage.checkpoint_schema_version = "research-stage-checkpoint-v1"
    stage.checkpoint_version = 0
    stage.checkpoint_checksum = "e" * 64
    stage.first_started_at = None
    stage.completed_at = None
    message_state = 2 if delivery_status == "dispatching" else 3
    delivery_state = 1 if delivery_status == "dispatching" else 2
    delivery_id = uuid.uuid4()
    token = uuid.uuid4()
    message = _message(
        workflow,
        stage,
        status=delivery_status,
        attempt_count=1,
        state_version=message_state,
        delivery_id=delivery_id,
        token=token,
    )
    delivery = OutboxDeliveryAttempt(
        id=delivery_id,
        message_id=message.id,
        delivery_cycle=message.delivery_cycle,
        attempt_number=message.attempt_count,
        cycle_key=message.cycle_key,
        delivery_token=token,
        publisher_id="publisher-1",
        status=delivery_status,
        state_version=delivery_state,
        leased_at=NOW - timedelta(seconds=30),
        heartbeat_at=NOW - timedelta(seconds=30),
        lease_expires_at=NOW + timedelta(seconds=30),
        broker_name="test_broker" if delivery_status == "awaiting_receipt" else "",
        broker_message_id=("broker-message-1" if delivery_status == "awaiting_receipt" else ""),
        broker_receipt_id="",
        dispatched_at=NOW if delivery_status == "awaiting_receipt" else None,
        receipt_deadline_at=message.receipt_deadline_at,
        receipt_received_at=None,
        completed_at=None,
        error_code="",
        error_class="",
        error_summary="",
        retryable=False,
        created_at=NOW - timedelta(seconds=30),
        updated_at=NOW - timedelta(seconds=30),
    )
    claim = runtime.ClaimedOutboxDelivery(
        message_id=message.id,
        delivery_attempt_id=delivery.id,
        delivery_token=token,
        message_state_version=2,
        delivery_state_version=1,
        delivery_cycle=delivery.delivery_cycle,
        cycle_key=delivery.cycle_key,
        correlation_id=workflow.correlation_id,
        topic=message.topic,
        schema_version=message.schema_version,
        envelope_checksum=message.envelope_checksum,
        logical_key=message.logical_key,
        envelope_canonical=message.envelope_canonical,
    )
    command = runtime.StageReceiptCommand(
        claim=claim,
        broker_name="test_broker",
        broker_message_id="broker-message-1",
        broker_receipt_id="f" * 64,
        worker_id="worker-1",
        lease_seconds=120,
    )
    return workflow, stage, message, delivery, command


def _failed_pair(
    *,
    retryable: bool = True,
    attempt_count: int = 1,
) -> tuple[OutboxMessage, OutboxDeliveryAttempt, uuid.UUID, SanitizedOutboxError]:
    message, delivery, token = _active_pair(
        attempt_count=attempt_count,
        message_state_version=2 * attempt_count,
    )
    error = sanitize_outbox_error(
        "Connection refused",
        code="outbox.connection_failed",
        retryable=retryable,
        error_class="BrokerConnectionError",
    )
    delivery.status = "failed"
    delivery.state_version = 2
    delivery.completed_at = NOW
    delivery.error_code = error.code
    delivery.error_class = error.error_class
    delivery.error_summary = error.summary
    delivery.retryable = error.retryable
    message.status = "retry_wait" if retryable and attempt_count < OUTBOX_V1_MAX_ATTEMPTS else "dead_lettered"
    message.state_version += 1
    message.active_delivery_attempt_id = None
    message.lease_owner = ""
    message.lease_token = None
    message.leased_at = None
    message.heartbeat_at = None
    message.lease_expires_at = None
    message.last_error_code = error.code
    message.last_error_class = error.error_class
    message.last_error_summary = error.summary
    message.last_error_retryable = error.retryable
    if message.status == "retry_wait":
        message.available_at = NOW + timedelta(
            seconds=deterministic_delivery_retry_delay_seconds(
                attempt_count,
                logical_key=message.logical_key,
            )
        )
        message.dead_lettered_at = None
    else:
        message.available_at = None
        message.dead_lettered_at = NOW
    return message, delivery, token, error


def _delivered_pair() -> tuple[OutboxMessage, OutboxDeliveryAttempt, uuid.UUID]:
    message, delivery, token = _active_pair(status="awaiting_receipt")
    completed = NOW + timedelta(seconds=10)
    message.status = "delivered"
    message.state_version = 4
    message.active_delivery_attempt_id = None
    message.receipt_deadline_at = None
    message.delivered_at = completed
    delivery.status = "delivered"
    delivery.state_version = 3
    delivery.receipt_deadline_at = None
    delivery.receipt_received_at = completed
    delivery.completed_at = completed
    return message, delivery, token


def _execution_receipt_case() -> tuple[
    WorkflowRun,
    StageRun,
    OutboxMessage,
    OutboxDeliveryAttempt,
    StageAttempt,
    runtime.ExecutableStageAuthority,
]:
    """Build one exact committed receipt-backed running attempt."""

    workflow = _workflow(status="running")
    stage = _stage(
        workflow,
        status="ready",
        attempt_count=0,
        state_version=1,
    )
    _bind_plan(workflow, stage)
    receipt_at = NOW - timedelta(seconds=30)
    activation_at = receipt_at + timedelta(microseconds=1)
    workflow.started_at = activation_at
    workflow.completed_at = None
    workflow.created_at = NOW - timedelta(minutes=5)
    workflow.updated_at = receipt_at
    stage.created_at = NOW - timedelta(minutes=5)
    stage.updated_at = receipt_at

    message = _message(
        workflow,
        stage,
        status="delivered",
        attempt_count=1,
        delivery_cycle=1,
        state_version=4,
    )
    message.delivered_at = receipt_at
    delivery_token = uuid.uuid4()
    delivery = OutboxDeliveryAttempt(
        id=uuid.uuid4(),
        message_id=message.id,
        delivery_cycle=1,
        attempt_number=1,
        cycle_key=message.cycle_key,
        delivery_token=delivery_token,
        publisher_id="publisher-1",
        status="delivered",
        state_version=3,
        leased_at=NOW - timedelta(minutes=2),
        heartbeat_at=NOW - timedelta(seconds=90),
        lease_expires_at=NOW + timedelta(seconds=30),
        broker_name="test_broker",
        broker_message_id="broker-message-1",
        broker_receipt_id="f" * 64,
        dispatched_at=NOW - timedelta(seconds=45),
        receipt_deadline_at=None,
        receipt_received_at=receipt_at,
        completed_at=receipt_at,
        error_code="",
        error_class="",
        error_summary="",
        retryable=False,
        created_at=NOW - timedelta(minutes=2),
        updated_at=receipt_at,
    )

    stage_lease_token = uuid.uuid4()
    stage.status = "running"
    stage.state_version = 2
    stage.attempt_count = 1
    stage.next_attempt_at = None
    stage.lease_owner = "worker-1"
    stage.lease_token = stage_lease_token
    stage.leased_at = activation_at
    stage.heartbeat_at = activation_at
    stage.lease_expires_at = NOW + timedelta(minutes=2)
    stage.first_started_at = activation_at
    stage.completed_at = None

    attempt = StageAttempt(
        id=uuid.uuid4(),
        stage_run_id=stage.id,
        outbox_delivery_attempt_id=delivery.id,
        attempt_number=1,
        lease_token=stage_lease_token,
        lease_owner=stage.lease_owner,
        delivery_id=delivery.cycle_key,
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
        started_at=activation_at,
        heartbeat_at=activation_at,
        lease_expires_at=stage.lease_expires_at,
        completed_at=None,
        created_at=receipt_at,
    )
    authority = runtime.ExecutableStageAuthority(
        workflow_run_id=workflow.id,
        stage_run_id=stage.id,
        stage_attempt_id=attempt.id,
        message_id=message.id,
        delivery_attempt_id=delivery.id,
        stage_lease_token=stage_lease_token,
        workflow_state_version=workflow.state_version,
        stage_state_version=stage.state_version,
        attempt_state_version=attempt.state_version,
        attempt_number=attempt.attempt_number,
        delivery_cycle=delivery.delivery_cycle,
        cycle_key=delivery.cycle_key,
        stage_key=stage.stage_key,
        input_checksum=stage.input_checksum,
        checkpoint_version=stage.checkpoint_version,
        lease_owner=stage.lease_owner,
        lease_expires_at=stage.lease_expires_at,
        broker_receipt_id=delivery.broker_receipt_id,
    )
    return workflow, stage, message, delivery, attempt, authority


def _rebind_execution_plan_authority(
    workflow: WorkflowRun,
    source: StageRun,
    source_message: OutboxMessage,
    source_delivery: OutboxDeliveryAttempt,
    attempt: StageAttempt,
    authority: runtime.ExecutableStageAuthority,
) -> runtime.ExecutableStageAuthority:
    source_normalized = normalize_outbox_envelope(
        {
            "topic": OUTBOX_TOPIC_WORKFLOW_STAGE_READY,
            "schema_version": OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1,
            "payload": {
                "workflow_run_id": str(workflow.id),
                "stage_run_id": str(source.id),
                "stage_key": source.stage_key,
                "target_attempt_number": authority.attempt_number,
                "input_checksum": source.input_checksum,
                "plan_checksum": workflow.plan_checksum,
            },
        }
    )
    source_message.plan_checksum = workflow.plan_checksum
    source_message.input_checksum = source.input_checksum
    source_message.envelope_canonical = source_normalized.canonical
    source_message.envelope_checksum = source_normalized.checksum
    source_message.envelope_bytes = len(source_normalized.canonical.encode("utf-8"))
    source_message.logical_key = source_normalized.logical_key
    source_message.cycle_key = delivery_cycle_idempotency_key(
        source_message.logical_key,
        delivery_cycle=source_message.delivery_cycle,
    )
    source_delivery.cycle_key = source_message.cycle_key
    attempt.delivery_id = source_message.cycle_key
    return replace(
        authority,
        cycle_key=source_message.cycle_key,
        input_checksum=source.input_checksum,
    )


def _completion_receipt_case(
    *,
    target_count: int = 1,
    existing_active: bool = False,
) -> tuple[
    WorkflowRun,
    tuple[StageRun, ...],
    OutboxMessage,
    OutboxDeliveryAttempt,
    StageAttempt,
    runtime.ExecutableStageAuthority,
    tuple[OutboxMessage | None, ...],
    tuple[OutboxDeliveryAttempt | None, ...],
]:
    workflow, source, source_message, source_delivery, attempt, authority = _execution_receipt_case()
    targets = tuple(
        _stage(
            workflow,
            status="pending",
            stage_key=f"target_{index + 1}",
            ordinal=index + 2,
            depends_on=[source.stage_key],
            attempt_count=0,
            state_version=1,
        )
        for index in range(target_count)
    )
    stages = (source, *targets)
    _bind_plan(workflow, *stages)

    # Rebind the already-delivered source envelope to the enlarged canonical
    # plan.  Its logical identity and cycle key intentionally remain stable.
    authority = _rebind_execution_plan_authority(
        workflow,
        source,
        source_message,
        source_delivery,
        attempt,
        authority,
    )

    target_messages: list[OutboxMessage | None] = []
    target_deliveries: list[OutboxDeliveryAttempt | None] = []
    for target in targets:
        if not existing_active:
            target_messages.append(None)
            target_deliveries.append(None)
            continue
        delivery_id = uuid.uuid4()
        token = uuid.uuid4()
        message = _message(
            workflow,
            target,
            status="dispatching",
            emission_kind="dependency_ready",
            attempt_count=1,
            state_version=2,
            delivery_id=delivery_id,
            token=token,
            causation_id=attempt.id,
        )
        message.aggregate_version = target.state_version + 1
        delivery = OutboxDeliveryAttempt(
            id=delivery_id,
            message_id=message.id,
            delivery_cycle=message.delivery_cycle,
            attempt_number=message.attempt_count,
            cycle_key=message.cycle_key,
            delivery_token=token,
            publisher_id=message.lease_owner,
            status="dispatching",
            state_version=1,
            leased_at=message.leased_at,
            heartbeat_at=message.heartbeat_at,
            lease_expires_at=message.lease_expires_at,
            broker_name="",
            broker_message_id="",
            broker_receipt_id="",
            dispatched_at=None,
            receipt_deadline_at=None,
            receipt_received_at=None,
            completed_at=None,
            error_code="",
            error_class="",
            error_summary="",
            retryable=False,
            created_at=message.created_at,
            updated_at=message.updated_at,
        )
        target_messages.append(message)
        target_deliveries.append(delivery)
    return (
        workflow,
        stages,
        source_message,
        source_delivery,
        attempt,
        authority,
        tuple(target_messages),
        tuple(target_deliveries),
    )


def _completion_scalar_script(
    workflow: WorkflowRun,
    stages: tuple[StageRun, ...],
    source_message: OutboxMessage,
    source_delivery: OutboxDeliveryAttempt,
    source_attempt: StageAttempt,
    target_messages: tuple[OutboxMessage | None, ...],
    target_deliveries: tuple[OutboxDeliveryAttempt | None, ...],
    *,
    reserve_clock: datetime = NOW,
    consume_clock: datetime | None = None,
) -> list[object]:
    values: list[object] = [workflow, *stages]
    values.extend(message.id if message is not None else None for message in target_messages)
    messages = [source_message, *(message for message in target_messages if message is not None)]
    values.extend(sorted(messages, key=lambda message: message.id.int))
    deliveries = [source_delivery, *(delivery for delivery in target_deliveries if delivery is not None)]
    values.extend(sorted(deliveries, key=lambda delivery: delivery.id.int))
    values.extend((source_attempt, reserve_clock))
    if consume_clock is not None:
        values.append(consume_clock)
    return values


def _apply_successful_completion(
    locked: runtime.LockedStageCompletionGraph,
) -> str:
    output_manifest = {"ok": True}
    output_checksum = checksum_json(output_manifest)
    source = locked.stages[locked.source_stage_index]
    attempt = locked.source_attempt
    now = locked.observed_at

    attempt.status = "succeeded"
    attempt.state_version += 1
    attempt.checkpoint_end_version = source.checkpoint_version
    attempt.output_checksum = output_checksum
    attempt.error_code = ""
    attempt.error_class = ""
    attempt.error_summary = ""
    attempt.retryable = False
    attempt.heartbeat_at = now
    attempt.completed_at = now

    source.status = "succeeded"
    source.state_version += 1
    source.output_manifest = output_manifest
    source.output_checksum = output_checksum
    source.last_error_code = ""
    source.last_error_summary = ""
    source.last_error_retryable = False
    source.completed_at = now
    source.lease_owner = ""
    source.lease_token = None
    source.leased_at = None
    source.lease_expires_at = None
    source.heartbeat_at = None

    by_id = {stage.id: stage for stage in locked.stages}
    for intent in locked.intents:
        target = by_id[intent.post_target.stage_run_id]
        target.status = intent.post_target.status
        target.state_version = intent.post_target.state_version
        target.next_attempt_at = intent.post_target.next_attempt_at
        target.lease_owner = intent.post_target.lease_owner
        target.lease_token = intent.post_target.lease_token
        target.leased_at = intent.post_target.leased_at
        target.lease_expires_at = intent.post_target.lease_expires_at
        target.heartbeat_at = intent.post_target.heartbeat_at
        target.last_error_code = intent.post_target.last_error_code
        target.last_error_summary = intent.post_target.last_error_summary
        target.last_error_retryable = intent.post_target.last_error_retryable
        target.output_checksum = intent.post_target.output_checksum
        target.completed_at = intent.post_target.completed_at
    return output_checksum


async def _consumed_completion_case(
    *,
    target_count: int = 2,
) -> tuple[
    _ScriptedDB,
    WorkflowRun,
    tuple[StageRun, ...],
    StageAttempt,
    runtime.StageCompletionReservation,
    runtime.LockedStageCompletionGraph,
]:
    (
        workflow,
        stages,
        source_message,
        source_delivery,
        attempt,
        authority,
        target_messages,
        target_deliveries,
    ) = _completion_receipt_case(target_count=target_count)
    consumed_at = NOW + timedelta(microseconds=1)
    db = _ScriptedDB(
        scalars=_completion_scalar_script(
            workflow,
            stages,
            source_message,
            source_delivery,
            attempt,
            target_messages,
            target_deliveries,
            consume_clock=consumed_at,
        )
    )
    reservation = await runtime.reserve_stage_completion_graph(db, authority=authority)
    locked = await runtime.consume_stage_completion_graph(
        db,
        reservation=reservation,
        authority=authority,
    )
    return db, workflow, stages, attempt, reservation, locked


class _ScriptedRows:
    def __init__(self, values):
        self.values = tuple(values)

    def scalars(self):
        return self

    def all(self):
        return list(self.values)


class _ScriptedDB:
    def __init__(self, *, scalars=(), executes=()):
        values = tuple(scalars)
        self.scalar_values = deque(values)
        self.execute_values = deque(executes)
        self.scalar_statements = []
        self.added = []
        self.flushes = []
        self.commit_calls = 0
        self.sync_session = self
        self.info = {}
        self.new = set()
        self.dirty = set()
        self.deleted = set()
        self.root_transaction = object()
        self.nested_transaction = None
        _attach(self, *values)

    def get_transaction(self):
        return self.root_transaction

    def get_nested_transaction(self):
        return self.nested_transaction

    def in_nested_transaction(self):
        return self.nested_transaction is not None

    async def scalar(self, statement):
        self.scalar_statements.append(statement)
        assert self.scalar_values, f"Unexpected scalar query: {statement}"
        return self.scalar_values.popleft()

    async def execute(self, statement):
        self.scalar_statements.append(statement)
        if self.execute_values:
            scripted = self.execute_values.popleft()
            if scripted is not None:
                return _ScriptedRows(scripted)
        rows = []
        while self.scalar_values and type(self.scalar_values[0]) is StageRun:
            rows.append(self.scalar_values.popleft())
        return _ScriptedRows(rows)

    def add(self, value):
        _attach(self, value)
        self.added.append(value)

    async def flush(self, objects=None):
        self.flushes.append([_snapshot(value) for value in list(objects or [])])

    async def commit(self):  # pragma: no cover - failure sentinel
        self.commit_calls += 1
        raise AssertionError("outbox runtime must never commit")


def _attach(db: _ScriptedDB, *values) -> None:
    for value in values:
        if type(value) in {WorkflowRun, StageRun, StageAttempt, OutboxMessage, OutboxDeliveryAttempt}:
            value._unit_sync_session = db.sync_session
            value._unit_persistent = True
            value._unit_modified = False
            value._unit_expired = False
            value._unit_expired_attributes = set()
            value._unit_unloaded = set()


def _terminal_attempt(
    stage: StageRun,
    *,
    status: str,
) -> StageAttempt:
    if status in {"succeeded", "degraded"}:
        output_checksum = checksum_json({"ok": True})
        error_code = error_class = error_summary = ""
        retryable = False
    elif status == "failed":
        output_checksum = ""
        error_code = "stage.retryable"
        error_class = "StageError"
        error_summary = "retryable stage failure"
        retryable = True
    elif status == "abandoned":
        output_checksum = ""
        error_code = "workflow.lease_expired"
        error_class = "LeaseExpired"
        error_summary = "Worker lease expired before the attempt reached a terminal outcome"
        retryable = True
    else:  # pragma: no cover - test helper contract
        raise AssertionError(status)
    return StageAttempt(
        id=uuid.uuid4(),
        stage_run_id=stage.id,
        outbox_delivery_attempt_id=uuid.uuid4(),
        attempt_number=stage.attempt_count,
        lease_token=stage.lease_token or uuid.uuid4(),
        lease_owner=stage.lease_owner or "worker-1",
        delivery_id="8" * 64,
        status=status,
        state_version=2,
        input_checksum=stage.input_checksum,
        checkpoint_start_version=0,
        checkpoint_end_version=stage.checkpoint_version,
        output_checksum=output_checksum,
        error_code=error_code,
        error_class=error_class,
        error_summary=error_summary,
        retryable=retryable,
        started_at=stage.leased_at or NOW - timedelta(minutes=1),
        heartbeat_at=(stage.heartbeat_at if status == "abandoned" else NOW),
        lease_expires_at=stage.lease_expires_at or NOW + timedelta(minutes=1),
        completed_at=NOW,
    )


def _clear_stage_lease(stage: StageRun) -> None:
    stage.lease_owner = ""
    stage.lease_token = None
    stage.leased_at = None
    stage.lease_expires_at = None
    stage.heartbeat_at = None


def _apply_dependency_success(
    source: StageRun,
    targets: tuple[StageRun, ...],
    attempt: StageAttempt,
    *,
    available_at: datetime,
) -> None:
    source.status = attempt.status
    source.state_version += 1
    source.output_manifest = {"ok": True}
    source.output_checksum = attempt.output_checksum
    source.last_error_code = ""
    source.last_error_summary = ""
    source.last_error_retryable = False
    source.completed_at = attempt.completed_at
    _clear_stage_lease(source)
    for target in targets:
        target.status = "ready"
        target.state_version += 1
        target.next_attempt_at = available_at


def _apply_retry(stage: StageRun, attempt: StageAttempt, *, available_at: datetime) -> None:
    stage.status = "retry_wait"
    stage.state_version += 1
    stage.output_manifest = {}
    stage.output_checksum = ""
    stage.last_error_code = attempt.error_code
    stage.last_error_summary = attempt.error_summary
    stage.last_error_retryable = True
    stage.next_attempt_at = available_at
    stage.completed_at = None
    _clear_stage_lease(stage)


def _delivery_for_message(
    message: OutboxMessage,
    *,
    delivery_token: uuid.UUID | None = None,
) -> OutboxDeliveryAttempt:
    awaiting = message.status == "awaiting_receipt"
    leased_at = message.leased_at or NOW - timedelta(seconds=30)
    heartbeat_at = message.heartbeat_at or NOW - timedelta(seconds=30)
    lease_expires_at = message.lease_expires_at or NOW + timedelta(seconds=30)
    return OutboxDeliveryAttempt(
        id=message.active_delivery_attempt_id,
        message_id=message.id,
        delivery_cycle=message.delivery_cycle,
        attempt_number=message.attempt_count,
        cycle_key=message.cycle_key,
        delivery_token=delivery_token or message.lease_token,
        publisher_id=message.lease_owner or "publisher-1",
        status=message.status,
        state_version=1,
        leased_at=leased_at,
        heartbeat_at=heartbeat_at,
        lease_expires_at=lease_expires_at,
        broker_name="test_broker" if awaiting else "",
        broker_message_id="broker-message-1" if awaiting else "",
        broker_receipt_id="",
        dispatched_at=NOW if awaiting else None,
        receipt_deadline_at=message.receipt_deadline_at,
        receipt_received_at=None,
        completed_at=None,
        error_code="",
        error_class="",
        error_summary="",
        retryable=False,
    )


async def _reserved_root_case() -> tuple[
    _ScriptedDB,
    WorkflowRun,
    StageRun,
    runtime.StageReadyReservation,
]:
    workflow = _workflow(status="queued")
    stage = _stage(workflow)
    _bind_plan(workflow, stage)
    intent = runtime.project_stage_ready_intent(
        workflow,
        stage,
        emission_kind="root_ready",
        post_status="ready",
        post_state_version=stage.state_version,
        post_next_attempt_at=stage.next_attempt_at,
        target_attempt_number=1,
    )
    db = _ScriptedDB(scalars=[None])
    _attach(db, workflow, stage)
    reservation = await runtime.reserve_stage_ready_intents(
        db,
        workflow=workflow,
        locked_stages=(stage,),
        target_stages=(stage,),
        intents=(intent,),
    )
    return db, workflow, stage, reservation


async def _reserved_causal_case(
    emission_kind: str,
    *,
    schedule_offset: timedelta = timedelta(0),
) -> tuple[
    _ScriptedDB,
    WorkflowRun,
    tuple[StageRun, ...],
    runtime.StageReadyReservation,
    StageAttempt,
]:
    workflow = _workflow()
    if emission_kind == "dependency_ready":
        available_at = NOW + schedule_offset
        source = _stage(workflow, status="running", stage_key="fetch", ordinal=1)
        target = _stage(
            workflow,
            status="pending",
            stage_key="extract",
            ordinal=2,
            depends_on=["fetch"],
        )
        stages = (source, target)
        _bind_plan(workflow, *stages)
        intent = runtime.project_stage_ready_intent(
            workflow,
            target,
            emission_kind="dependency_ready",
            post_status="ready",
            post_state_version=target.state_version + 1,
            post_next_attempt_at=available_at,
            target_attempt_number=1,
            causal_stage=source,
        )
        db = _ScriptedDB(scalars=[None])
        _attach(db, workflow, *stages)
        reservation = await runtime.reserve_stage_ready_intents(
            db,
            workflow=workflow,
            locked_stages=stages,
            target_stages=(target,),
            intents=(intent,),
        )
        attempt = _terminal_attempt(source, status="succeeded")
        _apply_dependency_success(source, (target,), attempt, available_at=available_at)
    else:
        stage = _stage(workflow, status="running", attempt_count=1)
        if emission_kind == "lease_recovered":
            stage.lease_expires_at = NOW - timedelta(seconds=1)
            stage.heartbeat_at = NOW - timedelta(seconds=2)
        stages = (stage,)
        _bind_plan(workflow, *stages)
        available_at = (
            _retry_available_at(
                workflow,
                stage,
                completed_at=NOW,
                attempt_number=stage.attempt_count,
            )
            + schedule_offset
        )
        error_code = "workflow.lease_expired" if emission_kind == "lease_recovered" else "stage.retryable"
        summary = (
            "Worker lease expired before the attempt reached a terminal outcome"
            if emission_kind == "lease_recovered"
            else "retryable stage failure"
        )
        intent = runtime.project_stage_ready_intent(
            workflow,
            stage,
            emission_kind=emission_kind,
            post_status="retry_wait",
            post_state_version=stage.state_version + 1,
            post_next_attempt_at=available_at,
            target_attempt_number=2,
            post_error_code=error_code,
            post_error_summary=summary,
            post_error_retryable=True,
            causal_stage=stage,
        )
        db = _ScriptedDB(scalars=[NOW, None] if emission_kind == "lease_recovered" else [None])
        _attach(db, workflow, stage)
        reservation = await runtime.reserve_stage_ready_intents(
            db,
            workflow=workflow,
            locked_stages=stages,
            target_stages=(stage,),
            intents=(intent,),
        )
        attempt = _terminal_attempt(
            stage,
            status="abandoned" if emission_kind == "lease_recovered" else "failed",
        )
        _apply_retry(stage, attempt, available_at=available_at)
    _attach(db, attempt)
    return db, workflow, stages, reservation, attempt


async def _reserved_active_replay_case(
    *,
    corrupt_delivery_field: str | None = None,
    status: str = "dispatching",
) -> tuple[
    _ScriptedDB,
    WorkflowRun,
    StageRun,
    OutboxMessage,
    OutboxDeliveryAttempt,
    runtime.StageReadyReservation,
]:
    workflow = _workflow(status="queued")
    stage = _stage(workflow)
    _bind_plan(workflow, stage)
    intent = replace(
        runtime.project_stage_ready_intent(
            workflow,
            stage,
            emission_kind="root_ready",
            post_status="ready",
            post_state_version=stage.state_version,
            post_next_attempt_at=stage.next_attempt_at,
            target_attempt_number=1,
        ),
        projection_mode="current",
    )
    delivery_token = uuid.uuid4()
    message = _message(
        workflow,
        stage,
        status=status,
        attempt_count=1,
        state_version=2 if status == "dispatching" else 3,
        delivery_id=uuid.uuid4(),
        token=delivery_token,
    )
    delivery = _delivery_for_message(
        message,
        delivery_token=delivery_token,
    )
    delivery.state_version = 1 if status == "dispatching" else 2
    if corrupt_delivery_field == "delivery_token":
        delivery.delivery_token = uuid.uuid4()
    elif corrupt_delivery_field == "state_version":
        delivery.state_version = 0
    elif corrupt_delivery_field == "lease_expires_at":
        delivery.lease_expires_at = delivery.leased_at
    elif corrupt_delivery_field is not None:  # pragma: no cover - helper contract
        raise AssertionError(corrupt_delivery_field)
    db = _ScriptedDB(scalars=[message, delivery])
    _attach(db, workflow, stage)
    reservation = await runtime.reserve_stage_ready_intents(
        db,
        workflow=workflow,
        locked_stages=(stage,),
        target_stages=(stage,),
        intents=(intent,),
    )
    return db, workflow, stage, message, delivery, reservation


def _snapshot(value) -> dict:
    result = {
        "type": type(value).__name__,
        "id": getattr(value, "id", None),
        "status": getattr(value, "status", None),
        "state_version": getattr(value, "state_version", None),
    }
    for name in (
        "attempt_count",
        "delivery_cycle",
        "cycle_key",
        "active_delivery_attempt_id",
        "lease_token",
        "heartbeat_at",
        "lease_expires_at",
        "receipt_deadline_at",
        "available_at",
        "completed_at",
        "dead_lettered_at",
        "error_code",
        "last_error_code",
        "broker_receipt_id",
        "outbox_delivery_attempt_id",
        "delivery_id",
        "lease_owner",
    ):
        if hasattr(value, name):
            result[name] = getattr(value, name)
    return result


def _compiled(statement) -> str:
    return str(statement.compile(dialect=postgresql.dialect()))


@pytest.mark.asyncio
async def test_emit_root_stage_ready_persists_exact_pointer_envelope_without_commit():
    workflow = _workflow(status="queued")
    stage = _stage(workflow)
    _bind_plan(workflow, stage)
    db = _ScriptedDB(scalars=[workflow, stage, None])

    message, created = await runtime.emit_stage_ready(
        db,
        workflow_run_id=workflow.id,
        stage_run_id=stage.id,
        emission_kind="root_ready",
    )

    normalized = _normalized(workflow, stage)
    assert created is True
    assert message.envelope_canonical == normalized.canonical
    assert message.envelope_checksum == normalized.checksum
    assert message.logical_key == normalized.logical_key
    assert message.max_attempts == OUTBOX_V1_MAX_ATTEMPTS == 8
    assert message.target_attempt_number == 1
    assert message.available_at == stage.next_attempt_at
    assert db.added == [message]
    assert db.flushes == [[_snapshot(message)]]
    sql = [_compiled(statement) for statement in db.scalar_statements]
    assert "workflow_runs" in sql[0] and "FOR UPDATE" in sql[0]
    assert "stage_runs" in sql[1] and "FOR UPDATE" in sql[1]
    assert "outbox_messages" in sql[2] and "FOR UPDATE" in sql[2]
    assert all(
        statement.get_execution_options().get("populate_existing") is True and statement.get_execution_options().get("autoflush") is False
        for statement in db.scalar_statements
    )
    assert db.commit_calls == 0


@pytest.mark.asyncio
async def test_emit_rejects_wrong_derived_kind_before_backfill_replay_lookup():
    workflow = _workflow()
    source = _stage(
        workflow,
        status="succeeded",
        stage_key="fetch",
        ordinal=1,
    )
    stage = _stage(
        workflow,
        stage_key="extract_claims",
        ordinal=2,
        depends_on=["fetch"],
    )
    _bind_plan(workflow, source, stage)
    db = _ScriptedDB(scalars=[workflow, source, stage])

    with pytest.raises(runtime.OutboxConflict, match="dependency_ready"):
        await runtime.emit_stage_ready(
            db,
            workflow_run_id=workflow.id,
            stage_run_id=stage.id,
            emission_kind="root_ready",
        )

    assert len(db.scalar_statements) == 3
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "forged_kind",
    [
        type("StringSubclass", (str,), {})("root_ready"),
        type(
            "LyingEquality",
            (),
            {"__eq__": lambda self, other: True},
        )(),
    ],
)
async def test_emit_rejects_nonexact_emission_kind_before_database_access(
    forged_kind,
):
    workflow = _workflow()
    stage = _stage(workflow)
    db = _ScriptedDB()

    with pytest.raises(runtime.OutboxValidation, match="runtime stage-ready origin"):
        await runtime.emit_stage_ready(
            db,
            workflow_run_id=workflow.id,
            stage_run_id=stage.id,
            emission_kind=forged_kind,
        )

    assert db.scalar_statements == []


@pytest.mark.asyncio
async def test_emit_accepts_exact_migration_backfill_as_idempotent_root():
    workflow = _workflow()
    stage = _stage(workflow)
    _bind_plan(workflow, stage)
    existing = _message(
        workflow,
        stage,
        emission_kind="migration_backfill",
    )
    db = _ScriptedDB(scalars=[workflow, stage, existing])

    result, created = await runtime.emit_stage_ready(
        db,
        workflow_run_id=workflow.id,
        stage_run_id=stage.id,
        emission_kind="root_ready",
    )

    assert result is existing
    assert created is False
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
async def test_public_nonroot_emission_is_replay_only_and_locks_persisted_causal_attempt():
    workflow = _workflow()
    stage = _stage(
        workflow,
        status="retry_wait",
        attempt_count=1,
        state_version=3,
        last_error_code="stage.retryable",
    )
    _bind_plan(workflow, stage)
    attempt = _terminal_attempt(stage, status="failed")
    stage.next_attempt_at = _retry_available_at(
        workflow,
        stage,
        completed_at=attempt.completed_at,
        attempt_number=attempt.attempt_number,
    )
    existing = _message(
        workflow,
        stage,
        emission_kind="retry_scheduled",
        causation_id=attempt.id,
    )
    db = _ScriptedDB(scalars=[workflow, stage, existing, attempt])

    result, created = await runtime.emit_stage_ready(
        db,
        workflow_run_id=workflow.id,
        stage_run_id=stage.id,
        emission_kind="retry_scheduled",
    )

    assert result is existing
    assert created is False
    sql = [_compiled(statement) for statement in db.scalar_statements]
    assert ["workflow_runs" in sql[0], "stage_runs" in sql[1]] == [True, True]
    assert "outbox_messages" in sql[2]
    assert "stage_attempts" in sql[3] and "stage_attempts.stage_run_id IN" in sql[3]
    cause_parameters = db.scalar_statements[3].compile(dialect=postgresql.dialect()).params
    assert cause_parameters["id_1"] == attempt.id
    assert cause_parameters["stage_run_id_1"] == [stage.id]
    assert db.flushes == []


@pytest.mark.asyncio
async def test_public_nonroot_replay_rejects_noncanonical_retry_schedule():
    workflow = _workflow()
    stage = _stage(
        workflow,
        status="retry_wait",
        attempt_count=1,
        state_version=3,
        last_error_code="stage.retryable",
    )
    _bind_plan(workflow, stage)
    attempt = _terminal_attempt(stage, status="failed")
    stage.next_attempt_at = _retry_available_at(
        workflow,
        stage,
        completed_at=attempt.completed_at,
        attempt_number=attempt.attempt_number,
    ) + timedelta(seconds=1)
    existing = _message(
        workflow,
        stage,
        emission_kind="retry_scheduled",
        causation_id=attempt.id,
    )
    db = _ScriptedDB(scalars=[workflow, stage, existing, attempt])

    with pytest.raises(runtime.OutboxStoredContractError, match="exact causal schedule"):
        await runtime.emit_stage_ready(
            db,
            workflow_run_id=workflow.id,
            stage_run_id=stage.id,
            emission_kind="retry_scheduled",
        )

    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
async def test_public_nonroot_emission_missing_root_fails_closed():
    workflow = _workflow()
    stage = _stage(
        workflow,
        status="retry_wait",
        attempt_count=1,
        last_error_code="stage.retryable",
    )
    _bind_plan(workflow, stage)
    db = _ScriptedDB(scalars=[workflow, stage, None])

    with pytest.raises(runtime.OutboxConflict, match="replay-only"):
        await runtime.emit_stage_ready(
            db,
            workflow_run_id=workflow.id,
            stage_run_id=stage.id,
            emission_kind="retry_scheduled",
        )

    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
async def test_public_nonroot_accepts_exact_migration_backfill_without_fabricated_cause():
    workflow = _workflow()
    stage = _stage(
        workflow,
        status="retry_wait",
        attempt_count=1,
        last_error_code="stage.retryable",
    )
    _bind_plan(workflow, stage)
    existing = _message(workflow, stage, emission_kind="migration_backfill")
    db = _ScriptedDB(scalars=[workflow, stage, existing])

    result, created = await runtime.emit_stage_ready(
        db,
        workflow_run_id=workflow.id,
        stage_run_id=stage.id,
        emission_kind="retry_scheduled",
    )

    assert result is existing
    assert existing.causation_id is None
    assert created is False
    assert db.flushes == []


@pytest.mark.asyncio
async def test_migration_backfill_with_fabricated_cause_is_rejected():
    workflow = _workflow()
    stage = _stage(workflow)
    _bind_plan(workflow, stage)
    existing = _message(
        workflow,
        stage,
        emission_kind="migration_backfill",
        causation_id=uuid.uuid4(),
    )
    db = _ScriptedDB(scalars=[workflow, stage, existing])

    with pytest.raises(runtime.OutboxStoredContractError, match="contradictory"):
        await runtime.emit_stage_ready(
            db,
            workflow_run_id=workflow.id,
            stage_run_id=stage.id,
            emission_kind="root_ready",
        )

    assert db.flushes == []


@pytest.mark.asyncio
async def test_emit_rejects_contradictory_existing_logical_authority():
    workflow = _workflow()
    stage = _stage(workflow)
    _bind_plan(workflow, stage)
    existing = _message(workflow, stage)
    existing.plan_checksum = "c" * 64
    db = _ScriptedDB(scalars=[workflow, stage, existing])

    with pytest.raises(runtime.OutboxStoredContractError, match="canonical envelope|contradictory"):
        await runtime.emit_stage_ready(
            db,
            workflow_run_id=workflow.id,
            stage_run_id=stage.id,
            emission_kind="root_ready",
        )

    assert db.flushes == []


@pytest.mark.asyncio
async def test_emit_rejects_caller_causation_before_database_access():
    db = _ScriptedDB()

    with pytest.raises(runtime.OutboxValidation, match="caller-supplied causation"):
        await runtime.emit_stage_ready(
            db,
            workflow_run_id=uuid.uuid4(),
            stage_run_id=uuid.uuid4(),
            emission_kind="root_ready",
            causation_id=uuid.uuid4(),
        )

    assert db.scalar_statements == []


@pytest.mark.asyncio
async def test_emit_rejects_plan_checksum_tamper_before_stage_lock():
    workflow = _workflow()
    stage = _stage(workflow)
    _bind_plan(workflow, stage)
    workflow.plan_checksum = "0" * 64
    db = _ScriptedDB(scalars=[workflow])

    with pytest.raises(runtime.OutboxStoredContractError, match="persisted checksum"):
        await runtime.emit_stage_ready(
            db,
            workflow_run_id=workflow.id,
            stage_run_id=stage.id,
            emission_kind="root_ready",
        )

    assert len(db.scalar_statements) == 1


@pytest.mark.asyncio
async def test_emit_rejects_noncanonical_plan_order_before_stage_lock():
    workflow = _workflow()
    first = _stage(workflow, stage_key="first", ordinal=1)
    second = _stage(workflow, stage_key="second", ordinal=2)
    _bind_plan(workflow, first, second)
    workflow.stage_plan = list(reversed(workflow.stage_plan))
    db = _ScriptedDB(scalars=[workflow])

    with pytest.raises(runtime.OutboxStoredContractError, match="persisted checksum"):
        await runtime.emit_stage_ready(
            db,
            workflow_run_id=workflow.id,
            stage_run_id=first.id,
            emission_kind="root_ready",
        )

    assert len(db.scalar_statements) == 1


@pytest.mark.asyncio
async def test_emit_rejects_stage_definition_tamper_before_message_lock():
    workflow = _workflow()
    stage = _stage(workflow)
    _bind_plan(workflow, stage)
    stage.max_attempts += 1
    db = _ScriptedDB(scalars=[workflow, stage])

    with pytest.raises(runtime.OutboxStoredContractError, match="canonical workflow plan"):
        await runtime.emit_stage_ready(
            db,
            workflow_run_id=workflow.id,
            stage_run_id=stage.id,
            emission_kind="root_ready",
        )

    assert len(db.scalar_statements) == 2


@pytest.mark.asyncio
async def test_root_projection_reserves_and_appends_in_same_session_transaction():
    workflow = _workflow(status="queued")
    stage = _stage(workflow)
    _bind_plan(workflow, stage)
    intent = runtime.project_stage_ready_intent(
        workflow,
        stage,
        emission_kind="root_ready",
        post_status="ready",
        post_state_version=stage.state_version,
        post_next_attempt_at=stage.next_attempt_at,
        target_attempt_number=1,
    )
    db = _ScriptedDB(scalars=[None])
    _attach(db, workflow, stage)

    reservation = await runtime.reserve_stage_ready_intents(
        db,
        workflow=workflow,
        locked_stages=(stage,),
        target_stages=(stage,),
        intents=(intent,),
    )
    query_count = len(db.scalar_statements)
    results = await runtime.append_reserved_stage_ready(
        db,
        reservation=reservation,
        workflow=workflow,
        locked_stages=(stage,),
    )

    message, created = results[0]
    assert created is True
    assert message.emission_kind == "root_ready"
    assert message.causation_id is None
    assert len(db.scalar_statements) == query_count == 1
    assert db.flushes == [[_snapshot(message)]]


@pytest.mark.asyncio
async def test_direct_and_equal_copy_reservations_cannot_consume_registered_capability():
    db, workflow, stage, reservation = await _reserved_root_case()
    direct = runtime.StageReadyReservation(
        intents=reservation.intents,
        message_ids=reservation.message_ids,
        existing_messages=reservation.existing_messages,
        active_deliveries=reservation.active_deliveries,
        locked_stage_ids=reservation.locked_stage_ids,
        locked_stage_states=reservation.locked_stage_states,
        _session=reservation._session,
        _transaction=reservation._transaction,
    )
    copied = replace(reservation)
    query_count = len(db.scalar_statements)

    for forged in (direct, copied):
        with pytest.raises(runtime.OutboxConflict, match="capability"):
            await runtime.append_reserved_stage_ready(
                db,
                reservation=forged,
                workflow=workflow,
                locked_stages=(stage,),
            )
        assert len(db.scalar_statements) == query_count
        assert db.added == []
        assert db.flushes == []

    ((message, created),) = await runtime.append_reserved_stage_ready(
        db,
        reservation=reservation,
        workflow=workflow,
        locked_stages=(stage,),
    )
    assert created is True and db.added == [message]


@pytest.mark.asyncio
async def test_object_setattr_reservation_forgery_consumes_and_fails_without_side_effects():
    db, workflow, stage, reservation = await _reserved_root_case()
    object.__setattr__(reservation, "message_ids", (uuid.uuid4(),))
    query_count = len(db.scalar_statements)

    with pytest.raises(runtime.OutboxConflict, match="mutated"):
        await runtime.append_reserved_stage_ready(
            db,
            reservation=reservation,
            workflow=workflow,
            locked_stages=(stage,),
        )

    assert len(db.scalar_statements) == query_count
    assert db.added == []
    assert db.flushes == []
    with pytest.raises(runtime.OutboxConflict, match="capability"):
        await runtime.append_reserved_stage_ready(
            db,
            reservation=reservation,
            workflow=workflow,
            locked_stages=(stage,),
        )


@pytest.mark.asyncio
async def test_registered_reservation_is_single_use_before_any_second_side_effect():
    db, workflow, stage, reservation = await _reserved_root_case()
    await runtime.append_reserved_stage_ready(
        db,
        reservation=reservation,
        workflow=workflow,
        locked_stages=(stage,),
    )
    counts = (len(db.scalar_statements), len(db.added), len(db.flushes))

    with pytest.raises(runtime.OutboxConflict, match="capability"):
        await runtime.append_reserved_stage_ready(
            db,
            reservation=reservation,
            workflow=workflow,
            locked_stages=(stage,),
        )

    assert (len(db.scalar_statements), len(db.added), len(db.flushes)) == counts


@pytest.mark.asyncio
async def test_nested_transaction_reservation_and_public_emit_fail_before_sql():
    workflow = _workflow(status="queued")
    stage = _stage(workflow)
    _bind_plan(workflow, stage)
    intent = runtime.project_stage_ready_intent(
        workflow,
        stage,
        emission_kind="root_ready",
        post_status="ready",
        post_state_version=stage.state_version,
        post_next_attempt_at=stage.next_attempt_at,
        target_attempt_number=1,
    )
    db = _ScriptedDB()
    _attach(db, workflow, stage)
    db.nested_transaction = object()

    with pytest.raises(runtime.OutboxConflict, match="nested transaction"):
        await runtime.reserve_stage_ready_intents(
            db,
            workflow=workflow,
            locked_stages=(stage,),
            target_stages=(stage,),
            intents=(intent,),
        )
    with pytest.raises(runtime.OutboxConflict, match="nested transaction"):
        await runtime.emit_stage_ready(
            db,
            workflow_run_id=workflow.id,
            stage_run_id=stage.id,
            emission_kind="root_ready",
        )

    assert db.scalar_statements == []
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
async def test_reservation_rejects_incomplete_or_reordered_stage_authority_without_sql():
    workflow = _workflow()
    first = _stage(workflow, stage_key="first", ordinal=1)
    second = _stage(workflow, stage_key="second", ordinal=2)
    _bind_plan(workflow, first, second)
    intent = runtime.project_stage_ready_intent(
        workflow,
        first,
        emission_kind="root_ready",
        post_status="ready",
        post_state_version=first.state_version,
        post_next_attempt_at=first.next_attempt_at,
        target_attempt_number=1,
    )
    db = _ScriptedDB()
    _attach(db, workflow, first, second)

    for stages in ((first,), (second, first)):
        with pytest.raises(runtime.OutboxConflict, match="complete|plan-ordered"):
            await runtime.reserve_stage_ready_intents(
                db,
                workflow=workflow,
                locked_stages=stages,
                target_stages=(first,),
                intents=(intent,),
            )

    assert db.scalar_statements == []


@pytest.mark.asyncio
async def test_reservation_requires_exact_plan_ordered_target_tuple_before_sql():
    workflow = _workflow()
    first = _stage(workflow, stage_key="first", ordinal=1)
    second = _stage(workflow, stage_key="second", ordinal=2)
    _bind_plan(workflow, first, second)
    intent = runtime.project_stage_ready_intent(
        workflow,
        first,
        emission_kind="root_ready",
        post_status="ready",
        post_state_version=first.state_version,
        post_next_attempt_at=first.next_attempt_at,
        target_attempt_number=1,
    )
    db = _ScriptedDB()
    _attach(db, workflow, first, second)

    with pytest.raises(runtime.OutboxValidation, match="target_stages"):
        await runtime.reserve_stage_ready_intents(
            db,
            workflow=workflow,
            locked_stages=(first, second),
            target_stages=[first],
            intents=(intent,),
        )

    assert db.scalar_statements == []


@pytest.mark.asyncio
async def test_reservation_revalidates_mutated_intent_before_sql():
    workflow = _workflow()
    stage = _stage(workflow)
    _bind_plan(workflow, stage)
    intent = runtime.project_stage_ready_intent(
        workflow,
        stage,
        emission_kind="root_ready",
        post_status="ready",
        post_state_version=stage.state_version,
        post_next_attempt_at=stage.next_attempt_at,
        target_attempt_number=1,
    )
    object.__setattr__(intent.post_target, "state_version", 99)
    db = _ScriptedDB()
    _attach(db, workflow, stage)

    with pytest.raises(runtime.OutboxValidation, match="fixed point|contradictory"):
        await runtime.reserve_stage_ready_intents(
            db,
            workflow=workflow,
            locked_stages=(stage,),
            target_stages=(stage,),
            intents=(intent,),
        )

    assert db.scalar_statements == []


@pytest.mark.asyncio
async def test_transition_reservation_rejects_any_preexisting_message():
    workflow = _workflow()
    stage = _stage(workflow)
    _bind_plan(workflow, stage)
    intent = runtime.project_stage_ready_intent(
        workflow,
        stage,
        emission_kind="root_ready",
        post_status="ready",
        post_state_version=stage.state_version,
        post_next_attempt_at=stage.next_attempt_at,
        target_attempt_number=1,
    )
    existing = _message(workflow, stage, emission_kind="migration_backfill")
    db = _ScriptedDB(scalars=[existing])
    _attach(db, workflow, stage)

    with pytest.raises(runtime.OutboxConflict, match="cannot reuse"):
        await runtime.reserve_stage_ready_intents(
            db,
            workflow=workflow,
            locked_stages=(stage,),
            target_stages=(stage,),
            intents=(intent,),
        )

    assert db.flushes == []


@pytest.mark.asyncio
async def test_dependency_transition_rejects_omitted_eligible_fanout_before_sql():
    workflow = _workflow()
    source = _stage(workflow, status="running", stage_key="fetch", ordinal=1)
    first = _stage(
        workflow,
        status="pending",
        stage_key="extract",
        ordinal=2,
        depends_on=["fetch"],
    )
    second = _stage(
        workflow,
        status="pending",
        stage_key="enrich",
        ordinal=3,
        depends_on=["fetch"],
    )
    _bind_plan(workflow, source, first, second)
    intent = runtime.project_stage_ready_intent(
        workflow,
        first,
        emission_kind="dependency_ready",
        post_status="ready",
        post_state_version=first.state_version + 1,
        post_next_attempt_at=NOW + timedelta(seconds=5),
        target_attempt_number=1,
        causal_stage=source,
    )
    db = _ScriptedDB()
    _attach(db, workflow, source, first, second)

    with pytest.raises(runtime.OutboxConflict, match="exact eligible fan-out"):
        await runtime.reserve_stage_ready_intents(
            db,
            workflow=workflow,
            locked_stages=(source, first, second),
            target_stages=(first,),
            intents=(intent,),
        )

    assert db.scalar_statements == []
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "corruption",
    [
        "pending_root",
        "ready_dependent",
        "checkpoint_history",
        "checkpoint_payload",
        "checkpoint_checksum",
        "output_payload",
    ],
)
async def test_root_transition_rejects_nonpristine_complete_graph_before_sql(corruption):
    workflow = _workflow(status="queued")
    root = _stage(workflow, stage_key="root", ordinal=1)
    if corruption == "pending_root":
        corrupt = _stage(
            workflow,
            status="pending",
            stage_key="corrupt",
            ordinal=2,
        )
    else:
        corrupt = _stage(
            workflow,
            status="pending" if corruption == "checkpoint_history" else "ready",
            stage_key="corrupt",
            ordinal=2,
            depends_on=["root"],
        )
    if corruption == "checkpoint_history":
        root.checkpoint_version = 1
    elif corruption == "checkpoint_payload":
        root.checkpoint = {"cursor": 1}
        root.checkpoint_checksum = checksum_json(root.checkpoint)
    elif corruption == "checkpoint_checksum":
        root.checkpoint_checksum = "a" * 64
    elif corruption == "output_payload":
        root.output_manifest = {"unexpected": True}
    _bind_plan(workflow, root, corrupt)
    intent = runtime.project_stage_ready_intent(
        workflow,
        root,
        emission_kind="root_ready",
        post_status="ready",
        post_state_version=root.state_version,
        post_next_attempt_at=root.next_attempt_at,
        target_attempt_number=1,
    )
    db = _ScriptedDB()
    _attach(db, workflow, root, corrupt)

    with pytest.raises(runtime.OutboxStoredContractError, match="pristine"):
        await runtime.reserve_stage_ready_intents(
            db,
            workflow=workflow,
            locked_stages=(root, corrupt),
            target_stages=(root,),
            intents=(intent,),
        )

    assert db.scalar_statements == []


@pytest.mark.asyncio
@pytest.mark.parametrize("payload_field", ["output_manifest", "checkpoint"])
async def test_dependency_transition_rejects_nonempty_never_run_target_payload(
    payload_field,
):
    workflow = _workflow()
    source = _stage(workflow, status="running", stage_key="source", ordinal=1)
    target = _stage(
        workflow,
        status="pending",
        stage_key="target",
        ordinal=2,
        depends_on=["source"],
    )
    _bind_plan(workflow, source, target)
    setattr(target, payload_field, {"forged": True})
    if payload_field == "checkpoint":
        target.checkpoint_checksum = checksum_json(target.checkpoint)
    intent = runtime.project_stage_ready_intent(
        workflow,
        target,
        emission_kind="dependency_ready",
        post_status="ready",
        post_state_version=target.state_version + 1,
        post_next_attempt_at=NOW,
        target_attempt_number=1,
        causal_stage=source,
    )
    db = _ScriptedDB()
    _attach(db, workflow, source, target)

    with pytest.raises(runtime.OutboxStoredContractError, match="pristine"):
        await runtime.reserve_stage_ready_intents(
            db,
            workflow=workflow,
            locked_stages=(source, target),
            target_stages=(target,),
            intents=(intent,),
        )

    assert db.scalar_statements == []
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
async def test_dependency_transition_rejects_unrelated_stale_eligible_pending_stage():
    workflow = _workflow()
    done = _stage(
        workflow,
        status="succeeded",
        stage_key="done",
        ordinal=1,
    )
    source = _stage(
        workflow,
        status="running",
        stage_key="source",
        ordinal=2,
    )
    stale = _stage(
        workflow,
        status="pending",
        stage_key="stale",
        ordinal=3,
        depends_on=["done"],
    )
    target = _stage(
        workflow,
        status="pending",
        stage_key="target",
        ordinal=4,
        depends_on=["source"],
    )
    _bind_plan(workflow, done, source, stale, target)
    intent = runtime.project_stage_ready_intent(
        workflow,
        target,
        emission_kind="dependency_ready",
        post_status="ready",
        post_state_version=target.state_version + 1,
        post_next_attempt_at=NOW + timedelta(seconds=5),
        target_attempt_number=1,
        causal_stage=source,
    )
    db = _ScriptedDB()
    _attach(db, workflow, done, source, stale, target)

    with pytest.raises(runtime.OutboxStoredContractError, match="already dependency-eligible"):
        await runtime.reserve_stage_ready_intents(
            db,
            workflow=workflow,
            locked_stages=(done, source, stale, target),
            target_stages=(target,),
            intents=(intent,),
        )

    assert db.scalar_statements == []


@pytest.mark.asyncio
async def test_dependency_projection_fanout_appends_atomically_after_exact_cause():
    workflow = _workflow()
    source = _stage(workflow, status="running", stage_key="fetch", ordinal=1)
    first = _stage(
        workflow,
        status="pending",
        stage_key="extract",
        ordinal=2,
        depends_on=["fetch"],
    )
    second = _stage(
        workflow,
        status="pending",
        stage_key="enrich",
        ordinal=3,
        depends_on=["fetch"],
    )
    _bind_plan(workflow, source, first, second)
    available_at = NOW
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
        for target in (first, second)
    )
    db = _ScriptedDB(scalars=[None, None])
    _attach(db, workflow, source, first, second)
    reservation = await runtime.reserve_stage_ready_intents(
        db,
        workflow=workflow,
        locked_stages=(source, first, second),
        target_stages=(first, second),
        intents=intents,
    )
    attempt = _terminal_attempt(source, status="succeeded")
    _apply_dependency_success(source, (first, second), attempt, available_at=available_at)
    _attach(db, attempt)
    query_count = len(db.scalar_statements)

    results = await runtime.append_reserved_stage_ready(
        db,
        reservation=reservation,
        workflow=workflow,
        locked_stages=(source, first, second),
        causal_attempt=attempt,
    )

    messages = [message for message, created in results if created]
    assert len(messages) == 2
    assert {message.stage_run_id for message in messages} == {first.id, second.id}
    assert all(message.causation_id == attempt.id for message in messages)
    assert [message.logical_key for message in messages] == sorted(message.logical_key for message in messages)
    assert len(db.scalar_statements) == query_count == 2
    assert len(db.flushes) == 1 and len(db.flushes[0]) == 2


@pytest.mark.asyncio
async def test_second_fanout_member_tamper_leaves_no_partial_pending_message():
    workflow = _workflow()
    source = _stage(workflow, status="running", stage_key="fetch", ordinal=1)
    first = _stage(
        workflow,
        status="pending",
        stage_key="extract",
        ordinal=2,
        depends_on=["fetch"],
    )
    second = _stage(
        workflow,
        status="pending",
        stage_key="enrich",
        ordinal=3,
        depends_on=["fetch"],
    )
    _bind_plan(workflow, source, first, second)
    available_at = NOW
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
        for target in (first, second)
    )
    db = _ScriptedDB(scalars=[None, None])
    _attach(db, workflow, source, first, second)
    reservation = await runtime.reserve_stage_ready_intents(
        db,
        workflow=workflow,
        locked_stages=(source, first, second),
        target_stages=(first, second),
        intents=intents,
    )
    attempt = _terminal_attempt(source, status="succeeded")
    _apply_dependency_success(source, (first, second), attempt, available_at=available_at)
    _attach(db, attempt)
    by_id = {stage.id: stage for stage in (first, second)}
    second_logical_target = by_id[reservation.intents[1].post_target.stage_run_id]
    second_logical_target.next_attempt_at += timedelta(seconds=1)
    query_count = len(db.scalar_statements)

    with pytest.raises(runtime.OutboxConflict, match="post projection"):
        await runtime.append_reserved_stage_ready(
            db,
            reservation=reservation,
            workflow=workflow,
            locked_stages=(source, first, second),
            causal_attempt=attempt,
        )

    assert len(db.scalar_statements) == query_count
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("emission_kind", "attempt_status", "error_code"),
    [
        ("retry_scheduled", "failed", "stage.retryable"),
        ("lease_recovered", "abandoned", "workflow.lease_expired"),
    ],
)
async def test_retry_and_recovery_projection_bind_exact_terminal_attempt(
    emission_kind,
    attempt_status,
    error_code,
):
    workflow = _workflow()
    stage = _stage(workflow, status="running", attempt_count=1)
    if emission_kind == "lease_recovered":
        stage.lease_expires_at = NOW - timedelta(seconds=1)
        stage.heartbeat_at = NOW - timedelta(seconds=2)
    _bind_plan(workflow, stage)
    available_at = _retry_available_at(
        workflow,
        stage,
        completed_at=NOW,
        attempt_number=stage.attempt_count,
    )
    summary = (
        "Worker lease expired before the attempt reached a terminal outcome"
        if emission_kind == "lease_recovered"
        else "retryable stage failure"
    )
    intent = runtime.project_stage_ready_intent(
        workflow,
        stage,
        emission_kind=emission_kind,
        post_status="retry_wait",
        post_state_version=stage.state_version + 1,
        post_next_attempt_at=available_at,
        target_attempt_number=2,
        post_error_code=error_code,
        post_error_summary=summary,
        post_error_retryable=True,
        causal_stage=stage,
    )
    scalar_values = [NOW, None] if emission_kind == "lease_recovered" else [None]
    db = _ScriptedDB(scalars=scalar_values)
    _attach(db, workflow, stage)
    reservation = await runtime.reserve_stage_ready_intents(
        db,
        workflow=workflow,
        locked_stages=(stage,),
        target_stages=(stage,),
        intents=(intent,),
    )
    if emission_kind == "lease_recovered":
        assert db.scalar_statements[0].get_execution_options()["autoflush"] is False
    attempt = _terminal_attempt(stage, status=attempt_status)
    _apply_retry(stage, attempt, available_at=available_at)
    _attach(db, attempt)
    query_count = len(db.scalar_statements)

    ((message, created),) = await runtime.append_reserved_stage_ready(
        db,
        reservation=reservation,
        workflow=workflow,
        locked_stages=(stage,),
        causal_attempt=attempt,
    )

    assert created is True
    assert message.emission_kind == emission_kind
    assert message.causation_id == attempt.id
    assert message.available_at == available_at
    assert len(db.scalar_statements) == query_count


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("emission_kind", "tampered_field"),
    [
        ("dependency_ready", "lease_owner"),
        ("dependency_ready", "heartbeat_after_expiry"),
        ("retry_scheduled", "started_at"),
        ("lease_recovered", "checkpoint_end_version"),
    ],
)
async def test_causal_attempt_lease_and_checkpoint_tamper_fails_closed(
    emission_kind,
    tampered_field,
):
    db, workflow, stages, reservation, attempt = await _reserved_causal_case(emission_kind)
    if tampered_field == "lease_owner":
        attempt.lease_owner = "different-worker"
    elif tampered_field == "heartbeat_after_expiry":
        attempt.heartbeat_at = attempt.lease_expires_at + timedelta(seconds=1)
        attempt.completed_at = attempt.heartbeat_at
    elif tampered_field == "started_at":
        attempt.started_at += timedelta(seconds=1)
    else:
        attempt.checkpoint_end_version = 999
    query_count = len(db.scalar_statements)

    with pytest.raises(runtime.OutboxStoredContractError, match="Causal attempt"):
        await runtime.append_reserved_stage_ready(
            db,
            reservation=reservation,
            workflow=workflow,
            locked_stages=stages,
            causal_attempt=attempt,
        )

    assert len(db.scalar_statements) == query_count
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("emission_kind", "chronology_tamper"),
    [
        ("dependency_ready", "live_expiry_equality"),
        ("retry_scheduled", "live_completed_after_expiry"),
        ("lease_recovered", "abandoned_completed_before_expiry"),
    ],
)
async def test_causal_attempt_status_specific_chronology_fails_closed(
    emission_kind,
    chronology_tamper,
):
    db, workflow, stages, reservation, attempt = await _reserved_causal_case(emission_kind)
    if chronology_tamper == "live_expiry_equality":
        attempt.heartbeat_at = attempt.lease_expires_at
        attempt.completed_at = attempt.lease_expires_at
    elif chronology_tamper == "live_completed_after_expiry":
        attempt.completed_at = attempt.lease_expires_at + timedelta(microseconds=1)
        attempt.heartbeat_at = attempt.completed_at
    else:
        attempt.completed_at = attempt.lease_expires_at - timedelta(microseconds=1)
        attempt.heartbeat_at = min(attempt.heartbeat_at, attempt.completed_at)
    query_count = len(db.scalar_statements)

    with pytest.raises(runtime.OutboxStoredContractError, match="Causal attempt"):
        await runtime.append_reserved_stage_ready(
            db,
            reservation=reservation,
            workflow=workflow,
            locked_stages=stages,
            causal_attempt=attempt,
        )

    assert len(db.scalar_statements) == query_count
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
async def test_failed_attempt_after_expiry_with_retry_before_completion_fails_closed():
    db, workflow, stages, reservation, attempt = await _reserved_causal_case("retry_scheduled")
    attempt.completed_at = attempt.lease_expires_at + timedelta(seconds=1)
    attempt.heartbeat_at = attempt.completed_at
    (stage,) = stages
    assert stage.next_attempt_at < attempt.completed_at
    query_count = len(db.scalar_statements)

    with pytest.raises(runtime.OutboxStoredContractError, match="Causal attempt"):
        await runtime.append_reserved_stage_ready(
            db,
            reservation=reservation,
            workflow=workflow,
            locked_stages=stages,
            causal_attempt=attempt,
        )

    assert len(db.scalar_statements) == query_count
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
async def test_abandoned_attempt_completed_before_expiry_fails_closed():
    db, workflow, stages, reservation, attempt = await _reserved_causal_case("lease_recovered")
    attempt.completed_at = attempt.lease_expires_at - timedelta(microseconds=1)
    attempt.heartbeat_at = min(attempt.heartbeat_at, attempt.completed_at)

    with pytest.raises(runtime.OutboxStoredContractError, match="Causal attempt"):
        await runtime.append_reserved_stage_ready(
            db,
            reservation=reservation,
            workflow=workflow,
            locked_stages=stages,
            causal_attempt=attempt,
        )

    assert db.added == []
    assert db.flushes == []


def test_abandoned_attempt_allows_expiry_completion_equality():
    workflow = _workflow()
    stage = _stage(workflow, status="running", attempt_count=1)
    stage.lease_expires_at = NOW - timedelta(seconds=1)
    stage.heartbeat_at = NOW - timedelta(seconds=2)
    _bind_plan(workflow, stage)
    pre = runtime._stage_ready_state(stage)
    attempt = _terminal_attempt(stage, status="abandoned")
    attempt.heartbeat_at = attempt.lease_expires_at
    attempt.completed_at = attempt.lease_expires_at

    runtime._assert_attempt_terminal_basics(
        attempt,
        source=stage,
        expected_attempt_number=pre.attempt_count,
        expected_lease_token=pre.lease_token,
        expected_pre=pre,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("emission_kind", "schedule_offset"),
    [
        ("dependency_ready", timedelta(seconds=-1)),
        ("dependency_ready", timedelta(seconds=1)),
        ("retry_scheduled", timedelta(seconds=-1)),
        ("retry_scheduled", timedelta(seconds=1)),
        ("lease_recovered", timedelta(seconds=-1)),
        ("lease_recovered", timedelta(seconds=1)),
    ],
)
async def test_causal_stage_ready_schedule_requires_exact_completion_or_backoff(
    emission_kind,
    schedule_offset,
):
    db, workflow, stages, reservation, attempt = await _reserved_causal_case(
        emission_kind,
        schedule_offset=schedule_offset,
    )
    query_count = len(db.scalar_statements)

    with pytest.raises(runtime.OutboxStoredContractError, match="exact causal schedule"):
        await runtime.append_reserved_stage_ready(
            db,
            reservation=reservation,
            workflow=workflow,
            locked_stages=stages,
            causal_attempt=attempt,
        )

    assert len(db.scalar_statements) == query_count
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    [
        ("delivery_id", "not-a-cycle-key"),
        ("outbox_delivery_attempt_id", "not-a-uuid"),
    ],
)
async def test_linked_causal_attempt_requires_canonical_receipt_lineage(
    field_name,
    invalid_value,
):
    db, workflow, stages, reservation, attempt = await _reserved_causal_case("retry_scheduled")
    setattr(attempt, field_name, invalid_value)
    query_count = len(db.scalar_statements)

    with pytest.raises(
        runtime.OutboxStoredContractError,
        match="Causal attempt|outbox_delivery_attempt_id",
    ):
        await runtime.append_reserved_stage_ready(
            db,
            reservation=reservation,
            workflow=workflow,
            locked_stages=stages,
            causal_attempt=attempt,
        )

    assert len(db.scalar_statements) == query_count
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
async def test_expand_phase_unlinked_causal_attempt_remains_valid():
    db, workflow, stages, reservation, attempt = await _reserved_causal_case("retry_scheduled")
    attempt.outbox_delivery_attempt_id = None
    attempt.delivery_id = "legacy-unbound-delivery"
    query_count = len(db.scalar_statements)

    ((message, created),) = await runtime.append_reserved_stage_ready(
        db,
        reservation=reservation,
        workflow=workflow,
        locked_stages=stages,
        causal_attempt=attempt,
    )

    assert created is True
    assert message.causation_id == attempt.id
    assert len(db.scalar_statements) == query_count


@pytest.mark.asyncio
async def test_append_rejects_cross_session_and_new_transaction_without_sql():
    workflow = _workflow(status="queued")
    stage = _stage(workflow)
    _bind_plan(workflow, stage)
    intent = runtime.project_stage_ready_intent(
        workflow,
        stage,
        emission_kind="root_ready",
        post_status="ready",
        post_state_version=stage.state_version,
        post_next_attempt_at=stage.next_attempt_at,
        target_attempt_number=1,
    )
    db = _ScriptedDB(scalars=[None])
    _attach(db, workflow, stage)
    reservation = await runtime.reserve_stage_ready_intents(
        db,
        workflow=workflow,
        locked_stages=(stage,),
        target_stages=(stage,),
        intents=(intent,),
    )
    other = _ScriptedDB()

    with pytest.raises(runtime.OutboxConflict, match="capability"):
        await runtime.append_reserved_stage_ready(
            other,
            reservation=reservation,
            workflow=workflow,
            locked_stages=(stage,),
        )
    assert other.scalar_statements == []

    db.root_transaction = object()
    before = len(db.scalar_statements)
    with pytest.raises(runtime.OutboxConflict, match="capability"):
        await runtime.append_reserved_stage_ready(
            db,
            reservation=reservation,
            workflow=workflow,
            locked_stages=(stage,),
        )
    assert len(db.scalar_statements) == before


@pytest.mark.asyncio
async def test_append_revalidates_workflow_target_and_unrelated_locked_stage_facts():
    workflow = _workflow()
    target = _stage(workflow, stage_key="target", ordinal=1)
    other = _stage(
        workflow,
        status="pending",
        stage_key="other",
        ordinal=2,
        depends_on=["target"],
    )
    _bind_plan(workflow, target, other)
    intent = runtime.project_stage_ready_intent(
        workflow,
        target,
        emission_kind="root_ready",
        post_status="ready",
        post_state_version=target.state_version,
        post_next_attempt_at=target.next_attempt_at,
        target_attempt_number=1,
    )
    db = _ScriptedDB(scalars=[None])
    _attach(db, workflow, target, other)
    reservation = await runtime.reserve_stage_ready_intents(
        db,
        workflow=workflow,
        locked_stages=(target, other),
        target_stages=(target,),
        intents=(intent,),
    )
    query_count = len(db.scalar_statements)
    other.state_version += 1

    with pytest.raises(runtime.OutboxConflict, match="unchanged"):
        await runtime.append_reserved_stage_ready(
            db,
            reservation=reservation,
            workflow=workflow,
            locked_stages=(target, other),
        )
    assert len(db.scalar_statements) == query_count
    assert db.flushes == []


@pytest.mark.asyncio
async def test_append_revalidates_workflow_version_with_single_use_capability():
    db, workflow, stage, reservation = await _reserved_root_case()
    workflow.state_version += 1
    query_count = len(db.scalar_statements)

    with pytest.raises(runtime.OutboxConflict, match="Workflow authority"):
        await runtime.append_reserved_stage_ready(
            db,
            reservation=reservation,
            workflow=workflow,
            locked_stages=(stage,),
        )

    assert len(db.scalar_statements) == query_count
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
@pytest.mark.parametrize("payload_field", ["output_manifest", "checkpoint"])
async def test_append_rejects_stage_payload_mutation_after_reservation(
    payload_field,
):
    db, workflow, stage, reservation = await _reserved_root_case()
    setattr(stage, payload_field, {"changed": True})
    if payload_field == "checkpoint":
        stage.checkpoint_checksum = checksum_json(stage.checkpoint)
    query_count = len(db.scalar_statements)

    with pytest.raises(runtime.OutboxConflict, match="post projection"):
        await runtime.append_reserved_stage_ready(
            db,
            reservation=reservation,
            workflow=workflow,
            locked_stages=(stage,),
        )

    assert len(db.scalar_statements) == query_count
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
async def test_append_rejects_arbitrary_terminal_attempt_provenance_without_sql():
    workflow = _workflow()
    stage = _stage(workflow, status="running", attempt_count=1)
    _bind_plan(workflow, stage)
    available_at = NOW + timedelta(minutes=1)
    intent = runtime.project_stage_ready_intent(
        workflow,
        stage,
        emission_kind="retry_scheduled",
        post_status="retry_wait",
        post_state_version=stage.state_version + 1,
        post_next_attempt_at=available_at,
        target_attempt_number=2,
        post_error_code="stage.retryable",
        post_error_summary="retryable stage failure",
        post_error_retryable=True,
        causal_stage=stage,
    )
    db = _ScriptedDB(scalars=[None])
    _attach(db, workflow, stage)
    reservation = await runtime.reserve_stage_ready_intents(
        db,
        workflow=workflow,
        locked_stages=(stage,),
        target_stages=(stage,),
        intents=(intent,),
    )
    attempt = _terminal_attempt(stage, status="failed")
    attempt.error_summary = "different terminal evidence"
    _apply_retry(stage, attempt, available_at=available_at)
    stage.last_error_summary = "retryable stage failure"
    _attach(db, attempt)
    query_count = len(db.scalar_statements)

    with pytest.raises(runtime.OutboxStoredContractError, match="contradicts"):
        await runtime.append_reserved_stage_ready(
            db,
            reservation=reservation,
            workflow=workflow,
            locked_stages=(stage,),
            causal_attempt=attempt,
        )

    assert len(db.scalar_statements) == query_count
    assert db.flushes == []


@pytest.mark.asyncio
async def test_reservation_rejects_nonpersistent_authority_before_sql():
    workflow = _workflow()
    stage = _stage(workflow)
    _bind_plan(workflow, stage)
    intent = runtime.project_stage_ready_intent(
        workflow,
        stage,
        emission_kind="root_ready",
        post_status="ready",
        post_state_version=stage.state_version,
        post_next_attempt_at=stage.next_attempt_at,
        target_attempt_number=1,
    )
    db = _ScriptedDB()
    _attach(db, workflow, stage)
    stage._unit_persistent = False

    with pytest.raises(runtime.OutboxConflict, match="clean persistent"):
        await runtime.reserve_stage_ready_intents(
            db,
            workflow=workflow,
            locked_stages=(stage,),
            target_stages=(stage,),
            intents=(intent,),
        )

    assert db.scalar_statements == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("state_field", "state_value"),
    [
        ("_unit_expired", True),
        ("_unit_expired_attributes", {"status"}),
        ("_unit_unloaded", {"state_version"}),
    ],
)
async def test_reservation_rejects_expired_or_unloaded_column_authority_before_sql(
    state_field,
    state_value,
):
    workflow = _workflow(status="queued")
    stage = _stage(workflow)
    _bind_plan(workflow, stage)
    intent = runtime.project_stage_ready_intent(
        workflow,
        stage,
        emission_kind="root_ready",
        post_status="ready",
        post_state_version=stage.state_version,
        post_next_attempt_at=stage.next_attempt_at,
        target_attempt_number=1,
    )
    db = _ScriptedDB()
    _attach(db, workflow, stage)
    setattr(stage, state_field, state_value)

    with pytest.raises(runtime.OutboxConflict, match="clean persistent"):
        await runtime.reserve_stage_ready_intents(
            db,
            workflow=workflow,
            locked_stages=(stage,),
            target_stages=(stage,),
            intents=(intent,),
        )

    assert db.scalar_statements == []
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
async def test_append_allows_only_server_managed_timestamp_expiry_after_flush():
    db, workflow, stages, reservation, attempt = await _reserved_causal_case("dependency_ready")
    for stage in stages:
        stage._unit_expired_attributes = {"updated_at"}
        stage._unit_unloaded = {"updated_at"}
    attempt._unit_expired_attributes = {"created_at"}
    attempt._unit_unloaded = {"created_at"}
    query_count = len(db.scalar_statements)

    ((message, created),) = await runtime.append_reserved_stage_ready(
        db,
        reservation=reservation,
        workflow=workflow,
        locked_stages=stages,
        causal_attempt=attempt,
    )

    assert created is True
    assert message.causation_id == attempt.id
    assert len(db.scalar_statements) == query_count


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "corrupt_delivery_field",
    ["delivery_token", "state_version", "lease_expires_at"],
)
async def test_reservation_rejects_invalid_active_delivery_authority(
    corrupt_delivery_field,
):
    with pytest.raises(runtime.OutboxStoredContractError, match="Reserved"):
        await _reserved_active_replay_case(corrupt_delivery_field=corrupt_delivery_field)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tampered_field",
    ["delivery_token", "state_version", "lease_expires_at"],
)
async def test_append_rejects_mutated_reserved_delivery_snapshot_without_side_effects(
    tampered_field,
):
    db, workflow, stage, _message_value, delivery, reservation = await _reserved_active_replay_case()
    if tampered_field == "delivery_token":
        delivery.delivery_token = uuid.uuid4()
    elif tampered_field == "state_version":
        delivery.state_version += 1
    else:
        delivery.lease_expires_at += timedelta(seconds=1)
    query_count = len(db.scalar_statements)

    with pytest.raises(runtime.OutboxConflict, match="mutated"):
        await runtime.append_reserved_stage_ready(
            db,
            reservation=reservation,
            workflow=workflow,
            locked_stages=(stage,),
        )

    assert len(db.scalar_statements) == query_count
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
async def test_append_rejects_expired_reserved_delivery_before_snapshot_dereference():
    db, workflow, stage, _message_value, delivery, reservation = await _reserved_active_replay_case()
    delivery._unit_expired = True
    query_count = len(db.scalar_statements)

    with pytest.raises(runtime.OutboxConflict, match="clean persistent"):
        await runtime.append_reserved_stage_ready(
            db,
            reservation=reservation,
            workflow=workflow,
            locked_stages=(stage,),
        )

    assert len(db.scalar_statements) == query_count
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["dispatching", "awaiting_receipt"])
async def test_append_accepts_exact_sealed_active_delivery_replay(status):
    db, workflow, stage, existing, _delivery, reservation = await _reserved_active_replay_case(status=status)
    query_count = len(db.scalar_statements)

    ((message, created),) = await runtime.append_reserved_stage_ready(
        db,
        reservation=reservation,
        workflow=workflow,
        locked_stages=(stage,),
    )

    assert message is existing
    assert created is False
    assert len(db.scalar_statements) == query_count
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
async def test_reservation_locks_all_messages_before_active_deliveries_in_logical_order():
    workflow = _workflow()
    first = _stage(workflow, stage_key="first", ordinal=1)
    second = _stage(workflow, stage_key="second", ordinal=2)
    _bind_plan(workflow, first, second)
    projected = tuple(
        replace(
            runtime.project_stage_ready_intent(
                workflow,
                stage,
                emission_kind="root_ready",
                post_status="ready",
                post_state_version=stage.state_version,
                post_next_attempt_at=stage.next_attempt_at,
                target_attempt_number=1,
            ),
            projection_mode="current",
        )
        for stage in (first, second)
    )
    ordered = tuple(sorted(projected, key=lambda intent: intent.logical_key))
    stage_by_id = {stage.id: stage for stage in (first, second)}
    messages = tuple(
        _message(
            workflow,
            stage_by_id[intent.post_target.stage_run_id],
            status="dispatching",
            attempt_count=1,
            state_version=2,
            delivery_id=uuid.uuid4(),
        )
        for intent in ordered
    )
    deliveries = tuple(_delivery_for_message(message) for message in messages)
    db = _ScriptedDB(scalars=[*messages, *deliveries])
    _attach(db, workflow, first, second)

    reservation = await runtime.reserve_stage_ready_intents(
        db,
        workflow=workflow,
        locked_stages=(first, second),
        target_stages=(first, second),
        intents=projected,
    )

    sql = [_compiled(statement) for statement in db.scalar_statements]
    assert all("outbox_messages" in statement for statement in sql[:2])
    assert all("outbox_delivery_attempts" in statement for statement in sql[2:])
    assert [intent.logical_key for intent in reservation.intents] == sorted(intent.logical_key for intent in reservation.intents)


def test_append_reserved_stage_ready_has_no_query_clock_commit_or_network_escape():
    source = inspect.getsource(runtime.append_reserved_stage_ready)

    for forbidden in (
        "select(",
        ".scalar(",
        "_db_now(",
        "_db_clock_now(",
        ".commit(",
        "requests.",
        "httpx.",
        "celery",
    ):
        assert forbidden not in source


@pytest.mark.asyncio
async def test_claim_uses_skip_locked_db_time_and_flushes_message_before_delivery():
    workflow = _workflow()
    stage = _stage(workflow)
    message = _message(workflow, stage)
    db = _ScriptedDB(scalars=[message, NOW])

    claim = await runtime.claim_outbox_delivery(
        db,
        publisher_id="publisher-1",
        lease_seconds=120,
    )

    assert claim is not None
    delivery = db.added[0]
    assert isinstance(delivery, OutboxDeliveryAttempt)
    assert message.status == delivery.status == "dispatching"
    assert message.state_version == 2
    assert delivery.state_version == 1
    assert message.attempt_count == delivery.attempt_number == 1
    assert message.delivery_cycle == delivery.delivery_cycle == 1
    assert message.cycle_key == delivery.cycle_key == claim.cycle_key
    assert message.active_delivery_attempt_id == delivery.id == claim.delivery_attempt_id
    assert message.lease_token == delivery.delivery_token == claim.delivery_token
    assert message.leased_at == delivery.leased_at == NOW
    assert message.heartbeat_at == delivery.heartbeat_at == NOW
    assert message.lease_expires_at == delivery.lease_expires_at == NOW + timedelta(seconds=120)
    assert [entry[0]["type"] for entry in db.flushes] == [
        "OutboxMessage",
        "OutboxDeliveryAttempt",
    ]
    first_copy = claim.envelope
    first_copy["payload"]["stage_key"] = "mutated"
    assert claim.envelope["payload"]["stage_key"] == stage.stage_key
    claim_sql = _compiled(db.scalar_statements[0])
    assert "FOR UPDATE OF outbox_messages SKIP LOCKED" in claim_sql
    assert "transaction_timestamp()" in claim_sql
    assert "transaction_timestamp()" in _compiled(db.scalar_statements[1])
    assert db.commit_calls == 0


@pytest.mark.asyncio
async def test_claim_detaches_driver_uuid_subtypes_into_exact_stdlib_authority():
    class DriverUUID(uuid.UUID):
        pass

    workflow = _workflow()
    stage = _stage(workflow)
    message = _message(workflow, stage)
    message.id = DriverUUID(str(message.id))
    message.correlation_id = DriverUUID(str(message.correlation_id))
    db = _ScriptedDB(scalars=[message, NOW])

    claim = await runtime.claim_outbox_delivery(db, publisher_id="publisher-1")

    assert claim is not None
    assert type(claim.message_id) is uuid.UUID
    assert type(claim.delivery_attempt_id) is uuid.UUID
    assert type(claim.delivery_token) is uuid.UUID
    assert type(claim.correlation_id) is uuid.UUID


@pytest.mark.asyncio
async def test_claim_query_skips_stale_workflow_stage_snapshots_without_locking_them():
    db = _ScriptedDB(scalars=[None])

    assert await runtime.claim_outbox_delivery(db, publisher_id="publisher-1") is None

    claim_sql = _compiled(db.scalar_statements[0])
    assert "JOIN stage_runs" in claim_sql
    assert "JOIN workflow_runs" in claim_sql
    for field_name in (
        "aggregate_version",
        "state_version",
        "target_attempt_number",
        "attempt_count",
        "input_checksum",
        "plan_checksum",
        "correlation_id",
    ):
        assert field_name in claim_sql
    assert "FOR UPDATE OF outbox_messages SKIP LOCKED" in claim_sql
    assert "FOR UPDATE OF stage_runs" not in claim_sql
    assert "FOR UPDATE OF workflow_runs" not in claim_sql
    assert db.flushes == []


@pytest.mark.parametrize(
    ("field_name", "forged_value"),
    [
        ("topic", "workflow.stage.other"),
        ("schema_version", "workflow-stage-ready-v2"),
        ("envelope_checksum", "0" * 64),
        ("logical_key", "0" * 64),
        ("cycle_key", "0" * 64),
        ("envelope_canonical", " {}"),
    ],
)
def test_claim_authority_rejects_registry_canonical_and_cycle_forgery(
    field_name,
    forged_value,
):
    claim = _claim_authority()
    with pytest.raises(runtime.OutboxValidation):
        replace(claim, **{field_name: forged_value})


def test_claim_authority_rejects_field_and_claim_subclasses():
    class StringSubclass(str):
        pass

    class IntSubclass(int):
        pass

    class UUIDSubclass(uuid.UUID):
        pass

    class ClaimSubclass(runtime.ClaimedOutboxDelivery):
        pass

    claim = _claim_authority()
    for field_name, forged_value in (
        ("topic", StringSubclass(claim.topic)),
        ("delivery_cycle", IntSubclass(claim.delivery_cycle)),
        ("message_id", UUIDSubclass(str(claim.message_id))),
    ):
        with pytest.raises(runtime.OutboxValidation):
            replace(claim, **{field_name: forged_value})
    with pytest.raises(runtime.OutboxValidation, match="exact runtime type"):
        ClaimSubclass(**vars(claim))


@pytest.mark.asyncio
async def test_claim_returns_none_and_rejects_noncanonical_opaque_identity():
    empty = _ScriptedDB(scalars=[None])
    assert await runtime.claim_outbox_delivery(empty, publisher_id="publisher-1") is None
    assert empty.flushes == []

    invalid = _ScriptedDB()
    with pytest.raises(runtime.OutboxValidation, match="surrounding whitespace"):
        await runtime.claim_outbox_delivery(invalid, publisher_id=" publisher-1 ")
    assert invalid.scalar_statements == []


@pytest.mark.asyncio
async def test_broker_message_id_rejects_lone_surrogate_before_database_access():
    message, delivery, token = _active_pair()
    db = _ScriptedDB()

    with pytest.raises(runtime.OutboxValidation, match="valid UTF-8"):
        await runtime.mark_outbox_dispatched(
            db,
            message_id=message.id,
            delivery_attempt_id=delivery.id,
            delivery_token=token,
            expected_message_version=2,
            expected_delivery_version=1,
            broker_name="test_broker",
            broker_message_id="\ud800",
            receipt_timeout_seconds=30,
        )

    assert db.scalar_statements == []


@pytest.mark.asyncio
async def test_claim_rejects_stored_envelope_pointer_drift_before_mutation():
    workflow = _workflow()
    stage = _stage(workflow)
    message = _message(workflow, stage)
    message.stage_key = "different_stage"
    db = _ScriptedDB(scalars=[message])

    with pytest.raises(runtime.OutboxStoredContractError, match="columns disagree"):
        await runtime.claim_outbox_delivery(db, publisher_id="publisher-1")

    assert len(db.scalar_statements) == 1
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
async def test_claim_rejects_stored_canonical_checksum_drift_before_mutation():
    workflow = _workflow()
    stage = _stage(workflow)
    message = _message(workflow, stage)
    message.envelope_checksum = "0" * 64
    db = _ScriptedDB(scalars=[message])

    with pytest.raises(runtime.OutboxStoredContractError, match="canonical authority"):
        await runtime.claim_outbox_delivery(db, publisher_id="publisher-1")

    assert db.flushes == []


@pytest.mark.asyncio
async def test_heartbeat_fences_both_versions_and_updates_exact_equal_lease_facts():
    message, delivery, token = _active_pair()
    old_expiry = message.lease_expires_at
    db = _ScriptedDB(scalars=[message, delivery, NOW])

    result = await runtime.heartbeat_outbox_delivery(
        db,
        message_id=message.id,
        delivery_attempt_id=delivery.id,
        delivery_token=token,
        expected_message_version=2,
        expected_delivery_version=1,
        lease_seconds=120,
    )

    assert result.message.state_version == 3
    assert result.delivery.state_version == 2
    assert message.heartbeat_at == delivery.heartbeat_at == NOW
    assert message.lease_expires_at == delivery.lease_expires_at == NOW + timedelta(seconds=120)
    assert message.lease_expires_at > old_expiry
    assert [entry[0]["type"] for entry in db.flushes] == [
        "OutboxMessage",
        "OutboxDeliveryAttempt",
    ]
    lock_sql = [_compiled(statement) for statement in db.scalar_statements[:2]]
    assert "outbox_messages" in lock_sql[0] and "FOR UPDATE" in lock_sql[0]
    assert "outbox_delivery_attempts" in lock_sql[1] and "FOR UPDATE" in lock_sql[1]
    assert db.commit_calls == 0


@pytest.mark.asyncio
async def test_heartbeat_rejects_stale_version_or_arbitrary_token_without_flush():
    message, delivery, token = _active_pair()
    stale = _ScriptedDB(scalars=[message, delivery, NOW])
    with pytest.raises(runtime.OutboxLeaseLost, match="version"):
        await runtime.heartbeat_outbox_delivery(
            stale,
            message_id=message.id,
            delivery_attempt_id=delivery.id,
            delivery_token=token,
            expected_message_version=99,
            expected_delivery_version=1,
        )
    assert stale.flushes == []

    message, delivery, _ = _active_pair()
    wrong_token = _ScriptedDB(scalars=[message, delivery, NOW])
    with pytest.raises(runtime.OutboxLeaseLost, match="token"):
        await runtime.heartbeat_outbox_delivery(
            wrong_token,
            message_id=message.id,
            delivery_attempt_id=delivery.id,
            delivery_token=uuid.uuid4(),
            expected_message_version=2,
            expected_delivery_version=1,
        )
    assert wrong_token.flushes == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    [
        ("message_id", "not-a-uuid"),
        ("delivery_attempt_id", "not-a-uuid"),
        ("delivery_token", "not-a-uuid"),
        ("expected_message_version", True),
        ("expected_delivery_version", 0),
        ("lease_seconds", 0),
    ],
)
async def test_heartbeat_prevalidates_commands_before_locking(
    field_name,
    invalid_value,
):
    message, delivery, token = _active_pair()
    command = {
        "message_id": message.id,
        "delivery_attempt_id": delivery.id,
        "delivery_token": token,
        "expected_message_version": 2,
        "expected_delivery_version": 1,
        "lease_seconds": 60,
    }
    command[field_name] = invalid_value
    db = _ScriptedDB()

    with pytest.raises(runtime.OutboxValidation):
        await runtime.heartbeat_outbox_delivery(db, **command)

    assert db.scalar_statements == []


@pytest.mark.asyncio
async def test_mark_dispatched_terminalizes_delivery_side_first_and_opens_receipt_window():
    message, delivery, token = _active_pair()
    db = _ScriptedDB(scalars=[message, delivery, NOW])

    result = await runtime.mark_outbox_dispatched(
        db,
        message_id=message.id,
        delivery_attempt_id=delivery.id,
        delivery_token=token,
        expected_message_version=2,
        expected_delivery_version=1,
        broker_name="test_broker",
        broker_message_id="broker-message-1",
        receipt_timeout_seconds=90,
    )

    assert result.replayed is False
    assert delivery.status == message.status == "awaiting_receipt"
    assert delivery.state_version == 2
    assert message.state_version == 3
    assert delivery.dispatched_at == NOW
    assert delivery.receipt_deadline_at == message.receipt_deadline_at == NOW + timedelta(seconds=90)
    assert message.lease_token is None
    assert message.lease_owner == ""
    assert [entry[0]["type"] for entry in db.flushes] == [
        "OutboxDeliveryAttempt",
        "OutboxMessage",
    ]
    assert db.commit_calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    [
        ("message_id", "not-a-uuid"),
        ("delivery_token", "not-a-uuid"),
        ("expected_message_version", 0),
        ("expected_delivery_version", False),
        ("receipt_timeout_seconds", 0),
        ("broker_name", "Not_An_Identity"),
        ("broker_message_id", " broker-message-1 "),
    ],
)
async def test_mark_prevalidates_commands_before_locking(
    field_name,
    invalid_value,
):
    message, delivery, token = _active_pair()
    command = {
        "message_id": message.id,
        "delivery_attempt_id": delivery.id,
        "delivery_token": token,
        "expected_message_version": 2,
        "expected_delivery_version": 1,
        "broker_name": "test_broker",
        "broker_message_id": "broker-message-1",
        "receipt_timeout_seconds": 30,
    }
    command[field_name] = invalid_value
    db = _ScriptedDB()

    with pytest.raises(runtime.OutboxValidation):
        await runtime.mark_outbox_dispatched(db, **command)

    assert db.scalar_statements == []


@pytest.mark.asyncio
async def test_mark_dispatched_exact_replay_is_lineage_bounded_and_noop():
    message, delivery, token = _active_pair(status="awaiting_receipt")
    db = _ScriptedDB(scalars=[message, delivery])

    result = await runtime.mark_outbox_dispatched(
        db,
        message_id=message.id,
        delivery_attempt_id=delivery.id,
        delivery_token=token,
        expected_message_version=2,
        expected_delivery_version=1,
        broker_name="test_broker",
        broker_message_id="broker-message-1",
        receipt_timeout_seconds=30,
    )

    assert result.replayed is True
    assert len(db.scalar_statements) == 2
    assert db.flushes == []

    message, delivery, _ = _active_pair(status="awaiting_receipt")
    wrong_token = _ScriptedDB(scalars=[message, delivery, NOW])
    with pytest.raises(runtime.OutboxLeaseLost):
        await runtime.mark_outbox_dispatched(
            wrong_token,
            message_id=message.id,
            delivery_attempt_id=delivery.id,
            delivery_token=uuid.uuid4(),
            expected_message_version=2,
            expected_delivery_version=1,
            broker_name="test_broker",
            broker_message_id="broker-message-1",
            receipt_timeout_seconds=30,
        )
    assert wrong_token.flushes == []


@pytest.mark.asyncio
async def test_mark_dispatched_replays_after_delivered_receipt():
    message, delivery, token = _delivered_pair()
    db = _ScriptedDB(scalars=[message, delivery])

    result = await runtime.mark_outbox_dispatched(
        db,
        message_id=message.id,
        delivery_attempt_id=delivery.id,
        delivery_token=token,
        expected_message_version=2,
        expected_delivery_version=1,
        broker_name="test_broker",
        broker_message_id="broker-message-1",
        receipt_timeout_seconds=999,
    )

    assert result.replayed is True
    assert message.status == delivery.status == "delivered"
    assert db.flushes == []


@pytest.mark.asyncio
async def test_mark_dispatched_replays_after_direct_receipt_with_delta_one():
    message, delivery, token = _delivered_pair()
    message.state_version = 3
    delivery.state_version = 2
    db = _ScriptedDB(scalars=[message, delivery])

    result = await runtime.mark_outbox_dispatched(
        db,
        message_id=message.id,
        delivery_attempt_id=delivery.id,
        delivery_token=token,
        expected_message_version=2,
        expected_delivery_version=1,
        broker_name="test_broker",
        broker_message_id="broker-message-1",
        receipt_timeout_seconds=30,
    )

    assert result.replayed is True
    assert db.flushes == []


@pytest.mark.asyncio
@pytest.mark.parametrize("version_mode", ["current", "future"])
async def test_mark_replay_rejects_current_or_future_expected_versions(version_mode):
    message, delivery, token = _active_pair(status="awaiting_receipt")
    expected_message = message.state_version + (1 if version_mode == "future" else 0)
    expected_delivery = delivery.state_version + (1 if version_mode == "future" else 0)
    db = _ScriptedDB(scalars=[message, delivery, NOW])

    with pytest.raises(runtime.OutboxLeaseLost):
        await runtime.mark_outbox_dispatched(
            db,
            message_id=message.id,
            delivery_attempt_id=delivery.id,
            delivery_token=token,
            expected_message_version=expected_message,
            expected_delivery_version=expected_delivery,
            broker_name="test_broker",
            broker_message_id="broker-message-1",
            receipt_timeout_seconds=30,
        )

    assert db.flushes == []


@pytest.mark.asyncio
async def test_mark_replay_rejects_older_equal_delta_outside_bounded_state_path():
    message, delivery, token = _active_pair(
        status="awaiting_receipt",
        message_state_version=4,
        delivery_state_version=3,
    )
    db = _ScriptedDB(scalars=[message, delivery, NOW])

    with pytest.raises(runtime.OutboxLeaseLost):
        await runtime.mark_outbox_dispatched(
            db,
            message_id=message.id,
            delivery_attempt_id=delivery.id,
            delivery_token=token,
            expected_message_version=2,
            expected_delivery_version=1,
            broker_name="test_broker",
            broker_message_id="broker-message-1",
            receipt_timeout_seconds=30,
        )

    assert db.flushes == []


@pytest.mark.asyncio
async def test_delivered_mark_replay_rejects_equal_delta_greater_than_two():
    message, delivery, token = _delivered_pair()
    message.state_version = 5
    delivery.state_version = 4
    db = _ScriptedDB(scalars=[message, delivery, NOW])

    with pytest.raises(runtime.OutboxLeaseLost):
        await runtime.mark_outbox_dispatched(
            db,
            message_id=message.id,
            delivery_attempt_id=delivery.id,
            delivery_token=token,
            expected_message_version=2,
            expected_delivery_version=1,
            broker_name="test_broker",
            broker_message_id="broker-message-1",
            receipt_timeout_seconds=30,
        )

    assert db.flushes == []


@pytest.mark.asyncio
async def test_historical_mark_replay_is_lease_lost_not_stored_contract_error():
    message, current_delivery, _ = _active_pair(
        attempt_count=2,
        message_state_version=5,
        delivery_state_version=1,
    )
    old_token = uuid.uuid4()
    historical = OutboxDeliveryAttempt(
        id=uuid.uuid4(),
        message_id=message.id,
        delivery_cycle=1,
        attempt_number=1,
        cycle_key=delivery_cycle_idempotency_key(message.logical_key, delivery_cycle=1),
        delivery_token=old_token,
        publisher_id="publisher-old",
        status="failed",
        state_version=2,
        leased_at=NOW - timedelta(minutes=2),
        heartbeat_at=NOW - timedelta(minutes=2),
        lease_expires_at=NOW - timedelta(minutes=1),
        broker_name="",
        broker_message_id="",
        broker_receipt_id="",
        dispatched_at=None,
        receipt_deadline_at=None,
        receipt_received_at=None,
        completed_at=NOW - timedelta(minutes=1),
        error_code="outbox.connection_failed",
        error_class="BrokerConnectionError",
        error_summary="Connection refused",
        retryable=True,
    )
    assert message.active_delivery_attempt_id == current_delivery.id
    db = _ScriptedDB(scalars=[message, historical, NOW])

    with pytest.raises(runtime.OutboxLeaseLost):
        await runtime.mark_outbox_dispatched(
            db,
            message_id=message.id,
            delivery_attempt_id=historical.id,
            delivery_token=old_token,
            expected_message_version=message.state_version,
            expected_delivery_version=historical.state_version,
            broker_name="test_broker",
            broker_message_id="broker-message-old",
            receipt_timeout_seconds=30,
        )

    assert db.flushes == []


@pytest.mark.asyncio
async def test_fail_delivery_records_sanitized_evidence_then_exact_retry_schedule():
    message, delivery, token = _active_pair()
    error = sanitize_outbox_error(
        "Authorization: Bearer secret-token",
        code="outbox.publish_failed",
        retryable=True,
        error_class="BrokerPublishError",
    )
    db = _ScriptedDB(scalars=[message, delivery, NOW])

    result = await runtime.fail_outbox_delivery(
        db,
        message_id=message.id,
        delivery_attempt_id=delivery.id,
        delivery_token=token,
        expected_message_version=2,
        expected_delivery_version=1,
        error=error,
    )

    delay = deterministic_delivery_retry_delay_seconds(
        1,
        logical_key=message.logical_key,
    )
    assert result.replayed is False
    assert delivery.status == "failed"
    assert delivery.state_version == 2
    assert message.status == "retry_wait"
    assert message.state_version == 3
    assert message.available_at == NOW + timedelta(seconds=delay)
    assert message.active_delivery_attempt_id is None
    assert "secret-token" not in message.last_error_summary
    assert message.last_error_summary == delivery.error_summary == error.summary
    assert [entry[0]["type"] for entry in db.flushes] == [
        "OutboxDeliveryAttempt",
        "OutboxMessage",
    ]
    assert db.commit_calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("retryable", "attempt_count"),
    [(False, 1), (True, OUTBOX_V1_MAX_ATTEMPTS)],
)
async def test_fail_delivery_dead_letters_nonretryable_or_exhausted_budget(
    retryable,
    attempt_count,
):
    message, delivery, token = _active_pair(
        attempt_count=attempt_count,
        message_state_version=2 * attempt_count,
    )
    error = sanitize_outbox_error(
        "Permanent broker failure",
        code="outbox.publish_failed",
        retryable=retryable,
        error_class="BrokerPublishError",
    )
    db = _ScriptedDB(scalars=[message, delivery, NOW])

    await runtime.fail_outbox_delivery(
        db,
        message_id=message.id,
        delivery_attempt_id=delivery.id,
        delivery_token=token,
        expected_message_version=2 * attempt_count,
        expected_delivery_version=1,
        error=error,
    )

    assert message.status == "dead_lettered"
    assert message.available_at is None
    assert message.dead_lettered_at == delivery.completed_at == NOW
    assert delivery.status == "failed"


@pytest.mark.asyncio
async def test_failure_exact_replay_is_noop_and_rejects_arbitrary_token():
    message, delivery, token, error = _failed_pair()
    exact = _ScriptedDB(scalars=[message, delivery])
    result = await runtime.fail_outbox_delivery(
        exact,
        message_id=message.id,
        delivery_attempt_id=delivery.id,
        delivery_token=token,
        expected_message_version=message.state_version - 1,
        expected_delivery_version=delivery.state_version - 1,
        error=error,
    )
    assert result.replayed is True
    assert exact.flushes == []

    message, delivery, _, error = _failed_pair()
    invalid = _ScriptedDB(scalars=[message, delivery, NOW])
    with pytest.raises(runtime.OutboxLeaseLost):
        await runtime.fail_outbox_delivery(
            invalid,
            message_id=message.id,
            delivery_attempt_id=delivery.id,
            delivery_token=uuid.uuid4(),
            expected_message_version=message.state_version - 1,
            expected_delivery_version=delivery.state_version - 1,
            error=error,
        )
    assert invalid.flushes == []


@pytest.mark.asyncio
@pytest.mark.parametrize("version_mode", ["older", "current", "future"])
async def test_failure_replay_rejects_nonpredecessor_versions(version_mode):
    message, delivery, token, error = _failed_pair()
    if version_mode == "older":
        # Two prior heartbeats make +3 an internally possible but stale delta.
        message.state_version = 5
        delivery.state_version = 4
        expected_message = 2
        expected_delivery = 1
    else:
        offset = 1 if version_mode == "future" else 0
        expected_message = message.state_version + offset
        expected_delivery = delivery.state_version + offset
    db = _ScriptedDB(scalars=[message, delivery, NOW])

    with pytest.raises(runtime.OutboxLeaseLost):
        await runtime.fail_outbox_delivery(
            db,
            message_id=message.id,
            delivery_attempt_id=delivery.id,
            delivery_token=token,
            expected_message_version=expected_message,
            expected_delivery_version=expected_delivery,
            error=error,
        )

    assert db.flushes == []


@pytest.mark.asyncio
async def test_historical_failure_replay_cannot_match_newer_active_lineage():
    message, _, _ = _active_pair(
        attempt_count=2,
        message_state_version=5,
    )
    old_message, historical, old_token, error = _failed_pair()
    historical.message_id = message.id
    historical.cycle_key = delivery_cycle_idempotency_key(
        message.logical_key,
        delivery_cycle=1,
    )
    historical.delivery_cycle = 1
    historical.attempt_number = 1
    assert old_message.attempt_count == 1
    db = _ScriptedDB(scalars=[message, historical, NOW])

    with pytest.raises(runtime.OutboxLeaseLost):
        await runtime.fail_outbox_delivery(
            db,
            message_id=message.id,
            delivery_attempt_id=historical.id,
            delivery_token=old_token,
            expected_message_version=message.state_version,
            expected_delivery_version=historical.state_version,
            error=error,
        )

    assert db.flushes == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    [
        ("message_id", "not-a-uuid"),
        ("delivery_attempt_id", "not-a-uuid"),
        ("delivery_token", "not-a-uuid"),
        ("expected_message_version", 0),
        ("expected_delivery_version", True),
    ],
)
async def test_failure_prevalidates_fences_before_locking(
    field_name,
    invalid_value,
):
    message, delivery, token = _active_pair()
    command = {
        "message_id": message.id,
        "delivery_attempt_id": delivery.id,
        "delivery_token": token,
        "expected_message_version": 2,
        "expected_delivery_version": 1,
        "error": sanitize_outbox_error(
            "Connection refused",
            code="outbox.connection_failed",
            retryable=True,
            error_class="BrokerConnectionError",
        ),
    }
    command[field_name] = invalid_value
    db = _ScriptedDB()

    with pytest.raises(runtime.OutboxValidation):
        await runtime.fail_outbox_delivery(db, **command)

    assert db.scalar_statements == []


@pytest.mark.asyncio
async def test_service_revalidates_even_exact_type_error_before_database_access():
    forged = object.__new__(SanitizedOutboxError)
    object.__setattr__(forged, "code", "outbox.publish_failed")
    object.__setattr__(forged, "error_class", "BrokerPublishError")
    object.__setattr__(forged, "summary", "token=raw-secret")
    object.__setattr__(forged, "retryable", True)
    db = _ScriptedDB()

    with pytest.raises(runtime.OutboxValidation, match="fixed point"):
        await runtime.fail_outbox_delivery(
            db,
            message_id=uuid.uuid4(),
            delivery_attempt_id=uuid.uuid4(),
            delivery_token=uuid.uuid4(),
            expected_message_version=1,
            expected_delivery_version=1,
            error=forged,
        )

    assert db.scalar_statements == []
    assert db.flushes == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field_name", "forged_value"),
    [
        ("code", "INVALID"),
        ("error_class", "invalid class"),
        ("summary", "token=raw-secret"),
        ("retryable", 1),
    ],
)
async def test_forged_exact_error_type_is_normalized_to_runtime_validation(
    field_name,
    forged_value,
):
    facts = {
        "code": "outbox.publish_failed",
        "error_class": "BrokerPublishError",
        "summary": "Connection refused",
        "retryable": True,
    }
    facts[field_name] = forged_value
    forged = object.__new__(SanitizedOutboxError)
    for name, value in facts.items():
        object.__setattr__(forged, name, value)
    db = _ScriptedDB()

    with pytest.raises(runtime.OutboxValidation):
        await runtime.fail_outbox_delivery(
            db,
            message_id=uuid.uuid4(),
            delivery_attempt_id=uuid.uuid4(),
            delivery_token=uuid.uuid4(),
            expected_message_version=1,
            expected_delivery_version=1,
            error=forged,
        )

    assert db.scalar_statements == []


def test_sanitized_error_constructor_itself_rejects_secret_forgery():
    with pytest.raises(OutboxContractError, match="fixed-point"):
        SanitizedOutboxError(
            code="outbox.publish_failed",
            error_class="BrokerPublishError",
            summary="password=raw-secret",
            retryable=True,
        )


@pytest.mark.asyncio
async def test_recover_expired_dispatch_abandons_delivery_then_schedules_retry():
    message, delivery, _ = _active_pair()
    message.lease_expires_at = NOW - timedelta(seconds=1)
    delivery.lease_expires_at = message.lease_expires_at
    db = _ScriptedDB(scalars=[message, delivery, NOW, None])

    results = await runtime.recover_expired_outbox_deliveries(db, limit=1)

    delay = deterministic_delivery_retry_delay_seconds(
        message.attempt_count,
        logical_key=message.logical_key,
    )
    assert len(results) == 1
    assert delivery.status == "abandoned"
    assert delivery.retryable is True
    assert delivery.error_code == "outbox.dispatch_lease_expired"
    assert message.status == "retry_wait"
    assert message.active_delivery_attempt_id is None
    assert message.available_at == NOW + timedelta(seconds=delay)
    assert [entry[0]["type"] for entry in db.flushes] == [
        "OutboxDeliveryAttempt",
        "OutboxMessage",
    ]
    recovery_sql = _compiled(db.scalar_statements[0])
    assert "FOR UPDATE SKIP LOCKED" in recovery_sql
    assert "transaction_timestamp()" in recovery_sql
    assert "outbox_messages" in recovery_sql
    assert "outbox_delivery_attempts" in _compiled(db.scalar_statements[1])
    assert db.commit_calls == 0


@pytest.mark.asyncio
async def test_recover_expired_receipt_dead_letters_exhausted_delivery():
    message, delivery, _ = _active_pair(
        status="awaiting_receipt",
        attempt_count=OUTBOX_V1_MAX_ATTEMPTS,
        message_state_version=17,
        delivery_state_version=2,
    )
    message.receipt_deadline_at = NOW - timedelta(seconds=1)
    delivery.receipt_deadline_at = message.receipt_deadline_at
    db = _ScriptedDB(scalars=[message, delivery, NOW, None])

    results = await runtime.recover_expired_outbox_deliveries(db)

    assert results[0].message_status == "dead_lettered"
    assert delivery.status == "abandoned"
    assert delivery.error_code == "outbox.receipt_timeout"
    assert message.status == "dead_lettered"
    assert message.available_at is None
    assert message.dead_lettered_at == delivery.completed_at == NOW


@pytest.mark.asyncio
async def test_recover_none_is_noop_and_runtime_never_calls_commit():
    db = _ScriptedDB(scalars=[None])
    assert await runtime.recover_expired_outbox_deliveries(db) == []
    assert db.flushes == []
    assert db.commit_calls == 0
    assert ".commit(" not in inspect.getsource(runtime)


@pytest.mark.asyncio
async def test_receipt_direct_dispatch_persists_evidence_then_pending_activation():
    workflow, stage, message, delivery, command = _receipt_case()
    db = _ScriptedDB(scalars=[workflow, stage, message, delivery, NOW, 101])

    pending = await runtime.receipt_and_claim_stage(db, command=command)

    attempt = db.added[-1]
    assert isinstance(attempt, StageAttempt)
    assert pending.disposition == "activated"
    assert pending.should_execute is False
    assert pending.commit_ticket is not None and len(pending.commit_ticket) == 160
    assert not hasattr(pending, "stage_lease_token")
    assert workflow.status == "running"
    assert workflow.started_at == NOW
    assert stage.status == "running"
    assert stage.attempt_count == 1
    assert delivery.status == message.status == "delivered"
    assert delivery.broker_receipt_id == "f" * 64
    assert attempt.outbox_delivery_attempt_id == delivery.id
    assert attempt.delivery_id == delivery.cycle_key
    assert attempt.lease_token == stage.lease_token
    assert attempt.lease_owner == stage.lease_owner == "worker-1"
    assert attempt.started_at == stage.leased_at == NOW
    assert attempt.lease_expires_at == stage.lease_expires_at == NOW + timedelta(seconds=120)
    assert [[item["type"] for item in flush] for flush in db.flushes] == [
        ["OutboxDeliveryAttempt"],
        ["OutboxMessage"],
        ["WorkflowRun", "StageRun"],
        ["StageAttempt"],
    ]
    lock_sql = [_compiled(statement) for statement in db.scalar_statements[:4]]
    assert all("FOR UPDATE" in statement for statement in lock_sql)
    assert all(statement.get_execution_options().get("populate_existing") is True for statement in db.scalar_statements[:4])
    assert all(statement.get_execution_options().get("autoflush") is False for statement in db.scalar_statements)
    assert "workflow_runs" in lock_sql[0]
    assert "stage_runs" in lock_sql[1]
    assert "outbox_messages" in lock_sql[2]
    assert "outbox_delivery_attempts" in lock_sql[3]
    assert "clock_timestamp()" in _compiled(db.scalar_statements[4])
    assert "txid_current()" in _compiled(db.scalar_statements[5])
    assert db.commit_calls == 0


@pytest.mark.asyncio
async def test_receipt_regenerates_a_worker_token_that_collides_with_delivery(
    monkeypatch,
):
    workflow, stage, message, delivery, command = _receipt_case()
    fresh_worker_token = uuid.UUID("11111111-1111-4111-8111-111111111111")
    attempt_id = uuid.UUID("22222222-2222-4222-8222-222222222222")
    generated = iter([delivery.delivery_token, fresh_worker_token, attempt_id])
    monkeypatch.setattr(runtime.uuid, "uuid4", lambda: next(generated))
    db = _ScriptedDB(scalars=[workflow, stage, message, delivery, NOW, 114])

    await runtime.receipt_and_claim_stage(db, command=command)

    attempt = db.added[-1]
    assert attempt.lease_token == stage.lease_token == fresh_worker_token
    assert attempt.lease_token != delivery.delivery_token
    assert attempt.id == attempt_id


@pytest.mark.asyncio
async def test_awaiting_receipt_accepts_one_version_delta_and_preserves_broker_identity():
    workflow, stage, message, delivery, command = _receipt_case(
        delivery_status="awaiting_receipt",
        workflow_status="running",
    )
    dispatched_at = delivery.dispatched_at
    db = _ScriptedDB(scalars=[workflow, stage, message, delivery, NOW, 102])

    pending = await runtime.receipt_and_claim_stage(db, command=command)

    assert pending.disposition == "activated"
    assert delivery.state_version == 3
    assert message.state_version == 4
    assert delivery.dispatched_at == dispatched_at
    assert delivery.broker_name == command.broker_name
    assert delivery.broker_message_id == command.broker_message_id
    assert [item[0]["type"] for item in db.flushes] == [
        "OutboxDeliveryAttempt",
        "OutboxMessage",
        "StageRun",
        "StageAttempt",
    ]


@pytest.mark.asyncio
async def test_receipt_uses_post_lock_wall_clock_and_rejects_blocked_past_expiry():
    workflow, stage, message, delivery, command = _receipt_case()
    after_expiry = NOW + timedelta(seconds=31)
    db = _ScriptedDB(scalars=[workflow, stage, message, delivery, after_expiry])

    with pytest.raises(runtime.OutboxLeaseLost, match="live lease"):
        await runtime.receipt_and_claim_stage(db, command=command)

    assert db.flushes == []
    assert len(db.scalar_statements) == 5
    assert "clock_timestamp()" in _compiled(db.scalar_statements[-1])


@pytest.mark.asyncio
async def test_exact_delivered_receipt_replay_never_mints_execution_or_ticket():
    workflow, stage, message, delivery, command = _receipt_case()
    first_db = _ScriptedDB(scalars=[workflow, stage, message, delivery, NOW, 103])
    first = await runtime.receipt_and_claim_stage(first_db, command=command)
    attempt = first_db.added[-1]
    replay_command = replace(command, worker_id="different-worker", lease_seconds=600)
    replay_db = _ScriptedDB(scalars=[workflow, stage, message, delivery, attempt])

    replay = await runtime.receipt_and_claim_stage(
        replay_db,
        command=replay_command,
    )

    assert replay.disposition == "replayed"
    assert replay.replayed is True
    assert replay.should_execute is False
    assert replay.commit_ticket is None
    assert replay.stage_attempt_id == attempt.id == first.stage_attempt_id
    assert replay_db.flushes == []
    assert len(replay_db.scalar_statements) == 5
    assert all(statement.get_execution_options().get("populate_existing") is True for statement in replay_db.scalar_statements)
    assert all(statement.get_execution_options().get("autoflush") is False for statement in replay_db.scalar_statements)


@pytest.mark.asyncio
async def test_failed_or_abandoned_historical_delivery_returns_stale_disposition():
    workflow, stage, message, delivery, command = _receipt_case(delivery_status="awaiting_receipt")
    delivery.status = "abandoned"
    delivery.state_version = 3
    delivery.receipt_deadline_at = None
    delivery.completed_at = NOW
    delivery.error_code = "outbox.receipt_timeout"
    delivery.error_class = "DeliveryReceiptTimeout"
    delivery.error_summary = "Receipt timed out"
    delivery.retryable = True
    message.status = "retry_wait"
    message.state_version = 4
    message.active_delivery_attempt_id = None
    message.receipt_deadline_at = None
    message.available_at = NOW + timedelta(seconds=10)
    message.last_error_code = delivery.error_code
    message.last_error_class = delivery.error_class
    message.last_error_summary = delivery.error_summary
    message.last_error_retryable = True
    db = _ScriptedDB(scalars=[workflow, stage, message, delivery])

    result = await runtime.receipt_and_claim_stage(db, command=command)

    assert result.disposition == "stale"
    assert result.stage_attempt_id is None
    assert result.commit_ticket is None
    assert result.should_execute is False
    assert db.flushes == []


@pytest.mark.asyncio
async def test_exact_cancelled_delivery_returns_cancelled_disposition():
    workflow, stage, message, delivery, command = _receipt_case()
    delivery.status = "cancelled"
    delivery.state_version = 2
    delivery.completed_at = NOW
    delivery.error_code = "outbox.cancelled"
    delivery.error_class = "DeliveryCancelled"
    delivery.error_summary = "Workflow cancelled"
    message.status = "cancelled"
    message.state_version = 3
    message.active_delivery_attempt_id = None
    message.lease_owner = ""
    message.lease_token = None
    message.leased_at = None
    message.heartbeat_at = None
    message.lease_expires_at = None
    message.cancelled_at = NOW
    db = _ScriptedDB(scalars=[workflow, stage, message, delivery])

    result = await runtime.receipt_and_claim_stage(db, command=command)

    assert result.disposition == "cancelled"
    assert result.stage_attempt_id is None
    assert result.commit_ticket is None
    assert result.should_execute is False
    assert db.flushes == []


@pytest.mark.asyncio
async def test_confirm_requires_a_new_transaction_then_returns_executable_authority():
    workflow, stage, message, delivery, command = _receipt_case()
    receipt_db = _ScriptedDB(scalars=[workflow, stage, message, delivery, NOW, 104])
    pending = await runtime.receipt_and_claim_stage(receipt_db, command=command)
    attempt = receipt_db.added[-1]
    assert pending.commit_ticket is not None

    same_transaction = _ScriptedDB(scalars=[104])
    with pytest.raises(runtime.OutboxConflict, match="commit"):
        await runtime.confirm_committed_activation(
            same_transaction,
            commit_ticket=pending.commit_ticket,
        )
    assert len(same_transaction.scalar_statements) == 1
    assert same_transaction.scalar_statements[0].get_execution_options().get("autoflush") is False

    confirm_db = _ScriptedDB(scalars=[105, workflow, stage, message, delivery, attempt, NOW])
    authority = await runtime.confirm_committed_activation(
        confirm_db,
        commit_ticket=pending.commit_ticket,
    )

    assert isinstance(authority, runtime.ExecutableStageAuthority)
    assert authority.stage_lease_token == attempt.lease_token
    assert authority.stage_attempt_id == attempt.id
    assert authority.delivery_attempt_id == delivery.id
    assert authority.broker_receipt_id == command.broker_receipt_id
    assert all(
        type(value) is uuid.UUID
        for value in (
            authority.workflow_run_id,
            authority.stage_run_id,
            authority.stage_attempt_id,
            authority.message_id,
            authority.delivery_attempt_id,
            authority.stage_lease_token,
        )
    )
    assert confirm_db.flushes == []
    assert "clock_timestamp()" in _compiled(confirm_db.scalar_statements[-1])
    assert all(statement.get_execution_options().get("autoflush") is False for statement in confirm_db.scalar_statements)
    assert all(statement.get_execution_options().get("populate_existing") is True for statement in confirm_db.scalar_statements[1:6])


@pytest.mark.asyncio
async def test_confirmation_of_missing_or_expired_activation_returns_none():
    workflow, stage, message, delivery, command = _receipt_case()
    receipt_db = _ScriptedDB(scalars=[workflow, stage, message, delivery, NOW, 106])
    pending = await runtime.receipt_and_claim_stage(receipt_db, command=command)
    attempt = receipt_db.added[-1]
    assert pending.commit_ticket is not None

    missing_db = _ScriptedDB(scalars=[107, None])
    assert (
        await runtime.confirm_committed_activation(
            missing_db,
            commit_ticket=pending.commit_ticket,
        )
        is None
    )

    stage.lease_expires_at = NOW - timedelta(seconds=1)
    attempt.lease_expires_at = stage.lease_expires_at
    expired_db = _ScriptedDB(scalars=[108, workflow, stage, message, delivery, attempt, NOW])
    assert (
        await runtime.confirm_committed_activation(
            expired_db,
            commit_ticket=pending.commit_ticket,
        )
        is None
    )


@pytest.mark.parametrize("receipt_id", ["raw-ack-handle", "F" * 64, "f" * 63])
def test_receipt_command_rejects_nonfingerprint_receipt_locator(receipt_id):
    *_, command = _receipt_case()
    with pytest.raises(runtime.OutboxValidation, match="SHA-256"):
        replace(command, broker_receipt_id=receipt_id)


@pytest.mark.asyncio
async def test_forged_receipt_command_is_revalidated_before_database_access():
    *_, command = _receipt_case()
    forged = object.__new__(runtime.StageReceiptCommand)
    for name in command.__dataclass_fields__:
        object.__setattr__(forged, name, getattr(command, name))
    object.__setattr__(forged, "broker_receipt_id", "raw-secret-ack-handle")
    db = _ScriptedDB()

    with pytest.raises(runtime.OutboxValidation):
        await runtime.receipt_and_claim_stage(db, command=forged)

    assert db.scalar_statements == []
    assert db.flushes == []


@pytest.mark.asyncio
async def test_receipt_result_normalizes_driver_uuid_subtypes():
    class DriverUUID(uuid.UUID):
        pass

    workflow, stage, message, delivery, command = _receipt_case()
    workflow.id = DriverUUID(str(workflow.id))
    stage.id = DriverUUID(str(stage.id))
    stage.workflow_run_id = workflow.id
    message.id = DriverUUID(str(message.id))
    message.workflow_run_id = workflow.id
    message.stage_run_id = stage.id
    message.aggregate_id = stage.id
    delivery.id = DriverUUID(str(delivery.id))
    delivery.message_id = message.id
    message.active_delivery_attempt_id = delivery.id
    db = _ScriptedDB(scalars=[workflow, stage, message, delivery, NOW, 109])

    pending = await runtime.receipt_and_claim_stage(db, command=command)

    assert type(pending.workflow_run_id) is uuid.UUID
    assert type(pending.stage_run_id) is uuid.UUID
    assert type(pending.message_id) is uuid.UUID
    assert type(pending.delivery_attempt_id) is uuid.UUID
    assert type(pending.stage_attempt_id) is uuid.UUID


@pytest.mark.asyncio
async def test_receipt_rejects_active_versions_outside_zero_or_one_delta():
    workflow, stage, message, delivery, command = _receipt_case()
    message.state_version += 2
    delivery.state_version += 2
    db = _ScriptedDB(scalars=[workflow, stage, message, delivery, NOW])

    with pytest.raises(runtime.OutboxLeaseLost, match="versions"):
        await runtime.receipt_and_claim_stage(db, command=command)

    assert db.flushes == []


@pytest.mark.asyncio
async def test_delivered_receipt_without_exact_linked_attempt_is_contract_error():
    workflow, stage, message, delivery, command = _receipt_case()
    first_db = _ScriptedDB(scalars=[workflow, stage, message, delivery, NOW, 110])
    await runtime.receipt_and_claim_stage(first_db, command=command)
    replay_db = _ScriptedDB(scalars=[workflow, stage, message, delivery, None])

    with pytest.raises(runtime.OutboxStoredContractError, match="linked stage attempt"):
        await runtime.receipt_and_claim_stage(replay_db, command=command)

    assert replay_db.flushes == []


@pytest.mark.asyncio
async def test_delivered_replay_rejects_broker_or_receipt_fingerprint_tamper():
    workflow, stage, message, delivery, command = _receipt_case()
    first_db = _ScriptedDB(scalars=[workflow, stage, message, delivery, NOW, 111])
    await runtime.receipt_and_claim_stage(first_db, command=command)
    attempt = first_db.added[-1]

    for changed in (
        replace(command, broker_message_id="different-broker-message"),
        replace(command, broker_receipt_id="0" * 64),
    ):
        replay_db = _ScriptedDB(scalars=[workflow, stage, message, delivery, attempt])
        with pytest.raises(runtime.OutboxLeaseLost, match="immutable evidence"):
            await runtime.receipt_and_claim_stage(replay_db, command=changed)
        assert replay_db.flushes == []


@pytest.mark.asyncio
async def test_linked_attempt_cannot_reuse_delivery_token_on_replay_or_confirmation():
    workflow, stage, message, delivery, command = _receipt_case()
    receipt_db = _ScriptedDB(scalars=[workflow, stage, message, delivery, NOW, 115])
    pending = await runtime.receipt_and_claim_stage(receipt_db, command=command)
    attempt = receipt_db.added[-1]
    assert pending.commit_ticket is not None
    attempt.lease_token = delivery.delivery_token
    replay_db = _ScriptedDB(scalars=[workflow, stage, message, delivery, attempt])

    with pytest.raises(runtime.OutboxStoredContractError, match="contradicts"):
        await runtime.receipt_and_claim_stage(replay_db, command=command)

    stage.lease_token = delivery.delivery_token
    confirm_db = _ScriptedDB(scalars=[116, workflow, stage, message, delivery, attempt, NOW])
    with pytest.raises(runtime.OutboxStoredContractError, match="inconsistent"):
        await runtime.confirm_committed_activation(
            confirm_db,
            commit_ticket=pending.commit_ticket,
        )


@pytest.mark.asyncio
async def test_commit_ticket_tamper_cannot_mint_executable_authority():
    workflow, stage, message, delivery, command = _receipt_case()
    receipt_db = _ScriptedDB(scalars=[workflow, stage, message, delivery, NOW, 112])
    pending = await runtime.receipt_and_claim_stage(receipt_db, command=command)
    attempt = receipt_db.added[-1]
    assert pending.commit_ticket is not None
    suffix = "A" if pending.commit_ticket[-1] != "A" else "B"
    tampered = pending.commit_ticket[:-1] + suffix
    confirm_db = _ScriptedDB(scalars=[113, workflow, stage, message, delivery, attempt, NOW])

    with pytest.raises(runtime.OutboxLeaseLost, match="ticket"):
        await runtime.confirm_committed_activation(
            confirm_db,
            commit_ticket=tampered,
        )

    assert confirm_db.flushes == []


@pytest.mark.asyncio
async def test_execution_receipt_reservation_locks_exact_w_s_m_d_a_then_consumes_at_fresh_clock():
    workflow, stage, message, delivery, attempt, authority = _execution_receipt_case()
    consumed_at = NOW + timedelta(microseconds=1)
    db = _ScriptedDB(
        scalars=[workflow, stage, message, delivery, attempt, NOW, consumed_at],
    )

    reservation = await runtime.reserve_stage_execution_receipt(
        db,
        authority=authority,
    )

    statements = [_compiled(statement) for statement in db.scalar_statements]
    assert len(statements) == 6
    assert [
        "FROM workflow_runs" in statements[0],
        "FROM stage_runs" in statements[1],
        "FROM outbox_messages" in statements[2],
        "FROM outbox_delivery_attempts" in statements[3],
        "FROM stage_attempts" in statements[4],
        "clock_timestamp" in statements[5],
    ] == [True] * 6
    assert all("FOR UPDATE" in statement for statement in statements[:5])
    assert "FOR UPDATE" not in statements[5]
    for statement in db.scalar_statements[:5]:
        options = statement.get_execution_options()
        assert options["populate_existing"] is True
        assert options["autoflush"] is False
    assert db.added == []
    assert db.flushes == []

    query_count = len(db.scalar_statements)
    locked = await runtime.consume_stage_execution_receipt(
        db,
        reservation=reservation,
        authority=authority,
    )
    assert locked.workflow is workflow
    assert locked.stage is stage
    assert locked.message is message
    assert locked.delivery is delivery
    assert locked.attempt is attempt
    assert locked.authority == authority
    assert locked.observed_at == consumed_at
    assert delivery.completed_at < attempt.started_at
    assert len(db.scalar_statements) == query_count + 1
    assert "clock_timestamp" in _compiled(db.scalar_statements[-1])
    assert db.added == []
    assert db.flushes == []

    with pytest.raises(runtime.OutboxConflict, match="not registered"):
        await runtime.consume_stage_execution_receipt(
            db,
            reservation=reservation,
            authority=authority,
        )


@pytest.mark.asyncio
async def test_execution_receipt_rejects_authority_subclass_and_forged_fields_before_sql():
    *_, authority = _execution_receipt_case()

    class AuthoritySubclass(runtime.ExecutableStageAuthority):
        pass

    subclass = object.__new__(AuthoritySubclass)
    for name in authority.__dataclass_fields__:
        object.__setattr__(subclass, name, getattr(authority, name))

    forged = object.__new__(runtime.ExecutableStageAuthority)
    for name in authority.__dataclass_fields__:
        object.__setattr__(forged, name, getattr(authority, name))
    object.__setattr__(forged, "broker_receipt_id", "raw-broker-receipt")

    for hostile in (subclass, forged):
        db = _ScriptedDB()
        with pytest.raises(runtime.OutboxValidation):
            await runtime.reserve_stage_execution_receipt(
                db,
                authority=hostile,
            )
        assert db.scalar_statements == []
        assert db.added == []
        assert db.flushes == []


@pytest.mark.asyncio
async def test_execution_receipt_rejects_nested_transaction_before_sql():
    *_, authority = _execution_receipt_case()
    db = _ScriptedDB()
    db.nested_transaction = object()

    with pytest.raises(runtime.OutboxConflict, match="nested transaction"):
        await runtime.reserve_stage_execution_receipt(
            db,
            authority=authority,
        )

    assert db.scalar_statements == []
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
@pytest.mark.parametrize("collection_name", ["new", "dirty", "deleted"])
async def test_execution_receipt_rejects_dirty_session_before_first_refresh(collection_name):
    *_, authority = _execution_receipt_case()
    db = _ScriptedDB()
    getattr(db, collection_name).add(object())

    with pytest.raises(runtime.OutboxConflict, match="entirely clean session"):
        await runtime.reserve_stage_execution_receipt(
            db,
            authority=authority,
        )

    assert db.scalar_statements == []
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
async def test_execution_receipt_reservation_is_identity_safe_and_single_use():
    workflow, stage, message, delivery, attempt, authority = _execution_receipt_case()
    db = _ScriptedDB(
        scalars=[workflow, stage, message, delivery, attempt, NOW, NOW],
    )
    reservation = await runtime.reserve_stage_execution_receipt(
        db,
        authority=authority,
    )
    forged = replace(reservation)

    with pytest.raises(runtime.OutboxConflict, match="not registered"):
        await runtime.consume_stage_execution_receipt(
            db,
            reservation=forged,
            authority=authority,
        )

    locked = await runtime.consume_stage_execution_receipt(
        db,
        reservation=reservation,
        authority=authority,
    )
    assert locked.attempt is attempt
    with pytest.raises(runtime.OutboxConflict, match="not registered"):
        await runtime.consume_stage_execution_receipt(
            db,
            reservation=reservation,
            authority=authority,
        )


@pytest.mark.asyncio
async def test_execution_receipt_coordinate_can_only_be_issued_once_per_root_transaction():
    workflow, stage, message, delivery, attempt, authority = _execution_receipt_case()
    db = _ScriptedDB(
        scalars=[
            workflow,
            stage,
            message,
            delivery,
            attempt,
            NOW,
            workflow,
            NOW,
            workflow,
        ],
    )
    reservation = await runtime.reserve_stage_execution_receipt(
        db,
        authority=authority,
    )

    with pytest.raises(runtime.OutboxConflict, match="already reserved"):
        await runtime.reserve_stage_execution_receipt(
            db,
            authority=authority,
        )

    locked = await runtime.consume_stage_execution_receipt(
        db,
        reservation=reservation,
        authority=authority,
    )
    assert locked.attempt is attempt

    with pytest.raises(runtime.OutboxConflict, match="already reserved"):
        await runtime.reserve_stage_execution_receipt(
            db,
            authority=authority,
        )

    assert len(db.scalar_statements) == 9
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
async def test_execution_receipt_reservation_cannot_cross_session_root_or_savepoint():
    workflow, stage, message, delivery, attempt, authority = _execution_receipt_case()
    db = _ScriptedDB(
        scalars=[workflow, stage, message, delivery, attempt, NOW, NOW],
    )
    reservation = await runtime.reserve_stage_execution_receipt(
        db,
        authority=authority,
    )

    other = _ScriptedDB()
    with pytest.raises(runtime.OutboxConflict, match="not registered"):
        await runtime.consume_stage_execution_receipt(
            other,
            reservation=reservation,
            authority=authority,
        )

    original_transaction = db.root_transaction
    db.root_transaction = object()
    with pytest.raises(runtime.OutboxConflict, match="not registered"):
        await runtime.consume_stage_execution_receipt(
            db,
            reservation=reservation,
            authority=authority,
        )
    db.root_transaction = original_transaction

    db.nested_transaction = object()
    with pytest.raises(runtime.OutboxConflict, match="nested transaction"):
        await runtime.consume_stage_execution_receipt(
            db,
            reservation=reservation,
            authority=authority,
        )
    db.nested_transaction = None
    assert (
        await runtime.consume_stage_execution_receipt(
            db,
            reservation=reservation,
            authority=authority,
        )
    ).attempt is attempt


@pytest.mark.asyncio
async def test_execution_receipt_consumption_detects_in_place_row_tamper_without_query():
    workflow, stage, message, delivery, attempt, authority = _execution_receipt_case()
    db = _ScriptedDB(
        scalars=[workflow, stage, message, delivery, attempt, NOW],
    )
    reservation = await runtime.reserve_stage_execution_receipt(
        db,
        authority=authority,
    )
    query_count = len(db.scalar_statements)
    stage.checkpoint["hostile"] = True

    with pytest.raises(runtime.OutboxConflict, match="mutated"):
        await runtime.consume_stage_execution_receipt(
            db,
            reservation=reservation,
            authority=authority,
        )

    assert len(db.scalar_statements) == query_count
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
async def test_execution_receipt_full_seal_detects_clean_untracked_workflow_tamper():
    workflow, stage, message, delivery, attempt, authority = _execution_receipt_case()
    db = _ScriptedDB(
        scalars=[workflow, stage, message, delivery, attempt, NOW],
    )
    reservation = await runtime.reserve_stage_execution_receipt(
        db,
        authority=authority,
    )
    query_count = len(db.scalar_statements)
    workflow.started_at -= timedelta(seconds=1)

    with pytest.raises(runtime.OutboxConflict, match="mutated"):
        await runtime.consume_stage_execution_receipt(
            db,
            reservation=reservation,
            authority=authority,
        )

    assert len(db.scalar_statements) == query_count
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
async def test_execution_receipt_fails_closed_on_null_attempt_delivery_link():
    workflow, stage, message, delivery, attempt, authority = _execution_receipt_case()
    attempt.outbox_delivery_attempt_id = None
    db = _ScriptedDB(
        scalars=[workflow, stage, message, delivery, attempt, NOW],
    )

    with pytest.raises(runtime.OutboxStoredContractError, match="UUID authority"):
        await runtime.reserve_stage_execution_receipt(
            db,
            authority=authority,
        )

    assert len(db.scalar_statements) == 6
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
async def test_execution_receipt_uses_post_lock_wall_clock_and_rejects_expired_lease():
    workflow, stage, message, delivery, attempt, authority = _execution_receipt_case()
    expired_at = NOW - timedelta(microseconds=1)
    stage.lease_expires_at = expired_at
    attempt.lease_expires_at = expired_at
    authority = replace(authority, lease_expires_at=expired_at)
    db = _ScriptedDB(
        scalars=[workflow, stage, message, delivery, attempt, NOW],
    )

    with pytest.raises(runtime.OutboxLeaseLost, match="no longer live"):
        await runtime.reserve_stage_execution_receipt(
            db,
            authority=authority,
        )

    assert "FROM stage_attempts" in _compiled(db.scalar_statements[-2])
    assert "clock_timestamp" in _compiled(db.scalar_statements[-1])
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
async def test_execution_receipt_consume_rechecks_wall_clock_and_spends_expired_capability():
    workflow, stage, message, delivery, attempt, authority = _execution_receipt_case()
    after_expiry = stage.lease_expires_at + timedelta(microseconds=1)
    db = _ScriptedDB(
        scalars=[workflow, stage, message, delivery, attempt, NOW, after_expiry],
    )
    reservation = await runtime.reserve_stage_execution_receipt(
        db,
        authority=authority,
    )

    with pytest.raises(runtime.OutboxLeaseLost, match="no longer live"):
        await runtime.consume_stage_execution_receipt(
            db,
            reservation=reservation,
            authority=authority,
        )
    with pytest.raises(runtime.OutboxConflict, match="not registered"):
        await runtime.consume_stage_execution_receipt(
            db,
            reservation=reservation,
            authority=authority,
        )

    assert "clock_timestamp" in _compiled(db.scalar_statements[-1])
    assert len(db.scalar_statements) == 7
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
async def test_execution_receipt_consume_fails_closed_if_wall_clock_moves_backwards():
    workflow, stage, message, delivery, attempt, authority = _execution_receipt_case()
    db = _ScriptedDB(
        scalars=[workflow, stage, message, delivery, attempt, NOW, NOW - timedelta(microseconds=1)],
    )
    reservation = await runtime.reserve_stage_execution_receipt(
        db,
        authority=authority,
    )

    with pytest.raises(runtime.OutboxStoredContractError, match="moved backwards"):
        await runtime.consume_stage_execution_receipt(
            db,
            reservation=reservation,
            authority=authority,
        )
    with pytest.raises(runtime.OutboxConflict, match="not registered"):
        await runtime.consume_stage_execution_receipt(
            db,
            reservation=reservation,
            authority=authority,
        )

    assert len(db.scalar_statements) == 7
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
async def test_execution_receipt_rejects_stale_dto_after_full_lock_without_writes():
    workflow, stage, message, delivery, attempt, authority = _execution_receipt_case()
    stale = replace(authority, attempt_state_version=authority.attempt_state_version + 1)
    db = _ScriptedDB(
        scalars=[workflow, stage, message, delivery, attempt, NOW],
    )

    with pytest.raises(runtime.OutboxLeaseLost, match="no longer matches"):
        await runtime.reserve_stage_execution_receipt(
            db,
            authority=stale,
        )

    assert len(db.scalar_statements) == 6
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tamper",
    [
        "canonical_envelope",
        "plan_correlation",
        "latest_cycle",
        "attempt_pointer",
        "attempt_delivery_id",
        "checkpoint_checksum",
        "version_lineage",
        "broker_chronology",
    ],
)
async def test_execution_receipt_rejects_persisted_lineage_tamper_without_writes(tamper):
    workflow, stage, message, delivery, attempt, authority = _execution_receipt_case()
    if tamper == "canonical_envelope":
        message.envelope_canonical += " "
    elif tamper == "plan_correlation":
        message.correlation_id = uuid.uuid4()
    elif tamper == "latest_cycle":
        message.delivery_cycle += 1
    elif tamper == "attempt_pointer":
        attempt.outbox_delivery_attempt_id = uuid.uuid4()
    elif tamper == "attempt_delivery_id":
        attempt.delivery_id = "0" * 64
    elif tamper == "checkpoint_checksum":
        stage.checkpoint_checksum = "0" * 64
    elif tamper == "version_lineage":
        message.aggregate_version += 1
    else:
        delivery.dispatched_at = delivery.receipt_received_at + timedelta(seconds=1)
    db = _ScriptedDB(
        scalars=[workflow, stage, message, delivery, attempt, NOW],
    )

    with pytest.raises((runtime.OutboxStoredContractError, runtime.OutboxLeaseLost)):
        await runtime.reserve_stage_execution_receipt(
            db,
            authority=authority,
        )

    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tamper",
    [
        "root_cause",
        "workflow_self_cause",
        "delivery_self_cause",
        "dependency_without_dependencies",
        "retry_for_first_attempt",
        "migration_cause",
        "unexpected_redrive",
        "manual_redrive",
    ],
)
async def test_execution_receipt_rejects_unprovable_source_provenance(tamper):
    workflow, stage, message, delivery, attempt, authority = _execution_receipt_case()
    cause_id = uuid.uuid4()
    if tamper == "root_cause":
        message.causation_id = cause_id
    elif tamper == "workflow_self_cause":
        message.causation_id = workflow.id
    elif tamper == "delivery_self_cause":
        message.causation_id = delivery.id
    elif tamper == "dependency_without_dependencies":
        message.emission_kind = "dependency_ready"
        message.causation_id = cause_id
    elif tamper == "retry_for_first_attempt":
        message.emission_kind = "retry_scheduled"
        message.causation_id = cause_id
    elif tamper == "migration_cause":
        message.emission_kind = "migration_backfill"
        message.causation_id = cause_id
    elif tamper == "unexpected_redrive":
        message.redrive_of_message_id = uuid.uuid4()
        message.redrive_ordinal = 1
    else:
        message.emission_kind = "manual_redrive"
        message.redrive_of_message_id = uuid.uuid4()
        message.redrive_ordinal = 1
        message.redrive_requested_by = "operator"
        message.redrive_requested_by_id = "operator-1"
        message.redrive_reason = "approved replay"
        message.redrive_requested_at = message.created_at
    registrations_before = dict(runtime._STAGE_EXECUTION_RECEIPT_RESERVATIONS)
    db = _ScriptedDB(
        scalars=[workflow, stage, message, delivery, attempt, NOW],
    )

    with pytest.raises(runtime.OutboxStoredContractError, match="execution source|execution cannot|Manual-redrive"):
        await runtime.reserve_stage_execution_receipt(
            db,
            authority=authority,
        )

    assert runtime._STAGE_EXECUTION_RECEIPT_RESERVATIONS == registrations_before
    fence = db.info.get(runtime._STAGE_EXECUTION_RECEIPT_FENCE_INFO_KEY)
    assert fence is not None
    assert fence.coordinates == {}
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "timeline",
    ["stage_heartbeat", "delivery_heartbeat", "workflow_updated_at"],
)
async def test_execution_receipt_rejects_future_authority_timestamps(timeline):
    workflow, stage, message, delivery, attempt, authority = _execution_receipt_case()
    if timeline == "stage_heartbeat":
        stage.heartbeat_at = NOW + timedelta(seconds=1)
        attempt.heartbeat_at = stage.heartbeat_at
    elif timeline == "delivery_heartbeat":
        delivery.heartbeat_at = NOW + timedelta(seconds=1)
    else:
        workflow.updated_at = NOW + timedelta(seconds=1)
    db = _ScriptedDB(
        scalars=[workflow, stage, message, delivery, attempt, NOW],
    )

    with pytest.raises(runtime.OutboxStoredContractError, match="internally inconsistent"):
        await runtime.reserve_stage_execution_receipt(
            db,
            authority=authority,
        )

    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
async def test_execution_receipt_rejects_expired_or_unloaded_orm_authority():
    workflow, stage, message, delivery, attempt, authority = _execution_receipt_case()
    stage._unit_unloaded = {"checkpoint_version"}
    db = _ScriptedDB(
        scalars=[workflow, stage, message, delivery, attempt, NOW],
    )
    stage._unit_unloaded = {"checkpoint_version"}

    with pytest.raises(runtime.OutboxConflict, match="clean persistent state"):
        await runtime.reserve_stage_execution_receipt(
            db,
            authority=authority,
        )

    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
async def test_completion_graph_locks_union_in_canonical_order_and_consumes_fresh_intents():
    (
        workflow,
        stages,
        source_message,
        source_delivery,
        attempt,
        authority,
        target_messages,
        target_deliveries,
    ) = _completion_receipt_case(target_count=2)
    consumed_at = NOW + timedelta(microseconds=1)
    db = _ScriptedDB(
        scalars=_completion_scalar_script(
            workflow,
            stages,
            source_message,
            source_delivery,
            attempt,
            target_messages,
            target_deliveries,
            consume_clock=consumed_at,
        )
    )

    reservation = await runtime.reserve_stage_completion_graph(db, authority=authority)

    statements = [_compiled(statement) for statement in db.scalar_statements]
    assert len(statements) == 8
    assert "FROM workflow_runs" in statements[0] and "FOR UPDATE" in statements[0]
    assert "FROM stage_runs" in statements[1] and "FOR UPDATE" in statements[1]
    assert "ORDER BY stage_runs.ordinal ASC, stage_runs.id ASC" in statements[1]
    assert all("FROM outbox_messages" in item and "FOR UPDATE" not in item for item in statements[2:4])
    assert "FROM outbox_messages" in statements[4] and "FOR UPDATE" in statements[4]
    assert "FROM outbox_delivery_attempts" in statements[5] and "FOR UPDATE" in statements[5]
    assert "FROM stage_attempts" in statements[6] and "FOR UPDATE" in statements[6]
    assert "clock_timestamp" in statements[7] and "FOR UPDATE" not in statements[7]
    assert reservation.stages == stages
    assert reservation.source_stage_index == 0
    assert len(reservation.target_projections) == 2
    assert reservation.existing_target_messages == (None, None)
    assert reservation.active_target_deliveries == (None, None)
    assert reservation.locked_message_ids == (source_message.id,)
    assert reservation.locked_delivery_ids == (source_delivery.id,)
    assert db.added == [] and db.flushes == [] and db.commit_calls == 0

    locked = await runtime.consume_stage_completion_graph(
        db,
        reservation=reservation,
        authority=authority,
    )
    assert locked.observed_at == consumed_at
    assert len(locked.intents) == 2
    assert tuple(intent.pre_target.stage_run_id for intent in locked.intents) == tuple(stage.id for stage in stages[1:])
    assert all(intent.emission_kind == "dependency_ready" for intent in locked.intents)
    assert all(intent.projection_mode == "transition" and intent.allow_create for intent in locked.intents)
    assert all(intent.post_target.status == "ready" for intent in locked.intents)
    assert all(intent.post_target.next_attempt_at == consumed_at for intent in locked.intents)
    assert tuple(intent.logical_key for intent in locked.intents) == tuple(item.logical_key for item in reservation.target_projections)
    append_reservation = locked.stage_ready_reservation
    assert type(append_reservation) is runtime.StageReadyReservation
    assert tuple(intent.logical_key for intent in append_reservation.intents) == tuple(
        sorted(intent.logical_key for intent in locked.intents)
    )
    message_id_by_key = dict(
        zip(
            (intent.logical_key for intent in locked.intents),
            reservation.target_message_ids,
            strict=True,
        )
    )
    assert append_reservation.message_ids == tuple(message_id_by_key[intent.logical_key] for intent in append_reservation.intents)
    assert append_reservation.existing_messages == (None, None)
    assert append_reservation.active_deliveries == (None, None)
    assert append_reservation.locked_stage_ids == tuple(stage.id for stage in stages)
    append_key = (id(db), id(db.root_transaction), id(append_reservation))
    assert runtime._STAGE_READY_RESERVATIONS[append_key].reservation_ref() is append_reservation
    fanout_coordinate = runtime._stage_ready_fanout_coordinate(append_reservation)
    assert runtime._stage_completion_fanout_fence(db, db.root_transaction).coordinates[fanout_coordinate] == (
        "issued",
        id(append_reservation),
    )
    assert "clock_timestamp" in _compiled(db.scalar_statements[-1])
    assert db.added == [] and db.flushes == [] and db.commit_calls == 0


@pytest.mark.asyncio
async def test_completion_graph_permits_exact_zero_target_fanout():
    case = _completion_receipt_case(target_count=0)
    workflow, stages, source_message, source_delivery, attempt, authority, messages, deliveries = case
    db = _ScriptedDB(
        scalars=_completion_scalar_script(
            workflow,
            stages,
            source_message,
            source_delivery,
            attempt,
            messages,
            deliveries,
            consume_clock=NOW,
        )
    )

    reservation = await runtime.reserve_stage_completion_graph(db, authority=authority)
    locked = await runtime.consume_stage_completion_graph(db, reservation=reservation, authority=authority)

    assert reservation.target_projections == ()
    assert reservation.target_message_ids == ()
    assert reservation.existing_target_messages == ()
    assert locked.intents == ()
    assert locked.stage_ready_reservation is None
    fanout_coordinate = runtime._stage_completion_fanout_coordinate(reservation)
    assert runtime._stage_completion_fanout_fence(db, db.root_transaction).coordinates[fanout_coordinate] == (
        "spent",
        id(reservation),
    )
    assert len(db.scalar_statements) == 7
    assert db.added == [] and db.flushes == []


@pytest.mark.asyncio
async def test_completion_graph_transfers_query_free_one_shot_append_authority():
    db, workflow, stages, attempt, _reservation, locked = await _consumed_completion_case()
    append_reservation = locked.stage_ready_reservation
    assert type(append_reservation) is runtime.StageReadyReservation
    query_count = len(db.scalar_statements)
    _apply_successful_completion(locked)

    results = await runtime.append_reserved_stage_ready(
        db,
        reservation=append_reservation,
        workflow=workflow,
        locked_stages=stages,
        causal_attempt=attempt,
    )

    assert len(db.scalar_statements) == query_count
    assert tuple(created for _message, created in results) == (True, True)
    messages = tuple(message for message, _created in results)
    assert tuple(message.id for message in messages) == append_reservation.message_ids
    assert tuple(message.logical_key for message in messages) == tuple(intent.logical_key for intent in append_reservation.intents)
    assert all(message.causation_id == attempt.id for message in messages)
    assert db.added == list(messages)
    assert db.flushes == [[_snapshot(message) for message in messages]]

    counts = (len(db.scalar_statements), len(db.added), len(db.flushes))
    with pytest.raises(runtime.OutboxConflict, match="capability"):
        await runtime.append_reserved_stage_ready(
            db,
            reservation=append_reservation,
            workflow=workflow,
            locked_stages=stages,
            causal_attempt=attempt,
        )
    assert (len(db.scalar_statements), len(db.added), len(db.flushes)) == counts


@pytest.mark.asyncio
async def test_completion_graph_forged_child_fails_but_copied_carrier_shares_authentic_one_shot():
    db, workflow, stages, attempt, _reservation, locked = await _consumed_completion_case()
    append_reservation = locked.stage_ready_reservation
    assert type(append_reservation) is runtime.StageReadyReservation
    forged_child = replace(append_reservation)
    forged_carrier = replace(locked, stage_ready_reservation=forged_child)
    copied_carrier = replace(locked)
    assert forged_carrier.stage_ready_reservation is forged_child
    assert copied_carrier.stage_ready_reservation is append_reservation
    query_count = len(db.scalar_statements)
    _apply_successful_completion(locked)

    with pytest.raises(runtime.OutboxConflict, match="capability"):
        await runtime.append_reserved_stage_ready(
            db,
            reservation=forged_carrier.stage_ready_reservation,
            workflow=workflow,
            locked_stages=stages,
            causal_attempt=attempt,
        )
    assert len(db.scalar_statements) == query_count
    assert db.added == [] and db.flushes == []

    results = await runtime.append_reserved_stage_ready(
        db,
        reservation=copied_carrier.stage_ready_reservation,
        workflow=workflow,
        locked_stages=stages,
        causal_attempt=attempt,
    )
    assert all(created for _message, created in results)
    with pytest.raises(runtime.OutboxConflict, match="capability"):
        await runtime.append_reserved_stage_ready(
            db,
            reservation=locked.stage_ready_reservation,
            workflow=workflow,
            locked_stages=stages,
            causal_attempt=attempt,
        )


@pytest.mark.asyncio
async def test_completion_graph_transferred_child_mutation_is_spent_before_side_effects():
    db, workflow, stages, attempt, _reservation, locked = await _consumed_completion_case()
    append_reservation = locked.stage_ready_reservation
    assert type(append_reservation) is runtime.StageReadyReservation
    original_ids = append_reservation.message_ids
    object.__setattr__(
        append_reservation,
        "message_ids",
        tuple(uuid.uuid4() for _message_id in original_ids),
    )
    query_count = len(db.scalar_statements)
    _apply_successful_completion(locked)

    with pytest.raises(runtime.OutboxConflict, match="mutated"):
        await runtime.append_reserved_stage_ready(
            db,
            reservation=append_reservation,
            workflow=workflow,
            locked_stages=stages,
            causal_attempt=attempt,
        )
    assert len(db.scalar_statements) == query_count
    assert db.added == [] and db.flushes == []

    object.__setattr__(append_reservation, "message_ids", original_ids)
    with pytest.raises(runtime.OutboxConflict, match="capability"):
        await runtime.append_reserved_stage_ready(
            db,
            reservation=append_reservation,
            workflow=workflow,
            locked_stages=stages,
            causal_attempt=attempt,
        )


@pytest.mark.asyncio
async def test_completion_graph_transferred_child_cannot_cross_session_or_root_transaction():
    db, workflow, stages, attempt, _reservation, locked = await _consumed_completion_case()
    append_reservation = locked.stage_ready_reservation
    assert type(append_reservation) is runtime.StageReadyReservation
    _apply_successful_completion(locked)
    other = _ScriptedDB()

    with pytest.raises(runtime.OutboxConflict, match="capability"):
        await runtime.append_reserved_stage_ready(
            other,
            reservation=append_reservation,
            workflow=workflow,
            locked_stages=stages,
            causal_attempt=attempt,
        )
    assert other.scalar_statements == [] and other.added == [] and other.flushes == []

    original_root = db.root_transaction
    db.root_transaction = object()
    with pytest.raises(runtime.OutboxConflict, match="capability"):
        await runtime.append_reserved_stage_ready(
            db,
            reservation=append_reservation,
            workflow=workflow,
            locked_stages=stages,
            causal_attempt=attempt,
        )
    db.root_transaction = original_root
    assert db.added == [] and db.flushes == []

    results = await runtime.append_reserved_stage_ready(
        db,
        reservation=append_reservation,
        workflow=workflow,
        locked_stages=stages,
        causal_attempt=attempt,
    )
    assert all(created for _message, created in results)


@pytest.mark.asyncio
async def test_completion_graph_transfer_failure_leaves_both_source_fences_spent(
    monkeypatch,
):
    (
        workflow,
        stages,
        source_message,
        source_delivery,
        attempt,
        authority,
        target_messages,
        target_deliveries,
    ) = _completion_receipt_case(target_count=2)
    db = _ScriptedDB(
        scalars=_completion_scalar_script(
            workflow,
            stages,
            source_message,
            source_delivery,
            attempt,
            target_messages,
            target_deliveries,
            consume_clock=NOW + timedelta(microseconds=1),
        )
    )
    reservation = await runtime.reserve_stage_completion_graph(db, authority=authority)
    ready_registrations = dict(runtime._STAGE_READY_RESERVATIONS)

    def fail_transfer(*_args, **_kwargs):
        raise runtime.OutboxConflict("injected completion fan-out transfer failure")

    monkeypatch.setattr(runtime, "_register_transferred_stage_ready_reservation", fail_transfer)
    with pytest.raises(runtime.OutboxConflict, match="injected completion fan-out"):
        await runtime.consume_stage_completion_graph(
            db,
            reservation=reservation,
            authority=authority,
        )

    assert runtime._STAGE_READY_RESERVATIONS == ready_registrations
    assert (id(db), id(db.root_transaction), id(reservation)) not in runtime._STAGE_COMPLETION_RESERVATIONS
    execution_coordinate = runtime._stage_execution_authority_seal(reservation.authority)
    assert runtime._stage_execution_receipt_transaction_fence(
        db,
        db.root_transaction,
    ).coordinates[execution_coordinate] == ("spent", id(reservation))
    fanout_coordinate = runtime._stage_completion_fanout_coordinate(reservation)
    assert runtime._stage_completion_fanout_fence(db, db.root_transaction).coordinates[fanout_coordinate] == (
        "spent",
        id(reservation),
    )
    assert db.added == [] and db.flushes == []
    query_count = len(db.scalar_statements)
    with pytest.raises(runtime.OutboxConflict, match="not registered"):
        await runtime.consume_stage_completion_graph(
            db,
            reservation=reservation,
            authority=authority,
        )
    assert len(db.scalar_statements) == query_count


@pytest.mark.asyncio
async def test_completion_graph_locks_existing_target_message_and_delivery_then_fails_closed():
    case = _completion_receipt_case(target_count=2, existing_active=True)
    workflow, stages, source_message, source_delivery, attempt, authority, messages, deliveries = case
    db = _ScriptedDB(
        scalars=_completion_scalar_script(
            workflow,
            stages,
            source_message,
            source_delivery,
            attempt,
            messages,
            deliveries,
        )
    )

    with pytest.raises(runtime.OutboxStoredContractError, match="already has impossible"):
        await runtime.reserve_stage_completion_graph(db, authority=authority)

    statements = [_compiled(statement) for statement in db.scalar_statements]
    message_lock_start = 2 + len(messages)
    message_lock_end = message_lock_start + 1 + len(messages)
    delivery_lock_end = message_lock_end + 1 + len(deliveries)
    assert all("FOR UPDATE" in item and "FROM outbox_messages" in item for item in statements[message_lock_start:message_lock_end])
    assert all("FOR UPDATE" in item and "FROM outbox_delivery_attempts" in item for item in statements[message_lock_end:delivery_lock_end])
    locked_message_ids = [value.id for value in sorted((source_message, *messages), key=lambda item: item.id.int)]
    locked_delivery_ids = [value.id for value in sorted((source_delivery, *deliveries), key=lambda item: item.id.int)]
    assert locked_message_ids == sorted(locked_message_ids, key=lambda value: value.int)
    assert locked_delivery_ids == sorted(locked_delivery_ids, key=lambda value: value.int)
    assert "FROM stage_attempts" in statements[-2]
    assert "clock_timestamp" in statements[-1]
    assert runtime._STAGE_COMPLETION_RESERVATIONS == {}
    assert db.added == [] and db.flushes == []


@pytest.mark.asyncio
@pytest.mark.parametrize("collection_name", ["new", "dirty", "deleted"])
async def test_completion_graph_rejects_dirty_session_before_sql(collection_name):
    *_, authority, _messages, _deliveries = _completion_receipt_case()
    db = _ScriptedDB()
    getattr(db, collection_name).add(object())

    with pytest.raises(runtime.OutboxConflict, match="entirely clean session"):
        await runtime.reserve_stage_completion_graph(db, authority=authority)

    assert db.scalar_statements == []
    assert db.added == [] and db.flushes == []


@pytest.mark.asyncio
async def test_completion_graph_revalidates_hostile_authority_before_sql():
    *_, authority, _messages, _deliveries = _completion_receipt_case()

    class AuthoritySubclass(runtime.ExecutableStageAuthority):
        pass

    subclass = object.__new__(AuthoritySubclass)
    for name in authority.__dataclass_fields__:
        object.__setattr__(subclass, name, getattr(authority, name))
    forged = object.__new__(runtime.ExecutableStageAuthority)
    for name in authority.__dataclass_fields__:
        object.__setattr__(forged, name, getattr(authority, name))
    object.__setattr__(forged, "cycle_key", "not-a-digest")

    for hostile in (subclass, forged):
        db = _ScriptedDB()
        with pytest.raises(runtime.OutboxValidation):
            await runtime.reserve_stage_completion_graph(db, authority=hostile)
        assert db.scalar_statements == []
        assert db.added == [] and db.flushes == []


@pytest.mark.asyncio
async def test_completion_graph_capability_is_identity_safe_single_use_and_sealed():
    case = _completion_receipt_case()
    workflow, stages, source_message, source_delivery, attempt, authority, messages, deliveries = case
    db = _ScriptedDB(
        scalars=_completion_scalar_script(
            workflow,
            stages,
            source_message,
            source_delivery,
            attempt,
            messages,
            deliveries,
            consume_clock=NOW,
        )
    )
    reservation = await runtime.reserve_stage_completion_graph(db, authority=authority)
    forged = replace(reservation)
    query_count = len(db.scalar_statements)

    with pytest.raises(runtime.OutboxConflict, match="not registered"):
        await runtime.consume_stage_completion_graph(db, reservation=forged, authority=authority)
    assert len(db.scalar_statements) == query_count

    stages[1].checkpoint["tamper"] = True
    with pytest.raises(runtime.OutboxConflict, match="mutated"):
        await runtime.consume_stage_completion_graph(db, reservation=reservation, authority=authority)
    assert len(db.scalar_statements) == query_count
    with pytest.raises(runtime.OutboxConflict, match="not registered"):
        await runtime.consume_stage_completion_graph(db, reservation=reservation, authority=authority)
    assert db.added == [] and db.flushes == []


@pytest.mark.asyncio
async def test_completion_graph_rejects_reservation_subclass_and_stale_authority_without_clock():
    case = _completion_receipt_case()
    workflow, stages, source_message, source_delivery, attempt, authority, messages, deliveries = case
    db = _ScriptedDB(
        scalars=_completion_scalar_script(
            workflow,
            stages,
            source_message,
            source_delivery,
            attempt,
            messages,
            deliveries,
        )
    )
    reservation = await runtime.reserve_stage_completion_graph(db, authority=authority)

    class ReservationSubclass(runtime.StageCompletionReservation):
        pass

    hostile = object.__new__(ReservationSubclass)
    for name in reservation.__dataclass_fields__:
        object.__setattr__(hostile, name, getattr(reservation, name))
    query_count = len(db.scalar_statements)
    with pytest.raises(runtime.OutboxValidation, match="exact stage completion"):
        await runtime.consume_stage_completion_graph(db, reservation=hostile, authority=authority)
    assert len(db.scalar_statements) == query_count

    stale = replace(authority, attempt_state_version=authority.attempt_state_version + 1)
    with pytest.raises(runtime.OutboxLeaseLost, match="changed"):
        await runtime.consume_stage_completion_graph(db, reservation=reservation, authority=stale)
    assert len(db.scalar_statements) == query_count
    with pytest.raises(runtime.OutboxConflict, match="not registered"):
        await runtime.consume_stage_completion_graph(db, reservation=reservation, authority=authority)


@pytest.mark.asyncio
async def test_completion_graph_cannot_cross_session_root_or_savepoint():
    case = _completion_receipt_case()
    workflow, stages, source_message, source_delivery, attempt, authority, messages, deliveries = case
    db = _ScriptedDB(
        scalars=_completion_scalar_script(
            workflow,
            stages,
            source_message,
            source_delivery,
            attempt,
            messages,
            deliveries,
            consume_clock=NOW,
        )
    )
    reservation = await runtime.reserve_stage_completion_graph(db, authority=authority)
    other = _ScriptedDB()
    with pytest.raises(runtime.OutboxConflict, match="not registered"):
        await runtime.consume_stage_completion_graph(other, reservation=reservation, authority=authority)

    original_root = db.root_transaction
    db.root_transaction = object()
    with pytest.raises(runtime.OutboxConflict, match="not registered"):
        await runtime.consume_stage_completion_graph(db, reservation=reservation, authority=authority)
    db.root_transaction = original_root
    db.nested_transaction = object()
    with pytest.raises(runtime.OutboxConflict, match="nested transaction"):
        await runtime.consume_stage_completion_graph(db, reservation=reservation, authority=authority)
    db.nested_transaction = None

    locked = await runtime.consume_stage_completion_graph(db, reservation=reservation, authority=authority)
    assert locked.source_attempt is attempt
    assert other.scalar_statements == []
    assert db.added == [] and db.flushes == []


@pytest.mark.asyncio
async def test_completion_graph_uses_post_lock_clock_and_rejects_expired_source():
    case = _completion_receipt_case()
    workflow, stages, source_message, source_delivery, attempt, authority, messages, deliveries = case
    expired_at = NOW - timedelta(microseconds=1)
    stages[0].lease_expires_at = expired_at
    attempt.lease_expires_at = expired_at
    authority = replace(authority, lease_expires_at=expired_at)
    db = _ScriptedDB(
        scalars=_completion_scalar_script(
            workflow,
            stages,
            source_message,
            source_delivery,
            attempt,
            messages,
            deliveries,
        )
    )

    with pytest.raises(runtime.OutboxLeaseLost, match="no longer live"):
        await runtime.reserve_stage_completion_graph(db, authority=authority)

    statements = [_compiled(item) for item in db.scalar_statements]
    assert "FROM stage_attempts" in statements[-2]
    assert "clock_timestamp" in statements[-1]
    assert runtime._STAGE_COMPLETION_RESERVATIONS == {}
    assert db.added == [] and db.flushes == []


@pytest.mark.asyncio
@pytest.mark.parametrize("future_row", ["target", "successful_dependency"])
async def test_completion_graph_rejects_future_non_source_stage_history(future_row):
    case = _completion_receipt_case(target_count=2)
    workflow, stages, source_message, source_delivery, attempt, authority, messages, deliveries = case
    if future_row == "target":
        stages[1].updated_at = NOW + timedelta(seconds=1)
    else:
        dependency = stages[1]
        target = stages[2]
        dependency.status = "succeeded"
        dependency.state_version = 2
        dependency.attempt_count = 1
        dependency.next_attempt_at = None
        dependency.first_started_at = NOW - timedelta(minutes=3)
        dependency.completed_at = NOW + timedelta(seconds=1)
        dependency.output_manifest = {"ok": True}
        dependency.output_checksum = checksum_json(dependency.output_manifest)
        dependency.updated_at = dependency.completed_at
        target.depends_on = [stages[0].stage_key, dependency.stage_key]
        _bind_plan(workflow, *stages)
        authority = _rebind_execution_plan_authority(
            workflow,
            stages[0],
            source_message,
            source_delivery,
            attempt,
            authority,
        )
        messages = (messages[1],)
        deliveries = (deliveries[1],)
    db = _ScriptedDB(
        scalars=_completion_scalar_script(
            workflow,
            stages,
            source_message,
            source_delivery,
            attempt,
            messages,
            deliveries,
        )
    )

    with pytest.raises(runtime.OutboxStoredContractError, match="future authority"):
        await runtime.reserve_stage_completion_graph(db, authority=authority)

    assert "clock_timestamp" in _compiled(db.scalar_statements[-1])
    assert runtime._STAGE_COMPLETION_RESERVATIONS == {}
    assert db.added == [] and db.flushes == []


@pytest.mark.asyncio
async def test_completion_graph_rejects_duplicate_projected_logical_keys_before_message_discovery(monkeypatch):
    case = _completion_receipt_case(target_count=2)
    workflow, stages, source_message, source_delivery, attempt, authority, _messages, _deliveries = case
    original = runtime._stage_completion_target_projection
    first_projection = None

    def collide(project_workflow, target):
        nonlocal first_projection
        projection = original(project_workflow, target)
        if first_projection is None:
            first_projection = projection
            return projection
        forged = object.__new__(runtime._StageCompletionTargetProjection)
        for name in projection.__dataclass_fields__:
            object.__setattr__(forged, name, getattr(projection, name))
        object.__setattr__(forged, "logical_key", first_projection.logical_key)
        return forged

    monkeypatch.setattr(runtime, "_stage_completion_target_projection", collide)
    db = _ScriptedDB(scalars=[workflow, *stages])

    with pytest.raises(runtime.OutboxStoredContractError, match="collide on one logical"):
        await runtime.reserve_stage_completion_graph(db, authority=authority)

    assert all("FROM outbox_messages" not in _compiled(item) for item in db.scalar_statements)
    assert db.added == [] and db.flushes == []


@pytest.mark.asyncio
async def test_completion_graph_locks_and_rejects_stage_row_outside_canonical_plan():
    case = _completion_receipt_case()
    workflow, stages, _source_message, _source_delivery, _attempt, authority, _messages, _deliveries = case
    rogue = _stage(
        workflow,
        status="pending",
        stage_key="rogue_extra",
        ordinal=99,
        depends_on=[stages[0].stage_key],
    )
    db = _ScriptedDB(scalars=[workflow, *stages, rogue])

    with pytest.raises(runtime.OutboxStoredContractError, match="exact persisted workflow plan"):
        await runtime.reserve_stage_completion_graph(db, authority=authority)

    statements = [_compiled(item) for item in db.scalar_statements]
    assert len(statements) == 2
    assert "FROM workflow_runs" in statements[0] and "FOR UPDATE" in statements[0]
    assert "FROM stage_runs" in statements[1] and "FOR UPDATE" in statements[1]
    assert "ORDER BY stage_runs.ordinal ASC, stage_runs.id ASC" in statements[1]
    assert db.added == [] and db.flushes == []


@pytest.mark.asyncio
async def test_completion_graph_consume_clock_reversal_is_stored_error_and_spent():
    case = _completion_receipt_case()
    workflow, stages, source_message, source_delivery, attempt, authority, messages, deliveries = case
    db = _ScriptedDB(
        scalars=_completion_scalar_script(
            workflow,
            stages,
            source_message,
            source_delivery,
            attempt,
            messages,
            deliveries,
            consume_clock=NOW - timedelta(microseconds=1),
        )
    )
    reservation = await runtime.reserve_stage_completion_graph(db, authority=authority)
    with pytest.raises(runtime.OutboxStoredContractError, match="moved backwards"):
        await runtime.consume_stage_completion_graph(db, reservation=reservation, authority=authority)
    with pytest.raises(runtime.OutboxConflict, match="not registered"):
        await runtime.consume_stage_completion_graph(db, reservation=reservation, authority=authority)
    assert db.added == [] and db.flushes == []


@pytest.mark.asyncio
async def test_completion_graph_is_read_lock_only_and_deep_authority_is_unchanged():
    case = _completion_receipt_case(target_count=2)
    workflow, stages, source_message, source_delivery, attempt, authority, messages, deliveries = case
    authorities = (workflow, *stages, source_message, source_delivery, attempt)
    before = tuple(_snapshot(value) for value in authorities)
    db = _ScriptedDB(
        scalars=_completion_scalar_script(
            workflow,
            stages,
            source_message,
            source_delivery,
            attempt,
            messages,
            deliveries,
            consume_clock=NOW,
        )
    )

    reservation = await runtime.reserve_stage_completion_graph(db, authority=authority)
    await runtime.consume_stage_completion_graph(db, reservation=reservation, authority=authority)

    assert tuple(_snapshot(value) for value in authorities) == before
    assert db.added == []
    assert db.flushes == []
    assert db.commit_calls == 0
    assert all(statement.get_execution_options().get("autoflush") is False for statement in db.scalar_statements)


@pytest.mark.asyncio
async def test_completion_graph_consume_rechecks_expiry_and_spends_capability():
    case = _completion_receipt_case()
    workflow, stages, source_message, source_delivery, attempt, authority, messages, deliveries = case
    after_expiry = authority.lease_expires_at + timedelta(microseconds=1)
    db = _ScriptedDB(
        scalars=_completion_scalar_script(
            workflow,
            stages,
            source_message,
            source_delivery,
            attempt,
            messages,
            deliveries,
            consume_clock=after_expiry,
        )
    )
    reservation = await runtime.reserve_stage_completion_graph(db, authority=authority)

    with pytest.raises(runtime.OutboxLeaseLost, match="no longer live"):
        await runtime.consume_stage_completion_graph(db, reservation=reservation, authority=authority)
    with pytest.raises(runtime.OutboxConflict, match="not registered"):
        await runtime.consume_stage_completion_graph(db, reservation=reservation, authority=authority)
    assert db.added == [] and db.flushes == []


@pytest.mark.asyncio
async def test_completion_and_execution_receipts_share_one_execution_coordinate_fence():
    case = _completion_receipt_case()
    workflow, stages, source_message, source_delivery, attempt, authority, messages, deliveries = case
    db = _ScriptedDB(
        scalars=_completion_scalar_script(
            workflow,
            stages,
            source_message,
            source_delivery,
            attempt,
            messages,
            deliveries,
        )
    )
    await runtime.reserve_stage_completion_graph(db, authority=authority)
    query_count = len(db.scalar_statements)
    db.scalar_values.append(workflow)

    with pytest.raises(runtime.OutboxConflict, match="already reserved"):
        await runtime.reserve_stage_execution_receipt(db, authority=authority)
    assert len(db.scalar_statements) == query_count + 1

    reverse_case = _completion_receipt_case()
    reverse_workflow, reverse_stages, reverse_message, reverse_delivery, reverse_attempt, reverse_authority, _, _ = reverse_case
    reverse_db = _ScriptedDB(scalars=[reverse_workflow, reverse_stages[0], reverse_message, reverse_delivery, reverse_attempt, NOW])
    await runtime.reserve_stage_execution_receipt(reverse_db, authority=reverse_authority)
    reverse_count = len(reverse_db.scalar_statements)
    with pytest.raises(runtime.OutboxConflict, match="already reserved"):
        await runtime.reserve_stage_completion_graph(reverse_db, authority=reverse_authority)
    assert len(reverse_db.scalar_statements) == reverse_count


@pytest.mark.asyncio
async def test_completion_and_stage_ready_reservations_share_one_fanout_fence_both_orders():
    case = _completion_receipt_case()
    workflow, stages, source_message, source_delivery, attempt, authority, messages, deliveries = case
    target = stages[1]
    intent = runtime.project_stage_ready_intent(
        workflow,
        target,
        emission_kind="dependency_ready",
        post_status="ready",
        post_state_version=target.state_version + 1,
        post_next_attempt_at=NOW,
        target_attempt_number=1,
        causal_stage=stages[0],
    )
    completion_db = _ScriptedDB(
        scalars=_completion_scalar_script(
            workflow,
            stages,
            source_message,
            source_delivery,
            attempt,
            messages,
            deliveries,
        )
    )
    await runtime.reserve_stage_completion_graph(completion_db, authority=authority)
    registrations_before = dict(runtime._STAGE_READY_RESERVATIONS)
    completion_db.scalar_values.append(None)
    with pytest.raises(runtime.OutboxConflict, match="fanout was already reserved"):
        await runtime.reserve_stage_ready_intents(
            completion_db,
            workflow=workflow,
            locked_stages=stages,
            target_stages=(target,),
            intents=(intent,),
        )
    assert runtime._STAGE_READY_RESERVATIONS == registrations_before

    reverse_case = _completion_receipt_case()
    reverse_workflow, reverse_stages, reverse_message, reverse_delivery, reverse_attempt, reverse_authority, msgs, ds = reverse_case
    reverse_target = reverse_stages[1]
    reverse_intent = runtime.project_stage_ready_intent(
        reverse_workflow,
        reverse_target,
        emission_kind="dependency_ready",
        post_status="ready",
        post_state_version=reverse_target.state_version + 1,
        post_next_attempt_at=NOW,
        target_attempt_number=1,
        causal_stage=reverse_stages[0],
    )
    reverse_script = _completion_scalar_script(
        reverse_workflow,
        reverse_stages,
        reverse_message,
        reverse_delivery,
        reverse_attempt,
        msgs,
        ds,
    )
    reverse_db = _ScriptedDB(scalars=[None, *reverse_script])
    await runtime.reserve_stage_ready_intents(
        reverse_db,
        workflow=reverse_workflow,
        locked_stages=reverse_stages,
        target_stages=(reverse_target,),
        intents=(reverse_intent,),
    )
    completion_registrations_before = dict(runtime._STAGE_COMPLETION_RESERVATIONS)
    with pytest.raises(runtime.OutboxConflict, match="fanout was already reserved"):
        await runtime.reserve_stage_completion_graph(reverse_db, authority=reverse_authority)
    assert runtime._STAGE_COMPLETION_RESERVATIONS == completion_registrations_before
    assert completion_db.added == reverse_db.added == []
    assert completion_db.flushes == reverse_db.flushes == []


@pytest.mark.asyncio
async def test_completion_graph_rejects_source_target_message_and_delivery_collisions():
    case = _completion_receipt_case()
    workflow, stages, source_message, source_delivery, attempt, authority, messages, deliveries = case
    message_collision_db = _ScriptedDB(scalars=[workflow, *stages, source_message.id])
    with pytest.raises(runtime.OutboxStoredContractError, match="message identities collide"):
        await runtime.reserve_stage_completion_graph(message_collision_db, authority=authority)
    assert all("FROM stage_attempts" not in _compiled(item) for item in message_collision_db.scalar_statements)

    target_message = _message(
        workflow,
        stages[1],
        status="dispatching",
        emission_kind="dependency_ready",
        attempt_count=1,
        state_version=2,
        delivery_id=source_delivery.id,
        causation_id=attempt.id,
    )
    target_message.aggregate_version = stages[1].state_version + 1
    messages_by_id = sorted((source_message, target_message), key=lambda item: item.id.int)
    delivery_collision_db = _ScriptedDB(scalars=[workflow, *stages, target_message.id, *messages_by_id])
    with pytest.raises(runtime.OutboxStoredContractError, match="delivery identities collide"):
        await runtime.reserve_stage_completion_graph(delivery_collision_db, authority=authority)
    assert all("FROM stage_attempts" not in _compiled(item) for item in delivery_collision_db.scalar_statements)
    assert message_collision_db.added == delivery_collision_db.added == []
    assert message_collision_db.flushes == delivery_collision_db.flushes == []


def test_locked_completion_graph_is_not_accepted_by_any_runtime_mutator():
    accepting = []
    for name, value in vars(runtime).items():
        if not callable(value) or name in {"LockedStageCompletionGraph"}:
            continue
        try:
            annotation = inspect.signature(value).parameters
        except (TypeError, ValueError):
            continue
        if any(parameter.annotation is runtime.LockedStageCompletionGraph for parameter in annotation.values()):
            accepting.append(name)
    assert accepting == []
    assert ".flush(" not in inspect.getsource(runtime.reserve_stage_completion_graph)
    assert ".flush(" not in inspect.getsource(runtime.consume_stage_completion_graph)
    assert ".add(" not in inspect.getsource(runtime.reserve_stage_completion_graph)
    assert ".add(" not in inspect.getsource(runtime.consume_stage_completion_graph)


def test_receipt_runtime_has_no_local_clock_or_commit_escape_hatch():
    source = inspect.getsource(runtime)
    assert "datetime.now(" not in source
    assert "datetime.utcnow(" not in source
    assert "time.time(" not in source
    assert ".commit(" not in source
    assert "_db_clock_now" in inspect.getsource(runtime.receipt_and_claim_stage)
    assert "clock_timestamp" in source


def _failure_case(
    *,
    retryable: bool,
    required: bool = True,
    target_count: int = 0,
):
    (
        workflow,
        stages,
        source_message,
        source_delivery,
        attempt,
        authority,
        _target_messages,
        _target_deliveries,
    ) = _completion_receipt_case(target_count=target_count)
    source = stages[0]
    if source.required != required:
        source.required = required
        _bind_plan(workflow, *stages)
        authority = _rebind_execution_plan_authority(
            workflow,
            source,
            source_message,
            source_delivery,
            attempt,
            authority,
        )
    evidence = runtime.StageFailureEvidence(
        code="provider.failure",
        error_class="ExternalError",
        summary="Provider request failed",
        retryable=retryable,
    )
    return workflow, stages, source_message, source_delivery, attempt, authority, evidence


def _failure_retry_script(
    workflow,
    stages,
    source_message,
    source_delivery,
    attempt,
    *,
    consume_at=NOW + timedelta(microseconds=1),
):
    return [
        workflow,
        *stages,
        None,
        source_message,
        source_delivery,
        attempt,
        NOW,
        NOW,
        consume_at,
    ]


def _failure_terminal_script(
    workflow,
    stages,
    source_message,
    source_delivery,
    attempt,
    *,
    required: bool,
    live_messages=(),
    active_deliveries=(),
    transaction_at=NOW,
    reserve_clock=NOW,
    consume_at=NOW + timedelta(microseconds=1),
):
    values = [workflow, *stages]
    if required:
        running = tuple(stage for stage in stages if stage.status == "running")
        attempts = (attempt,)
        assert len(running) == len(attempts) == 1
        for current_attempt in attempts:
            values.extend(
                (
                    current_attempt.id,
                    current_attempt.outbox_delivery_attempt_id,
                    source_message.id,
                )
            )
    messages = tuple(sorted((source_message, *live_messages), key=lambda item: item.id.int))
    deliveries = tuple(sorted((source_delivery, *active_deliveries), key=lambda item: item.id.int))
    values.extend((*messages, *deliveries, attempt, transaction_at, reserve_clock, consume_at))
    return values


def test_stage_failure_evidence_is_exact_sanitizer_fixed_point():
    exact = runtime.StageFailureEvidence(
        code="provider.failure",
        error_class="ExternalError",
        summary="Provider request failed",
        retryable=True,
    )
    assert exact.summary == "Provider request failed"
    with pytest.raises(runtime.OutboxValidation, match="sanitizer fixed point"):
        runtime.StageFailureEvidence(
            code="provider.failure",
            error_class="ExternalError",
            summary="password=hunter2 Bearer abc.def.ghi",
            retryable=True,
        )
    with pytest.raises(runtime.OutboxValidation):
        runtime.StageFailureEvidence(
            code="workflow.forged",
            error_class="ExternalError",
            summary="forged runtime failure",
            retryable=False,
        )
    with pytest.raises(runtime.OutboxValidation):
        runtime.StageFailureEvidence(
            code="provider.failure",
            error_class="ExternalError",
            summary="control\x00value",
            retryable=False,
        )


@pytest.mark.asyncio
async def test_failure_retry_reserves_consumes_and_transfers_exact_stage_ready_child():
    workflow, stages, message, delivery, attempt, authority, evidence = _failure_case(retryable=True)
    db = _ScriptedDB(
        scalars=_failure_retry_script(
            workflow,
            stages,
            message,
            delivery,
            attempt,
        )
    )
    reservation = await runtime.reserve_stage_failure_graph(
        db,
        authority=authority,
        evidence=evidence,
    )
    assert reservation.decision == "retry"
    assert reservation.retry_projection is not None
    assert reservation.retry_message_id is not None
    assert db.added == db.flushes == []

    locked = await runtime.consume_stage_failure_graph(
        db,
        reservation=reservation,
        authority=authority,
        evidence=evidence,
    )
    assert locked.decision == "retry"
    assert locked.retry_intent is not None
    assert locked.next_attempt_at == locked.observed_at + timedelta(seconds=locked.retry_delay_seconds)
    assert type(locked.stage_ready_reservation) is runtime.StageReadyReservation
    assert locked.outbox_cancellation_reservation is None
    assert locked.stage_ready_reservation.message_ids == (locked.retry_message_id,)
    assert locked.stage_ready_reservation.intents == (locked.retry_intent,)
    assert db.added == db.flushes == []


@pytest.mark.asyncio
async def test_failure_after_native_recovery_classifies_old_authority_stale_before_retry_projection():
    workflow, stages, message, delivery, attempt, authority, evidence = _failure_case(retryable=True)
    source = stages[0]
    source.status = "retry_wait"
    source.state_version += 1
    source.next_attempt_at = NOW
    source.lease_owner = ""
    source.lease_token = None
    source.leased_at = None
    source.lease_expires_at = None
    source.heartbeat_at = None
    source.last_error_code = "workflow.lease_expired"
    source.last_error_summary = "Worker lease expired"
    source.last_error_retryable = True
    db = _ScriptedDB(scalars=(workflow, *stages))

    with pytest.raises(runtime.OutboxLeaseLost, match="source authority"):
        await runtime.reserve_stage_failure_graph(
            db,
            authority=authority,
            evidence=evidence,
        )

    assert len(db.scalar_statements) == 2
    assert "FROM workflow_runs" in _compiled(db.scalar_statements[0])
    assert "FROM stage_runs" in _compiled(db.scalar_statements[1])
    assert not any("FROM outbox_messages" in _compiled(statement) for statement in db.scalar_statements)
    assert db.added == db.flushes == []


@pytest.mark.asyncio
async def test_required_terminal_zero_live_suffix_transfers_one_shot_empty_cancellation():
    workflow, stages, message, delivery, attempt, authority, evidence = _failure_case(retryable=False)
    db = _ScriptedDB(
        scalars=_failure_terminal_script(
            workflow,
            stages,
            message,
            delivery,
            attempt,
            required=True,
        ),
        executes=(None, ()),
    )
    reservation = await runtime.reserve_stage_failure_graph(
        db,
        authority=authority,
        evidence=evidence,
    )
    locked = await runtime.consume_stage_failure_graph(
        db,
        reservation=reservation,
        authority=authority,
        evidence=evidence,
    )
    child = locked.outbox_cancellation_reservation
    assert locked.decision == "failed"
    assert type(child) is runtime.OutboxCancellationReservation
    assert child.messages == child.deliveries == ()
    assert await runtime.cancel_reserved_outbox_messages(db, reservation=child) == ((), ())
    with pytest.raises(runtime.OutboxConflict, match="not registered"):
        await runtime.cancel_reserved_outbox_messages(db, reservation=child)
    assert db.flushes == []


@pytest.mark.asyncio
async def test_optional_terminal_has_no_child_and_degrades_when_all_terminal():
    workflow, stages, message, delivery, attempt, authority, evidence = _failure_case(
        retryable=False,
        required=False,
    )
    db = _ScriptedDB(
        scalars=_failure_terminal_script(
            workflow,
            stages,
            message,
            delivery,
            attempt,
            required=False,
        )
    )
    reservation = await runtime.reserve_stage_failure_graph(db, authority=authority, evidence=evidence)
    locked = await runtime.consume_stage_failure_graph(
        db,
        reservation=reservation,
        authority=authority,
        evidence=evidence,
    )
    assert locked.decision == "failed"
    assert locked.settlement.workflow_post_status == "degraded"
    assert locked.stage_ready_reservation is None
    assert locked.outbox_cancellation_reservation is None
    assert db.flushes == []


@pytest.mark.asyncio
async def test_required_terminal_cancels_exact_active_suffix_delivery_then_message():
    workflow, stages, source_message, source_delivery, attempt, authority, evidence = _failure_case(
        retryable=False,
        target_count=1,
    )
    target = stages[1]
    target.status = "ready"
    target.state_version += 1
    target.next_attempt_at = NOW
    target.updated_at = NOW - timedelta(seconds=20)
    active_id = uuid.uuid4()
    token = uuid.uuid4()
    active_message = _message(
        workflow,
        target,
        status="dispatching",
        emission_kind="dependency_ready",
        attempt_count=1,
        state_version=2,
        delivery_id=active_id,
        token=token,
        causation_id=attempt.id,
    )
    active_delivery = _delivery_for_message(active_message)
    db = _ScriptedDB(
        scalars=_failure_terminal_script(
            workflow,
            stages,
            source_message,
            source_delivery,
            attempt,
            required=True,
            live_messages=(active_message,),
            active_deliveries=(active_delivery,),
        ),
        executes=(None, (active_message.id,)),
    )
    reservation = await runtime.reserve_stage_failure_graph(db, authority=authority, evidence=evidence)
    locked = await runtime.consume_stage_failure_graph(
        db,
        reservation=reservation,
        authority=authority,
        evidence=evidence,
    )
    child = locked.outbox_cancellation_reservation
    assert type(child) is runtime.OutboxCancellationReservation
    assert child.message_ids == (active_message.id,)
    assert child.delivery_ids == (active_delivery.id,)
    deliveries, messages = await runtime.cancel_reserved_outbox_messages(db, reservation=child)
    assert deliveries == (active_delivery,)
    assert messages == (active_message,)
    assert [flush[0]["id"] for flush in db.flushes] == [active_delivery.id, active_message.id]
    assert active_delivery.status == "cancelled"
    assert active_delivery.error_code == "workflow.required_stage_failed"
    assert active_delivery.error_class == "WorkflowCancelled"
    assert active_delivery.error_summary == "Workflow stopped after a required stage failed"
    assert not active_delivery.retryable
    assert active_message.status == "cancelled"
    assert active_message.cancelled_by == "AdversaryGraph workflow runtime"
    assert active_message.cancelled_by_id == "workflow.runtime"
    assert active_message.cancel_reason == "Workflow stopped after a required stage failed"
    assert active_message.last_error_code == ""


@pytest.mark.asyncio
async def test_required_terminal_rejects_publisher_suffix_newer_than_transaction_before_registration():
    workflow, stages, source_message, source_delivery, attempt, authority, evidence = _failure_case(
        retryable=False,
        target_count=1,
    )
    target = stages[1]
    target.status = "ready"
    target.state_version += 1
    target.next_attempt_at = NOW
    target.updated_at = NOW
    active_id = uuid.uuid4()
    active_message = _message(
        workflow,
        target,
        status="dispatching",
        emission_kind="dependency_ready",
        attempt_count=1,
        state_version=2,
        delivery_id=active_id,
        causation_id=attempt.id,
    )
    active_delivery = _delivery_for_message(active_message)
    publisher_at = NOW + timedelta(seconds=1)
    active_message.created_at = publisher_at
    active_message.updated_at = publisher_at
    active_delivery.created_at = publisher_at
    active_delivery.updated_at = publisher_at
    active_delivery.leased_at = publisher_at
    active_delivery.heartbeat_at = publisher_at
    active_delivery.lease_expires_at = publisher_at + timedelta(minutes=1)
    active_message.leased_at = publisher_at
    active_message.heartbeat_at = publisher_at
    active_message.lease_expires_at = publisher_at + timedelta(minutes=1)
    db = _ScriptedDB(
        scalars=_failure_terminal_script(
            workflow,
            stages,
            source_message,
            source_delivery,
            attempt,
            required=True,
            live_messages=(active_message,),
            active_deliveries=(active_delivery,),
            transaction_at=NOW,
            reserve_clock=publisher_at + timedelta(seconds=1),
        )[:-1],
        executes=(None, (active_message.id,)),
    )
    registrations = dict(runtime._STAGE_FAILURE_RESERVATIONS)
    with pytest.raises(runtime.OutboxConflict, match="retry in a fresh transaction"):
        await runtime.reserve_stage_failure_graph(db, authority=authority, evidence=evidence)
    assert runtime._STAGE_FAILURE_RESERVATIONS == registrations
    assert db.added == db.flushes == []


@pytest.mark.parametrize("field_name", ["redrive_requested_at", "leased_at", "heartbeat_at"])
@pytest.mark.parametrize("phase", ["reserve", "consume"])
@pytest.mark.asyncio
async def test_required_terminal_rejects_each_newer_message_history_field_at_reserve_and_consume(
    field_name,
    phase,
):
    workflow, stages, source_message, source_delivery, attempt, authority, evidence = _failure_case(
        retryable=False,
        target_count=1,
    )
    target = stages[1]
    target.status = "ready"
    target.state_version += 1
    target.next_attempt_at = NOW
    target.updated_at = NOW
    active_id = uuid.uuid4()
    active_message = _message(
        workflow,
        target,
        status="dispatching",
        emission_kind="dependency_ready",
        attempt_count=1,
        state_version=2,
        delivery_id=active_id,
        causation_id=attempt.id,
    )
    active_delivery = _delivery_for_message(active_message)
    publisher_at = NOW + timedelta(seconds=1)
    consume_at = publisher_at + timedelta(seconds=1)
    db = _ScriptedDB(
        scalars=_failure_terminal_script(
            workflow,
            stages,
            source_message,
            source_delivery,
            attempt,
            required=True,
            live_messages=(active_message,),
            active_deliveries=(active_delivery,),
            transaction_at=NOW,
            reserve_clock=NOW,
            consume_at=consume_at,
        ),
        executes=(None, (active_message.id,)),
    )

    def make_newer() -> None:
        setattr(active_message, field_name, publisher_at)
        if field_name == "leased_at":
            active_message.heartbeat_at = publisher_at
            active_message.lease_expires_at = publisher_at + timedelta(minutes=1)
            active_delivery.leased_at = publisher_at
            active_delivery.heartbeat_at = publisher_at
            active_delivery.lease_expires_at = publisher_at + timedelta(minutes=1)
        elif field_name == "heartbeat_at":
            active_delivery.heartbeat_at = publisher_at

    if phase == "reserve":
        make_newer()
        registrations = dict(runtime._STAGE_FAILURE_RESERVATIONS)
        with pytest.raises(runtime.OutboxConflict, match="retry in a fresh transaction"):
            await runtime.reserve_stage_failure_graph(db, authority=authority, evidence=evidence)
        assert runtime._STAGE_FAILURE_RESERVATIONS == registrations
    else:
        reservation = await runtime.reserve_stage_failure_graph(db, authority=authority, evidence=evidence)
        make_newer()
        with pytest.raises(runtime.OutboxConflict, match="mutated"):
            await runtime.consume_stage_failure_graph(
                db,
                reservation=reservation,
                authority=authority,
                evidence=evidence,
            )
        with pytest.raises(runtime.OutboxConflict, match="not registered"):
            await runtime.consume_stage_failure_graph(
                db,
                reservation=reservation,
                authority=authority,
                evidence=evidence,
            )
    assert db.added == db.flushes == []


@pytest.mark.asyncio
async def test_failure_capability_is_sealed_single_use_and_shares_execution_coordinate():
    workflow, stages, message, delivery, attempt, authority, evidence = _failure_case(retryable=True)
    db = _ScriptedDB(scalars=_failure_retry_script(workflow, stages, message, delivery, attempt))
    reservation = await runtime.reserve_stage_failure_graph(db, authority=authority, evidence=evidence)
    sql_count = len(db.scalar_statements)
    with pytest.raises(runtime.OutboxConflict, match="already reserved"):
        await runtime.reserve_stage_execution_receipt(db, authority=authority)
    # The older phase-1 primitive takes W before consulting the shared fence;
    # it must stop there and never reach S/M/D/A.
    assert len(db.scalar_statements) == sql_count + 1
    forged = replace(reservation)
    with pytest.raises(runtime.OutboxConflict, match="not registered"):
        await runtime.consume_stage_failure_graph(
            db,
            reservation=forged,
            authority=authority,
            evidence=evidence,
        )
    object.__setattr__(reservation, "retry_message_id", uuid.uuid4())
    with pytest.raises(runtime.OutboxConflict, match="mutated"):
        await runtime.consume_stage_failure_graph(
            db,
            reservation=reservation,
            authority=authority,
            evidence=evidence,
        )
    with pytest.raises(runtime.OutboxConflict, match="not registered"):
        await runtime.consume_stage_failure_graph(
            db,
            reservation=reservation,
            authority=authority,
            evidence=evidence,
        )
    assert db.added == db.flushes == []


@pytest.mark.asyncio
async def test_optional_failure_settlement_skips_descendants_without_ready_repair():
    workflow, stages, message, delivery, attempt, authority, evidence = _failure_case(
        retryable=False,
        required=False,
        target_count=1,
    )
    db = _ScriptedDB(
        scalars=_failure_terminal_script(
            workflow,
            stages,
            message,
            delivery,
            attempt,
            required=False,
        )
    )
    reservation = await runtime.reserve_stage_failure_graph(db, authority=authority, evidence=evidence)
    assert reservation.settlement.post_stage_statuses == ("failed", "skipped")
    assert reservation.settlement.skipped_stage_ids == (stages[1].id,)


def test_locked_failure_graph_is_not_accepted_by_any_runtime_mutator():
    accepting = []
    for name, value in vars(runtime).items():
        if not callable(value) or name == "LockedStageFailureGraph":
            continue
        try:
            parameters = inspect.signature(value).parameters
        except (TypeError, ValueError):
            continue
        if any(parameter.annotation is runtime.LockedStageFailureGraph for parameter in parameters.values()):
            accepting.append(name)
    assert accepting == []
    for function in (
        runtime.reserve_stage_failure_graph,
        runtime.consume_stage_failure_graph,
    ):
        source = inspect.getsource(function)
        assert ".flush(" not in source
        assert ".add(" not in source
        assert ".commit(" not in source


def _explicit_cancellation_case(*, active_delivery: bool = False):
    workflow = _workflow(status="running")
    workflow.started_at = NOW - timedelta(minutes=4)
    workflow.completed_at = None
    workflow.created_at = NOW - timedelta(minutes=5)
    workflow.updated_at = NOW - timedelta(minutes=1)
    workflow.cancel_requested_by = ""
    workflow.cancel_requested_by_id = ""
    workflow.cancel_reason = ""
    workflow.cancel_requested_at = None
    workflow.cancel_request_id = None
    stage = _stage(workflow, status="ready", state_version=1)
    _bind_plan(workflow, stage)
    delivery = None
    if active_delivery:
        delivery_id = uuid.uuid4()
        token = uuid.uuid4()
        message = _message(
            workflow,
            stage,
            status="dispatching",
            attempt_count=1,
            state_version=2,
            delivery_id=delivery_id,
            token=token,
        )
        delivery = _delivery_for_message(message)
    else:
        message = _message(workflow, stage, status="pending")
    command = runtime.WorkflowCancellationCommand(
        request_id=uuid.uuid4(),
        workflow_run_id=workflow.id,
        expected_workflow_state_version=workflow.state_version,
        actor="incident commander",
        actor_id="user-42",
        reason="Operator stopped this workflow",
    )
    return workflow, (stage,), message, delivery, command


def _explicit_cancellation_script(
    workflow,
    stages,
    message,
    delivery,
    *,
    consume_at=NOW + timedelta(microseconds=1),
):
    scalars = [workflow, *stages, message]
    if delivery is not None:
        scalars.append(delivery)
    scalars.extend((NOW, NOW, consume_at))
    executes = (None, (), (message.id,))
    return scalars, executes


@pytest.mark.asyncio
async def test_explicit_cancellation_reserves_full_graph_and_transfers_query_free_child():
    workflow, stages, message, delivery, command = _explicit_cancellation_case(active_delivery=True)
    scalars, executes = _explicit_cancellation_script(
        workflow,
        stages,
        message,
        delivery,
    )
    db = _ScriptedDB(scalars=scalars, executes=executes)

    reservation = await runtime.reserve_workflow_terminalization_graph(
        db,
        command=command,
    )
    assert reservation.decision == "apply"
    assert reservation.locked_message_ids == (message.id,)
    assert reservation.locked_delivery_ids == (delivery.id,)
    assert reservation.locked_attempt_ids == ()
    assert reservation.projection.post_stage_statuses == ("cancelled",)
    assert db.added == db.flushes == []

    locked = await runtime.consume_workflow_terminalization_graph(
        db,
        reservation=reservation,
        command=command,
    )
    child = locked.outbox_cancellation_reservation
    assert type(child) is runtime.OutboxCancellationReservation
    assert child.error_code == "workflow.cancelled"
    assert child.cancelled_by == command.actor
    assert child.cancelled_by_id == command.actor_id
    assert child.cancel_reason == command.reason
    query_count = len(db.scalar_statements)
    deliveries, messages = await runtime.cancel_reserved_outbox_messages(
        db,
        reservation=child,
    )
    assert len(db.scalar_statements) == query_count
    assert deliveries == (delivery,) and messages == (message,)
    assert [items[0]["id"] for items in db.flushes] == [delivery.id, message.id]
    with pytest.raises(runtime.OutboxConflict, match="not registered"):
        await runtime.cancel_reserved_outbox_messages(db, reservation=child)


@pytest.mark.asyncio
async def test_explicit_cancellation_lock_order_is_w_all_s_m_d_a_then_clocks():
    workflow, stages, message, delivery, command = _explicit_cancellation_case(active_delivery=True)
    scalars, executes = _explicit_cancellation_script(
        workflow,
        stages,
        message,
        delivery,
    )
    db = _ScriptedDB(scalars=scalars[:-1], executes=executes)

    await runtime.reserve_workflow_terminalization_graph(db, command=command)
    statements = [_compiled(value) for value in db.scalar_statements]
    assert "FROM workflow_runs" in statements[0] and "FOR UPDATE" in statements[0]
    assert "FROM stage_runs" in statements[1] and "FOR UPDATE" in statements[1]
    assert "ORDER BY stage_runs.ordinal ASC, stage_runs.id ASC" in statements[1]
    assert "FROM stage_attempts" in statements[2] and "FOR UPDATE" not in statements[2]
    assert "FROM outbox_messages" in statements[3] and "FOR UPDATE" not in statements[3]
    assert "FROM outbox_messages" in statements[4] and "FOR UPDATE" in statements[4]
    assert "FROM outbox_delivery_attempts" in statements[5] and "FOR UPDATE" in statements[5]
    assert "transaction_timestamp" in statements[-2]
    assert "clock_timestamp" in statements[-1]
    assert db.added == db.flushes == []


@pytest.mark.asyncio
async def test_explicit_cancellation_replay_is_exact_and_has_no_child():
    workflow, stages, _message, _delivery, command = _explicit_cancellation_case()
    workflow.status = "cancelled"
    workflow.state_version = command.expected_workflow_state_version + 1
    workflow.cancel_request_id = command.request_id
    workflow.cancel_requested_by = command.actor
    workflow.cancel_requested_by_id = command.actor_id
    workflow.cancel_reason = command.reason
    workflow.cancel_requested_at = NOW - timedelta(seconds=5)
    workflow.completed_at = workflow.cancel_requested_at
    workflow.updated_at = workflow.completed_at
    stage = stages[0]
    stage.status = "cancelled"
    stage.state_version += 1
    stage.next_attempt_at = None
    stage.completed_at = workflow.completed_at
    stage.updated_at = workflow.completed_at
    db = _ScriptedDB(
        scalars=(workflow, stage, NOW, NOW, NOW + timedelta(microseconds=1)),
        executes=(None, (), ()),
    )

    reservation = await runtime.reserve_workflow_terminalization_graph(db, command=command)
    assert reservation.decision == "replay"
    locked = await runtime.consume_workflow_terminalization_graph(
        db,
        reservation=reservation,
        command=command,
    )
    assert locked.decision == "replay"
    assert locked.outbox_cancellation_reservation is None
    assert locked.projection.cancelled_stage_ids == ()
    assert db.added == db.flushes == []

    for hostile in (
        replace(command, request_id=uuid.uuid4()),
        replace(command, actor="different actor"),
        replace(command, actor_id="different-id"),
        replace(command, reason="Different cancellation reason"),
        replace(
            command,
            expected_workflow_state_version=command.expected_workflow_state_version - 1,
        ),
    ):
        hostile_db = _ScriptedDB(scalars=(workflow,))
        with pytest.raises(runtime.OutboxConflict):
            await runtime.reserve_workflow_terminalization_graph(
                hostile_db,
                command=hostile,
            )


@pytest.mark.asyncio
async def test_cancellation_command_and_clean_session_are_validated_before_sql():
    workflow, _stages, _message, _delivery, command = _explicit_cancellation_case()

    class CommandSubclass(runtime.WorkflowCancellationCommand):
        pass

    subclass = object.__new__(CommandSubclass)
    for name in command.__dataclass_fields__:
        object.__setattr__(subclass, name, getattr(command, name))
    empty_actor_id = object.__new__(runtime.WorkflowCancellationCommand)
    nul_reason = object.__new__(runtime.WorkflowCancellationCommand)
    for hostile, changed_name, changed_value in (
        (empty_actor_id, "actor_id", ""),
        (nul_reason, "reason", "bad\x00reason"),
    ):
        for name in command.__dataclass_fields__:
            object.__setattr__(
                hostile,
                name,
                changed_value if name == changed_name else getattr(command, name),
            )
    for hostile in (
        subclass,
        empty_actor_id,
        nul_reason,
    ):
        db = _ScriptedDB()
        with pytest.raises(runtime.OutboxValidation):
            await runtime.reserve_workflow_terminalization_graph(db, command=hostile)
        assert db.scalar_statements == []

    dirty = _ScriptedDB()
    dirty.dirty.add(workflow)
    with pytest.raises(runtime.OutboxConflict, match="entirely clean session"):
        await runtime.reserve_workflow_terminalization_graph(dirty, command=command)
    assert dirty.scalar_statements == []


@pytest.mark.asyncio
async def test_terminalization_capability_is_identity_safe_sealed_and_single_use():
    workflow, stages, message, delivery, command = _explicit_cancellation_case()
    scalars, executes = _explicit_cancellation_script(
        workflow,
        stages,
        message,
        delivery,
    )
    db = _ScriptedDB(scalars=scalars, executes=executes)
    reservation = await runtime.reserve_workflow_terminalization_graph(db, command=command)
    forged = replace(reservation)
    query_count = len(db.scalar_statements)
    with pytest.raises(runtime.OutboxConflict, match="not registered"):
        await runtime.consume_workflow_terminalization_graph(
            db,
            reservation=forged,
            command=command,
        )
    assert len(db.scalar_statements) == query_count
    stages[0].checkpoint["tamper"] = True
    with pytest.raises(runtime.OutboxConflict, match="mutated"):
        await runtime.consume_workflow_terminalization_graph(
            db,
            reservation=reservation,
            command=command,
        )
    with pytest.raises(runtime.OutboxConflict, match="not registered"):
        await runtime.consume_workflow_terminalization_graph(
            db,
            reservation=reservation,
            command=command,
        )


def _expired_recovery_case(*, exhausted: bool = False):
    workflow, stage, message, delivery, attempt, authority = _execution_receipt_case()
    if exhausted:
        stage.max_attempts = stage.attempt_count
        _bind_plan(workflow, stage)
        authority = _rebind_execution_plan_authority(
            workflow,
            stage,
            message,
            delivery,
            attempt,
            authority,
        )
    expired_at = NOW - timedelta(seconds=1)
    stage.lease_expires_at = expired_at
    attempt.lease_expires_at = expired_at
    authority = replace(authority, lease_expires_at=expired_at)
    return workflow, (stage,), message, delivery, attempt, authority


def _recovery_retry_script(workflow, stages, message, delivery, attempt, *, consume=True):
    values = [
        workflow,
        *stages,
        attempt.id,
        delivery.id,
        message.id,
        None,
        message,
        delivery,
        attempt,
        NOW,
        NOW,
    ]
    if consume:
        values.append(NOW + timedelta(microseconds=1))
    return values


@pytest.mark.asyncio
async def test_expired_recovery_retry_locks_exact_delivered_receipt_and_transfers_child():
    workflow, stages, message, delivery, attempt, _authority = _expired_recovery_case()
    db = _ScriptedDB(scalars=_recovery_retry_script(workflow, stages, message, delivery, attempt))

    reservation = await runtime.reserve_one_expired_stage_recovery(db)
    assert type(reservation) is runtime.StageRecoveryReservation
    assert reservation.decision == "retry"
    assert reservation.source_authority.message_id == message.id
    assert reservation.source_authority.delivery_attempt_id == delivery.id
    assert reservation.source_authority.stage_attempt_id == attempt.id
    assert reservation.locked_message_ids == (message.id,)
    assert reservation.locked_delivery_ids == (delivery.id,)
    assert reservation.locked_attempt_ids == (attempt.id,)
    assert db.added == db.flushes == []

    locked = await runtime.consume_stage_recovery_graph(db, reservation=reservation)
    assert locked.decision == "retry"
    assert locked.retry_intent.emission_kind == "lease_recovered"
    assert locked.retry_intent.post_target.last_error_code == "workflow.lease_expired"
    assert locked.next_attempt_at > locked.observed_at
    assert type(locked.stage_ready_reservation) is runtime.StageReadyReservation
    assert locked.outbox_cancellation_reservation is None
    with pytest.raises(runtime.OutboxConflict, match="not registered"):
        await runtime.consume_stage_recovery_graph(db, reservation=reservation)


@pytest.mark.asyncio
async def test_expired_recovery_retry_query_order_is_w_s_union_m_union_d_a_then_clocks():
    workflow, stages, message, delivery, attempt, _authority = _expired_recovery_case()
    db = _ScriptedDB(
        scalars=_recovery_retry_script(
            workflow,
            stages,
            message,
            delivery,
            attempt,
            consume=False,
        )
    )
    await runtime.reserve_one_expired_stage_recovery(db)
    statements = [_compiled(value) for value in db.scalar_statements]
    assert "SKIP LOCKED" in statements[0] and "FROM workflow_runs" in statements[0]
    assert "FROM stage_runs" in statements[1] and "FOR UPDATE" in statements[1]
    assert all("FOR UPDATE" not in value for value in statements[2:6])
    assert "FROM outbox_messages" in statements[6] and "FOR UPDATE" in statements[6]
    assert "FROM outbox_delivery_attempts" in statements[7] and "FOR UPDATE" in statements[7]
    assert "FROM stage_attempts" in statements[8] and "FOR UPDATE" in statements[8]
    assert "transaction_timestamp" in statements[9]
    assert "clock_timestamp" in statements[10]
    assert db.added == db.flushes == []


@pytest.mark.asyncio
async def test_expired_recovery_requires_nonnull_delivered_receipt_link():
    workflow, stages, _message, _delivery, attempt, _authority = _expired_recovery_case()
    db = _ScriptedDB(scalars=(workflow, *stages, attempt.id, None))
    registrations = dict(runtime._STAGE_RECOVERY_RESERVATIONS)
    with pytest.raises(runtime.OutboxStoredContractError, match="no receipt delivery"):
        await runtime.reserve_one_expired_stage_recovery(db)
    assert runtime._STAGE_RECOVERY_RESERVATIONS == registrations
    assert db.added == db.flushes == []


@pytest.mark.asyncio
async def test_exhausted_required_recovery_transfers_empty_terminalization_child_query_free():
    workflow, stages, message, delivery, attempt, _authority = _expired_recovery_case(exhausted=True)
    db = _ScriptedDB(
        scalars=(
            workflow,
            *stages,
            delivery.id,
            message.id,
            message,
            delivery,
            attempt,
            NOW,
            NOW,
            NOW + timedelta(microseconds=1),
        ),
        executes=(None, (attempt.id,), ()),
    )
    reservation = await runtime.reserve_one_expired_stage_recovery(db)
    assert type(reservation) is runtime.StageRecoveryReservation
    assert reservation.decision == "dead_lettered"
    locked = await runtime.consume_stage_recovery_graph(db, reservation=reservation)
    child = locked.outbox_cancellation_reservation
    assert type(child) is runtime.OutboxCancellationReservation
    assert child.messages == child.deliveries == ()
    query_count = len(db.scalar_statements)
    assert await runtime.cancel_reserved_outbox_messages(db, reservation=child) == ((), ())
    assert len(db.scalar_statements) == query_count
    assert db.added == db.flushes == []


@pytest.mark.asyncio
async def test_empty_recovery_sweep_consumes_one_root_transaction_slot():
    db = _ScriptedDB(scalars=(None,))
    assert await runtime.reserve_one_expired_stage_recovery(db) is None
    query_count = len(db.scalar_statements)
    with pytest.raises(runtime.OutboxConflict, match="Only one expired stage recovery"):
        await runtime.reserve_one_expired_stage_recovery(db)
    assert len(db.scalar_statements) == query_count
    fence = db.info[runtime._STAGE_RECOVERY_SWEEP_FENCE_INFO_KEY]
    assert fence.state == "spent" and fence.reservation_id is None


@pytest.mark.asyncio
async def test_recovery_capability_is_identity_bound_sealed_and_cannot_cross_root():
    workflow, stages, message, delivery, attempt, _authority = _expired_recovery_case()
    db = _ScriptedDB(scalars=_recovery_retry_script(workflow, stages, message, delivery, attempt))
    reservation = await runtime.reserve_one_expired_stage_recovery(db)
    forged = replace(reservation)
    with pytest.raises(runtime.OutboxConflict, match="not registered"):
        await runtime.consume_stage_recovery_graph(db, reservation=forged)
    original_root = db.root_transaction
    db.root_transaction = object()
    with pytest.raises(runtime.OutboxConflict, match="not registered"):
        await runtime.consume_stage_recovery_graph(db, reservation=reservation)
    db.root_transaction = original_root
    stages[0].checkpoint["tamper"] = True
    with pytest.raises(runtime.OutboxConflict, match="mutated"):
        await runtime.consume_stage_recovery_graph(db, reservation=reservation)
    assert db.added == db.flushes == []


def test_locked_terminalization_and_recovery_graphs_are_not_mutation_authority():
    accepting = []
    locked_types = {
        runtime.LockedWorkflowTerminalizationGraph,
        runtime.LockedStageRecoveryGraph,
    }
    for name, value in vars(runtime).items():
        if not callable(value) or value in locked_types:
            continue
        try:
            parameters = inspect.signature(value).parameters
        except (TypeError, ValueError):
            continue
        if any(parameter.annotation in locked_types for parameter in parameters.values()):
            accepting.append(name)
    assert accepting == []
    for function in (
        runtime.reserve_workflow_terminalization_graph,
        runtime.consume_workflow_terminalization_graph,
        runtime.reserve_one_expired_stage_recovery,
        runtime.consume_stage_recovery_graph,
    ):
        source = inspect.getsource(function)
        assert ".flush(" not in source
        assert ".add(" not in source
        assert ".commit(" not in source


@pytest.mark.asyncio
async def test_explicit_cancellation_rejects_newer_publisher_suffix_before_registration():
    workflow, stages, message, delivery, command = _explicit_cancellation_case(active_delivery=True)
    publisher_at = NOW + timedelta(seconds=1)
    message.created_at = publisher_at
    message.updated_at = publisher_at
    message.leased_at = publisher_at
    message.heartbeat_at = publisher_at
    message.lease_expires_at = publisher_at + timedelta(minutes=1)
    delivery.created_at = publisher_at
    delivery.updated_at = publisher_at
    delivery.leased_at = publisher_at
    delivery.heartbeat_at = publisher_at
    delivery.lease_expires_at = publisher_at + timedelta(minutes=1)
    scalars, executes = _explicit_cancellation_script(
        workflow,
        stages,
        message,
        delivery,
        consume_at=publisher_at + timedelta(seconds=2),
    )
    scalars[-3:] = (NOW, publisher_at + timedelta(seconds=1), publisher_at + timedelta(seconds=2))
    db = _ScriptedDB(scalars=scalars[:-1], executes=executes)
    registrations = dict(runtime._WORKFLOW_TERMINALIZATION_RESERVATIONS)
    with pytest.raises(runtime.OutboxConflict, match="retry in a fresh transaction"):
        await runtime.reserve_workflow_terminalization_graph(db, command=command)
    assert runtime._WORKFLOW_TERMINALIZATION_RESERVATIONS == registrations
    assert db.added == db.flushes == []


@pytest.mark.asyncio
async def test_terminalization_rejects_future_stage_history_and_clock_reversal():
    workflow, stages, message, delivery, command = _explicit_cancellation_case()
    stage = stages[0]
    stage.updated_at = NOW + timedelta(seconds=1)
    scalars, executes = _explicit_cancellation_script(
        workflow,
        stages,
        message,
        delivery,
        consume_at=NOW + timedelta(seconds=2),
    )
    db = _ScriptedDB(scalars=scalars[:-1], executes=executes)
    with pytest.raises(runtime.OutboxStoredContractError, match="future authority"):
        await runtime.reserve_workflow_terminalization_graph(db, command=command)

    workflow, stages, message, delivery, command = _explicit_cancellation_case()
    scalars, executes = _explicit_cancellation_script(
        workflow,
        stages,
        message,
        delivery,
        consume_at=NOW - timedelta(microseconds=1),
    )
    reverse_db = _ScriptedDB(scalars=scalars, executes=executes)
    reservation = await runtime.reserve_workflow_terminalization_graph(
        reverse_db,
        command=command,
    )
    with pytest.raises(runtime.OutboxStoredContractError, match="moved backwards"):
        await runtime.consume_workflow_terminalization_graph(
            reverse_db,
            reservation=reservation,
            command=command,
        )
    with pytest.raises(runtime.OutboxConflict, match="not registered"):
        await runtime.consume_workflow_terminalization_graph(
            reverse_db,
            reservation=reservation,
            command=command,
        )


@pytest.mark.asyncio
async def test_terminalization_and_stage_ready_share_workflow_fence_both_orders():
    ready_db, workflow, stage, _ready = await _reserved_root_case()
    workflow.created_at = NOW - timedelta(minutes=5)
    workflow.updated_at = NOW - timedelta(minutes=1)
    workflow.cancel_requested_by = ""
    workflow.cancel_requested_by_id = ""
    workflow.cancel_reason = ""
    workflow.cancel_requested_at = None
    workflow.cancel_request_id = None
    command = runtime.WorkflowCancellationCommand(
        request_id=uuid.uuid4(),
        workflow_run_id=workflow.id,
        expected_workflow_state_version=workflow.state_version,
        actor="incident commander",
        actor_id="user-42",
        reason="Stop queued workflow",
    )
    query_count = len(ready_db.scalar_statements)
    with pytest.raises(runtime.OutboxConflict, match="fanout authority"):
        await runtime.reserve_workflow_terminalization_graph(ready_db, command=command)
    assert len(ready_db.scalar_statements) == query_count

    workflow, stages, message, delivery, command = _explicit_cancellation_case()
    scalars, executes = _explicit_cancellation_script(
        workflow,
        stages,
        message,
        delivery,
    )
    terminal_db = _ScriptedDB(scalars=scalars[:-1], executes=executes)
    await runtime.reserve_workflow_terminalization_graph(terminal_db, command=command)
    intent = runtime.project_stage_ready_intent(
        workflow,
        stages[0],
        emission_kind="root_ready",
        post_status="ready",
        post_state_version=stages[0].state_version,
        post_next_attempt_at=stages[0].next_attempt_at,
        target_attempt_number=1,
    )
    query_count = len(terminal_db.scalar_statements)
    with pytest.raises(runtime.OutboxConflict, match="terminalization authority"):
        await runtime.reserve_stage_ready_intents(
            terminal_db,
            workflow=workflow,
            locked_stages=stages,
            target_stages=stages,
            intents=(intent,),
        )
    assert len(terminal_db.scalar_statements) == query_count


@pytest.mark.asyncio
async def test_terminalization_deep_snapshot_is_read_lock_only_until_child_consumption():
    workflow, stages, message, delivery, command = _explicit_cancellation_case(active_delivery=True)
    before = tuple(_snapshot(value) for value in (workflow, *stages, message, delivery))
    scalars, executes = _explicit_cancellation_script(
        workflow,
        stages,
        message,
        delivery,
    )
    db = _ScriptedDB(scalars=scalars, executes=executes)
    reservation = await runtime.reserve_workflow_terminalization_graph(db, command=command)
    await runtime.consume_workflow_terminalization_graph(
        db,
        reservation=reservation,
        command=command,
    )
    after = tuple(_snapshot(value) for value in (workflow, *stages, message, delivery))
    assert after == before
    assert db.added == db.flushes == []


@pytest.mark.asyncio
async def test_recovery_rejects_future_stage_history_and_consume_clock_reversal():
    workflow, stages, message, delivery, attempt, _authority = _expired_recovery_case()
    stages[0].updated_at = NOW + timedelta(seconds=1)
    db = _ScriptedDB(
        scalars=_recovery_retry_script(
            workflow,
            stages,
            message,
            delivery,
            attempt,
            consume=False,
        ),
    )
    with pytest.raises(runtime.OutboxStoredContractError, match="future authority"):
        await runtime.reserve_one_expired_stage_recovery(db)

    workflow, stages, message, delivery, attempt, _authority = _expired_recovery_case()
    values = _recovery_retry_script(workflow, stages, message, delivery, attempt)
    values[-1] = NOW - timedelta(microseconds=1)
    reverse_db = _ScriptedDB(scalars=values)
    reservation = await runtime.reserve_one_expired_stage_recovery(reverse_db)
    with pytest.raises(runtime.OutboxStoredContractError, match="moved backwards"):
        await runtime.consume_stage_recovery_graph(reverse_db, reservation=reservation)
    with pytest.raises(runtime.OutboxConflict, match="not registered"):
        await runtime.consume_stage_recovery_graph(reverse_db, reservation=reservation)


@pytest.mark.asyncio
async def test_recovery_locks_then_rejects_impossible_existing_future_retry_root():
    workflow, stages, source_message, source_delivery, attempt, _authority = _expired_recovery_case()
    source = stages[0]
    future_message = _message(
        workflow,
        source,
        status="pending",
        emission_kind="lease_recovered",
        causation_id=attempt.id,
    )
    messages = tuple(sorted((source_message, future_message), key=lambda value: value.id.int))
    db = _ScriptedDB(
        scalars=(
            workflow,
            *stages,
            attempt.id,
            source_delivery.id,
            source_message.id,
            future_message.id,
            *messages,
            source_delivery,
            attempt,
            NOW,
            NOW,
        )
    )
    registrations = dict(runtime._STAGE_RECOVERY_RESERVATIONS)
    with pytest.raises(runtime.OutboxStoredContractError, match="impossible future"):
        await runtime.reserve_one_expired_stage_recovery(db)
    statements = [_compiled(value) for value in db.scalar_statements]
    locked_message_statements = [value for value in statements if "FROM outbox_messages" in value and "FOR UPDATE" in value]
    assert len(locked_message_statements) == 2
    assert runtime._STAGE_RECOVERY_RESERVATIONS == registrations
    assert db.added == db.flushes == []


@pytest.mark.asyncio
async def test_transferred_cancellation_child_is_sealed_and_spent_before_mutation():
    workflow, stages, message, delivery, command = _explicit_cancellation_case(active_delivery=True)
    scalars, executes = _explicit_cancellation_script(
        workflow,
        stages,
        message,
        delivery,
    )
    db = _ScriptedDB(scalars=scalars, executes=executes)
    reservation = await runtime.reserve_workflow_terminalization_graph(db, command=command)
    locked = await runtime.consume_workflow_terminalization_graph(
        db,
        reservation=reservation,
        command=command,
    )
    child = locked.outbox_cancellation_reservation
    object.__setattr__(child, "cancel_reason", "tampered cancellation reason")
    with pytest.raises(runtime.OutboxConflict, match="mutated"):
        await runtime.cancel_reserved_outbox_messages(db, reservation=child)
    with pytest.raises(runtime.OutboxConflict, match="not registered"):
        await runtime.cancel_reserved_outbox_messages(db, reservation=child)
    assert db.flushes == []
