"""Flush-only PostgreSQL runtime for the durable workflow outbox.

This module owns persistence transitions for ``OutboxMessage`` and
``OutboxDeliveryAttempt``.  It deliberately performs no broker or network I/O
and never commits: callers own the short surrounding transaction.  Publisher
claims are committed before an adapter sends the detached envelope.

All publisher and recovery paths lock only the outbox suffix in canonical
``Message -> DeliveryAttempt`` order.  PostgreSQL transaction time remains the
authority for trigger-stamped facts and deterministic schedules.  Receipt and
post-commit activation liveness use ``clock_timestamp()`` after all authority
locks, so lock waits cannot preserve an already-expired lease.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import struct
import unicodedata
import uuid
import weakref
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from sqlalchemy import and_, exists, func, inspect as sa_inspect, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import object_session

from app.models.research_workflow import (
    OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1,
    OUTBOX_TOPIC_WORKFLOW_STAGE_READY,
    OUTBOX_V1_MAX_ATTEMPTS,
    MAX_OUTBOX_DELIVERY_CYCLE,
    OutboxDeliveryAttempt,
    OutboxMessage,
    StageAttempt,
    StageRun,
    WorkflowRun,
)
from app.services.outbox_engine import (
    NormalizedOutboxEnvelope,
    OutboxContractError,
    SanitizedOutboxError,
    delivery_cycle_idempotency_key,
    deterministic_delivery_retry_delay_seconds,
    normalize_outbox_envelope,
    sanitize_outbox_error,
)
from app.services.workflow_engine import (
    SanitizedWorkflowError,
    WorkflowContractError,
    WorkflowPlanValidationError,
    checksum_json,
    deterministic_retry_backoff_seconds,
    normalize_stage_plan,
    sanitize_workflow_error,
)


_ACTIVE_WORKFLOW_STATUSES = ("queued", "running")
_CLAIMABLE_STAGE_STATUSES = ("ready", "retry_wait")
_CLAIMABLE_MESSAGE_STATUSES = ("pending", "retry_wait")
_ACTIVE_DELIVERY_STATUSES = ("dispatching", "awaiting_receipt")
_RUNTIME_EMISSION_KINDS = (
    "root_ready",
    "dependency_ready",
    "retry_scheduled",
    "lease_recovered",
)
_IDENTITY_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,79}$")
_LOWER_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ERROR_CLASS_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,119}$")
_COMMIT_TICKET_RE = re.compile(r"^[A-Za-z0-9_-]{160}$")
_COMMIT_TICKET_DOMAIN = b"adversarygraph:workflow-stage-activation:v1\x00"
_MAX_LEASE_SECONDS = 3_600
_MAX_RECEIPT_TIMEOUT_SECONDS = 86_400
_MAX_RECOVERY_BATCH = 500
_EMPTY_OBJECT_CHECKSUM = checksum_json({})
_FAILURE_CANCELLATION_ACTOR = "AdversaryGraph workflow runtime"
_FAILURE_CANCELLATION_ACTOR_ID = "workflow.runtime"
_FAILURE_CANCELLATION_REASON = "Workflow stopped after a required stage failed"
_FAILURE_CANCELLATION_CLASS = "WorkflowCancelled"
_EXPLICIT_CANCELLATION_CODE = "workflow.cancelled"
_LEASE_EXPIRED_CODE = "workflow.lease_expired"
_LEASE_EXPIRED_CLASS = "LeaseExpired"
_LEASE_EXPIRED_SUMMARY = "Worker lease expired before the attempt reached a terminal outcome"
_UNRESOLVED_STAGE_STATUSES = ("pending", "ready", "running", "retry_wait")
_TERMINAL_STAGE_STATUSES = (
    "succeeded",
    "degraded",
    "skipped",
    "failed",
    "cancelled",
    "dead_lettered",
)
_DEPENDENCY_SUCCESS_STATUSES = ("succeeded", "degraded")
_DEPENDENCY_FAILURE_STATUSES = ("skipped", "failed", "cancelled", "dead_lettered")
_WORKFLOW_EMISSION_AUTHORITY_COLUMNS = frozenset(
    {
        "id",
        "status",
        "state_version",
        "correlation_id",
        "plan_checksum",
        "stage_plan",
        "input_manifest",
    }
)
_STAGE_EMISSION_AUTHORITY_COLUMNS = frozenset(
    {
        "id",
        "workflow_run_id",
        "stage_key",
        "stage_type",
        "stage_version",
        "ordinal",
        "status",
        "priority",
        "state_version",
        "depends_on",
        "required",
        "config_schema_version",
        "config",
        "config_checksum",
        "input_manifest",
        "input_checksum",
        "output_manifest",
        "output_checksum",
        "checkpoint",
        "checkpoint_schema_version",
        "checkpoint_version",
        "checkpoint_checksum",
        "attempt_count",
        "max_attempts",
        "next_attempt_at",
        "lease_owner",
        "lease_token",
        "leased_at",
        "lease_expires_at",
        "heartbeat_at",
        "last_error_code",
        "last_error_summary",
        "last_error_retryable",
        "first_started_at",
        "completed_at",
    }
)
_ATTEMPT_EMISSION_AUTHORITY_COLUMNS = frozenset(
    {
        "id",
        "stage_run_id",
        "outbox_delivery_attempt_id",
        "attempt_number",
        "lease_token",
        "lease_owner",
        "delivery_id",
        "status",
        "state_version",
        "input_checksum",
        "checkpoint_start_version",
        "checkpoint_end_version",
        "output_checksum",
        "error_code",
        "error_class",
        "error_summary",
        "retryable",
        "started_at",
        "heartbeat_at",
        "lease_expires_at",
        "completed_at",
    }
)
_OUTBOX_MESSAGE_EMISSION_AUTHORITY_COLUMNS = frozenset(
    column.key for column in OutboxMessage.__table__.columns if column.key not in {"created_at", "updated_at"}
)
_OUTBOX_DELIVERY_EMISSION_AUTHORITY_COLUMNS = frozenset(
    column.key for column in OutboxDeliveryAttempt.__table__.columns if column.key not in {"created_at", "updated_at"}
)
_EMISSION_AUTHORITY_COLUMNS = {
    WorkflowRun: _WORKFLOW_EMISSION_AUTHORITY_COLUMNS,
    StageRun: _STAGE_EMISSION_AUTHORITY_COLUMNS,
    StageAttempt: _ATTEMPT_EMISSION_AUTHORITY_COLUMNS,
    OutboxMessage: _OUTBOX_MESSAGE_EMISSION_AUTHORITY_COLUMNS,
    OutboxDeliveryAttempt: _OUTBOX_DELIVERY_EMISSION_AUTHORITY_COLUMNS,
}
_STAGE_EXECUTION_AUTHORITY_COLUMNS = {
    model: frozenset(column.key for column in model.__table__.columns)
    for model in (
        WorkflowRun,
        StageRun,
        StageAttempt,
        OutboxMessage,
        OutboxDeliveryAttempt,
    )
}


class OutboxRuntimeError(RuntimeError):
    """Base class for durable outbox runtime failures."""


class OutboxNotFound(OutboxRuntimeError):
    """A requested outbox authority record does not exist."""


class OutboxConflict(OutboxRuntimeError):
    """A requested transition conflicts with durable outbox state."""


class OutboxValidation(OutboxRuntimeError):
    """An outbox runtime command is outside the bounded contract."""


class OutboxLeaseLost(OutboxConflict):
    """A publisher no longer owns the exact live delivery fence."""


class OutboxStoredContractError(OutboxRuntimeError):
    """Persisted outbox authority is internally inconsistent."""


@dataclass(frozen=True)
class _StageReadyState:
    """Detached exact stage facts used on both sides of an emission cutover."""

    stage_run_id: uuid.UUID
    workflow_run_id: uuid.UUID
    stage_key: str
    ordinal: int
    depends_on: tuple[str, ...]
    input_checksum: str
    output_manifest_checksum: str
    checkpoint_payload_checksum: str
    checkpoint_checksum: str
    checkpoint_version: int
    status: str
    state_version: int
    attempt_count: int
    max_attempts: int
    next_attempt_at: datetime | None
    lease_owner: str
    lease_token: uuid.UUID | None
    leased_at: datetime | None
    lease_expires_at: datetime | None
    heartbeat_at: datetime | None
    last_error_code: str
    last_error_summary: str
    last_error_retryable: bool
    output_checksum: str
    first_started_at: datetime | None
    completed_at: datetime | None

    def __post_init__(self) -> None:
        if type(self) is not _StageReadyState:
            raise OutboxValidation("Stage-ready state must use its exact runtime type")
        _uuid(self.stage_run_id, field_name="stage state id")
        _uuid(self.workflow_run_id, field_name="stage state workflow id")
        _identity(self.stage_key, field_name="stage state key")
        _bounded_int(self.ordinal, field_name="stage state ordinal", minimum=1, maximum=100)
        if type(self.depends_on) is not tuple or any(type(key) is not str for key in self.depends_on):
            raise OutboxValidation("Stage-ready dependencies must be an exact tuple of strings")
        if len(self.depends_on) != len(set(self.depends_on)):
            raise OutboxValidation("Stage-ready dependencies must be unique")
        for key in self.depends_on:
            _identity(key, field_name="stage dependency")
        if self.stage_key in self.depends_on:
            raise OutboxValidation("Stage-ready state cannot depend on itself")
        _lower_sha256(self.input_checksum, field_name="stage input_checksum")
        _lower_sha256(
            self.output_manifest_checksum,
            field_name="stage output_manifest_checksum",
        )
        _lower_sha256(
            self.checkpoint_payload_checksum,
            field_name="stage checkpoint_payload_checksum",
        )
        _lower_sha256(
            self.checkpoint_checksum,
            field_name="stage checkpoint_checksum",
        )
        _bounded_int(
            self.checkpoint_version,
            field_name="stage checkpoint_version",
            minimum=0,
            maximum=2_147_483_647,
        )
        if type(self.status) is not str or self.status not in {
            "pending",
            "ready",
            "running",
            "retry_wait",
            "succeeded",
            "degraded",
            "skipped",
            "failed",
            "cancelled",
            "dead_lettered",
        }:
            raise OutboxValidation("Stage-ready state has an invalid status")
        _state_version(self.state_version, field_name="stage state_version")
        _bounded_int(self.attempt_count, field_name="stage attempt_count", minimum=0, maximum=20)
        _bounded_int(self.max_attempts, field_name="stage max_attempts", minimum=1, maximum=20)
        if self.attempt_count > self.max_attempts:
            raise OutboxValidation("Stage-ready attempt count exceeds its maximum")
        for field_name in (
            "next_attempt_at",
            "leased_at",
            "lease_expires_at",
            "heartbeat_at",
            "first_started_at",
            "completed_at",
        ):
            value = getattr(self, field_name)
            if value is not None:
                _aware_datetime(value, field_name=field_name)
        if type(self.lease_owner) is not str:
            raise OutboxValidation("Stage lease_owner must be an exact string")
        if self.lease_owner:
            _text(self.lease_owner, field_name="stage lease_owner", maximum=255)
        if self.lease_token is not None:
            _uuid(self.lease_token, field_name="stage lease_token")
        if type(self.last_error_code) is not str or type(self.last_error_summary) is not str:
            raise OutboxValidation("Stage error facts must be exact strings")
        if self.last_error_code:
            _identity(self.last_error_code, field_name="stage last_error_code")
        _optional_text(self.last_error_summary, field_name="stage last_error_summary", maximum=500)
        if type(self.last_error_retryable) is not bool:
            raise OutboxValidation("Stage retryability must be an exact boolean")
        if type(self.output_checksum) is not str or (self.output_checksum != "" and not _LOWER_SHA256_RE.fullmatch(self.output_checksum)):
            raise OutboxValidation("Stage output_checksum must be empty or lowercase SHA-256")

        if self.status == "running":
            if (
                not self.lease_owner
                or self.lease_token is None
                or self.leased_at is None
                or self.lease_expires_at is None
                or self.heartbeat_at is None
            ):
                raise OutboxValidation("Running stage projection requires complete lease facts")
        elif (
            self.lease_owner != ""
            or self.lease_token is not None
            or self.leased_at is not None
            or self.lease_expires_at is not None
            or self.heartbeat_at is not None
        ):
            raise OutboxValidation("Non-running stage projection cannot retain lease facts")
        if (self.status in _CLAIMABLE_STAGE_STATUSES) != (self.next_attempt_at is not None):
            raise OutboxValidation("Stage-ready schedule facts disagree with status")
        terminal = self.status in {
            "succeeded",
            "degraded",
            "skipped",
            "failed",
            "cancelled",
            "dead_lettered",
        }
        if terminal != (self.completed_at is not None):
            raise OutboxValidation("Stage-ready completion facts disagree with status")
        never_started = self.status in {"pending", "ready", "skipped"}
        started = self.status in {"running", "retry_wait", "succeeded", "degraded", "failed", "dead_lettered"}
        if never_started and (self.attempt_count != 0 or self.first_started_at is not None):
            raise OutboxValidation("Unstarted stage projection has attempt history")
        if started and (self.attempt_count == 0 or self.first_started_at is None):
            raise OutboxValidation("Started stage projection has incomplete attempt history")
        success = self.status in {"succeeded", "degraded"}
        if success != (self.output_checksum != ""):
            raise OutboxValidation("Stage-ready output facts disagree with status")
        if self.status == "retry_wait":
            valid_error = bool(self.last_error_code) and self.last_error_retryable
        elif self.status == "failed":
            valid_error = bool(self.last_error_code) and not self.last_error_retryable
        elif self.status == "dead_lettered":
            valid_error = bool(self.last_error_code) and self.last_error_retryable
        else:
            valid_error = self.last_error_code == "" and self.last_error_summary == "" and not self.last_error_retryable
        if not valid_error:
            raise OutboxValidation("Stage-ready error facts disagree with status")
        if self.status == "running" and not (
            self.lease_expires_at > self.leased_at and self.heartbeat_at >= self.leased_at and self.heartbeat_at <= self.lease_expires_at
        ):
            raise OutboxValidation("Stage-ready lease timestamps are contradictory")
        if self.completed_at is not None and self.first_started_at is not None and self.completed_at < self.first_started_at:
            raise OutboxValidation("Stage-ready completion precedes its first start")


@dataclass(frozen=True)
class StageReadyIntent:
    """Immutable pre/post projection for one same-transaction outbox root."""

    workflow_run_id: uuid.UUID
    workflow_status: str
    workflow_state_version: int
    correlation_id: uuid.UUID
    plan_checksum: str
    emission_kind: Literal[
        "root_ready",
        "dependency_ready",
        "retry_scheduled",
        "lease_recovered",
    ]
    projection_mode: Literal["transition", "current"]
    allow_create: bool
    pre_target: _StageReadyState
    post_target: _StageReadyState
    causal_pre_stage: _StageReadyState | None
    target_attempt_number: int
    envelope_canonical: str
    envelope_checksum: str
    logical_key: str

    def __post_init__(self) -> None:
        if type(self) is not StageReadyIntent:
            raise OutboxValidation("Stage-ready intent must use its exact runtime type")
        _uuid(self.workflow_run_id, field_name="intent workflow_run_id")
        if type(self.workflow_status) is not str or self.workflow_status not in _ACTIVE_WORKFLOW_STATUSES:
            raise OutboxValidation("Stage-ready intent requires an active workflow")
        _state_version(self.workflow_state_version, field_name="intent workflow_state_version")
        _uuid(self.correlation_id, field_name="intent correlation_id")
        _lower_sha256(self.plan_checksum, field_name="intent plan_checksum")
        if type(self.emission_kind) is not str or self.emission_kind not in _RUNTIME_EMISSION_KINDS:
            raise OutboxValidation("Stage-ready intent has an invalid emission kind")
        if type(self.projection_mode) is not str or self.projection_mode not in {"transition", "current"}:
            raise OutboxValidation("Stage-ready intent has an invalid projection mode")
        if type(self.allow_create) is not bool:
            raise OutboxValidation("Stage-ready creation policy must be an exact boolean")
        if type(self.pre_target) is not _StageReadyState or type(self.post_target) is not _StageReadyState:
            raise OutboxValidation("Stage-ready intent requires exact target state projections")
        if self.causal_pre_stage is not None and type(self.causal_pre_stage) is not _StageReadyState:
            raise OutboxValidation("Stage-ready intent causal projection is invalid")
        object.__setattr__(self, "pre_target", _copy_stage_ready_state(self.pre_target))
        object.__setattr__(self, "post_target", _copy_stage_ready_state(self.post_target))
        if self.causal_pre_stage is not None:
            object.__setattr__(self, "causal_pre_stage", _copy_stage_ready_state(self.causal_pre_stage))
        _bounded_int(
            self.target_attempt_number,
            field_name="target_attempt_number",
            minimum=1,
            maximum=20,
        )
        for field_name in ("envelope_canonical", "envelope_checksum", "logical_key"):
            if type(getattr(self, field_name)) is not str:
                raise OutboxValidation(f"{field_name} must be an exact built-in string")
        _assert_stage_ready_intent_fixed_point(self)


@dataclass(frozen=True)
class StageReadyReservation:
    """Session- and root-transaction-local lock authority for full fan-out."""

    intents: tuple[StageReadyIntent, ...]
    message_ids: tuple[uuid.UUID, ...]
    existing_messages: tuple[OutboxMessage | None, ...] = field(repr=False, compare=False)
    active_deliveries: tuple[OutboxDeliveryAttempt | None, ...] = field(repr=False, compare=False)
    locked_stage_ids: tuple[uuid.UUID, ...]
    locked_stage_states: tuple[_StageReadyState, ...] = field(repr=False)
    _session: object = field(repr=False, compare=False)
    _transaction: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self) is not StageReadyReservation:
            raise OutboxValidation("Stage-ready reservation must use its exact runtime type")
        if (
            type(self.intents) is not tuple
            or not self.intents
            or type(self.message_ids) is not tuple
            or type(self.existing_messages) is not tuple
            or type(self.active_deliveries) is not tuple
            or type(self.locked_stage_ids) is not tuple
            or type(self.locked_stage_states) is not tuple
        ):
            raise OutboxValidation("Stage-ready reservation tuples are invalid")
        size = len(self.intents)
        if not (size == len(self.message_ids) == len(self.existing_messages) == len(self.active_deliveries)):
            raise OutboxValidation("Stage-ready reservation tuples have contradictory lengths")
        rebuilt = tuple(_copy_stage_ready_intent(intent) for intent in self.intents)
        if tuple(intent.logical_key for intent in rebuilt) != tuple(sorted(intent.logical_key for intent in rebuilt)):
            raise OutboxValidation("Stage-ready reservation is not in logical-key order")
        if len({intent.logical_key for intent in rebuilt}) != size:
            raise OutboxValidation("Stage-ready reservation contains duplicate logical keys")
        for message_id in self.message_ids:
            _uuid(message_id, field_name="reserved message id")
        if len(set(self.message_ids)) != size:
            raise OutboxValidation("Stage-ready reservation contains duplicate message ids")
        for stage_id in self.locked_stage_ids:
            _uuid(stage_id, field_name="reserved locked stage id")
        if len(set(self.locked_stage_ids)) != len(self.locked_stage_ids):
            raise OutboxValidation("Stage-ready reservation contains duplicate stage ids")
        if len(self.locked_stage_states) != len(self.locked_stage_ids):
            raise OutboxValidation("Stage-ready reservation stage snapshots are incomplete")
        copied_states = tuple(_copy_stage_ready_state(state) for state in self.locked_stage_states)
        if tuple(state.stage_run_id for state in copied_states) != self.locked_stage_ids:
            raise OutboxValidation("Stage-ready reservation stage snapshots are out of order")
        for message, delivery in zip(self.existing_messages, self.active_deliveries, strict=True):
            if message is not None and type(message) is not OutboxMessage:
                raise OutboxValidation("Reserved message authority has an invalid runtime type")
            if delivery is not None and type(delivery) is not OutboxDeliveryAttempt:
                raise OutboxValidation("Reserved delivery authority has an invalid runtime type")
            if message is None and delivery is not None:
                raise OutboxValidation("Reserved delivery has no message authority")
        if self._session is None or self._transaction is None:
            raise OutboxValidation("Stage-ready reservation has no transaction authority")
        object.__setattr__(self, "intents", rebuilt)
        object.__setattr__(self, "locked_stage_states", copied_states)


@dataclass(frozen=True)
class _StageReadyReservationRegistration:
    session_ref: weakref.ReferenceType[object]
    reservation_ref: weakref.ReferenceType[StageReadyReservation]
    seal: tuple[object, ...]
    fanout_coordinate: tuple[object, ...]


_STAGE_READY_RESERVATIONS: dict[
    tuple[int, int, int],
    _StageReadyReservationRegistration,
] = {}


@dataclass(frozen=True)
class ClaimedOutboxDelivery:
    """Detached authority a publisher may send after its claim commits."""

    message_id: uuid.UUID
    delivery_attempt_id: uuid.UUID
    delivery_token: uuid.UUID
    message_state_version: int
    delivery_state_version: int
    delivery_cycle: int
    cycle_key: str
    correlation_id: uuid.UUID
    topic: str
    schema_version: str
    envelope_checksum: str
    logical_key: str
    envelope_canonical: str

    def __post_init__(self) -> None:
        if type(self) is not ClaimedOutboxDelivery:
            raise OutboxValidation("Claim authority must use its exact runtime type")
        for field_name in (
            "message_id",
            "delivery_attempt_id",
            "delivery_token",
            "correlation_id",
        ):
            _uuid(getattr(self, field_name), field_name=field_name)
        _bounded_int(
            self.message_state_version,
            field_name="message_state_version",
            minimum=1,
            maximum=2_147_483_647,
        )
        _bounded_int(
            self.delivery_state_version,
            field_name="delivery_state_version",
            minimum=1,
            maximum=2_147_483_647,
        )
        _bounded_int(
            self.delivery_cycle,
            field_name="delivery_cycle",
            minimum=1,
            maximum=MAX_OUTBOX_DELIVERY_CYCLE,
        )
        for field_name in (
            "cycle_key",
            "topic",
            "schema_version",
            "envelope_checksum",
            "logical_key",
            "envelope_canonical",
        ):
            if type(getattr(self, field_name)) is not str:
                raise OutboxValidation(f"{field_name} must be an exact built-in string")
        if self.topic != OUTBOX_TOPIC_WORKFLOW_STAGE_READY or self.schema_version != OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1:
            raise OutboxValidation("Claim authority is outside the closed v1 registry")
        normalized = self._normalized_envelope()
        if normalized.envelope.topic != self.topic or normalized.envelope.schema_version != self.schema_version:
            raise OutboxValidation("Claim registry facts disagree with the canonical envelope")
        expected_cycle_key = delivery_cycle_idempotency_key(
            self.logical_key,
            delivery_cycle=self.delivery_cycle,
        )
        if self.cycle_key != expected_cycle_key:
            raise OutboxValidation("Claim cycle key disagrees with its logical key and cycle")

    @property
    def envelope(self) -> dict[str, Any]:
        """Return a fresh detached copy of the exact persisted envelope."""

        return self._normalized_envelope().as_payload()

    def _normalized_envelope(self) -> NormalizedOutboxEnvelope:
        try:
            return NormalizedOutboxEnvelope(
                canonical=self.envelope_canonical,
                checksum=self.envelope_checksum,
                logical_key=self.logical_key,
            )
        except (OutboxContractError, TypeError, ValueError) as exc:
            raise OutboxValidation("Claim envelope is not exact canonical authority") from exc


@dataclass(frozen=True)
class StageReceiptCommand:
    """Fixed-point receipt command bound to a detached publisher claim."""

    claim: ClaimedOutboxDelivery
    broker_name: str
    broker_message_id: str
    broker_receipt_id: str
    worker_id: str
    lease_seconds: int = 300

    def __post_init__(self) -> None:
        if type(self) is not StageReceiptCommand:
            raise OutboxValidation("Receipt command must use its exact runtime type")
        object.__setattr__(self, "claim", _copy_claim_authority(self.claim))
        _identity(self.broker_name, field_name="broker_name")
        _text(
            self.broker_message_id,
            field_name="broker_message_id",
            maximum=255,
        )
        _lower_sha256(self.broker_receipt_id, field_name="broker_receipt_id")
        _text(self.worker_id, field_name="worker_id", maximum=255)
        _bounded_int(
            self.lease_seconds,
            field_name="lease_seconds",
            minimum=1,
            maximum=_MAX_LEASE_SECONDS,
        )


@dataclass(frozen=True)
class PendingReceiptActivation:
    """Non-executable receipt effect awaiting an external transaction commit."""

    workflow_run_id: uuid.UUID
    stage_run_id: uuid.UUID
    stage_attempt_id: uuid.UUID | None
    message_id: uuid.UUID
    delivery_attempt_id: uuid.UUID
    attempt_number: int
    delivery_cycle: int
    cycle_key: str
    broker_receipt_id: str
    commit_ticket: str | None
    disposition: Literal["activated", "replayed", "stale", "cancelled"]
    should_execute: bool = False

    def __post_init__(self) -> None:
        if type(self) is not PendingReceiptActivation:
            raise OutboxValidation("Pending activation must use its exact runtime type")
        for field_name in (
            "workflow_run_id",
            "stage_run_id",
            "message_id",
            "delivery_attempt_id",
        ):
            _uuid(getattr(self, field_name), field_name=field_name)
        if self.stage_attempt_id is not None:
            _uuid(self.stage_attempt_id, field_name="stage_attempt_id")
        _bounded_int(
            self.attempt_number,
            field_name="attempt_number",
            minimum=1,
            maximum=20,
        )
        _bounded_int(
            self.delivery_cycle,
            field_name="delivery_cycle",
            minimum=1,
            maximum=MAX_OUTBOX_DELIVERY_CYCLE,
        )
        _lower_sha256(self.cycle_key, field_name="cycle_key")
        _lower_sha256(self.broker_receipt_id, field_name="broker_receipt_id")
        if type(self.disposition) is not str or self.disposition not in {
            "activated",
            "replayed",
            "stale",
            "cancelled",
        }:
            raise OutboxValidation("Receipt disposition is outside its closed registry")
        if type(self.should_execute) is not bool:
            raise OutboxValidation("Pending activation flag must be an exact boolean")
        if self.should_execute:
            raise OutboxValidation("Pending activation is never executable before commit confirmation")
        if self.disposition == "activated":
            if self.stage_attempt_id is None:
                raise OutboxValidation("Activated receipt requires its linked stage attempt")
            _commit_ticket(self.commit_ticket)
        elif self.commit_ticket is not None:
            raise OutboxValidation("Terminal receipt disposition cannot mint a commit ticket")
        if (self.disposition == "replayed") != (self.stage_attempt_id is not None):
            if self.disposition != "activated":
                raise OutboxValidation("Only activated or replayed receipts identify a stage attempt")

    @property
    def replayed(self) -> bool:
        """Compatibility-safe derived replay marker; disposition is authoritative."""

        return self.disposition == "replayed"


@dataclass(frozen=True)
class ExecutableStageAuthority:
    """Detached worker authority revalidated after the receipt transaction."""

    workflow_run_id: uuid.UUID
    stage_run_id: uuid.UUID
    stage_attempt_id: uuid.UUID
    message_id: uuid.UUID
    delivery_attempt_id: uuid.UUID
    stage_lease_token: uuid.UUID
    workflow_state_version: int
    stage_state_version: int
    attempt_state_version: int
    attempt_number: int
    delivery_cycle: int
    cycle_key: str
    stage_key: str
    input_checksum: str
    checkpoint_version: int
    lease_owner: str
    lease_expires_at: datetime
    broker_receipt_id: str

    def __post_init__(self) -> None:
        if type(self) is not ExecutableStageAuthority:
            raise OutboxValidation("Executable authority must use its exact runtime type")
        for field_name in (
            "workflow_run_id",
            "stage_run_id",
            "stage_attempt_id",
            "message_id",
            "delivery_attempt_id",
            "stage_lease_token",
        ):
            _uuid(getattr(self, field_name), field_name=field_name)
        for field_name in (
            "workflow_state_version",
            "stage_state_version",
            "attempt_state_version",
        ):
            _state_version(getattr(self, field_name), field_name=field_name)
        _bounded_int(
            self.attempt_number,
            field_name="attempt_number",
            minimum=1,
            maximum=20,
        )
        _bounded_int(
            self.delivery_cycle,
            field_name="delivery_cycle",
            minimum=1,
            maximum=MAX_OUTBOX_DELIVERY_CYCLE,
        )
        _bounded_int(
            self.checkpoint_version,
            field_name="checkpoint_version",
            minimum=0,
            maximum=2_147_483_647,
        )
        _lower_sha256(self.cycle_key, field_name="cycle_key")
        _identity(self.stage_key, field_name="stage_key")
        _lower_sha256(self.input_checksum, field_name="input_checksum")
        _text(self.lease_owner, field_name="lease_owner", maximum=255)
        _aware_datetime(self.lease_expires_at, field_name="lease_expires_at")
        _lower_sha256(self.broker_receipt_id, field_name="broker_receipt_id")


@dataclass(frozen=True)
class StageExecutionReceiptReservation:
    """Single-use proof that one worker attempt has delivered receipt lineage.

    The contained ORM rows remain private transaction-local authority.  This
    object is not self-authenticating: only a reservation registered by
    :func:`reserve_stage_execution_receipt` can be consumed, once, in the same
    session and root transaction.
    """

    authority: ExecutableStageAuthority
    workflow: WorkflowRun = field(repr=False, compare=False)
    stage: StageRun = field(repr=False, compare=False)
    message: OutboxMessage = field(repr=False, compare=False)
    delivery: OutboxDeliveryAttempt = field(repr=False, compare=False)
    attempt: StageAttempt = field(repr=False, compare=False)
    observed_at: datetime
    _session: object = field(repr=False, compare=False)
    _transaction: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self) is not StageExecutionReceiptReservation:
            raise OutboxValidation("Stage execution receipt reservation must use its exact runtime type")
        object.__setattr__(
            self,
            "authority",
            _copy_executable_stage_authority(self.authority),
        )
        for value, model, field_name in (
            (self.workflow, WorkflowRun, "reserved workflow"),
            (self.stage, StageRun, "reserved stage"),
            (self.message, OutboxMessage, "reserved message"),
            (self.delivery, OutboxDeliveryAttempt, "reserved delivery"),
            (self.attempt, StageAttempt, "reserved attempt"),
        ):
            _exact_model(value, model, field_name=field_name)
        _aware_datetime(self.observed_at, field_name="reservation observed_at")
        if self._session is None or self._transaction is None:
            raise OutboxValidation("Stage execution receipt reservation has no transaction authority")


@dataclass(frozen=True)
class LockedStageExecutionReceipt:
    """Fresh-clock consumed W/S/M/D/A authority for an immediate mutation."""

    authority: ExecutableStageAuthority
    workflow: WorkflowRun = field(repr=False, compare=False)
    stage: StageRun = field(repr=False, compare=False)
    message: OutboxMessage = field(repr=False, compare=False)
    delivery: OutboxDeliveryAttempt = field(repr=False, compare=False)
    attempt: StageAttempt = field(repr=False, compare=False)
    observed_at: datetime

    def __post_init__(self) -> None:
        if type(self) is not LockedStageExecutionReceipt:
            raise OutboxValidation("Locked stage execution receipt must use its exact runtime type")
        object.__setattr__(
            self,
            "authority",
            _copy_executable_stage_authority(self.authority),
        )
        for value, model, field_name in (
            (self.workflow, WorkflowRun, "locked workflow"),
            (self.stage, StageRun, "locked stage"),
            (self.message, OutboxMessage, "locked message"),
            (self.delivery, OutboxDeliveryAttempt, "locked delivery"),
            (self.attempt, StageAttempt, "locked attempt"),
        ):
            _exact_model(value, model, field_name=field_name)
        _aware_datetime(self.observed_at, field_name="locked receipt observed_at")


@dataclass(frozen=True)
class _StageCompletionTargetProjection:
    """Clock-free dependency-ready identity for one completion target."""

    pre_target: _StageReadyState
    target_attempt_number: int
    envelope_canonical: str
    envelope_checksum: str
    logical_key: str

    def __post_init__(self) -> None:
        if type(self) is not _StageCompletionTargetProjection:
            raise OutboxValidation("Stage completion target projection must use its exact runtime type")
        object.__setattr__(self, "pre_target", _copy_stage_ready_state(self.pre_target))
        if self.pre_target.status != "pending" or self.pre_target.attempt_count != 0:
            raise OutboxValidation("Stage completion target projection requires a pristine pending target")
        if self.target_attempt_number != 1:
            raise OutboxValidation("Stage completion target projection requires first-attempt authority")
        for field_name in ("envelope_canonical", "envelope_checksum", "logical_key"):
            if type(getattr(self, field_name)) is not str:
                raise OutboxValidation(f"{field_name} must be an exact built-in string")
        _assert_stage_completion_projection_fixed_point(self)


@dataclass(frozen=True)
class StageCompletionReservation:
    """Single-use W/all-S/union-M/union-D/A completion authority."""

    authority: ExecutableStageAuthority
    workflow: WorkflowRun = field(repr=False, compare=False)
    stages: tuple[StageRun, ...] = field(repr=False, compare=False)
    stage_states: tuple[_StageReadyState, ...] = field(repr=False)
    source_stage_id: uuid.UUID
    source_stage_index: int
    causal_source: _StageReadyState
    target_projections: tuple[_StageCompletionTargetProjection, ...]
    target_message_ids: tuple[uuid.UUID, ...]
    existing_target_messages: tuple[OutboxMessage | None, ...] = field(repr=False, compare=False)
    active_target_deliveries: tuple[OutboxDeliveryAttempt | None, ...] = field(repr=False, compare=False)
    locked_messages: tuple[OutboxMessage, ...] = field(repr=False, compare=False)
    locked_message_ids: tuple[uuid.UUID, ...]
    locked_deliveries: tuple[OutboxDeliveryAttempt, ...] = field(repr=False, compare=False)
    locked_delivery_ids: tuple[uuid.UUID, ...]
    source_attempt: StageAttempt = field(repr=False, compare=False)
    observed_at: datetime
    _session: object = field(repr=False, compare=False)
    _transaction: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self) is not StageCompletionReservation:
            raise OutboxValidation("Stage completion reservation must use its exact runtime type")
        object.__setattr__(self, "authority", _copy_executable_stage_authority(self.authority))
        _validate_stage_completion_dto(self, locked=False)


@dataclass(frozen=True)
class LockedStageCompletionGraph:
    """Fresh-clock consumed completion graph for an immediate Phase-B writer.

    This constructible DTO is deliberately not executable authority.  For a
    non-empty fan-out it carries a separately registered, single-use
    ``StageReadyReservation``; only that identity-bound child may authorize
    the later query-free append.  A writer must still reserve and consume the
    completion graph internally and never accept this DTO as authorization.
    """

    authority: ExecutableStageAuthority
    workflow: WorkflowRun = field(repr=False, compare=False)
    stages: tuple[StageRun, ...] = field(repr=False, compare=False)
    stage_states: tuple[_StageReadyState, ...] = field(repr=False)
    source_stage_id: uuid.UUID
    source_stage_index: int
    causal_source: _StageReadyState
    target_projections: tuple[_StageCompletionTargetProjection, ...]
    target_message_ids: tuple[uuid.UUID, ...]
    existing_target_messages: tuple[OutboxMessage | None, ...] = field(repr=False, compare=False)
    active_target_deliveries: tuple[OutboxDeliveryAttempt | None, ...] = field(repr=False, compare=False)
    locked_messages: tuple[OutboxMessage, ...] = field(repr=False, compare=False)
    locked_message_ids: tuple[uuid.UUID, ...]
    locked_deliveries: tuple[OutboxDeliveryAttempt, ...] = field(repr=False, compare=False)
    locked_delivery_ids: tuple[uuid.UUID, ...]
    source_attempt: StageAttempt = field(repr=False, compare=False)
    intents: tuple[StageReadyIntent, ...]
    stage_ready_reservation: StageReadyReservation | None = field(
        repr=False,
        compare=False,
    )
    observed_at: datetime

    def __post_init__(self) -> None:
        if type(self) is not LockedStageCompletionGraph:
            raise OutboxValidation("Locked stage completion graph must use its exact runtime type")
        object.__setattr__(self, "authority", _copy_executable_stage_authority(self.authority))
        _validate_stage_completion_dto(self, locked=True)


@dataclass(frozen=True)
class StageFailureEvidence:
    """Exact detached, already-sanitized worker failure evidence."""

    code: str
    error_class: str
    summary: str
    retryable: bool

    def __post_init__(self) -> None:
        if type(self) is not StageFailureEvidence:
            raise OutboxValidation("Stage failure evidence must use its exact runtime type")
        _identity(self.code, field_name="failure code")
        if self.code.startswith("workflow."):
            raise OutboxValidation("workflow.* failure codes are reserved for runtime authority")
        if type(self.error_class) is not str or not _ERROR_CLASS_RE.fullmatch(self.error_class):
            raise OutboxValidation("failure error_class must be an exact bounded class identity")
        _text(self.summary, field_name="failure summary", maximum=500)
        if type(self.retryable) is not bool:
            raise OutboxValidation("failure retryable must be an exact boolean")
        try:
            rebuilt = sanitize_workflow_error(
                self.summary,
                code=self.code,
                retryable=self.retryable,
                error_class=self.error_class,
            )
        except (WorkflowContractError, TypeError, ValueError) as exc:
            raise OutboxValidation("Stage failure evidence is not valid sanitized authority") from exc
        if type(rebuilt) is not SanitizedWorkflowError or (
            rebuilt.code,
            rebuilt.error_class,
            rebuilt.summary,
            rebuilt.retryable,
        ) != (self.code, self.error_class, self.summary, self.retryable):
            raise OutboxValidation("Stage failure evidence is not a sanitizer fixed point")


@dataclass(frozen=True)
class _StageFailureRetryProjection:
    """Clock-free retry root identity for the running failure source."""

    pre_source: _StageReadyState
    target_attempt_number: int
    plan_checksum: str
    envelope_canonical: str
    envelope_checksum: str
    logical_key: str

    def __post_init__(self) -> None:
        if type(self) is not _StageFailureRetryProjection:
            raise OutboxValidation("Stage failure retry projection must use its exact runtime type")
        object.__setattr__(self, "pre_source", _copy_stage_ready_state(self.pre_source))
        if self.pre_source.status != "running" or self.pre_source.attempt_count < 1:
            raise OutboxValidation("Stage failure retry projection requires a running source")
        if self.target_attempt_number != self.pre_source.attempt_count + 1:
            raise OutboxValidation("Stage failure retry projection has the wrong target attempt")
        _lower_sha256(self.plan_checksum, field_name="failure retry plan_checksum")
        for field_name in ("envelope_canonical", "envelope_checksum", "logical_key"):
            if type(getattr(self, field_name)) is not str:
                raise OutboxValidation(f"{field_name} must be an exact built-in string")
        _assert_stage_failure_retry_projection_fixed_point(self)


@dataclass(frozen=True)
class _StageFailureSettlementProjection:
    """Clock-free status closure for one retry or terminal failure decision."""

    decision: Literal["retry", "failed", "dead_lettered"]
    post_stage_statuses: tuple[str, ...]
    skipped_stage_ids: tuple[uuid.UUID, ...]
    cancelled_stage_ids: tuple[uuid.UUID, ...]
    cancelled_attempt_ids: tuple[uuid.UUID, ...]
    workflow_post_status: Literal["running", "degraded", "failed", "dead_lettered"]
    workflow_reason_code: str
    workflow_summary: str

    def __post_init__(self) -> None:
        if type(self) is not _StageFailureSettlementProjection:
            raise OutboxValidation("Stage failure settlement must use its exact runtime type")
        if type(self.decision) is not str or self.decision not in {"retry", "failed", "dead_lettered"}:
            raise OutboxValidation("Stage failure settlement has an invalid decision")
        if type(self.post_stage_statuses) is not tuple or not self.post_stage_statuses:
            raise OutboxValidation("Stage failure settlement requires exact stage statuses")
        allowed = {*_UNRESOLVED_STAGE_STATUSES, *_TERMINAL_STAGE_STATUSES}
        if any(type(status) is not str or status not in allowed for status in self.post_stage_statuses):
            raise OutboxValidation("Stage failure settlement contains an invalid stage status")
        for field_name in ("skipped_stage_ids", "cancelled_stage_ids", "cancelled_attempt_ids"):
            values = getattr(self, field_name)
            if type(values) is not tuple:
                raise OutboxValidation(f"{field_name} must be an exact tuple")
            for value in values:
                _uuid(value, field_name=field_name)
            if len(set(values)) != len(values):
                raise OutboxValidation(f"{field_name} must contain unique identities")
        if type(self.workflow_post_status) is not str or self.workflow_post_status not in {
            "running",
            "degraded",
            "failed",
            "dead_lettered",
        }:
            raise OutboxValidation("Stage failure settlement has an invalid workflow status")
        if self.workflow_reason_code:
            _identity(self.workflow_reason_code, field_name="workflow failure reason code")
            _text(self.workflow_summary, field_name="workflow failure summary", maximum=500)
        elif self.workflow_summary:
            raise OutboxValidation("Workflow failure summary requires a reason code")


@dataclass(frozen=True)
class OutboxCancellationReservation:
    """Transferred one-shot authority to cancel one exact live outbox suffix."""

    workflow_run_id: uuid.UUID
    messages: tuple[OutboxMessage, ...] = field(repr=False, compare=False)
    message_ids: tuple[uuid.UUID, ...]
    deliveries: tuple[OutboxDeliveryAttempt, ...] = field(repr=False, compare=False)
    delivery_ids: tuple[uuid.UUID, ...]
    error_code: str
    error_class: str
    error_summary: str
    cancelled_by: str
    cancelled_by_id: str
    cancel_reason: str
    transaction_at: datetime
    _session: object = field(repr=False, compare=False)
    _transaction: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self) is not OutboxCancellationReservation:
            raise OutboxValidation("Outbox cancellation reservation must use its exact runtime type")
        _uuid(self.workflow_run_id, field_name="cancellation workflow_run_id")
        if type(self.messages) is not tuple or type(self.message_ids) is not tuple:
            raise OutboxValidation("Cancellation message authority tuples are invalid")
        if type(self.deliveries) is not tuple or type(self.delivery_ids) is not tuple:
            raise OutboxValidation("Cancellation delivery authority tuples are invalid")
        if len(self.messages) != len(self.message_ids) or len(self.deliveries) != len(self.delivery_ids):
            raise OutboxValidation("Cancellation authority tuples are misaligned")
        for value in self.messages:
            _exact_model(value, OutboxMessage, field_name="cancellation message")
        for value in self.deliveries:
            _exact_model(value, OutboxDeliveryAttempt, field_name="cancellation delivery")
        for field_name, values in (("message_ids", self.message_ids), ("delivery_ids", self.delivery_ids)):
            for value in values:
                _uuid(value, field_name=field_name)
            if values != tuple(sorted(values, key=lambda value: value.int)) or len(set(values)) != len(values):
                raise OutboxValidation(f"Cancellation {field_name} lost canonical UUID order")
        if tuple(_persisted_uuid(value.id, field_name="cancellation message id") for value in self.messages) != self.message_ids:
            raise OutboxValidation("Cancellation messages do not match their identity tuple")
        if tuple(_persisted_uuid(value.id, field_name="cancellation delivery id") for value in self.deliveries) != self.delivery_ids:
            raise OutboxValidation("Cancellation deliveries do not match their identity tuple")
        if type(self.error_code) is not str or self.error_code not in {
            "workflow.required_stage_failed",
            "workflow.required_stage_dead_lettered",
            _EXPLICIT_CANCELLATION_CODE,
        }:
            raise OutboxValidation("Cancellation error code is outside the closed terminal registry")
        if self.error_class != _FAILURE_CANCELLATION_CLASS:
            raise OutboxValidation("Cancellation error class changed runtime authority")
        if self.error_code == _EXPLICIT_CANCELLATION_CODE:
            _text(self.cancelled_by, field_name="cancellation actor", maximum=255)
            _text(self.cancelled_by_id, field_name="cancellation actor_id", maximum=80)
            reason = _text(self.cancel_reason, field_name="cancellation reason", maximum=500)
            if self.error_summary != reason:
                raise OutboxValidation("Explicit cancellation summary changed command authority")
        elif (
            self.error_summary != _FAILURE_CANCELLATION_REASON
            or self.cancelled_by != _FAILURE_CANCELLATION_ACTOR
            or self.cancelled_by_id != _FAILURE_CANCELLATION_ACTOR_ID
            or self.cancel_reason != _FAILURE_CANCELLATION_REASON
        ):
            raise OutboxValidation("Required-stage cancellation facts changed runtime authority")
        _aware_datetime(self.transaction_at, field_name="cancellation transaction_at")
        if self._session is None or self._transaction is None:
            raise OutboxValidation("Cancellation reservation has no transaction authority")


@dataclass(frozen=True)
class StageFailureReservation:
    """Single-use W/all-S/union-M/union-D/all-current-A failure authority."""

    authority: ExecutableStageAuthority
    evidence: StageFailureEvidence
    workflow: WorkflowRun = field(repr=False, compare=False)
    stages: tuple[StageRun, ...] = field(repr=False, compare=False)
    stage_states: tuple[_StageReadyState, ...] = field(repr=False)
    source_stage_id: uuid.UUID
    source_stage_index: int
    causal_source: _StageReadyState
    decision: Literal["retry", "failed", "dead_lettered"]
    retry_delay_seconds: int | None
    retry_projection: _StageFailureRetryProjection | None
    retry_message_id: uuid.UUID | None
    settlement: _StageFailureSettlementProjection
    locked_messages: tuple[OutboxMessage, ...] = field(repr=False, compare=False)
    locked_message_ids: tuple[uuid.UUID, ...]
    locked_deliveries: tuple[OutboxDeliveryAttempt, ...] = field(repr=False, compare=False)
    locked_delivery_ids: tuple[uuid.UUID, ...]
    locked_attempts: tuple[StageAttempt, ...] = field(repr=False, compare=False)
    locked_attempt_ids: tuple[uuid.UUID, ...]
    source_attempt_id: uuid.UUID
    transaction_at: datetime
    observed_at: datetime
    _session: object = field(repr=False, compare=False)
    _transaction: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self) is not StageFailureReservation:
            raise OutboxValidation("Stage failure reservation must use its exact runtime type")
        object.__setattr__(self, "authority", _copy_executable_stage_authority(self.authority))
        object.__setattr__(self, "evidence", _copy_stage_failure_evidence(self.evidence))
        _validate_stage_failure_dto(self, locked=False)


@dataclass(frozen=True)
class LockedStageFailureGraph:
    """Fresh-clock consumed failure graph; never executable by itself."""

    authority: ExecutableStageAuthority
    evidence: StageFailureEvidence
    workflow: WorkflowRun = field(repr=False, compare=False)
    stages: tuple[StageRun, ...] = field(repr=False, compare=False)
    stage_states: tuple[_StageReadyState, ...] = field(repr=False)
    source_stage_id: uuid.UUID
    source_stage_index: int
    causal_source: _StageReadyState
    decision: Literal["retry", "failed", "dead_lettered"]
    retry_delay_seconds: int | None
    retry_projection: _StageFailureRetryProjection | None
    retry_message_id: uuid.UUID | None
    settlement: _StageFailureSettlementProjection
    locked_messages: tuple[OutboxMessage, ...] = field(repr=False, compare=False)
    locked_message_ids: tuple[uuid.UUID, ...]
    locked_deliveries: tuple[OutboxDeliveryAttempt, ...] = field(repr=False, compare=False)
    locked_delivery_ids: tuple[uuid.UUID, ...]
    locked_attempts: tuple[StageAttempt, ...] = field(repr=False, compare=False)
    locked_attempt_ids: tuple[uuid.UUID, ...]
    source_attempt_id: uuid.UUID
    transaction_at: datetime
    retry_intent: StageReadyIntent | None
    next_attempt_at: datetime | None
    stage_ready_reservation: StageReadyReservation | None = field(repr=False, compare=False)
    outbox_cancellation_reservation: OutboxCancellationReservation | None = field(
        repr=False,
        compare=False,
    )
    observed_at: datetime

    def __post_init__(self) -> None:
        if type(self) is not LockedStageFailureGraph:
            raise OutboxValidation("Locked stage failure graph must use its exact runtime type")
        object.__setattr__(self, "authority", _copy_executable_stage_authority(self.authority))
        object.__setattr__(self, "evidence", _copy_stage_failure_evidence(self.evidence))
        _validate_stage_failure_dto(self, locked=True)


@dataclass(frozen=True)
class WorkflowCancellationCommand:
    """Exact idempotent command authority for one explicit cancellation."""

    request_id: uuid.UUID
    workflow_run_id: uuid.UUID
    expected_workflow_state_version: int
    actor: str
    actor_id: str
    reason: str

    def __post_init__(self) -> None:
        if type(self) is not WorkflowCancellationCommand:
            raise OutboxValidation("Workflow cancellation command must use its exact runtime type")
        _uuid(self.request_id, field_name="cancellation request_id")
        _uuid(self.workflow_run_id, field_name="cancellation workflow_run_id")
        _state_version(
            self.expected_workflow_state_version,
            field_name="cancellation expected workflow state_version",
        )
        _text(self.actor, field_name="cancellation actor", maximum=255)
        _text(self.actor_id, field_name="cancellation actor_id", maximum=80)
        _text(self.reason, field_name="cancellation reason", maximum=500)


@dataclass(frozen=True)
class _WorkflowTerminalizationProjection:
    """Clock-free exact workflow/stage effects for apply or replay."""

    decision: Literal["apply", "replay"]
    post_stage_statuses: tuple[str, ...]
    cancelled_stage_ids: tuple[uuid.UUID, ...]
    cancelled_attempt_ids: tuple[uuid.UUID, ...]

    def __post_init__(self) -> None:
        if type(self) is not _WorkflowTerminalizationProjection:
            raise OutboxValidation("Workflow terminalization projection must use its exact runtime type")
        if type(self.decision) is not str or self.decision not in {"apply", "replay"}:
            raise OutboxValidation("Workflow terminalization projection has an invalid decision")
        if type(self.post_stage_statuses) is not tuple or not self.post_stage_statuses:
            raise OutboxValidation("Workflow terminalization projection requires exact stage statuses")
        if any(type(value) is not str or value not in _TERMINAL_STAGE_STATUSES for value in self.post_stage_statuses):
            raise OutboxValidation("Workflow terminalization projection contains a nonterminal stage")
        for field_name in ("cancelled_stage_ids", "cancelled_attempt_ids"):
            values = getattr(self, field_name)
            if type(values) is not tuple:
                raise OutboxValidation(f"{field_name} must be an exact tuple")
            for value in values:
                _uuid(value, field_name=field_name)
            if len(set(values)) != len(values):
                raise OutboxValidation(f"{field_name} must contain unique identities")
        if self.cancelled_attempt_ids != tuple(sorted(self.cancelled_attempt_ids, key=lambda value: value.int)):
            raise OutboxValidation("cancelled_attempt_ids must use canonical UUID order")
        if self.decision == "replay" and (self.cancelled_stage_ids or self.cancelled_attempt_ids):
            raise OutboxValidation("Workflow cancellation replay cannot claim new effects")


@dataclass(frozen=True)
class _TerminalizationGraphRows:
    """Internal complete lock-cut shared by cancellation and recovery."""

    stages: tuple[StageRun, ...]
    stage_states: tuple[_StageReadyState, ...]
    locked_messages: tuple[OutboxMessage, ...]
    locked_message_ids: tuple[uuid.UUID, ...]
    locked_deliveries: tuple[OutboxDeliveryAttempt, ...]
    locked_delivery_ids: tuple[uuid.UUID, ...]
    locked_attempts: tuple[StageAttempt, ...]
    locked_attempt_ids: tuple[uuid.UUID, ...]
    live_message_ids: tuple[uuid.UUID, ...]
    transaction_at: datetime
    observed_at: datetime


@dataclass(frozen=True)
class WorkflowTerminalizationReservation:
    """Registered W/all-S/union-M/union-D/all-current-A cancellation graph."""

    command: WorkflowCancellationCommand
    decision: Literal["apply", "replay"]
    workflow: WorkflowRun = field(repr=False, compare=False)
    stages: tuple[StageRun, ...] = field(repr=False, compare=False)
    stage_states: tuple[_StageReadyState, ...] = field(repr=False)
    projection: _WorkflowTerminalizationProjection
    locked_messages: tuple[OutboxMessage, ...] = field(repr=False, compare=False)
    locked_message_ids: tuple[uuid.UUID, ...]
    locked_deliveries: tuple[OutboxDeliveryAttempt, ...] = field(repr=False, compare=False)
    locked_delivery_ids: tuple[uuid.UUID, ...]
    locked_attempts: tuple[StageAttempt, ...] = field(repr=False, compare=False)
    locked_attempt_ids: tuple[uuid.UUID, ...]
    live_message_ids: tuple[uuid.UUID, ...]
    transaction_at: datetime
    observed_at: datetime
    _session: object = field(repr=False, compare=False)
    _transaction: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self) is not WorkflowTerminalizationReservation:
            raise OutboxValidation("Workflow terminalization reservation must use its exact runtime type")
        object.__setattr__(self, "command", _copy_workflow_cancellation_command(self.command))
        _validate_workflow_terminalization_dto(self, locked=False)


@dataclass(frozen=True)
class LockedWorkflowTerminalizationGraph:
    """Fresh-clock consumed cancellation graph; never authority by itself."""

    command: WorkflowCancellationCommand
    decision: Literal["apply", "replay"]
    workflow: WorkflowRun = field(repr=False, compare=False)
    stages: tuple[StageRun, ...] = field(repr=False, compare=False)
    stage_states: tuple[_StageReadyState, ...] = field(repr=False)
    projection: _WorkflowTerminalizationProjection
    locked_messages: tuple[OutboxMessage, ...] = field(repr=False, compare=False)
    locked_message_ids: tuple[uuid.UUID, ...]
    locked_deliveries: tuple[OutboxDeliveryAttempt, ...] = field(repr=False, compare=False)
    locked_delivery_ids: tuple[uuid.UUID, ...]
    locked_attempts: tuple[StageAttempt, ...] = field(repr=False, compare=False)
    locked_attempt_ids: tuple[uuid.UUID, ...]
    live_message_ids: tuple[uuid.UUID, ...]
    transaction_at: datetime
    outbox_cancellation_reservation: OutboxCancellationReservation | None = field(
        repr=False,
        compare=False,
    )
    observed_at: datetime

    def __post_init__(self) -> None:
        if type(self) is not LockedWorkflowTerminalizationGraph:
            raise OutboxValidation("Locked workflow terminalization graph must use its exact runtime type")
        object.__setattr__(self, "command", _copy_workflow_cancellation_command(self.command))
        _validate_workflow_terminalization_dto(self, locked=True)


@dataclass(frozen=True)
class StageRecoveryReservation:
    """Registered receipt-bound authority for one auto-selected expired stage."""

    source_authority: ExecutableStageAuthority
    workflow: WorkflowRun = field(repr=False, compare=False)
    stages: tuple[StageRun, ...] = field(repr=False, compare=False)
    stage_states: tuple[_StageReadyState, ...] = field(repr=False)
    source_stage_id: uuid.UUID
    source_stage_index: int
    causal_source: _StageReadyState
    decision: Literal["retry", "dead_lettered"]
    retry_delay_seconds: int | None
    retry_projection: _StageFailureRetryProjection | None
    retry_message_id: uuid.UUID | None
    settlement: _StageFailureSettlementProjection
    locked_messages: tuple[OutboxMessage, ...] = field(repr=False, compare=False)
    locked_message_ids: tuple[uuid.UUID, ...]
    locked_deliveries: tuple[OutboxDeliveryAttempt, ...] = field(repr=False, compare=False)
    locked_delivery_ids: tuple[uuid.UUID, ...]
    locked_attempts: tuple[StageAttempt, ...] = field(repr=False, compare=False)
    locked_attempt_ids: tuple[uuid.UUID, ...]
    source_attempt_id: uuid.UUID
    live_message_ids: tuple[uuid.UUID, ...]
    transaction_at: datetime
    observed_at: datetime
    _session: object = field(repr=False, compare=False)
    _transaction: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self) is not StageRecoveryReservation:
            raise OutboxValidation("Stage recovery reservation must use its exact runtime type")
        object.__setattr__(self, "source_authority", _copy_executable_stage_authority(self.source_authority))
        _validate_stage_recovery_dto(self, locked=False)


@dataclass(frozen=True)
class LockedStageRecoveryGraph:
    """Fresh-clock consumed recovery graph carrying only a registered child."""

    source_authority: ExecutableStageAuthority
    workflow: WorkflowRun = field(repr=False, compare=False)
    stages: tuple[StageRun, ...] = field(repr=False, compare=False)
    stage_states: tuple[_StageReadyState, ...] = field(repr=False)
    source_stage_id: uuid.UUID
    source_stage_index: int
    causal_source: _StageReadyState
    decision: Literal["retry", "dead_lettered"]
    retry_delay_seconds: int | None
    retry_projection: _StageFailureRetryProjection | None
    retry_message_id: uuid.UUID | None
    settlement: _StageFailureSettlementProjection
    locked_messages: tuple[OutboxMessage, ...] = field(repr=False, compare=False)
    locked_message_ids: tuple[uuid.UUID, ...]
    locked_deliveries: tuple[OutboxDeliveryAttempt, ...] = field(repr=False, compare=False)
    locked_delivery_ids: tuple[uuid.UUID, ...]
    locked_attempts: tuple[StageAttempt, ...] = field(repr=False, compare=False)
    locked_attempt_ids: tuple[uuid.UUID, ...]
    source_attempt_id: uuid.UUID
    live_message_ids: tuple[uuid.UUID, ...]
    transaction_at: datetime
    retry_intent: StageReadyIntent | None
    next_attempt_at: datetime | None
    stage_ready_reservation: StageReadyReservation | None = field(repr=False, compare=False)
    outbox_cancellation_reservation: OutboxCancellationReservation | None = field(
        repr=False,
        compare=False,
    )
    observed_at: datetime

    def __post_init__(self) -> None:
        if type(self) is not LockedStageRecoveryGraph:
            raise OutboxValidation("Locked stage recovery graph must use its exact runtime type")
        object.__setattr__(self, "source_authority", _copy_executable_stage_authority(self.source_authority))
        _validate_stage_recovery_dto(self, locked=True)


@dataclass(frozen=True)
class _StageExecutionReceiptRegistration:
    session_ref: weakref.ReferenceType[object]
    reservation_ref: weakref.ReferenceType[StageExecutionReceiptReservation]
    seal: tuple[object, ...]
    coordinate: tuple[object, ...]


@dataclass
class _StageExecutionReceiptTransactionFence:
    transaction: object
    coordinates: dict[tuple[object, ...], tuple[Literal["issued", "spent"], int]]


_STAGE_EXECUTION_RECEIPT_RESERVATIONS: dict[
    tuple[int, int, int],
    _StageExecutionReceiptRegistration,
] = {}
_STAGE_EXECUTION_RECEIPT_FENCE_INFO_KEY = object()


@dataclass(frozen=True)
class _StageCompletionRegistration:
    session_ref: weakref.ReferenceType[object]
    reservation_ref: weakref.ReferenceType[StageCompletionReservation]
    seal: tuple[object, ...]
    execution_coordinate: tuple[object, ...]
    fanout_coordinate: tuple[object, ...]


@dataclass
class _StageCompletionFanoutFence:
    transaction: object
    coordinates: dict[tuple[object, ...], tuple[Literal["issued", "spent"], int]]


_STAGE_COMPLETION_RESERVATIONS: dict[
    tuple[int, int, int],
    _StageCompletionRegistration,
] = {}
_STAGE_COMPLETION_FANOUT_FENCE_INFO_KEY = object()


@dataclass(frozen=True)
class _StageFailureRegistration:
    session_ref: weakref.ReferenceType[object]
    reservation_ref: weakref.ReferenceType[StageFailureReservation]
    seal: tuple[object, ...]
    execution_coordinate: tuple[object, ...]
    branch_coordinate: tuple[object, ...] | None


@dataclass
class _WorkflowTerminalizationFence:
    transaction: object
    coordinates: dict[tuple[object, ...], tuple[Literal["issued", "spent"], int]]


@dataclass(frozen=True)
class _OutboxCancellationRegistration:
    session_ref: weakref.ReferenceType[object]
    reservation_ref: weakref.ReferenceType[OutboxCancellationReservation]
    seal: tuple[object, ...]
    terminal_coordinate: tuple[object, ...]


@dataclass(frozen=True)
class _WorkflowTerminalizationRegistration:
    session_ref: weakref.ReferenceType[object]
    reservation_ref: weakref.ReferenceType[WorkflowTerminalizationReservation]
    seal: tuple[object, ...]
    terminal_coordinate: tuple[object, ...]
    execution_coordinates: tuple[tuple[object, ...], ...]


@dataclass(frozen=True)
class _StageRecoveryRegistration:
    session_ref: weakref.ReferenceType[object]
    reservation_ref: weakref.ReferenceType[StageRecoveryReservation]
    seal: tuple[object, ...]
    execution_coordinates: tuple[tuple[object, ...], ...]
    branch_coordinate: tuple[object, ...] | None


@dataclass
class _StageRecoverySweepFence:
    transaction: object
    state: Literal["pending", "issued", "spent"]
    reservation_id: int | None


_STAGE_FAILURE_RESERVATIONS: dict[
    tuple[int, int, int],
    _StageFailureRegistration,
] = {}
_OUTBOX_CANCELLATION_RESERVATIONS: dict[
    tuple[int, int, int],
    _OutboxCancellationRegistration,
] = {}
_WORKFLOW_TERMINALIZATION_RESERVATIONS: dict[
    tuple[int, int, int],
    _WorkflowTerminalizationRegistration,
] = {}
_STAGE_RECOVERY_RESERVATIONS: dict[
    tuple[int, int, int],
    _StageRecoveryRegistration,
] = {}
_WORKFLOW_TERMINALIZATION_FENCE_INFO_KEY = object()
_STAGE_RECOVERY_SWEEP_FENCE_INFO_KEY = object()


@dataclass(frozen=True)
class OutboxDeliveryMutation:
    """State returned after a fenced publisher transition.

    ``replayed`` means the requested durable effect already exists.  A
    delivered consumer receipt may therefore satisfy broker-dispatch marking
    even when the publisher's mark command itself did not persist first.
    """

    message: OutboxMessage
    delivery: OutboxDeliveryAttempt
    replayed: bool = False


@dataclass(frozen=True)
class OutboxRecoveryResult:
    """One expired delivery recovered into retry wait or dead letter."""

    message_id: uuid.UUID
    delivery_attempt_id: uuid.UUID
    message_status: str
    available_at: datetime | None


@dataclass(frozen=True)
class _CommitTicketCoordinates:
    workflow_run_id: uuid.UUID
    stage_run_id: uuid.UUID
    message_id: uuid.UUID
    delivery_attempt_id: uuid.UUID
    stage_attempt_id: uuid.UUID
    origin_transaction_id: int


def project_stage_ready_intent(
    workflow: WorkflowRun,
    target_stage: StageRun,
    *,
    emission_kind: Literal[
        "root_ready",
        "dependency_ready",
        "retry_scheduled",
        "lease_recovered",
    ],
    post_status: Literal["ready", "retry_wait"],
    post_state_version: int,
    post_next_attempt_at: datetime,
    target_attempt_number: int,
    post_error_code: str = "",
    post_error_summary: str = "",
    post_error_retryable: bool = False,
    causal_stage: StageRun | None = None,
) -> StageReadyIntent:
    """Project one exact post-transition message before the causal A lock."""

    _exact_model(workflow, WorkflowRun, field_name="workflow")
    _exact_model(target_stage, StageRun, field_name="target_stage")
    if causal_stage is not None:
        _exact_model(causal_stage, StageRun, field_name="causal_stage")
    if type(emission_kind) is not str or emission_kind not in _RUNTIME_EMISSION_KINDS:
        raise OutboxValidation("emission_kind is not a runtime stage-ready origin")
    if type(post_status) is not str or post_status not in _CLAIMABLE_STAGE_STATUSES:
        raise OutboxValidation("Projected stage status must be ready or retry_wait")
    version = _state_version(post_state_version, field_name="post_state_version")
    available_at = _aware_datetime(post_next_attempt_at, field_name="post_next_attempt_at")
    target_attempt = _bounded_int(
        target_attempt_number,
        field_name="target_attempt_number",
        minimum=1,
        maximum=20,
    )
    if type(post_error_code) is not str or type(post_error_summary) is not str:
        raise OutboxValidation("Projected stage error facts must be exact strings")
    if type(post_error_retryable) is not bool:
        raise OutboxValidation("Projected stage retryability must be an exact boolean")

    pre_target = _stage_ready_state(target_stage)
    post_target = replace(
        pre_target,
        status=post_status,
        state_version=version,
        next_attempt_at=available_at,
        lease_owner="",
        lease_token=None,
        leased_at=None,
        lease_expires_at=None,
        heartbeat_at=None,
        last_error_code=post_error_code,
        last_error_summary=post_error_summary,
        last_error_retryable=post_error_retryable,
        output_checksum="",
        completed_at=None,
    )
    intent = _make_stage_ready_intent(
        workflow=workflow,
        emission_kind=emission_kind,
        projection_mode="transition",
        allow_create=True,
        pre_target=pre_target,
        post_target=post_target,
        causal_pre_stage=(_stage_ready_state(causal_stage) if causal_stage is not None else None),
        target_attempt_number=target_attempt,
    )
    _assert_transition_projection(intent)
    return intent


async def reserve_stage_ready_intents(
    db: AsyncSession,
    *,
    workflow: WorkflowRun,
    locked_stages: tuple[StageRun, ...],
    target_stages: tuple[StageRun, ...],
    intents: tuple[StageReadyIntent, ...],
) -> StageReadyReservation:
    """Reserve one complete fan-out before locking its causal attempt."""

    transaction = _sync_root_transaction(db)
    _prevalidate_locked_stage_authority(db, workflow, locked_stages)
    stages = _validate_complete_locked_stages(workflow, locked_stages)
    targets = _validate_target_stage_tuple(stages, target_stages)
    if type(intents) is not tuple or len(intents) != len(targets) or not intents:
        raise OutboxValidation("Stage-ready intents must exactly match the target tuple")
    copied = tuple(_copy_stage_ready_intent(intent) for intent in intents)
    for target, intent in zip(targets, copied, strict=True):
        if intent.pre_target.stage_run_id != _persisted_uuid(target.id, field_name="target.id"):
            raise OutboxValidation("Stage-ready intent order disagrees with target stages")
        _assert_intent_pre_authority(workflow, stages, target, intent)
    _assert_fanout_origin(copied)
    _assert_exact_transition_target_set(stages, targets, copied)
    _assert_workflow_has_no_terminalization(
        db,
        transaction,
        copied[0].workflow_run_id,
    )

    if any(intent.emission_kind == "lease_recovered" for intent in copied):
        now = await _db_now(db, autoflush=False)
        for intent in copied:
            if intent.emission_kind != "lease_recovered":
                continue
            causal = intent.causal_pre_stage
            if causal is None or causal.lease_expires_at is None or causal.lease_expires_at > now:
                raise OutboxConflict("Lease recovery intent is not expired at PostgreSQL transaction time")

    ordered = tuple(sorted(copied, key=lambda item: item.logical_key))
    existing_messages: list[OutboxMessage | None] = []
    for intent in ordered:
        existing = await db.scalar(
            select(OutboxMessage)
            .where(
                OutboxMessage.logical_key == intent.logical_key,
                OutboxMessage.redrive_ordinal == 0,
            )
            .order_by(OutboxMessage.logical_key.asc(), OutboxMessage.id.asc())
            .execution_options(populate_existing=True, autoflush=False)
            .with_for_update()
        )
        if existing is not None:
            _require_session_authorities(db, (existing,))
            _assert_existing_intent_authority(existing, intent, causation_id=None, cause_is_deferred=True)
        elif not intent.allow_create:
            raise OutboxConflict("Public causal stage-ready emission is replay-only")
        existing_messages.append(existing)

    active_deliveries: list[OutboxDeliveryAttempt | None] = [None] * len(ordered)
    for index, (_intent, message) in enumerate(zip(ordered, existing_messages, strict=True)):
        if message is None:
            continue
        if message.status not in _ACTIVE_DELIVERY_STATUSES:
            if message.active_delivery_attempt_id is not None:
                raise OutboxStoredContractError("Inactive root message retains an active delivery pointer")
            continue
        if message.active_delivery_attempt_id is None:
            raise OutboxStoredContractError("Active root message has no delivery pointer")
        delivery = await db.scalar(
            select(OutboxDeliveryAttempt)
            .where(
                OutboxDeliveryAttempt.id == message.active_delivery_attempt_id,
                OutboxDeliveryAttempt.message_id == message.id,
            )
            .order_by(OutboxDeliveryAttempt.message_id.asc(), OutboxDeliveryAttempt.id.asc())
            .execution_options(populate_existing=True, autoflush=False)
            .with_for_update()
        )
        if delivery is None:
            raise OutboxStoredContractError("Active root message has no locked delivery evidence")
        _require_session_authorities(db, (delivery,))
        _assert_reserved_active_delivery(message, delivery)
        active_deliveries[index] = delivery

    reservation = StageReadyReservation(
        intents=ordered,
        message_ids=tuple(uuid.uuid4() for _ in ordered),
        existing_messages=tuple(existing_messages),
        active_deliveries=tuple(active_deliveries),
        locked_stage_ids=tuple(_persisted_uuid(stage.id, field_name="locked stage id") for stage in stages),
        locked_stage_states=tuple(_stage_ready_state(stage) for stage in stages),
        _session=db,
        _transaction=transaction,
    )
    _register_stage_ready_reservation(db, transaction, reservation)
    return reservation


async def append_reserved_stage_ready(
    db: AsyncSession,
    *,
    reservation: StageReadyReservation,
    workflow: WorkflowRun,
    locked_stages: tuple[StageRun, ...],
    causal_attempt: StageAttempt | None = None,
) -> tuple[tuple[OutboxMessage, bool], ...]:
    """Append the complete reserved fan-out without a SELECT, lock, or clock."""

    transaction = _sync_root_transaction(db)
    registered_seal = _consume_stage_ready_reservation(db, transaction, reservation)
    reserved = _copy_stage_ready_reservation(reservation)
    if db is not reserved._session or transaction is not reserved._transaction:
        raise OutboxConflict("Stage-ready reservation is outside its original session transaction")
    reserved_suffix = tuple(value for value in (*reserved.existing_messages, *reserved.active_deliveries) if value is not None)
    if reserved_suffix:
        _require_session_authorities(db, reserved_suffix)
    if _stage_ready_reservation_seal(reservation) != registered_seal:
        raise OutboxConflict("Stage-ready reservation capability was mutated after registration")
    _prevalidate_locked_stage_authority(db, workflow, locked_stages)
    stages = _validate_complete_locked_stages(workflow, locked_stages)
    stage_ids = tuple(_persisted_uuid(stage.id, field_name="locked stage id") for stage in stages)
    if stage_ids != reserved.locked_stage_ids:
        raise OutboxConflict("Stage-ready reservation no longer has its complete stage lock set")
    _assert_unmodified_reserved_stages(stages, reserved)

    attempts_required = any(
        intent.emission_kind != "root_ready" and not _is_migration_backfill(message)
        for intent, message in zip(reserved.intents, reserved.existing_messages, strict=True)
    )
    if attempts_required:
        _exact_model(causal_attempt, StageAttempt, field_name="causal_attempt")
        _require_session_authorities(db, (causal_attempt,))
    elif causal_attempt is not None:
        raise OutboxValidation("Root or migration-backfill emission cannot carry a causal attempt")

    results: list[tuple[OutboxMessage, bool]] = []
    by_id = {_persisted_uuid(stage.id, field_name="stage.id"): stage for stage in stages}
    _assert_workflow_post_authority(workflow, reserved.intents)
    for intent, message_id, existing, delivery in zip(
        reserved.intents,
        reserved.message_ids,
        reserved.existing_messages,
        reserved.active_deliveries,
        strict=True,
    ):
        target = by_id.get(intent.post_target.stage_run_id)
        if target is None:
            raise OutboxStoredContractError("Reserved target is absent from the locked stage plan")
        _assert_stage_matches_ready_state(target, intent.post_target, phase="post")
        if intent.emission_kind in {"root_ready", "dependency_ready"} and intent.post_target.attempt_count == 0:
            _assert_empty_never_run_stage_payload(target, intent.post_target)
        cause_id = _validated_intent_causation(
            intent,
            workflow=workflow,
            stages=stages,
            target=target,
            causal_attempt=causal_attempt,
            existing_message=existing,
        )
        if existing is not None:
            _assert_existing_intent_authority(
                existing,
                intent,
                causation_id=cause_id,
                cause_is_deferred=False,
            )
            if delivery is not None:
                _assert_reserved_active_delivery(existing, delivery)
            results.append((existing, False))
            continue
        if delivery is not None:
            raise OutboxStoredContractError("New message reservation unexpectedly has delivery evidence")
        message = _build_stage_ready_message(
            intent,
            message_id=message_id,
            causation_id=cause_id,
        )
        results.append((message, True))
    pending_flush = [message for message, created in results if created]
    if pending_flush:
        for message in pending_flush:
            db.add(message)
        await db.flush(pending_flush)
    return tuple(results)


async def emit_stage_ready(
    db: AsyncSession,
    *,
    workflow_run_id: uuid.UUID,
    stage_run_id: uuid.UUID,
    emission_kind: Literal[
        "root_ready",
        "dependency_ready",
        "retry_scheduled",
        "lease_recovered",
    ],
    causation_id: uuid.UUID | None = None,
) -> tuple[OutboxMessage, bool]:
    """Create root-ready authority or replay one exact existing lineage root."""

    workflow_id = _uuid(workflow_run_id, field_name="workflow_run_id")
    stage_id = _uuid(stage_run_id, field_name="stage_run_id")
    cause_id = _optional_uuid(causation_id, field_name="causation_id")
    if cause_id is not None:
        raise OutboxValidation("Public stage-ready emission cannot accept caller-supplied causation")
    if type(emission_kind) is not str or emission_kind not in _RUNTIME_EMISSION_KINDS:
        raise OutboxValidation("emission_kind is not a runtime stage-ready origin")
    _sync_root_transaction(db)

    workflow = await db.scalar(
        select(WorkflowRun)
        .where(
            WorkflowRun.id == workflow_id,
            WorkflowRun.status.in_(_ACTIVE_WORKFLOW_STATUSES),
        )
        .execution_options(populate_existing=True, autoflush=False)
        .with_for_update()
    )
    if workflow is None:
        raise OutboxNotFound("Active workflow run not found")
    _exact_model(workflow, WorkflowRun, field_name="workflow")
    _require_session_authorities(db, (workflow,))
    stages = await _lock_complete_workflow_stages(db, workflow)
    stage = next(
        (candidate for candidate in stages if _persisted_uuid(candidate.id, field_name="stage.id") == stage_id),
        None,
    )
    if stage is None or stage.status not in _CLAIMABLE_STAGE_STATUSES or stage.next_attempt_at is None:
        raise OutboxConflict("Stage is not currently eligible for stage-ready emission")
    if stage.attempt_count >= stage.max_attempts:
        raise OutboxConflict("Stage has exhausted its attempts")
    expected_kind = _expected_emission_kind(stage)
    if emission_kind != expected_kind:
        raise OutboxConflict(f"Stage facts require {expected_kind!r}, not {emission_kind!r}")

    intent = _make_stage_ready_intent(
        workflow=workflow,
        emission_kind=emission_kind,
        projection_mode="current",
        allow_create=emission_kind == "root_ready",
        pre_target=_stage_ready_state(stage),
        post_target=_stage_ready_state(stage),
        causal_pre_stage=None,
        target_attempt_number=stage.attempt_count + 1,
    )
    reservation = await reserve_stage_ready_intents(
        db,
        workflow=workflow,
        locked_stages=stages,
        target_stages=(stage,),
        intents=(intent,),
    )
    existing = reservation.existing_messages[0]
    causal_attempt: StageAttempt | None = None
    if existing is not None and not _is_migration_backfill(existing) and emission_kind != "root_ready":
        if existing.causation_id is None:
            raise OutboxStoredContractError("Existing causal root has no attempt provenance")
        persisted_cause_id = _persisted_uuid(
            existing.causation_id,
            field_name="existing message causation_id",
        )
        locked_stage_ids = tuple(_persisted_uuid(candidate.id, field_name="locked stage id") for candidate in stages)
        causal_attempt = await db.scalar(
            select(StageAttempt)
            .where(
                StageAttempt.id == persisted_cause_id,
                StageAttempt.stage_run_id.in_(locked_stage_ids),
            )
            .execution_options(populate_existing=True, autoflush=False)
            .with_for_update()
        )
        if causal_attempt is None:
            raise OutboxStoredContractError("Existing causal root has no locked attempt provenance")
    results = await append_reserved_stage_ready(
        db,
        reservation=reservation,
        workflow=workflow,
        locked_stages=stages,
        causal_attempt=causal_attempt,
    )
    return results[0]


async def receipt_and_claim_stage(
    db: AsyncSession,
    *,
    command: StageReceiptCommand,
) -> PendingReceiptActivation:
    """Atomically receipt one delivery and activate its exact workflow stage.

    All command facts are bounded before the first query.  Existing authority
    is then locked in canonical ``Workflow -> Stage -> Message -> Delivery``
    order.  The delivery and message are terminalized before the stage becomes
    running, so a linked ``StageAttempt`` can be inserted under both database
    guards in the same caller-owned transaction.
    """

    receipt = _copy_receipt_command(command)
    claim = receipt.claim
    payload = claim._normalized_envelope().envelope.payload

    workflow, stage, message, delivery = await _lock_receipt_authority(
        db,
        workflow_run_id=payload.workflow_run_id,
        stage_run_id=payload.stage_run_id,
        message_id=claim.message_id,
        delivery_attempt_id=claim.delivery_attempt_id,
    )
    _assert_receipt_lineage(
        workflow,
        stage,
        message,
        delivery,
        claim=claim,
    )

    if delivery.status in {"failed", "abandoned"}:
        _assert_stale_receipt_disposition(
            message,
            delivery,
            claim=claim,
            broker_name=receipt.broker_name,
            broker_message_id=receipt.broker_message_id,
        )
        return _pending_receipt_activation(
            workflow=workflow,
            stage=stage,
            attempt=None,
            message=message,
            delivery=delivery,
            broker_receipt_id=receipt.broker_receipt_id,
            disposition="stale",
            commit_ticket=None,
        )

    if message.status == "cancelled" and delivery.status == "cancelled":
        _assert_cancelled_receipt_disposition(
            message,
            delivery,
            claim=claim,
            broker_name=receipt.broker_name,
            broker_message_id=receipt.broker_message_id,
        )
        return _pending_receipt_activation(
            workflow=workflow,
            stage=stage,
            attempt=None,
            message=message,
            delivery=delivery,
            broker_receipt_id=receipt.broker_receipt_id,
            disposition="cancelled",
            commit_ticket=None,
        )

    if message.status == "delivered" and delivery.status == "delivered":
        _assert_latest_delivery_lineage(message, delivery)
        _assert_receipt_replay(
            message,
            delivery,
            claim=claim,
            broker_name=receipt.broker_name,
            broker_message_id=receipt.broker_message_id,
            broker_receipt_id=receipt.broker_receipt_id,
        )
        attempt = await _lock_receipt_stage_attempt(
            db,
            stage=stage,
            message=message,
            delivery=delivery,
        )
        return _pending_receipt_activation(
            workflow=workflow,
            stage=stage,
            attempt=attempt,
            message=message,
            delivery=delivery,
            broker_receipt_id=receipt.broker_receipt_id,
            disposition="replayed",
            commit_ticket=None,
        )

    if message.status not in _ACTIVE_DELIVERY_STATUSES or delivery.status != message.status:
        raise OutboxLeaseLost("Delivery is no longer an active receipt authority")
    _assert_latest_delivery_lineage(message, delivery)
    now = await _db_clock_now(db)
    _assert_live_receipt_authority(
        workflow,
        stage,
        message,
        delivery,
        claim=claim,
        broker_name=receipt.broker_name,
        broker_message_id=receipt.broker_message_id,
        now=now,
    )
    transaction_id = await _db_transaction_id(db)

    delivery.status = "delivered"
    delivery.state_version += 1
    delivery.broker_name = receipt.broker_name
    delivery.broker_message_id = receipt.broker_message_id
    delivery.broker_receipt_id = receipt.broker_receipt_id
    delivery.dispatched_at = delivery.dispatched_at or now
    delivery.receipt_deadline_at = None
    delivery.receipt_received_at = now
    delivery.completed_at = now
    await db.flush([delivery])

    message.status = "delivered"
    message.state_version += 1
    message.available_at = None
    message.active_delivery_attempt_id = None
    message.lease_owner = ""
    message.lease_token = None
    message.leased_at = None
    message.heartbeat_at = None
    message.lease_expires_at = None
    message.receipt_deadline_at = None
    message.delivered_at = now
    await db.flush([message])

    stage_lease_token = _fresh_stage_lease_token(delivery.delivery_token)
    lease_expires_at = now + timedelta(seconds=receipt.lease_seconds)
    workflow_was_queued = workflow.status == "queued"
    if workflow_was_queued:
        workflow.status = "running"
        workflow.state_version += 1
        workflow.started_at = now

    stage.status = "running"
    stage.state_version += 1
    stage.attempt_count += 1
    stage.next_attempt_at = None
    stage.lease_owner = receipt.worker_id
    stage.lease_token = stage_lease_token
    stage.leased_at = now
    stage.heartbeat_at = now
    stage.lease_expires_at = lease_expires_at
    stage.last_error_code = ""
    stage.last_error_summary = ""
    stage.last_error_retryable = False
    stage.first_started_at = stage.first_started_at or now
    stage.completed_at = None
    await db.flush([workflow, stage] if workflow_was_queued else [stage])

    attempt = StageAttempt(
        id=uuid.uuid4(),
        stage_run_id=stage.id,
        outbox_delivery_attempt_id=delivery.id,
        attempt_number=stage.attempt_count,
        lease_token=stage_lease_token,
        lease_owner=receipt.worker_id,
        delivery_id=claim.cycle_key,
        status="running",
        state_version=1,
        input_checksum=stage.input_checksum,
        checkpoint_start_version=stage.checkpoint_version,
        checkpoint_end_version=stage.checkpoint_version,
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
    commit_ticket = _mint_commit_ticket(
        workflow=workflow,
        stage=stage,
        message=message,
        delivery=delivery,
        attempt=attempt,
        origin_transaction_id=transaction_id,
    )
    return _pending_receipt_activation(
        workflow=workflow,
        stage=stage,
        attempt=attempt,
        message=message,
        delivery=delivery,
        broker_receipt_id=receipt.broker_receipt_id,
        disposition="activated",
        commit_ticket=commit_ticket,
    )


async def confirm_committed_activation(
    db: AsyncSession,
    *,
    commit_ticket: str,
) -> ExecutableStageAuthority | None:
    """Return executable authority only after the receipt transaction ended.

    The ticket carries the complete row identity and originating PostgreSQL
    transaction ID under an HMAC keyed by the private stage lease token.  A
    caller invoking confirmation from the receipt transaction is rejected;
    missing, rolled-back, terminal, or expired authority returns ``None``.
    """

    ticket = _commit_ticket(commit_ticket)
    coordinates = _decode_commit_ticket(ticket)
    current_transaction_id = await _db_transaction_id(db)
    if current_transaction_id == coordinates.origin_transaction_id:
        raise OutboxConflict("Receipt activation must commit before confirmation")

    workflow, stage, message, delivery = await _lock_receipt_authority(
        db,
        workflow_run_id=coordinates.workflow_run_id,
        stage_run_id=coordinates.stage_run_id,
        message_id=coordinates.message_id,
        delivery_attempt_id=coordinates.delivery_attempt_id,
        missing_is_none=True,
    )
    if workflow is None:
        return None
    attempt = await db.scalar(
        select(StageAttempt)
        .where(
            StageAttempt.id == coordinates.stage_attempt_id,
            StageAttempt.stage_run_id == stage.id,
            StageAttempt.outbox_delivery_attempt_id == delivery.id,
        )
        .execution_options(populate_existing=True, autoflush=False)
        .with_for_update()
    )
    if attempt is None:
        return None
    now = await _db_clock_now(db)
    if not _is_live_committed_activation(
        workflow,
        stage,
        message,
        delivery,
        attempt,
        now=now,
    ):
        return None
    expected_ticket = _mint_commit_ticket(
        workflow=workflow,
        stage=stage,
        message=message,
        delivery=delivery,
        attempt=attempt,
        origin_transaction_id=coordinates.origin_transaction_id,
    )
    if not hmac.compare_digest(expected_ticket, ticket):
        raise OutboxLeaseLost("Commit ticket does not match durable activation authority")
    return _executable_stage_authority(
        workflow=workflow,
        stage=stage,
        message=message,
        delivery=delivery,
        attempt=attempt,
    )


async def reserve_stage_execution_receipt(
    db: AsyncSession,
    *,
    authority: ExecutableStageAuthority,
) -> StageExecutionReceiptReservation:
    """Lock and prove one live worker's exact delivered receipt lineage.

    The detached authority is fully copied before the first query.  Rows are
    then locked in canonical ``W -> S -> M -> D -> A`` order.  Wall-clock
    liveness is checked only after the complete lock set is held, so a lock
    wait cannot preserve an expired worker lease.

    This function is read/lock-only and never flushes or commits.  Callers must
    consume the returned reservation before mutating any contained row.
    """

    credential = _copy_executable_stage_authority(authority)
    _preflight_stage_execution_session(db)

    workflow = await db.scalar(
        select(WorkflowRun)
        .where(WorkflowRun.id == credential.workflow_run_id)
        .execution_options(populate_existing=True, autoflush=False)
        .with_for_update()
    )
    if workflow is None:
        raise OutboxLeaseLost("Stage execution workflow authority is no longer live")
    transaction = _stage_execution_root_transaction(db)
    _assert_stage_execution_coordinate_available(db, transaction, credential)

    stage = await db.scalar(
        select(StageRun)
        .where(
            StageRun.id == credential.stage_run_id,
            StageRun.workflow_run_id == credential.workflow_run_id,
        )
        .execution_options(populate_existing=True, autoflush=False)
        .with_for_update()
    )
    if stage is None:
        raise OutboxLeaseLost("Stage execution stage authority is no longer live")

    message = await db.scalar(
        select(OutboxMessage)
        .where(
            OutboxMessage.id == credential.message_id,
            OutboxMessage.workflow_run_id == credential.workflow_run_id,
            OutboxMessage.stage_run_id == credential.stage_run_id,
        )
        .execution_options(populate_existing=True, autoflush=False)
        .with_for_update()
    )
    if message is None:
        raise OutboxLeaseLost("Stage execution message authority is no longer live")

    delivery = await db.scalar(
        select(OutboxDeliveryAttempt)
        .where(
            OutboxDeliveryAttempt.id == credential.delivery_attempt_id,
            OutboxDeliveryAttempt.message_id == credential.message_id,
        )
        .execution_options(populate_existing=True, autoflush=False)
        .with_for_update()
    )
    if delivery is None:
        raise OutboxLeaseLost("Stage execution delivery authority is no longer live")

    attempt = await db.scalar(
        select(StageAttempt)
        .where(
            StageAttempt.id == credential.stage_attempt_id,
            StageAttempt.stage_run_id == credential.stage_run_id,
        )
        .execution_options(populate_existing=True, autoflush=False)
        .with_for_update()
    )
    if attempt is None:
        raise OutboxLeaseLost("Stage execution attempt authority is no longer live")

    observed_at = await _db_clock_now(db)
    _assert_stage_execution_receipt(
        db,
        authority=credential,
        workflow=workflow,
        stage=stage,
        message=message,
        delivery=delivery,
        attempt=attempt,
        observed_at=observed_at,
    )
    if _stage_execution_root_transaction(db) is not transaction:
        raise OutboxConflict("Stage execution receipt changed root transaction while locking authority")

    reservation = StageExecutionReceiptReservation(
        authority=credential,
        workflow=workflow,
        stage=stage,
        message=message,
        delivery=delivery,
        attempt=attempt,
        observed_at=observed_at,
        _session=db,
        _transaction=transaction,
    )
    _register_stage_execution_receipt(db, transaction, reservation)
    return reservation


async def consume_stage_execution_receipt(
    db: AsyncSession,
    *,
    reservation: StageExecutionReceiptReservation,
    authority: ExecutableStageAuthority,
) -> LockedStageExecutionReceipt:
    """Consume one reservation against a fresh PostgreSQL wall-clock reading.

    The capability is permanently spent before the clock query or any durable
    validation.  A failed consume therefore cannot be retried in the same root
    transaction.  The function remains read/lock-only and never flushes or
    commits.
    """

    credential = _copy_executable_stage_authority(authority)
    transaction = _stage_execution_root_transaction(db)
    registered_seal = _consume_stage_execution_receipt_registration(
        db,
        transaction,
        reservation,
    )
    if db is not reservation._session or transaction is not reservation._transaction:
        raise OutboxConflict("Stage execution receipt is outside its original session transaction")
    if credential != reservation.authority:
        raise OutboxLeaseLost("Stage execution authority changed after receipt reservation")
    _require_stage_execution_authorities(
        db,
        (
            reservation.workflow,
            reservation.stage,
            reservation.message,
            reservation.delivery,
            reservation.attempt,
        ),
    )
    if _stage_execution_receipt_reservation_seal(reservation) != registered_seal:
        raise OutboxConflict("Stage execution receipt reservation was mutated after registration")
    observed_at = await _db_clock_now(db)
    if observed_at < reservation.observed_at:
        raise OutboxStoredContractError("PostgreSQL wall clock moved backwards across receipt consumption")
    if _stage_execution_root_transaction(db) is not transaction:
        raise OutboxConflict("Stage execution receipt changed root transaction while consuming authority")
    _assert_stage_execution_receipt(
        db,
        authority=credential,
        workflow=reservation.workflow,
        stage=reservation.stage,
        message=reservation.message,
        delivery=reservation.delivery,
        attempt=reservation.attempt,
        observed_at=observed_at,
    )
    return LockedStageExecutionReceipt(
        authority=credential,
        workflow=reservation.workflow,
        stage=reservation.stage,
        message=reservation.message,
        delivery=reservation.delivery,
        attempt=reservation.attempt,
        observed_at=observed_at,
    )


async def reserve_stage_completion_graph(
    db: AsyncSession,
    *,
    authority: ExecutableStageAuthority,
) -> StageCompletionReservation:
    """Reserve one exact completion graph in global authority-lock order.

    The operation is read/lock-only.  It locks ``W -> all S`` in canonical
    plan order, discovers target logical roots without populating ORM state,
    locks the union of source and target ``M``/``D`` rows by UUID, locks the
    source ``A`` last, and only then reads PostgreSQL wall-clock time.
    """

    credential = _copy_executable_stage_authority(authority)
    transaction = _stage_execution_root_transaction(db)
    _assert_workflow_has_no_terminalization(
        db,
        transaction,
        credential.workflow_run_id,
    )
    _assert_stage_execution_coordinate_available(db, transaction, credential)

    workflow = await db.scalar(
        select(WorkflowRun)
        .where(WorkflowRun.id == credential.workflow_run_id)
        .execution_options(populate_existing=True, autoflush=False)
        .with_for_update()
    )
    if workflow is None:
        raise OutboxLeaseLost("Stage completion workflow authority is no longer live")
    plan = _workflow_plan_order(workflow)
    stage_rows = await db.execute(
        select(StageRun)
        .where(StageRun.workflow_run_id == credential.workflow_run_id)
        .order_by(StageRun.ordinal.asc(), StageRun.id.asc())
        .execution_options(populate_existing=True, autoflush=False)
        .with_for_update()
    )
    loaded_stages = tuple(stage_rows.scalars().all())
    if not loaded_stages or len(loaded_stages) != len(plan):
        raise OutboxStoredContractError("Stage completion rows are not the exact persisted workflow plan")
    try:
        locked_stages = _validate_complete_locked_stages(workflow, loaded_stages)
    except (OutboxConflict, OutboxValidation) as exc:
        raise OutboxStoredContractError("Stage completion rows contradict the persisted workflow plan") from exc
    source_index = next(
        (index for index, stage in enumerate(locked_stages) if _persisted_uuid(stage.id, field_name="stage.id") == credential.stage_run_id),
        None,
    )
    if source_index is None:
        raise OutboxLeaseLost("Stage completion source is absent from its locked workflow plan")
    source = locked_stages[source_index]
    stage_states = tuple(_stage_ready_state(stage) for stage in locked_stages)
    causal_source = stage_states[source_index]
    targets = _completion_targets(locked_stages, source=source)
    target_projections = tuple(_stage_completion_target_projection(workflow, target) for target in targets)
    _assert_unique_completion_projection_keys(target_projections, stored=True)

    discovered_target_ids: list[uuid.UUID | None] = []
    for projection in target_projections:
        discovered = await db.scalar(
            select(OutboxMessage.id)
            .where(
                OutboxMessage.logical_key == projection.logical_key,
                OutboxMessage.redrive_ordinal == 0,
            )
            .order_by(OutboxMessage.id.asc())
            .execution_options(autoflush=False)
        )
        discovered_target_ids.append(
            _persisted_uuid(discovered, field_name="discovered target message id") if discovered is not None else None
        )

    target_message_ids = tuple(discovered if discovered is not None else uuid.uuid4() for discovered in discovered_target_ids)
    _assert_completion_message_id_partition(
        source_message_id=credential.message_id,
        target_message_ids=target_message_ids,
    )
    locked_message_ids = tuple(
        sorted(
            (credential.message_id, *(value for value in discovered_target_ids if value is not None)),
            key=lambda value: value.int,
        )
    )
    locked_messages_list: list[OutboxMessage] = []
    for message_id in locked_message_ids:
        message = await db.scalar(
            select(OutboxMessage)
            .where(OutboxMessage.id == message_id)
            .execution_options(populate_existing=True, autoflush=False)
            .with_for_update()
        )
        if message is None:
            if message_id == credential.message_id:
                raise OutboxLeaseLost("Stage completion source message authority is no longer live")
            raise OutboxStoredContractError("Discovered completion target message disappeared before lock")
        locked_messages_list.append(message)
    locked_messages = tuple(locked_messages_list)
    messages_by_id = {_persisted_uuid(message.id, field_name="locked message id"): message for message in locked_messages}
    source_message = messages_by_id.get(credential.message_id)
    if source_message is None:
        raise OutboxLeaseLost("Stage completion source message was not locked")
    existing_target_messages = tuple(
        messages_by_id.get(message_id) if discovered is not None else None
        for message_id, discovered in zip(target_message_ids, discovered_target_ids, strict=True)
    )
    for projection, discovered, message in zip(
        target_projections,
        discovered_target_ids,
        existing_target_messages,
        strict=True,
    ):
        if discovered is not None and (
            message is None
            or _persisted_uuid(message.id, field_name="locked target message id") != discovered
            or message.logical_key != projection.logical_key
            or message.redrive_ordinal != 0
        ):
            raise OutboxStoredContractError("Discovered completion target message changed logical authority")

    target_active_delivery_ids: list[uuid.UUID | None] = []
    for message in existing_target_messages:
        if message is None or message.status not in _ACTIVE_DELIVERY_STATUSES:
            if message is not None and message.active_delivery_attempt_id is not None:
                raise OutboxStoredContractError("Inactive completion target message retains an active delivery pointer")
            target_active_delivery_ids.append(None)
            continue
        if message.active_delivery_attempt_id is None:
            raise OutboxStoredContractError("Active completion target message has no delivery pointer")
        target_active_delivery_ids.append(_persisted_uuid(message.active_delivery_attempt_id, field_name="target active delivery id"))
    _assert_completion_delivery_id_partition(
        source_delivery_id=credential.delivery_attempt_id,
        target_delivery_ids=tuple(target_active_delivery_ids),
    )
    locked_delivery_ids = tuple(
        sorted(
            (credential.delivery_attempt_id, *(value for value in target_active_delivery_ids if value is not None)),
            key=lambda value: value.int,
        )
    )
    locked_deliveries_list: list[OutboxDeliveryAttempt] = []
    for delivery_id in locked_delivery_ids:
        delivery = await db.scalar(
            select(OutboxDeliveryAttempt)
            .where(OutboxDeliveryAttempt.id == delivery_id)
            .execution_options(populate_existing=True, autoflush=False)
            .with_for_update()
        )
        if delivery is None:
            if delivery_id == credential.delivery_attempt_id:
                raise OutboxLeaseLost("Stage completion source delivery authority is no longer live")
            raise OutboxStoredContractError("Active completion target delivery disappeared before lock")
        locked_deliveries_list.append(delivery)
    locked_deliveries = tuple(locked_deliveries_list)
    deliveries_by_id = {_persisted_uuid(delivery.id, field_name="locked delivery id"): delivery for delivery in locked_deliveries}
    source_delivery = deliveries_by_id.get(credential.delivery_attempt_id)
    if source_delivery is None:
        raise OutboxLeaseLost("Stage completion source delivery was not locked")
    active_target_deliveries = tuple(
        deliveries_by_id.get(delivery_id) if delivery_id is not None else None for delivery_id in target_active_delivery_ids
    )

    source_attempt = await db.scalar(
        select(StageAttempt)
        .where(
            StageAttempt.id == credential.stage_attempt_id,
            StageAttempt.stage_run_id == credential.stage_run_id,
        )
        .execution_options(populate_existing=True, autoflush=False)
        .with_for_update()
    )
    if source_attempt is None:
        raise OutboxLeaseLost("Stage completion attempt authority is no longer live")

    observed_at = await _db_clock_now(db)
    _assert_stage_completion_graph(
        db,
        authority=credential,
        workflow=workflow,
        stages=locked_stages,
        stage_states=stage_states,
        source_index=source_index,
        causal_source=causal_source,
        target_projections=target_projections,
        target_message_ids=target_message_ids,
        existing_target_messages=existing_target_messages,
        active_target_deliveries=active_target_deliveries,
        locked_messages=locked_messages,
        locked_message_ids=locked_message_ids,
        locked_deliveries=locked_deliveries,
        locked_delivery_ids=locked_delivery_ids,
        source_attempt=source_attempt,
        observed_at=observed_at,
    )
    if _stage_execution_root_transaction(db) is not transaction:
        raise OutboxConflict("Stage completion graph changed root transaction while locking authority")

    reservation = StageCompletionReservation(
        authority=credential,
        workflow=workflow,
        stages=locked_stages,
        stage_states=stage_states,
        source_stage_id=credential.stage_run_id,
        source_stage_index=source_index,
        causal_source=causal_source,
        target_projections=target_projections,
        target_message_ids=target_message_ids,
        existing_target_messages=existing_target_messages,
        active_target_deliveries=active_target_deliveries,
        locked_messages=locked_messages,
        locked_message_ids=locked_message_ids,
        locked_deliveries=locked_deliveries,
        locked_delivery_ids=locked_delivery_ids,
        source_attempt=source_attempt,
        observed_at=observed_at,
        _session=db,
        _transaction=transaction,
    )
    _register_stage_completion_reservation(db, transaction, reservation)
    return reservation


async def consume_stage_completion_graph(
    db: AsyncSession,
    *,
    reservation: StageCompletionReservation,
    authority: ExecutableStageAuthority,
) -> LockedStageCompletionGraph:
    """Spend a completion reservation and re-prove it at a fresh DB clock."""

    credential = _copy_executable_stage_authority(authority)
    transaction = _stage_execution_root_transaction(db)
    completion_registration = _consume_stage_completion_registration(
        db,
        transaction,
        reservation,
    )
    if db is not reservation._session or transaction is not reservation._transaction:
        raise OutboxConflict("Stage completion reservation is outside its original session transaction")
    if credential != reservation.authority:
        raise OutboxLeaseLost("Stage completion authority changed after graph reservation")
    _require_stage_execution_authorities(
        db,
        (
            reservation.workflow,
            *reservation.stages,
            *reservation.locked_messages,
            *reservation.locked_deliveries,
            reservation.source_attempt,
        ),
    )
    if _stage_completion_reservation_seal(reservation) != completion_registration.seal:
        raise OutboxConflict("Stage completion reservation capability was mutated after registration")
    observed_at = await _db_clock_now(db)
    if observed_at < reservation.observed_at:
        raise OutboxStoredContractError("PostgreSQL wall clock moved backwards across completion consumption")
    if _stage_execution_root_transaction(db) is not transaction:
        raise OutboxConflict("Stage completion graph changed root transaction while consuming authority")
    _assert_stage_completion_graph(
        db,
        authority=credential,
        workflow=reservation.workflow,
        stages=reservation.stages,
        stage_states=reservation.stage_states,
        source_index=reservation.source_stage_index,
        causal_source=reservation.causal_source,
        target_projections=reservation.target_projections,
        target_message_ids=reservation.target_message_ids,
        existing_target_messages=reservation.existing_target_messages,
        active_target_deliveries=reservation.active_target_deliveries,
        locked_messages=reservation.locked_messages,
        locked_message_ids=reservation.locked_message_ids,
        locked_deliveries=reservation.locked_deliveries,
        locked_delivery_ids=reservation.locked_delivery_ids,
        source_attempt=reservation.source_attempt,
        observed_at=observed_at,
    )
    intents = tuple(
        _completion_stage_ready_intent(
            reservation.workflow,
            projection,
            causal_source=reservation.causal_source,
            observed_at=observed_at,
        )
        for projection in reservation.target_projections
    )
    stage_ready_reservation = _completion_stage_ready_reservation(
        db,
        transaction,
        stages=reservation.stages,
        stage_states=reservation.stage_states,
        intents=intents,
        message_ids=reservation.target_message_ids,
    )
    locked = LockedStageCompletionGraph(
        authority=credential,
        workflow=reservation.workflow,
        stages=reservation.stages,
        stage_states=reservation.stage_states,
        source_stage_id=reservation.source_stage_id,
        source_stage_index=reservation.source_stage_index,
        causal_source=reservation.causal_source,
        target_projections=reservation.target_projections,
        target_message_ids=reservation.target_message_ids,
        existing_target_messages=reservation.existing_target_messages,
        active_target_deliveries=reservation.active_target_deliveries,
        locked_messages=reservation.locked_messages,
        locked_message_ids=reservation.locked_message_ids,
        locked_deliveries=reservation.locked_deliveries,
        locked_delivery_ids=reservation.locked_delivery_ids,
        source_attempt=reservation.source_attempt,
        intents=intents,
        stage_ready_reservation=stage_ready_reservation,
        observed_at=observed_at,
    )
    if stage_ready_reservation is not None:
        _register_transferred_stage_ready_reservation(
            db,
            transaction,
            completion_reservation=reservation,
            completion_registration=completion_registration,
            stage_ready_reservation=stage_ready_reservation,
        )
    return locked


async def _lock_all_terminalization_stages(
    db: AsyncSession,
    workflow: WorkflowRun,
) -> tuple[StageRun, ...]:
    rows = await db.execute(
        select(StageRun)
        .where(StageRun.workflow_run_id == workflow.id)
        .order_by(StageRun.ordinal.asc(), StageRun.id.asc())
        .execution_options(populate_existing=True, autoflush=False)
        .with_for_update()
    )
    loaded = tuple(rows.scalars().all())
    try:
        return _validate_complete_locked_stages(workflow, loaded)
    except (OutboxConflict, OutboxValidation) as exc:
        raise OutboxStoredContractError("Terminalization stages contradict the complete persisted workflow plan") from exc


async def _project_running_attempt_receipts(
    db: AsyncSession,
    workflow: WorkflowRun,
) -> tuple[tuple[uuid.UUID, ...], tuple[uuid.UUID, ...], tuple[uuid.UUID, ...]]:
    rows = await db.execute(
        select(StageAttempt.id)
        .join(StageRun, StageRun.id == StageAttempt.stage_run_id)
        .where(
            StageRun.workflow_run_id == workflow.id,
            StageAttempt.status == "running",
        )
        .order_by(StageAttempt.id.asc())
        .execution_options(autoflush=False)
    )
    attempt_ids = tuple(_persisted_uuid(value, field_name="projected running attempt id") for value in rows.scalars().all())
    if attempt_ids != tuple(sorted(attempt_ids, key=lambda value: value.int)) or len(set(attempt_ids)) != len(attempt_ids):
        raise OutboxStoredContractError("Running attempt projection is not unique UUID order")
    delivery_ids: list[uuid.UUID] = []
    message_ids: list[uuid.UUID] = []
    for attempt_id in attempt_ids:
        delivery_id = await db.scalar(
            select(StageAttempt.outbox_delivery_attempt_id).where(StageAttempt.id == attempt_id).execution_options(autoflush=False)
        )
        if delivery_id is None:
            raise OutboxStoredContractError("Running stage attempt has no receipt delivery projection")
        delivery_key = _persisted_uuid(
            delivery_id,
            field_name="projected running receipt delivery id",
        )
        message_id = await db.scalar(
            select(OutboxDeliveryAttempt.message_id).where(OutboxDeliveryAttempt.id == delivery_key).execution_options(autoflush=False)
        )
        if message_id is None:
            raise OutboxStoredContractError("Running stage receipt has no source message projection")
        delivery_ids.append(delivery_key)
        message_ids.append(
            _persisted_uuid(
                message_id,
                field_name="projected running receipt message id",
            )
        )
    if len(set(delivery_ids)) != len(delivery_ids) or len(set(message_ids)) != len(message_ids):
        raise OutboxStoredContractError("Running stage receipt projections collide")
    return attempt_ids, tuple(delivery_ids), tuple(message_ids)


async def _project_live_workflow_message_ids(
    db: AsyncSession,
    workflow: WorkflowRun,
) -> tuple[uuid.UUID, ...]:
    rows = await db.execute(
        select(OutboxMessage.id)
        .where(
            OutboxMessage.workflow_run_id == workflow.id,
            OutboxMessage.status.in_((*_CLAIMABLE_MESSAGE_STATUSES, *_ACTIVE_DELIVERY_STATUSES)),
        )
        .order_by(OutboxMessage.id.asc())
        .execution_options(autoflush=False)
    )
    identities = tuple(_persisted_uuid(value, field_name="projected live workflow message id") for value in rows.scalars().all())
    if identities != tuple(sorted(identities, key=lambda value: value.int)) or len(set(identities)) != len(identities):
        raise OutboxStoredContractError("Live workflow message projection is not unique UUID order")
    return identities


async def _lock_message_union(
    db: AsyncSession,
    message_ids: tuple[uuid.UUID, ...],
) -> tuple[OutboxMessage, ...]:
    messages: list[OutboxMessage] = []
    for message_id in message_ids:
        message = await db.scalar(
            select(OutboxMessage)
            .where(OutboxMessage.id == message_id)
            .execution_options(populate_existing=True, autoflush=False)
            .with_for_update()
        )
        if message is None:
            raise OutboxStoredContractError("Projected workflow message disappeared before lock")
        messages.append(message)
    return tuple(messages)


def _active_delivery_ids_for_live_messages(
    messages: tuple[OutboxMessage, ...],
    live_message_ids: tuple[uuid.UUID, ...],
) -> tuple[uuid.UUID, ...]:
    by_id = {_persisted_uuid(message.id, field_name="locked workflow message id"): message for message in messages}
    active: list[uuid.UUID] = []
    for message_id in live_message_ids:
        message = by_id.get(message_id)
        if message is None:
            raise OutboxStoredContractError("Projected live workflow message disappeared from locked union")
        if message.status in _ACTIVE_DELIVERY_STATUSES:
            if message.active_delivery_attempt_id is None:
                raise OutboxStoredContractError("Active workflow message has no delivery pointer")
            active.append(
                _persisted_uuid(
                    message.active_delivery_attempt_id,
                    field_name="live workflow active delivery id",
                )
            )
        elif message.status in _CLAIMABLE_MESSAGE_STATUSES:
            if message.active_delivery_attempt_id is not None:
                raise OutboxStoredContractError("Idle workflow message retains an active delivery pointer")
        else:
            raise OutboxStoredContractError("Projected live workflow message changed status before lock")
    if len(set(active)) != len(active):
        raise OutboxStoredContractError("Live workflow active delivery projections collide")
    return tuple(sorted(active, key=lambda value: value.int))


async def _lock_delivery_union(
    db: AsyncSession,
    delivery_ids: tuple[uuid.UUID, ...],
) -> tuple[OutboxDeliveryAttempt, ...]:
    deliveries: list[OutboxDeliveryAttempt] = []
    for delivery_id in delivery_ids:
        delivery = await db.scalar(
            select(OutboxDeliveryAttempt)
            .where(OutboxDeliveryAttempt.id == delivery_id)
            .execution_options(populate_existing=True, autoflush=False)
            .with_for_update()
        )
        if delivery is None:
            raise OutboxStoredContractError("Projected workflow delivery disappeared before lock")
        deliveries.append(delivery)
    return tuple(deliveries)


async def _lock_attempt_union(
    db: AsyncSession,
    attempt_ids: tuple[uuid.UUID, ...],
) -> tuple[StageAttempt, ...]:
    attempts: list[StageAttempt] = []
    for attempt_id in attempt_ids:
        attempt = await db.scalar(
            select(StageAttempt)
            .where(StageAttempt.id == attempt_id)
            .execution_options(populate_existing=True, autoflush=False)
            .with_for_update()
        )
        if attempt is None:
            raise OutboxStoredContractError("Projected running attempt disappeared before lock")
        attempts.append(attempt)
    return tuple(attempts)


def _assert_terminalization_graph_rows(
    db: AsyncSession,
    *,
    workflow: WorkflowRun,
    rows: _TerminalizationGraphRows,
) -> None:
    _require_stage_execution_authorities(
        db,
        (
            workflow,
            *rows.stages,
            *rows.locked_messages,
            *rows.locked_deliveries,
            *rows.locked_attempts,
        ),
    )
    complete = _validate_complete_locked_stages(workflow, rows.stages)
    now = _aware_datetime(rows.observed_at, field_name="terminalization observed_at")
    tx_at = _aware_datetime(rows.transaction_at, field_name="terminalization transaction_at")
    if tx_at > now:
        raise OutboxStoredContractError("Terminalization transaction clock is later than its wall clock")
    try:
        workflow_created_at = _aware_datetime(
            workflow.created_at,
            field_name="terminalization workflow created_at",
        )
        workflow_updated_at = _aware_datetime(
            workflow.updated_at,
            field_name="terminalization workflow updated_at",
        )
        workflow_started_at = (
            _aware_datetime(
                workflow.started_at,
                field_name="terminalization workflow started_at",
            )
            if workflow.started_at is not None
            else None
        )
        workflow_completed_at = (
            _aware_datetime(
                workflow.completed_at,
                field_name="terminalization workflow completed_at",
            )
            if workflow.completed_at is not None
            else None
        )
        workflow_cancelled_at = (
            _aware_datetime(
                workflow.cancel_requested_at,
                field_name="terminalization workflow cancel_requested_at",
            )
            if workflow.cancel_requested_at is not None
            else None
        )
    except OutboxValidation as exc:
        raise OutboxStoredContractError("Terminalization workflow chronology is invalid") from exc
    historical = tuple(
        value
        for value in (
            workflow_created_at,
            workflow_updated_at,
            workflow_started_at,
            workflow_completed_at,
            workflow_cancelled_at,
        )
        if value is not None
    )
    if (
        workflow_created_at > workflow_updated_at
        or any(value > now for value in historical)
        or (workflow_started_at is not None and workflow_started_at < workflow_created_at)
        or (workflow_completed_at is not None and workflow_started_at is not None and workflow_completed_at < workflow_started_at)
        or (workflow_cancelled_at is not None and (workflow_completed_at is None or workflow_completed_at < workflow_cancelled_at))
    ):
        raise OutboxStoredContractError("Terminalization workflow chronology is inconsistent")
    for stage in complete:
        _assert_completion_stage_chronology(stage, observed_at=now)
    if tuple(_stage_ready_state(stage) for stage in complete) != rows.stage_states:
        raise OutboxConflict("Terminalization stage authority changed after graph reservation")
    messages_by_id = {
        _persisted_uuid(message.id, field_name="terminalization locked message id"): message for message in rows.locked_messages
    }
    deliveries_by_id = {
        _persisted_uuid(delivery.id, field_name="terminalization locked delivery id"): delivery for delivery in rows.locked_deliveries
    }
    attempts_by_id = {
        _persisted_uuid(attempt.id, field_name="terminalization locked attempt id"): attempt for attempt in rows.locked_attempts
    }
    if (
        tuple(messages_by_id) != rows.locked_message_ids
        or tuple(deliveries_by_id) != rows.locked_delivery_ids
        or tuple(attempts_by_id) != rows.locked_attempt_ids
    ):
        raise OutboxConflict("Terminalization union authority changed identity or UUID order")
    running_stages = tuple(stage for stage in complete if stage.status == "running")
    attempts_by_stage = {
        _persisted_uuid(attempt.stage_run_id, field_name="terminalization attempt stage id"): attempt for attempt in rows.locked_attempts
    }
    running_stage_ids = {_persisted_uuid(stage.id, field_name="terminalization running stage id") for stage in running_stages}
    if set(attempts_by_stage) != running_stage_ids or len(attempts_by_stage) != len(rows.locked_attempts):
        raise OutboxStoredContractError("Current running attempts are not bijective with running stages")
    receipt_message_ids: set[uuid.UUID] = set()
    receipt_delivery_ids: set[uuid.UUID] = set()
    for stage in running_stages:
        stage_id = _persisted_uuid(stage.id, field_name="terminalization running stage id")
        attempt = attempts_by_stage[stage_id]
        if attempt.outbox_delivery_attempt_id is None:
            raise OutboxStoredContractError("Running stage attempt has no receipt-bound delivery")
        delivery_id = _persisted_uuid(
            attempt.outbox_delivery_attempt_id,
            field_name="terminalization receipt delivery id",
        )
        delivery = deliveries_by_id.get(delivery_id)
        if delivery is None:
            raise OutboxStoredContractError("Running receipt delivery is absent from locked union")
        message_id = _persisted_uuid(delivery.message_id, field_name="terminalization receipt message id")
        message = messages_by_id.get(message_id)
        if message is None:
            raise OutboxStoredContractError("Running receipt message is absent from locked union")
        authority = _executable_stage_authority(
            workflow=workflow,
            stage=stage,
            message=message,
            delivery=delivery,
            attempt=attempt,
        )
        try:
            _assert_stage_execution_receipt(
                db,
                authority=authority,
                workflow=workflow,
                stage=stage,
                message=message,
                delivery=delivery,
                attempt=attempt,
                observed_at=now,
                lease_policy="any",
            )
        except OutboxLeaseLost as exc:
            raise OutboxStoredContractError("Running stage receipt lineage is not exact authority") from exc
        receipt_message_ids.add(message_id)
        receipt_delivery_ids.add(delivery_id)
    active_delivery_ids: set[uuid.UUID] = set()
    stages_by_id = {_persisted_uuid(stage.id, field_name="terminalization stage id"): stage for stage in complete}
    for message_id in rows.live_message_ids:
        message = messages_by_id.get(message_id)
        if message is None:
            raise OutboxStoredContractError("Live message is absent from terminalization union")
        stage = stages_by_id.get(_persisted_uuid(message.stage_run_id, field_name="terminalization live message stage id"))
        if stage is None or stage.status not in _CLAIMABLE_STAGE_STATUSES:
            raise OutboxStoredContractError("Live workflow message is outside a runnable stage")
        _assert_live_failure_message(workflow, stage, message, observed_at=now)
        if message.status in _ACTIVE_DELIVERY_STATUSES:
            delivery_id = _persisted_uuid(
                message.active_delivery_attempt_id,
                field_name="terminalization active delivery id",
            )
            delivery = deliveries_by_id.get(delivery_id)
            if delivery is None:
                raise OutboxStoredContractError("Live active message lacks its locked delivery")
            _assert_reserved_active_delivery(message, delivery)
            active_delivery_ids.add(delivery_id)
    expected_message_ids = receipt_message_ids | set(rows.live_message_ids)
    expected_delivery_ids = receipt_delivery_ids | active_delivery_ids
    if set(rows.locked_message_ids) != expected_message_ids or set(rows.locked_delivery_ids) != expected_delivery_ids:
        raise OutboxStoredContractError("Terminalization graph contains unexpected M/D authority")
    _assert_cancellation_suffix_predates_transaction(
        tuple(messages_by_id[value] for value in rows.live_message_ids),
        tuple(deliveries_by_id[value] for value in sorted(active_delivery_ids, key=lambda item: item.int)),
        transaction_at=tx_at,
    )


async def _lock_terminalization_union(
    db: AsyncSession,
    *,
    workflow: WorkflowRun,
    stages: tuple[StageRun, ...],
) -> _TerminalizationGraphRows:
    attempt_ids, receipt_delivery_ids, receipt_message_ids = await _project_running_attempt_receipts(
        db,
        workflow,
    )
    live_message_ids = await _project_live_workflow_message_ids(db, workflow)
    message_ids = tuple(sorted(set((*receipt_message_ids, *live_message_ids)), key=lambda value: value.int))
    messages = await _lock_message_union(db, message_ids)
    active_delivery_ids = _active_delivery_ids_for_live_messages(messages, live_message_ids)
    delivery_ids = tuple(sorted(set((*receipt_delivery_ids, *active_delivery_ids)), key=lambda value: value.int))
    deliveries = await _lock_delivery_union(db, delivery_ids)
    attempts = await _lock_attempt_union(db, attempt_ids)
    transaction_at = await _db_now(db, autoflush=False)
    observed_at = await _db_clock_now(db)
    rows = _TerminalizationGraphRows(
        stages=stages,
        stage_states=tuple(_stage_ready_state(stage) for stage in stages),
        locked_messages=messages,
        locked_message_ids=message_ids,
        locked_deliveries=deliveries,
        locked_delivery_ids=delivery_ids,
        locked_attempts=attempts,
        locked_attempt_ids=attempt_ids,
        live_message_ids=live_message_ids,
        transaction_at=transaction_at,
        observed_at=observed_at,
    )
    _assert_terminalization_graph_rows(db, workflow=workflow, rows=rows)
    return rows


def _workflow_terminalization_projection(
    stages: tuple[StageRun, ...],
    attempts: tuple[StageAttempt, ...],
    *,
    decision: Literal["apply", "replay"],
) -> _WorkflowTerminalizationProjection:
    statuses = [stage.status for stage in stages]
    if decision == "replay":
        if any(status not in _TERMINAL_STAGE_STATUSES for status in statuses):
            raise OutboxStoredContractError("Cancelled workflow retains an unresolved stage")
        return _WorkflowTerminalizationProjection(
            decision="replay",
            post_stage_statuses=tuple(statuses),
            cancelled_stage_ids=(),
            cancelled_attempt_ids=(),
        )
    cancelled_stage_ids: list[uuid.UUID] = []
    for index, stage in enumerate(stages):
        if statuses[index] in _UNRESOLVED_STAGE_STATUSES:
            statuses[index] = "cancelled"
            cancelled_stage_ids.append(_persisted_uuid(stage.id, field_name="explicitly cancelled stage id"))
    cancelled_attempt_ids = tuple(
        sorted(
            (_persisted_uuid(attempt.id, field_name="explicitly cancelled attempt id") for attempt in attempts),
            key=lambda value: value.int,
        )
    )
    return _WorkflowTerminalizationProjection(
        decision="apply",
        post_stage_statuses=tuple(statuses),
        cancelled_stage_ids=tuple(cancelled_stage_ids),
        cancelled_attempt_ids=cancelled_attempt_ids,
    )


def _explicit_cancellation_decision(
    workflow: WorkflowRun,
    command: WorkflowCancellationCommand,
) -> Literal["apply", "replay"]:
    workflow_id = _persisted_uuid(workflow.id, field_name="cancellation workflow id")
    if workflow_id != command.workflow_run_id:
        raise OutboxConflict("Cancellation workflow identity changed under lock")
    if workflow.status in _ACTIVE_WORKFLOW_STATUSES:
        if workflow.state_version != command.expected_workflow_state_version:
            raise OutboxConflict("Cancellation workflow state version does not match")
        if (
            workflow.completed_at is not None
            or workflow.cancel_requested_at is not None
            or workflow.cancel_requested_by != ""
            or workflow.cancel_requested_by_id != ""
            or workflow.cancel_reason != ""
        ):
            raise OutboxStoredContractError("Active workflow retains contradictory cancellation facts")
        return "apply"
    if workflow.status != "cancelled":
        raise OutboxConflict("Terminal workflows cannot accept this cancellation command")
    if workflow.state_version != command.expected_workflow_state_version + 1:
        raise OutboxConflict("Cancellation replay version does not match its predecessor")
    persisted_request_id = getattr(workflow, "cancel_request_id", None)
    if persisted_request_id is None:
        raise OutboxConflict("Cancellation replay identity is unavailable before schema contract 0004")
    if (
        _persisted_uuid(persisted_request_id, field_name="persisted cancellation request id") != command.request_id
        or workflow.cancel_requested_by != command.actor
        or workflow.cancel_requested_by_id != command.actor_id
        or workflow.cancel_reason != command.reason
    ):
        raise OutboxConflict("Cancellation replay does not match persisted request authority")
    try:
        requested_at = _aware_datetime(
            workflow.cancel_requested_at,
            field_name="persisted cancellation requested_at",
        )
        completed_at = _aware_datetime(
            workflow.completed_at,
            field_name="persisted cancellation completed_at",
        )
    except OutboxValidation as exc:
        raise OutboxStoredContractError("Cancellation replay has invalid persisted timestamps") from exc
    if requested_at != completed_at:
        raise OutboxStoredContractError("Cancellation replay has contradictory terminal timestamps")
    return "replay"


def _make_outbox_cancellation_reservation(
    db: AsyncSession,
    transaction: object,
    *,
    workflow_run_id: uuid.UUID,
    locked_messages: tuple[OutboxMessage, ...],
    live_message_ids: tuple[uuid.UUID, ...],
    locked_deliveries: tuple[OutboxDeliveryAttempt, ...],
    error_code: str,
    error_summary: str,
    cancelled_by: str,
    cancelled_by_id: str,
    cancel_reason: str,
    transaction_at: datetime,
) -> OutboxCancellationReservation:
    live = set(live_message_ids)
    messages = tuple(message for message in locked_messages if _persisted_uuid(message.id, field_name="cancellation message id") in live)
    active_ids = {
        _persisted_uuid(
            message.active_delivery_attempt_id,
            field_name="cancellation active delivery id",
        )
        for message in messages
        if message.status in _ACTIVE_DELIVERY_STATUSES
    }
    deliveries = tuple(
        delivery for delivery in locked_deliveries if _persisted_uuid(delivery.id, field_name="cancellation delivery id") in active_ids
    )
    try:
        return OutboxCancellationReservation(
            workflow_run_id=_uuid(workflow_run_id, field_name="cancellation workflow_run_id"),
            messages=messages,
            message_ids=tuple(_persisted_uuid(message.id, field_name="cancellation message id") for message in messages),
            deliveries=deliveries,
            delivery_ids=tuple(_persisted_uuid(delivery.id, field_name="cancellation delivery id") for delivery in deliveries),
            error_code=error_code,
            error_class=_FAILURE_CANCELLATION_CLASS,
            error_summary=error_summary,
            cancelled_by=cancelled_by,
            cancelled_by_id=cancelled_by_id,
            cancel_reason=cancel_reason,
            transaction_at=transaction_at,
            _session=db,
            _transaction=transaction,
        )
    except OutboxValidation as exc:
        raise OutboxStoredContractError("Outbox cancellation child is not an exact fixed point") from exc


async def reserve_workflow_terminalization_graph(
    db: AsyncSession,
    *,
    command: WorkflowCancellationCommand,
) -> WorkflowTerminalizationReservation:
    """Reserve an explicit apply/replay cancellation graph without mutation."""

    safe_command = _copy_workflow_cancellation_command(command)
    transaction = _stage_execution_root_transaction(db)
    terminal_coordinate = (safe_command.workflow_run_id, "terminalize")
    terminal_fence = _workflow_terminalization_fence(db, transaction)
    if terminal_coordinate in terminal_fence.coordinates:
        raise OutboxConflict("Workflow terminalization was already reserved in this root transaction")
    _assert_workflow_has_no_reserved_fanout(
        db,
        transaction,
        safe_command.workflow_run_id,
    )

    workflow = await db.scalar(
        select(WorkflowRun)
        .where(WorkflowRun.id == safe_command.workflow_run_id)
        .execution_options(populate_existing=True, autoflush=False)
        .with_for_update()
    )
    if workflow is None:
        raise OutboxNotFound("Cancellation workflow does not exist")
    decision = _explicit_cancellation_decision(workflow, safe_command)
    stages = await _lock_all_terminalization_stages(db, workflow)
    rows = await _lock_terminalization_union(db, workflow=workflow, stages=stages)
    if decision == "replay" and (rows.live_message_ids or rows.locked_attempt_ids or workflow.status != "cancelled"):
        raise OutboxStoredContractError("Cancellation replay retains live outbox or attempt authority")
    projection = _workflow_terminalization_projection(
        stages,
        rows.locked_attempts,
        decision=decision,
    )
    if _stage_execution_root_transaction(db) is not transaction:
        raise OutboxConflict("Workflow terminalization changed root transaction while locking authority")
    reservation = WorkflowTerminalizationReservation(
        command=safe_command,
        decision=decision,
        workflow=workflow,
        stages=stages,
        stage_states=rows.stage_states,
        projection=projection,
        locked_messages=rows.locked_messages,
        locked_message_ids=rows.locked_message_ids,
        locked_deliveries=rows.locked_deliveries,
        locked_delivery_ids=rows.locked_delivery_ids,
        locked_attempts=rows.locked_attempts,
        locked_attempt_ids=rows.locked_attempt_ids,
        live_message_ids=rows.live_message_ids,
        transaction_at=rows.transaction_at,
        observed_at=rows.observed_at,
        _session=db,
        _transaction=transaction,
    )
    _register_workflow_terminalization_reservation(db, transaction, reservation)
    return reservation


async def consume_workflow_terminalization_graph(
    db: AsyncSession,
    *,
    reservation: WorkflowTerminalizationReservation,
    command: WorkflowCancellationCommand,
) -> LockedWorkflowTerminalizationGraph:
    """Spend and freshly re-prove one explicit cancellation graph."""

    safe_command = _copy_workflow_cancellation_command(command)
    transaction = _stage_execution_root_transaction(db)
    registration = _consume_workflow_terminalization_registration(
        db,
        transaction,
        reservation,
    )
    if db is not reservation._session or transaction is not reservation._transaction:
        raise OutboxConflict("Workflow terminalization is outside its original session transaction")
    if safe_command != reservation.command:
        raise OutboxConflict("Workflow cancellation command changed after graph reservation")
    _require_stage_execution_authorities(
        db,
        (
            reservation.workflow,
            *reservation.stages,
            *reservation.locked_messages,
            *reservation.locked_deliveries,
            *reservation.locked_attempts,
        ),
    )
    if _workflow_terminalization_reservation_seal(reservation) != registration.seal:
        raise OutboxConflict("Workflow terminalization capability was mutated after registration")
    observed_at = await _db_clock_now(db)
    if observed_at < reservation.observed_at:
        raise OutboxStoredContractError("PostgreSQL wall clock moved backwards across terminalization consumption")
    if _stage_execution_root_transaction(db) is not transaction:
        raise OutboxConflict("Workflow terminalization changed root transaction while consuming authority")
    rows = _TerminalizationGraphRows(
        stages=reservation.stages,
        stage_states=reservation.stage_states,
        locked_messages=reservation.locked_messages,
        locked_message_ids=reservation.locked_message_ids,
        locked_deliveries=reservation.locked_deliveries,
        locked_delivery_ids=reservation.locked_delivery_ids,
        locked_attempts=reservation.locked_attempts,
        locked_attempt_ids=reservation.locked_attempt_ids,
        live_message_ids=reservation.live_message_ids,
        transaction_at=reservation.transaction_at,
        observed_at=observed_at,
    )
    _assert_terminalization_graph_rows(db, workflow=reservation.workflow, rows=rows)
    decision = _explicit_cancellation_decision(reservation.workflow, safe_command)
    projection = _workflow_terminalization_projection(
        reservation.stages,
        reservation.locked_attempts,
        decision=decision,
    )
    if decision != reservation.decision or projection != reservation.projection:
        raise OutboxConflict("Workflow terminalization decision changed after reservation")
    child: OutboxCancellationReservation | None = None
    if decision == "apply":
        child = _make_outbox_cancellation_reservation(
            db,
            transaction,
            workflow_run_id=safe_command.workflow_run_id,
            locked_messages=reservation.locked_messages,
            live_message_ids=reservation.live_message_ids,
            locked_deliveries=reservation.locked_deliveries,
            error_code=_EXPLICIT_CANCELLATION_CODE,
            error_summary=safe_command.reason,
            cancelled_by=safe_command.actor,
            cancelled_by_id=safe_command.actor_id,
            cancel_reason=safe_command.reason,
            transaction_at=reservation.transaction_at,
        )
    locked = LockedWorkflowTerminalizationGraph(
        command=safe_command,
        decision=decision,
        workflow=reservation.workflow,
        stages=reservation.stages,
        stage_states=reservation.stage_states,
        projection=reservation.projection,
        locked_messages=reservation.locked_messages,
        locked_message_ids=reservation.locked_message_ids,
        locked_deliveries=reservation.locked_deliveries,
        locked_delivery_ids=reservation.locked_delivery_ids,
        locked_attempts=reservation.locked_attempts,
        locked_attempt_ids=reservation.locked_attempt_ids,
        live_message_ids=reservation.live_message_ids,
        transaction_at=reservation.transaction_at,
        outbox_cancellation_reservation=child,
        observed_at=observed_at,
    )
    if child is not None:
        _register_transferred_terminalization_cancellation_reservation(
            db,
            transaction,
            terminalization_reservation=reservation,
            terminalization_registration=registration,
            cancellation_reservation=child,
        )
    return locked


def _expired_recovery_source(
    stages: tuple[StageRun, ...],
    *,
    transaction_at: datetime | None = None,
) -> tuple[int, StageRun]:
    running: list[tuple[int, StageRun]] = []
    for index, stage in enumerate(stages):
        if stage.status != "running":
            continue
        try:
            lease_expires_at = _aware_datetime(
                stage.lease_expires_at,
                field_name="recovery source lease_expires_at",
            )
        except OutboxValidation as exc:
            raise OutboxStoredContractError("Running recovery stage has invalid lease authority") from exc
        if transaction_at is None or lease_expires_at <= transaction_at:
            running.append((index, stage))
    if not running:
        raise OutboxStoredContractError("Selected recovery workflow has no expired running stage")
    return min(
        running,
        key=lambda item: (
            item[1].lease_expires_at,
            item[1].ordinal,
            _persisted_uuid(item[1].id, field_name="recovery candidate id").int,
        ),
    )


async def _lock_recovery_retry_union(
    db: AsyncSession,
    *,
    workflow: WorkflowRun,
    stages: tuple[StageRun, ...],
    source: StageRun,
    retry_projection: _StageFailureRetryProjection,
) -> tuple[_TerminalizationGraphRows, uuid.UUID, bool]:
    attempt_id = await db.scalar(
        select(StageAttempt.id)
        .where(
            StageAttempt.stage_run_id == source.id,
            StageAttempt.attempt_number == source.attempt_count,
            StageAttempt.status == "running",
        )
        .execution_options(autoflush=False)
    )
    if attempt_id is None:
        raise OutboxStoredContractError("Expired recovery source has no current running attempt projection")
    source_attempt_id = _persisted_uuid(attempt_id, field_name="recovery source attempt id")
    source_delivery = await db.scalar(
        select(StageAttempt.outbox_delivery_attempt_id).where(StageAttempt.id == source_attempt_id).execution_options(autoflush=False)
    )
    if source_delivery is None:
        raise OutboxStoredContractError("Expired recovery attempt has no receipt delivery projection")
    source_delivery_id = _persisted_uuid(
        source_delivery,
        field_name="recovery source delivery id",
    )
    source_message = await db.scalar(
        select(OutboxDeliveryAttempt.message_id).where(OutboxDeliveryAttempt.id == source_delivery_id).execution_options(autoflush=False)
    )
    if source_message is None:
        raise OutboxStoredContractError("Expired recovery receipt has no source message projection")
    source_message_id = _persisted_uuid(source_message, field_name="recovery source message id")
    discovered = await db.scalar(
        select(OutboxMessage.id)
        .where(
            OutboxMessage.logical_key == retry_projection.logical_key,
            OutboxMessage.redrive_ordinal == 0,
        )
        .order_by(OutboxMessage.id.asc())
        .execution_options(autoflush=False)
    )
    discovered_id = _persisted_uuid(discovered, field_name="discovered recovery retry message id") if discovered is not None else None
    retry_message_id = discovered_id or uuid.uuid4()
    if retry_message_id == source_message_id:
        raise OutboxStoredContractError("Recovery retry root collides with its delivered source message")
    message_ids = tuple(
        sorted(
            {source_message_id, *((discovered_id,) if discovered_id is not None else ())},
            key=lambda value: value.int,
        )
    )
    messages = await _lock_message_union(db, message_ids)
    messages_by_id = {_persisted_uuid(message.id, field_name="recovery locked message id"): message for message in messages}
    active_delivery_ids: tuple[uuid.UUID, ...] = ()
    if discovered_id is not None:
        retry_message = messages_by_id.get(discovered_id)
        if retry_message is None or retry_message.logical_key != retry_projection.logical_key:
            raise OutboxStoredContractError("Discovered recovery retry root changed logical identity")
        if retry_message.status in _ACTIVE_DELIVERY_STATUSES:
            if retry_message.active_delivery_attempt_id is None:
                raise OutboxStoredContractError("Active recovery retry root has no delivery pointer")
            active_delivery_ids = (
                _persisted_uuid(
                    retry_message.active_delivery_attempt_id,
                    field_name="recovery retry active delivery id",
                ),
            )
        elif retry_message.active_delivery_attempt_id is not None:
            raise OutboxStoredContractError("Inactive recovery retry root retains an active delivery pointer")
    delivery_ids = tuple(sorted({source_delivery_id, *active_delivery_ids}, key=lambda value: value.int))
    deliveries = await _lock_delivery_union(db, delivery_ids)
    attempts = await _lock_attempt_union(db, (source_attempt_id,))
    transaction_at = await _db_now(db, autoflush=False)
    observed_at = await _db_clock_now(db)
    rows = _TerminalizationGraphRows(
        stages=stages,
        stage_states=tuple(_stage_ready_state(stage) for stage in stages),
        locked_messages=messages,
        locked_message_ids=message_ids,
        locked_deliveries=deliveries,
        locked_delivery_ids=delivery_ids,
        locked_attempts=attempts,
        locked_attempt_ids=(source_attempt_id,),
        live_message_ids=(),
        transaction_at=transaction_at,
        observed_at=observed_at,
    )
    return rows, retry_message_id, discovered_id is not None


def _assert_expired_recovery_graph(
    db: AsyncSession,
    *,
    reservation: StageRecoveryReservation,
    observed_at: datetime,
) -> None:
    _require_stage_execution_authorities(
        db,
        (
            reservation.workflow,
            *reservation.stages,
            *reservation.locked_messages,
            *reservation.locked_deliveries,
            *reservation.locked_attempts,
        ),
    )
    complete = _validate_complete_locked_stages(reservation.workflow, reservation.stages)
    now = _aware_datetime(observed_at, field_name="recovery observed_at")
    tx_at = _aware_datetime(reservation.transaction_at, field_name="recovery transaction_at")
    if tx_at > now:
        raise OutboxStoredContractError("Recovery transaction clock is later than its wall clock")
    for stage in complete:
        _assert_completion_stage_chronology(stage, observed_at=now)
    current_states = tuple(_stage_ready_state(stage) for stage in complete)
    if current_states != reservation.stage_states:
        raise OutboxConflict("Recovery stage authority changed after graph reservation")
    expected_index, source = _expired_recovery_source(complete, transaction_at=tx_at)
    if (
        expected_index != reservation.source_stage_index
        or _persisted_uuid(source.id, field_name="recovery source id") != reservation.source_stage_id
        or current_states[expected_index] != reservation.causal_source
    ):
        raise OutboxConflict("Recovery source selection changed after reservation")
    messages_by_id = {
        _persisted_uuid(message.id, field_name="recovery locked message id"): message for message in reservation.locked_messages
    }
    deliveries_by_id = {
        _persisted_uuid(delivery.id, field_name="recovery locked delivery id"): delivery for delivery in reservation.locked_deliveries
    }
    attempts_by_id = {
        _persisted_uuid(attempt.id, field_name="recovery locked attempt id"): attempt for attempt in reservation.locked_attempts
    }
    if (
        tuple(messages_by_id) != reservation.locked_message_ids
        or tuple(deliveries_by_id) != reservation.locked_delivery_ids
        or tuple(attempts_by_id) != reservation.locked_attempt_ids
    ):
        raise OutboxConflict("Recovery union authority changed identity or UUID order")
    message = messages_by_id.get(reservation.source_authority.message_id)
    delivery = deliveries_by_id.get(reservation.source_authority.delivery_attempt_id)
    attempt = attempts_by_id.get(reservation.source_attempt_id)
    if message is None or delivery is None or attempt is None:
        raise OutboxStoredContractError("Recovery source receipt is absent from its locked union")
    try:
        _assert_stage_execution_receipt(
            db,
            authority=reservation.source_authority,
            workflow=reservation.workflow,
            stage=source,
            message=message,
            delivery=delivery,
            attempt=attempt,
            observed_at=now,
            lease_policy="expired",
        )
    except OutboxLeaseLost as exc:
        raise OutboxStoredContractError("Expired recovery source receipt is not exact authority") from exc
    decision: Literal["retry", "dead_lettered"] = "retry" if source.attempt_count < source.max_attempts else "dead_lettered"
    if decision != reservation.decision:
        raise OutboxConflict("Recovery retry budget changed after reservation")
    cancelled_attempt_ids = (
        tuple(value for value in reservation.locked_attempt_ids if value != reservation.source_attempt_id)
        if decision == "dead_lettered" and source.required
        else ()
    )
    settlement = _stage_failure_settlement_projection(
        reservation.workflow,
        complete,
        source_index=expected_index,
        decision=decision,
        cancelled_attempt_ids=cancelled_attempt_ids,
    )
    if settlement != reservation.settlement:
        raise OutboxConflict("Recovery settlement projection changed after reservation")
    if decision == "retry":
        expected_delay = _stage_failure_retry_delay(reservation.workflow, source)
        expected_projection = _stage_failure_retry_projection(
            reservation.workflow,
            reservation.causal_source,
        )
        if (
            reservation.retry_delay_seconds != expected_delay
            or reservation.retry_projection != expected_projection
            or reservation.retry_message_id is None
            or set(reservation.locked_message_ids) != {reservation.source_authority.message_id}
            or set(reservation.locked_delivery_ids) != {reservation.source_authority.delivery_attempt_id}
            or set(reservation.locked_attempt_ids) != {reservation.source_attempt_id}
            or reservation.live_message_ids
        ):
            raise OutboxStoredContractError("Retry recovery graph contains unexpected authority")
    else:
        rows = _TerminalizationGraphRows(
            stages=reservation.stages,
            stage_states=reservation.stage_states,
            locked_messages=reservation.locked_messages,
            locked_message_ids=reservation.locked_message_ids,
            locked_deliveries=reservation.locked_deliveries,
            locked_delivery_ids=reservation.locked_delivery_ids,
            locked_attempts=reservation.locked_attempts,
            locked_attempt_ids=reservation.locked_attempt_ids,
            live_message_ids=reservation.live_message_ids,
            transaction_at=reservation.transaction_at,
            observed_at=now,
        )
        _assert_terminalization_graph_rows(db, workflow=reservation.workflow, rows=rows)


def _stage_recovery_retry_intent(
    workflow: WorkflowRun,
    projection: _StageFailureRetryProjection,
    *,
    next_attempt_at: datetime,
) -> StageReadyIntent:
    pre = _copy_stage_ready_state(projection.pre_source)
    post = replace(
        pre,
        status="retry_wait",
        state_version=pre.state_version + 1,
        next_attempt_at=_aware_datetime(
            next_attempt_at,
            field_name="recovery next_attempt_at",
        ),
        lease_owner="",
        lease_token=None,
        leased_at=None,
        lease_expires_at=None,
        heartbeat_at=None,
        last_error_code=_LEASE_EXPIRED_CODE,
        last_error_summary=_LEASE_EXPIRED_SUMMARY,
        last_error_retryable=True,
        output_checksum="",
        completed_at=None,
    )
    intent = _make_stage_ready_intent(
        workflow=workflow,
        emission_kind="lease_recovered",
        projection_mode="transition",
        allow_create=True,
        pre_target=pre,
        post_target=post,
        causal_pre_stage=pre,
        target_attempt_number=projection.target_attempt_number,
    )
    if (
        intent.envelope_canonical != projection.envelope_canonical
        or intent.envelope_checksum != projection.envelope_checksum
        or intent.logical_key != projection.logical_key
    ):
        raise OutboxStoredContractError("Recovery retry intent changed its clock-free identity")
    return intent


async def reserve_one_expired_stage_recovery(
    db: AsyncSession,
) -> StageRecoveryReservation | None:
    """Auto-select and reserve one exact expired receipt graph via SKIP LOCKED."""

    transaction = _stage_execution_root_transaction(db)
    _begin_stage_recovery_sweep(db, transaction)
    expired_stage = exists(
        select(StageRun.id).where(
            StageRun.workflow_run_id == WorkflowRun.id,
            StageRun.status == "running",
            StageRun.lease_expires_at <= func.transaction_timestamp(),
        )
    )
    workflow = await db.scalar(
        select(WorkflowRun)
        .where(WorkflowRun.status == "running", expired_stage)
        .order_by(WorkflowRun.created_at.asc(), WorkflowRun.id.asc())
        .execution_options(populate_existing=True, autoflush=False)
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if workflow is None:
        _spend_empty_stage_recovery_sweep(db, transaction)
        return None
    stages = await _lock_all_terminalization_stages(db, workflow)
    source_index, source = _expired_recovery_source(stages)
    causal_source = _stage_ready_state(source)
    decision: Literal["retry", "dead_lettered"] = "retry" if source.attempt_count < source.max_attempts else "dead_lettered"
    retry_delay_seconds: int | None = None
    retry_projection: _StageFailureRetryProjection | None = None
    retry_message_id: uuid.UUID | None = None
    if decision == "retry":
        retry_delay_seconds = _stage_failure_retry_delay(workflow, source)
        retry_projection = _stage_failure_retry_projection(workflow, causal_source)
        rows, retry_message_id, discovered_retry = await _lock_recovery_retry_union(
            db,
            workflow=workflow,
            stages=stages,
            source=source,
            retry_projection=retry_projection,
        )
        if discovered_retry:
            raise OutboxStoredContractError("Expired recovery source already has impossible future outbox authority")
    else:
        rows = await _lock_terminalization_union(db, workflow=workflow, stages=stages)
    if rows.transaction_at > rows.observed_at:
        raise OutboxStoredContractError("Recovery transaction clock is later than its wall clock")
    attempts_by_stage = {
        _persisted_uuid(attempt.stage_run_id, field_name="recovery attempt stage id"): attempt for attempt in rows.locked_attempts
    }
    source_id = _persisted_uuid(source.id, field_name="recovery source stage id")
    source_attempt = attempts_by_stage.get(source_id)
    if source_attempt is None:
        raise OutboxStoredContractError("Expired recovery source has no locked running attempt")
    if source_attempt.outbox_delivery_attempt_id is None:
        raise OutboxStoredContractError("Expired recovery source attempt is not receipt-bound")
    deliveries_by_id = {_persisted_uuid(delivery.id, field_name="recovery delivery id"): delivery for delivery in rows.locked_deliveries}
    source_delivery_id = _persisted_uuid(
        source_attempt.outbox_delivery_attempt_id,
        field_name="recovery source delivery id",
    )
    source_delivery = deliveries_by_id.get(source_delivery_id)
    if source_delivery is None:
        raise OutboxStoredContractError("Expired recovery source delivery is outside locked union")
    messages_by_id = {_persisted_uuid(message.id, field_name="recovery message id"): message for message in rows.locked_messages}
    source_message_id = _persisted_uuid(
        source_delivery.message_id,
        field_name="recovery source message id",
    )
    source_message = messages_by_id.get(source_message_id)
    if source_message is None:
        raise OutboxStoredContractError("Expired recovery source message is outside locked union")
    source_authority = _executable_stage_authority(
        workflow=workflow,
        stage=source,
        message=source_message,
        delivery=source_delivery,
        attempt=source_attempt,
    )
    cancelled_attempt_ids = (
        tuple(
            value
            for value in rows.locked_attempt_ids
            if value != _persisted_uuid(source_attempt.id, field_name="recovery source attempt id")
        )
        if decision == "dead_lettered" and source.required
        else ()
    )
    settlement = _stage_failure_settlement_projection(
        workflow,
        stages,
        source_index=source_index,
        decision=decision,
        cancelled_attempt_ids=cancelled_attempt_ids,
    )
    reservation = StageRecoveryReservation(
        source_authority=source_authority,
        workflow=workflow,
        stages=stages,
        stage_states=rows.stage_states,
        source_stage_id=source_id,
        source_stage_index=source_index,
        causal_source=causal_source,
        decision=decision,
        retry_delay_seconds=retry_delay_seconds,
        retry_projection=retry_projection,
        retry_message_id=retry_message_id,
        settlement=settlement,
        locked_messages=rows.locked_messages,
        locked_message_ids=rows.locked_message_ids,
        locked_deliveries=rows.locked_deliveries,
        locked_delivery_ids=rows.locked_delivery_ids,
        locked_attempts=rows.locked_attempts,
        locked_attempt_ids=rows.locked_attempt_ids,
        source_attempt_id=_persisted_uuid(source_attempt.id, field_name="recovery source attempt id"),
        live_message_ids=rows.live_message_ids,
        transaction_at=rows.transaction_at,
        observed_at=rows.observed_at,
        _session=db,
        _transaction=transaction,
    )
    _assert_expired_recovery_graph(db, reservation=reservation, observed_at=rows.observed_at)
    if _stage_execution_root_transaction(db) is not transaction:
        raise OutboxConflict("Stage recovery changed root transaction while locking authority")
    _register_stage_recovery_reservation(db, transaction, reservation)
    return reservation


async def consume_stage_recovery_graph(
    db: AsyncSession,
    *,
    reservation: StageRecoveryReservation,
) -> LockedStageRecoveryGraph:
    """Spend and freshly re-prove one auto-selected expired stage graph."""

    transaction = _stage_execution_root_transaction(db)
    registration = _consume_stage_recovery_registration(db, transaction, reservation)
    if db is not reservation._session or transaction is not reservation._transaction:
        raise OutboxConflict("Stage recovery is outside its original session transaction")
    _require_stage_execution_authorities(
        db,
        (
            reservation.workflow,
            *reservation.stages,
            *reservation.locked_messages,
            *reservation.locked_deliveries,
            *reservation.locked_attempts,
        ),
    )
    if _stage_recovery_reservation_seal(reservation) != registration.seal:
        raise OutboxConflict("Stage recovery capability was mutated after registration")
    observed_at = await _db_clock_now(db)
    if observed_at < reservation.observed_at:
        raise OutboxStoredContractError("PostgreSQL wall clock moved backwards across recovery consumption")
    if _stage_execution_root_transaction(db) is not transaction:
        raise OutboxConflict("Stage recovery changed root transaction while consuming authority")
    _assert_expired_recovery_graph(db, reservation=reservation, observed_at=observed_at)

    retry_intent: StageReadyIntent | None = None
    next_attempt_at: datetime | None = None
    stage_ready_child: StageReadyReservation | None = None
    cancellation_child: OutboxCancellationReservation | None = None
    if reservation.decision == "retry":
        if reservation.retry_projection is None or reservation.retry_delay_seconds is None or reservation.retry_message_id is None:
            raise OutboxStoredContractError("Retry recovery lacks exact projection authority")
        next_attempt_at = observed_at + timedelta(seconds=reservation.retry_delay_seconds)
        retry_intent = _stage_recovery_retry_intent(
            reservation.workflow,
            reservation.retry_projection,
            next_attempt_at=next_attempt_at,
        )
        stage_ready_child = _stage_failure_stage_ready_reservation(
            db,
            transaction,
            stages=reservation.stages,
            stage_states=reservation.stage_states,
            intent=retry_intent,
            message_id=reservation.retry_message_id,
        )
    elif reservation.stages[reservation.source_stage_index].required:
        cancellation_child = _make_outbox_cancellation_reservation(
            db,
            transaction,
            workflow_run_id=reservation.source_authority.workflow_run_id,
            locked_messages=reservation.locked_messages,
            live_message_ids=reservation.live_message_ids,
            locked_deliveries=reservation.locked_deliveries,
            error_code="workflow.required_stage_dead_lettered",
            error_summary=_FAILURE_CANCELLATION_REASON,
            cancelled_by=_FAILURE_CANCELLATION_ACTOR,
            cancelled_by_id=_FAILURE_CANCELLATION_ACTOR_ID,
            cancel_reason=_FAILURE_CANCELLATION_REASON,
            transaction_at=reservation.transaction_at,
        )
    locked = LockedStageRecoveryGraph(
        source_authority=reservation.source_authority,
        workflow=reservation.workflow,
        stages=reservation.stages,
        stage_states=reservation.stage_states,
        source_stage_id=reservation.source_stage_id,
        source_stage_index=reservation.source_stage_index,
        causal_source=reservation.causal_source,
        decision=reservation.decision,
        retry_delay_seconds=reservation.retry_delay_seconds,
        retry_projection=reservation.retry_projection,
        retry_message_id=reservation.retry_message_id,
        settlement=reservation.settlement,
        locked_messages=reservation.locked_messages,
        locked_message_ids=reservation.locked_message_ids,
        locked_deliveries=reservation.locked_deliveries,
        locked_delivery_ids=reservation.locked_delivery_ids,
        locked_attempts=reservation.locked_attempts,
        locked_attempt_ids=reservation.locked_attempt_ids,
        source_attempt_id=reservation.source_attempt_id,
        live_message_ids=reservation.live_message_ids,
        transaction_at=reservation.transaction_at,
        retry_intent=retry_intent,
        next_attempt_at=next_attempt_at,
        stage_ready_reservation=stage_ready_child,
        outbox_cancellation_reservation=cancellation_child,
        observed_at=observed_at,
    )
    if stage_ready_child is not None:
        _register_transferred_recovery_stage_ready_reservation(
            db,
            transaction,
            recovery_reservation=reservation,
            recovery_registration=registration,
            stage_ready_reservation=stage_ready_child,
        )
    elif cancellation_child is not None:
        _register_transferred_recovery_cancellation_reservation(
            db,
            transaction,
            recovery_reservation=reservation,
            recovery_registration=registration,
            cancellation_reservation=cancellation_child,
        )
    return locked


async def reserve_stage_failure_graph(
    db: AsyncSession,
    *,
    authority: ExecutableStageAuthority,
    evidence: StageFailureEvidence,
) -> StageFailureReservation:
    """Reserve one exact retry or terminal failure graph without mutation.

    The canonical lock order is ``W -> all S -> union M -> union D -> all
    current A``.  Required terminalization intentionally includes every live
    workflow message and every running receipt lineage.  The workflow row lock
    stabilizes normal ORM writers, but migration 0003 cannot prevent a raw-SQL
    phantom child insert; migration 0004 must close that database-level gap.
    """

    credential = _copy_executable_stage_authority(authority)
    safe_evidence = _copy_stage_failure_evidence(evidence)
    transaction = _stage_execution_root_transaction(db)
    if safe_evidence.retryable:
        _assert_workflow_has_no_terminalization(
            db,
            transaction,
            credential.workflow_run_id,
        )
    _assert_stage_execution_coordinate_available(db, transaction, credential)

    workflow = await db.scalar(
        select(WorkflowRun)
        .where(WorkflowRun.id == credential.workflow_run_id)
        .execution_options(populate_existing=True, autoflush=False)
        .with_for_update()
    )
    if workflow is None:
        raise OutboxLeaseLost("Stage failure workflow authority is no longer live")
    plan = _workflow_plan_order(workflow)
    stage_rows = await db.execute(
        select(StageRun)
        .where(StageRun.workflow_run_id == credential.workflow_run_id)
        .order_by(StageRun.ordinal.asc(), StageRun.id.asc())
        .execution_options(populate_existing=True, autoflush=False)
        .with_for_update()
    )
    loaded_stages = tuple(stage_rows.scalars().all())
    if not loaded_stages or len(loaded_stages) != len(plan):
        raise OutboxStoredContractError("Stage failure rows are not the exact persisted workflow plan")
    try:
        locked_stages = _validate_complete_locked_stages(workflow, loaded_stages)
    except (OutboxConflict, OutboxValidation) as exc:
        raise OutboxStoredContractError("Stage failure rows contradict the persisted workflow plan") from exc
    source_index = next(
        (index for index, stage in enumerate(locked_stages) if _persisted_uuid(stage.id, field_name="stage.id") == credential.stage_run_id),
        None,
    )
    if source_index is None:
        raise OutboxLeaseLost("Stage failure source is absent from its locked workflow plan")
    source = locked_stages[source_index]
    # Classify an old worker presentation before deriving retry authority.
    # Native recovery legally changes the source to retry_wait and clears its
    # lease; feeding that valid non-running state into a running-only retry
    # projection would otherwise leak OutboxValidation instead of stale lease
    # loss.  No wall-clock claim is made here; expiry remains proven only after
    # the complete M/D/A lock cut and fresh database clock below.
    if (
        workflow.id != credential.workflow_run_id
        or workflow.status != "running"
        or workflow.state_version != credential.workflow_state_version
        or source.id != credential.stage_run_id
        or source.workflow_run_id != credential.workflow_run_id
        or source.stage_key != credential.stage_key
        or source.status != "running"
        or source.state_version != credential.stage_state_version
        or source.input_checksum != credential.input_checksum
        or source.checkpoint_version != credential.checkpoint_version
        or source.attempt_count != credential.attempt_number
        or source.lease_token != credential.stage_lease_token
        or source.lease_owner != credential.lease_owner
        or source.lease_expires_at != credential.lease_expires_at
    ):
        raise OutboxLeaseLost("Stage failure source authority is no longer live")
    stage_states = tuple(_stage_ready_state(stage) for stage in locked_stages)
    causal_source = stage_states[source_index]
    decision = _stage_failure_decision(source, safe_evidence)
    required_terminal = source.required and decision != "retry"

    retry_delay_seconds: int | None = None
    retry_projection: _StageFailureRetryProjection | None = None
    retry_message_id: uuid.UUID | None = None
    discovered_retry_message_id: uuid.UUID | None = None
    if decision == "retry":
        retry_delay_seconds = _stage_failure_retry_delay(workflow, source)
        retry_projection = _stage_failure_retry_projection(workflow, causal_source)
        discovered = await db.scalar(
            select(OutboxMessage.id)
            .where(
                OutboxMessage.logical_key == retry_projection.logical_key,
                OutboxMessage.redrive_ordinal == 0,
            )
            .order_by(OutboxMessage.id.asc())
            .execution_options(autoflush=False)
        )
        if discovered is not None:
            discovered_retry_message_id = _persisted_uuid(
                discovered,
                field_name="discovered retry message id",
            )
        retry_message_id = discovered_retry_message_id or uuid.uuid4()
        if retry_message_id == credential.message_id:
            raise OutboxStoredContractError("Failure retry root collides with its source message")

    running_stage_ids: tuple[uuid.UUID, ...] = ()
    projected_attempt_ids: tuple[uuid.UUID, ...] = (credential.stage_attempt_id,)
    projected_receipt_delivery_ids: tuple[uuid.UUID, ...] = (credential.delivery_attempt_id,)
    projected_receipt_message_ids: tuple[uuid.UUID, ...] = (credential.message_id,)
    live_message_ids: tuple[uuid.UUID, ...] = ()
    if required_terminal:
        running_stages = tuple(stage for stage in locked_stages if stage.status == "running")
        running_stage_ids = tuple(_persisted_uuid(stage.id, field_name="running stage id") for stage in running_stages)
        attempt_ids: list[uuid.UUID] = []
        receipt_delivery_ids: list[uuid.UUID] = []
        receipt_message_ids: list[uuid.UUID] = []
        for stage in running_stages:
            attempt_id = await db.scalar(
                select(StageAttempt.id)
                .where(
                    StageAttempt.stage_run_id == stage.id,
                    StageAttempt.attempt_number == stage.attempt_count,
                    StageAttempt.status == "running",
                )
                .execution_options(autoflush=False)
            )
            if attempt_id is None:
                raise OutboxStoredContractError("Running failure stage has no current attempt projection")
            attempt_key = _persisted_uuid(attempt_id, field_name="projected running attempt id")
            delivery_id = await db.scalar(
                select(StageAttempt.outbox_delivery_attempt_id).where(StageAttempt.id == attempt_key).execution_options(autoflush=False)
            )
            if delivery_id is None:
                raise OutboxStoredContractError("Running failure attempt has no receipt delivery projection")
            delivery_key = _persisted_uuid(delivery_id, field_name="projected receipt delivery id")
            message_id = await db.scalar(
                select(OutboxDeliveryAttempt.message_id).where(OutboxDeliveryAttempt.id == delivery_key).execution_options(autoflush=False)
            )
            if message_id is None:
                raise OutboxStoredContractError("Running failure receipt has no source message projection")
            attempt_ids.append(attempt_key)
            receipt_delivery_ids.append(delivery_key)
            receipt_message_ids.append(_persisted_uuid(message_id, field_name="projected receipt message id"))
        if (
            len(set(attempt_ids)) != len(attempt_ids)
            or len(set(receipt_delivery_ids)) != len(receipt_delivery_ids)
            or len(set(receipt_message_ids)) != len(receipt_message_ids)
        ):
            raise OutboxStoredContractError("Running failure receipt projections collide")
        projected_attempt_ids = tuple(attempt_ids)
        projected_receipt_delivery_ids = tuple(receipt_delivery_ids)
        projected_receipt_message_ids = tuple(receipt_message_ids)
        live_rows = await db.execute(
            select(OutboxMessage.id)
            .where(
                OutboxMessage.workflow_run_id == credential.workflow_run_id,
                OutboxMessage.status.in_((*_CLAIMABLE_MESSAGE_STATUSES, *_ACTIVE_DELIVERY_STATUSES)),
            )
            .order_by(OutboxMessage.id.asc())
            .execution_options(autoflush=False)
        )
        live_message_ids = tuple(_persisted_uuid(value, field_name="projected live message id") for value in live_rows.scalars().all())
        if live_message_ids != tuple(sorted(live_message_ids, key=lambda value: value.int)) or len(set(live_message_ids)) != len(
            live_message_ids
        ):
            raise OutboxStoredContractError("Live workflow message projection is not unique UUID order")

    union_message_candidates = [*projected_receipt_message_ids, *live_message_ids]
    if discovered_retry_message_id is not None:
        union_message_candidates.append(discovered_retry_message_id)
    locked_message_ids = tuple(sorted(set(union_message_candidates), key=lambda value: value.int))
    if not locked_message_ids:
        raise OutboxStoredContractError("Stage failure graph has no source message authority")
    locked_messages_list: list[OutboxMessage] = []
    for message_id in locked_message_ids:
        message = await db.scalar(
            select(OutboxMessage)
            .where(OutboxMessage.id == message_id)
            .execution_options(populate_existing=True, autoflush=False)
            .with_for_update()
        )
        if message is None:
            if message_id == credential.message_id:
                raise OutboxLeaseLost("Stage failure source message authority is no longer live")
            raise OutboxStoredContractError("Projected failure message disappeared before lock")
        locked_messages_list.append(message)
    locked_messages = tuple(locked_messages_list)
    messages_by_id = {_persisted_uuid(message.id, field_name="failure locked message id"): message for message in locked_messages}

    if discovered_retry_message_id is not None:
        retry_message = messages_by_id.get(discovered_retry_message_id)
        if retry_message is None or retry_projection is None or retry_message.logical_key != retry_projection.logical_key:
            raise OutboxStoredContractError("Discovered retry root changed logical identity before lock")

    active_delivery_ids: list[uuid.UUID] = []
    if required_terminal:
        for message_id in live_message_ids:
            message = messages_by_id.get(message_id)
            if message is None:
                raise OutboxStoredContractError("Projected live workflow message disappeared before validation")
            if message.status in _ACTIVE_DELIVERY_STATUSES:
                if message.active_delivery_attempt_id is None:
                    raise OutboxStoredContractError("Active workflow message has no delivery pointer")
                active_delivery_ids.append(_persisted_uuid(message.active_delivery_attempt_id, field_name="live active delivery id"))
            elif message.active_delivery_attempt_id is not None:
                raise OutboxStoredContractError("Idle workflow message retains an active delivery pointer")
    elif discovered_retry_message_id is not None:
        retry_message = messages_by_id[discovered_retry_message_id]
        if retry_message.status in _ACTIVE_DELIVERY_STATUSES:
            if retry_message.active_delivery_attempt_id is None:
                raise OutboxStoredContractError("Active retry root has no delivery pointer")
            active_delivery_ids.append(_persisted_uuid(retry_message.active_delivery_attempt_id, field_name="retry active delivery id"))
        elif retry_message.active_delivery_attempt_id is not None:
            raise OutboxStoredContractError("Inactive retry root retains an active delivery pointer")

    if len(set(active_delivery_ids)) != len(active_delivery_ids):
        raise OutboxStoredContractError("Failure active delivery projections collide")
    union_delivery_candidates = [*projected_receipt_delivery_ids, *active_delivery_ids]
    locked_delivery_ids = tuple(sorted(set(union_delivery_candidates), key=lambda value: value.int))
    locked_deliveries_list: list[OutboxDeliveryAttempt] = []
    for delivery_id in locked_delivery_ids:
        delivery = await db.scalar(
            select(OutboxDeliveryAttempt)
            .where(OutboxDeliveryAttempt.id == delivery_id)
            .execution_options(populate_existing=True, autoflush=False)
            .with_for_update()
        )
        if delivery is None:
            if delivery_id == credential.delivery_attempt_id:
                raise OutboxLeaseLost("Stage failure source delivery authority is no longer live")
            raise OutboxStoredContractError("Projected failure delivery disappeared before lock")
        locked_deliveries_list.append(delivery)
    locked_deliveries = tuple(locked_deliveries_list)

    locked_attempt_ids = tuple(sorted(projected_attempt_ids, key=lambda value: value.int))
    locked_attempts_list: list[StageAttempt] = []
    for attempt_id in locked_attempt_ids:
        attempt = await db.scalar(
            select(StageAttempt)
            .where(StageAttempt.id == attempt_id)
            .execution_options(populate_existing=True, autoflush=False)
            .with_for_update()
        )
        if attempt is None:
            if attempt_id == credential.stage_attempt_id:
                raise OutboxLeaseLost("Stage failure source attempt authority is no longer live")
            raise OutboxStoredContractError("Projected running attempt disappeared before lock")
        locked_attempts_list.append(attempt)
    locked_attempts = tuple(locked_attempts_list)

    transaction_at = await _db_now(db, autoflush=False)
    observed_at = await _db_clock_now(db)
    if transaction_at > observed_at:
        raise OutboxStoredContractError("PostgreSQL transaction clock is later than its wall clock")
    settlement = _stage_failure_settlement_projection(
        workflow,
        locked_stages,
        source_index=source_index,
        decision=decision,
        cancelled_attempt_ids=(
            tuple(
                attempt_id
                for stage_id, attempt_id in zip(running_stage_ids, projected_attempt_ids, strict=True)
                if stage_id != credential.stage_run_id
            )
            if required_terminal
            else ()
        ),
    )
    _assert_stage_failure_graph(
        db,
        authority=credential,
        evidence=safe_evidence,
        workflow=workflow,
        stages=locked_stages,
        stage_states=stage_states,
        source_index=source_index,
        causal_source=causal_source,
        decision=decision,
        retry_delay_seconds=retry_delay_seconds,
        retry_projection=retry_projection,
        retry_message_id=retry_message_id,
        settlement=settlement,
        locked_messages=locked_messages,
        locked_message_ids=locked_message_ids,
        locked_deliveries=locked_deliveries,
        locked_delivery_ids=locked_delivery_ids,
        locked_attempts=locked_attempts,
        locked_attempt_ids=locked_attempt_ids,
        source_attempt_id=credential.stage_attempt_id,
        projected_running_stage_ids=running_stage_ids,
        projected_receipt_message_ids=projected_receipt_message_ids,
        projected_receipt_delivery_ids=projected_receipt_delivery_ids,
        live_message_ids=live_message_ids,
        transaction_at=transaction_at,
        observed_at=observed_at,
    )
    if discovered_retry_message_id is not None:
        raise OutboxStoredContractError("Retry failure source already has impossible future outbox authority")
    if _stage_execution_root_transaction(db) is not transaction:
        raise OutboxConflict("Stage failure graph changed root transaction while locking authority")

    reservation = StageFailureReservation(
        authority=credential,
        evidence=safe_evidence,
        workflow=workflow,
        stages=locked_stages,
        stage_states=stage_states,
        source_stage_id=credential.stage_run_id,
        source_stage_index=source_index,
        causal_source=causal_source,
        decision=decision,
        retry_delay_seconds=retry_delay_seconds,
        retry_projection=retry_projection,
        retry_message_id=retry_message_id,
        settlement=settlement,
        locked_messages=locked_messages,
        locked_message_ids=locked_message_ids,
        locked_deliveries=locked_deliveries,
        locked_delivery_ids=locked_delivery_ids,
        locked_attempts=locked_attempts,
        locked_attempt_ids=locked_attempt_ids,
        source_attempt_id=credential.stage_attempt_id,
        transaction_at=transaction_at,
        observed_at=observed_at,
        _session=db,
        _transaction=transaction,
    )
    _register_stage_failure_reservation(db, transaction, reservation)
    return reservation


async def consume_stage_failure_graph(
    db: AsyncSession,
    *,
    reservation: StageFailureReservation,
    authority: ExecutableStageAuthority,
    evidence: StageFailureEvidence,
) -> LockedStageFailureGraph:
    """Spend and re-prove one failure graph at a fresh PostgreSQL wall clock."""

    credential = _copy_executable_stage_authority(authority)
    safe_evidence = _copy_stage_failure_evidence(evidence)
    transaction = _stage_execution_root_transaction(db)
    registration = _consume_stage_failure_registration(db, transaction, reservation)
    if db is not reservation._session or transaction is not reservation._transaction:
        raise OutboxConflict("Stage failure reservation is outside its original session transaction")
    if credential != reservation.authority or safe_evidence != reservation.evidence:
        raise OutboxLeaseLost("Stage failure authority or evidence changed after graph reservation")
    _require_stage_execution_authorities(
        db,
        (
            reservation.workflow,
            *reservation.stages,
            *reservation.locked_messages,
            *reservation.locked_deliveries,
            *reservation.locked_attempts,
        ),
    )
    if _stage_failure_reservation_seal(reservation) != registration.seal:
        raise OutboxConflict("Stage failure reservation capability was mutated after registration")
    observed_at = await _db_clock_now(db)
    if observed_at < reservation.observed_at:
        raise OutboxStoredContractError("PostgreSQL wall clock moved backwards across failure consumption")
    if _stage_execution_root_transaction(db) is not transaction:
        raise OutboxConflict("Stage failure graph changed root transaction while consuming authority")
    _assert_stage_failure_graph_from_reservation(db, reservation, observed_at=observed_at)

    retry_intent: StageReadyIntent | None = None
    next_attempt_at: datetime | None = None
    stage_ready_reservation: StageReadyReservation | None = None
    cancellation_reservation: OutboxCancellationReservation | None = None
    if reservation.decision == "retry":
        if reservation.retry_projection is None or reservation.retry_delay_seconds is None or reservation.retry_message_id is None:
            raise OutboxStoredContractError("Retry failure graph lacks its exact projection authority")
        next_attempt_at = observed_at + timedelta(seconds=reservation.retry_delay_seconds)
        retry_intent = _stage_failure_retry_intent(
            reservation.workflow,
            reservation.retry_projection,
            evidence=reservation.evidence,
            next_attempt_at=next_attempt_at,
        )
        stage_ready_reservation = _stage_failure_stage_ready_reservation(
            db,
            transaction,
            stages=reservation.stages,
            stage_states=reservation.stage_states,
            intent=retry_intent,
            message_id=reservation.retry_message_id,
        )
    elif reservation.stages[reservation.source_stage_index].required:
        cancellation_reservation = _stage_failure_cancellation_reservation(
            db,
            transaction,
            reservation=reservation,
        )

    locked = LockedStageFailureGraph(
        authority=credential,
        evidence=safe_evidence,
        workflow=reservation.workflow,
        stages=reservation.stages,
        stage_states=reservation.stage_states,
        source_stage_id=reservation.source_stage_id,
        source_stage_index=reservation.source_stage_index,
        causal_source=reservation.causal_source,
        decision=reservation.decision,
        retry_delay_seconds=reservation.retry_delay_seconds,
        retry_projection=reservation.retry_projection,
        retry_message_id=reservation.retry_message_id,
        settlement=reservation.settlement,
        locked_messages=reservation.locked_messages,
        locked_message_ids=reservation.locked_message_ids,
        locked_deliveries=reservation.locked_deliveries,
        locked_delivery_ids=reservation.locked_delivery_ids,
        locked_attempts=reservation.locked_attempts,
        locked_attempt_ids=reservation.locked_attempt_ids,
        source_attempt_id=reservation.source_attempt_id,
        transaction_at=reservation.transaction_at,
        retry_intent=retry_intent,
        next_attempt_at=next_attempt_at,
        stage_ready_reservation=stage_ready_reservation,
        outbox_cancellation_reservation=cancellation_reservation,
        observed_at=observed_at,
    )
    if stage_ready_reservation is not None:
        _register_transferred_failure_stage_ready_reservation(
            db,
            transaction,
            failure_reservation=reservation,
            failure_registration=registration,
            stage_ready_reservation=stage_ready_reservation,
        )
    elif cancellation_reservation is not None:
        _register_transferred_outbox_cancellation_reservation(
            db,
            transaction,
            failure_reservation=reservation,
            failure_registration=registration,
            cancellation_reservation=cancellation_reservation,
        )
    return locked


async def cancel_reserved_outbox_messages(
    db: AsyncSession,
    *,
    reservation: OutboxCancellationReservation,
) -> tuple[tuple[OutboxDeliveryAttempt, ...], tuple[OutboxMessage, ...]]:
    """Consume transferred terminalization authority and cancel its suffix."""

    transaction = _stage_execution_root_transaction(db)
    registered_seal = _consume_outbox_cancellation_registration(db, transaction, reservation)
    if db is not reservation._session or transaction is not reservation._transaction:
        raise OutboxConflict("Outbox cancellation is outside its original session transaction")
    _require_stage_execution_authorities(db, (*reservation.deliveries, *reservation.messages))
    if _outbox_cancellation_reservation_seal(reservation) != registered_seal:
        raise OutboxConflict("Outbox cancellation capability was mutated after registration")
    _assert_outbox_cancellation_authority(reservation)

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


async def claim_outbox_delivery(
    db: AsyncSession,
    *,
    publisher_id: str,
    lease_seconds: int = 60,
) -> ClaimedOutboxDelivery | None:
    """Claim the oldest due message and create its exact delivery evidence."""

    owner = _text(publisher_id, field_name="publisher_id", maximum=255)
    duration = _bounded_int(
        lease_seconds,
        field_name="lease_seconds",
        minimum=1,
        maximum=_MAX_LEASE_SECONDS,
    )
    message = await db.scalar(
        select(OutboxMessage)
        .join(
            StageRun,
            and_(
                StageRun.id == OutboxMessage.stage_run_id,
                StageRun.workflow_run_id == OutboxMessage.workflow_run_id,
            ),
        )
        .join(
            WorkflowRun,
            WorkflowRun.id == OutboxMessage.workflow_run_id,
        )
        .where(
            OutboxMessage.status.in_(_CLAIMABLE_MESSAGE_STATUSES),
            OutboxMessage.available_at <= func.transaction_timestamp(),
            OutboxMessage.attempt_count < OutboxMessage.max_attempts,
            OutboxMessage.aggregate_type == "workflow_stage",
            OutboxMessage.aggregate_id == StageRun.id,
            OutboxMessage.aggregate_version == StageRun.state_version,
            OutboxMessage.stage_key == StageRun.stage_key,
            OutboxMessage.target_attempt_number == StageRun.attempt_count + 1,
            OutboxMessage.input_checksum == StageRun.input_checksum,
            OutboxMessage.plan_checksum == WorkflowRun.plan_checksum,
            OutboxMessage.correlation_id == WorkflowRun.correlation_id,
            WorkflowRun.status.in_(_ACTIVE_WORKFLOW_STATUSES),
            StageRun.status.in_(_CLAIMABLE_STAGE_STATUSES),
            StageRun.next_attempt_at.is_not(None),
            StageRun.attempt_count < StageRun.max_attempts,
        )
        .order_by(
            OutboxMessage.available_at.asc(),
            OutboxMessage.created_at.asc(),
            OutboxMessage.id.asc(),
        )
        .with_for_update(of=OutboxMessage, skip_locked=True)
        .limit(1)
    )
    if message is None:
        return None
    if message.status not in _CLAIMABLE_MESSAGE_STATUSES:
        raise OutboxStoredContractError("Claim query returned a non-claimable message")
    normalized = _stored_envelope(message)
    if message.max_attempts != OUTBOX_V1_MAX_ATTEMPTS:
        raise OutboxStoredContractError("Persisted outbox retry budget is not v1")

    now = await _db_now(db)
    delivery_id = uuid.uuid4()
    token = uuid.uuid4()
    delivery_cycle = message.delivery_cycle + 1
    cycle_key = delivery_cycle_idempotency_key(
        message.logical_key,
        delivery_cycle=delivery_cycle,
    )
    expires_at = now + timedelta(seconds=duration)

    message.status = "dispatching"
    message.state_version += 1
    message.attempt_count += 1
    message.delivery_cycle = delivery_cycle
    message.cycle_key = cycle_key
    message.available_at = None
    message.active_delivery_attempt_id = delivery_id
    message.lease_owner = owner
    message.lease_token = token
    message.leased_at = now
    message.heartbeat_at = now
    message.lease_expires_at = expires_at
    message.receipt_deadline_at = None
    await db.flush([message])

    delivery = OutboxDeliveryAttempt(
        id=delivery_id,
        message_id=message.id,
        delivery_cycle=delivery_cycle,
        attempt_number=message.attempt_count,
        cycle_key=cycle_key,
        delivery_token=token,
        publisher_id=owner,
        status="dispatching",
        state_version=1,
        leased_at=now,
        heartbeat_at=now,
        lease_expires_at=expires_at,
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
    )
    db.add(delivery)
    await db.flush([delivery])
    return ClaimedOutboxDelivery(
        message_id=_persisted_uuid(message.id, field_name="message.id"),
        delivery_attempt_id=_persisted_uuid(
            delivery.id,
            field_name="delivery.id",
        ),
        delivery_token=_persisted_uuid(token, field_name="delivery_token"),
        message_state_version=message.state_version,
        delivery_state_version=delivery.state_version,
        delivery_cycle=delivery_cycle,
        cycle_key=cycle_key,
        correlation_id=_persisted_uuid(
            message.correlation_id,
            field_name="message.correlation_id",
        ),
        topic=message.topic,
        schema_version=message.schema_version,
        envelope_checksum=message.envelope_checksum,
        logical_key=message.logical_key,
        envelope_canonical=normalized.canonical,
    )


async def heartbeat_outbox_delivery(
    db: AsyncSession,
    *,
    message_id: uuid.UUID,
    delivery_attempt_id: uuid.UUID,
    delivery_token: uuid.UUID,
    expected_message_version: int,
    expected_delivery_version: int,
    lease_seconds: int = 60,
) -> OutboxDeliveryMutation:
    """Extend a dispatch lease with token-and-two-version fencing."""

    message_key = _uuid(message_id, field_name="message_id")
    delivery_key = _uuid(
        delivery_attempt_id,
        field_name="delivery_attempt_id",
    )
    token = _uuid(delivery_token, field_name="delivery_token")
    message_version = _state_version(
        expected_message_version,
        field_name="expected_message_version",
    )
    delivery_version = _state_version(
        expected_delivery_version,
        field_name="expected_delivery_version",
    )
    duration = _bounded_int(
        lease_seconds,
        field_name="lease_seconds",
        minimum=1,
        maximum=_MAX_LEASE_SECONDS,
    )
    message, delivery = await _lock_delivery_pair(
        db,
        message_id=message_key,
        delivery_attempt_id=delivery_key,
    )
    now = await _db_now(db)
    _assert_live_dispatch_fence(
        message,
        delivery,
        delivery_token=token,
        expected_message_version=message_version,
        expected_delivery_version=delivery_version,
        now=now,
    )
    expires_at = max(message.lease_expires_at, now + timedelta(seconds=duration))

    message.state_version += 1
    message.heartbeat_at = now
    message.lease_expires_at = expires_at
    await db.flush([message])
    delivery.state_version += 1
    delivery.heartbeat_at = now
    delivery.lease_expires_at = expires_at
    await db.flush([delivery])
    return OutboxDeliveryMutation(message=message, delivery=delivery)


async def mark_outbox_dispatched(
    db: AsyncSession,
    *,
    message_id: uuid.UUID,
    delivery_attempt_id: uuid.UUID,
    delivery_token: uuid.UUID,
    expected_message_version: int,
    expected_delivery_version: int,
    broker_name: str,
    broker_message_id: str,
    receipt_timeout_seconds: int,
) -> OutboxDeliveryMutation:
    """Record broker acceptance and open the bounded receipt window."""

    message_key = _uuid(message_id, field_name="message_id")
    delivery_key = _uuid(
        delivery_attempt_id,
        field_name="delivery_attempt_id",
    )
    token = _uuid(delivery_token, field_name="delivery_token")
    message_version = _state_version(
        expected_message_version,
        field_name="expected_message_version",
    )
    delivery_version = _state_version(
        expected_delivery_version,
        field_name="expected_delivery_version",
    )
    clean_broker = _identity(broker_name, field_name="broker_name")
    clean_broker_id = _text(
        broker_message_id,
        field_name="broker_message_id",
        maximum=255,
    )
    timeout = _bounded_int(
        receipt_timeout_seconds,
        field_name="receipt_timeout_seconds",
        minimum=1,
        maximum=_MAX_RECEIPT_TIMEOUT_SECONDS,
    )
    message, delivery = await _lock_delivery_pair(
        db,
        message_id=message_key,
        delivery_attempt_id=delivery_key,
    )
    if _is_dispatch_effect_replay(
        message,
        delivery,
        delivery_token=token,
        expected_message_version=message_version,
        expected_delivery_version=delivery_version,
        broker_name=clean_broker,
        broker_message_id=clean_broker_id,
        receipt_timeout_seconds=timeout,
    ):
        return OutboxDeliveryMutation(
            message=message,
            delivery=delivery,
            replayed=True,
        )
    now = await _db_now(db)
    _assert_live_dispatch_fence(
        message,
        delivery,
        delivery_token=token,
        expected_message_version=message_version,
        expected_delivery_version=delivery_version,
        now=now,
    )
    deadline = now + timedelta(seconds=timeout)

    delivery.status = "awaiting_receipt"
    delivery.state_version += 1
    delivery.broker_name = clean_broker
    delivery.broker_message_id = clean_broker_id
    delivery.broker_receipt_id = ""
    delivery.dispatched_at = now
    delivery.receipt_deadline_at = deadline
    await db.flush([delivery])

    message.status = "awaiting_receipt"
    message.state_version += 1
    message.available_at = None
    message.lease_owner = ""
    message.lease_token = None
    message.leased_at = None
    message.heartbeat_at = None
    message.lease_expires_at = None
    message.receipt_deadline_at = deadline
    await db.flush([message])
    return OutboxDeliveryMutation(message=message, delivery=delivery)


async def fail_outbox_delivery(
    db: AsyncSession,
    *,
    message_id: uuid.UUID,
    delivery_attempt_id: uuid.UUID,
    delivery_token: uuid.UUID,
    expected_message_version: int,
    expected_delivery_version: int,
    error: SanitizedOutboxError,
) -> OutboxDeliveryMutation:
    """Record one exact delivery failure and retry or dead-letter it."""

    safe_error = _safe_error(error)
    message_key = _uuid(message_id, field_name="message_id")
    delivery_key = _uuid(
        delivery_attempt_id,
        field_name="delivery_attempt_id",
    )
    token = _uuid(delivery_token, field_name="delivery_token")
    message_version = _state_version(
        expected_message_version,
        field_name="expected_message_version",
    )
    delivery_version = _state_version(
        expected_delivery_version,
        field_name="expected_delivery_version",
    )
    message, delivery = await _lock_delivery_pair(
        db,
        message_id=message_key,
        delivery_attempt_id=delivery_key,
    )
    if _is_exact_failure_replay(
        message,
        delivery,
        delivery_token=token,
        expected_message_version=message_version,
        expected_delivery_version=delivery_version,
        error=safe_error,
    ):
        return OutboxDeliveryMutation(
            message=message,
            delivery=delivery,
            replayed=True,
        )
    now = await _db_now(db)
    _assert_active_delivery_fence(
        message,
        delivery,
        delivery_token=token,
        expected_message_version=message_version,
        expected_delivery_version=delivery_version,
        now=now,
    )
    await _terminalize_delivery_failure(
        db,
        delivery,
        status="failed",
        error=safe_error,
        now=now,
    )
    _schedule_message_after_failure(message, error=safe_error, now=now)
    await db.flush([message])
    return OutboxDeliveryMutation(message=message, delivery=delivery)


async def recover_expired_outbox_deliveries(
    db: AsyncSession,
    *,
    limit: int = 100,
) -> list[OutboxRecoveryResult]:
    """Abandon expired dispatch/receipt cycles and retry or dead-letter them."""

    batch_limit = _bounded_int(
        limit,
        field_name="limit",
        minimum=1,
        maximum=_MAX_RECOVERY_BATCH,
    )
    recovered: list[OutboxRecoveryResult] = []
    due_at = func.coalesce(
        OutboxMessage.lease_expires_at,
        OutboxMessage.receipt_deadline_at,
    )
    while len(recovered) < batch_limit:
        message = await db.scalar(
            select(OutboxMessage)
            .where(
                or_(
                    ((OutboxMessage.status == "dispatching") & (OutboxMessage.lease_expires_at <= func.transaction_timestamp())),
                    ((OutboxMessage.status == "awaiting_receipt") & (OutboxMessage.receipt_deadline_at <= func.transaction_timestamp())),
                )
            )
            .order_by(due_at.asc(), OutboxMessage.id.asc())
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if message is None:
            break
        if message.active_delivery_attempt_id is None:
            raise OutboxStoredContractError("Expired active message has no delivery-attempt pointer")
        delivery = await db.scalar(
            select(OutboxDeliveryAttempt)
            .where(
                OutboxDeliveryAttempt.id == message.active_delivery_attempt_id,
                OutboxDeliveryAttempt.message_id == message.id,
            )
            .with_for_update()
        )
        if delivery is None or delivery.status != message.status:
            raise OutboxStoredContractError("Expired message and active delivery evidence disagree")
        _assert_recovery_pair(message, delivery)
        now = await _db_now(db)
        if message.status == "dispatching":
            if message.lease_expires_at is None or message.lease_expires_at > now:
                raise OutboxStoredContractError("Recovery query returned a live dispatch")
            safe_error = sanitize_outbox_error(
                "Publisher lease expired before broker acceptance was recorded",
                code="outbox.dispatch_lease_expired",
                retryable=True,
                error_class="DeliveryLeaseExpired",
            )
        else:
            if message.receipt_deadline_at is None or message.receipt_deadline_at > now:
                raise OutboxStoredContractError("Recovery query returned a live receipt window")
            safe_error = sanitize_outbox_error(
                "Broker delivery receipt did not arrive before its deadline",
                code="outbox.receipt_timeout",
                retryable=True,
                error_class="DeliveryReceiptTimeout",
            )
        await _terminalize_delivery_failure(
            db,
            delivery,
            status="abandoned",
            error=safe_error,
            now=now,
        )
        _schedule_message_after_failure(message, error=safe_error, now=now)
        await db.flush([message])
        recovered.append(
            OutboxRecoveryResult(
                message_id=message.id,
                delivery_attempt_id=delivery.id,
                message_status=message.status,
                available_at=message.available_at,
            )
        )
    return recovered


async def _lock_receipt_authority(
    db: AsyncSession,
    *,
    workflow_run_id: uuid.UUID,
    stage_run_id: uuid.UUID,
    message_id: uuid.UUID,
    delivery_attempt_id: uuid.UUID,
    missing_is_none: bool = False,
) -> tuple[
    WorkflowRun | None,
    StageRun | None,
    OutboxMessage | None,
    OutboxDeliveryAttempt | None,
]:
    """Lock one receipt chain in canonical W -> S -> M -> D order."""

    workflow = await db.scalar(
        select(WorkflowRun)
        .where(WorkflowRun.id == workflow_run_id)
        .execution_options(populate_existing=True, autoflush=False)
        .with_for_update()
    )
    if workflow is None:
        if missing_is_none:
            return None, None, None, None
        raise OutboxNotFound("Workflow run not found")
    stage = await db.scalar(
        select(StageRun)
        .where(
            StageRun.id == stage_run_id,
            StageRun.workflow_run_id == workflow.id,
        )
        .execution_options(populate_existing=True, autoflush=False)
        .with_for_update()
    )
    if stage is None:
        if missing_is_none:
            return None, None, None, None
        raise OutboxNotFound("Workflow stage not found")
    message = await db.scalar(
        select(OutboxMessage)
        .where(
            OutboxMessage.id == message_id,
            OutboxMessage.workflow_run_id == workflow.id,
            OutboxMessage.stage_run_id == stage.id,
        )
        .execution_options(populate_existing=True, autoflush=False)
        .with_for_update()
    )
    if message is None:
        if missing_is_none:
            return None, None, None, None
        raise OutboxNotFound("Outbox message not found")
    delivery = await db.scalar(
        select(OutboxDeliveryAttempt)
        .where(
            OutboxDeliveryAttempt.id == delivery_attempt_id,
            OutboxDeliveryAttempt.message_id == message.id,
        )
        .execution_options(populate_existing=True, autoflush=False)
        .with_for_update()
    )
    if delivery is None:
        if missing_is_none:
            return None, None, None, None
        raise OutboxNotFound("Outbox delivery attempt not found")
    return workflow, stage, message, delivery


def _assert_persisted_receipt_lineage(
    workflow: WorkflowRun,
    stage: StageRun,
    message: OutboxMessage,
    delivery: OutboxDeliveryAttempt,
) -> None:
    _stored_envelope(message)
    if (
        message.workflow_run_id != workflow.id
        or message.stage_run_id != stage.id
        or stage.workflow_run_id != workflow.id
        or message.aggregate_type != "workflow_stage"
        or message.aggregate_id != stage.id
        or message.correlation_id != workflow.correlation_id
        or message.plan_checksum != workflow.plan_checksum
        or message.stage_key != stage.stage_key
        or message.input_checksum != stage.input_checksum
        or message.max_attempts != OUTBOX_V1_MAX_ATTEMPTS
        or delivery.message_id != message.id
        or delivery.cycle_key
        != delivery_cycle_idempotency_key(
            message.logical_key,
            delivery_cycle=delivery.delivery_cycle,
        )
    ):
        raise OutboxStoredContractError("Persisted workflow receipt lineage is inconsistent")


def _assert_latest_delivery_lineage(
    message: OutboxMessage,
    delivery: OutboxDeliveryAttempt,
) -> None:
    if (
        delivery.attempt_number != message.attempt_count
        or delivery.delivery_cycle != message.delivery_cycle
        or delivery.cycle_key != message.cycle_key
    ):
        raise OutboxLeaseLost("Receipt delivery is no longer the latest message lineage")


def _assert_stage_execution_receipt(
    db: AsyncSession,
    *,
    authority: ExecutableStageAuthority,
    workflow: WorkflowRun,
    stage: StageRun,
    message: OutboxMessage,
    delivery: OutboxDeliveryAttempt,
    attempt: StageAttempt,
    observed_at: datetime,
    lease_policy: Literal["live", "expired", "any"] = "live",
) -> None:
    """Prove exact live W/S/M/D/A authority without querying or mutating."""

    _require_stage_execution_authorities(
        db,
        (workflow, stage, message, delivery, attempt),
    )
    now = _aware_datetime(observed_at, field_name="stage execution observed_at")
    if type(lease_policy) is not str or lease_policy not in {"live", "expired", "any"}:
        raise OutboxValidation("Stage execution receipt lease policy is outside its closed registry")

    # First distinguish a stale or forged detached credential from malformed
    # durable authority.  Every identity and CAS field in the DTO participates.
    if (
        _persisted_uuid(workflow.id, field_name="workflow.id") != authority.workflow_run_id
        or _persisted_uuid(stage.id, field_name="stage.id") != authority.stage_run_id
        or _persisted_uuid(attempt.id, field_name="attempt.id") != authority.stage_attempt_id
        or _persisted_uuid(message.id, field_name="message.id") != authority.message_id
        or _persisted_uuid(delivery.id, field_name="delivery.id") != authority.delivery_attempt_id
        or workflow.state_version != authority.workflow_state_version
        or stage.state_version != authority.stage_state_version
        or attempt.state_version != authority.attempt_state_version
        or attempt.attempt_number != authority.attempt_number
        or delivery.delivery_cycle != authority.delivery_cycle
        or delivery.cycle_key != authority.cycle_key
        or stage.stage_key != authority.stage_key
        or stage.input_checksum != authority.input_checksum
        or stage.checkpoint_version != authority.checkpoint_version
        or stage.lease_owner != authority.lease_owner
        or stage.lease_token != authority.stage_lease_token
        or stage.lease_expires_at != authority.lease_expires_at
        or delivery.broker_receipt_id != authority.broker_receipt_id
    ):
        raise OutboxLeaseLost("Executable stage authority no longer matches its locked receipt lineage")
    if (
        workflow.status != "running"
        or stage.status != "running"
        or attempt.status != "running"
        or message.status != "delivered"
        or delivery.status != "delivered"
        or type(stage.lease_expires_at) is not datetime
        or stage.lease_expires_at.tzinfo is None
    ):
        raise OutboxLeaseLost("Executable stage receipt is no longer live")
    if lease_policy == "live" and stage.lease_expires_at <= now:
        raise OutboxLeaseLost("Executable stage receipt is no longer live")
    if lease_policy == "expired" and stage.lease_expires_at > now:
        raise OutboxLeaseLost("Executable stage receipt has not expired")

    _assert_persisted_receipt_lineage(workflow, stage, message, delivery)
    _assert_latest_delivery_lineage(message, delivery)
    try:
        normalized_plan = _normalized_workflow_plan(workflow)
        if type(workflow.input_manifest) is not dict or checksum_json(workflow.input_manifest) != workflow.input_checksum:
            raise OutboxStoredContractError("Workflow input authority is not canonical")
        definition = next(
            (raw for raw in workflow.stage_plan if raw.get("stage_key") == stage.stage_key and raw.get("ordinal") == stage.ordinal),
            None,
        )
        if definition is None or len(normalized_plan.stages) != len(workflow.stage_plan):
            raise OutboxStoredContractError("Running stage is absent from canonical workflow authority")
        _assert_stage_plan_definition(workflow, stage, definition)
        _assert_stage_execution_message_provenance(
            workflow,
            stage,
            message,
            delivery,
            attempt,
        )

        for value, field_name in (
            (workflow.started_at, "workflow.started_at"),
            (stage.first_started_at, "stage.first_started_at"),
            (stage.leased_at, "stage.leased_at"),
            (stage.heartbeat_at, "stage.heartbeat_at"),
            (stage.lease_expires_at, "stage.lease_expires_at"),
            (attempt.started_at, "attempt.started_at"),
            (attempt.heartbeat_at, "attempt.heartbeat_at"),
            (attempt.lease_expires_at, "attempt.lease_expires_at"),
            (message.delivered_at, "message.delivered_at"),
            (delivery.leased_at, "delivery.leased_at"),
            (delivery.heartbeat_at, "delivery.heartbeat_at"),
            (delivery.lease_expires_at, "delivery.lease_expires_at"),
            (delivery.dispatched_at, "delivery.dispatched_at"),
            (delivery.receipt_received_at, "delivery.receipt_received_at"),
            (delivery.completed_at, "delivery.completed_at"),
            (workflow.created_at, "workflow.created_at"),
            (workflow.updated_at, "workflow.updated_at"),
            (stage.created_at, "stage.created_at"),
            (stage.updated_at, "stage.updated_at"),
            (message.created_at, "message.created_at"),
            (message.updated_at, "message.updated_at"),
            (delivery.created_at, "delivery.created_at"),
            (delivery.updated_at, "delivery.updated_at"),
            (attempt.created_at, "attempt.created_at"),
        ):
            _aware_datetime(value, field_name=field_name)
        for value, field_name in (
            (workflow.state_version, "workflow.state_version"),
            (stage.state_version, "stage.state_version"),
            (attempt.state_version, "attempt.state_version"),
            (message.aggregate_version, "message.aggregate_version"),
            (message.state_version, "message.state_version"),
            (message.attempt_count, "message.attempt_count"),
            (delivery.state_version, "delivery.state_version"),
        ):
            _state_version(value, field_name=field_name)
        for value, field_name in (
            (attempt.checkpoint_start_version, "attempt.checkpoint_start_version"),
            (attempt.checkpoint_end_version, "attempt.checkpoint_end_version"),
        ):
            _bounded_int(
                value,
                field_name=field_name,
                minimum=0,
                maximum=2_147_483_647,
            )
        _bounded_int(
            stage.attempt_count,
            field_name="stage.attempt_count",
            minimum=1,
            maximum=20,
        )
        _bounded_int(
            delivery.attempt_number,
            field_name="delivery.attempt_number",
            minimum=1,
            maximum=OUTBOX_V1_MAX_ATTEMPTS,
        )
        _persisted_uuid(attempt.outbox_delivery_attempt_id, field_name="attempt.outbox_delivery_attempt_id")
        _persisted_uuid(attempt.lease_token, field_name="attempt.lease_token")
        _persisted_uuid(delivery.delivery_token, field_name="delivery.delivery_token")
        _identity(delivery.broker_name, field_name="delivery.broker_name")
        _text(
            delivery.broker_message_id,
            field_name="delivery.broker_message_id",
            maximum=255,
        )
        _lower_sha256(
            delivery.broker_receipt_id,
            field_name="delivery.broker_receipt_id",
        )
        _text(delivery.publisher_id, field_name="delivery.publisher_id", maximum=255)
        _text(attempt.lease_owner, field_name="attempt.lease_owner", maximum=255)
        _lower_sha256(attempt.delivery_id, field_name="attempt.delivery_id")
        if type(stage.checkpoint) is not dict or checksum_json(stage.checkpoint) != stage.checkpoint_checksum:
            raise OutboxStoredContractError("Running stage checkpoint authority is not canonical")
        if type(stage.output_manifest) is not dict:
            raise OutboxStoredContractError("Running stage output authority is not an object")
    except OutboxStoredContractError:
        raise
    except (OutboxValidation, TypeError, ValueError) as exc:
        raise OutboxStoredContractError("Stage execution receipt contains invalid persisted authority") from exc

    expected_cycle_key = delivery_cycle_idempotency_key(
        message.logical_key,
        delivery_cycle=message.delivery_cycle,
    )
    if (
        stage.workflow_run_id != workflow.id
        or workflow.started_at is None
        or workflow.completed_at is not None
        or stage.attempt_count > stage.max_attempts
        or stage.attempt_count != attempt.attempt_number
        or stage.attempt_count != message.target_attempt_number
        or stage.state_version != message.aggregate_version + attempt.state_version
        or stage.next_attempt_at is not None
        or stage.completed_at is not None
        or stage.output_manifest != {}
        or stage.output_checksum != ""
        or stage.last_error_code != ""
        or stage.last_error_summary != ""
        or stage.last_error_retryable
        or stage.first_started_at is None
        or stage.leased_at is None
        or stage.heartbeat_at is None
        or stage.lease_token is None
        or stage.first_started_at > stage.leased_at
        or stage.leased_at > stage.heartbeat_at
        or stage.heartbeat_at > stage.lease_expires_at
        or attempt.stage_run_id != stage.id
        or attempt.outbox_delivery_attempt_id is None
        or attempt.outbox_delivery_attempt_id != delivery.id
        or attempt.delivery_id != delivery.cycle_key
        or attempt.input_checksum != stage.input_checksum
        or attempt.checkpoint_start_version > attempt.checkpoint_end_version
        or attempt.checkpoint_end_version != stage.checkpoint_version
        or attempt.lease_token != stage.lease_token
        or attempt.lease_token == delivery.delivery_token
        or attempt.lease_owner != stage.lease_owner
        or attempt.started_at != stage.leased_at
        or attempt.heartbeat_at != stage.heartbeat_at
        or attempt.lease_expires_at != stage.lease_expires_at
        or attempt.completed_at is not None
        or attempt.output_checksum != ""
        or attempt.error_code != ""
        or attempt.error_class != ""
        or attempt.error_summary != ""
        or attempt.retryable
        or message.aggregate_version < 1
        or message.target_attempt_number != attempt.attempt_number
        or message.active_delivery_attempt_id is not None
        or message.available_at is not None
        or message.lease_owner != ""
        or message.lease_token is not None
        or message.leased_at is not None
        or message.heartbeat_at is not None
        or message.lease_expires_at is not None
        or message.receipt_deadline_at is not None
        or message.dead_lettered_at is not None
        or message.cancelled_at is not None
        or message.attempt_count < 1
        or message.attempt_count > message.max_attempts
        or message.max_attempts != OUTBOX_V1_MAX_ATTEMPTS
        or message.cycle_key != expected_cycle_key
        or delivery.attempt_number != message.attempt_count
        or delivery.delivery_cycle != message.delivery_cycle
        or delivery.cycle_key != message.cycle_key
        or delivery.receipt_deadline_at is not None
        or delivery.receipt_received_at != delivery.completed_at
        or message.delivered_at != delivery.completed_at
        or delivery.leased_at > delivery.heartbeat_at
        or delivery.heartbeat_at > delivery.lease_expires_at
        or delivery.dispatched_at < delivery.leased_at
        or delivery.receipt_received_at < delivery.dispatched_at
        or delivery.completed_at > attempt.started_at
        or workflow.started_at > attempt.started_at
        or workflow.created_at > workflow.updated_at
        or stage.created_at > stage.updated_at
        or message.created_at > message.updated_at
        or delivery.created_at > delivery.updated_at
        or attempt.created_at > attempt.started_at
        or workflow.started_at > now
        or workflow.created_at > now
        or workflow.updated_at > now
        or stage.first_started_at > now
        or stage.leased_at > now
        or stage.heartbeat_at > now
        or stage.created_at > now
        or stage.updated_at > now
        or attempt.started_at > now
        or attempt.heartbeat_at > now
        or attempt.created_at > now
        or message.delivered_at > now
        or message.created_at > now
        or message.updated_at > now
        or delivery.leased_at > now
        or delivery.heartbeat_at > now
        or delivery.dispatched_at > now
        or delivery.receipt_received_at > now
        or delivery.completed_at > now
        or delivery.created_at > now
        or delivery.updated_at > now
        or delivery.error_code != ""
        or delivery.error_class != ""
        or delivery.error_summary != ""
        or delivery.retryable
    ):
        raise OutboxStoredContractError("Locked W/S/M/D/A receipt authority is internally inconsistent")


def _assert_stage_execution_message_provenance(
    workflow: WorkflowRun,
    stage: StageRun,
    message: OutboxMessage,
    delivery: OutboxDeliveryAttempt,
    attempt: StageAttempt,
) -> None:
    """Validate intrinsic source provenance without claiming an unlocked cause."""

    if type(message.emission_kind) is not str:
        raise OutboxStoredContractError("Stage execution source has invalid emission provenance")
    if message.emission_kind == "manual_redrive":
        raise OutboxStoredContractError("Manual-redrive execution requires an expanded parent-lineage lock")
    if message.emission_kind not in {*_RUNTIME_EMISSION_KINDS, "migration_backfill"}:
        raise OutboxStoredContractError("Stage execution source has unknown emission provenance")
    if (
        message.redrive_of_message_id is not None
        or message.redrive_ordinal != 0
        or message.redrive_requested_by != ""
        or message.redrive_requested_by_id != ""
        or message.redrive_reason != ""
        or message.redrive_requested_at is not None
    ):
        raise OutboxStoredContractError("Stage execution source is not a root delivery lineage")

    cause_id = None
    if message.causation_id is not None:
        cause_id = _persisted_uuid(
            message.causation_id,
            field_name="message.causation_id",
        )
        if cause_id in {
            _persisted_uuid(workflow.id, field_name="workflow.id"),
            _persisted_uuid(stage.id, field_name="stage.id"),
            _persisted_uuid(message.id, field_name="message.id"),
            _persisted_uuid(delivery.id, field_name="delivery.id"),
            _persisted_uuid(attempt.id, field_name="attempt.id"),
        }:
            raise OutboxStoredContractError("Stage execution source has self-referential causation")

    if message.emission_kind == "migration_backfill":
        if cause_id is not None:
            raise OutboxStoredContractError("Migration-backfill execution cannot claim runtime causation")
        return
    if message.emission_kind == "root_ready":
        valid_shape = cause_id is None and not stage.depends_on and message.target_attempt_number == 1
    elif message.emission_kind == "dependency_ready":
        valid_shape = cause_id is not None and bool(stage.depends_on) and message.target_attempt_number == 1
    else:
        valid_shape = cause_id is not None and message.target_attempt_number > 1
    if not valid_shape:
        raise OutboxStoredContractError("Stage execution source emission kind contradicts its intrinsic causal shape")


def _assert_receipt_lineage(
    workflow: WorkflowRun,
    stage: StageRun,
    message: OutboxMessage,
    delivery: OutboxDeliveryAttempt,
    *,
    claim: ClaimedOutboxDelivery,
) -> None:
    _assert_persisted_receipt_lineage(workflow, stage, message, delivery)
    if (
        message.id != claim.message_id
        or delivery.id != claim.delivery_attempt_id
        or delivery.delivery_token != claim.delivery_token
        or delivery.delivery_cycle != claim.delivery_cycle
        or delivery.cycle_key != claim.cycle_key
        or message.correlation_id != claim.correlation_id
        or message.topic != claim.topic
        or message.schema_version != claim.schema_version
        or message.envelope_checksum != claim.envelope_checksum
        or message.logical_key != claim.logical_key
        or message.envelope_canonical != claim.envelope_canonical
    ):
        raise OutboxLeaseLost("Receipt command no longer matches the latest delivery lineage")


def _assert_live_receipt_authority(
    workflow: WorkflowRun,
    stage: StageRun,
    message: OutboxMessage,
    delivery: OutboxDeliveryAttempt,
    *,
    claim: ClaimedOutboxDelivery,
    broker_name: str,
    broker_message_id: str,
    now: datetime,
) -> None:
    if (
        workflow.status not in _ACTIVE_WORKFLOW_STATUSES
        or stage.status not in _CLAIMABLE_STAGE_STATUSES
        or stage.next_attempt_at is None
        or stage.next_attempt_at > now
        or stage.attempt_count >= stage.max_attempts
        or message.aggregate_version != stage.state_version
        or message.target_attempt_number != stage.attempt_count + 1
    ):
        raise OutboxLeaseLost("Workflow stage is no longer eligible for receipt activation")
    if not _has_exact_replay_version_delta(
        message,
        delivery,
        expected_message_version=claim.message_state_version,
        expected_delivery_version=claim.delivery_state_version,
        allowed_deltas={0, 1},
    ):
        raise OutboxLeaseLost("Receipt command versions are outside the active transition window")
    if (
        message.active_delivery_attempt_id != delivery.id
        or message.status != delivery.status
        or delivery.status not in _ACTIVE_DELIVERY_STATUSES
        or delivery.broker_receipt_id != ""
        or delivery.error_code != ""
        or delivery.error_class != ""
        or delivery.error_summary != ""
        or delivery.retryable
    ):
        raise OutboxStoredContractError("Active receipt evidence is internally inconsistent")
    if message.status == "dispatching":
        if (
            message.lease_token != claim.delivery_token
            or message.lease_owner != delivery.publisher_id
            or message.leased_at != delivery.leased_at
            or message.heartbeat_at != delivery.heartbeat_at
            or message.lease_expires_at != delivery.lease_expires_at
            or message.lease_expires_at is None
            or delivery.lease_expires_at is None
            or message.lease_expires_at <= now
            or delivery.lease_expires_at <= now
            or delivery.broker_name != ""
            or delivery.broker_message_id != ""
            or delivery.dispatched_at is not None
            or delivery.receipt_deadline_at is not None
        ):
            raise OutboxLeaseLost("Dispatch receipt arrived outside its live lease fence")
        return
    if (
        message.lease_owner != ""
        or message.lease_token is not None
        or message.leased_at is not None
        or message.heartbeat_at is not None
        or message.lease_expires_at is not None
        or message.receipt_deadline_at is None
        or message.receipt_deadline_at <= now
        or message.receipt_deadline_at != delivery.receipt_deadline_at
        or delivery.dispatched_at is None
        or delivery.broker_name != broker_name
        or delivery.broker_message_id != broker_message_id
    ):
        raise OutboxLeaseLost("Broker receipt arrived outside its exact live receipt window")


def _assert_receipt_replay(
    message: OutboxMessage,
    delivery: OutboxDeliveryAttempt,
    *,
    claim: ClaimedOutboxDelivery,
    broker_name: str,
    broker_message_id: str,
    broker_receipt_id: str,
) -> None:
    if not _has_exact_replay_version_delta(
        message,
        delivery,
        expected_message_version=claim.message_state_version,
        expected_delivery_version=claim.delivery_state_version,
        allowed_deltas={1, 2},
    ):
        raise OutboxLeaseLost("Receipt replay versions are outside the exact transition window")
    if (
        message.active_delivery_attempt_id is not None
        or message.receipt_deadline_at is not None
        or message.delivered_at is None
        or delivery.dispatched_at is None
        or delivery.receipt_deadline_at is not None
        or delivery.receipt_received_at is None
        or delivery.completed_at is None
        or message.delivered_at != delivery.completed_at
        or delivery.receipt_received_at != delivery.completed_at
        or delivery.broker_name != broker_name
        or delivery.broker_message_id != broker_message_id
        or delivery.broker_receipt_id != broker_receipt_id
        or delivery.error_code != ""
        or delivery.error_class != ""
        or delivery.error_summary != ""
        or delivery.retryable
    ):
        raise OutboxLeaseLost("Delivered receipt replay does not match immutable evidence")


def _assert_stale_receipt_disposition(
    message: OutboxMessage,
    delivery: OutboxDeliveryAttempt,
    *,
    claim: ClaimedOutboxDelivery,
    broker_name: str,
    broker_message_id: str,
) -> None:
    if (
        delivery.state_version - claim.delivery_state_version not in {1, 2}
        or message.state_version < claim.message_state_version + 1
        or delivery.completed_at is None
        or delivery.error_code == ""
        or delivery.error_class == ""
        or delivery.error_summary == ""
        or delivery.broker_receipt_id != ""
    ):
        raise OutboxLeaseLost("Historical delivery does not prove an exact stale disposition")
    if delivery.broker_name and (delivery.broker_name != broker_name or delivery.broker_message_id != broker_message_id):
        raise OutboxLeaseLost("Historical delivery broker facts do not match the receipt")


def _assert_cancelled_receipt_disposition(
    message: OutboxMessage,
    delivery: OutboxDeliveryAttempt,
    *,
    claim: ClaimedOutboxDelivery,
    broker_name: str,
    broker_message_id: str,
) -> None:
    _assert_latest_delivery_lineage(message, delivery)
    if not _has_exact_replay_version_delta(
        message,
        delivery,
        expected_message_version=claim.message_state_version,
        expected_delivery_version=claim.delivery_state_version,
        allowed_deltas={1, 2},
    ):
        raise OutboxLeaseLost("Cancelled receipt versions are outside the exact transition window")
    if message.cancelled_at is None or delivery.completed_at is None or delivery.broker_receipt_id != "":
        raise OutboxStoredContractError("Cancelled receipt evidence is incomplete")
    if delivery.broker_name and (delivery.broker_name != broker_name or delivery.broker_message_id != broker_message_id):
        raise OutboxLeaseLost("Cancelled delivery broker facts do not match the receipt")


async def _lock_receipt_stage_attempt(
    db: AsyncSession,
    *,
    stage: StageRun,
    message: OutboxMessage,
    delivery: OutboxDeliveryAttempt,
) -> StageAttempt:
    attempt = await db.scalar(
        select(StageAttempt)
        .where(
            StageAttempt.stage_run_id == stage.id,
            StageAttempt.outbox_delivery_attempt_id == delivery.id,
        )
        .execution_options(populate_existing=True, autoflush=False)
        .with_for_update()
    )
    if attempt is None:
        raise OutboxStoredContractError("Delivered receipt has no linked stage attempt")
    if (
        attempt.attempt_number != message.target_attempt_number
        or attempt.input_checksum != message.input_checksum
        or attempt.delivery_id != delivery.cycle_key
        or attempt.lease_token == delivery.delivery_token
        or stage.attempt_count < attempt.attempt_number
    ):
        raise OutboxStoredContractError("Linked stage attempt contradicts delivered receipt authority")
    return attempt


def _pending_receipt_activation(
    *,
    workflow: WorkflowRun,
    stage: StageRun,
    attempt: StageAttempt | None,
    message: OutboxMessage,
    delivery: OutboxDeliveryAttempt,
    broker_receipt_id: str,
    disposition: Literal["activated", "replayed", "stale", "cancelled"],
    commit_ticket: str | None,
) -> PendingReceiptActivation:
    return PendingReceiptActivation(
        workflow_run_id=_persisted_uuid(workflow.id, field_name="workflow.id"),
        stage_run_id=_persisted_uuid(stage.id, field_name="stage.id"),
        stage_attempt_id=(_persisted_uuid(attempt.id, field_name="attempt.id") if attempt is not None else None),
        message_id=_persisted_uuid(message.id, field_name="message.id"),
        delivery_attempt_id=_persisted_uuid(delivery.id, field_name="delivery.id"),
        attempt_number=message.target_attempt_number,
        delivery_cycle=delivery.delivery_cycle,
        cycle_key=delivery.cycle_key,
        broker_receipt_id=broker_receipt_id,
        commit_ticket=commit_ticket,
        disposition=disposition,
        should_execute=False,
    )


def _is_live_committed_activation(
    workflow: WorkflowRun,
    stage: StageRun,
    message: OutboxMessage,
    delivery: OutboxDeliveryAttempt,
    attempt: StageAttempt,
    *,
    now: datetime,
) -> bool:
    if (
        workflow.status != "running"
        or stage.status != "running"
        or message.status != "delivered"
        or delivery.status != "delivered"
        or attempt.status != "running"
    ):
        return False
    _assert_persisted_receipt_lineage(workflow, stage, message, delivery)
    _assert_latest_delivery_lineage(message, delivery)
    if stage.lease_expires_at is None or stage.lease_expires_at <= now:
        return False
    if (
        message.active_delivery_attempt_id is not None
        or message.delivered_at is None
        or attempt.stage_run_id != stage.id
        or attempt.outbox_delivery_attempt_id != delivery.id
        or attempt.attempt_number != stage.attempt_count
        or attempt.attempt_number != message.target_attempt_number
        or attempt.delivery_id != delivery.cycle_key
        or attempt.input_checksum != stage.input_checksum
        or attempt.checkpoint_start_version != stage.checkpoint_version
        or attempt.checkpoint_end_version != stage.checkpoint_version
        or attempt.lease_token != stage.lease_token
        or attempt.lease_token == delivery.delivery_token
        or attempt.lease_owner != stage.lease_owner
        or attempt.started_at != stage.leased_at
        or attempt.heartbeat_at != stage.heartbeat_at
        or attempt.lease_expires_at != stage.lease_expires_at
        or not _LOWER_SHA256_RE.fullmatch(delivery.broker_receipt_id)
        or delivery.receipt_received_at is None
        or delivery.completed_at is None
        or message.delivered_at != delivery.completed_at
        or delivery.receipt_received_at != delivery.completed_at
    ):
        raise OutboxStoredContractError("Committed stage activation authority is inconsistent")
    return True


def _executable_stage_authority(
    *,
    workflow: WorkflowRun,
    stage: StageRun,
    message: OutboxMessage,
    delivery: OutboxDeliveryAttempt,
    attempt: StageAttempt,
) -> ExecutableStageAuthority:
    return ExecutableStageAuthority(
        workflow_run_id=_persisted_uuid(workflow.id, field_name="workflow.id"),
        stage_run_id=_persisted_uuid(stage.id, field_name="stage.id"),
        stage_attempt_id=_persisted_uuid(attempt.id, field_name="attempt.id"),
        message_id=_persisted_uuid(message.id, field_name="message.id"),
        delivery_attempt_id=_persisted_uuid(delivery.id, field_name="delivery.id"),
        stage_lease_token=_persisted_uuid(attempt.lease_token, field_name="attempt.lease_token"),
        workflow_state_version=workflow.state_version,
        stage_state_version=stage.state_version,
        attempt_state_version=attempt.state_version,
        attempt_number=attempt.attempt_number,
        delivery_cycle=delivery.delivery_cycle,
        cycle_key=delivery.cycle_key,
        stage_key=stage.stage_key,
        input_checksum=attempt.input_checksum,
        checkpoint_version=attempt.checkpoint_end_version,
        lease_owner=attempt.lease_owner,
        lease_expires_at=attempt.lease_expires_at,
        broker_receipt_id=delivery.broker_receipt_id,
    )


async def _lock_delivery_pair(
    db: AsyncSession,
    *,
    message_id: uuid.UUID,
    delivery_attempt_id: uuid.UUID,
) -> tuple[OutboxMessage, OutboxDeliveryAttempt]:
    message_key = _uuid(message_id, field_name="message_id")
    delivery_key = _uuid(
        delivery_attempt_id,
        field_name="delivery_attempt_id",
    )
    message = await db.scalar(select(OutboxMessage).where(OutboxMessage.id == message_key).with_for_update())
    if message is None:
        raise OutboxNotFound("Outbox message not found")
    delivery = await db.scalar(
        select(OutboxDeliveryAttempt)
        .where(
            OutboxDeliveryAttempt.id == delivery_key,
            OutboxDeliveryAttempt.message_id == message.id,
        )
        .with_for_update()
    )
    if delivery is None:
        raise OutboxNotFound("Outbox delivery attempt not found")
    return message, delivery


async def _terminalize_delivery_failure(
    db: AsyncSession,
    delivery: OutboxDeliveryAttempt,
    *,
    status: Literal["failed", "abandoned"],
    error: SanitizedOutboxError,
    now: datetime,
) -> None:
    delivery.status = status
    delivery.state_version += 1
    delivery.receipt_deadline_at = None
    delivery.receipt_received_at = None
    delivery.completed_at = now
    delivery.error_code = error.code
    delivery.error_class = error.error_class
    delivery.error_summary = error.summary
    delivery.retryable = error.retryable
    await db.flush([delivery])


def _schedule_message_after_failure(
    message: OutboxMessage,
    *,
    error: SanitizedOutboxError,
    now: datetime,
) -> None:
    can_retry = error.retryable and message.attempt_count < message.max_attempts
    message.status = "retry_wait" if can_retry else "dead_lettered"
    message.state_version += 1
    message.active_delivery_attempt_id = None
    message.lease_owner = ""
    message.lease_token = None
    message.leased_at = None
    message.heartbeat_at = None
    message.lease_expires_at = None
    message.receipt_deadline_at = None
    message.last_error_code = error.code
    message.last_error_class = error.error_class
    message.last_error_summary = error.summary
    message.last_error_retryable = error.retryable
    if can_retry:
        delay = deterministic_delivery_retry_delay_seconds(
            message.attempt_count,
            logical_key=message.logical_key,
        )
        message.available_at = now + timedelta(seconds=delay)
        message.dead_lettered_at = None
    else:
        message.available_at = None
        message.dead_lettered_at = now


def _assert_live_dispatch_fence(
    message: OutboxMessage,
    delivery: OutboxDeliveryAttempt,
    *,
    delivery_token: uuid.UUID,
    expected_message_version: int,
    expected_delivery_version: int,
    now: datetime,
) -> None:
    _assert_active_delivery_fence(
        message,
        delivery,
        delivery_token=delivery_token,
        expected_message_version=expected_message_version,
        expected_delivery_version=expected_delivery_version,
        now=now,
    )
    if message.status != "dispatching":
        raise OutboxLeaseLost("Delivery is no longer in dispatch")


def _assert_active_delivery_fence(
    message: OutboxMessage,
    delivery: OutboxDeliveryAttempt,
    *,
    delivery_token: uuid.UUID,
    expected_message_version: int,
    expected_delivery_version: int,
    now: datetime,
) -> None:
    _assert_versions(
        message,
        delivery,
        expected_message_version=expected_message_version,
        expected_delivery_version=expected_delivery_version,
    )
    token = _uuid(delivery_token, field_name="delivery_token")
    if (
        message.status not in _ACTIVE_DELIVERY_STATUSES
        or delivery.status != message.status
        or message.active_delivery_attempt_id != delivery.id
        or delivery.attempt_number != message.attempt_count
        or delivery.delivery_cycle != message.delivery_cycle
        or delivery.cycle_key != message.cycle_key
        or delivery.delivery_token != token
    ):
        raise OutboxLeaseLost("Delivery token or active state no longer matches")
    if message.status == "dispatching" and (
        message.lease_token != token
        or message.lease_owner != delivery.publisher_id
        or message.leased_at is None
        or message.heartbeat_at is None
        or message.leased_at != delivery.leased_at
        or message.heartbeat_at != delivery.heartbeat_at
        or message.lease_expires_at != delivery.lease_expires_at
        or message.lease_expires_at is None
        or delivery.lease_expires_at is None
        or message.lease_expires_at <= now
        or delivery.lease_expires_at <= now
    ):
        raise OutboxLeaseLost("Dispatch lease is no longer live")
    if message.status == "awaiting_receipt" and (
        message.receipt_deadline_at is None
        or message.receipt_deadline_at <= now
        or message.receipt_deadline_at != delivery.receipt_deadline_at
        or message.lease_owner != ""
        or message.lease_token is not None
        or message.leased_at is not None
        or message.heartbeat_at is not None
        or message.lease_expires_at is not None
    ):
        raise OutboxLeaseLost("Receipt window is no longer live")


def _assert_versions(
    message: OutboxMessage,
    delivery: OutboxDeliveryAttempt,
    *,
    expected_message_version: int,
    expected_delivery_version: int,
) -> None:
    message_version = _bounded_int(
        expected_message_version,
        field_name="expected_message_version",
        minimum=1,
        maximum=2_147_483_647,
    )
    delivery_version = _bounded_int(
        expected_delivery_version,
        field_name="expected_delivery_version",
        minimum=1,
        maximum=2_147_483_647,
    )
    if message.state_version != message_version or delivery.state_version != delivery_version:
        raise OutboxLeaseLost("Outbox message or delivery version no longer matches")


def _exact_model(value: object, model_type: type, *, field_name: str):
    if type(value) is not model_type:
        raise OutboxValidation(f"{field_name} must be exact loaded {model_type.__name__} authority")
    return value


def _stage_ready_state(stage: StageRun) -> _StageReadyState:
    _exact_model(stage, StageRun, field_name="stage")
    if type(stage.depends_on) is not list:
        raise OutboxStoredContractError("Persisted stage dependencies are not an array")
    if type(stage.output_manifest) is not dict or type(stage.checkpoint) is not dict:
        raise OutboxStoredContractError("Persisted stage payload facts are not JSON objects")
    try:
        return _StageReadyState(
            stage_run_id=_persisted_uuid(stage.id, field_name="stage.id"),
            workflow_run_id=_persisted_uuid(stage.workflow_run_id, field_name="stage.workflow_run_id"),
            stage_key=stage.stage_key,
            ordinal=stage.ordinal,
            depends_on=tuple(stage.depends_on),
            input_checksum=stage.input_checksum,
            output_manifest_checksum=checksum_json(stage.output_manifest),
            checkpoint_payload_checksum=checksum_json(stage.checkpoint),
            checkpoint_checksum=stage.checkpoint_checksum,
            checkpoint_version=stage.checkpoint_version,
            status=stage.status,
            state_version=stage.state_version,
            attempt_count=stage.attempt_count,
            max_attempts=stage.max_attempts,
            next_attempt_at=stage.next_attempt_at,
            lease_owner=stage.lease_owner,
            lease_token=(_persisted_uuid(stage.lease_token, field_name="stage.lease_token") if stage.lease_token is not None else None),
            leased_at=stage.leased_at,
            lease_expires_at=stage.lease_expires_at,
            heartbeat_at=stage.heartbeat_at,
            last_error_code=stage.last_error_code,
            last_error_summary=stage.last_error_summary,
            last_error_retryable=stage.last_error_retryable,
            output_checksum=stage.output_checksum,
            first_started_at=stage.first_started_at,
            completed_at=stage.completed_at,
        )
    except (
        AttributeError,
        OutboxValidation,
        TypeError,
        WorkflowContractError,
    ) as exc:
        raise OutboxStoredContractError("Persisted stage cannot form exact emission authority") from exc


def _make_stage_ready_intent(
    *,
    workflow: WorkflowRun,
    emission_kind: str,
    projection_mode: str,
    allow_create: bool,
    pre_target: _StageReadyState,
    post_target: _StageReadyState,
    causal_pre_stage: _StageReadyState | None,
    target_attempt_number: int,
) -> StageReadyIntent:
    normalized = normalize_outbox_envelope(
        {
            "topic": OUTBOX_TOPIC_WORKFLOW_STAGE_READY,
            "schema_version": OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1,
            "payload": {
                "workflow_run_id": str(_persisted_uuid(workflow.id, field_name="workflow.id")),
                "stage_run_id": str(post_target.stage_run_id),
                "stage_key": post_target.stage_key,
                "target_attempt_number": target_attempt_number,
                "input_checksum": post_target.input_checksum,
                "plan_checksum": workflow.plan_checksum,
            },
        }
    )
    return StageReadyIntent(
        workflow_run_id=_persisted_uuid(workflow.id, field_name="workflow.id"),
        workflow_status=workflow.status,
        workflow_state_version=workflow.state_version,
        correlation_id=_persisted_uuid(workflow.correlation_id, field_name="workflow.correlation_id"),
        plan_checksum=workflow.plan_checksum,
        emission_kind=emission_kind,
        projection_mode=projection_mode,
        allow_create=allow_create,
        pre_target=pre_target,
        post_target=post_target,
        causal_pre_stage=causal_pre_stage,
        target_attempt_number=target_attempt_number,
        envelope_canonical=normalized.canonical,
        envelope_checksum=normalized.checksum,
        logical_key=normalized.logical_key,
    )


def _assert_stage_ready_intent_fixed_point(intent: StageReadyIntent) -> None:
    pre = intent.pre_target
    post = intent.post_target
    if (
        pre.workflow_run_id != intent.workflow_run_id
        or post.workflow_run_id != intent.workflow_run_id
        or pre.stage_run_id != post.stage_run_id
        or pre.stage_key != post.stage_key
        or pre.ordinal != post.ordinal
        or pre.depends_on != post.depends_on
        or pre.input_checksum != post.input_checksum
        or pre.output_manifest_checksum != post.output_manifest_checksum
        or pre.checkpoint_payload_checksum != post.checkpoint_payload_checksum
        or pre.checkpoint_checksum != post.checkpoint_checksum
        or pre.checkpoint_version != post.checkpoint_version
        or pre.attempt_count != post.attempt_count
        or pre.max_attempts != post.max_attempts
        or pre.first_started_at != post.first_started_at
        or intent.target_attempt_number != post.attempt_count + 1
    ):
        raise OutboxValidation("Stage-ready intent pre/post identity is contradictory")
    normalized = normalize_outbox_envelope(
        {
            "topic": OUTBOX_TOPIC_WORKFLOW_STAGE_READY,
            "schema_version": OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1,
            "payload": {
                "workflow_run_id": str(intent.workflow_run_id),
                "stage_run_id": str(post.stage_run_id),
                "stage_key": post.stage_key,
                "target_attempt_number": intent.target_attempt_number,
                "input_checksum": post.input_checksum,
                "plan_checksum": intent.plan_checksum,
            },
        }
    )
    if (
        intent.envelope_canonical != normalized.canonical
        or intent.envelope_checksum != normalized.checksum
        or intent.logical_key != normalized.logical_key
    ):
        raise OutboxValidation("Stage-ready intent is not a canonical fixed point")
    if intent.projection_mode == "transition":
        _assert_transition_projection(intent)
    else:
        _assert_current_projection(intent)


def _assert_transition_projection(intent: StageReadyIntent) -> None:
    pre = intent.pre_target
    post = intent.post_target
    cause = intent.causal_pre_stage
    if not intent.allow_create:
        raise OutboxValidation("Transition intents must permit their atomic message append")
    if post.status not in _CLAIMABLE_STAGE_STATUSES or post.next_attempt_at is None:
        raise OutboxValidation("Transition intent does not project a schedulable target")
    if intent.emission_kind == "root_ready":
        if cause is not None or pre != post or pre.status != "ready" or pre.depends_on:
            raise OutboxValidation("Root-ready intent must project an unchanged root stage")
        if pre.last_error_code or pre.last_error_summary or pre.last_error_retryable:
            raise OutboxValidation("Root-ready intent cannot carry stage error facts")
        return
    if intent.emission_kind == "dependency_ready":
        if (
            cause is None
            or cause.stage_run_id == pre.stage_run_id
            or cause.workflow_run_id != intent.workflow_run_id
            or cause.stage_key not in pre.depends_on
            or cause.status != "running"
            or cause.attempt_count < 1
            or pre.status != "pending"
            or post.status != "ready"
            or post.state_version != pre.state_version + 1
            or post.last_error_code != ""
            or post.last_error_summary != ""
            or post.last_error_retryable
        ):
            raise OutboxValidation("Dependency-ready projection contradicts its causal transition")
        return
    if (
        cause is None
        or cause != pre
        or pre.status != "running"
        or pre.attempt_count < 1
        or pre.attempt_count >= pre.max_attempts
        or post.status != "retry_wait"
        or post.state_version != pre.state_version + 1
        or not post.last_error_code
        or not post.last_error_summary
        or not post.last_error_retryable
    ):
        raise OutboxValidation("Retry projection contradicts its same-stage causal transition")
    if intent.emission_kind == "retry_scheduled":
        if post.last_error_code == "workflow.lease_expired":
            raise OutboxValidation("Ordinary retry cannot claim lease-recovery provenance")
    elif post.last_error_code != "workflow.lease_expired":
        raise OutboxValidation("Lease recovery requires workflow.lease_expired provenance")


def _assert_current_projection(intent: StageReadyIntent) -> None:
    if intent.pre_target != intent.post_target or intent.causal_pre_stage is not None:
        raise OutboxValidation("Current-state replay intent cannot project a transition")
    state = intent.post_target
    if state.status not in _CLAIMABLE_STAGE_STATUSES or state.next_attempt_at is None:
        raise OutboxValidation("Current-state replay target is not schedulable")
    if _expected_emission_kind_state(state) != intent.emission_kind:
        raise OutboxValidation("Current-state replay kind disagrees with stage facts")
    if intent.allow_create != (intent.emission_kind == "root_ready"):
        raise OutboxValidation("Only public root-ready current state may create a message")


def _expected_emission_kind_state(state: _StageReadyState) -> str:
    if state.status == "ready":
        return "root_ready" if not state.depends_on else "dependency_ready"
    if state.status == "retry_wait":
        return "lease_recovered" if state.last_error_code == "workflow.lease_expired" else "retry_scheduled"
    raise OutboxValidation("Stage-ready state is not eligible for emission")


def _copy_stage_ready_state(value: object) -> _StageReadyState:
    if type(value) is not _StageReadyState:
        raise OutboxValidation("Stage-ready state must be exact detached authority")
    try:
        return _StageReadyState(
            stage_run_id=value.stage_run_id,
            workflow_run_id=value.workflow_run_id,
            stage_key=value.stage_key,
            ordinal=value.ordinal,
            depends_on=value.depends_on,
            input_checksum=value.input_checksum,
            output_manifest_checksum=value.output_manifest_checksum,
            checkpoint_payload_checksum=value.checkpoint_payload_checksum,
            checkpoint_checksum=value.checkpoint_checksum,
            checkpoint_version=value.checkpoint_version,
            status=value.status,
            state_version=value.state_version,
            attempt_count=value.attempt_count,
            max_attempts=value.max_attempts,
            next_attempt_at=value.next_attempt_at,
            lease_owner=value.lease_owner,
            lease_token=value.lease_token,
            leased_at=value.leased_at,
            lease_expires_at=value.lease_expires_at,
            heartbeat_at=value.heartbeat_at,
            last_error_code=value.last_error_code,
            last_error_summary=value.last_error_summary,
            last_error_retryable=value.last_error_retryable,
            output_checksum=value.output_checksum,
            first_started_at=value.first_started_at,
            completed_at=value.completed_at,
        )
    except (AttributeError, OutboxValidation) as exc:
        raise OutboxValidation("Stage-ready state is not a fixed point") from exc


def _stage_ready_state_seal(value: _StageReadyState) -> tuple[object, ...]:
    return (
        id(value),
        value.stage_run_id,
        value.workflow_run_id,
        value.stage_key,
        value.ordinal,
        id(value.depends_on),
        value.depends_on,
        value.input_checksum,
        value.output_manifest_checksum,
        value.checkpoint_payload_checksum,
        value.checkpoint_checksum,
        value.checkpoint_version,
        value.status,
        value.state_version,
        value.attempt_count,
        value.max_attempts,
        value.next_attempt_at,
        value.lease_owner,
        value.lease_token,
        value.leased_at,
        value.lease_expires_at,
        value.heartbeat_at,
        value.last_error_code,
        value.last_error_summary,
        value.last_error_retryable,
        value.output_checksum,
        value.first_started_at,
        value.completed_at,
    )


def _stage_ready_intent_seal(value: StageReadyIntent) -> tuple[object, ...]:
    return (
        id(value),
        value.workflow_run_id,
        value.workflow_status,
        value.workflow_state_version,
        value.correlation_id,
        value.plan_checksum,
        value.emission_kind,
        value.projection_mode,
        value.allow_create,
        _stage_ready_state_seal(value.pre_target),
        _stage_ready_state_seal(value.post_target),
        (_stage_ready_state_seal(value.causal_pre_stage) if value.causal_pre_stage is not None else None),
        value.target_attempt_number,
        value.envelope_canonical,
        value.envelope_checksum,
        value.logical_key,
    )


def _stage_ready_reservation_seal(value: StageReadyReservation) -> tuple[object, ...]:
    return (
        id(value.intents),
        tuple(_stage_ready_intent_seal(intent) for intent in value.intents),
        id(value.message_ids),
        value.message_ids,
        id(value.existing_messages),
        tuple(
            (
                id(message),
                tuple(
                    (column.key, getattr(message, column.key))
                    for column in OutboxMessage.__table__.columns
                    if column.key in _OUTBOX_MESSAGE_EMISSION_AUTHORITY_COLUMNS
                ),
            )
            if message is not None
            else None
            for message in value.existing_messages
        ),
        id(value.active_deliveries),
        tuple(
            (
                id(delivery),
                tuple(
                    (column.key, getattr(delivery, column.key))
                    for column in OutboxDeliveryAttempt.__table__.columns
                    if column.key in _OUTBOX_DELIVERY_EMISSION_AUTHORITY_COLUMNS
                ),
            )
            if delivery is not None
            else None
            for delivery in value.active_deliveries
        ),
        id(value.locked_stage_ids),
        value.locked_stage_ids,
        id(value.locked_stage_states),
        tuple(_stage_ready_state_seal(state) for state in value.locked_stage_states),
        id(value._session),
        id(value._transaction),
    )


def _copy_stage_ready_intent(value: object) -> StageReadyIntent:
    if type(value) is not StageReadyIntent:
        raise OutboxValidation("intent must be exact StageReadyIntent authority")
    try:
        return StageReadyIntent(
            workflow_run_id=value.workflow_run_id,
            workflow_status=value.workflow_status,
            workflow_state_version=value.workflow_state_version,
            correlation_id=value.correlation_id,
            plan_checksum=value.plan_checksum,
            emission_kind=value.emission_kind,
            projection_mode=value.projection_mode,
            allow_create=value.allow_create,
            pre_target=value.pre_target,
            post_target=value.post_target,
            causal_pre_stage=value.causal_pre_stage,
            target_attempt_number=value.target_attempt_number,
            envelope_canonical=value.envelope_canonical,
            envelope_checksum=value.envelope_checksum,
            logical_key=value.logical_key,
        )
    except (AttributeError, OutboxValidation) as exc:
        raise OutboxValidation("Stage-ready intent is not a fixed point") from exc


def _copy_stage_ready_reservation(value: object) -> StageReadyReservation:
    if type(value) is not StageReadyReservation:
        raise OutboxValidation("reservation must be exact StageReadyReservation authority")
    try:
        return StageReadyReservation(
            intents=value.intents,
            message_ids=value.message_ids,
            existing_messages=value.existing_messages,
            active_deliveries=value.active_deliveries,
            locked_stage_ids=value.locked_stage_ids,
            locked_stage_states=value.locked_stage_states,
            _session=value._session,
            _transaction=value._transaction,
        )
    except (AttributeError, OutboxValidation) as exc:
        raise OutboxValidation("Stage-ready reservation is not a fixed point") from exc


def _normalized_workflow_plan(workflow: WorkflowRun):
    if type(workflow.stage_plan) is not list or not workflow.stage_plan:
        raise OutboxStoredContractError("Workflow stage plan is not a non-empty array")
    try:
        normalized = normalize_stage_plan(workflow.stage_plan)
    except WorkflowPlanValidationError as exc:
        raise OutboxStoredContractError("Workflow stage plan is not canonical authority") from exc
    if normalized.checksum != workflow.plan_checksum or normalized.as_payload() != workflow.stage_plan:
        raise OutboxStoredContractError("Workflow stage plan disagrees with its persisted checksum")
    return normalized


def _workflow_plan_order(workflow: WorkflowRun) -> tuple[tuple[int, str, tuple[str, ...]], ...]:
    _normalized_workflow_plan(workflow)
    plan: list[tuple[int, str, tuple[str, ...]]] = []
    for raw in workflow.stage_plan:
        if type(raw) is not dict:
            raise OutboxStoredContractError("Workflow stage plan contains a non-object definition")
        ordinal = raw.get("ordinal")
        stage_key = raw.get("stage_key")
        dependencies = raw.get("depends_on")
        if (
            type(ordinal) is not int
            or type(stage_key) is not str
            or type(dependencies) is not list
            or any(type(key) is not str for key in dependencies)
        ):
            raise OutboxStoredContractError("Workflow stage plan membership facts are invalid")
        plan.append((ordinal, stage_key, tuple(dependencies)))
    expected_ordinals = tuple(range(1, len(plan) + 1))
    actual_ordinals = tuple(item[0] for item in plan)
    keys = tuple(item[1] for item in plan)
    if actual_ordinals != expected_ordinals or len(set(keys)) != len(keys):
        raise OutboxStoredContractError("Workflow stage plan is not uniquely plan-ordered")
    return tuple(plan)


def _prevalidate_locked_stage_authority(
    db: AsyncSession,
    workflow: object,
    locked_stages: object,
) -> None:
    _exact_model(workflow, WorkflowRun, field_name="workflow")
    if type(locked_stages) is not tuple or not locked_stages:
        raise OutboxValidation("locked_stages must be an exact non-empty tuple")
    for stage in locked_stages:
        _exact_model(stage, StageRun, field_name="locked stage")
    _require_session_authorities(db, (workflow, *locked_stages))


def _validate_complete_locked_stages(
    workflow: WorkflowRun,
    locked_stages: object,
) -> tuple[StageRun, ...]:
    if type(locked_stages) is not tuple or not locked_stages:
        raise OutboxValidation("locked_stages must be an exact non-empty tuple")
    plan = _workflow_plan_order(workflow)
    if len(locked_stages) != len(plan):
        raise OutboxConflict("Locked stages are not the complete workflow plan")
    workflow_id = _persisted_uuid(workflow.id, field_name="workflow.id")
    seen_ids: set[uuid.UUID] = set()
    seen_keys: set[str] = set()
    seen_ordinals: set[int] = set()
    for index, (stage, expected) in enumerate(zip(locked_stages, plan, strict=True)):
        _exact_model(stage, StageRun, field_name="locked stage")
        stage_id = _persisted_uuid(stage.id, field_name="stage.id")
        if type(stage.depends_on) is not list:
            raise OutboxStoredContractError("Persisted stage dependencies are not an array")
        if (
            _persisted_uuid(stage.workflow_run_id, field_name="stage.workflow_run_id") != workflow_id
            or (stage.ordinal, stage.stage_key, tuple(stage.depends_on)) != expected
            or stage_id in seen_ids
            or stage.stage_key in seen_keys
            or stage.ordinal in seen_ordinals
        ):
            raise OutboxConflict("Locked stages contradict complete plan-ordered authority")
        seen_ids.add(stage_id)
        seen_keys.add(stage.stage_key)
        seen_ordinals.add(stage.ordinal)
        _assert_stage_plan_definition(workflow, stage, workflow.stage_plan[index])
    return locked_stages


def _assert_stage_plan_definition(
    workflow: WorkflowRun,
    stage: StageRun,
    definition: dict[str, Any],
) -> None:
    expected_input = definition["input_manifest"] if definition["input_manifest"] is not None else workflow.input_manifest
    try:
        config_checksum = checksum_json(definition["config"])
        input_checksum = checksum_json(expected_input)
    except (KeyError, ValueError, TypeError) as exc:
        raise OutboxStoredContractError("Workflow plan cannot derive persisted stage authority") from exc
    if (
        stage.stage_type != definition["stage_type"]
        or stage.stage_version != definition["stage_version"]
        or stage.required != definition["required"]
        or stage.priority != definition["priority"]
        or stage.max_attempts != definition["max_attempts"]
        or stage.config_schema_version != definition["config_schema_version"]
        or stage.checkpoint_schema_version != definition["checkpoint_schema_version"]
        or stage.config != definition["config"]
        or stage.config_checksum != config_checksum
        or stage.input_manifest != expected_input
        or stage.input_checksum != input_checksum
    ):
        raise OutboxStoredContractError("Persisted stage disagrees with its canonical workflow plan")


def _validate_target_stage_tuple(
    locked_stages: tuple[StageRun, ...],
    target_stages: object,
) -> tuple[StageRun, ...]:
    if type(target_stages) is not tuple or not target_stages:
        raise OutboxValidation("target_stages must be an exact non-empty tuple")
    for target in target_stages:
        _exact_model(target, StageRun, field_name="target stage")
    if (
        tuple(
            sorted(
                target_stages,
                key=lambda stage: (
                    stage.ordinal,
                    _persisted_uuid(stage.id, field_name="target.id").int,
                ),
            )
        )
        != target_stages
    ):
        raise OutboxValidation("target_stages must be in plan order")
    locked_by_id = {_persisted_uuid(stage.id, field_name="locked stage id"): stage for stage in locked_stages}
    seen: set[uuid.UUID] = set()
    for target in target_stages:
        target_id = _persisted_uuid(target.id, field_name="target.id")
        if target_id in seen or locked_by_id.get(target_id) is not target:
            raise OutboxConflict("Target stages are not identical members of the locked stage plan")
        seen.add(target_id)
    return target_stages


def _assert_intent_pre_authority(
    workflow: WorkflowRun,
    stages: tuple[StageRun, ...],
    target: StageRun,
    intent: StageReadyIntent,
) -> None:
    if (
        _persisted_uuid(workflow.id, field_name="workflow.id") != intent.workflow_run_id
        or workflow.status != intent.workflow_status
        or workflow.state_version != intent.workflow_state_version
        or _persisted_uuid(workflow.correlation_id, field_name="workflow.correlation_id") != intent.correlation_id
        or workflow.plan_checksum != intent.plan_checksum
    ):
        raise OutboxConflict("Workflow authority changed before stage-ready reservation")
    _assert_stage_matches_ready_state(target, intent.pre_target, phase="pre")
    if intent.emission_kind in {"root_ready", "dependency_ready"} and intent.pre_target.attempt_count == 0:
        _assert_empty_never_run_stage_payload(target, intent.pre_target)
    by_id = {_persisted_uuid(stage.id, field_name="stage.id"): stage for stage in stages}
    cause = intent.causal_pre_stage
    if cause is not None:
        causal_stage = by_id.get(cause.stage_run_id)
        if causal_stage is None:
            raise OutboxConflict("Causal stage is absent from the complete locked plan")
        _assert_stage_matches_ready_state(causal_stage, cause, phase="causal pre")
    if intent.emission_kind == "dependency_ready" and intent.projection_mode == "transition":
        if cause is None:
            raise OutboxValidation("Dependency projection has no causal stage")
        by_key = {stage.stage_key: stage for stage in stages}
        for dependency_key in intent.pre_target.depends_on:
            dependency = by_key.get(dependency_key)
            if dependency is None:
                raise OutboxStoredContractError("Dependency target references a missing locked stage")
            if dependency_key == cause.stage_key:
                if dependency.status != "running":
                    raise OutboxConflict("Projected causal dependency is not running")
            elif dependency.status not in {"succeeded", "degraded"}:
                raise OutboxConflict("Dependency target has another incomplete prerequisite")


def _assert_fanout_origin(intents: tuple[StageReadyIntent, ...]) -> None:
    first = intents[0]
    origin = (
        first.workflow_run_id,
        first.emission_kind,
        first.projection_mode,
        first.causal_pre_stage.stage_run_id if first.causal_pre_stage is not None else None,
    )
    if any(
        (
            intent.workflow_run_id,
            intent.emission_kind,
            intent.projection_mode,
            intent.causal_pre_stage.stage_run_id if intent.causal_pre_stage is not None else None,
        )
        != origin
        for intent in intents
    ):
        raise OutboxValidation("Stage-ready fan-out must share one exact transition origin")
    if first.emission_kind in {"retry_scheduled", "lease_recovered"} and len(intents) != 1:
        raise OutboxValidation("Same-stage retry emissions cannot fan out")


def _assert_exact_transition_target_set(
    stages: tuple[StageRun, ...],
    targets: tuple[StageRun, ...],
    intents: tuple[StageReadyIntent, ...],
) -> None:
    first = intents[0]
    if first.projection_mode == "current":
        return
    states = tuple(_stage_ready_state(stage) for stage in stages)
    if first.emission_kind == "root_ready":
        for stage, state in zip(stages, states, strict=True):
            _assert_empty_never_run_stage_payload(stage, state)
            expected_status = "pending" if state.depends_on else "ready"
            if (
                state.status != expected_status
                or state.state_version != 1
                or state.attempt_count != 0
                or state.checkpoint_version != 0
                or state.first_started_at is not None
                or state.output_checksum != ""
                or state.last_error_code != ""
                or state.last_error_summary != ""
                or state.last_error_retryable
                or state.completed_at is not None
            ):
                raise OutboxStoredContractError("Root-ready transition requires a pristine newly-created stage graph")
        eligible_ids = tuple(state.stage_run_id for state in states if not state.depends_on)
    elif first.emission_kind == "dependency_ready":
        cause = first.causal_pre_stage
        if cause is None:
            raise OutboxValidation("Dependency-ready fan-out has no causal source")
        by_key = {state.stage_key: state for state in states}
        eligible: list[uuid.UUID] = []
        for stage, state in zip(stages, states, strict=True):
            if state.status != "pending":
                continue
            _assert_empty_never_run_stage_payload(stage, state)
            dependencies = tuple(by_key.get(key) for key in state.depends_on)
            if any(dependency is None for dependency in dependencies):
                raise OutboxStoredContractError("Workflow plan has an unresolved stage dependency")
            if cause.stage_key not in state.depends_on:
                if all(dependency.status in {"succeeded", "degraded"} for dependency in dependencies):
                    raise OutboxStoredContractError("Pending stage was already dependency-eligible before this causal transition")
                continue
            if all(
                dependency == cause if dependency.stage_key == cause.stage_key else dependency.status in {"succeeded", "degraded"}
                for dependency in dependencies
            ):
                eligible.append(state.stage_run_id)
        eligible_ids = tuple(eligible)
    else:
        eligible_ids = (first.pre_target.stage_run_id,)
    target_ids = tuple(_persisted_uuid(target.id, field_name="target.id") for target in targets)
    if target_ids != eligible_ids:
        raise OutboxConflict("Stage-ready transition targets are not the exact eligible fan-out")


def _assert_empty_never_run_stage_payload(
    stage: StageRun,
    state: _StageReadyState,
) -> None:
    if (
        state.attempt_count != 0
        or state.output_manifest_checksum != _EMPTY_OBJECT_CHECKSUM
        or state.output_checksum != ""
        or state.checkpoint_payload_checksum != _EMPTY_OBJECT_CHECKSUM
        or state.checkpoint_checksum != _EMPTY_OBJECT_CHECKSUM
        or state.checkpoint_version != 0
        or type(stage.output_manifest) is not dict
        or stage.output_manifest != {}
        or type(stage.checkpoint) is not dict
        or stage.checkpoint != {}
    ):
        raise OutboxStoredContractError("Never-run stage requires pristine output and checkpoint payloads")


def _completion_targets(
    stages: tuple[StageRun, ...],
    *,
    source: StageRun,
) -> tuple[StageRun, ...]:
    """Derive the exact plan-ordered fan-out after hypothetical source success."""

    by_key = {stage.stage_key: stage for stage in stages}
    if len(by_key) != len(stages):
        raise OutboxStoredContractError("Stage completion graph has duplicate stage keys")
    targets: list[StageRun] = []
    failure_statuses = {"failed", "dead_lettered", "cancelled", "skipped"}
    for candidate in stages:
        if candidate.status != "pending":
            continue
        state = _stage_ready_state(candidate)
        _assert_empty_never_run_stage_payload(candidate, state)
        dependencies = tuple(by_key.get(key) for key in state.depends_on)
        if not dependencies or any(dependency is None for dependency in dependencies):
            raise OutboxStoredContractError("Pending completion target has invalid dependencies")
        if any(dependency.status in failure_statuses for dependency in dependencies if dependency is not None):
            raise OutboxStoredContractError("Pending completion target retains a failed dependency")
        source_is_dependency = any(dependency is source for dependency in dependencies)
        if not source_is_dependency:
            if all(dependency.status in {"succeeded", "degraded"} for dependency in dependencies if dependency is not None):
                raise OutboxStoredContractError("Pending stage was already dependency-eligible before completion")
            continue
        if all(
            dependency is source or dependency.status in {"succeeded", "degraded"} for dependency in dependencies if dependency is not None
        ):
            targets.append(candidate)
    return tuple(targets)


def _stage_completion_target_projection(
    workflow: WorkflowRun,
    target: StageRun,
) -> _StageCompletionTargetProjection:
    pre_target = _stage_ready_state(target)
    if pre_target.status != "pending" or pre_target.attempt_count != 0:
        raise OutboxStoredContractError("Completion target is not pristine pending authority")
    normalized = normalize_outbox_envelope(
        {
            "topic": OUTBOX_TOPIC_WORKFLOW_STAGE_READY,
            "schema_version": OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1,
            "payload": {
                "workflow_run_id": str(_persisted_uuid(workflow.id, field_name="workflow.id")),
                "stage_run_id": str(pre_target.stage_run_id),
                "stage_key": pre_target.stage_key,
                "target_attempt_number": 1,
                "input_checksum": pre_target.input_checksum,
                "plan_checksum": workflow.plan_checksum,
            },
        }
    )
    return _StageCompletionTargetProjection(
        pre_target=pre_target,
        target_attempt_number=1,
        envelope_canonical=normalized.canonical,
        envelope_checksum=normalized.checksum,
        logical_key=normalized.logical_key,
    )


def _assert_stage_completion_projection_fixed_point(
    projection: _StageCompletionTargetProjection,
) -> None:
    pre = projection.pre_target
    try:
        normalized = NormalizedOutboxEnvelope(
            canonical=projection.envelope_canonical,
            checksum=projection.envelope_checksum,
            logical_key=projection.logical_key,
        )
    except (OutboxContractError, TypeError, ValueError) as exc:
        raise OutboxValidation("Completion projection envelope is not canonical authority") from exc
    envelope = normalized.as_payload()
    payload = envelope.get("payload")
    if (
        envelope.get("topic") != OUTBOX_TOPIC_WORKFLOW_STAGE_READY
        or envelope.get("schema_version") != OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1
        or type(payload) is not dict
        or payload.get("workflow_run_id") != str(pre.workflow_run_id)
        or payload.get("stage_run_id") != str(pre.stage_run_id)
        or payload.get("stage_key") != pre.stage_key
        or payload.get("target_attempt_number") != projection.target_attempt_number
        or payload.get("input_checksum") != pre.input_checksum
    ):
        raise OutboxValidation("Stage completion target projection is not a canonical fixed point")
    _lower_sha256(payload.get("plan_checksum"), field_name="completion projection plan_checksum")


def _copy_stage_completion_projection(value: object) -> _StageCompletionTargetProjection:
    if type(value) is not _StageCompletionTargetProjection:
        raise OutboxValidation("Completion target projection must be exact detached authority")
    try:
        return _StageCompletionTargetProjection(
            pre_target=value.pre_target,
            target_attempt_number=value.target_attempt_number,
            envelope_canonical=value.envelope_canonical,
            envelope_checksum=value.envelope_checksum,
            logical_key=value.logical_key,
        )
    except (AttributeError, OutboxValidation) as exc:
        raise OutboxValidation("Completion target projection is not a fixed point") from exc


def _assert_unique_completion_projection_keys(
    projections: tuple[_StageCompletionTargetProjection, ...],
    *,
    stored: bool,
) -> None:
    keys = tuple(item.logical_key for item in projections)
    if len(set(keys)) != len(keys):
        if stored:
            raise OutboxStoredContractError("Completion targets collide on one logical outbox root")
        raise OutboxValidation("Stage completion target projections contain duplicate logical keys")


def _completion_stage_ready_intent(
    workflow: WorkflowRun,
    projection: _StageCompletionTargetProjection,
    *,
    causal_source: _StageReadyState,
    observed_at: datetime,
) -> StageReadyIntent:
    pre = _copy_stage_ready_state(projection.pre_target)
    post = replace(
        pre,
        status="ready",
        state_version=pre.state_version + 1,
        next_attempt_at=_aware_datetime(observed_at, field_name="completion intent observed_at"),
        lease_owner="",
        lease_token=None,
        leased_at=None,
        lease_expires_at=None,
        heartbeat_at=None,
        last_error_code="",
        last_error_summary="",
        last_error_retryable=False,
        output_checksum="",
        completed_at=None,
    )
    intent = _make_stage_ready_intent(
        workflow=workflow,
        emission_kind="dependency_ready",
        projection_mode="transition",
        allow_create=True,
        pre_target=pre,
        post_target=post,
        causal_pre_stage=causal_source,
        target_attempt_number=projection.target_attempt_number,
    )
    if (
        intent.envelope_canonical != projection.envelope_canonical
        or intent.envelope_checksum != projection.envelope_checksum
        or intent.logical_key != projection.logical_key
    ):
        raise OutboxStoredContractError("Completion intent changed its clock-free projection identity")
    return intent


def _completion_stage_ready_reservation(
    db: AsyncSession,
    transaction: object,
    *,
    stages: tuple[StageRun, ...],
    stage_states: tuple[_StageReadyState, ...],
    intents: tuple[StageReadyIntent, ...],
    message_ids: tuple[uuid.UUID, ...],
) -> StageReadyReservation | None:
    """Build the query-free append capability before its authenticated transfer."""

    if type(intents) is not tuple or type(message_ids) is not tuple:
        raise OutboxStoredContractError("Completion append authority tuples are invalid")
    if len(intents) != len(message_ids):
        raise OutboxStoredContractError("Completion append authority tuples are misaligned")
    if not intents:
        return None
    ordered = tuple(
        sorted(
            zip(intents, message_ids, strict=True),
            key=lambda item: item[0].logical_key,
        )
    )
    try:
        return StageReadyReservation(
            intents=tuple(intent for intent, _message_id in ordered),
            message_ids=tuple(message_id for _intent, message_id in ordered),
            existing_messages=(None,) * len(ordered),
            active_deliveries=(None,) * len(ordered),
            locked_stage_ids=tuple(_persisted_uuid(stage.id, field_name="completion locked stage id") for stage in stages),
            locked_stage_states=stage_states,
            _session=db,
            _transaction=transaction,
        )
    except OutboxValidation as exc:
        raise OutboxStoredContractError("Completion append capability is not an exact stage-ready fixed point") from exc


def _assert_completion_message_id_partition(
    *,
    source_message_id: uuid.UUID,
    target_message_ids: tuple[uuid.UUID, ...],
) -> None:
    _uuid(source_message_id, field_name="completion source message id")
    if type(target_message_ids) is not tuple:
        raise OutboxValidation("Completion target message ids must be an exact tuple")
    for message_id in target_message_ids:
        _uuid(message_id, field_name="completion target message id")
    if source_message_id in target_message_ids or len(set(target_message_ids)) != len(target_message_ids):
        raise OutboxStoredContractError("Completion source and target message identities collide")


def _assert_completion_delivery_id_partition(
    *,
    source_delivery_id: uuid.UUID,
    target_delivery_ids: tuple[uuid.UUID | None, ...],
) -> None:
    _uuid(source_delivery_id, field_name="completion source delivery id")
    if type(target_delivery_ids) is not tuple:
        raise OutboxValidation("Completion target delivery ids must be an exact tuple")
    present: list[uuid.UUID] = []
    for delivery_id in target_delivery_ids:
        if delivery_id is not None:
            _uuid(delivery_id, field_name="completion target delivery id")
            present.append(delivery_id)
    if source_delivery_id in present or len(set(present)) != len(present):
        raise OutboxStoredContractError("Completion source and target delivery identities collide")


def _validate_stage_completion_dto(
    value: StageCompletionReservation | LockedStageCompletionGraph,
    *,
    locked: bool,
) -> None:
    tuple_fields = (
        "stages",
        "stage_states",
        "target_projections",
        "target_message_ids",
        "existing_target_messages",
        "active_target_deliveries",
        "locked_messages",
        "locked_message_ids",
        "locked_deliveries",
        "locked_delivery_ids",
    )
    if any(type(getattr(value, field_name)) is not tuple for field_name in tuple_fields):
        raise OutboxValidation("Stage completion graph tuples must use exact tuple authority")
    if not value.stages or len(value.stages) != len(value.stage_states):
        raise OutboxValidation("Stage completion graph requires a complete non-empty stage snapshot")
    _exact_model(value.workflow, WorkflowRun, field_name="completion workflow")
    for stage in value.stages:
        _exact_model(stage, StageRun, field_name="completion stage")
    copied_states = tuple(_copy_stage_ready_state(state) for state in value.stage_states)
    if tuple(state.stage_run_id for state in copied_states) != tuple(
        _persisted_uuid(stage.id, field_name="completion stage id") for stage in value.stages
    ):
        raise OutboxValidation("Stage completion snapshots are not aligned with locked stages")
    if type(value.source_stage_index) is not int or not 0 <= value.source_stage_index < len(value.stages):
        raise OutboxValidation("Stage completion source index is invalid")
    _uuid(value.source_stage_id, field_name="completion source stage id")
    if copied_states[value.source_stage_index].stage_run_id != value.source_stage_id:
        raise OutboxValidation("Stage completion source index and identity disagree")
    causal_source = _copy_stage_ready_state(value.causal_source)
    if causal_source != copied_states[value.source_stage_index]:
        raise OutboxValidation("Stage completion causal source snapshot is not exact")
    projections = tuple(_copy_stage_completion_projection(item) for item in value.target_projections)
    _assert_unique_completion_projection_keys(projections, stored=False)
    target_count = len(projections)
    if not (target_count == len(value.target_message_ids) == len(value.existing_target_messages) == len(value.active_target_deliveries)):
        raise OutboxValidation("Stage completion target tuples have contradictory lengths")
    for message_id in value.target_message_ids:
        _uuid(message_id, field_name="completion target message id")
    _assert_completion_message_id_partition(
        source_message_id=value.authority.message_id,
        target_message_ids=value.target_message_ids,
    )
    for projection, message_id, message, delivery in zip(
        projections,
        value.target_message_ids,
        value.existing_target_messages,
        value.active_target_deliveries,
        strict=True,
    ):
        if message is not None:
            _exact_model(message, OutboxMessage, field_name="completion target message")
            if (
                _persisted_uuid(message.id, field_name="completion target message id") != message_id
                or message.logical_key != projection.logical_key
            ):
                raise OutboxValidation("Completion target message alignment is invalid")
        if delivery is not None:
            _exact_model(delivery, OutboxDeliveryAttempt, field_name="completion target delivery")
            if message is None:
                raise OutboxValidation("Completion target delivery has no message authority")
    for message in value.locked_messages:
        _exact_model(message, OutboxMessage, field_name="completion locked message")
    for delivery in value.locked_deliveries:
        _exact_model(delivery, OutboxDeliveryAttempt, field_name="completion locked delivery")
    if not value.locked_messages or not value.locked_deliveries:
        raise OutboxValidation("Stage completion graph has no source receipt authority")
    if (
        tuple(_persisted_uuid(message.id, field_name="completion locked message id") for message in value.locked_messages)
        != value.locked_message_ids
    ):
        raise OutboxValidation("Completion locked message rows and ids are not aligned")
    if (
        tuple(_persisted_uuid(delivery.id, field_name="completion locked delivery id") for delivery in value.locked_deliveries)
        != value.locked_delivery_ids
    ):
        raise OutboxValidation("Completion locked delivery rows and ids are not aligned")
    if value.locked_message_ids != tuple(sorted(value.locked_message_ids, key=lambda item: item.int)):
        raise OutboxValidation("Completion message authority is not UUID ordered")
    if value.locked_delivery_ids != tuple(sorted(value.locked_delivery_ids, key=lambda item: item.int)):
        raise OutboxValidation("Completion delivery authority is not UUID ordered")
    if len(set(value.locked_message_ids)) != len(value.locked_message_ids):
        raise OutboxValidation("Completion locked messages contain duplicate identities")
    if len(set(value.locked_delivery_ids)) != len(value.locked_delivery_ids):
        raise OutboxValidation("Completion locked deliveries contain duplicate identities")
    if value.locked_message_ids.count(value.authority.message_id) != 1:
        raise OutboxValidation("Completion source message is not locked exactly once")
    if value.locked_delivery_ids.count(value.authority.delivery_attempt_id) != 1:
        raise OutboxValidation("Completion source delivery is not locked exactly once")
    _exact_model(value.source_attempt, StageAttempt, field_name="completion source attempt")
    _aware_datetime(value.observed_at, field_name="completion observed_at")
    object.__setattr__(value, "stage_states", copied_states)
    object.__setattr__(value, "causal_source", causal_source)
    object.__setattr__(value, "target_projections", projections)
    if locked:
        if type(value) is not LockedStageCompletionGraph or type(value.intents) is not tuple:
            raise OutboxValidation("Locked completion graph has invalid intent authority")
        if len(value.intents) != target_count:
            raise OutboxValidation("Locked completion intents do not match target projections")
        rebuilt_intents = tuple(_copy_stage_ready_intent(intent) for intent in value.intents)
        for projection, intent in zip(projections, rebuilt_intents, strict=True):
            if (
                intent.envelope_canonical != projection.envelope_canonical
                or intent.envelope_checksum != projection.envelope_checksum
                or intent.logical_key != projection.logical_key
                or intent.post_target.next_attempt_at != value.observed_at
            ):
                raise OutboxValidation("Locked completion intent changed its reserved projection")
        append_reservation = getattr(value, "stage_ready_reservation", object())
        if target_count == 0:
            if append_reservation is not None:
                raise OutboxValidation("Zero-target completion cannot carry append authority")
        else:
            if type(append_reservation) is not StageReadyReservation:
                raise OutboxValidation("Completion fan-out lacks exact stage-ready append authority")
            ordered = tuple(
                sorted(
                    zip(rebuilt_intents, value.target_message_ids, strict=True),
                    key=lambda item: item[0].logical_key,
                )
            )
            expected_intents = tuple(intent for intent, _message_id in ordered)
            expected_message_ids = tuple(message_id for _intent, message_id in ordered)
            expected_stage_ids = tuple(_persisted_uuid(stage.id, field_name="completion stage id") for stage in value.stages)
            if (
                append_reservation.intents != expected_intents
                or append_reservation.message_ids != expected_message_ids
                or append_reservation.existing_messages != (None,) * target_count
                or append_reservation.active_deliveries != (None,) * target_count
                or append_reservation.locked_stage_ids != expected_stage_ids
                or append_reservation.locked_stage_states != copied_states
            ):
                raise OutboxValidation("Completion append authority changed its consumed fan-out")
        object.__setattr__(value, "intents", rebuilt_intents)
    elif type(value) is not StageCompletionReservation or value._session is None or value._transaction is None:
        raise OutboxValidation("Stage completion reservation has no transaction authority")


def _assert_completion_target_message(
    workflow: WorkflowRun,
    projection: _StageCompletionTargetProjection,
    message: OutboxMessage,
    delivery: OutboxDeliveryAttempt | None,
    *,
    source_attempt: StageAttempt,
    observed_at: datetime,
) -> None:
    _stored_envelope(message)
    pre = projection.pre_target
    expected_cause = _persisted_uuid(source_attempt.id, field_name="completion source attempt id")
    if (
        _persisted_uuid(message.workflow_run_id, field_name="completion target workflow id")
        != _persisted_uuid(workflow.id, field_name="workflow.id")
        or _persisted_uuid(message.stage_run_id, field_name="completion target stage id") != pre.stage_run_id
        or message.aggregate_type != "workflow_stage"
        or _persisted_uuid(message.aggregate_id, field_name="completion target aggregate id") != pre.stage_run_id
        or message.aggregate_version != pre.state_version + 1
        or message.emission_kind != "dependency_ready"
        or message.topic != OUTBOX_TOPIC_WORKFLOW_STAGE_READY
        or message.schema_version != OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1
        or _persisted_uuid(message.correlation_id, field_name="completion target correlation id")
        != _persisted_uuid(workflow.correlation_id, field_name="workflow correlation id")
        or _persisted_uuid(message.causation_id, field_name="completion target causation id") != expected_cause
        or message.stage_key != pre.stage_key
        or message.target_attempt_number != projection.target_attempt_number
        or message.input_checksum != pre.input_checksum
        or message.plan_checksum != workflow.plan_checksum
        or message.envelope_canonical != projection.envelope_canonical
        or message.envelope_checksum != projection.envelope_checksum
        or message.envelope_bytes != len(projection.envelope_canonical.encode("utf-8"))
        or message.logical_key != projection.logical_key
        or message.redrive_of_message_id is not None
        or message.redrive_ordinal != 0
        or message.redrive_requested_by != ""
        or message.redrive_requested_by_id != ""
        or message.redrive_reason != ""
        or message.redrive_requested_at is not None
        or message.max_attempts != OUTBOX_V1_MAX_ATTEMPTS
    ):
        raise OutboxStoredContractError("Completion target message contradicts its projected authority")
    for value, field_name in (
        (message.created_at, "completion target message created_at"),
        (message.updated_at, "completion target message updated_at"),
    ):
        timestamp = _aware_datetime(value, field_name=field_name)
        if timestamp > observed_at:
            raise OutboxStoredContractError("Completion target message contains future authority")
    if message.status in _ACTIVE_DELIVERY_STATUSES:
        if delivery is None:
            raise OutboxStoredContractError("Active completion target message lacks locked delivery authority")
        _assert_reserved_active_delivery(message, delivery)
        for value, field_name in (
            (delivery.created_at, "completion target delivery created_at"),
            (delivery.updated_at, "completion target delivery updated_at"),
            (delivery.leased_at, "completion target delivery leased_at"),
            (delivery.heartbeat_at, "completion target delivery heartbeat_at"),
        ):
            if _aware_datetime(value, field_name=field_name) > observed_at:
                raise OutboxStoredContractError("Completion target delivery contains future authority")
    elif delivery is not None or message.active_delivery_attempt_id is not None:
        raise OutboxStoredContractError("Inactive completion target retained active delivery authority")


def _assert_stage_completion_graph(
    db: AsyncSession,
    *,
    authority: ExecutableStageAuthority,
    workflow: WorkflowRun,
    stages: tuple[StageRun, ...],
    stage_states: tuple[_StageReadyState, ...],
    source_index: int,
    causal_source: _StageReadyState,
    target_projections: tuple[_StageCompletionTargetProjection, ...],
    target_message_ids: tuple[uuid.UUID, ...],
    existing_target_messages: tuple[OutboxMessage | None, ...],
    active_target_deliveries: tuple[OutboxDeliveryAttempt | None, ...],
    locked_messages: tuple[OutboxMessage, ...],
    locked_message_ids: tuple[uuid.UUID, ...],
    locked_deliveries: tuple[OutboxDeliveryAttempt, ...],
    locked_delivery_ids: tuple[uuid.UUID, ...],
    source_attempt: StageAttempt,
    observed_at: datetime,
) -> None:
    _require_stage_execution_authorities(
        db,
        (workflow, *stages, *locked_messages, *locked_deliveries, source_attempt),
    )
    complete_stages = _validate_complete_locked_stages(workflow, stages)
    now = _aware_datetime(observed_at, field_name="stage completion observed_at")
    for stage in complete_stages:
        _assert_completion_stage_chronology(stage, observed_at=now)
    if type(stage_states) is not tuple or len(stage_states) != len(complete_stages):
        raise OutboxConflict("Completion stage snapshots are incomplete")
    current_states = tuple(_stage_ready_state(stage) for stage in complete_stages)
    if current_states != stage_states:
        raise OutboxConflict("Completion stage authority changed after graph reservation")
    if type(source_index) is not int or not 0 <= source_index < len(complete_stages):
        raise OutboxStoredContractError("Completion source index is outside the locked plan")
    source = complete_stages[source_index]
    if (
        _persisted_uuid(source.id, field_name="completion source stage id") != authority.stage_run_id
        or causal_source != current_states[source_index]
    ):
        raise OutboxLeaseLost("Completion source no longer matches worker authority")
    targets = _completion_targets(complete_stages, source=source)
    rebuilt_projections = tuple(_stage_completion_target_projection(workflow, target) for target in targets)
    _assert_unique_completion_projection_keys(rebuilt_projections, stored=True)
    if rebuilt_projections != target_projections:
        raise OutboxLeaseLost("Completion target fan-out changed after reservation")
    if not (len(target_projections) == len(target_message_ids) == len(existing_target_messages) == len(active_target_deliveries)):
        raise OutboxConflict("Completion target authority tuples are misaligned")
    _assert_completion_message_id_partition(
        source_message_id=authority.message_id,
        target_message_ids=target_message_ids,
    )
    if locked_message_ids != tuple(sorted(locked_message_ids, key=lambda item: item.int)):
        raise OutboxConflict("Completion messages lost canonical UUID lock order")
    if locked_delivery_ids != tuple(sorted(locked_delivery_ids, key=lambda item: item.int)):
        raise OutboxConflict("Completion deliveries lost canonical UUID lock order")
    messages_by_id = {_persisted_uuid(message.id, field_name="completion locked message id"): message for message in locked_messages}
    deliveries_by_id = {
        _persisted_uuid(delivery.id, field_name="completion locked delivery id"): delivery for delivery in locked_deliveries
    }
    if tuple(messages_by_id) != locked_message_ids or tuple(deliveries_by_id) != locked_delivery_ids:
        raise OutboxConflict("Completion union authority no longer matches its locked id seal")
    source_message = messages_by_id.get(authority.message_id)
    source_delivery = deliveries_by_id.get(authority.delivery_attempt_id)
    if source_message is None or source_delivery is None:
        raise OutboxLeaseLost("Completion source receipt is absent from the locked union")
    _assert_stage_execution_receipt(
        db,
        authority=authority,
        workflow=workflow,
        stage=source,
        message=source_message,
        delivery=source_delivery,
        attempt=source_attempt,
        observed_at=observed_at,
    )
    expected_message_ids = {authority.message_id}
    expected_delivery_ids = {authority.delivery_attempt_id}
    for projection, message_id, message, delivery in zip(
        target_projections,
        target_message_ids,
        existing_target_messages,
        active_target_deliveries,
        strict=True,
    ):
        if message is None:
            if delivery is not None or message_id in messages_by_id:
                raise OutboxStoredContractError("New completion target has contradictory existing suffix authority")
            continue
        # Under 0003 a dependency-ready root can only be inserted after the
        # target stage has atomically become ready.  This graph still proves a
        # pristine pending target, so any pre-existing logical root is a
        # future/half-transition artifact and can never be replay authority.
        # It is nevertheless locked (with any active D) before rejection so
        # the decision is stable and cannot launder a concurrent suffix.
        if (
            _persisted_uuid(message.id, field_name="completion target message id") != message_id
            or messages_by_id.get(message_id) is not message
        ):
            raise OutboxConflict("Completion target message mapping changed after reservation")
        _assert_completion_target_message(
            workflow,
            projection,
            message,
            delivery,
            source_attempt=source_attempt,
            observed_at=observed_at,
        )
        raise OutboxStoredContractError("Pending completion target already has impossible outbox authority")
    if set(locked_message_ids) != expected_message_ids or set(locked_delivery_ids) != expected_delivery_ids:
        raise OutboxStoredContractError("Completion union contains unexpected message or delivery authority")


def _assert_completion_stage_chronology(
    stage: StageRun,
    *,
    observed_at: datetime,
) -> None:
    """Validate historical facts for every S without rejecting schedules."""

    try:
        created_at = _aware_datetime(stage.created_at, field_name="completion stage created_at")
        updated_at = _aware_datetime(stage.updated_at, field_name="completion stage updated_at")
        optional: dict[str, datetime | None] = {}
        for field_name in ("first_started_at", "leased_at", "heartbeat_at", "completed_at"):
            value = getattr(stage, field_name)
            optional[field_name] = _aware_datetime(value, field_name=f"completion stage {field_name}") if value is not None else None
        if stage.next_attempt_at is not None:
            _aware_datetime(stage.next_attempt_at, field_name="completion stage next_attempt_at")
        if stage.lease_expires_at is not None:
            _aware_datetime(stage.lease_expires_at, field_name="completion stage lease_expires_at")
    except OutboxValidation as exc:
        raise OutboxStoredContractError("Completion stage chronology contains invalid timestamps") from exc
    historical = (created_at, updated_at, *(value for value in optional.values() if value is not None))
    if any(value > observed_at for value in historical):
        raise OutboxStoredContractError("Completion stage chronology contains future authority")
    first_started_at = optional["first_started_at"]
    leased_at = optional["leased_at"]
    heartbeat_at = optional["heartbeat_at"]
    completed_at = optional["completed_at"]
    if (
        created_at > updated_at
        or (first_started_at is not None and first_started_at < created_at)
        or (leased_at is not None and (first_started_at is None or leased_at < first_started_at))
        or (heartbeat_at is not None and (leased_at is None or heartbeat_at < leased_at))
        or (
            completed_at is not None
            and (
                (first_started_at is None and (stage.status not in {"skipped", "cancelled"} or completed_at < created_at))
                or (first_started_at is not None and completed_at < first_started_at)
            )
        )
    ):
        raise OutboxStoredContractError("Completion stage chronology is internally inconsistent")


async def _lock_complete_workflow_stages(
    db: AsyncSession,
    workflow: WorkflowRun,
) -> tuple[StageRun, ...]:
    plan = _workflow_plan_order(workflow)
    stages: list[StageRun] = []
    for ordinal, stage_key, _dependencies in plan:
        stage = await db.scalar(
            select(StageRun)
            .where(
                StageRun.workflow_run_id == workflow.id,
                StageRun.ordinal == ordinal,
                StageRun.stage_key == stage_key,
            )
            .execution_options(populate_existing=True, autoflush=False)
            .with_for_update()
        )
        if stage is None:
            raise OutboxStoredContractError("Workflow plan has no complete persisted stage set")
        _exact_model(stage, StageRun, field_name="locked stage")
        _require_session_authorities(db, (stage,))
        stages.append(stage)
    return _validate_complete_locked_stages(workflow, tuple(stages))


def _sync_root_transaction(db: AsyncSession):
    sync_session = getattr(db, "sync_session", None)
    if (
        sync_session is None
        or not hasattr(sync_session, "get_transaction")
        or not hasattr(sync_session, "get_nested_transaction")
        or not hasattr(sync_session, "in_nested_transaction")
    ):
        raise OutboxValidation("Stage-ready reservation requires an AsyncSession transaction")
    if sync_session.in_nested_transaction() or sync_session.get_nested_transaction() is not None:
        raise OutboxConflict("Stage-ready reservation cannot cross a nested transaction boundary")
    transaction = sync_session.get_transaction()
    if transaction is None:
        raise OutboxConflict("Stage-ready reservation requires an active root transaction")
    return transaction


def _preflight_stage_execution_session(db: AsyncSession) -> None:
    """Reject unsafe session state before the first authority refresh query."""

    sync_session = getattr(db, "sync_session", None)
    if (
        sync_session is None
        or not hasattr(sync_session, "get_transaction")
        or not hasattr(sync_session, "get_nested_transaction")
        or not hasattr(sync_session, "in_nested_transaction")
        or type(getattr(sync_session, "info", None)) is not dict
    ):
        raise OutboxValidation("Stage execution receipt requires an AsyncSession transaction")
    if sync_session.in_nested_transaction() or sync_session.get_nested_transaction() is not None:
        raise OutboxConflict("Stage execution receipt cannot cross a nested transaction boundary")
    for collection_name in ("new", "dirty", "deleted"):
        collection = getattr(sync_session, collection_name, None)
        if collection is None:
            raise OutboxValidation("Stage execution receipt requires inspectable clean session state")
        if collection:
            raise OutboxConflict("Stage execution receipt requires an entirely clean session")


def _stage_execution_root_transaction(db: AsyncSession):
    _preflight_stage_execution_session(db)
    transaction = db.sync_session.get_transaction()
    if transaction is None:
        raise OutboxConflict("Stage execution receipt requires an active root transaction")
    return transaction


def _stage_execution_authority_seal(value: ExecutableStageAuthority) -> tuple[object, ...]:
    return tuple(getattr(value, field_name) for field_name in ExecutableStageAuthority.__dataclass_fields__)


def _stage_execution_model_seal(value: object) -> tuple[object, ...]:
    column_keys = _STAGE_EXECUTION_AUTHORITY_COLUMNS.get(type(value))
    if column_keys is None:
        raise OutboxValidation("Stage execution receipt has an unsupported persistence type")
    fields: list[object] = []
    for column in type(value).__table__.columns:
        if column.key not in column_keys:
            continue
        field_value = getattr(value, column.key)
        if isinstance(field_value, (dict, list)):
            if type(field_value) not in {dict, list}:
                raise OutboxStoredContractError("Stage execution receipt contains a non-exact JSON authority type")
            try:
                field_value = (type(field_value), checksum_json(field_value))
            except (TypeError, ValueError) as exc:
                raise OutboxStoredContractError("Stage execution receipt contains noncanonical JSON authority") from exc
        else:
            field_value = (type(field_value), field_value)
        fields.append((column.key, field_value))
    return (id(value), tuple(fields))


def _require_stage_execution_authorities(db: AsyncSession, values: tuple[object, ...]) -> None:
    """Require every persisted column to be loaded and clean in this session."""

    sync_session = getattr(db, "sync_session", None)
    if sync_session is None:
        raise OutboxValidation("Stage execution authority requires an AsyncSession")
    for value in values:
        state = sa_inspect(value)
        column_keys = _STAGE_EXECUTION_AUTHORITY_COLUMNS.get(type(value))
        if column_keys is None:
            raise OutboxValidation("Stage execution authority has an unsupported persistence type")
        if (
            object_session(value) is not sync_session
            or not state.persistent
            or state.deleted
            or state.detached
            or state.modified
            or state.expired
            or bool(column_keys.intersection(state.expired_attributes))
            or bool(column_keys.intersection(state.unloaded))
        ):
            raise OutboxConflict("Stage execution authority is not complete clean persistent state in its locked session")


def _stage_execution_receipt_transaction_fence(
    db: AsyncSession,
    transaction: object,
) -> _StageExecutionReceiptTransactionFence:
    info = db.sync_session.info
    fence = info.get(_STAGE_EXECUTION_RECEIPT_FENCE_INFO_KEY)
    if fence is None or (type(fence) is _StageExecutionReceiptTransactionFence and fence.transaction is not transaction):
        fence = _StageExecutionReceiptTransactionFence(
            transaction=transaction,
            coordinates={},
        )
        info[_STAGE_EXECUTION_RECEIPT_FENCE_INFO_KEY] = fence
    if (
        type(fence) is not _StageExecutionReceiptTransactionFence
        or fence.transaction is not transaction
        or type(fence.coordinates) is not dict
    ):
        raise OutboxConflict("Stage execution receipt transaction fence is invalid")
    return fence


def _assert_stage_execution_coordinate_available(
    db: AsyncSession,
    transaction: object,
    authority: ExecutableStageAuthority,
) -> None:
    coordinate = _stage_execution_authority_seal(authority)
    fence = _stage_execution_receipt_transaction_fence(db, transaction)
    if coordinate in fence.coordinates:
        raise OutboxConflict("Stage execution receipt coordinate was already reserved in this root transaction")


def _stage_execution_receipt_reservation_seal(
    value: StageExecutionReceiptReservation,
) -> tuple[object, ...]:
    return (
        id(value.authority),
        _stage_execution_authority_seal(value.authority),
        _stage_execution_model_seal(value.workflow),
        _stage_execution_model_seal(value.stage),
        _stage_execution_model_seal(value.message),
        _stage_execution_model_seal(value.delivery),
        _stage_execution_model_seal(value.attempt),
        value.observed_at,
        id(value._session),
        id(value._transaction),
    )


def _register_stage_execution_receipt(
    db: AsyncSession,
    transaction: object,
    reservation: StageExecutionReceiptReservation,
) -> None:
    key = (id(db), id(transaction), id(reservation))
    _assert_workflow_has_no_terminalization(
        db,
        transaction,
        reservation.authority.workflow_run_id,
    )
    coordinate = _stage_execution_authority_seal(reservation.authority)
    fence = _stage_execution_receipt_transaction_fence(db, transaction)
    if coordinate in fence.coordinates:
        raise OutboxConflict("Stage execution receipt coordinate was already reserved in this root transaction")

    def discard(reference: object) -> None:
        current = _STAGE_EXECUTION_RECEIPT_RESERVATIONS.get(key)
        if current is not None and (reference is current.session_ref or reference is current.reservation_ref):
            _STAGE_EXECUTION_RECEIPT_RESERVATIONS.pop(key, None)

    try:
        registration = _StageExecutionReceiptRegistration(
            session_ref=weakref.ref(db, discard),
            reservation_ref=weakref.ref(reservation, discard),
            seal=_stage_execution_receipt_reservation_seal(reservation),
            coordinate=coordinate,
        )
    except TypeError as exc:
        raise OutboxValidation("Stage execution receipt session cannot hold a capability") from exc
    if key in _STAGE_EXECUTION_RECEIPT_RESERVATIONS:
        raise OutboxConflict("Stage execution receipt capability is already registered")
    _STAGE_EXECUTION_RECEIPT_RESERVATIONS[key] = registration
    fence.coordinates[coordinate] = ("issued", id(reservation))


def _consume_stage_execution_receipt_registration(
    db: AsyncSession,
    transaction: object,
    reservation: object,
) -> tuple[object, ...]:
    if type(reservation) is not StageExecutionReceiptReservation:
        raise OutboxValidation("reservation must be exact stage execution receipt authority")
    key = (id(db), id(transaction), id(reservation))
    registration = _STAGE_EXECUTION_RECEIPT_RESERVATIONS.get(key)
    if registration is None or registration.session_ref() is not db or registration.reservation_ref() is not reservation:
        raise OutboxConflict("Stage execution receipt capability is not registered for this transaction")
    fence = _stage_execution_receipt_transaction_fence(db, transaction)
    if fence.coordinates.get(registration.coordinate) != ("issued", id(reservation)):
        raise OutboxConflict("Stage execution receipt coordinate is not live in this root transaction")
    fence.coordinates[registration.coordinate] = ("spent", id(reservation))
    del _STAGE_EXECUTION_RECEIPT_RESERVATIONS[key]
    return registration.seal


def _stage_completion_projection_seal(
    value: _StageCompletionTargetProjection,
) -> tuple[object, ...]:
    return (
        id(value),
        _stage_ready_state_seal(value.pre_target),
        value.target_attempt_number,
        value.envelope_canonical,
        value.envelope_checksum,
        value.logical_key,
    )


def _stage_completion_reservation_seal(
    value: StageCompletionReservation,
) -> tuple[object, ...]:
    return (
        id(value.authority),
        _stage_execution_authority_seal(value.authority),
        _stage_execution_model_seal(value.workflow),
        id(value.stages),
        tuple(_stage_execution_model_seal(stage) for stage in value.stages),
        id(value.stage_states),
        tuple(_stage_ready_state_seal(state) for state in value.stage_states),
        value.source_stage_id,
        value.source_stage_index,
        _stage_ready_state_seal(value.causal_source),
        id(value.target_projections),
        tuple(_stage_completion_projection_seal(item) for item in value.target_projections),
        id(value.target_message_ids),
        value.target_message_ids,
        id(value.existing_target_messages),
        tuple(_stage_execution_model_seal(message) if message is not None else None for message in value.existing_target_messages),
        id(value.active_target_deliveries),
        tuple(_stage_execution_model_seal(delivery) if delivery is not None else None for delivery in value.active_target_deliveries),
        id(value.locked_messages),
        tuple(_stage_execution_model_seal(message) for message in value.locked_messages),
        id(value.locked_message_ids),
        value.locked_message_ids,
        id(value.locked_deliveries),
        tuple(_stage_execution_model_seal(delivery) for delivery in value.locked_deliveries),
        id(value.locked_delivery_ids),
        value.locked_delivery_ids,
        _stage_execution_model_seal(value.source_attempt),
        value.observed_at,
        id(value._session),
        id(value._transaction),
    )


def _stage_completion_fanout_coordinate(
    value: StageCompletionReservation,
) -> tuple[object, ...]:
    return (
        value.authority.workflow_run_id,
        value.source_stage_id,
        "dependency_ready",
        tuple(sorted(item.logical_key for item in value.target_projections)),
    )


def _stage_ready_fanout_coordinate(
    value: StageReadyReservation,
) -> tuple[object, ...]:
    first = value.intents[0]
    causal_id = first.causal_pre_stage.stage_run_id if first.causal_pre_stage is not None else None
    return (
        first.workflow_run_id,
        causal_id,
        first.emission_kind,
        tuple(sorted(item.logical_key for item in value.intents)),
    )


def _stage_completion_fanout_fence(
    db: AsyncSession,
    transaction: object,
) -> _StageCompletionFanoutFence:
    info = db.sync_session.info
    fence = info.get(_STAGE_COMPLETION_FANOUT_FENCE_INFO_KEY)
    if fence is None or (type(fence) is _StageCompletionFanoutFence and fence.transaction is not transaction):
        fence = _StageCompletionFanoutFence(transaction=transaction, coordinates={})
        info[_STAGE_COMPLETION_FANOUT_FENCE_INFO_KEY] = fence
    if type(fence) is not _StageCompletionFanoutFence or fence.transaction is not transaction or type(fence.coordinates) is not dict:
        raise OutboxConflict("Stage completion fanout transaction fence is invalid")
    return fence


def _register_stage_completion_reservation(
    db: AsyncSession,
    transaction: object,
    reservation: StageCompletionReservation,
) -> None:
    key = (id(db), id(transaction), id(reservation))
    _assert_workflow_has_no_terminalization(
        db,
        transaction,
        reservation.authority.workflow_run_id,
    )
    execution_coordinate = _stage_execution_authority_seal(reservation.authority)
    execution_fence = _stage_execution_receipt_transaction_fence(db, transaction)
    if execution_coordinate in execution_fence.coordinates:
        raise OutboxConflict("Stage execution receipt coordinate was already reserved in this root transaction")
    fanout_coordinate = _stage_completion_fanout_coordinate(reservation)
    fanout_fence = _stage_completion_fanout_fence(db, transaction)
    if fanout_coordinate in fanout_fence.coordinates:
        raise OutboxConflict("Stage completion fanout was already reserved in this root transaction")

    def discard(reference: object) -> None:
        current = _STAGE_COMPLETION_RESERVATIONS.get(key)
        if current is not None and (reference is current.session_ref or reference is current.reservation_ref):
            _STAGE_COMPLETION_RESERVATIONS.pop(key, None)

    try:
        registration = _StageCompletionRegistration(
            session_ref=weakref.ref(db, discard),
            reservation_ref=weakref.ref(reservation, discard),
            seal=_stage_completion_reservation_seal(reservation),
            execution_coordinate=execution_coordinate,
            fanout_coordinate=fanout_coordinate,
        )
    except TypeError as exc:
        raise OutboxValidation("Stage completion session cannot hold a capability") from exc
    if key in _STAGE_COMPLETION_RESERVATIONS:
        raise OutboxConflict("Stage completion capability is already registered")
    _STAGE_COMPLETION_RESERVATIONS[key] = registration
    execution_fence.coordinates[execution_coordinate] = ("issued", id(reservation))
    fanout_fence.coordinates[fanout_coordinate] = ("issued", id(reservation))


def _consume_stage_completion_registration(
    db: AsyncSession,
    transaction: object,
    reservation: object,
) -> _StageCompletionRegistration:
    if type(reservation) is not StageCompletionReservation:
        raise OutboxValidation("reservation must be exact stage completion authority")
    key = (id(db), id(transaction), id(reservation))
    registration = _STAGE_COMPLETION_RESERVATIONS.get(key)
    if registration is None or registration.session_ref() is not db or registration.reservation_ref() is not reservation:
        raise OutboxConflict("Stage completion capability is not registered for this transaction")
    execution_fence = _stage_execution_receipt_transaction_fence(db, transaction)
    fanout_fence = _stage_completion_fanout_fence(db, transaction)
    if execution_fence.coordinates.get(registration.execution_coordinate) != ("issued", id(reservation)):
        raise OutboxConflict("Stage completion execution coordinate is not live in this root transaction")
    if fanout_fence.coordinates.get(registration.fanout_coordinate) != ("issued", id(reservation)):
        raise OutboxConflict("Stage completion fanout coordinate is not live in this root transaction")
    execution_fence.coordinates[registration.execution_coordinate] = ("spent", id(reservation))
    fanout_fence.coordinates[registration.fanout_coordinate] = ("spent", id(reservation))
    del _STAGE_COMPLETION_RESERVATIONS[key]
    return registration


def _register_transferred_stage_ready_reservation(
    db: AsyncSession,
    transaction: object,
    *,
    completion_reservation: StageCompletionReservation,
    completion_registration: _StageCompletionRegistration,
    stage_ready_reservation: StageReadyReservation,
) -> None:
    """Transfer one consumed completion fan-out into query-free append authority."""

    if (
        type(completion_reservation) is not StageCompletionReservation
        or type(completion_registration) is not _StageCompletionRegistration
        or type(stage_ready_reservation) is not StageReadyReservation
    ):
        raise OutboxValidation("Completion fan-out transfer requires exact capability types")
    if (
        completion_registration.session_ref() is not db
        or completion_registration.reservation_ref() is not completion_reservation
        or stage_ready_reservation._session is not db
        or stage_ready_reservation._transaction is not transaction
    ):
        raise OutboxConflict("Completion fan-out transfer changed session or transaction authority")
    if _stage_completion_reservation_seal(completion_reservation) != completion_registration.seal:
        raise OutboxConflict("Completion fan-out transfer source was mutated after consumption")

    completion_id = id(completion_reservation)
    execution_fence = _stage_execution_receipt_transaction_fence(db, transaction)
    fanout_fence = _stage_completion_fanout_fence(db, transaction)
    if execution_fence.coordinates.get(completion_registration.execution_coordinate) != (
        "spent",
        completion_id,
    ):
        raise OutboxConflict("Completion execution authority is not spent for fan-out transfer")
    if fanout_fence.coordinates.get(completion_registration.fanout_coordinate) != (
        "spent",
        completion_id,
    ):
        raise OutboxConflict("Completion fan-out authority is not spent for transfer")
    if (
        _stage_completion_fanout_coordinate(completion_reservation) != completion_registration.fanout_coordinate
        or _stage_ready_fanout_coordinate(stage_ready_reservation) != completion_registration.fanout_coordinate
    ):
        raise OutboxStoredContractError("Transferred stage-ready fan-out changed completion identity")

    key = (id(db), id(transaction), id(stage_ready_reservation))
    if key in _STAGE_READY_RESERVATIONS:
        raise OutboxConflict("Transferred stage-ready capability is already registered")

    def discard(reference: object) -> None:
        current = _STAGE_READY_RESERVATIONS.get(key)
        if current is not None and (reference is current.session_ref or reference is current.reservation_ref):
            _STAGE_READY_RESERVATIONS.pop(key, None)

    try:
        registration = _StageReadyReservationRegistration(
            session_ref=weakref.ref(db, discard),
            reservation_ref=weakref.ref(stage_ready_reservation, discard),
            seal=_stage_ready_reservation_seal(stage_ready_reservation),
            fanout_coordinate=completion_registration.fanout_coordinate,
        )
    except TypeError as exc:
        raise OutboxValidation("Transferred stage-ready capability cannot be registered") from exc
    _STAGE_READY_RESERVATIONS[key] = registration
    fanout_fence.coordinates[completion_registration.fanout_coordinate] = (
        "issued",
        id(stage_ready_reservation),
    )


def _register_stage_ready_reservation(
    db: AsyncSession,
    transaction: object,
    reservation: StageReadyReservation,
) -> None:
    key = (id(db), id(transaction), id(reservation))
    fanout_coordinate = _stage_ready_fanout_coordinate(reservation)
    _assert_workflow_has_no_terminalization(
        db,
        transaction,
        fanout_coordinate[0],
    )
    fanout_fence = _stage_completion_fanout_fence(db, transaction)
    if fanout_coordinate in fanout_fence.coordinates:
        raise OutboxConflict("Stage-ready fanout was already reserved in this root transaction")

    def discard(reference: object) -> None:
        current = _STAGE_READY_RESERVATIONS.get(key)
        if current is not None and (reference is current.session_ref or reference is current.reservation_ref):
            _STAGE_READY_RESERVATIONS.pop(key, None)

    try:
        registration = _StageReadyReservationRegistration(
            session_ref=weakref.ref(db, discard),
            reservation_ref=weakref.ref(reservation, discard),
            seal=_stage_ready_reservation_seal(reservation),
            fanout_coordinate=fanout_coordinate,
        )
    except TypeError as exc:
        raise OutboxValidation("Stage-ready reservation session cannot hold a capability") from exc
    if key in _STAGE_READY_RESERVATIONS:
        raise OutboxConflict("Stage-ready reservation capability is already registered")
    _STAGE_READY_RESERVATIONS[key] = registration
    fanout_fence.coordinates[fanout_coordinate] = ("issued", id(reservation))


def _consume_stage_ready_reservation(
    db: AsyncSession,
    transaction: object,
    reservation: object,
) -> tuple[object, ...]:
    if type(reservation) is not StageReadyReservation:
        raise OutboxValidation("reservation must be exact StageReadyReservation authority")
    key = (id(db), id(transaction), id(reservation))
    registration = _STAGE_READY_RESERVATIONS.get(key)
    if registration is None or registration.session_ref() is not db or registration.reservation_ref() is not reservation:
        raise OutboxConflict("Stage-ready reservation capability is not registered for this transaction")
    fanout_fence = _stage_completion_fanout_fence(db, transaction)
    if fanout_fence.coordinates.get(registration.fanout_coordinate) != ("issued", id(reservation)):
        raise OutboxConflict("Stage-ready fanout coordinate is not live in this root transaction")
    fanout_fence.coordinates[registration.fanout_coordinate] = ("spent", id(reservation))
    del _STAGE_READY_RESERVATIONS[key]
    return registration.seal


def _require_session_authorities(db: AsyncSession, values: tuple[object, ...]) -> None:
    sync_session = getattr(db, "sync_session", None)
    if sync_session is None:
        raise OutboxValidation("Stage-ready authority requires an AsyncSession")
    for value in values:
        state = sa_inspect(value)
        column_keys = _EMISSION_AUTHORITY_COLUMNS.get(type(value))
        if column_keys is None:
            raise OutboxValidation("Stage-ready authority has an unsupported persistence type")
        if (
            object_session(value) is not sync_session
            or not state.persistent
            or state.deleted
            or state.detached
            or state.modified
            or state.expired
            or bool(column_keys.intersection(state.expired_attributes))
            or bool(column_keys.intersection(state.unloaded))
        ):
            raise OutboxConflict("Stage-ready authority is not clean persistent state in its locked session")


def _is_migration_backfill(message: OutboxMessage | None) -> bool:
    return message is not None and message.emission_kind == "migration_backfill" and message.redrive_ordinal == 0


def _assert_existing_intent_authority(
    message: OutboxMessage,
    intent: StageReadyIntent,
    *,
    causation_id: uuid.UUID | None,
    cause_is_deferred: bool,
) -> None:
    _exact_model(message, OutboxMessage, field_name="existing message")
    if intent.projection_mode == "transition":
        raise OutboxConflict("A stage transition cannot reuse pre-existing outbox authority")
    _stored_envelope(message)
    compatible_origin = message.emission_kind == intent.emission_kind or _is_migration_backfill(message)
    if _is_migration_backfill(message):
        compatible_cause = message.causation_id is None and causation_id is None
    elif intent.emission_kind == "root_ready":
        compatible_cause = message.causation_id is None and causation_id is None
    elif cause_is_deferred:
        compatible_cause = message.causation_id is not None
    else:
        compatible_cause = message.causation_id == causation_id and causation_id is not None
    post = intent.post_target
    if not (
        message.workflow_run_id == intent.workflow_run_id
        and message.stage_run_id == post.stage_run_id
        and message.aggregate_type == "workflow_stage"
        and message.aggregate_id == post.stage_run_id
        and message.aggregate_version == post.state_version
        and compatible_origin
        and message.topic == OUTBOX_TOPIC_WORKFLOW_STAGE_READY
        and message.schema_version == OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1
        and message.correlation_id == intent.correlation_id
        and compatible_cause
        and message.stage_key == post.stage_key
        and message.target_attempt_number == intent.target_attempt_number
        and message.input_checksum == post.input_checksum
        and message.plan_checksum == intent.plan_checksum
        and message.envelope_canonical == intent.envelope_canonical
        and message.envelope_checksum == intent.envelope_checksum
        and message.envelope_bytes == len(intent.envelope_canonical.encode("utf-8"))
        and message.logical_key == intent.logical_key
        and message.redrive_of_message_id is None
        and message.redrive_ordinal == 0
        and message.max_attempts == OUTBOX_V1_MAX_ATTEMPTS
    ):
        raise OutboxStoredContractError("Stage-ready logical key is already bound to contradictory authority")


def _assert_reserved_active_delivery(
    message: OutboxMessage,
    delivery: OutboxDeliveryAttempt,
) -> None:
    _exact_model(message, OutboxMessage, field_name="reserved message")
    _exact_model(delivery, OutboxDeliveryAttempt, field_name="reserved delivery")
    try:
        message_id = _persisted_uuid(message.id, field_name="reserved message id")
        delivery_id = _persisted_uuid(delivery.id, field_name="reserved delivery id")
        active_delivery_id = _persisted_uuid(
            message.active_delivery_attempt_id,
            field_name="reserved active delivery id",
        )
        delivery_message_id = _persisted_uuid(
            delivery.message_id,
            field_name="reserved delivery message id",
        )
        delivery_token = _persisted_uuid(
            delivery.delivery_token,
            field_name="reserved delivery token",
        )
        _state_version(
            message.state_version,
            field_name="reserved message state_version",
        )
        _state_version(
            delivery.state_version,
            field_name="reserved delivery state_version",
        )
        attempt_count = _bounded_int(
            message.attempt_count,
            field_name="reserved message attempt_count",
            minimum=1,
            maximum=OUTBOX_V1_MAX_ATTEMPTS,
        )
        delivery_attempt = _bounded_int(
            delivery.attempt_number,
            field_name="reserved delivery attempt_number",
            minimum=1,
            maximum=OUTBOX_V1_MAX_ATTEMPTS,
        )
        message_cycle = _bounded_int(
            message.delivery_cycle,
            field_name="reserved message delivery_cycle",
            minimum=1,
            maximum=MAX_OUTBOX_DELIVERY_CYCLE,
        )
        delivery_cycle = _bounded_int(
            delivery.delivery_cycle,
            field_name="reserved delivery cycle",
            minimum=1,
            maximum=MAX_OUTBOX_DELIVERY_CYCLE,
        )
        message_cycle_key = _lower_sha256(
            message.cycle_key,
            field_name="reserved message cycle_key",
        )
        delivery_cycle_key = _lower_sha256(
            delivery.cycle_key,
            field_name="reserved delivery cycle_key",
        )
        expected_cycle_key = delivery_cycle_idempotency_key(
            _lower_sha256(
                message.logical_key,
                field_name="reserved message logical_key",
            ),
            delivery_cycle=message_cycle,
        )
        publisher_id = _text(
            delivery.publisher_id,
            field_name="reserved delivery publisher_id",
            maximum=255,
        )
        delivery_leased_at = _aware_datetime(
            delivery.leased_at,
            field_name="reserved delivery leased_at",
        )
        delivery_heartbeat_at = _aware_datetime(
            delivery.heartbeat_at,
            field_name="reserved delivery heartbeat_at",
        )
        delivery_lease_expires_at = _aware_datetime(
            delivery.lease_expires_at,
            field_name="reserved delivery lease_expires_at",
        )
        if type(message.status) is not str or message.status not in _ACTIVE_DELIVERY_STATUSES:
            raise OutboxValidation("Reserved message status is not active")
        if type(delivery.status) is not str or delivery.status not in _ACTIVE_DELIVERY_STATUSES:
            raise OutboxValidation("Reserved delivery status is not active")
        if type(message.last_error_retryable) is not bool or type(delivery.retryable) is not bool:
            raise OutboxValidation("Reserved delivery retryability is not exact")
        for value, field_name, maximum in (
            (message.lease_owner, "reserved message lease_owner", 255),
            (delivery.broker_name, "reserved delivery broker_name", 80),
            (delivery.broker_message_id, "reserved delivery broker_message_id", 255),
            (delivery.broker_receipt_id, "reserved delivery broker_receipt_id", 255),
            (message.last_error_code, "reserved message error_code", 80),
            (message.last_error_class, "reserved message error_class", 120),
            (message.last_error_summary, "reserved message error_summary", 500),
            (delivery.error_code, "reserved delivery error_code", 80),
            (delivery.error_class, "reserved delivery error_class", 120),
            (delivery.error_summary, "reserved delivery error_summary", 500),
        ):
            _optional_text(value, field_name=field_name, maximum=maximum)
    except (OutboxContractError, OutboxValidation) as exc:
        raise OutboxStoredContractError("Reserved active delivery facts are invalid") from exc

    if (
        message_id != delivery_message_id
        or active_delivery_id != delivery_id
        or delivery.status != message.status
        or delivery_attempt != attempt_count
        or delivery_cycle != message_cycle
        or delivery_cycle_key != message_cycle_key
        or message_cycle_key != expected_cycle_key
        or message.available_at is not None
        or message.max_attempts != OUTBOX_V1_MAX_ATTEMPTS
        or message.last_error_code != ""
        or message.last_error_class != ""
        or message.last_error_summary != ""
        or message.last_error_retryable
        or delivery.error_code != ""
        or delivery.error_class != ""
        or delivery.error_summary != ""
        or delivery.retryable
        or delivery.broker_receipt_id != ""
        or delivery.receipt_received_at is not None
        or delivery.completed_at is not None
        or delivery_lease_expires_at <= delivery_leased_at
        or delivery_heartbeat_at < delivery_leased_at
        or delivery_heartbeat_at > delivery_lease_expires_at
    ):
        raise OutboxStoredContractError("Reserved active message and delivery evidence disagree")

    if message.status == "dispatching":
        try:
            message_token = _persisted_uuid(
                message.lease_token,
                field_name="reserved message lease_token",
            )
            message_leased_at = _aware_datetime(
                message.leased_at,
                field_name="reserved message leased_at",
            )
            message_heartbeat_at = _aware_datetime(
                message.heartbeat_at,
                field_name="reserved message heartbeat_at",
            )
            message_lease_expires_at = _aware_datetime(
                message.lease_expires_at,
                field_name="reserved message lease_expires_at",
            )
            _text(
                message.lease_owner,
                field_name="reserved message lease_owner",
                maximum=255,
            )
        except OutboxValidation as exc:
            raise OutboxStoredContractError("Reserved dispatch lease facts are invalid") from exc
        if (
            message_token != delivery_token
            or message.lease_owner != publisher_id
            or message_leased_at != delivery_leased_at
            or message_heartbeat_at != delivery_heartbeat_at
            or message_lease_expires_at != delivery_lease_expires_at
            or message.receipt_deadline_at is not None
            or delivery.broker_name != ""
            or delivery.broker_message_id != ""
            or delivery.dispatched_at is not None
            or delivery.receipt_deadline_at is not None
        ):
            raise OutboxStoredContractError("Reserved dispatch lease evidence disagrees")
        return

    try:
        receipt_deadline = _aware_datetime(
            message.receipt_deadline_at,
            field_name="reserved message receipt_deadline_at",
        )
        dispatched_at = _aware_datetime(
            delivery.dispatched_at,
            field_name="reserved delivery dispatched_at",
        )
        delivery_receipt_deadline = _aware_datetime(
            delivery.receipt_deadline_at,
            field_name="reserved delivery receipt_deadline_at",
        )
        _identity(
            delivery.broker_name,
            field_name="reserved delivery broker_name",
        )
        _text(
            delivery.broker_message_id,
            field_name="reserved delivery broker_message_id",
            maximum=255,
        )
    except OutboxValidation as exc:
        raise OutboxStoredContractError("Reserved receipt-window facts are invalid") from exc
    if (
        message.lease_owner != ""
        or message.lease_token is not None
        or message.leased_at is not None
        or message.heartbeat_at is not None
        or message.lease_expires_at is not None
        or receipt_deadline != delivery_receipt_deadline
        or dispatched_at < delivery_leased_at
        or delivery_receipt_deadline <= dispatched_at
    ):
        raise OutboxStoredContractError("Reserved receipt-window evidence disagrees")


def _assert_workflow_post_authority(
    workflow: WorkflowRun,
    intents: tuple[StageReadyIntent, ...],
) -> None:
    for intent in intents:
        if (
            _persisted_uuid(workflow.id, field_name="workflow.id") != intent.workflow_run_id
            or workflow.status != intent.workflow_status
            or workflow.state_version != intent.workflow_state_version
            or _persisted_uuid(workflow.correlation_id, field_name="workflow.correlation_id") != intent.correlation_id
            or workflow.plan_checksum != intent.plan_checksum
        ):
            raise OutboxConflict("Workflow authority changed after stage-ready reservation")


def _assert_stage_matches_ready_state(
    stage: StageRun,
    expected: _StageReadyState,
    *,
    phase: str,
) -> None:
    actual = _stage_ready_state(stage)
    if actual != expected:
        raise OutboxConflict(f"Stage authority changed from its reserved {phase} projection")


def _assert_unmodified_reserved_stages(
    stages: tuple[StageRun, ...],
    reservation: StageReadyReservation,
) -> None:
    target_ids = {intent.post_target.stage_run_id for intent in reservation.intents}
    transitioned_source_ids = {
        intent.causal_pre_stage.stage_run_id
        for intent in reservation.intents
        if intent.projection_mode == "transition" and intent.causal_pre_stage is not None
    }
    for stage, expected in zip(stages, reservation.locked_stage_states, strict=True):
        if expected.stage_run_id in target_ids or expected.stage_run_id in transitioned_source_ids:
            continue
        _assert_stage_matches_ready_state(stage, expected, phase="unchanged")


def _validated_intent_causation(
    intent: StageReadyIntent,
    *,
    workflow: WorkflowRun,
    stages: tuple[StageRun, ...],
    target: StageRun,
    causal_attempt: StageAttempt | None,
    existing_message: OutboxMessage | None,
) -> uuid.UUID | None:
    if _is_migration_backfill(existing_message):
        return None
    if intent.emission_kind == "root_ready":
        if causal_attempt is not None:
            raise OutboxValidation("Root-ready emission cannot carry causal attempt provenance")
        return None
    attempt = _exact_model(causal_attempt, StageAttempt, field_name="causal_attempt")
    attempt_id = _persisted_uuid(attempt.id, field_name="causal_attempt.id")
    by_id = {_persisted_uuid(stage.id, field_name="stage.id"): stage for stage in stages}
    if intent.projection_mode == "transition":
        causal_pre = intent.causal_pre_stage
        if causal_pre is None:
            raise OutboxStoredContractError("Causal transition intent lost its source projection")
        source = by_id.get(causal_pre.stage_run_id)
        if source is None:
            raise OutboxStoredContractError("Causal stage is absent after reservation")
        _assert_transition_causal_attempt(
            intent,
            workflow=workflow,
            source=source,
            target=target,
            attempt=attempt,
        )
    else:
        source_id = _persisted_uuid(attempt.stage_run_id, field_name="causal_attempt.stage_run_id")
        source = by_id.get(source_id)
        if source is None:
            raise OutboxStoredContractError("Persisted causal attempt is outside the locked workflow plan")
        _assert_current_causal_attempt(
            intent,
            workflow=workflow,
            source=source,
            target=target,
            attempt=attempt,
        )
    if intent.emission_kind == "dependency_ready":
        by_key = {stage.stage_key: stage for stage in stages}
        for dependency_key in target.depends_on:
            dependency = by_key.get(dependency_key)
            if dependency is None or dependency.status not in {"succeeded", "degraded"}:
                raise OutboxStoredContractError("Dependency-ready append has an incomplete locked prerequisite")
    return attempt_id


def _assert_attempt_terminal_basics(
    attempt: StageAttempt,
    *,
    source: StageRun,
    expected_attempt_number: int,
    expected_lease_token: uuid.UUID | None,
    expected_pre: _StageReadyState | None,
) -> None:
    _exact_model(attempt, StageAttempt, field_name="causal_attempt")
    try:
        _state_version(attempt.state_version, field_name="causal attempt state_version")
        _bounded_int(
            attempt.attempt_number,
            field_name="causal attempt number",
            minimum=1,
            maximum=20,
        )
        checkpoint_start = _bounded_int(
            attempt.checkpoint_start_version,
            field_name="causal attempt checkpoint_start_version",
            minimum=0,
            maximum=2_147_483_647,
        )
        checkpoint_end = _bounded_int(
            attempt.checkpoint_end_version,
            field_name="causal attempt checkpoint_end_version",
            minimum=0,
            maximum=2_147_483_647,
        )
        if checkpoint_start > checkpoint_end:
            raise OutboxValidation("Causal attempt checkpoint versions are contradictory")
        _uuid(
            _persisted_uuid(attempt.lease_token, field_name="causal attempt lease_token"),
            field_name="causal lease",
        )
        _text(attempt.lease_owner, field_name="causal attempt lease_owner", maximum=255)
        for field_name in ("started_at", "heartbeat_at", "lease_expires_at", "completed_at"):
            _aware_datetime(getattr(attempt, field_name), field_name=f"causal attempt {field_name}")
        _lower_sha256(attempt.input_checksum, field_name="causal attempt input_checksum")
        _optional_text(
            attempt.delivery_id,
            field_name="causal attempt delivery_id",
            maximum=100,
        )
        if attempt.outbox_delivery_attempt_id is not None:
            _persisted_uuid(
                attempt.outbox_delivery_attempt_id,
                field_name="causal attempt outbox_delivery_attempt_id",
            )
            _lower_sha256(
                attempt.delivery_id,
                field_name="linked causal attempt delivery_id",
            )
        if type(attempt.status) is not str or attempt.status not in {
            "succeeded",
            "degraded",
            "failed",
            "abandoned",
        }:
            raise OutboxValidation("Causal attempt status is not terminal emission authority")
        for field_name, maximum in (
            ("error_code", 80),
            ("error_class", 120),
            ("error_summary", 500),
        ):
            _optional_text(
                getattr(attempt, field_name),
                field_name=f"causal attempt {field_name}",
                maximum=maximum,
            )
        if type(attempt.output_checksum) is not str or (
            attempt.output_checksum != "" and not _LOWER_SHA256_RE.fullmatch(attempt.output_checksum)
        ):
            raise OutboxValidation("Causal attempt output checksum is invalid")
        if type(attempt.retryable) is not bool:
            raise OutboxValidation("Causal attempt retryability is not exact")
    except OutboxValidation as exc:
        raise OutboxStoredContractError("Causal attempt has invalid persisted terminal facts") from exc
    if (
        _persisted_uuid(attempt.stage_run_id, field_name="causal attempt stage_run_id")
        != _persisted_uuid(source.id, field_name="causal source stage id")
        or attempt.attempt_number != expected_attempt_number
        or (
            expected_lease_token is not None
            and _persisted_uuid(attempt.lease_token, field_name="causal attempt lease_token") != expected_lease_token
        )
        or attempt.input_checksum != source.input_checksum
        or attempt.checkpoint_end_version != source.checkpoint_version
        or attempt.lease_expires_at <= attempt.started_at
        or attempt.heartbeat_at < attempt.started_at
        or attempt.heartbeat_at > attempt.lease_expires_at
        or attempt.completed_at < attempt.heartbeat_at
        or (
            attempt.status in {"succeeded", "degraded", "failed"}
            and (attempt.heartbeat_at != attempt.completed_at or attempt.completed_at >= attempt.lease_expires_at)
        )
        or (attempt.status == "abandoned" and not (attempt.heartbeat_at <= attempt.lease_expires_at <= attempt.completed_at))
    ):
        raise OutboxStoredContractError("Causal attempt does not match its locked source stage")
    if expected_pre is not None and (
        attempt.lease_owner != expected_pre.lease_owner
        or attempt.started_at != expected_pre.leased_at
        or attempt.lease_expires_at != expected_pre.lease_expires_at
    ):
        raise OutboxStoredContractError("Causal attempt lease facts disagree with the reserved source")


def _assert_transition_causal_attempt(
    intent: StageReadyIntent,
    *,
    workflow: WorkflowRun,
    source: StageRun,
    target: StageRun,
    attempt: StageAttempt,
) -> None:
    pre = intent.causal_pre_stage
    if pre is None:
        raise OutboxStoredContractError("Transition has no causal pre-state")
    _assert_attempt_terminal_basics(
        attempt,
        source=source,
        expected_attempt_number=pre.attempt_count,
        expected_lease_token=pre.lease_token,
        expected_pre=pre,
    )
    if intent.emission_kind == "dependency_ready":
        expected_source = replace(
            pre,
            status=attempt.status,
            state_version=pre.state_version + 1,
            next_attempt_at=None,
            lease_owner="",
            lease_token=None,
            leased_at=None,
            lease_expires_at=None,
            heartbeat_at=None,
            last_error_code="",
            last_error_summary="",
            last_error_retryable=False,
            output_manifest_checksum=attempt.output_checksum,
            output_checksum=attempt.output_checksum,
            completed_at=attempt.completed_at,
        )
        if (
            attempt.status not in {"succeeded", "degraded"}
            or attempt.retryable
            or attempt.error_code != ""
            or attempt.error_class != ""
            or attempt.error_summary != ""
            or not _LOWER_SHA256_RE.fullmatch(attempt.output_checksum)
            or _stage_ready_state(source) != expected_source
            or source.stage_key not in target.depends_on
        ):
            raise OutboxStoredContractError("Dependency-ready cause contradicts terminal success evidence")
        _assert_causal_stage_ready_schedule(
            intent,
            workflow=workflow,
            target=target,
            attempt=attempt,
        )
        return
    if source is not target:
        raise OutboxStoredContractError("Retry cause must be the target stage")
    if intent.emission_kind == "retry_scheduled":
        valid = (
            attempt.status == "failed"
            and attempt.retryable
            and attempt.error_code != "workflow.lease_expired"
            and bool(attempt.error_class)
            and bool(attempt.error_summary)
            and attempt.output_checksum == ""
            and attempt.error_code == target.last_error_code
            and attempt.error_summary == target.last_error_summary
        )
    else:
        valid = (
            attempt.status == "abandoned"
            and attempt.retryable
            and attempt.error_code == "workflow.lease_expired"
            and attempt.error_class == "LeaseExpired"
            and bool(attempt.error_summary)
            and attempt.output_checksum == ""
            and attempt.error_code == target.last_error_code
            and attempt.error_summary == target.last_error_summary
        )
    if not valid:
        raise OutboxStoredContractError("Retry cause contradicts terminal attempt evidence")
    _assert_causal_stage_ready_schedule(
        intent,
        workflow=workflow,
        target=target,
        attempt=attempt,
    )


def _assert_current_causal_attempt(
    intent: StageReadyIntent,
    *,
    workflow: WorkflowRun,
    source: StageRun,
    target: StageRun,
    attempt: StageAttempt,
) -> None:
    _assert_attempt_terminal_basics(
        attempt,
        source=source,
        expected_attempt_number=source.attempt_count,
        expected_lease_token=None,
        expected_pre=None,
    )
    if intent.emission_kind == "dependency_ready":
        if (
            source.stage_key not in target.depends_on
            or source.status not in {"succeeded", "degraded"}
            or attempt.status != source.status
            or attempt.retryable
            or attempt.error_code != ""
            or attempt.error_class != ""
            or attempt.error_summary != ""
            or source.output_checksum != attempt.output_checksum
            or source.completed_at != attempt.completed_at
        ):
            raise OutboxStoredContractError("Existing dependency-ready cause is not exact success evidence")
        _assert_causal_stage_ready_schedule(
            intent,
            workflow=workflow,
            target=target,
            attempt=attempt,
        )
        return
    if source is not target:
        raise OutboxStoredContractError("Existing retry cause is not the target stage")
    if intent.emission_kind == "retry_scheduled":
        valid = (
            attempt.status == "failed"
            and attempt.retryable
            and attempt.error_code != "workflow.lease_expired"
            and bool(attempt.error_class)
            and bool(attempt.error_summary)
            and attempt.output_checksum == ""
            and attempt.error_code == target.last_error_code
            and attempt.error_summary == target.last_error_summary
        )
    else:
        valid = (
            attempt.status == "abandoned"
            and attempt.retryable
            and attempt.error_code == "workflow.lease_expired"
            and attempt.error_class == "LeaseExpired"
            and bool(attempt.error_summary)
            and attempt.output_checksum == ""
            and attempt.error_code == target.last_error_code
            and attempt.error_summary == target.last_error_summary
        )
    if not valid:
        raise OutboxStoredContractError("Existing retry cause contradicts target evidence")
    _assert_causal_stage_ready_schedule(
        intent,
        workflow=workflow,
        target=target,
        attempt=attempt,
    )


def _assert_causal_stage_ready_schedule(
    intent: StageReadyIntent,
    *,
    workflow: WorkflowRun,
    target: StageRun,
    attempt: StageAttempt,
) -> None:
    if intent.emission_kind == "dependency_ready":
        expected = attempt.completed_at
    else:
        normalized = _normalized_workflow_plan(workflow)
        definition = next(
            (candidate for candidate in normalized.stages if candidate.stage_key == target.stage_key),
            None,
        )
        if definition is None:
            raise OutboxStoredContractError("Causal retry target is absent from canonical workflow authority")
        try:
            delay = deterministic_retry_backoff_seconds(
                attempt.attempt_number,
                seed=str(_persisted_uuid(target.id, field_name="retry target id")),
                policy=definition.retry_policy,
            )
        except WorkflowContractError as exc:
            raise OutboxStoredContractError("Causal retry schedule cannot be derived from workflow authority") from exc
        expected = attempt.completed_at + timedelta(seconds=delay)
    if intent.post_target.next_attempt_at != expected or target.next_attempt_at != expected:
        raise OutboxStoredContractError("Stage-ready availability disagrees with exact causal schedule")


def _build_stage_ready_message(
    intent: StageReadyIntent,
    *,
    message_id: uuid.UUID,
    causation_id: uuid.UUID | None,
) -> OutboxMessage:
    post = intent.post_target
    return OutboxMessage(
        id=message_id,
        workflow_run_id=intent.workflow_run_id,
        stage_run_id=post.stage_run_id,
        aggregate_type="workflow_stage",
        aggregate_id=post.stage_run_id,
        aggregate_version=post.state_version,
        emission_kind=intent.emission_kind,
        topic=OUTBOX_TOPIC_WORKFLOW_STAGE_READY,
        schema_version=OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1,
        correlation_id=intent.correlation_id,
        causation_id=causation_id,
        stage_key=post.stage_key,
        target_attempt_number=intent.target_attempt_number,
        input_checksum=post.input_checksum,
        plan_checksum=intent.plan_checksum,
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
        max_attempts=OUTBOX_V1_MAX_ATTEMPTS,
        delivery_cycle=0,
        cycle_key=None,
        available_at=post.next_attempt_at,
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


def _is_dispatch_effect_replay(
    message: OutboxMessage,
    delivery: OutboxDeliveryAttempt,
    *,
    delivery_token: uuid.UUID,
    expected_message_version: int,
    expected_delivery_version: int,
    broker_name: str,
    broker_message_id: str,
    receipt_timeout_seconds: int,
) -> bool:
    if not _is_latest_delivery(
        message,
        delivery,
        delivery_token=delivery_token,
    ):
        return False
    allowed_deltas = {1, 2} if message.status == "delivered" else {1}
    if not _has_exact_replay_version_delta(
        message,
        delivery,
        expected_message_version=expected_message_version,
        expected_delivery_version=expected_delivery_version,
        allowed_deltas=allowed_deltas,
    ):
        return False
    if message.status == "awaiting_receipt":
        if (
            message.active_delivery_attempt_id != delivery.id
            or message.receipt_deadline_at != delivery.receipt_deadline_at
            or delivery.dispatched_at is None
            or delivery.receipt_deadline_at is None
            or delivery.receipt_deadline_at - delivery.dispatched_at != timedelta(seconds=receipt_timeout_seconds)
        ):
            return False
    elif message.status == "delivered":
        if (
            message.active_delivery_attempt_id is not None
            or message.receipt_deadline_at is not None
            or message.delivered_at is None
            or delivery.dispatched_at is None
            or delivery.receipt_deadline_at is not None
            or delivery.receipt_received_at is None
            or delivery.completed_at is None
            or message.delivered_at != delivery.completed_at
            or delivery.receipt_received_at != delivery.completed_at
        ):
            return False
    return (
        message.status in {"awaiting_receipt", "delivered"}
        and delivery.status == message.status
        and delivery.broker_name == broker_name
        and delivery.broker_message_id == broker_message_id
        and (message.status == "delivered" or message.receipt_deadline_at == delivery.receipt_deadline_at)
    )


def _is_exact_failure_replay(
    message: OutboxMessage,
    delivery: OutboxDeliveryAttempt,
    *,
    delivery_token: uuid.UUID,
    expected_message_version: int,
    expected_delivery_version: int,
    error: SanitizedOutboxError,
) -> bool:
    return (
        _is_latest_delivery(
            message,
            delivery,
            delivery_token=delivery_token,
        )
        and _has_exact_replay_version_delta(
            message,
            delivery,
            expected_message_version=expected_message_version,
            expected_delivery_version=expected_delivery_version,
            allowed_deltas={1},
        )
        and message.status in {"retry_wait", "dead_lettered"}
        and delivery.status == "failed"
        and message.active_delivery_attempt_id is None
        and message.last_error_code == error.code
        and message.last_error_class == error.error_class
        and message.last_error_summary == error.summary
        and message.last_error_retryable == error.retryable
        and delivery.error_code == error.code
        and delivery.error_class == error.error_class
        and delivery.error_summary == error.summary
        and delivery.retryable == error.retryable
        and (
            (
                message.status == "retry_wait"
                and message.available_at is not None
                and delivery.completed_at is not None
                and message.available_at
                == delivery.completed_at
                + timedelta(
                    seconds=deterministic_delivery_retry_delay_seconds(
                        message.attempt_count,
                        logical_key=message.logical_key,
                    )
                )
            )
            or (
                message.status == "dead_lettered"
                and message.available_at is None
                and delivery.completed_at is not None
                and message.dead_lettered_at == delivery.completed_at
            )
        )
    )


def _is_latest_delivery(
    message: OutboxMessage,
    delivery: OutboxDeliveryAttempt,
    *,
    delivery_token: uuid.UUID,
) -> bool:
    return (
        message.max_attempts == OUTBOX_V1_MAX_ATTEMPTS
        and delivery.delivery_token == delivery_token
        and delivery.attempt_number == message.attempt_count
        and delivery.delivery_cycle == message.delivery_cycle
        and delivery.cycle_key == message.cycle_key
    )


def _has_exact_replay_version_delta(
    message: OutboxMessage,
    delivery: OutboxDeliveryAttempt,
    *,
    expected_message_version: int,
    expected_delivery_version: int,
    allowed_deltas: set[int],
) -> bool:
    expected_message = _bounded_int(
        expected_message_version,
        field_name="expected_message_version",
        minimum=1,
        maximum=2_147_483_647,
    )
    expected_delivery = _bounded_int(
        expected_delivery_version,
        field_name="expected_delivery_version",
        minimum=1,
        maximum=2_147_483_647,
    )
    message_delta = message.state_version - expected_message
    delivery_delta = delivery.state_version - expected_delivery
    return message_delta == delivery_delta and message_delta in allowed_deltas


def _safe_error(value: object) -> SanitizedOutboxError:
    if type(value) is not SanitizedOutboxError:
        raise OutboxValidation("error must be exact sanitized outbox error facts")
    try:
        code = value.code
        error_class = value.error_class
        summary = value.summary
        retryable = value.retryable
        rebuilt = sanitize_outbox_error(
            summary,
            code=code,
            retryable=retryable,
            error_class=error_class,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise OutboxValidation("error facts are not valid sanitized authority") from exc
    if (
        rebuilt.code,
        rebuilt.error_class,
        rebuilt.summary,
        rebuilt.retryable,
    ) != (code, error_class, summary, retryable):
        raise OutboxValidation("error facts are not a sanitizer fixed point")
    return rebuilt


def _expected_emission_kind(stage: StageRun) -> str:
    if type(stage.depends_on) is not list:
        raise OutboxStoredContractError("Stage dependencies are not an array")
    if stage.status == "ready":
        return "root_ready" if not stage.depends_on else "dependency_ready"
    if stage.status == "retry_wait":
        return "lease_recovered" if stage.last_error_code == "workflow.lease_expired" else "retry_scheduled"
    raise OutboxStoredContractError("Stage is not eligible for stage-ready emission")


def _stored_envelope(message: OutboxMessage) -> NormalizedOutboxEnvelope:
    try:
        normalized = NormalizedOutboxEnvelope(
            canonical=message.envelope_canonical,
            checksum=message.envelope_checksum,
            logical_key=message.logical_key,
        )
    except (OutboxContractError, TypeError, ValueError) as exc:
        raise OutboxStoredContractError("Persisted outbox envelope is not valid canonical authority") from exc
    envelope = normalized.envelope
    payload = envelope.payload
    if (
        message.topic != envelope.topic
        or message.schema_version != envelope.schema_version
        or message.workflow_run_id != payload.workflow_run_id
        or message.stage_run_id != payload.stage_run_id
        or message.aggregate_type != "workflow_stage"
        or message.aggregate_id != payload.stage_run_id
        or message.stage_key != payload.stage_key
        or message.target_attempt_number != payload.target_attempt_number
        or message.input_checksum != payload.input_checksum
        or message.plan_checksum != payload.plan_checksum
        or message.envelope_bytes != len(normalized.canonical.encode("utf-8"))
    ):
        raise OutboxStoredContractError("Persisted outbox columns disagree with their canonical envelope")
    return normalized


def _assert_recovery_pair(
    message: OutboxMessage,
    delivery: OutboxDeliveryAttempt,
) -> None:
    if (
        message.max_attempts != OUTBOX_V1_MAX_ATTEMPTS
        or message.active_delivery_attempt_id != delivery.id
        or delivery.message_id != message.id
        or delivery.attempt_number != message.attempt_count
        or delivery.delivery_cycle != message.delivery_cycle
        or delivery.cycle_key != message.cycle_key
    ):
        raise OutboxStoredContractError("Expired message and delivery lineage facts disagree")
    if message.status == "dispatching" and (
        message.lease_token != delivery.delivery_token
        or message.lease_owner != delivery.publisher_id
        or message.leased_at != delivery.leased_at
        or message.heartbeat_at != delivery.heartbeat_at
        or message.lease_expires_at != delivery.lease_expires_at
    ):
        raise OutboxStoredContractError("Expired message and delivery lease facts disagree")
    if message.status == "awaiting_receipt" and (
        message.receipt_deadline_at != delivery.receipt_deadline_at
        or message.lease_owner != ""
        or message.lease_token is not None
        or message.leased_at is not None
        or message.heartbeat_at is not None
        or message.lease_expires_at is not None
    ):
        raise OutboxStoredContractError("Expired message and delivery receipt facts disagree")


def _copy_claim_authority(value: object) -> ClaimedOutboxDelivery:
    if type(value) is not ClaimedOutboxDelivery:
        raise OutboxValidation("claim must be exact detached publisher authority")
    try:
        return ClaimedOutboxDelivery(
            message_id=value.message_id,
            delivery_attempt_id=value.delivery_attempt_id,
            delivery_token=value.delivery_token,
            message_state_version=value.message_state_version,
            delivery_state_version=value.delivery_state_version,
            delivery_cycle=value.delivery_cycle,
            cycle_key=value.cycle_key,
            correlation_id=value.correlation_id,
            topic=value.topic,
            schema_version=value.schema_version,
            envelope_checksum=value.envelope_checksum,
            logical_key=value.logical_key,
            envelope_canonical=value.envelope_canonical,
        )
    except AttributeError as exc:
        raise OutboxValidation("claim authority fields are incomplete") from exc


def _copy_executable_stage_authority(value: object) -> ExecutableStageAuthority:
    if type(value) is not ExecutableStageAuthority:
        raise OutboxValidation("authority must be exact executable stage authority")
    try:
        return ExecutableStageAuthority(
            workflow_run_id=value.workflow_run_id,
            stage_run_id=value.stage_run_id,
            stage_attempt_id=value.stage_attempt_id,
            message_id=value.message_id,
            delivery_attempt_id=value.delivery_attempt_id,
            stage_lease_token=value.stage_lease_token,
            workflow_state_version=value.workflow_state_version,
            stage_state_version=value.stage_state_version,
            attempt_state_version=value.attempt_state_version,
            attempt_number=value.attempt_number,
            delivery_cycle=value.delivery_cycle,
            cycle_key=value.cycle_key,
            stage_key=value.stage_key,
            input_checksum=value.input_checksum,
            checkpoint_version=value.checkpoint_version,
            lease_owner=value.lease_owner,
            lease_expires_at=value.lease_expires_at,
            broker_receipt_id=value.broker_receipt_id,
        )
    except AttributeError as exc:
        raise OutboxValidation("executable stage authority fields are incomplete") from exc


def _copy_receipt_command(value: object) -> StageReceiptCommand:
    if type(value) is not StageReceiptCommand:
        raise OutboxValidation("command must be exact stage receipt authority")
    try:
        return StageReceiptCommand(
            claim=value.claim,
            broker_name=value.broker_name,
            broker_message_id=value.broker_message_id,
            broker_receipt_id=value.broker_receipt_id,
            worker_id=value.worker_id,
            lease_seconds=value.lease_seconds,
        )
    except AttributeError as exc:
        raise OutboxValidation("receipt command fields are incomplete") from exc


def _fresh_stage_lease_token(delivery_token: uuid.UUID) -> uuid.UUID:
    """Mint a bounded fresh worker fence distinct from broker authority."""

    broker_token = _persisted_uuid(
        delivery_token,
        field_name="delivery.delivery_token",
    )
    for _ in range(3):
        candidate = uuid.uuid4()
        if candidate != broker_token:
            return candidate
    raise OutboxStoredContractError("Could not mint a stage lease token distinct from delivery authority")


def _mint_commit_ticket(
    *,
    workflow: WorkflowRun,
    stage: StageRun,
    message: OutboxMessage,
    delivery: OutboxDeliveryAttempt,
    attempt: StageAttempt,
    origin_transaction_id: int,
) -> str:
    coordinates = _CommitTicketCoordinates(
        workflow_run_id=_persisted_uuid(workflow.id, field_name="workflow.id"),
        stage_run_id=_persisted_uuid(stage.id, field_name="stage.id"),
        message_id=_persisted_uuid(message.id, field_name="message.id"),
        delivery_attempt_id=_persisted_uuid(delivery.id, field_name="delivery.id"),
        stage_attempt_id=_persisted_uuid(attempt.id, field_name="attempt.id"),
        origin_transaction_id=_transaction_id(
            origin_transaction_id,
            field_name="origin_transaction_id",
        ),
    )
    prefix = _commit_ticket_prefix(coordinates)
    token = _persisted_uuid(attempt.lease_token, field_name="attempt.lease_token")
    digest = hmac.new(
        token.bytes,
        _commit_ticket_content(
            prefix=prefix,
            workflow=workflow,
            stage=stage,
            message=message,
            delivery=delivery,
            attempt=attempt,
        ),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(prefix + digest).decode("ascii")


def _decode_commit_ticket(value: str) -> _CommitTicketCoordinates:
    ticket = _commit_ticket(value)
    try:
        raw = base64.b64decode(ticket, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise OutboxValidation("commit_ticket is not canonical base64url authority") from exc
    if len(raw) != 120 or base64.urlsafe_b64encode(raw).decode("ascii") != ticket:
        raise OutboxValidation("commit_ticket has a noncanonical binary shape")
    coordinates = _CommitTicketCoordinates(
        workflow_run_id=uuid.UUID(bytes=raw[0:16]),
        stage_run_id=uuid.UUID(bytes=raw[16:32]),
        message_id=uuid.UUID(bytes=raw[32:48]),
        delivery_attempt_id=uuid.UUID(bytes=raw[48:64]),
        stage_attempt_id=uuid.UUID(bytes=raw[64:80]),
        origin_transaction_id=struct.unpack(">Q", raw[80:88])[0],
    )
    _transaction_id(
        coordinates.origin_transaction_id,
        field_name="commit_ticket transaction ID",
    )
    return coordinates


def _commit_ticket_prefix(coordinates: _CommitTicketCoordinates) -> bytes:
    return b"".join(
        (
            coordinates.workflow_run_id.bytes,
            coordinates.stage_run_id.bytes,
            coordinates.message_id.bytes,
            coordinates.delivery_attempt_id.bytes,
            coordinates.stage_attempt_id.bytes,
            struct.pack(">Q", coordinates.origin_transaction_id),
        )
    )


def _commit_ticket_content(
    *,
    prefix: bytes,
    workflow: WorkflowRun,
    stage: StageRun,
    message: OutboxMessage,
    delivery: OutboxDeliveryAttempt,
    attempt: StageAttempt,
) -> bytes:
    fields = (
        prefix,
        stage.stage_key.encode("ascii"),
        attempt.lease_owner.encode("utf-8"),
        message.envelope_checksum.encode("ascii"),
        message.logical_key.encode("ascii"),
        message.plan_checksum.encode("ascii"),
        delivery.cycle_key.encode("ascii"),
        delivery.broker_name.encode("ascii"),
        delivery.broker_message_id.encode("utf-8"),
        delivery.broker_receipt_id.encode("ascii"),
        attempt.input_checksum.encode("ascii"),
        _persisted_uuid(
            attempt.lease_token,
            field_name="attempt.lease_token",
        ).bytes,
        struct.pack(">I", workflow.state_version),
        struct.pack(">I", stage.state_version),
        struct.pack(">I", message.state_version),
        struct.pack(">I", delivery.state_version),
        struct.pack(">I", attempt.state_version),
        struct.pack(">I", attempt.attempt_number),
        struct.pack(">I", attempt.checkpoint_start_version),
        struct.pack(">I", attempt.checkpoint_end_version),
        struct.pack(">q", _datetime_microseconds(attempt.started_at)),
        struct.pack(">q", _datetime_microseconds(attempt.lease_expires_at)),
    )
    bounded = bytearray(_COMMIT_TICKET_DOMAIN)
    for field in fields:
        bounded.extend(struct.pack(">I", len(field)))
        bounded.extend(field)
    return bytes(bounded)


def _datetime_microseconds(value: object) -> int:
    timestamp = _aware_datetime(value, field_name="commit ticket timestamp")
    utc_value = timestamp.astimezone(timezone.utc)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = utc_value - epoch
    return delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds


def _copy_stage_failure_evidence(value: object) -> StageFailureEvidence:
    if type(value) is not StageFailureEvidence:
        raise OutboxValidation("evidence must be exact StageFailureEvidence authority")
    try:
        return StageFailureEvidence(
            code=value.code,
            error_class=value.error_class,
            summary=value.summary,
            retryable=value.retryable,
        )
    except (AttributeError, OutboxValidation) as exc:
        raise OutboxValidation("Stage failure evidence is not a fixed point") from exc


def _copy_workflow_cancellation_command(value: object) -> WorkflowCancellationCommand:
    if type(value) is not WorkflowCancellationCommand:
        raise OutboxValidation("command must be exact workflow cancellation authority")
    try:
        return WorkflowCancellationCommand(
            request_id=value.request_id,
            workflow_run_id=value.workflow_run_id,
            expected_workflow_state_version=value.expected_workflow_state_version,
            actor=value.actor,
            actor_id=value.actor_id,
            reason=value.reason,
        )
    except (AttributeError, OutboxValidation) as exc:
        raise OutboxValidation("Workflow cancellation command is not a fixed point") from exc


def _validate_locked_model_union(
    *,
    model_values: object,
    id_values: object,
    model: type,
    field_name: str,
    allow_empty: bool,
) -> None:
    if type(model_values) is not tuple or type(id_values) is not tuple:
        raise OutboxValidation(f"{field_name} must be exact tuples")
    if not allow_empty and not model_values:
        raise OutboxValidation(f"{field_name} cannot be empty")
    if len(model_values) != len(id_values):
        raise OutboxValidation(f"{field_name} identity tuples are misaligned")
    for item in model_values:
        _exact_model(item, model, field_name=field_name)
    for item in id_values:
        _uuid(item, field_name=field_name)
    if id_values != tuple(sorted(id_values, key=lambda item: item.int)) or len(set(id_values)) != len(id_values):
        raise OutboxValidation(f"{field_name} lost canonical UUID order")
    if tuple(_persisted_uuid(item.id, field_name=field_name) for item in model_values) != id_values:
        raise OutboxValidation(f"{field_name} identities are misaligned")


def _validate_workflow_terminalization_dto(
    value: WorkflowTerminalizationReservation | LockedWorkflowTerminalizationGraph,
    *,
    locked: bool,
) -> None:
    _exact_model(value.workflow, WorkflowRun, field_name="terminalization workflow")
    if type(value.stages) is not tuple or not value.stages:
        raise OutboxValidation("Terminalization stages must be an exact non-empty tuple")
    if type(value.stage_states) is not tuple or len(value.stage_states) != len(value.stages):
        raise OutboxValidation("Terminalization stage snapshots are incomplete")
    for stage in value.stages:
        _exact_model(stage, StageRun, field_name="terminalization stage")
    copied_states = tuple(_copy_stage_ready_state(state) for state in value.stage_states)
    if tuple(state.stage_run_id for state in copied_states) != tuple(
        _persisted_uuid(stage.id, field_name="terminalization stage id") for stage in value.stages
    ):
        raise OutboxValidation("Terminalization stage snapshots are out of plan order")
    if type(value.decision) is not str or value.decision not in {"apply", "replay"}:
        raise OutboxValidation("Terminalization decision is outside its closed registry")
    if type(value.projection) is not _WorkflowTerminalizationProjection or value.projection.decision != value.decision:
        raise OutboxValidation("Terminalization projection and decision disagree")
    if len(value.projection.post_stage_statuses) != len(value.stages):
        raise OutboxValidation("Terminalization projection does not cover the complete stage plan")
    _validate_locked_model_union(
        model_values=value.locked_messages,
        id_values=value.locked_message_ids,
        model=OutboxMessage,
        field_name="terminalization messages",
        allow_empty=True,
    )
    _validate_locked_model_union(
        model_values=value.locked_deliveries,
        id_values=value.locked_delivery_ids,
        model=OutboxDeliveryAttempt,
        field_name="terminalization deliveries",
        allow_empty=True,
    )
    _validate_locked_model_union(
        model_values=value.locked_attempts,
        id_values=value.locked_attempt_ids,
        model=StageAttempt,
        field_name="terminalization attempts",
        allow_empty=True,
    )
    if type(value.live_message_ids) is not tuple:
        raise OutboxValidation("Terminalization live_message_ids must be an exact tuple")
    for item in value.live_message_ids:
        _uuid(item, field_name="terminalization live message id")
    if value.live_message_ids != tuple(sorted(value.live_message_ids, key=lambda item: item.int)):
        raise OutboxValidation("Terminalization live messages lost canonical UUID order")
    if not set(value.live_message_ids).issubset(value.locked_message_ids):
        raise OutboxValidation("Terminalization live messages are outside the locked union")
    if value.decision == "apply":
        expected_statuses = tuple("cancelled" if state.status in _UNRESOLVED_STAGE_STATUSES else state.status for state in copied_states)
        expected_cancelled_stage_ids = tuple(state.stage_run_id for state in copied_states if state.status in _UNRESOLVED_STAGE_STATUSES)
        if (
            value.projection.post_stage_statuses != expected_statuses
            or value.projection.cancelled_stage_ids != expected_cancelled_stage_ids
            or value.projection.cancelled_attempt_ids != value.locked_attempt_ids
        ):
            raise OutboxValidation("Terminalization apply projection is not an exact pre/post fixed point")
    elif (
        value.projection.post_stage_statuses != tuple(state.status for state in copied_states)
        or value.projection.cancelled_stage_ids
        or value.projection.cancelled_attempt_ids
        or value.live_message_ids
        or value.locked_attempt_ids
    ):
        raise OutboxValidation("Terminalization replay projection is not an immutable fixed point")
    transaction_at = _aware_datetime(value.transaction_at, field_name="terminalization transaction_at")
    observed_at = _aware_datetime(value.observed_at, field_name="terminalization observed_at")
    if transaction_at > observed_at:
        raise OutboxValidation("Terminalization transaction clock is later than its wall clock")
    object.__setattr__(value, "stage_states", copied_states)
    if locked:
        if type(value) is not LockedWorkflowTerminalizationGraph:
            raise OutboxValidation("Locked terminalization DTO has an invalid runtime type")
        child = value.outbox_cancellation_reservation
        if value.decision == "apply" and type(child) is not OutboxCancellationReservation:
            raise OutboxValidation("Applied terminalization lacks exact outbox cancellation authority")
        if value.decision == "replay" and child is not None:
            raise OutboxValidation("Terminalization replay cannot carry mutation authority")
    elif type(value) is not WorkflowTerminalizationReservation or value._session is None or value._transaction is None:
        raise OutboxValidation("Workflow terminalization reservation has no transaction authority")


def _validate_stage_recovery_dto(
    value: StageRecoveryReservation | LockedStageRecoveryGraph,
    *,
    locked: bool,
) -> None:
    _exact_model(value.workflow, WorkflowRun, field_name="recovery workflow")
    if type(value.stages) is not tuple or not value.stages:
        raise OutboxValidation("Recovery stages must be an exact non-empty tuple")
    if type(value.stage_states) is not tuple or len(value.stage_states) != len(value.stages):
        raise OutboxValidation("Recovery stage snapshots are incomplete")
    for stage in value.stages:
        _exact_model(stage, StageRun, field_name="recovery stage")
    copied_states = tuple(_copy_stage_ready_state(state) for state in value.stage_states)
    if tuple(state.stage_run_id for state in copied_states) != tuple(
        _persisted_uuid(stage.id, field_name="recovery stage id") for stage in value.stages
    ):
        raise OutboxValidation("Recovery stage snapshots are out of plan order")
    _uuid(value.source_stage_id, field_name="recovery source_stage_id")
    if type(value.source_stage_index) is not int or not 0 <= value.source_stage_index < len(value.stages):
        raise OutboxValidation("Recovery source index is outside the stage plan")
    if (
        value.source_stage_id != copied_states[value.source_stage_index].stage_run_id
        or value.causal_source != copied_states[value.source_stage_index]
    ):
        raise OutboxValidation("Recovery source projection is misaligned")
    if type(value.decision) is not str or value.decision not in {"retry", "dead_lettered"}:
        raise OutboxValidation("Recovery decision is outside its closed registry")
    if type(value.settlement) is not _StageFailureSettlementProjection or value.settlement.decision != value.decision:
        raise OutboxValidation("Recovery decision and settlement disagree")
    if len(value.settlement.post_stage_statuses) != len(value.stages):
        raise OutboxValidation("Recovery settlement does not cover the complete stage plan")
    if value.decision == "retry":
        _bounded_int(value.retry_delay_seconds, field_name="recovery retry delay", minimum=1, maximum=86_400)
        projection = _copy_stage_failure_retry_projection(value.retry_projection)
        _uuid(value.retry_message_id, field_name="recovery retry message id")
        object.__setattr__(value, "retry_projection", projection)
    elif value.retry_delay_seconds is not None or value.retry_projection is not None or value.retry_message_id is not None:
        raise OutboxValidation("Exhausted recovery cannot carry retry projection authority")
    _validate_locked_model_union(
        model_values=value.locked_messages,
        id_values=value.locked_message_ids,
        model=OutboxMessage,
        field_name="recovery messages",
        allow_empty=False,
    )
    _validate_locked_model_union(
        model_values=value.locked_deliveries,
        id_values=value.locked_delivery_ids,
        model=OutboxDeliveryAttempt,
        field_name="recovery deliveries",
        allow_empty=False,
    )
    _validate_locked_model_union(
        model_values=value.locked_attempts,
        id_values=value.locked_attempt_ids,
        model=StageAttempt,
        field_name="recovery attempts",
        allow_empty=False,
    )
    _uuid(value.source_attempt_id, field_name="recovery source_attempt_id")
    if value.source_attempt_id not in value.locked_attempt_ids:
        raise OutboxValidation("Recovery source attempt is absent from the locked union")
    if (
        value.source_authority.workflow_run_id != _persisted_uuid(value.workflow.id, field_name="recovery workflow id")
        or value.source_authority.stage_run_id != value.source_stage_id
        or value.source_authority.stage_attempt_id != value.source_attempt_id
        or value.source_authority.message_id not in value.locked_message_ids
        or value.source_authority.delivery_attempt_id not in value.locked_delivery_ids
        or value.source_authority.stage_state_version != copied_states[value.source_stage_index].state_version
        or value.source_authority.attempt_number != copied_states[value.source_stage_index].attempt_count
    ):
        raise OutboxValidation("Recovery source authority is not aligned with its complete graph")
    if value.retry_message_id == value.source_authority.message_id:
        raise OutboxValidation("Recovery retry message cannot reuse delivered source identity")
    if type(value.live_message_ids) is not tuple:
        raise OutboxValidation("Recovery live_message_ids must be an exact tuple")
    for item in value.live_message_ids:
        _uuid(item, field_name="recovery live message id")
    if value.live_message_ids != tuple(sorted(value.live_message_ids, key=lambda item: item.int)):
        raise OutboxValidation("Recovery live messages lost canonical UUID order")
    if not set(value.live_message_ids).issubset(value.locked_message_ids):
        raise OutboxValidation("Recovery live messages are outside the locked union")
    transaction_at = _aware_datetime(value.transaction_at, field_name="recovery transaction_at")
    observed_at = _aware_datetime(value.observed_at, field_name="recovery observed_at")
    if transaction_at > observed_at:
        raise OutboxValidation("Recovery transaction clock is later than its wall clock")
    object.__setattr__(value, "stage_states", copied_states)
    if locked:
        if type(value) is not LockedStageRecoveryGraph:
            raise OutboxValidation("Locked recovery DTO has an invalid runtime type")
        if value.decision == "retry":
            if (
                type(value.retry_intent) is not StageReadyIntent
                or value.next_attempt_at is None
                or type(value.stage_ready_reservation) is not StageReadyReservation
                or value.outbox_cancellation_reservation is not None
            ):
                raise OutboxValidation("Consumed retry recovery lacks its exact append authority")
            expected_intent = _stage_recovery_retry_intent(
                value.workflow,
                value.retry_projection,
                next_attempt_at=value.next_attempt_at,
            )
            expected_stage_ids = tuple(_persisted_uuid(stage.id, field_name="recovery locked stage id") for stage in value.stages)
            child = value.stage_ready_reservation
            if (
                value.next_attempt_at != value.observed_at + timedelta(seconds=value.retry_delay_seconds)
                or value.retry_intent != expected_intent
                or child.intents != (expected_intent,)
                or child.message_ids != (value.retry_message_id,)
                or child.existing_messages != (None,)
                or child.active_deliveries != (None,)
                or child.locked_stage_ids != expected_stage_ids
                or child.locked_stage_states != copied_states
            ):
                raise OutboxValidation("Consumed retry recovery child is not an exact fixed point")
        else:
            if value.retry_intent is not None or value.next_attempt_at is not None or value.stage_ready_reservation is not None:
                raise OutboxValidation("Exhausted recovery retained retry authority")
            required = value.stages[value.source_stage_index].required
            if required != (type(value.outbox_cancellation_reservation) is OutboxCancellationReservation):
                raise OutboxValidation("Exhausted recovery cancellation authority disagrees with requiredness")
    elif type(value) is not StageRecoveryReservation or value._session is None or value._transaction is None:
        raise OutboxValidation("Stage recovery reservation has no transaction authority")


def _stage_failure_decision(
    source: StageRun,
    evidence: StageFailureEvidence,
) -> Literal["retry", "failed", "dead_lettered"]:
    _exact_model(source, StageRun, field_name="failure source")
    safe = _copy_stage_failure_evidence(evidence)
    try:
        attempt_count = _bounded_int(
            source.attempt_count,
            field_name="failure source attempt_count",
            minimum=1,
            maximum=20,
        )
        max_attempts = _bounded_int(
            source.max_attempts,
            field_name="failure source max_attempts",
            minimum=1,
            maximum=20,
        )
    except OutboxValidation as exc:
        raise OutboxStoredContractError("Failure source has invalid attempt authority") from exc
    if attempt_count > max_attempts:
        raise OutboxStoredContractError("Failure source exceeded its persisted retry budget")
    if safe.retryable and attempt_count < max_attempts:
        return "retry"
    return "dead_lettered" if safe.retryable else "failed"


def _stage_failure_retry_delay(workflow: WorkflowRun, source: StageRun) -> int:
    normalized = _normalized_workflow_plan(workflow)
    definition = next(
        (candidate for candidate in normalized.stages if candidate.stage_key == source.stage_key),
        None,
    )
    if definition is None:
        raise OutboxStoredContractError("Failure retry source is absent from canonical workflow authority")
    try:
        return deterministic_retry_backoff_seconds(
            source.attempt_count,
            seed=str(_persisted_uuid(source.id, field_name="failure retry source id")),
            policy=definition.retry_policy,
        )
    except WorkflowContractError as exc:
        raise OutboxStoredContractError("Failure retry delay cannot be derived from workflow authority") from exc


def _stage_failure_retry_projection(
    workflow: WorkflowRun,
    causal_source: _StageReadyState,
) -> _StageFailureRetryProjection:
    normalized = normalize_outbox_envelope(
        {
            "topic": OUTBOX_TOPIC_WORKFLOW_STAGE_READY,
            "schema_version": OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1,
            "payload": {
                "workflow_run_id": str(_persisted_uuid(workflow.id, field_name="workflow.id")),
                "stage_run_id": str(causal_source.stage_run_id),
                "stage_key": causal_source.stage_key,
                "target_attempt_number": causal_source.attempt_count + 1,
                "input_checksum": causal_source.input_checksum,
                "plan_checksum": workflow.plan_checksum,
            },
        }
    )
    return _StageFailureRetryProjection(
        pre_source=causal_source,
        target_attempt_number=causal_source.attempt_count + 1,
        plan_checksum=workflow.plan_checksum,
        envelope_canonical=normalized.canonical,
        envelope_checksum=normalized.checksum,
        logical_key=normalized.logical_key,
    )


def _assert_stage_failure_retry_projection_fixed_point(
    value: _StageFailureRetryProjection,
) -> None:
    try:
        normalized = normalize_outbox_envelope(
            {
                "topic": OUTBOX_TOPIC_WORKFLOW_STAGE_READY,
                "schema_version": OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1,
                "payload": {
                    "workflow_run_id": str(value.pre_source.workflow_run_id),
                    "stage_run_id": str(value.pre_source.stage_run_id),
                    "stage_key": value.pre_source.stage_key,
                    "target_attempt_number": value.target_attempt_number,
                    "input_checksum": value.pre_source.input_checksum,
                    "plan_checksum": value.plan_checksum,
                },
            }
        )
    except (AttributeError, OutboxContractError, OutboxValidation) as exc:
        raise OutboxValidation("Stage failure retry projection is not canonical") from exc
    if (
        value.envelope_canonical != normalized.canonical
        or value.envelope_checksum != normalized.checksum
        or value.logical_key != normalized.logical_key
    ):
        raise OutboxValidation("Stage failure retry projection is not a fixed point")


def _stage_failure_settlement_projection(
    workflow: WorkflowRun,
    stages: tuple[StageRun, ...],
    *,
    source_index: int,
    decision: Literal["retry", "failed", "dead_lettered"],
    cancelled_attempt_ids: tuple[uuid.UUID, ...],
) -> _StageFailureSettlementProjection:
    if type(source_index) is not int or not 0 <= source_index < len(stages):
        raise OutboxStoredContractError("Failure settlement source index is outside the plan")
    if type(cancelled_attempt_ids) is not tuple:
        raise OutboxValidation("cancelled_attempt_ids must be an exact tuple")
    source = stages[source_index]
    statuses = [stage.status for stage in stages]
    skipped: list[uuid.UUID] = []
    cancelled: list[uuid.UUID] = []
    if decision == "retry":
        statuses[source_index] = "retry_wait"
        return _StageFailureSettlementProjection(
            decision=decision,
            post_stage_statuses=tuple(statuses),
            skipped_stage_ids=(),
            cancelled_stage_ids=(),
            cancelled_attempt_ids=(),
            workflow_post_status="running",
            workflow_reason_code="",
            workflow_summary="",
        )

    statuses[source_index] = decision
    if source.required:
        for index, stage in enumerate(stages):
            if index != source_index and statuses[index] in _UNRESOLVED_STAGE_STATUSES:
                statuses[index] = "cancelled"
                cancelled.append(_persisted_uuid(stage.id, field_name="cancelled stage id"))
        workflow_status: Literal["failed", "dead_lettered"] = "dead_lettered" if decision == "dead_lettered" else "failed"
        reason_code = "workflow.required_stage_dead_lettered" if workflow_status == "dead_lettered" else "workflow.required_stage_failed"
        return _StageFailureSettlementProjection(
            decision=decision,
            post_stage_statuses=tuple(statuses),
            skipped_stage_ids=(),
            cancelled_stage_ids=tuple(cancelled),
            cancelled_attempt_ids=tuple(sorted(cancelled_attempt_ids, key=lambda value: value.int)),
            workflow_post_status=workflow_status,
            workflow_reason_code=reason_code,
            workflow_summary=f"Required stage failure: {source.stage_key}",
        )

    by_key = {stage.stage_key: index for index, stage in enumerate(stages)}
    changed = True
    while changed:
        changed = False
        for index, stage in enumerate(stages):
            if statuses[index] != "pending":
                continue
            dependencies = [by_key.get(key) for key in stage.depends_on]
            if any(item is None for item in dependencies):
                raise OutboxStoredContractError("Failure settlement references a missing dependency")
            if any(statuses[item] in _DEPENDENCY_FAILURE_STATUSES for item in dependencies if item is not None):
                statuses[index] = "skipped"
                skipped.append(_persisted_uuid(stage.id, field_name="skipped stage id"))
                changed = True
    for index, stage in enumerate(stages):
        if statuses[index] != "pending":
            continue
        dependency_indexes = [by_key[key] for key in stage.depends_on]
        if all(statuses[item] in _DEPENDENCY_SUCCESS_STATUSES for item in dependency_indexes):
            raise OutboxStoredContractError("Pending all-success failure target requires missing stage-ready authority")
    all_terminal = all(status in _TERMINAL_STAGE_STATUSES for status in statuses)
    if all_terminal:
        unavailable = sorted(
            stage.stage_key
            for stage, status in zip(stages, statuses, strict=True)
            if status in {"degraded", "skipped", "failed", "cancelled", "dead_lettered"}
        )
        return _StageFailureSettlementProjection(
            decision=decision,
            post_stage_statuses=tuple(statuses),
            skipped_stage_ids=tuple(skipped),
            cancelled_stage_ids=(),
            cancelled_attempt_ids=(),
            workflow_post_status="degraded",
            workflow_reason_code="workflow.degraded_stages",
            workflow_summary=f"Workflow completed with degraded or unavailable stages: {', '.join(unavailable)}",
        )
    return _StageFailureSettlementProjection(
        decision=decision,
        post_stage_statuses=tuple(statuses),
        skipped_stage_ids=tuple(skipped),
        cancelled_stage_ids=(),
        cancelled_attempt_ids=(),
        workflow_post_status="running",
        workflow_reason_code="",
        workflow_summary="",
    )


def _stage_failure_retry_intent(
    workflow: WorkflowRun,
    projection: _StageFailureRetryProjection,
    *,
    evidence: StageFailureEvidence,
    next_attempt_at: datetime,
) -> StageReadyIntent:
    safe = _copy_stage_failure_evidence(evidence)
    pre = _copy_stage_ready_state(projection.pre_source)
    post = replace(
        pre,
        status="retry_wait",
        state_version=pre.state_version + 1,
        next_attempt_at=_aware_datetime(next_attempt_at, field_name="failure retry next_attempt_at"),
        lease_owner="",
        lease_token=None,
        leased_at=None,
        lease_expires_at=None,
        heartbeat_at=None,
        last_error_code=safe.code,
        last_error_summary=safe.summary,
        last_error_retryable=True,
        output_checksum="",
        completed_at=None,
    )
    intent = _make_stage_ready_intent(
        workflow=workflow,
        emission_kind="retry_scheduled",
        projection_mode="transition",
        allow_create=True,
        pre_target=pre,
        post_target=post,
        causal_pre_stage=pre,
        target_attempt_number=projection.target_attempt_number,
    )
    if (
        intent.envelope_canonical != projection.envelope_canonical
        or intent.envelope_checksum != projection.envelope_checksum
        or intent.logical_key != projection.logical_key
    ):
        raise OutboxStoredContractError("Failure retry intent changed its clock-free logical identity")
    return intent


def _stage_failure_stage_ready_reservation(
    db: AsyncSession,
    transaction: object,
    *,
    stages: tuple[StageRun, ...],
    stage_states: tuple[_StageReadyState, ...],
    intent: StageReadyIntent,
    message_id: uuid.UUID,
) -> StageReadyReservation:
    try:
        return StageReadyReservation(
            intents=(intent,),
            message_ids=(_uuid(message_id, field_name="failure retry message id"),),
            existing_messages=(None,),
            active_deliveries=(None,),
            locked_stage_ids=tuple(_persisted_uuid(stage.id, field_name="failure locked stage id") for stage in stages),
            locked_stage_states=stage_states,
            _session=db,
            _transaction=transaction,
        )
    except OutboxValidation as exc:
        raise OutboxStoredContractError("Failure retry append capability is not an exact fixed point") from exc


def _copy_stage_failure_retry_projection(
    value: object,
) -> _StageFailureRetryProjection:
    if type(value) is not _StageFailureRetryProjection:
        raise OutboxValidation("Failure retry projection must be exact detached authority")
    try:
        return _StageFailureRetryProjection(
            pre_source=value.pre_source,
            target_attempt_number=value.target_attempt_number,
            plan_checksum=value.plan_checksum,
            envelope_canonical=value.envelope_canonical,
            envelope_checksum=value.envelope_checksum,
            logical_key=value.logical_key,
        )
    except (AttributeError, OutboxValidation) as exc:
        raise OutboxValidation("Failure retry projection is not a fixed point") from exc


def _validate_stage_failure_dto(
    value: StageFailureReservation | LockedStageFailureGraph,
    *,
    locked: bool,
) -> None:
    _exact_model(value.workflow, WorkflowRun, field_name="failure workflow")
    if type(value.stages) is not tuple or not value.stages:
        raise OutboxValidation("Failure stages must be an exact non-empty tuple")
    if type(value.stage_states) is not tuple or len(value.stage_states) != len(value.stages):
        raise OutboxValidation("Failure stage snapshots are incomplete")
    for stage in value.stages:
        _exact_model(stage, StageRun, field_name="failure stage")
    copied_states = tuple(_copy_stage_ready_state(state) for state in value.stage_states)
    if tuple(state.stage_run_id for state in copied_states) != tuple(
        _persisted_uuid(stage.id, field_name="failure stage id") for stage in value.stages
    ):
        raise OutboxValidation("Failure stage snapshots are out of plan order")
    _uuid(value.source_stage_id, field_name="failure source_stage_id")
    if type(value.source_stage_index) is not int or not 0 <= value.source_stage_index < len(value.stages):
        raise OutboxValidation("Failure source index is outside the stage plan")
    if (
        value.source_stage_id != copied_states[value.source_stage_index].stage_run_id
        or value.causal_source != copied_states[value.source_stage_index]
    ):
        raise OutboxValidation("Failure source projection is misaligned")
    if type(value.causal_source) is not _StageReadyState:
        raise OutboxValidation("Failure causal source must be exact detached authority")
    if type(value.settlement) is not _StageFailureSettlementProjection:
        raise OutboxValidation("Failure settlement must be exact detached authority")
    if (
        type(value.decision) is not str
        or value.decision not in {"retry", "failed", "dead_lettered"}
        or value.settlement.decision != value.decision
    ):
        raise OutboxValidation("Failure decision and settlement disagree")
    if len(value.settlement.post_stage_statuses) != len(value.stages):
        raise OutboxValidation("Failure settlement does not cover every stage")
    retry = value.decision == "retry"
    if retry:
        _bounded_int(
            value.retry_delay_seconds,
            field_name="failure retry delay",
            minimum=1,
            maximum=86_400,
        )
        projection = _copy_stage_failure_retry_projection(value.retry_projection)
        _uuid(value.retry_message_id, field_name="failure retry message id")
        object.__setattr__(value, "retry_projection", projection)
    elif value.retry_delay_seconds is not None or value.retry_projection is not None or value.retry_message_id is not None:
        raise OutboxValidation("Terminal failure cannot carry retry projection authority")
    for model_values, id_values, model, field_name in (
        (value.locked_messages, value.locked_message_ids, OutboxMessage, "failure messages"),
        (value.locked_deliveries, value.locked_delivery_ids, OutboxDeliveryAttempt, "failure deliveries"),
        (value.locked_attempts, value.locked_attempt_ids, StageAttempt, "failure attempts"),
    ):
        if type(model_values) is not tuple or type(id_values) is not tuple or not model_values:
            raise OutboxValidation(f"{field_name} must be exact non-empty tuples")
        for item in model_values:
            _exact_model(item, model, field_name=field_name)
        for item in id_values:
            _uuid(item, field_name=field_name)
        if id_values != tuple(sorted(id_values, key=lambda item: item.int)) or len(set(id_values)) != len(id_values):
            raise OutboxValidation(f"{field_name} lost canonical UUID order")
        if tuple(_persisted_uuid(item.id, field_name=field_name) for item in model_values) != id_values:
            raise OutboxValidation(f"{field_name} identities are misaligned")
    _uuid(value.source_attempt_id, field_name="failure source_attempt_id")
    if value.source_attempt_id not in value.locked_attempt_ids:
        raise OutboxValidation("Failure source attempt is absent from the locked attempt union")
    transaction_at = _aware_datetime(value.transaction_at, field_name="failure transaction_at")
    observed_at = _aware_datetime(value.observed_at, field_name="failure observed_at")
    if transaction_at > observed_at:
        raise OutboxValidation("Failure transaction clock is later than its wall clock")
    object.__setattr__(value, "stage_states", copied_states)
    if locked:
        if type(value) is not LockedStageFailureGraph:
            raise OutboxValidation("Locked failure DTO has an invalid runtime type")
        if retry:
            if type(value.retry_intent) is not StageReadyIntent or value.next_attempt_at is None:
                raise OutboxValidation("Consumed retry failure lacks its finalized intent")
            if type(value.stage_ready_reservation) is not StageReadyReservation:
                raise OutboxValidation("Consumed retry failure lacks append authority")
            if value.outbox_cancellation_reservation is not None:
                raise OutboxValidation("Retry failure cannot carry cancellation authority")
        else:
            if value.retry_intent is not None or value.next_attempt_at is not None or value.stage_ready_reservation is not None:
                raise OutboxValidation("Terminal failure retained retry authority")
            required = value.stages[value.source_stage_index].required
            if required != (type(value.outbox_cancellation_reservation) is OutboxCancellationReservation):
                raise OutboxValidation("Terminal failure cancellation authority disagrees with requiredness")
    elif type(value) is not StageFailureReservation or value._session is None or value._transaction is None:
        raise OutboxValidation("Stage failure reservation has no transaction authority")


def _assert_stage_failure_graph_from_reservation(
    db: AsyncSession,
    reservation: StageFailureReservation,
    *,
    observed_at: datetime,
) -> None:
    required_terminal = reservation.decision != "retry" and reservation.stages[reservation.source_stage_index].required
    attempts_by_stage = {
        _persisted_uuid(attempt.stage_run_id, field_name="failure attempt stage id"): attempt for attempt in reservation.locked_attempts
    }
    projected_running_stage_ids = (
        tuple(_persisted_uuid(stage.id, field_name="failure running stage id") for stage in reservation.stages if stage.status == "running")
        if required_terminal
        else ()
    )
    receipt_message_ids: list[uuid.UUID] = []
    receipt_delivery_ids: list[uuid.UUID] = []
    if required_terminal:
        deliveries_by_id = {
            _persisted_uuid(delivery.id, field_name="failure locked delivery id"): delivery for delivery in reservation.locked_deliveries
        }
        for stage_id in projected_running_stage_ids:
            attempt = attempts_by_stage.get(stage_id)
            if attempt is None or attempt.outbox_delivery_attempt_id is None:
                raise OutboxStoredContractError("Consumed running stage lost its receipt attempt")
            delivery_id = _persisted_uuid(
                attempt.outbox_delivery_attempt_id,
                field_name="failure running receipt delivery id",
            )
            delivery = deliveries_by_id.get(delivery_id)
            if delivery is None:
                raise OutboxStoredContractError("Consumed running receipt is absent from the locked delivery union")
            receipt_delivery_ids.append(delivery_id)
            receipt_message_ids.append(_persisted_uuid(delivery.message_id, field_name="failure running receipt message id"))
    else:
        receipt_message_ids.append(reservation.authority.message_id)
        receipt_delivery_ids.append(reservation.authority.delivery_attempt_id)
    live_message_ids = tuple(
        _persisted_uuid(message.id, field_name="failure live message id")
        for message in reservation.locked_messages
        if message.status in {*_CLAIMABLE_MESSAGE_STATUSES, *_ACTIVE_DELIVERY_STATUSES}
    )
    _assert_stage_failure_graph(
        db,
        authority=reservation.authority,
        evidence=reservation.evidence,
        workflow=reservation.workflow,
        stages=reservation.stages,
        stage_states=reservation.stage_states,
        source_index=reservation.source_stage_index,
        causal_source=reservation.causal_source,
        decision=reservation.decision,
        retry_delay_seconds=reservation.retry_delay_seconds,
        retry_projection=reservation.retry_projection,
        retry_message_id=reservation.retry_message_id,
        settlement=reservation.settlement,
        locked_messages=reservation.locked_messages,
        locked_message_ids=reservation.locked_message_ids,
        locked_deliveries=reservation.locked_deliveries,
        locked_delivery_ids=reservation.locked_delivery_ids,
        locked_attempts=reservation.locked_attempts,
        locked_attempt_ids=reservation.locked_attempt_ids,
        source_attempt_id=reservation.source_attempt_id,
        projected_running_stage_ids=projected_running_stage_ids,
        projected_receipt_message_ids=tuple(receipt_message_ids),
        projected_receipt_delivery_ids=tuple(receipt_delivery_ids),
        live_message_ids=live_message_ids,
        transaction_at=reservation.transaction_at,
        observed_at=observed_at,
    )


def _assert_stage_failure_graph(
    db: AsyncSession,
    *,
    authority: ExecutableStageAuthority,
    evidence: StageFailureEvidence,
    workflow: WorkflowRun,
    stages: tuple[StageRun, ...],
    stage_states: tuple[_StageReadyState, ...],
    source_index: int,
    causal_source: _StageReadyState,
    decision: str,
    retry_delay_seconds: int | None,
    retry_projection: _StageFailureRetryProjection | None,
    retry_message_id: uuid.UUID | None,
    settlement: _StageFailureSettlementProjection,
    locked_messages: tuple[OutboxMessage, ...],
    locked_message_ids: tuple[uuid.UUID, ...],
    locked_deliveries: tuple[OutboxDeliveryAttempt, ...],
    locked_delivery_ids: tuple[uuid.UUID, ...],
    locked_attempts: tuple[StageAttempt, ...],
    locked_attempt_ids: tuple[uuid.UUID, ...],
    source_attempt_id: uuid.UUID,
    projected_running_stage_ids: tuple[uuid.UUID, ...],
    projected_receipt_message_ids: tuple[uuid.UUID, ...],
    projected_receipt_delivery_ids: tuple[uuid.UUID, ...],
    live_message_ids: tuple[uuid.UUID, ...],
    transaction_at: datetime,
    observed_at: datetime,
) -> None:
    _require_stage_execution_authorities(
        db,
        (workflow, *stages, *locked_messages, *locked_deliveries, *locked_attempts),
    )
    complete = _validate_complete_locked_stages(workflow, stages)
    now = _aware_datetime(observed_at, field_name="failure observed_at")
    tx_at = _aware_datetime(transaction_at, field_name="failure transaction_at")
    if tx_at > now:
        raise OutboxStoredContractError("Failure transaction clock is later than its wall clock")
    for stage in complete:
        _assert_completion_stage_chronology(stage, observed_at=now)
    current_states = tuple(_stage_ready_state(stage) for stage in complete)
    if current_states != stage_states:
        raise OutboxConflict("Failure stage authority changed after graph reservation")
    if type(source_index) is not int or not 0 <= source_index < len(complete):
        raise OutboxStoredContractError("Failure source index is outside the locked plan")
    source = complete[source_index]
    if (
        _persisted_uuid(source.id, field_name="failure source stage id") != authority.stage_run_id
        or causal_source != current_states[source_index]
    ):
        raise OutboxLeaseLost("Failure source no longer matches worker authority")
    safe_evidence = _copy_stage_failure_evidence(evidence)
    expected_decision = _stage_failure_decision(source, safe_evidence)
    if decision != expected_decision:
        raise OutboxLeaseLost("Failure decision changed after graph reservation")
    if locked_message_ids != tuple(sorted(locked_message_ids, key=lambda value: value.int)):
        raise OutboxConflict("Failure messages lost canonical UUID lock order")
    if locked_delivery_ids != tuple(sorted(locked_delivery_ids, key=lambda value: value.int)):
        raise OutboxConflict("Failure deliveries lost canonical UUID lock order")
    if locked_attempt_ids != tuple(sorted(locked_attempt_ids, key=lambda value: value.int)):
        raise OutboxConflict("Failure attempts lost canonical UUID lock order")
    messages_by_id = {_persisted_uuid(message.id, field_name="failure locked message id"): message for message in locked_messages}
    deliveries_by_id = {_persisted_uuid(delivery.id, field_name="failure locked delivery id"): delivery for delivery in locked_deliveries}
    attempts_by_id = {_persisted_uuid(attempt.id, field_name="failure locked attempt id"): attempt for attempt in locked_attempts}
    if (
        tuple(messages_by_id) != locked_message_ids
        or tuple(deliveries_by_id) != locked_delivery_ids
        or tuple(attempts_by_id) != locked_attempt_ids
    ):
        raise OutboxConflict("Failure union authority no longer matches its locked id seal")
    source_message = messages_by_id.get(authority.message_id)
    source_delivery = deliveries_by_id.get(authority.delivery_attempt_id)
    source_attempt = attempts_by_id.get(source_attempt_id)
    if source_message is None or source_delivery is None or source_attempt is None:
        raise OutboxLeaseLost("Failure source receipt is absent from the locked union")
    _assert_stage_execution_receipt(
        db,
        authority=authority,
        workflow=workflow,
        stage=source,
        message=source_message,
        delivery=source_delivery,
        attempt=source_attempt,
        observed_at=now,
    )

    required_terminal = source.required and expected_decision != "retry"
    if expected_decision == "retry":
        expected_delay = _stage_failure_retry_delay(workflow, source)
        expected_projection = _stage_failure_retry_projection(workflow, causal_source)
        if retry_delay_seconds != expected_delay or retry_projection != expected_projection or retry_message_id is None:
            raise OutboxLeaseLost("Failure retry projection changed after reservation")
        expected_m = {authority.message_id}
        expected_d = {authority.delivery_attempt_id}
        expected_a = {authority.stage_attempt_id}
    elif required_terminal:
        if retry_delay_seconds is not None or retry_projection is not None or retry_message_id is not None:
            raise OutboxStoredContractError("Required terminal failure retained retry authority")
        expected_running_ids = tuple(
            _persisted_uuid(stage.id, field_name="failure running stage id") for stage in complete if stage.status == "running"
        )
        if projected_running_stage_ids != expected_running_ids:
            raise OutboxStoredContractError("Running failure stage projection changed after lock")
        if not (
            len(projected_running_stage_ids)
            == len(projected_receipt_message_ids)
            == len(projected_receipt_delivery_ids)
            == len(locked_attempts)
        ):
            raise OutboxStoredContractError("Required terminal receipt projections are not bijective")
        attempts_by_stage = {
            _persisted_uuid(attempt.stage_run_id, field_name="failure attempt stage id"): attempt for attempt in locked_attempts
        }
        if set(attempts_by_stage) != set(projected_running_stage_ids):
            raise OutboxStoredContractError("Required terminal attempts do not cover every running stage")
        for stage_id, message_id, delivery_id in zip(
            projected_running_stage_ids,
            projected_receipt_message_ids,
            projected_receipt_delivery_ids,
            strict=True,
        ):
            stage = next(item for item in complete if item.id == stage_id)
            attempt = attempts_by_stage[stage_id]
            message = messages_by_id.get(message_id)
            delivery = deliveries_by_id.get(delivery_id)
            if (
                message is None
                or delivery is None
                or attempt.outbox_delivery_attempt_id != delivery.id
                or delivery.message_id != message.id
            ):
                raise OutboxStoredContractError("Running failure receipt projection changed under lock")
            peer_authority = _executable_stage_authority(
                workflow=workflow,
                stage=stage,
                message=message,
                delivery=delivery,
                attempt=attempt,
            )
            _assert_stage_execution_receipt(
                db,
                authority=peer_authority,
                workflow=workflow,
                stage=stage,
                message=message,
                delivery=delivery,
                attempt=attempt,
                observed_at=now,
            )
        expected_live = tuple(
            sorted(
                (
                    _persisted_uuid(message.id, field_name="failure live message id")
                    for message in locked_messages
                    if message.status in {*_CLAIMABLE_MESSAGE_STATUSES, *_ACTIVE_DELIVERY_STATUSES}
                ),
                key=lambda value: value.int,
            )
        )
        if live_message_ids != expected_live:
            raise OutboxStoredContractError("Required terminal live message projection changed under lock")
        active_ids: set[uuid.UUID] = set()
        by_stage_id = {_persisted_uuid(stage.id, field_name="failure stage id"): stage for stage in complete}
        for message_id in live_message_ids:
            message = messages_by_id[message_id]
            stage = by_stage_id.get(_persisted_uuid(message.stage_run_id, field_name="live message stage id"))
            if stage is None or stage.status not in _CLAIMABLE_STAGE_STATUSES:
                raise OutboxStoredContractError("Live workflow message is outside a runnable unresolved stage")
            _assert_live_failure_message(workflow, stage, message, observed_at=now)
            if message.status in _ACTIVE_DELIVERY_STATUSES:
                delivery_id = _persisted_uuid(message.active_delivery_attempt_id, field_name="live active delivery id")
                delivery = deliveries_by_id.get(delivery_id)
                if delivery is None:
                    raise OutboxStoredContractError("Live active message lacks its locked delivery")
                _assert_reserved_active_delivery(message, delivery)
                active_ids.add(delivery_id)
        _assert_cancellation_suffix_predates_transaction(
            tuple(messages_by_id[message_id] for message_id in live_message_ids),
            tuple(deliveries_by_id[delivery_id] for delivery_id in sorted(active_ids, key=lambda value: value.int)),
            transaction_at=tx_at,
        )
        expected_m = {*projected_receipt_message_ids, *live_message_ids}
        expected_d = {*projected_receipt_delivery_ids, *active_ids}
        expected_a = set(attempts_by_id)
    else:
        if retry_delay_seconds is not None or retry_projection is not None or retry_message_id is not None:
            raise OutboxStoredContractError("Optional terminal failure retained retry authority")
        expected_m = {authority.message_id}
        expected_d = {authority.delivery_attempt_id}
        expected_a = {authority.stage_attempt_id}
    if set(locked_message_ids) != expected_m or set(locked_delivery_ids) != expected_d or set(locked_attempt_ids) != expected_a:
        raise OutboxStoredContractError("Failure graph contains unexpected M/D/A authority")
    cancelled_attempt_ids = (
        tuple(attempt.id for attempt in locked_attempts if attempt.id != authority.stage_attempt_id) if required_terminal else ()
    )
    rebuilt_settlement = _stage_failure_settlement_projection(
        workflow,
        complete,
        source_index=source_index,
        decision=expected_decision,
        cancelled_attempt_ids=tuple(_persisted_uuid(value, field_name="cancelled attempt id") for value in cancelled_attempt_ids),
    )
    if settlement != rebuilt_settlement:
        raise OutboxConflict("Failure settlement projection changed after reservation")


def _assert_live_failure_message(
    workflow: WorkflowRun,
    stage: StageRun,
    message: OutboxMessage,
    *,
    observed_at: datetime,
) -> None:
    _stored_envelope(message)
    if (
        message.workflow_run_id != workflow.id
        or message.stage_run_id != stage.id
        or message.aggregate_type != "workflow_stage"
        or message.aggregate_id != stage.id
        or message.aggregate_version != stage.state_version
        or message.stage_key != stage.stage_key
        or message.target_attempt_number != stage.attempt_count + 1
        or message.input_checksum != stage.input_checksum
        or message.plan_checksum != workflow.plan_checksum
        or message.correlation_id != workflow.correlation_id
        or message.status not in {*_CLAIMABLE_MESSAGE_STATUSES, *_ACTIVE_DELIVERY_STATUSES}
        or message.max_attempts != OUTBOX_V1_MAX_ATTEMPTS
    ):
        raise OutboxStoredContractError("Live workflow message contradicts its runnable stage authority")
    for value, field_name in (
        (message.created_at, "live message created_at"),
        (message.updated_at, "live message updated_at"),
    ):
        if _aware_datetime(value, field_name=field_name) > observed_at:
            raise OutboxStoredContractError("Live workflow message contains future authority")
    if message.status in _CLAIMABLE_MESSAGE_STATUSES:
        if (
            message.available_at is None
            or message.active_delivery_attempt_id is not None
            or message.lease_owner != ""
            or message.lease_token is not None
            or message.leased_at is not None
            or message.heartbeat_at is not None
            or message.lease_expires_at is not None
            or message.receipt_deadline_at is not None
        ):
            raise OutboxStoredContractError("Idle workflow message has contradictory delivery authority")


def _stage_failure_cancellation_reservation(
    db: AsyncSession,
    transaction: object,
    *,
    reservation: StageFailureReservation,
) -> OutboxCancellationReservation:
    messages = tuple(
        message for message in reservation.locked_messages if message.status in {*_CLAIMABLE_MESSAGE_STATUSES, *_ACTIVE_DELIVERY_STATUSES}
    )
    active_ids = {
        _persisted_uuid(message.active_delivery_attempt_id, field_name="cancellation active delivery id")
        for message in messages
        if message.status in _ACTIVE_DELIVERY_STATUSES
    }
    deliveries = tuple(
        delivery
        for delivery in reservation.locked_deliveries
        if _persisted_uuid(delivery.id, field_name="cancellation delivery id") in active_ids
    )
    code = "workflow.required_stage_dead_lettered" if reservation.decision == "dead_lettered" else "workflow.required_stage_failed"
    return OutboxCancellationReservation(
        workflow_run_id=reservation.authority.workflow_run_id,
        messages=messages,
        message_ids=tuple(_persisted_uuid(message.id, field_name="cancellation message id") for message in messages),
        deliveries=deliveries,
        delivery_ids=tuple(_persisted_uuid(delivery.id, field_name="cancellation delivery id") for delivery in deliveries),
        error_code=code,
        error_class=_FAILURE_CANCELLATION_CLASS,
        error_summary=_FAILURE_CANCELLATION_REASON,
        cancelled_by=_FAILURE_CANCELLATION_ACTOR,
        cancelled_by_id=_FAILURE_CANCELLATION_ACTOR_ID,
        cancel_reason=_FAILURE_CANCELLATION_REASON,
        transaction_at=reservation.transaction_at,
        _session=db,
        _transaction=transaction,
    )


def _assert_outbox_cancellation_authority(
    reservation: OutboxCancellationReservation,
) -> None:
    deliveries_by_id = {
        _persisted_uuid(delivery.id, field_name="cancellation delivery id"): delivery for delivery in reservation.deliveries
    }
    active_ids: set[uuid.UUID] = set()
    for message in reservation.messages:
        if message.workflow_run_id != reservation.workflow_run_id or message.status not in {
            *_CLAIMABLE_MESSAGE_STATUSES,
            *_ACTIVE_DELIVERY_STATUSES,
        }:
            raise OutboxConflict("Cancellation message is no longer exact live authority")
        if message.status in _ACTIVE_DELIVERY_STATUSES:
            if message.active_delivery_attempt_id is None:
                raise OutboxStoredContractError("Cancellation message lacks active delivery authority")
            delivery_id = _persisted_uuid(message.active_delivery_attempt_id, field_name="cancellation active delivery id")
            delivery = deliveries_by_id.get(delivery_id)
            if delivery is None:
                raise OutboxStoredContractError("Cancellation active delivery is absent from the reservation")
            _assert_reserved_active_delivery(message, delivery)
            active_ids.add(delivery_id)
        elif message.active_delivery_attempt_id is not None:
            raise OutboxStoredContractError("Cancellation idle message retained active delivery authority")
    if active_ids != set(reservation.delivery_ids):
        raise OutboxStoredContractError("Cancellation delivery set is not the exact active suffix")


def _assert_cancellation_suffix_predates_transaction(
    messages: tuple[OutboxMessage, ...],
    deliveries: tuple[OutboxDeliveryAttempt, ...],
    *,
    transaction_at: datetime,
) -> None:
    """Prevent 0003 triggers from stamping terminal time before new suffix rows."""

    tx_at = _aware_datetime(transaction_at, field_name="cancellation transaction_at")
    try:
        for message in messages:
            for field_name in (
                "created_at",
                "updated_at",
                "redrive_requested_at",
                "leased_at",
                "heartbeat_at",
            ):
                value = getattr(message, field_name)
                if (
                    value is not None
                    and _aware_datetime(
                        value,
                        field_name=f"cancellation message {field_name}",
                    )
                    > tx_at
                ):
                    raise OutboxConflict("Live outbox authority is newer than this transaction; retry in a fresh transaction")
        for delivery in deliveries:
            for field_name in (
                "created_at",
                "updated_at",
                "leased_at",
                "heartbeat_at",
                "dispatched_at",
            ):
                value = getattr(delivery, field_name)
                if (
                    value is not None
                    and _aware_datetime(
                        value,
                        field_name=f"cancellation delivery {field_name}",
                    )
                    > tx_at
                ):
                    raise OutboxConflict("Live outbox authority is newer than this transaction; retry in a fresh transaction")
    except OutboxConflict:
        raise
    except (AttributeError, OutboxValidation) as exc:
        raise OutboxStoredContractError("Cancellation suffix contains invalid chronology") from exc


def _stage_failure_evidence_seal(value: StageFailureEvidence) -> tuple[object, ...]:
    return (
        id(value),
        value.code,
        value.error_class,
        value.summary,
        value.retryable,
    )


def _stage_failure_retry_projection_seal(
    value: _StageFailureRetryProjection,
) -> tuple[object, ...]:
    return (
        id(value),
        _stage_ready_state_seal(value.pre_source),
        value.target_attempt_number,
        value.plan_checksum,
        value.envelope_canonical,
        value.envelope_checksum,
        value.logical_key,
    )


def _stage_failure_settlement_seal(
    value: _StageFailureSettlementProjection,
) -> tuple[object, ...]:
    return (
        id(value),
        value.decision,
        id(value.post_stage_statuses),
        value.post_stage_statuses,
        id(value.skipped_stage_ids),
        value.skipped_stage_ids,
        id(value.cancelled_stage_ids),
        value.cancelled_stage_ids,
        id(value.cancelled_attempt_ids),
        value.cancelled_attempt_ids,
        value.workflow_post_status,
        value.workflow_reason_code,
        value.workflow_summary,
    )


def _stage_failure_reservation_seal(
    value: StageFailureReservation,
) -> tuple[object, ...]:
    return (
        id(value.authority),
        _stage_execution_authority_seal(value.authority),
        _stage_failure_evidence_seal(value.evidence),
        _stage_execution_model_seal(value.workflow),
        id(value.stages),
        tuple(_stage_execution_model_seal(stage) for stage in value.stages),
        id(value.stage_states),
        tuple(_stage_ready_state_seal(state) for state in value.stage_states),
        value.source_stage_id,
        value.source_stage_index,
        _stage_ready_state_seal(value.causal_source),
        value.decision,
        value.retry_delay_seconds,
        (_stage_failure_retry_projection_seal(value.retry_projection) if value.retry_projection is not None else None),
        value.retry_message_id,
        _stage_failure_settlement_seal(value.settlement),
        id(value.locked_messages),
        tuple(_stage_execution_model_seal(message) for message in value.locked_messages),
        id(value.locked_message_ids),
        value.locked_message_ids,
        id(value.locked_deliveries),
        tuple(_stage_execution_model_seal(delivery) for delivery in value.locked_deliveries),
        id(value.locked_delivery_ids),
        value.locked_delivery_ids,
        id(value.locked_attempts),
        tuple(_stage_execution_model_seal(attempt) for attempt in value.locked_attempts),
        id(value.locked_attempt_ids),
        value.locked_attempt_ids,
        value.source_attempt_id,
        value.transaction_at,
        value.observed_at,
        id(value._session),
        id(value._transaction),
    )


def _workflow_cancellation_command_seal(
    value: WorkflowCancellationCommand,
) -> tuple[object, ...]:
    return (
        id(value),
        value.request_id,
        value.workflow_run_id,
        value.expected_workflow_state_version,
        value.actor,
        value.actor_id,
        value.reason,
    )


def _workflow_terminalization_projection_seal(
    value: _WorkflowTerminalizationProjection,
) -> tuple[object, ...]:
    return (
        id(value),
        value.decision,
        id(value.post_stage_statuses),
        value.post_stage_statuses,
        id(value.cancelled_stage_ids),
        value.cancelled_stage_ids,
        id(value.cancelled_attempt_ids),
        value.cancelled_attempt_ids,
    )


def _workflow_terminalization_reservation_seal(
    value: WorkflowTerminalizationReservation,
) -> tuple[object, ...]:
    return (
        _workflow_cancellation_command_seal(value.command),
        value.decision,
        _stage_execution_model_seal(value.workflow),
        id(value.stages),
        tuple(_stage_execution_model_seal(stage) for stage in value.stages),
        id(value.stage_states),
        tuple(_stage_ready_state_seal(state) for state in value.stage_states),
        _workflow_terminalization_projection_seal(value.projection),
        id(value.locked_messages),
        tuple(_stage_execution_model_seal(message) for message in value.locked_messages),
        id(value.locked_message_ids),
        value.locked_message_ids,
        id(value.locked_deliveries),
        tuple(_stage_execution_model_seal(delivery) for delivery in value.locked_deliveries),
        id(value.locked_delivery_ids),
        value.locked_delivery_ids,
        id(value.locked_attempts),
        tuple(_stage_execution_model_seal(attempt) for attempt in value.locked_attempts),
        id(value.locked_attempt_ids),
        value.locked_attempt_ids,
        id(value.live_message_ids),
        value.live_message_ids,
        value.transaction_at,
        value.observed_at,
        id(value._session),
        id(value._transaction),
    )


def _stage_recovery_reservation_seal(
    value: StageRecoveryReservation,
) -> tuple[object, ...]:
    return (
        id(value.source_authority),
        _stage_execution_authority_seal(value.source_authority),
        _stage_execution_model_seal(value.workflow),
        id(value.stages),
        tuple(_stage_execution_model_seal(stage) for stage in value.stages),
        id(value.stage_states),
        tuple(_stage_ready_state_seal(state) for state in value.stage_states),
        value.source_stage_id,
        value.source_stage_index,
        _stage_ready_state_seal(value.causal_source),
        value.decision,
        value.retry_delay_seconds,
        (_stage_failure_retry_projection_seal(value.retry_projection) if value.retry_projection is not None else None),
        value.retry_message_id,
        _stage_failure_settlement_seal(value.settlement),
        id(value.locked_messages),
        tuple(_stage_execution_model_seal(message) for message in value.locked_messages),
        id(value.locked_message_ids),
        value.locked_message_ids,
        id(value.locked_deliveries),
        tuple(_stage_execution_model_seal(delivery) for delivery in value.locked_deliveries),
        id(value.locked_delivery_ids),
        value.locked_delivery_ids,
        id(value.locked_attempts),
        tuple(_stage_execution_model_seal(attempt) for attempt in value.locked_attempts),
        id(value.locked_attempt_ids),
        value.locked_attempt_ids,
        value.source_attempt_id,
        id(value.live_message_ids),
        value.live_message_ids,
        value.transaction_at,
        value.observed_at,
        id(value._session),
        id(value._transaction),
    )


def _outbox_cancellation_reservation_seal(
    value: OutboxCancellationReservation,
) -> tuple[object, ...]:
    return (
        value.workflow_run_id,
        id(value.messages),
        tuple(_stage_execution_model_seal(message) for message in value.messages),
        id(value.message_ids),
        value.message_ids,
        id(value.deliveries),
        tuple(_stage_execution_model_seal(delivery) for delivery in value.deliveries),
        id(value.delivery_ids),
        value.delivery_ids,
        value.error_code,
        value.error_class,
        value.error_summary,
        value.cancelled_by,
        value.cancelled_by_id,
        value.cancel_reason,
        value.transaction_at,
        id(value._session),
        id(value._transaction),
    )


def _stage_failure_branch_coordinate(
    value: StageFailureReservation,
) -> tuple[object, ...] | None:
    if value.decision == "retry":
        if value.retry_projection is None:
            raise OutboxStoredContractError("Retry failure has no fanout identity")
        return (
            value.authority.workflow_run_id,
            value.source_stage_id,
            "retry_scheduled",
            (value.retry_projection.logical_key,),
        )
    if value.stages[value.source_stage_index].required:
        return (value.authority.workflow_run_id, "terminalize")
    return None


def _workflow_terminalization_fence(
    db: AsyncSession,
    transaction: object,
) -> _WorkflowTerminalizationFence:
    info = db.sync_session.info
    fence = info.get(_WORKFLOW_TERMINALIZATION_FENCE_INFO_KEY)
    if fence is None or (type(fence) is _WorkflowTerminalizationFence and fence.transaction is not transaction):
        fence = _WorkflowTerminalizationFence(transaction=transaction, coordinates={})
        info[_WORKFLOW_TERMINALIZATION_FENCE_INFO_KEY] = fence
    if type(fence) is not _WorkflowTerminalizationFence or fence.transaction is not transaction or type(fence.coordinates) is not dict:
        raise OutboxConflict("Workflow terminalization transaction fence is invalid")
    return fence


def _stage_recovery_sweep_fence(
    db: AsyncSession,
    transaction: object,
) -> _StageRecoverySweepFence | None:
    fence = db.sync_session.info.get(_STAGE_RECOVERY_SWEEP_FENCE_INFO_KEY)
    if fence is None:
        return None
    if (
        type(fence) is not _StageRecoverySweepFence
        or fence.transaction is not transaction
        or type(fence.state) is not str
        or fence.state not in {"pending", "issued", "spent"}
        or (fence.state == "pending" and fence.reservation_id is not None)
        or (fence.state == "issued" and type(fence.reservation_id) is not int)
        or (fence.state == "spent" and fence.reservation_id is not None and type(fence.reservation_id) is not int)
    ):
        raise OutboxConflict("Stage recovery sweep transaction fence is invalid")
    return fence


def _begin_stage_recovery_sweep(db: AsyncSession, transaction: object) -> None:
    fence = _stage_recovery_sweep_fence(db, transaction)
    if fence is not None:
        raise OutboxConflict("Only one expired stage recovery is allowed per root transaction")
    db.sync_session.info[_STAGE_RECOVERY_SWEEP_FENCE_INFO_KEY] = _StageRecoverySweepFence(
        transaction=transaction,
        state="pending",
        reservation_id=None,
    )


def _spend_empty_stage_recovery_sweep(db: AsyncSession, transaction: object) -> None:
    fence = _stage_recovery_sweep_fence(db, transaction)
    if fence is None or fence.state != "pending":
        raise OutboxConflict("Stage recovery sweep slot is not pending")
    fence.state = "spent"
    fence.reservation_id = None


def _execution_authorities_for_locked_attempts(
    *,
    workflow: WorkflowRun,
    stages: tuple[StageRun, ...],
    messages: tuple[OutboxMessage, ...],
    deliveries: tuple[OutboxDeliveryAttempt, ...],
    attempts: tuple[StageAttempt, ...],
) -> tuple[ExecutableStageAuthority, ...]:
    stages_by_id = {_persisted_uuid(stage.id, field_name="execution fence stage id"): stage for stage in stages}
    deliveries_by_id = {_persisted_uuid(delivery.id, field_name="execution fence delivery id"): delivery for delivery in deliveries}
    messages_by_id = {_persisted_uuid(message.id, field_name="execution fence message id"): message for message in messages}
    authorities: list[ExecutableStageAuthority] = []
    for attempt in attempts:
        stage = stages_by_id.get(_persisted_uuid(attempt.stage_run_id, field_name="execution fence attempt stage id"))
        if stage is None or attempt.outbox_delivery_attempt_id is None:
            raise OutboxStoredContractError("Execution fence attempt lacks exact stage or receipt authority")
        delivery = deliveries_by_id.get(
            _persisted_uuid(
                attempt.outbox_delivery_attempt_id,
                field_name="execution fence attempt delivery id",
            )
        )
        if delivery is None:
            raise OutboxStoredContractError("Execution fence attempt delivery is outside locked union")
        message = messages_by_id.get(_persisted_uuid(delivery.message_id, field_name="execution fence delivery message id"))
        if message is None:
            raise OutboxStoredContractError("Execution fence receipt message is outside locked union")
        authorities.append(
            _executable_stage_authority(
                workflow=workflow,
                stage=stage,
                message=message,
                delivery=delivery,
                attempt=attempt,
            )
        )
    return tuple(authorities)


def _assert_workflow_has_no_reserved_fanout(
    db: AsyncSession,
    transaction: object,
    workflow_run_id: uuid.UUID,
) -> None:
    fence = _stage_completion_fanout_fence(db, transaction)
    if any(type(coordinate) is tuple and bool(coordinate) and coordinate[0] == workflow_run_id for coordinate in fence.coordinates):
        raise OutboxConflict("Workflow fanout authority already exists in this root transaction")


def _assert_workflow_has_no_terminalization(
    db: AsyncSession,
    transaction: object,
    workflow_run_id: uuid.UUID,
) -> None:
    coordinate = (workflow_run_id, "terminalize")
    if coordinate in _workflow_terminalization_fence(db, transaction).coordinates:
        raise OutboxConflict("Workflow terminalization authority already exists in this root transaction")


def _register_workflow_terminalization_reservation(
    db: AsyncSession,
    transaction: object,
    reservation: WorkflowTerminalizationReservation,
) -> None:
    key = (id(db), id(transaction), id(reservation))
    coordinate = (reservation.command.workflow_run_id, "terminalize")
    terminal_fence = _workflow_terminalization_fence(db, transaction)
    if coordinate in terminal_fence.coordinates:
        raise OutboxConflict("Workflow terminalization was already reserved in this root transaction")
    _assert_workflow_has_no_reserved_fanout(
        db,
        transaction,
        reservation.command.workflow_run_id,
    )
    authorities = _execution_authorities_for_locked_attempts(
        workflow=reservation.workflow,
        stages=reservation.stages,
        messages=reservation.locked_messages,
        deliveries=reservation.locked_deliveries,
        attempts=reservation.locked_attempts,
    )
    execution_coordinates = tuple(_stage_execution_authority_seal(authority) for authority in authorities)
    execution_fence = _stage_execution_receipt_transaction_fence(db, transaction)
    if any(value in execution_fence.coordinates for value in execution_coordinates):
        raise OutboxConflict("Workflow execution authority was already reserved in this root transaction")

    def discard(reference: object) -> None:
        current = _WORKFLOW_TERMINALIZATION_RESERVATIONS.get(key)
        if current is not None and (reference is current.session_ref or reference is current.reservation_ref):
            _WORKFLOW_TERMINALIZATION_RESERVATIONS.pop(key, None)

    try:
        registration = _WorkflowTerminalizationRegistration(
            session_ref=weakref.ref(db, discard),
            reservation_ref=weakref.ref(reservation, discard),
            seal=_workflow_terminalization_reservation_seal(reservation),
            terminal_coordinate=coordinate,
            execution_coordinates=execution_coordinates,
        )
    except TypeError as exc:
        raise OutboxValidation("Workflow terminalization session cannot hold a capability") from exc
    if key in _WORKFLOW_TERMINALIZATION_RESERVATIONS:
        raise OutboxConflict("Workflow terminalization capability is already registered")
    _WORKFLOW_TERMINALIZATION_RESERVATIONS[key] = registration
    terminal_fence.coordinates[coordinate] = ("issued", id(reservation))
    for execution_coordinate in execution_coordinates:
        execution_fence.coordinates[execution_coordinate] = ("issued", id(reservation))


def _consume_workflow_terminalization_registration(
    db: AsyncSession,
    transaction: object,
    reservation: object,
) -> _WorkflowTerminalizationRegistration:
    if type(reservation) is not WorkflowTerminalizationReservation:
        raise OutboxValidation("reservation must be exact workflow terminalization authority")
    key = (id(db), id(transaction), id(reservation))
    registration = _WORKFLOW_TERMINALIZATION_RESERVATIONS.get(key)
    if registration is None or registration.session_ref() is not db or registration.reservation_ref() is not reservation:
        raise OutboxConflict("Workflow terminalization capability is not registered for this transaction")
    terminal_fence = _workflow_terminalization_fence(db, transaction)
    if terminal_fence.coordinates.get(registration.terminal_coordinate) != (
        "issued",
        id(reservation),
    ):
        raise OutboxConflict("Workflow terminalization coordinate is not live")
    execution_fence = _stage_execution_receipt_transaction_fence(db, transaction)
    if any(execution_fence.coordinates.get(coordinate) != ("issued", id(reservation)) for coordinate in registration.execution_coordinates):
        raise OutboxConflict("Workflow execution coordinates are not live for terminalization")
    terminal_fence.coordinates[registration.terminal_coordinate] = ("spent", id(reservation))
    for coordinate in registration.execution_coordinates:
        execution_fence.coordinates[coordinate] = ("spent", id(reservation))
    del _WORKFLOW_TERMINALIZATION_RESERVATIONS[key]
    return registration


def _stage_recovery_branch_coordinate(
    reservation: StageRecoveryReservation,
) -> tuple[object, ...] | None:
    if reservation.decision == "retry":
        if reservation.retry_projection is None:
            raise OutboxStoredContractError("Recovery retry has no fanout identity")
        return (
            reservation.source_authority.workflow_run_id,
            reservation.source_stage_id,
            "lease_recovered",
            (reservation.retry_projection.logical_key,),
        )
    if reservation.stages[reservation.source_stage_index].required:
        return (reservation.source_authority.workflow_run_id, "terminalize")
    return None


def _register_stage_recovery_reservation(
    db: AsyncSession,
    transaction: object,
    reservation: StageRecoveryReservation,
) -> None:
    key = (id(db), id(transaction), id(reservation))
    sweep = _stage_recovery_sweep_fence(db, transaction)
    if sweep is None or sweep.state != "pending":
        raise OutboxConflict("Stage recovery sweep slot is not pending for registration")
    authorities = _execution_authorities_for_locked_attempts(
        workflow=reservation.workflow,
        stages=reservation.stages,
        messages=reservation.locked_messages,
        deliveries=reservation.locked_deliveries,
        attempts=reservation.locked_attempts,
    )
    execution_coordinates = tuple(_stage_execution_authority_seal(authority) for authority in authorities)
    if _stage_execution_authority_seal(reservation.source_authority) not in execution_coordinates:
        raise OutboxStoredContractError("Recovery source is absent from its execution coordinate set")
    execution_fence = _stage_execution_receipt_transaction_fence(db, transaction)
    if any(value in execution_fence.coordinates for value in execution_coordinates):
        raise OutboxConflict("Stage recovery execution coordinate was already reserved")
    branch_coordinate = _stage_recovery_branch_coordinate(reservation)
    branch_fence: _StageCompletionFanoutFence | _WorkflowTerminalizationFence | None = None
    if reservation.decision == "retry":
        _assert_workflow_has_no_terminalization(
            db,
            transaction,
            reservation.source_authority.workflow_run_id,
        )
        branch_fence = _stage_completion_fanout_fence(db, transaction)
    elif branch_coordinate is not None:
        _assert_workflow_has_no_reserved_fanout(
            db,
            transaction,
            reservation.source_authority.workflow_run_id,
        )
        branch_fence = _workflow_terminalization_fence(db, transaction)
    if branch_coordinate is not None and (branch_fence is None or branch_coordinate in branch_fence.coordinates):
        raise OutboxConflict("Stage recovery branch was already reserved in this root transaction")

    def discard(reference: object) -> None:
        current = _STAGE_RECOVERY_RESERVATIONS.get(key)
        if current is not None and (reference is current.session_ref or reference is current.reservation_ref):
            _STAGE_RECOVERY_RESERVATIONS.pop(key, None)

    try:
        registration = _StageRecoveryRegistration(
            session_ref=weakref.ref(db, discard),
            reservation_ref=weakref.ref(reservation, discard),
            seal=_stage_recovery_reservation_seal(reservation),
            execution_coordinates=execution_coordinates,
            branch_coordinate=branch_coordinate,
        )
    except TypeError as exc:
        raise OutboxValidation("Stage recovery session cannot hold a capability") from exc
    if key in _STAGE_RECOVERY_RESERVATIONS:
        raise OutboxConflict("Stage recovery capability is already registered")
    _STAGE_RECOVERY_RESERVATIONS[key] = registration
    sweep.state = "issued"
    sweep.reservation_id = id(reservation)
    for coordinate in execution_coordinates:
        execution_fence.coordinates[coordinate] = ("issued", id(reservation))
    if branch_coordinate is not None and branch_fence is not None:
        branch_fence.coordinates[branch_coordinate] = ("issued", id(reservation))


def _consume_stage_recovery_registration(
    db: AsyncSession,
    transaction: object,
    reservation: object,
) -> _StageRecoveryRegistration:
    if type(reservation) is not StageRecoveryReservation:
        raise OutboxValidation("reservation must be exact stage recovery authority")
    key = (id(db), id(transaction), id(reservation))
    registration = _STAGE_RECOVERY_RESERVATIONS.get(key)
    if registration is None or registration.session_ref() is not db or registration.reservation_ref() is not reservation:
        raise OutboxConflict("Stage recovery capability is not registered for this transaction")
    sweep = _stage_recovery_sweep_fence(db, transaction)
    if sweep is None or sweep.state != "issued" or sweep.reservation_id != id(reservation):
        raise OutboxConflict("Stage recovery sweep coordinate is not live")
    execution_fence = _stage_execution_receipt_transaction_fence(db, transaction)
    if any(execution_fence.coordinates.get(coordinate) != ("issued", id(reservation)) for coordinate in registration.execution_coordinates):
        raise OutboxConflict("Stage recovery execution coordinates are not live")
    branch_fence: _StageCompletionFanoutFence | _WorkflowTerminalizationFence | None = None
    if reservation.decision == "retry":
        branch_fence = _stage_completion_fanout_fence(db, transaction)
    elif registration.branch_coordinate is not None:
        branch_fence = _workflow_terminalization_fence(db, transaction)
    if registration.branch_coordinate is not None and (
        branch_fence is None or branch_fence.coordinates.get(registration.branch_coordinate) != ("issued", id(reservation))
    ):
        raise OutboxConflict("Stage recovery branch coordinate is not live")
    sweep.state = "spent"
    sweep.reservation_id = id(reservation)
    for coordinate in registration.execution_coordinates:
        execution_fence.coordinates[coordinate] = ("spent", id(reservation))
    if registration.branch_coordinate is not None and branch_fence is not None:
        branch_fence.coordinates[registration.branch_coordinate] = ("spent", id(reservation))
    del _STAGE_RECOVERY_RESERVATIONS[key]
    return registration


def _register_stage_failure_reservation(
    db: AsyncSession,
    transaction: object,
    reservation: StageFailureReservation,
) -> None:
    key = (id(db), id(transaction), id(reservation))
    if reservation.decision == "retry":
        _assert_workflow_has_no_terminalization(
            db,
            transaction,
            reservation.authority.workflow_run_id,
        )
    execution_coordinate = _stage_execution_authority_seal(reservation.authority)
    execution_fence = _stage_execution_receipt_transaction_fence(db, transaction)
    if execution_coordinate in execution_fence.coordinates:
        raise OutboxConflict("Stage execution receipt coordinate was already reserved in this root transaction")
    branch_coordinate = _stage_failure_branch_coordinate(reservation)
    branch_fence: _StageCompletionFanoutFence | _WorkflowTerminalizationFence | None = None
    if reservation.decision == "retry":
        branch_fence = _stage_completion_fanout_fence(db, transaction)
    elif branch_coordinate is not None:
        branch_fence = _workflow_terminalization_fence(db, transaction)
    if branch_coordinate is not None and branch_fence is not None and branch_coordinate in branch_fence.coordinates:
        raise OutboxConflict("Stage failure branch was already reserved in this root transaction")

    def discard(reference: object) -> None:
        current = _STAGE_FAILURE_RESERVATIONS.get(key)
        if current is not None and (reference is current.session_ref or reference is current.reservation_ref):
            _STAGE_FAILURE_RESERVATIONS.pop(key, None)

    try:
        registration = _StageFailureRegistration(
            session_ref=weakref.ref(db, discard),
            reservation_ref=weakref.ref(reservation, discard),
            seal=_stage_failure_reservation_seal(reservation),
            execution_coordinate=execution_coordinate,
            branch_coordinate=branch_coordinate,
        )
    except TypeError as exc:
        raise OutboxValidation("Stage failure session cannot hold a capability") from exc
    if key in _STAGE_FAILURE_RESERVATIONS:
        raise OutboxConflict("Stage failure capability is already registered")
    _STAGE_FAILURE_RESERVATIONS[key] = registration
    execution_fence.coordinates[execution_coordinate] = ("issued", id(reservation))
    if branch_coordinate is not None and branch_fence is not None:
        branch_fence.coordinates[branch_coordinate] = ("issued", id(reservation))


def _consume_stage_failure_registration(
    db: AsyncSession,
    transaction: object,
    reservation: object,
) -> _StageFailureRegistration:
    if type(reservation) is not StageFailureReservation:
        raise OutboxValidation("reservation must be exact stage failure authority")
    key = (id(db), id(transaction), id(reservation))
    registration = _STAGE_FAILURE_RESERVATIONS.get(key)
    if registration is None or registration.session_ref() is not db or registration.reservation_ref() is not reservation:
        raise OutboxConflict("Stage failure capability is not registered for this transaction")
    execution_fence = _stage_execution_receipt_transaction_fence(db, transaction)
    if execution_fence.coordinates.get(registration.execution_coordinate) != (
        "issued",
        id(reservation),
    ):
        raise OutboxConflict("Stage failure execution coordinate is not live in this root transaction")
    branch_fence: _StageCompletionFanoutFence | _WorkflowTerminalizationFence | None = None
    if reservation.decision == "retry":
        branch_fence = _stage_completion_fanout_fence(db, transaction)
    elif registration.branch_coordinate is not None:
        branch_fence = _workflow_terminalization_fence(db, transaction)
    if registration.branch_coordinate is not None and (
        branch_fence is None or branch_fence.coordinates.get(registration.branch_coordinate) != ("issued", id(reservation))
    ):
        raise OutboxConflict("Stage failure branch coordinate is not live in this root transaction")
    execution_fence.coordinates[registration.execution_coordinate] = (
        "spent",
        id(reservation),
    )
    if registration.branch_coordinate is not None and branch_fence is not None:
        branch_fence.coordinates[registration.branch_coordinate] = (
            "spent",
            id(reservation),
        )
    del _STAGE_FAILURE_RESERVATIONS[key]
    return registration


def _register_transferred_failure_stage_ready_reservation(
    db: AsyncSession,
    transaction: object,
    *,
    failure_reservation: StageFailureReservation,
    failure_registration: _StageFailureRegistration,
    stage_ready_reservation: StageReadyReservation,
) -> None:
    if (
        type(failure_reservation) is not StageFailureReservation
        or type(failure_registration) is not _StageFailureRegistration
        or type(stage_ready_reservation) is not StageReadyReservation
    ):
        raise OutboxValidation("Failure retry transfer requires exact capability types")
    if (
        failure_registration.session_ref() is not db
        or failure_registration.reservation_ref() is not failure_reservation
        or stage_ready_reservation._session is not db
        or stage_ready_reservation._transaction is not transaction
    ):
        raise OutboxConflict("Failure retry transfer changed session or transaction authority")
    if _stage_failure_reservation_seal(failure_reservation) != failure_registration.seal:
        raise OutboxConflict("Failure retry transfer source was mutated after consumption")
    coordinate = failure_registration.branch_coordinate
    if coordinate is None or _stage_ready_fanout_coordinate(stage_ready_reservation) != coordinate:
        raise OutboxStoredContractError("Transferred retry fanout changed failure identity")
    failure_id = id(failure_reservation)
    execution_fence = _stage_execution_receipt_transaction_fence(db, transaction)
    fanout_fence = _stage_completion_fanout_fence(db, transaction)
    if execution_fence.coordinates.get(failure_registration.execution_coordinate) != (
        "spent",
        failure_id,
    ) or fanout_fence.coordinates.get(coordinate) != ("spent", failure_id):
        raise OutboxConflict("Failure retry authority is not spent for transfer")
    key = (id(db), id(transaction), id(stage_ready_reservation))
    if key in _STAGE_READY_RESERVATIONS:
        raise OutboxConflict("Transferred retry capability is already registered")

    def discard(reference: object) -> None:
        current = _STAGE_READY_RESERVATIONS.get(key)
        if current is not None and (reference is current.session_ref or reference is current.reservation_ref):
            _STAGE_READY_RESERVATIONS.pop(key, None)

    try:
        child_registration = _StageReadyReservationRegistration(
            session_ref=weakref.ref(db, discard),
            reservation_ref=weakref.ref(stage_ready_reservation, discard),
            seal=_stage_ready_reservation_seal(stage_ready_reservation),
            fanout_coordinate=coordinate,
        )
    except TypeError as exc:
        raise OutboxValidation("Transferred retry capability cannot be registered") from exc
    _STAGE_READY_RESERVATIONS[key] = child_registration
    fanout_fence.coordinates[coordinate] = ("issued", id(stage_ready_reservation))


def _register_transferred_outbox_cancellation_reservation(
    db: AsyncSession,
    transaction: object,
    *,
    failure_reservation: StageFailureReservation,
    failure_registration: _StageFailureRegistration,
    cancellation_reservation: OutboxCancellationReservation,
) -> None:
    if (
        type(failure_reservation) is not StageFailureReservation
        or type(failure_registration) is not _StageFailureRegistration
        or type(cancellation_reservation) is not OutboxCancellationReservation
    ):
        raise OutboxValidation("Failure cancellation transfer requires exact capability types")
    if (
        failure_registration.session_ref() is not db
        or failure_registration.reservation_ref() is not failure_reservation
        or cancellation_reservation._session is not db
        or cancellation_reservation._transaction is not transaction
    ):
        raise OutboxConflict("Failure cancellation transfer changed session or transaction authority")
    if _stage_failure_reservation_seal(failure_reservation) != failure_registration.seal:
        raise OutboxConflict("Failure cancellation transfer source was mutated after consumption")
    coordinate = failure_registration.branch_coordinate
    expected_coordinate = (failure_reservation.authority.workflow_run_id, "terminalize")
    if coordinate != expected_coordinate:
        raise OutboxStoredContractError("Transferred cancellation changed terminalization identity")
    failure_id = id(failure_reservation)
    execution_fence = _stage_execution_receipt_transaction_fence(db, transaction)
    terminal_fence = _workflow_terminalization_fence(db, transaction)
    if execution_fence.coordinates.get(failure_registration.execution_coordinate) != (
        "spent",
        failure_id,
    ) or terminal_fence.coordinates.get(coordinate) != ("spent", failure_id):
        raise OutboxConflict("Failure cancellation authority is not spent for transfer")
    key = (id(db), id(transaction), id(cancellation_reservation))
    if key in _OUTBOX_CANCELLATION_RESERVATIONS:
        raise OutboxConflict("Transferred cancellation capability is already registered")

    def discard(reference: object) -> None:
        current = _OUTBOX_CANCELLATION_RESERVATIONS.get(key)
        if current is not None and (reference is current.session_ref or reference is current.reservation_ref):
            _OUTBOX_CANCELLATION_RESERVATIONS.pop(key, None)

    try:
        child_registration = _OutboxCancellationRegistration(
            session_ref=weakref.ref(db, discard),
            reservation_ref=weakref.ref(cancellation_reservation, discard),
            seal=_outbox_cancellation_reservation_seal(cancellation_reservation),
            terminal_coordinate=coordinate,
        )
    except TypeError as exc:
        raise OutboxValidation("Transferred cancellation capability cannot be registered") from exc
    _OUTBOX_CANCELLATION_RESERVATIONS[key] = child_registration
    terminal_fence.coordinates[coordinate] = (
        "issued",
        id(cancellation_reservation),
    )


def _register_cancellation_child(
    db: AsyncSession,
    transaction: object,
    *,
    coordinate: tuple[object, ...],
    source_id: int,
    cancellation_reservation: OutboxCancellationReservation,
) -> None:
    if type(cancellation_reservation) is not OutboxCancellationReservation:
        raise OutboxValidation("Cancellation transfer requires exact child authority")
    if cancellation_reservation._session is not db or cancellation_reservation._transaction is not transaction:
        raise OutboxConflict("Cancellation transfer changed session or transaction authority")
    terminal_fence = _workflow_terminalization_fence(db, transaction)
    if terminal_fence.coordinates.get(coordinate) != ("spent", source_id):
        raise OutboxConflict("Terminalization authority is not spent for cancellation transfer")
    key = (id(db), id(transaction), id(cancellation_reservation))
    if key in _OUTBOX_CANCELLATION_RESERVATIONS:
        raise OutboxConflict("Transferred cancellation capability is already registered")

    def discard(reference: object) -> None:
        current = _OUTBOX_CANCELLATION_RESERVATIONS.get(key)
        if current is not None and (reference is current.session_ref or reference is current.reservation_ref):
            _OUTBOX_CANCELLATION_RESERVATIONS.pop(key, None)

    try:
        registration = _OutboxCancellationRegistration(
            session_ref=weakref.ref(db, discard),
            reservation_ref=weakref.ref(cancellation_reservation, discard),
            seal=_outbox_cancellation_reservation_seal(cancellation_reservation),
            terminal_coordinate=coordinate,
        )
    except TypeError as exc:
        raise OutboxValidation("Transferred cancellation capability cannot be registered") from exc
    _OUTBOX_CANCELLATION_RESERVATIONS[key] = registration
    terminal_fence.coordinates[coordinate] = (
        "issued",
        id(cancellation_reservation),
    )


def _register_transferred_terminalization_cancellation_reservation(
    db: AsyncSession,
    transaction: object,
    *,
    terminalization_reservation: WorkflowTerminalizationReservation,
    terminalization_registration: _WorkflowTerminalizationRegistration,
    cancellation_reservation: OutboxCancellationReservation,
) -> None:
    if (
        type(terminalization_reservation) is not WorkflowTerminalizationReservation
        or type(terminalization_registration) is not _WorkflowTerminalizationRegistration
    ):
        raise OutboxValidation("Terminalization cancellation transfer requires exact source authority")
    if (
        terminalization_registration.session_ref() is not db
        or terminalization_registration.reservation_ref() is not terminalization_reservation
        or _workflow_terminalization_reservation_seal(terminalization_reservation) != terminalization_registration.seal
    ):
        raise OutboxConflict("Terminalization cancellation source changed after consumption")
    coordinate = (
        terminalization_reservation.command.workflow_run_id,
        "terminalize",
    )
    if terminalization_registration.terminal_coordinate != coordinate:
        raise OutboxStoredContractError("Terminalization cancellation changed workflow identity")
    _register_cancellation_child(
        db,
        transaction,
        coordinate=coordinate,
        source_id=id(terminalization_reservation),
        cancellation_reservation=cancellation_reservation,
    )


def _register_transferred_recovery_stage_ready_reservation(
    db: AsyncSession,
    transaction: object,
    *,
    recovery_reservation: StageRecoveryReservation,
    recovery_registration: _StageRecoveryRegistration,
    stage_ready_reservation: StageReadyReservation,
) -> None:
    if (
        type(recovery_reservation) is not StageRecoveryReservation
        or type(recovery_registration) is not _StageRecoveryRegistration
        or type(stage_ready_reservation) is not StageReadyReservation
    ):
        raise OutboxValidation("Recovery retry transfer requires exact capability types")
    if (
        recovery_registration.session_ref() is not db
        or recovery_registration.reservation_ref() is not recovery_reservation
        or stage_ready_reservation._session is not db
        or stage_ready_reservation._transaction is not transaction
        or _stage_recovery_reservation_seal(recovery_reservation) != recovery_registration.seal
    ):
        raise OutboxConflict("Recovery retry transfer source changed after consumption")
    coordinate = recovery_registration.branch_coordinate
    if coordinate is None or _stage_ready_fanout_coordinate(stage_ready_reservation) != coordinate:
        raise OutboxStoredContractError("Transferred recovery retry changed fanout identity")
    recovery_id = id(recovery_reservation)
    fanout_fence = _stage_completion_fanout_fence(db, transaction)
    if fanout_fence.coordinates.get(coordinate) != ("spent", recovery_id):
        raise OutboxConflict("Recovery retry authority is not spent for transfer")
    key = (id(db), id(transaction), id(stage_ready_reservation))
    if key in _STAGE_READY_RESERVATIONS:
        raise OutboxConflict("Transferred recovery retry capability is already registered")

    def discard(reference: object) -> None:
        current = _STAGE_READY_RESERVATIONS.get(key)
        if current is not None and (reference is current.session_ref or reference is current.reservation_ref):
            _STAGE_READY_RESERVATIONS.pop(key, None)

    try:
        child_registration = _StageReadyReservationRegistration(
            session_ref=weakref.ref(db, discard),
            reservation_ref=weakref.ref(stage_ready_reservation, discard),
            seal=_stage_ready_reservation_seal(stage_ready_reservation),
            fanout_coordinate=coordinate,
        )
    except TypeError as exc:
        raise OutboxValidation("Transferred recovery retry cannot be registered") from exc
    _STAGE_READY_RESERVATIONS[key] = child_registration
    fanout_fence.coordinates[coordinate] = ("issued", id(stage_ready_reservation))


def _register_transferred_recovery_cancellation_reservation(
    db: AsyncSession,
    transaction: object,
    *,
    recovery_reservation: StageRecoveryReservation,
    recovery_registration: _StageRecoveryRegistration,
    cancellation_reservation: OutboxCancellationReservation,
) -> None:
    if type(recovery_reservation) is not StageRecoveryReservation or type(recovery_registration) is not _StageRecoveryRegistration:
        raise OutboxValidation("Recovery cancellation transfer requires exact source authority")
    if (
        recovery_registration.session_ref() is not db
        or recovery_registration.reservation_ref() is not recovery_reservation
        or _stage_recovery_reservation_seal(recovery_reservation) != recovery_registration.seal
    ):
        raise OutboxConflict("Recovery cancellation source changed after consumption")
    coordinate = (
        recovery_reservation.source_authority.workflow_run_id,
        "terminalize",
    )
    if recovery_registration.branch_coordinate != coordinate:
        raise OutboxStoredContractError("Recovery cancellation changed terminalization identity")
    _register_cancellation_child(
        db,
        transaction,
        coordinate=coordinate,
        source_id=id(recovery_reservation),
        cancellation_reservation=cancellation_reservation,
    )


def _consume_outbox_cancellation_registration(
    db: AsyncSession,
    transaction: object,
    reservation: object,
) -> tuple[object, ...]:
    if type(reservation) is not OutboxCancellationReservation:
        raise OutboxValidation("reservation must be exact outbox cancellation authority")
    key = (id(db), id(transaction), id(reservation))
    registration = _OUTBOX_CANCELLATION_RESERVATIONS.get(key)
    if registration is None or registration.session_ref() is not db or registration.reservation_ref() is not reservation:
        raise OutboxConflict("Outbox cancellation capability is not registered for this transaction")
    fence = _workflow_terminalization_fence(db, transaction)
    if fence.coordinates.get(registration.terminal_coordinate) != (
        "issued",
        id(reservation),
    ):
        raise OutboxConflict("Outbox cancellation terminalization coordinate is not live")
    fence.coordinates[registration.terminal_coordinate] = ("spent", id(reservation))
    del _OUTBOX_CANCELLATION_RESERVATIONS[key]
    return registration.seal


def _commit_ticket(value: object) -> str:
    if type(value) is not str or not _COMMIT_TICKET_RE.fullmatch(value):
        raise OutboxValidation("commit_ticket must be exact opaque v1 authority")
    return value


def _transaction_id(value: object, *, field_name: str) -> int:
    return _bounded_int(
        value,
        field_name=field_name,
        minimum=1,
        maximum=9_223_372_036_854_775_807,
    )


def _lower_sha256(value: object, *, field_name: str) -> str:
    if type(value) is not str or not _LOWER_SHA256_RE.fullmatch(value):
        raise OutboxValidation(f"{field_name} must be an exact lowercase SHA-256 value")
    return value


def _aware_datetime(value: object, *, field_name: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise OutboxValidation(f"{field_name} must be an exact timezone-aware datetime")
    return value


def _uuid(value: object, *, field_name: str) -> uuid.UUID:
    if type(value) is not uuid.UUID:
        raise OutboxValidation(f"{field_name} must be a UUID")
    return value


def _persisted_uuid(value: object, *, field_name: str) -> uuid.UUID:
    """Detach an async-driver UUID subtype into exact stdlib authority."""

    if not isinstance(value, uuid.UUID):
        raise OutboxStoredContractError(f"{field_name} is not persisted UUID authority")
    try:
        normalized = uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise OutboxStoredContractError(f"{field_name} is not canonical persisted UUID authority") from exc
    return normalized


def _optional_uuid(value: object, *, field_name: str) -> uuid.UUID | None:
    if value is None:
        return None
    return _uuid(value, field_name=field_name)


def _identity(value: object, *, field_name: str) -> str:
    if type(value) is not str or not _IDENTITY_RE.fullmatch(value):
        raise OutboxValidation(f"{field_name} must be a lowercase identity")
    return value


def _text(value: object, *, field_name: str, maximum: int) -> str:
    if type(value) is not str:
        raise OutboxValidation(f"{field_name} must be an exact string")
    if value != value.strip():
        raise OutboxValidation(f"{field_name} cannot have surrounding whitespace")
    if not value or len(value) > maximum:
        raise OutboxValidation(f"{field_name} must contain 1-{maximum} characters")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise OutboxValidation(f"{field_name} must be valid UTF-8 text") from exc
    if any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value):
        raise OutboxValidation(f"{field_name} cannot contain control characters")
    return value


def _optional_text(value: object, *, field_name: str, maximum: int) -> str:
    if type(value) is not str:
        raise OutboxValidation(f"{field_name} must be an exact string")
    if value == "":
        return value
    return _text(value, field_name=field_name, maximum=maximum)


def _bounded_int(
    value: object,
    *,
    field_name: str,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise OutboxValidation(f"{field_name} must be an integer from {minimum} to {maximum}")
    return value


def _state_version(value: object, *, field_name: str) -> int:
    return _bounded_int(
        value,
        field_name=field_name,
        minimum=1,
        maximum=2_147_483_647,
    )


async def _db_now(db: AsyncSession, *, autoflush: bool = True) -> datetime:
    if type(autoflush) is not bool:
        raise OutboxValidation("autoflush policy must be an exact boolean")
    statement = select(func.transaction_timestamp())
    if not autoflush:
        statement = statement.execution_options(autoflush=False)
    value = await db.scalar(statement)
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise OutboxStoredContractError("PostgreSQL transaction clock did not return a timezone-aware timestamp")
    return value


async def _db_clock_now(db: AsyncSession) -> datetime:
    value = await db.scalar(select(func.clock_timestamp()).execution_options(autoflush=False))
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise OutboxStoredContractError("PostgreSQL wall clock did not return a timezone-aware timestamp")
    return value


async def _db_transaction_id(db: AsyncSession) -> int:
    value = await db.scalar(select(func.txid_current()).execution_options(autoflush=False))
    try:
        return _transaction_id(value, field_name="PostgreSQL transaction ID")
    except OutboxValidation as exc:
        raise OutboxStoredContractError("PostgreSQL did not return a bounded transaction ID") from exc
