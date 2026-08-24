"""Commit-confirmed worker mutations bound to delivered outbox receipts.

Worker code enters through :func:`coordinate_stage_heartbeat`,
:func:`coordinate_stage_checkpoint`, :func:`coordinate_stage_complete`, or
:func:`coordinate_stage_fail`.
The dedicated mutation transaction revalidates exact W/S/M/D/A receipt
authority and flushes one mutation.  Renewals are confirmed in a second,
distinct transaction; terminal completion is confirmed by the mutation
context's successful exit and exposes no further authority.  No ORM row,
reservation, or pre-commit executable authority crosses the public boundary.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import unicodedata
import uuid
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal, TypeAlias

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.research_workflow import (
    MAX_OUTBOX_DELIVERY_CYCLE,
    OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1,
    OUTBOX_TOPIC_WORKFLOW_STAGE_READY,
    OUTBOX_V1_MAX_ATTEMPTS,
    OutboxDeliveryAttempt,
    OutboxMessage,
    StageAttempt,
    StageRun,
    WorkflowRun,
)
from app.services.outbox_runtime import (
    ExecutableStageAuthority,
    LockedStageCompletionGraph,
    LockedStageExecutionReceipt,
    LockedStageFailureGraph,
    LockedStageRecoveryGraph,
    LockedWorkflowTerminalizationGraph,
    OutboxLeaseLost,
    OutboxCancellationReservation,
    OutboxStoredContractError,
    OutboxValidation,
    StageFailureEvidence,
    StageReadyReservation,
    WorkflowCancellationCommand,
    append_reserved_stage_ready as _append_reserved_stage_ready,
    cancel_reserved_outbox_messages as _cancel_reserved_outbox_messages,
    consume_stage_completion_graph as _consume_stage_completion_graph,
    consume_stage_execution_receipt as _consume_stage_execution_receipt,
    consume_stage_failure_graph as _consume_stage_failure_graph,
    consume_stage_recovery_graph as _consume_stage_recovery_graph,
    consume_workflow_terminalization_graph as _consume_workflow_terminalization_graph,
    reserve_one_expired_stage_recovery as _reserve_one_expired_stage_recovery,
    reserve_stage_completion_graph as _reserve_stage_completion_graph,
    reserve_stage_execution_receipt as _reserve_stage_execution_receipt,
    reserve_stage_failure_graph as _reserve_stage_failure_graph,
    reserve_workflow_terminalization_graph as _reserve_workflow_terminalization_graph,
)
from app.services.workflow_engine import (
    MAX_JSON_DEPTH,
    MAX_JSON_ITEMS,
    SanitizedWorkflowError,
    WorkflowContractError,
    canonical_json,
    sanitize_workflow_error,
)
from app.services.workflow_runtime import (
    WorkflowCheckpointConflict,
    WorkflowStoredContractError,
    WorkflowValidation,
)


SessionFactory: TypeAlias = Callable[[], AbstractAsyncContextManager[AsyncSession]]
HeartbeatDisposition: TypeAlias = Literal["renewed", "stale"]
CheckpointDisposition: TypeAlias = Literal["renewed", "stale"]
CompletionDisposition: TypeAlias = Literal["completed", "stale"]
CompletionOutcome: TypeAlias = Literal["succeeded", "degraded"]
FailureDisposition: TypeAlias = Literal["recorded", "stale"]
FailureDecision: TypeAlias = Literal["retry", "failed", "dead_lettered"]
CancellationDisposition: TypeAlias = Literal["applied", "replayed"]
RecoveryDecision: TypeAlias = Literal["retry", "dead_lettered"]

_LOWER_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTITY_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,79}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,79}$")
_MAX_LEASE_SECONDS = 3_600
_TERMINAL_STAGE_STATUSES = frozenset({"succeeded", "degraded", "skipped", "failed", "cancelled", "dead_lettered"})
_DEGRADED_STAGE_STATUSES = frozenset({"degraded", "skipped", "failed", "cancelled", "dead_lettered"})
_FAILURE_CANCELLATION_CLASS = "WorkflowCancelled"
_FAILURE_CANCELLATION_SUMMARY = "Workflow stopped after a required stage failed"
_EXPLICIT_CANCELLATION_CODE = "workflow.cancelled"
_LEASE_EXPIRED_CODE = "workflow.lease_expired"
_LEASE_EXPIRED_CLASS = "LeaseExpired"
_LEASE_EXPIRED_SUMMARY = "Worker lease expired before the attempt reached a terminal outcome"
_MAX_RECOVERY_PASS = 500

__all__ = (
    "CoordinatedStageCompletion",
    "CoordinatedStageEmission",
    "CoordinatedStageFailure",
    "CoordinatedStageCheckpoint",
    "CoordinatedStageHeartbeat",
    "CoordinatedStageRecovery",
    "CoordinatedWorkflowCancellation",
    "SessionFactory",
    "coordinate_expired_stage_recovery_pass",
    "coordinate_one_expired_stage_recovery",
    "coordinate_stage_complete",
    "coordinate_stage_fail",
    "coordinate_stage_checkpoint",
    "coordinate_stage_heartbeat",
    "coordinate_workflow_cancel",
)


@dataclass(frozen=True, slots=True)
class CoordinatedStageEmission:
    """Committed, capability-free identity of one dependency-ready root."""

    stage_run_id: uuid.UUID
    stage_key: str
    stage_state_version: int
    message_id: uuid.UUID
    logical_key: str
    available_at: datetime

    def __post_init__(self) -> None:
        if type(self) is not CoordinatedStageEmission:
            raise OutboxValidation("Coordinated emission must use its exact public result type")
        _exact_uuid(self.stage_run_id, field_name="emission stage_run_id")
        _identity(self.stage_key, field_name="emission stage_key")
        _state_version(self.stage_state_version, field_name="emission stage_state_version")
        _exact_uuid(self.message_id, field_name="emission message_id")
        _lower_sha256(self.logical_key, field_name="emission logical_key")
        _aware_datetime(self.available_at, field_name="emission available_at")


@dataclass(frozen=True, slots=True)
class CoordinatedWorkflowCancellation:
    """Commit-confirmed explicit cancellation or exact immutable replay."""

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("CoordinatedWorkflowCancellation is sealed and cannot be subclassed")

    request_id: uuid.UUID
    workflow_run_id: uuid.UUID
    actor: str
    actor_id: str
    reason: str
    previous_workflow_state_version: int
    workflow_state_version: int
    cancelled_at: datetime
    cancelled_stage_ids: tuple[uuid.UUID, ...]
    cancelled_attempt_ids: tuple[uuid.UUID, ...]
    cancelled_message_ids: tuple[uuid.UUID, ...]
    cancelled_delivery_ids: tuple[uuid.UUID, ...]
    disposition: CancellationDisposition
    should_apply: bool

    def __post_init__(self) -> None:
        if type(self) is not CoordinatedWorkflowCancellation:
            raise OutboxValidation("Coordinated cancellation must use its exact public result type")
        _exact_uuid(self.request_id, field_name="cancellation request_id")
        _exact_uuid(self.workflow_run_id, field_name="cancellation workflow_run_id")
        _text(self.actor, field_name="cancellation actor", maximum=255)
        _text(self.actor_id, field_name="cancellation actor_id", maximum=80)
        _text(self.reason, field_name="cancellation reason", maximum=500)
        previous = _state_version(
            self.previous_workflow_state_version,
            field_name="cancellation previous workflow state_version",
        )
        current = _state_version(
            self.workflow_state_version,
            field_name="cancellation workflow state_version",
        )
        cancelled_at = _aware_datetime(self.cancelled_at, field_name="cancellation cancelled_at")
        copied_ids: dict[str, tuple[uuid.UUID, ...]] = {}
        for field_name in (
            "cancelled_stage_ids",
            "cancelled_attempt_ids",
            "cancelled_message_ids",
            "cancelled_delivery_ids",
        ):
            values = getattr(self, field_name)
            if type(values) is not tuple:
                raise OutboxValidation(f"{field_name} must be an exact tuple")
            copied = tuple(_exact_uuid(value, field_name=field_name) for value in values)
            if len(set(copied)) != len(copied):
                raise OutboxValidation(f"{field_name} must contain unique identities")
            if field_name != "cancelled_stage_ids" and copied != tuple(sorted(copied, key=lambda value: value.int)):
                raise OutboxValidation(f"{field_name} must use canonical UUID order")
            copied_ids[field_name] = copied
        if len(copied_ids["cancelled_attempt_ids"]) > len(copied_ids["cancelled_stage_ids"]):
            raise OutboxValidation("Cancellation attempts cannot outnumber cancelled stages")
        if len(copied_ids["cancelled_delivery_ids"]) > len(copied_ids["cancelled_message_ids"]):
            raise OutboxValidation("Cancellation deliveries cannot outnumber cancelled messages")
        if type(self.disposition) is not str or self.disposition not in {"applied", "replayed"}:
            raise OutboxValidation("Cancellation disposition is outside its closed registry")
        if type(self.should_apply) is not bool or self.should_apply != (self.disposition == "applied"):
            raise OutboxValidation("Cancellation execution decision must be disposition-derived")
        if current != previous + 1:
            raise OutboxValidation("Cancellation result does not identify one exact workflow transition")
        if self.disposition == "replayed" and any(copied_ids.values()):
            raise OutboxValidation("Cancellation replay cannot claim new durable effects")
        if self.disposition == "applied" and not copied_ids["cancelled_stage_ids"]:
            raise OutboxValidation("Applied cancellation requires at least one cancelled stage")
        if (
            copied_ids["cancelled_attempt_ids"] or copied_ids["cancelled_message_ids"] or copied_ids["cancelled_delivery_ids"]
        ) and not copied_ids["cancelled_stage_ids"]:
            raise OutboxValidation("Cancellation details require at least one cancelled stage")
        object.__setattr__(self, "cancelled_at", cancelled_at)
        for field_name, values in copied_ids.items():
            object.__setattr__(self, field_name, values)


@dataclass(frozen=True, slots=True)
class CoordinatedStageRecovery:
    """Commit-confirmed receipt-bound recovery with no executable authority."""

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("CoordinatedStageRecovery is sealed and cannot be subclassed")

    workflow_run_id: uuid.UUID
    stage_run_id: uuid.UUID
    stage_attempt_id: uuid.UUID
    message_id: uuid.UUID
    delivery_attempt_id: uuid.UUID
    stage_lease_token: uuid.UUID
    attempt_number: int
    delivery_cycle: int
    cycle_key: str
    broker_receipt_id: str
    stage_key: str
    input_checksum: str
    checkpoint_version: int
    lease_owner: str
    lease_expires_at: datetime
    decision: RecoveryDecision
    previous_workflow_state_version: int
    workflow_state_version: int
    workflow_status: str
    previous_stage_state_version: int
    stage_state_version: int
    stage_status: str
    previous_attempt_state_version: int
    attempt_state_version: int
    attempt_status: str
    recovered_at: datetime
    next_attempt_at: datetime | None
    skipped_stage_ids: tuple[uuid.UUID, ...]
    cancelled_stage_ids: tuple[uuid.UUID, ...]
    cancelled_attempt_ids: tuple[uuid.UUID, ...]
    cancelled_message_ids: tuple[uuid.UUID, ...]
    cancelled_delivery_ids: tuple[uuid.UUID, ...]
    retry_emission: CoordinatedStageEmission | None
    should_retry: bool
    should_continue: bool

    def __post_init__(self) -> None:
        if type(self) is not CoordinatedStageRecovery:
            raise OutboxValidation("Coordinated recovery must use its exact public result type")
        for field_name in (
            "workflow_run_id",
            "stage_run_id",
            "stage_attempt_id",
            "message_id",
            "delivery_attempt_id",
            "stage_lease_token",
        ):
            _exact_uuid(getattr(self, field_name), field_name=field_name)
        _bounded_int(self.attempt_number, field_name="recovery attempt_number", minimum=1, maximum=20)
        _bounded_int(
            self.delivery_cycle,
            field_name="recovery delivery_cycle",
            minimum=1,
            maximum=MAX_OUTBOX_DELIVERY_CYCLE,
        )
        _lower_sha256(self.cycle_key, field_name="recovery cycle_key")
        _lower_sha256(self.broker_receipt_id, field_name="recovery broker_receipt_id")
        _identity(self.stage_key, field_name="recovery stage_key")
        _lower_sha256(self.input_checksum, field_name="recovery input_checksum")
        _bounded_int(
            self.checkpoint_version,
            field_name="recovery checkpoint_version",
            minimum=0,
            maximum=2_147_483_647,
        )
        _text(self.lease_owner, field_name="recovery lease_owner", maximum=255)
        lease_expires_at = _aware_datetime(
            self.lease_expires_at,
            field_name="recovery lease_expires_at",
        )
        if type(self.decision) is not str or self.decision not in {"retry", "dead_lettered"}:
            raise OutboxValidation("Recovery decision is outside its closed registry")
        for field_name in (
            "previous_workflow_state_version",
            "workflow_state_version",
            "previous_stage_state_version",
            "stage_state_version",
            "previous_attempt_state_version",
            "attempt_state_version",
        ):
            _state_version(getattr(self, field_name), field_name=field_name)
        if type(self.workflow_status) is not str or self.workflow_status not in {
            "running",
            "degraded",
            "dead_lettered",
        }:
            raise OutboxValidation("Recovery workflow status is outside its closed registry")
        expected_stage_status = "retry_wait" if self.decision == "retry" else "dead_lettered"
        if self.stage_status != expected_stage_status or self.attempt_status != "abandoned":
            raise OutboxValidation("Recovery terminal facts contradict their decision")
        if (
            self.stage_state_version != self.previous_stage_state_version + 1
            or self.attempt_state_version != self.previous_attempt_state_version + 1
        ):
            raise OutboxValidation("Recovery result does not identify exact S/A mutations")
        workflow_changed = self.workflow_status != "running"
        if self.workflow_state_version != self.previous_workflow_state_version + int(workflow_changed):
            raise OutboxValidation("Recovery aggregate version contradicts workflow status")
        recovered_at = _aware_datetime(self.recovered_at, field_name="recovery recovered_at")
        if lease_expires_at > recovered_at:
            raise OutboxValidation("Recovery result does not prove an expired presented lease")
        next_attempt_at = (
            None if self.next_attempt_at is None else _aware_datetime(self.next_attempt_at, field_name="recovery next_attempt_at")
        )
        copied_ids: dict[str, tuple[uuid.UUID, ...]] = {}
        for field_name in (
            "skipped_stage_ids",
            "cancelled_stage_ids",
            "cancelled_attempt_ids",
            "cancelled_message_ids",
            "cancelled_delivery_ids",
        ):
            values = getattr(self, field_name)
            if type(values) is not tuple:
                raise OutboxValidation(f"{field_name} must be an exact tuple")
            copied = tuple(_exact_uuid(value, field_name=field_name) for value in values)
            if len(set(copied)) != len(copied):
                raise OutboxValidation(f"{field_name} must contain unique identities")
            if field_name in {
                "cancelled_attempt_ids",
                "cancelled_message_ids",
                "cancelled_delivery_ids",
            } and copied != tuple(sorted(copied, key=lambda value: value.int)):
                raise OutboxValidation(f"{field_name} must use canonical UUID order")
            copied_ids[field_name] = copied
        if self.stage_run_id in set(copied_ids["skipped_stage_ids"] + copied_ids["cancelled_stage_ids"]):
            raise OutboxValidation("Recovery collateral stages cannot include the source")
        if self.stage_attempt_id in copied_ids["cancelled_attempt_ids"]:
            raise OutboxValidation("Recovery collateral attempts cannot include the source")
        if self.message_id in copied_ids["cancelled_message_ids"]:
            raise OutboxValidation("Recovery collateral messages cannot include the delivered source")
        if self.delivery_attempt_id in copied_ids["cancelled_delivery_ids"]:
            raise OutboxValidation("Recovery collateral deliveries cannot include the delivered source")
        if set(copied_ids["skipped_stage_ids"]).intersection(copied_ids["cancelled_stage_ids"]):
            raise OutboxValidation("Recovery skipped and cancelled stage effects must be disjoint")
        if (
            copied_ids["cancelled_attempt_ids"] or copied_ids["cancelled_message_ids"] or copied_ids["cancelled_delivery_ids"]
        ) and not copied_ids["cancelled_stage_ids"]:
            raise OutboxValidation("Recovery cancellation effects require a cancelled stage")
        if len(copied_ids["cancelled_attempt_ids"]) > len(copied_ids["cancelled_stage_ids"]):
            raise OutboxValidation("Recovery cancelled attempts cannot outnumber cancelled stages")
        if len(copied_ids["cancelled_delivery_ids"]) > len(copied_ids["cancelled_message_ids"]):
            raise OutboxValidation("Recovery cancelled deliveries cannot outnumber cancelled messages")
        if (
            any(
                copied_ids[field_name]
                for field_name in (
                    "cancelled_stage_ids",
                    "cancelled_attempt_ids",
                    "cancelled_message_ids",
                    "cancelled_delivery_ids",
                )
            )
            and self.workflow_status != "dead_lettered"
        ) or (copied_ids["skipped_stage_ids"] and self.workflow_status == "dead_lettered"):
            raise OutboxValidation("Recovery collateral effects contradict aggregate status")
        emission = self.retry_emission
        if emission is not None:
            if type(emission) is not CoordinatedStageEmission:
                raise OutboxValidation("Recovery retry emission must use exact public facts")
            emission = CoordinatedStageEmission(
                stage_run_id=emission.stage_run_id,
                stage_key=emission.stage_key,
                stage_state_version=emission.stage_state_version,
                message_id=emission.message_id,
                logical_key=emission.logical_key,
                available_at=emission.available_at,
            )
        if type(self.should_retry) is not bool or self.should_retry != (self.decision == "retry"):
            raise OutboxValidation("Recovery retry decision must be decision-derived")
        if type(self.should_continue) is not bool or self.should_continue:
            raise OutboxValidation("Recovered expired execution must never continue")
        if self.decision == "retry":
            if (
                self.workflow_status != "running"
                or next_attempt_at is None
                or emission is None
                or emission.stage_run_id != self.stage_run_id
                or emission.stage_key != self.stage_key
                or emission.stage_state_version != self.stage_state_version
                or emission.available_at != next_attempt_at
                or emission.message_id == self.message_id
                or any(copied_ids.values())
            ):
                raise OutboxValidation("Retry recovery result is not an exact fixed point")
            delay = next_attempt_at - recovered_at
            if delay.microseconds != 0 or not timedelta(seconds=1) <= delay <= timedelta(seconds=86_400):
                raise OutboxValidation("Recovery retry delay is outside its bounded integer contract")
        elif next_attempt_at is not None or emission is not None:
            raise OutboxValidation("Exhausted recovery cannot claim retry authority")
        object.__setattr__(self, "recovered_at", recovered_at)
        object.__setattr__(self, "lease_expires_at", lease_expires_at)
        object.__setattr__(self, "next_attempt_at", next_attempt_at)
        object.__setattr__(self, "retry_emission", emission)
        for field_name, values in copied_ids.items():
            object.__setattr__(self, field_name, values)


@dataclass(frozen=True, slots=True)
class CoordinatedStageCompletion:
    """Commit-confirmed terminal worker decision with no executable authority."""

    workflow_run_id: uuid.UUID
    stage_run_id: uuid.UUID
    stage_attempt_id: uuid.UUID
    message_id: uuid.UUID
    delivery_attempt_id: uuid.UUID
    stage_lease_token: uuid.UUID
    attempt_number: int
    delivery_cycle: int
    cycle_key: str
    broker_receipt_id: str
    stage_key: str
    input_checksum: str
    checkpoint_version: int
    lease_owner: str
    lease_expires_at: datetime
    outcome: CompletionOutcome
    requested_output_checksum: str
    committed_output_checksum: str | None
    previous_workflow_state_version: int
    workflow_state_version: int
    workflow_status: str
    previous_stage_state_version: int
    stage_state_version: int
    previous_attempt_state_version: int
    attempt_state_version: int
    completed_at: datetime | None
    workflow_completed_at: datetime | None
    emissions: tuple[CoordinatedStageEmission, ...]
    disposition: CompletionDisposition
    should_continue: bool
    should_ack: bool

    def __post_init__(self) -> None:
        if type(self) is not CoordinatedStageCompletion:
            raise OutboxValidation("Coordinated completion must use its exact public result type")
        for field_name in (
            "workflow_run_id",
            "stage_run_id",
            "stage_attempt_id",
            "message_id",
            "delivery_attempt_id",
            "stage_lease_token",
        ):
            _exact_uuid(getattr(self, field_name), field_name=field_name)
        _bounded_int(self.attempt_number, field_name="attempt_number", minimum=1, maximum=20)
        _bounded_int(
            self.delivery_cycle,
            field_name="delivery_cycle",
            minimum=1,
            maximum=MAX_OUTBOX_DELIVERY_CYCLE,
        )
        _lower_sha256(self.cycle_key, field_name="cycle_key")
        _lower_sha256(self.broker_receipt_id, field_name="broker_receipt_id")
        _identity(self.stage_key, field_name="stage_key")
        _lower_sha256(self.input_checksum, field_name="input_checksum")
        _bounded_int(
            self.checkpoint_version,
            field_name="checkpoint_version",
            minimum=0,
            maximum=2_147_483_647,
        )
        _text(self.lease_owner, field_name="lease_owner", maximum=255)
        lease_expires_at = _aware_datetime(self.lease_expires_at, field_name="lease_expires_at")
        if type(self.outcome) is not str or self.outcome not in {"succeeded", "degraded"}:
            raise OutboxValidation("Completion outcome is outside its closed registry")
        _lower_sha256(self.requested_output_checksum, field_name="requested_output_checksum")
        if self.committed_output_checksum is not None:
            _lower_sha256(self.committed_output_checksum, field_name="committed_output_checksum")
        for field_name in (
            "previous_workflow_state_version",
            "workflow_state_version",
            "previous_stage_state_version",
            "stage_state_version",
            "previous_attempt_state_version",
            "attempt_state_version",
        ):
            _state_version(getattr(self, field_name), field_name=field_name)
        if type(self.workflow_status) is not str or self.workflow_status not in {
            "running",
            "succeeded",
            "degraded",
        }:
            raise OutboxValidation("Completion workflow status is outside its closed registry")
        completed_at = None
        if self.completed_at is not None:
            completed_at = _aware_datetime(self.completed_at, field_name="completed_at")
        workflow_completed_at = None
        if self.workflow_completed_at is not None:
            workflow_completed_at = _aware_datetime(
                self.workflow_completed_at,
                field_name="workflow_completed_at",
            )
        if type(self.emissions) is not tuple or any(type(item) is not CoordinatedStageEmission for item in self.emissions):
            raise OutboxValidation("Completion emissions must be an exact tuple of public facts")
        copied_emissions = tuple(
            CoordinatedStageEmission(
                stage_run_id=item.stage_run_id,
                stage_key=item.stage_key,
                stage_state_version=item.stage_state_version,
                message_id=item.message_id,
                logical_key=item.logical_key,
                available_at=item.available_at,
            )
            for item in self.emissions
        )
        if any(
            len({getattr(item, field_name) for item in copied_emissions}) != len(copied_emissions)
            for field_name in ("stage_run_id", "stage_key", "message_id", "logical_key")
        ):
            raise OutboxValidation("Completion emissions contain duplicate identities")
        if type(self.disposition) is not str or self.disposition not in {"completed", "stale"}:
            raise OutboxValidation("Coordinated completion disposition is outside its closed registry")
        if type(self.should_continue) is not bool or self.should_continue:
            raise OutboxValidation("Completion must never authorize continued execution")
        if type(self.should_ack) is not bool or not self.should_ack:
            raise OutboxValidation("Completion and stale dispositions must acknowledge the terminal broker delivery")

        if self.disposition == "completed":
            if (
                completed_at is None
                or self.committed_output_checksum != self.requested_output_checksum
                or self.stage_state_version != self.previous_stage_state_version + 1
                or self.attempt_state_version != self.previous_attempt_state_version + 1
                or any(item.available_at != completed_at for item in copied_emissions)
            ):
                raise OutboxValidation("Completed result does not describe one exact terminal mutation")
            if self.workflow_status == "running":
                if self.workflow_state_version != self.previous_workflow_state_version or workflow_completed_at is not None:
                    raise OutboxValidation("Active workflow completion result claims an aggregate mutation")
            elif self.workflow_state_version != self.previous_workflow_state_version + 1 or workflow_completed_at != completed_at:
                raise OutboxValidation("Terminal workflow completion result lacks its exact aggregate mutation")
            elif copied_emissions or (self.workflow_status == "succeeded" and self.outcome != "succeeded"):
                raise OutboxValidation("Terminal workflow completion result contradicts its stage outcomes")
        elif (
            self.committed_output_checksum is not None
            or completed_at is not None
            or workflow_completed_at is not None
            or copied_emissions
            or self.workflow_status != "running"
            or self.workflow_state_version != self.previous_workflow_state_version
            or self.stage_state_version != self.previous_stage_state_version
            or self.attempt_state_version != self.previous_attempt_state_version
        ):
            raise OutboxValidation("Stale completion cannot claim a durable mutation")
        object.__setattr__(self, "lease_expires_at", lease_expires_at)
        object.__setattr__(self, "emissions", copied_emissions)


@dataclass(frozen=True, slots=True)
class CoordinatedStageFailure:
    """Commit-confirmed worker failure facts with no executable authority."""

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("CoordinatedStageFailure is sealed and cannot be subclassed")

    workflow_run_id: uuid.UUID
    stage_run_id: uuid.UUID
    stage_attempt_id: uuid.UUID
    message_id: uuid.UUID
    delivery_attempt_id: uuid.UUID
    stage_lease_token: uuid.UUID
    attempt_number: int
    delivery_cycle: int
    cycle_key: str
    broker_receipt_id: str
    stage_key: str
    input_checksum: str
    checkpoint_version: int
    lease_owner: str
    lease_expires_at: datetime
    error_code: str
    error_class: str
    error_summary: str
    retryable: bool
    decision: FailureDecision | None
    previous_workflow_state_version: int
    workflow_state_version: int
    workflow_status: str
    previous_stage_state_version: int
    stage_state_version: int
    previous_attempt_state_version: int
    attempt_state_version: int
    attempt_completed_at: datetime | None
    stage_completed_at: datetime | None
    workflow_completed_at: datetime | None
    next_attempt_at: datetime | None
    skipped_stage_ids: tuple[uuid.UUID, ...]
    cancelled_stage_ids: tuple[uuid.UUID, ...]
    cancelled_attempt_ids: tuple[uuid.UUID, ...]
    cancelled_message_ids: tuple[uuid.UUID, ...]
    cancelled_delivery_ids: tuple[uuid.UUID, ...]
    retry_emission: CoordinatedStageEmission | None
    disposition: FailureDisposition
    should_retry: bool
    should_continue: bool
    should_ack: bool

    def __post_init__(self) -> None:
        if type(self) is not CoordinatedStageFailure:
            raise OutboxValidation("Coordinated failure must use its exact public result type")
        for field_name in (
            "workflow_run_id",
            "stage_run_id",
            "stage_attempt_id",
            "message_id",
            "delivery_attempt_id",
            "stage_lease_token",
        ):
            _exact_uuid(getattr(self, field_name), field_name=field_name)
        _bounded_int(self.attempt_number, field_name="attempt_number", minimum=1, maximum=20)
        _bounded_int(
            self.delivery_cycle,
            field_name="delivery_cycle",
            minimum=1,
            maximum=MAX_OUTBOX_DELIVERY_CYCLE,
        )
        _lower_sha256(self.cycle_key, field_name="cycle_key")
        _lower_sha256(self.broker_receipt_id, field_name="broker_receipt_id")
        _identity(self.stage_key, field_name="stage_key")
        _lower_sha256(self.input_checksum, field_name="input_checksum")
        _bounded_int(
            self.checkpoint_version,
            field_name="checkpoint_version",
            minimum=0,
            maximum=2_147_483_647,
        )
        _text(self.lease_owner, field_name="lease_owner", maximum=255)
        lease_expires_at = _aware_datetime(self.lease_expires_at, field_name="lease_expires_at")
        safe_evidence = _public_failure_evidence(
            code=self.error_code,
            error_class=self.error_class,
            summary=self.error_summary,
            retryable=self.retryable,
        )
        for field_name in (
            "previous_workflow_state_version",
            "workflow_state_version",
            "previous_stage_state_version",
            "stage_state_version",
            "previous_attempt_state_version",
            "attempt_state_version",
        ):
            _state_version(getattr(self, field_name), field_name=field_name)
        if type(self.workflow_status) is not str or self.workflow_status not in {
            "running",
            "degraded",
            "failed",
            "dead_lettered",
        }:
            raise OutboxValidation("Failure workflow status is outside its closed registry")
        if self.decision is not None and (type(self.decision) is not str or self.decision not in {"retry", "failed", "dead_lettered"}):
            raise OutboxValidation("Failure decision is outside its closed registry")
        times: dict[str, datetime | None] = {}
        for field_name in (
            "attempt_completed_at",
            "stage_completed_at",
            "workflow_completed_at",
            "next_attempt_at",
        ):
            value = getattr(self, field_name)
            times[field_name] = None if value is None else _aware_datetime(value, field_name=field_name)
        copied_ids: dict[str, tuple[uuid.UUID, ...]] = {}
        for field_name in (
            "skipped_stage_ids",
            "cancelled_stage_ids",
            "cancelled_attempt_ids",
            "cancelled_message_ids",
            "cancelled_delivery_ids",
        ):
            values = getattr(self, field_name)
            if type(values) is not tuple:
                raise OutboxValidation(f"{field_name} must be an exact tuple")
            copied = tuple(_exact_uuid(value, field_name=field_name) for value in values)
            if len(set(copied)) != len(copied):
                raise OutboxValidation(f"{field_name} must contain unique identities")
            if field_name in {
                "cancelled_attempt_ids",
                "cancelled_message_ids",
                "cancelled_delivery_ids",
            } and copied != tuple(sorted(copied, key=lambda value: value.int)):
                raise OutboxValidation(f"{field_name} must be in canonical UUID order")
            copied_ids[field_name] = copied
        if self.stage_run_id in copied_ids["skipped_stage_ids"] or self.stage_run_id in copied_ids["cancelled_stage_ids"]:
            raise OutboxValidation("Failure collateral stage effects cannot include the source stage")
        if self.stage_attempt_id in copied_ids["cancelled_attempt_ids"]:
            raise OutboxValidation("Failure collateral attempt effects cannot include the source attempt")
        if self.message_id in copied_ids["cancelled_message_ids"]:
            raise OutboxValidation("Failure collateral message effects cannot include the source message")
        if self.delivery_attempt_id in copied_ids["cancelled_delivery_ids"]:
            raise OutboxValidation("Failure collateral delivery effects cannot include the source delivery")
        if (
            copied_ids["cancelled_attempt_ids"] or copied_ids["cancelled_message_ids"] or copied_ids["cancelled_delivery_ids"]
        ) and not copied_ids["cancelled_stage_ids"]:
            raise OutboxValidation("Failure collateral cancellation effects require at least one cancelled stage")
        if len(copied_ids["cancelled_attempt_ids"]) > len(copied_ids["cancelled_stage_ids"]):
            raise OutboxValidation("Failure cancellation attempts cannot outnumber cancelled stages")
        if len(copied_ids["cancelled_delivery_ids"]) > len(copied_ids["cancelled_message_ids"]):
            raise OutboxValidation("Failure cancellation deliveries cannot outnumber cancelled messages")
        if set(copied_ids["skipped_stage_ids"]).intersection(copied_ids["cancelled_stage_ids"]):
            raise OutboxValidation("Failure skipped and cancelled stage effects must be disjoint")
        emission = self.retry_emission
        if emission is not None:
            if type(emission) is not CoordinatedStageEmission:
                raise OutboxValidation("Failure retry emission must use its exact public fact type")
            emission = CoordinatedStageEmission(
                stage_run_id=emission.stage_run_id,
                stage_key=emission.stage_key,
                stage_state_version=emission.stage_state_version,
                message_id=emission.message_id,
                logical_key=emission.logical_key,
                available_at=emission.available_at,
            )
            if emission.message_id == self.message_id:
                raise OutboxValidation("Failure retry emission cannot reuse the delivered source message")
        if type(self.disposition) is not str or self.disposition not in {"recorded", "stale"}:
            raise OutboxValidation("Coordinated failure disposition is outside its closed registry")
        if type(self.should_retry) is not bool or self.should_retry != (self.disposition == "recorded" and self.decision == "retry"):
            raise OutboxValidation("Failure retry advice must be exactly decision-derived")
        if type(self.should_continue) is not bool or self.should_continue:
            raise OutboxValidation("Failure must never authorize continued execution")
        if type(self.should_ack) is not bool or not self.should_ack:
            raise OutboxValidation("Recorded and stale failures must acknowledge the broker delivery")

        attempt_completed = times["attempt_completed_at"]
        stage_completed = times["stage_completed_at"]
        workflow_completed = times["workflow_completed_at"]
        next_attempt = times["next_attempt_at"]
        has_effect_ids = any(copied_ids.values())
        if self.disposition == "stale":
            if (
                self.decision is not None
                or self.workflow_status != "running"
                or self.workflow_state_version != self.previous_workflow_state_version
                or self.stage_state_version != self.previous_stage_state_version
                or self.attempt_state_version != self.previous_attempt_state_version
                or any(value is not None for value in times.values())
                or has_effect_ids
                or emission is not None
            ):
                raise OutboxValidation("Stale failure cannot claim a durable mutation")
        else:
            if (
                self.decision is None
                or attempt_completed is None
                or self.stage_state_version != self.previous_stage_state_version + 1
                or self.attempt_state_version != self.previous_attempt_state_version + 1
            ):
                raise OutboxValidation("Recorded failure lacks one exact attempt and stage mutation")
            if self.decision == "retry":
                if (
                    not safe_evidence.retryable
                    or next_attempt is None
                    or stage_completed is not None
                    or workflow_completed is not None
                    or self.workflow_status != "running"
                    or self.workflow_state_version != self.previous_workflow_state_version
                    or has_effect_ids
                    or emission is None
                    or emission.stage_run_id != self.stage_run_id
                    or emission.stage_key != self.stage_key
                    or emission.stage_state_version != self.stage_state_version
                    or emission.available_at != next_attempt
                ):
                    raise OutboxValidation("Recorded retry failure lacks its exact scheduled emission")
                retry_delay = next_attempt - attempt_completed
                if retry_delay.microseconds != 0 or not timedelta(seconds=1) <= retry_delay <= timedelta(seconds=86_400):
                    raise OutboxValidation("Recorded retry failure has an invalid bounded retry delay")
            else:
                if next_attempt is not None or emission is not None or stage_completed != attempt_completed:
                    raise OutboxValidation("Recorded terminal failure has contradictory retry or completion facts")
                if self.decision == "failed" and safe_evidence.retryable:
                    raise OutboxValidation("Failed decision cannot retain retryable evidence")
                if self.decision == "dead_lettered" and not safe_evidence.retryable:
                    raise OutboxValidation("Dead-letter decision requires retryable exhausted evidence")
                if self.workflow_status == "running":
                    if self.workflow_state_version != self.previous_workflow_state_version or workflow_completed is not None:
                        raise OutboxValidation("Active failure result claims a workflow aggregate mutation")
                elif self.workflow_state_version != self.previous_workflow_state_version + 1 or workflow_completed != attempt_completed:
                    raise OutboxValidation("Terminal failure result lacks its exact workflow aggregate mutation")
                if (
                    (self.workflow_status == "failed" and self.decision != "failed")
                    or (self.workflow_status == "dead_lettered" and self.decision != "dead_lettered")
                    or (
                        any(
                            copied_ids[field_name]
                            for field_name in (
                                "cancelled_stage_ids",
                                "cancelled_attempt_ids",
                                "cancelled_message_ids",
                                "cancelled_delivery_ids",
                            )
                        )
                        and self.workflow_status not in {"failed", "dead_lettered"}
                    )
                    or (copied_ids["skipped_stage_ids"] and self.workflow_status in {"failed", "dead_lettered"})
                ):
                    raise OutboxValidation("Failure effect identities contradict their aggregate outcome")
        for field_name, values in copied_ids.items():
            object.__setattr__(self, field_name, values)
        object.__setattr__(self, "lease_expires_at", lease_expires_at)
        object.__setattr__(self, "retry_emission", emission)


@dataclass(frozen=True, slots=True)
class CoordinatedStageHeartbeat:
    """Post-transaction worker decision with no live ORM authority.

    Version and time fields are the last facts proven by this coordinator.
    For an initially stale presentation they equal the presented authority;
    for a confirmation-time stale result they describe the committed
    heartbeat, but ``should_continue`` remains false because its current lease
    could not be reconfirmed.
    """

    workflow_run_id: uuid.UUID
    stage_run_id: uuid.UUID
    stage_attempt_id: uuid.UUID
    message_id: uuid.UUID
    delivery_attempt_id: uuid.UUID
    stage_lease_token: uuid.UUID
    attempt_number: int
    delivery_cycle: int
    cycle_key: str
    broker_receipt_id: str
    stage_key: str
    input_checksum: str
    checkpoint_version: int
    lease_owner: str
    workflow_state_version: int
    previous_stage_state_version: int
    stage_state_version: int
    previous_attempt_state_version: int
    attempt_state_version: int
    previous_lease_expires_at: datetime
    heartbeat_at: datetime | None
    lease_expires_at: datetime
    disposition: HeartbeatDisposition
    authority: ExecutableStageAuthority | None = field(repr=False)
    should_continue: bool

    def __post_init__(self) -> None:
        if type(self) is not CoordinatedStageHeartbeat:
            raise OutboxValidation("Coordinated heartbeat must use its exact public result type")
        for field_name in (
            "workflow_run_id",
            "stage_run_id",
            "stage_attempt_id",
            "message_id",
            "delivery_attempt_id",
            "stage_lease_token",
        ):
            _exact_uuid(getattr(self, field_name), field_name=field_name)
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
        _identity(self.stage_key, field_name="stage_key")
        _lower_sha256(self.input_checksum, field_name="input_checksum")
        _bounded_int(
            self.checkpoint_version,
            field_name="checkpoint_version",
            minimum=0,
            maximum=2_147_483_647,
        )
        _text(self.lease_owner, field_name="lease_owner", maximum=255)
        for field_name in (
            "workflow_state_version",
            "previous_stage_state_version",
            "stage_state_version",
            "previous_attempt_state_version",
            "attempt_state_version",
        ):
            _state_version(getattr(self, field_name), field_name=field_name)
        previous_expiry = _aware_datetime(
            self.previous_lease_expires_at,
            field_name="previous_lease_expires_at",
        )
        expiry = _aware_datetime(
            self.lease_expires_at,
            field_name="lease_expires_at",
        )
        heartbeat = None
        if self.heartbeat_at is not None:
            heartbeat = _aware_datetime(self.heartbeat_at, field_name="heartbeat_at")
        if type(self.disposition) is not str or self.disposition not in {"renewed", "stale"}:
            raise OutboxValidation("Coordinated heartbeat disposition is outside its closed registry")
        if type(self.should_continue) is not bool or self.should_continue != (self.disposition == "renewed"):
            raise OutboxValidation("Heartbeat continuation decision must be exactly disposition-derived")

        heartbeat_was_written = heartbeat is not None
        if heartbeat_was_written:
            if (
                self.stage_state_version != self.previous_stage_state_version + 1
                or self.attempt_state_version != self.previous_attempt_state_version + 1
                or expiry < previous_expiry
                or expiry <= heartbeat
            ):
                raise OutboxValidation("Heartbeat result does not describe one exact monotonic renewal")
        elif (
            self.stage_state_version != self.previous_stage_state_version
            or self.attempt_state_version != self.previous_attempt_state_version
            or expiry != previous_expiry
        ):
            raise OutboxValidation("Initially stale heartbeat cannot claim a durable mutation")

        if self.disposition == "renewed":
            if not heartbeat_was_written:
                raise OutboxValidation("Renewed heartbeat requires committed heartbeat evidence")
            authority = _copy_public_authority(self.authority)
            _assert_result_authority(self, authority)
            object.__setattr__(self, "authority", authority)
        elif self.authority is not None:
            raise OutboxValidation("Stale heartbeat cannot expose executable authority")


@dataclass(frozen=True, slots=True)
class CoordinatedStageCheckpoint:
    """Post-transaction checkpoint facts and, only when confirmed, authority."""

    workflow_run_id: uuid.UUID
    stage_run_id: uuid.UUID
    stage_attempt_id: uuid.UUID
    message_id: uuid.UUID
    delivery_attempt_id: uuid.UUID
    stage_lease_token: uuid.UUID
    attempt_number: int
    delivery_cycle: int
    cycle_key: str
    broker_receipt_id: str
    stage_key: str
    input_checksum: str
    checkpoint_schema_version: str
    requested_checkpoint_checksum: str
    committed_checkpoint_checksum: str | None
    lease_owner: str
    workflow_state_version: int
    previous_checkpoint_version: int
    checkpoint_version: int
    previous_stage_state_version: int
    stage_state_version: int
    previous_attempt_state_version: int
    attempt_state_version: int
    previous_lease_expires_at: datetime
    heartbeat_at: datetime | None
    lease_expires_at: datetime
    disposition: CheckpointDisposition
    authority: ExecutableStageAuthority | None = field(repr=False)
    should_continue: bool

    def __post_init__(self) -> None:
        if type(self) is not CoordinatedStageCheckpoint:
            raise OutboxValidation("Coordinated checkpoint must use its exact public result type")
        for field_name in (
            "workflow_run_id",
            "stage_run_id",
            "stage_attempt_id",
            "message_id",
            "delivery_attempt_id",
            "stage_lease_token",
        ):
            _exact_uuid(getattr(self, field_name), field_name=field_name)
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
        _identity(self.stage_key, field_name="stage_key")
        _lower_sha256(self.input_checksum, field_name="input_checksum")
        _version_identity(
            self.checkpoint_schema_version,
            field_name="checkpoint_schema_version",
        )
        _lower_sha256(
            self.requested_checkpoint_checksum,
            field_name="requested_checkpoint_checksum",
        )
        if self.committed_checkpoint_checksum is not None:
            _lower_sha256(
                self.committed_checkpoint_checksum,
                field_name="committed_checkpoint_checksum",
            )
        _text(self.lease_owner, field_name="lease_owner", maximum=255)
        _bounded_int(
            self.previous_checkpoint_version,
            field_name="previous_checkpoint_version",
            minimum=0,
            maximum=2_147_483_647,
        )
        _bounded_int(
            self.checkpoint_version,
            field_name="checkpoint_version",
            minimum=0,
            maximum=2_147_483_647,
        )
        for field_name in (
            "workflow_state_version",
            "previous_stage_state_version",
            "stage_state_version",
            "previous_attempt_state_version",
            "attempt_state_version",
        ):
            _state_version(getattr(self, field_name), field_name=field_name)
        previous_expiry = _aware_datetime(
            self.previous_lease_expires_at,
            field_name="previous_lease_expires_at",
        )
        expiry = _aware_datetime(self.lease_expires_at, field_name="lease_expires_at")
        heartbeat = None
        if self.heartbeat_at is not None:
            heartbeat = _aware_datetime(self.heartbeat_at, field_name="heartbeat_at")
        if type(self.disposition) is not str or self.disposition not in {"renewed", "stale"}:
            raise OutboxValidation("Coordinated checkpoint disposition is outside its closed registry")
        if type(self.should_continue) is not bool or self.should_continue != (self.disposition == "renewed"):
            raise OutboxValidation("Checkpoint continuation decision must be exactly disposition-derived")

        checkpoint_was_written = heartbeat is not None
        if checkpoint_was_written:
            if (
                self.committed_checkpoint_checksum != self.requested_checkpoint_checksum
                or self.checkpoint_version != self.previous_checkpoint_version + 1
                or self.stage_state_version != self.previous_stage_state_version + 1
                or self.attempt_state_version != self.previous_attempt_state_version + 1
                or expiry < previous_expiry
                or expiry <= heartbeat
            ):
                raise OutboxValidation("Checkpoint result does not describe one exact monotonic write")
        elif (
            self.committed_checkpoint_checksum is not None
            or self.checkpoint_version != self.previous_checkpoint_version
            or self.stage_state_version != self.previous_stage_state_version
            or self.attempt_state_version != self.previous_attempt_state_version
            or expiry != previous_expiry
        ):
            raise OutboxValidation("Initially stale checkpoint cannot claim a durable mutation")

        if self.disposition == "renewed":
            if not checkpoint_was_written:
                raise OutboxValidation("Renewed checkpoint requires committed checkpoint evidence")
            authority = _copy_public_authority(self.authority)
            _assert_checkpoint_result_authority(self, authority)
            object.__setattr__(self, "authority", authority)
        elif self.authority is not None:
            raise OutboxValidation("Stale checkpoint cannot expose executable authority")


@dataclass(frozen=True, slots=True)
class _StageCompletionEmissionFacts:
    """Private post-flush emission facts that carry no append capability."""

    stage_run_id: uuid.UUID
    stage_key: str
    stage_state_version: int
    message_id: uuid.UUID
    logical_key: str
    available_at: datetime

    def __post_init__(self) -> None:
        if type(self) is not _StageCompletionEmissionFacts:
            raise WorkflowStoredContractError("Completion emission facts must use their exact private type")
        try:
            _exact_uuid(self.stage_run_id, field_name="completion emission stage_run_id")
            _identity(self.stage_key, field_name="completion emission stage_key")
            _state_version(self.stage_state_version, field_name="completion emission stage_state_version")
            _exact_uuid(self.message_id, field_name="completion emission message_id")
            _lower_sha256(self.logical_key, field_name="completion emission logical_key")
        except (OutboxValidation, WorkflowValidation) as exc:
            raise WorkflowStoredContractError("Completion emission facts are invalid") from exc
        _aware_internal_datetime(self.available_at, field_name="completion emission available_at")


@dataclass(frozen=True, slots=True)
class _StageCompletionMutationFacts:
    """Capability-free facts retained until the mutation context commits."""

    outcome: CompletionOutcome
    requested_output_checksum: str
    committed_output_checksum: str
    workflow_state_version: int
    workflow_status: Literal["running", "succeeded", "degraded"]
    stage_state_version: int
    attempt_state_version: int
    completed_at: datetime
    workflow_completed_at: datetime | None
    emissions: tuple[_StageCompletionEmissionFacts, ...]

    def __post_init__(self) -> None:
        if type(self) is not _StageCompletionMutationFacts:
            raise WorkflowStoredContractError("Completion mutation facts must use their exact private type")
        if type(self.outcome) is not str or self.outcome not in {"succeeded", "degraded"}:
            raise WorkflowStoredContractError("Completion mutation outcome is invalid")
        try:
            requested = _lower_sha256(
                self.requested_output_checksum,
                field_name="completion requested output checksum",
            )
            committed = _lower_sha256(
                self.committed_output_checksum,
                field_name="completion committed output checksum",
            )
            workflow_version = _state_version(
                self.workflow_state_version,
                field_name="completion workflow state_version",
            )
            stage_version = _state_version(
                self.stage_state_version,
                field_name="completion stage state_version",
            )
            attempt_version = _state_version(
                self.attempt_state_version,
                field_name="completion attempt state_version",
            )
        except (OutboxValidation, WorkflowValidation) as exc:
            raise WorkflowStoredContractError("Completion mutation facts are invalid") from exc
        if requested != committed:
            raise WorkflowStoredContractError("Completion mutation changed its validated output")
        if type(self.workflow_status) is not str or self.workflow_status not in {
            "running",
            "succeeded",
            "degraded",
        }:
            raise WorkflowStoredContractError("Completion mutation workflow status is invalid")
        completed = _aware_internal_datetime(self.completed_at, field_name="completion completed_at")
        workflow_completed = None
        if self.workflow_completed_at is not None:
            workflow_completed = _aware_internal_datetime(
                self.workflow_completed_at,
                field_name="completion workflow_completed_at",
            )
        if (self.workflow_status == "running") != (workflow_completed is None):
            raise WorkflowStoredContractError("Completion aggregate facts contradict workflow status")
        if workflow_completed is not None and workflow_completed != completed:
            raise WorkflowStoredContractError("Completion aggregate timestamp changed from its source cutover")
        if type(self.emissions) is not tuple or any(type(item) is not _StageCompletionEmissionFacts for item in self.emissions):
            raise WorkflowStoredContractError("Completion mutation emissions are invalid")
        if any(item.available_at != completed for item in self.emissions):
            raise WorkflowStoredContractError("Completion emission time changed from its source cutover")
        if len({item.stage_run_id for item in self.emissions}) != len(self.emissions) or len(
            {item.message_id for item in self.emissions}
        ) != len(self.emissions):
            raise WorkflowStoredContractError("Completion mutation emissions contain duplicate identities")
        object.__setattr__(self, "requested_output_checksum", requested)
        object.__setattr__(self, "committed_output_checksum", committed)
        object.__setattr__(self, "workflow_state_version", workflow_version)
        object.__setattr__(self, "stage_state_version", stage_version)
        object.__setattr__(self, "attempt_state_version", attempt_version)
        object.__setattr__(self, "completed_at", completed)
        object.__setattr__(self, "workflow_completed_at", workflow_completed)


@dataclass(frozen=True, slots=True)
class _StageFailureRetryEmissionFacts:
    """Private post-flush retry emission facts with no append capability."""

    stage_run_id: uuid.UUID
    stage_key: str
    stage_state_version: int
    message_id: uuid.UUID
    logical_key: str
    available_at: datetime

    def __post_init__(self) -> None:
        if type(self) is not _StageFailureRetryEmissionFacts:
            raise WorkflowStoredContractError("Failure retry emission facts must use their exact private type")
        try:
            _exact_uuid(self.stage_run_id, field_name="failure retry emission stage_run_id")
            _identity(self.stage_key, field_name="failure retry emission stage_key")
            _state_version(self.stage_state_version, field_name="failure retry emission stage state_version")
            _exact_uuid(self.message_id, field_name="failure retry emission message_id")
            _lower_sha256(self.logical_key, field_name="failure retry emission logical_key")
        except (OutboxValidation, WorkflowValidation) as exc:
            raise WorkflowStoredContractError("Failure retry emission facts are invalid") from exc
        _aware_internal_datetime(self.available_at, field_name="failure retry emission available_at")


@dataclass(frozen=True, slots=True)
class _StageFailureMutationFacts:
    """Capability-free failure facts retained until the mutation commits."""

    evidence: StageFailureEvidence
    decision: FailureDecision
    workflow_state_version: int
    workflow_status: Literal["running", "degraded", "failed", "dead_lettered"]
    stage_state_version: int
    attempt_state_version: int
    attempt_completed_at: datetime
    stage_completed_at: datetime | None
    workflow_completed_at: datetime | None
    next_attempt_at: datetime | None
    skipped_stage_ids: tuple[uuid.UUID, ...]
    cancelled_stage_ids: tuple[uuid.UUID, ...]
    cancelled_attempt_ids: tuple[uuid.UUID, ...]
    cancelled_message_ids: tuple[uuid.UUID, ...]
    cancelled_delivery_ids: tuple[uuid.UUID, ...]
    retry_emission: _StageFailureRetryEmissionFacts | None

    def __post_init__(self) -> None:
        if type(self) is not _StageFailureMutationFacts:
            raise WorkflowStoredContractError("Failure mutation facts must use their exact private type")
        try:
            evidence = _copy_internal_failure_evidence(self.evidence)
            workflow_version = _state_version(
                self.workflow_state_version,
                field_name="failure workflow state_version",
            )
            stage_version = _state_version(
                self.stage_state_version,
                field_name="failure stage state_version",
            )
            attempt_version = _state_version(
                self.attempt_state_version,
                field_name="failure attempt state_version",
            )
        except (OutboxValidation, WorkflowValidation) as exc:
            raise WorkflowStoredContractError("Failure mutation facts are invalid") from exc
        if type(self.decision) is not str or self.decision not in {"retry", "failed", "dead_lettered"}:
            raise WorkflowStoredContractError("Failure mutation decision is invalid")
        if type(self.workflow_status) is not str or self.workflow_status not in {
            "running",
            "degraded",
            "failed",
            "dead_lettered",
        }:
            raise WorkflowStoredContractError("Failure mutation workflow status is invalid")
        attempt_completed = _aware_internal_datetime(
            self.attempt_completed_at,
            field_name="failure attempt_completed_at",
        )
        stage_completed = (
            None
            if self.stage_completed_at is None
            else _aware_internal_datetime(self.stage_completed_at, field_name="failure stage_completed_at")
        )
        workflow_completed = (
            None
            if self.workflow_completed_at is None
            else _aware_internal_datetime(self.workflow_completed_at, field_name="failure workflow_completed_at")
        )
        next_attempt = (
            None if self.next_attempt_at is None else _aware_internal_datetime(self.next_attempt_at, field_name="failure next_attempt_at")
        )
        copied_ids: dict[str, tuple[uuid.UUID, ...]] = {}
        for field_name in (
            "skipped_stage_ids",
            "cancelled_stage_ids",
            "cancelled_attempt_ids",
            "cancelled_message_ids",
            "cancelled_delivery_ids",
        ):
            values = getattr(self, field_name)
            if type(values) is not tuple:
                raise WorkflowStoredContractError(f"Failure {field_name} is not an exact tuple")
            try:
                copied = tuple(_exact_uuid(value, field_name=field_name) for value in values)
            except OutboxValidation as exc:
                raise WorkflowStoredContractError(f"Failure {field_name} contains invalid authority") from exc
            if len(set(copied)) != len(copied):
                raise WorkflowStoredContractError(f"Failure {field_name} contains duplicate identities")
            if field_name in {
                "cancelled_attempt_ids",
                "cancelled_message_ids",
                "cancelled_delivery_ids",
            } and copied != tuple(sorted(copied, key=lambda value: value.int)):
                raise WorkflowStoredContractError(f"Failure {field_name} is not in canonical UUID order")
            copied_ids[field_name] = copied
        if (
            copied_ids["cancelled_attempt_ids"] or copied_ids["cancelled_message_ids"] or copied_ids["cancelled_delivery_ids"]
        ) and not copied_ids["cancelled_stage_ids"]:
            raise WorkflowStoredContractError("Failure collateral cancellation facts lack a cancelled stage")
        if len(copied_ids["cancelled_attempt_ids"]) > len(copied_ids["cancelled_stage_ids"]):
            raise WorkflowStoredContractError("Failure cancellation attempts outnumber cancelled stages")
        if len(copied_ids["cancelled_delivery_ids"]) > len(copied_ids["cancelled_message_ids"]):
            raise WorkflowStoredContractError("Failure cancellation deliveries outnumber cancelled messages")
        emission = self.retry_emission
        if emission is not None and type(emission) is not _StageFailureRetryEmissionFacts:
            raise WorkflowStoredContractError("Failure retry emission facts are invalid")
        if self.decision == "retry":
            if (
                not evidence.retryable
                or self.workflow_status != "running"
                or stage_completed is not None
                or workflow_completed is not None
                or next_attempt is None
                or emission is None
                or emission.available_at != next_attempt
                or any(copied_ids.values())
            ):
                raise WorkflowStoredContractError("Retry failure mutation facts are contradictory")
            retry_delay = next_attempt - attempt_completed
            if retry_delay.microseconds != 0 or not timedelta(seconds=1) <= retry_delay <= timedelta(seconds=86_400):
                raise WorkflowStoredContractError("Retry failure mutation facts have an invalid bounded retry delay")
        elif (
            next_attempt is not None
            or emission is not None
            or stage_completed != attempt_completed
            or (self.decision == "failed" and evidence.retryable)
            or (self.decision == "dead_lettered" and not evidence.retryable)
        ):
            raise WorkflowStoredContractError("Terminal failure mutation facts are contradictory")
        if (
            (self.workflow_status == "failed" and self.decision != "failed")
            or (self.workflow_status == "dead_lettered" and self.decision != "dead_lettered")
            or (
                any(
                    copied_ids[field_name]
                    for field_name in (
                        "cancelled_stage_ids",
                        "cancelled_attempt_ids",
                        "cancelled_message_ids",
                        "cancelled_delivery_ids",
                    )
                )
                and self.workflow_status not in {"failed", "dead_lettered"}
            )
            or (copied_ids["skipped_stage_ids"] and self.workflow_status in {"failed", "dead_lettered"})
        ):
            raise WorkflowStoredContractError("Failure settlement facts contradict their aggregate outcome")
        if (self.workflow_status == "running") != (workflow_completed is None):
            raise WorkflowStoredContractError("Failure aggregate timestamp contradicts workflow status")
        if workflow_completed is not None and workflow_completed != attempt_completed:
            raise WorkflowStoredContractError("Failure aggregate time changed from its source cutover")
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "workflow_state_version", workflow_version)
        object.__setattr__(self, "stage_state_version", stage_version)
        object.__setattr__(self, "attempt_state_version", attempt_version)
        object.__setattr__(self, "attempt_completed_at", attempt_completed)
        object.__setattr__(self, "stage_completed_at", stage_completed)
        object.__setattr__(self, "workflow_completed_at", workflow_completed)
        object.__setattr__(self, "next_attempt_at", next_attempt)
        for field_name, values in copied_ids.items():
            object.__setattr__(self, field_name, values)


@dataclass(frozen=True, slots=True)
class _WorkflowCancellationMutationFacts:
    """Capability-free cancellation facts retained until context commit."""

    command: WorkflowCancellationCommand
    decision: Literal["apply", "replay"]
    workflow_state_version: int
    cancelled_at: datetime
    cancelled_stage_ids: tuple[uuid.UUID, ...]
    cancelled_attempt_ids: tuple[uuid.UUID, ...]
    cancelled_message_ids: tuple[uuid.UUID, ...]
    cancelled_delivery_ids: tuple[uuid.UUID, ...]

    def __post_init__(self) -> None:
        if type(self) is not _WorkflowCancellationMutationFacts:
            raise WorkflowStoredContractError("Cancellation mutation facts must use their exact private type")
        command = _copy_internal_cancellation_command(self.command)
        if type(self.decision) is not str or self.decision not in {"apply", "replay"}:
            raise WorkflowStoredContractError("Cancellation mutation decision is invalid")
        try:
            workflow_version = _state_version(
                self.workflow_state_version,
                field_name="cancellation mutation workflow state_version",
            )
        except (OutboxValidation, WorkflowValidation) as exc:
            raise WorkflowStoredContractError("Cancellation mutation version is invalid") from exc
        if workflow_version != command.expected_workflow_state_version + 1:
            raise WorkflowStoredContractError("Cancellation mutation changed its predecessor version")
        cancelled_at = _aware_internal_datetime(
            self.cancelled_at,
            field_name="cancellation mutation cancelled_at",
        )
        copied: dict[str, tuple[uuid.UUID, ...]] = {}
        for field_name in (
            "cancelled_stage_ids",
            "cancelled_attempt_ids",
            "cancelled_message_ids",
            "cancelled_delivery_ids",
        ):
            values = _exact_internal_uuid_tuple(getattr(self, field_name), field_name=field_name)
            if field_name != "cancelled_stage_ids" and values != tuple(sorted(values, key=lambda value: value.int)):
                raise WorkflowStoredContractError(f"Cancellation {field_name} lost canonical order")
            copied[field_name] = values
        if self.decision == "replay" and any(copied.values()):
            raise WorkflowStoredContractError("Cancellation replay cannot claim new effects")
        if self.decision == "apply" and not copied["cancelled_stage_ids"]:
            raise WorkflowStoredContractError("Applied cancellation mutation lacks a cancelled stage")
        if (copied["cancelled_attempt_ids"] or copied["cancelled_message_ids"] or copied["cancelled_delivery_ids"]) and not copied[
            "cancelled_stage_ids"
        ]:
            raise WorkflowStoredContractError("Cancellation mutation details lack a cancelled stage")
        if len(copied["cancelled_attempt_ids"]) > len(copied["cancelled_stage_ids"]):
            raise WorkflowStoredContractError("Cancellation attempts outnumber cancelled stages")
        if len(copied["cancelled_delivery_ids"]) > len(copied["cancelled_message_ids"]):
            raise WorkflowStoredContractError("Cancellation deliveries outnumber cancelled messages")
        object.__setattr__(self, "command", command)
        object.__setattr__(self, "workflow_state_version", workflow_version)
        object.__setattr__(self, "cancelled_at", cancelled_at)
        for field_name, values in copied.items():
            object.__setattr__(self, field_name, values)


@dataclass(frozen=True, slots=True)
class _StageRecoveryRetryEmissionFacts:
    """Private query-free facts for one committed lease-recovery root."""

    stage_run_id: uuid.UUID
    stage_key: str
    stage_state_version: int
    message_id: uuid.UUID
    logical_key: str
    available_at: datetime

    def __post_init__(self) -> None:
        if type(self) is not _StageRecoveryRetryEmissionFacts:
            raise WorkflowStoredContractError("Recovery emission facts must use their exact private type")
        try:
            _exact_uuid(self.stage_run_id, field_name="recovery emission stage_run_id")
            _identity(self.stage_key, field_name="recovery emission stage_key")
            _state_version(self.stage_state_version, field_name="recovery emission stage state_version")
            _exact_uuid(self.message_id, field_name="recovery emission message_id")
            _lower_sha256(self.logical_key, field_name="recovery emission logical_key")
        except (OutboxValidation, WorkflowValidation) as exc:
            raise WorkflowStoredContractError("Recovery emission facts are invalid") from exc
        _aware_internal_datetime(self.available_at, field_name="recovery emission available_at")


@dataclass(frozen=True, slots=True)
class _StageRecoveryMutationFacts:
    """Capability-free expired-receipt mutation facts held until commit."""

    workflow_run_id: uuid.UUID
    stage_run_id: uuid.UUID
    stage_attempt_id: uuid.UUID
    message_id: uuid.UUID
    delivery_attempt_id: uuid.UUID
    stage_lease_token: uuid.UUID
    attempt_number: int
    delivery_cycle: int
    cycle_key: str
    broker_receipt_id: str
    stage_key: str
    input_checksum: str
    checkpoint_version: int
    lease_owner: str
    lease_expires_at: datetime
    decision: RecoveryDecision
    previous_workflow_state_version: int
    workflow_state_version: int
    workflow_status: Literal["running", "degraded", "dead_lettered"]
    previous_stage_state_version: int
    stage_state_version: int
    previous_attempt_state_version: int
    attempt_state_version: int
    recovered_at: datetime
    next_attempt_at: datetime | None
    skipped_stage_ids: tuple[uuid.UUID, ...]
    cancelled_stage_ids: tuple[uuid.UUID, ...]
    cancelled_attempt_ids: tuple[uuid.UUID, ...]
    cancelled_message_ids: tuple[uuid.UUID, ...]
    cancelled_delivery_ids: tuple[uuid.UUID, ...]
    retry_emission: _StageRecoveryRetryEmissionFacts | None

    def __post_init__(self) -> None:
        if type(self) is not _StageRecoveryMutationFacts:
            raise WorkflowStoredContractError("Recovery mutation facts must use their exact private type")
        try:
            for field_name in (
                "workflow_run_id",
                "stage_run_id",
                "stage_attempt_id",
                "message_id",
                "delivery_attempt_id",
                "stage_lease_token",
            ):
                _exact_uuid(getattr(self, field_name), field_name=field_name)
            _bounded_int(self.attempt_number, field_name="recovery attempt_number", minimum=1, maximum=20)
            _bounded_int(
                self.delivery_cycle,
                field_name="recovery delivery_cycle",
                minimum=1,
                maximum=MAX_OUTBOX_DELIVERY_CYCLE,
            )
            _lower_sha256(self.cycle_key, field_name="recovery cycle_key")
            _lower_sha256(self.broker_receipt_id, field_name="recovery broker_receipt_id")
            _identity(self.stage_key, field_name="recovery stage_key")
            _lower_sha256(self.input_checksum, field_name="recovery input_checksum")
            _bounded_int(
                self.checkpoint_version,
                field_name="recovery checkpoint_version",
                minimum=0,
                maximum=2_147_483_647,
            )
            _text(self.lease_owner, field_name="recovery lease_owner", maximum=255)
            for field_name in (
                "previous_workflow_state_version",
                "workflow_state_version",
                "previous_stage_state_version",
                "stage_state_version",
                "previous_attempt_state_version",
                "attempt_state_version",
            ):
                _state_version(getattr(self, field_name), field_name=field_name)
        except (OutboxValidation, WorkflowValidation) as exc:
            raise WorkflowStoredContractError("Recovery mutation lineage is invalid") from exc
        if type(self.decision) is not str or self.decision not in {"retry", "dead_lettered"}:
            raise WorkflowStoredContractError("Recovery mutation decision is invalid")
        if type(self.workflow_status) is not str or self.workflow_status not in {
            "running",
            "degraded",
            "dead_lettered",
        }:
            raise WorkflowStoredContractError("Recovery mutation aggregate status is invalid")
        if (
            self.stage_state_version != self.previous_stage_state_version + 1
            or self.attempt_state_version != self.previous_attempt_state_version + 1
            or self.workflow_state_version != self.previous_workflow_state_version + int(self.workflow_status != "running")
        ):
            raise WorkflowStoredContractError("Recovery mutation versions are not exact")
        recovered_at = _aware_internal_datetime(self.recovered_at, field_name="recovery mutation time")
        lease_expires_at = _aware_internal_datetime(
            self.lease_expires_at,
            field_name="recovery mutation lease_expires_at",
        )
        if lease_expires_at > recovered_at:
            raise WorkflowStoredContractError("Recovery mutation does not prove an expired lease")
        next_attempt_at = (
            None if self.next_attempt_at is None else _aware_internal_datetime(self.next_attempt_at, field_name="recovery next_attempt_at")
        )
        copied: dict[str, tuple[uuid.UUID, ...]] = {}
        for field_name in (
            "skipped_stage_ids",
            "cancelled_stage_ids",
            "cancelled_attempt_ids",
            "cancelled_message_ids",
            "cancelled_delivery_ids",
        ):
            values = _exact_internal_uuid_tuple(getattr(self, field_name), field_name=field_name)
            if field_name in {
                "cancelled_attempt_ids",
                "cancelled_message_ids",
                "cancelled_delivery_ids",
            } and values != tuple(sorted(values, key=lambda value: value.int)):
                raise WorkflowStoredContractError(f"Recovery {field_name} lost canonical order")
            copied[field_name] = values
        emission = self.retry_emission
        if emission is not None and type(emission) is not _StageRecoveryRetryEmissionFacts:
            raise WorkflowStoredContractError("Recovery mutation emission facts are invalid")
        if self.stage_run_id in set(copied["skipped_stage_ids"] + copied["cancelled_stage_ids"]):
            raise WorkflowStoredContractError("Recovery collateral stages include the source")
        if self.stage_attempt_id in copied["cancelled_attempt_ids"]:
            raise WorkflowStoredContractError("Recovery collateral attempts include the source")
        if self.message_id in copied["cancelled_message_ids"]:
            raise WorkflowStoredContractError("Recovery collateral messages include the delivered source")
        if self.delivery_attempt_id in copied["cancelled_delivery_ids"]:
            raise WorkflowStoredContractError("Recovery collateral deliveries include the delivered source")
        if set(copied["skipped_stage_ids"]).intersection(copied["cancelled_stage_ids"]):
            raise WorkflowStoredContractError("Recovery skipped and cancelled stage effects overlap")
        if (copied["cancelled_attempt_ids"] or copied["cancelled_message_ids"] or copied["cancelled_delivery_ids"]) and not copied[
            "cancelled_stage_ids"
        ]:
            raise WorkflowStoredContractError("Recovery cancellation details lack a cancelled stage")
        if len(copied["cancelled_attempt_ids"]) > len(copied["cancelled_stage_ids"]):
            raise WorkflowStoredContractError("Recovery cancelled attempts outnumber cancelled stages")
        if len(copied["cancelled_delivery_ids"]) > len(copied["cancelled_message_ids"]):
            raise WorkflowStoredContractError("Recovery cancelled deliveries outnumber cancelled messages")
        if (
            any(
                copied[field_name]
                for field_name in (
                    "cancelled_stage_ids",
                    "cancelled_attempt_ids",
                    "cancelled_message_ids",
                    "cancelled_delivery_ids",
                )
            )
            and self.workflow_status != "dead_lettered"
        ) or (copied["skipped_stage_ids"] and self.workflow_status == "dead_lettered"):
            raise WorkflowStoredContractError("Recovery collateral facts contradict aggregate status")
        if self.decision == "retry":
            if (
                self.workflow_status != "running"
                or next_attempt_at is None
                or emission is None
                or emission.stage_run_id != self.stage_run_id
                or emission.stage_key != self.stage_key
                or emission.stage_state_version != self.stage_state_version
                or emission.available_at != next_attempt_at
                or emission.message_id == self.message_id
                or any(copied.values())
            ):
                raise WorkflowStoredContractError("Retry recovery mutation facts are contradictory")
            delay = next_attempt_at - recovered_at
            if delay.microseconds != 0 or not timedelta(seconds=1) <= delay <= timedelta(seconds=86_400):
                raise WorkflowStoredContractError("Recovery retry delay is outside its bounded contract")
        elif next_attempt_at is not None or emission is not None:
            raise WorkflowStoredContractError("Exhausted recovery retained retry facts")
        object.__setattr__(self, "recovered_at", recovered_at)
        object.__setattr__(self, "lease_expires_at", lease_expires_at)
        object.__setattr__(self, "next_attempt_at", next_attempt_at)
        for field_name, values in copied.items():
            object.__setattr__(self, field_name, values)


@dataclass(frozen=True, slots=True)
class _PendingStageHeartbeat:
    """Private, non-public candidate that is not executable before commit."""

    presented: ExecutableStageAuthority = field(repr=False)
    _candidate: ExecutableStageAuthority = field(repr=False)
    heartbeat_at: datetime

    def __post_init__(self) -> None:
        if type(self) is not _PendingStageHeartbeat:
            raise WorkflowStoredContractError("Pending heartbeat must use its exact private type")
        presented = _copy_internal_authority(self.presented)
        candidate = _copy_internal_authority(self._candidate)
        heartbeat = _aware_internal_datetime(self.heartbeat_at, field_name="pending heartbeat_at")
        expected = _renewed_authority(
            presented,
            stage_state_version=presented.stage_state_version + 1,
            attempt_state_version=presented.attempt_state_version + 1,
            lease_expires_at=candidate.lease_expires_at,
        )
        if candidate != expected or candidate.lease_expires_at < presented.lease_expires_at or candidate.lease_expires_at <= heartbeat:
            raise WorkflowStoredContractError("Pending heartbeat candidate is not one exact monotonic renewal")
        object.__setattr__(self, "presented", presented)
        object.__setattr__(self, "_candidate", candidate)
        object.__setattr__(self, "heartbeat_at", heartbeat)


@dataclass(frozen=True, slots=True)
class _CheckpointMutationFacts:
    """Exact post-flush facts with no executable or pending authority."""

    checkpoint_schema_version: str
    requested_checkpoint_checksum: str
    committed_checkpoint_checksum: str
    checkpoint_version: int
    stage_state_version: int
    attempt_state_version: int
    heartbeat_at: datetime
    lease_expires_at: datetime

    def __post_init__(self) -> None:
        if type(self) is not _CheckpointMutationFacts:
            raise WorkflowStoredContractError("Checkpoint mutation facts must use their exact private type")
        try:
            schema_version = _version_identity(
                self.checkpoint_schema_version,
                field_name="checkpoint mutation schema version",
            )
            requested_checksum = _lower_sha256(
                self.requested_checkpoint_checksum,
                field_name="checkpoint mutation requested checksum",
            )
            committed_checksum = _lower_sha256(
                self.committed_checkpoint_checksum,
                field_name="checkpoint mutation committed checksum",
            )
            checkpoint_version = _bounded_int(
                self.checkpoint_version,
                field_name="checkpoint mutation checkpoint_version",
                minimum=1,
                maximum=2_147_483_647,
            )
            stage_state_version = _state_version(
                self.stage_state_version,
                field_name="checkpoint mutation stage_state_version",
            )
            attempt_state_version = _state_version(
                self.attempt_state_version,
                field_name="checkpoint mutation attempt_state_version",
            )
        except (OutboxValidation, WorkflowValidation) as exc:
            raise WorkflowStoredContractError("Checkpoint mutation facts are invalid") from exc
        heartbeat = _aware_internal_datetime(self.heartbeat_at, field_name="checkpoint mutation heartbeat_at")
        expires_at = _aware_internal_datetime(
            self.lease_expires_at,
            field_name="checkpoint mutation lease_expires_at",
        )
        if requested_checksum != committed_checksum or expires_at <= heartbeat:
            raise WorkflowStoredContractError("Checkpoint mutation facts are not an exact committed write")
        object.__setattr__(self, "checkpoint_schema_version", schema_version)
        object.__setattr__(self, "requested_checkpoint_checksum", requested_checksum)
        object.__setattr__(self, "committed_checkpoint_checksum", committed_checksum)
        object.__setattr__(self, "checkpoint_version", checkpoint_version)
        object.__setattr__(self, "stage_state_version", stage_state_version)
        object.__setattr__(self, "attempt_state_version", attempt_state_version)
        object.__setattr__(self, "heartbeat_at", heartbeat)
        object.__setattr__(self, "lease_expires_at", expires_at)


@dataclass(frozen=True, slots=True)
class _PendingStageCheckpoint:
    """Private checkpoint candidate that cannot execute before confirmation."""

    presented: ExecutableStageAuthority = field(repr=False)
    _candidate: ExecutableStageAuthority = field(repr=False)
    checkpoint_schema_version: str
    requested_checkpoint_checksum: str
    committed_checkpoint_checksum: str
    heartbeat_at: datetime

    def __post_init__(self) -> None:
        if type(self) is not _PendingStageCheckpoint:
            raise WorkflowStoredContractError("Pending checkpoint must use its exact private type")
        presented = _copy_internal_authority(self.presented)
        candidate = _copy_internal_authority(self._candidate)
        heartbeat = _aware_internal_datetime(self.heartbeat_at, field_name="pending checkpoint heartbeat_at")
        try:
            schema_version = _version_identity(
                self.checkpoint_schema_version,
                field_name="pending checkpoint_schema_version",
            )
            requested_checksum = _lower_sha256(
                self.requested_checkpoint_checksum,
                field_name="pending requested_checkpoint_checksum",
            )
            committed_checksum = _lower_sha256(
                self.committed_checkpoint_checksum,
                field_name="pending committed_checkpoint_checksum",
            )
        except (OutboxValidation, WorkflowValidation) as exc:
            raise WorkflowStoredContractError("Pending checkpoint content authority is invalid") from exc
        expected = _renewed_authority(
            presented,
            stage_state_version=presented.stage_state_version + 1,
            attempt_state_version=presented.attempt_state_version + 1,
            checkpoint_version=presented.checkpoint_version + 1,
            lease_expires_at=candidate.lease_expires_at,
        )
        if (
            candidate != expected
            or requested_checksum != committed_checksum
            or candidate.lease_expires_at < presented.lease_expires_at
            or candidate.lease_expires_at <= heartbeat
        ):
            raise WorkflowStoredContractError("Pending checkpoint is not one exact monotonic write")
        object.__setattr__(self, "presented", presented)
        object.__setattr__(self, "_candidate", candidate)
        object.__setattr__(self, "checkpoint_schema_version", schema_version)
        object.__setattr__(self, "requested_checkpoint_checksum", requested_checksum)
        object.__setattr__(self, "committed_checkpoint_checksum", committed_checksum)
        object.__setattr__(self, "heartbeat_at", heartbeat)


class _ReceiptAuthorityStale(Exception):
    """Internal rollback sentinel; never crosses the coordinator boundary."""


async def coordinate_stage_heartbeat(
    session_factory: SessionFactory,
    *,
    authority: ExecutableStageAuthority,
    lease_seconds: int = 300,
) -> CoordinatedStageHeartbeat:
    """Commit one receipt-bound heartbeat and confirm it in a fresh session.

    Only receipt reservation/consumption lease loss is converted into a stale
    worker decision.  Flush, transaction-exit, factory, and stored-contract
    failures propagate without constructing a public result.
    """

    presented = _copy_presented_authority(authority)
    duration = _lease_seconds(lease_seconds)
    if not callable(session_factory):
        raise WorkflowValidation("session_factory must create an async session context")

    mutation_session: AsyncSession | None = None
    mutation_sync_session: object | None = None
    mutation_root: object | None = None
    pending: _PendingStageHeartbeat | None = None
    mutation_stale = _ReceiptAuthorityStale()
    try:
        async with session_factory() as session:
            mutation_session = session
            async with session.begin():
                mutation_sync_session, mutation_root = _active_root_transaction(session)
                try:
                    pending = await _reserve_consume_and_heartbeat(
                        session,
                        authority=presented,
                        duration=duration,
                    )
                except OutboxLeaseLost as exc:
                    raise mutation_stale from exc
    except _ReceiptAuthorityStale as exc:
        if exc is not mutation_stale:
            raise
        return _build_public_result(
            presented,
            pending=None,
            disposition="stale",
            authority=None,
        )

    if (
        mutation_session is None or mutation_sync_session is None or mutation_root is None or pending is None
    ):  # pragma: no cover - defensive context-manager invariant
        raise WorkflowStoredContractError("Heartbeat mutation context exited without exact pending authority")

    raw_confirmed: ExecutableStageAuthority | None = None
    confirmation_stale = _ReceiptAuthorityStale()
    try:
        async with session_factory() as confirmation_session:
            if confirmation_session is mutation_session or getattr(confirmation_session, "sync_session", None) is mutation_sync_session:
                raise WorkflowValidation("Heartbeat confirmation requires a distinct fresh session")
            async with confirmation_session.begin():
                _confirmation_sync, confirmation_root = _active_root_transaction(confirmation_session)
                if confirmation_root is mutation_root:
                    raise WorkflowValidation("Heartbeat confirmation requires a distinct root transaction")
                try:
                    confirmed = await _reserve_and_consume_execution_receipt(
                        confirmation_session,
                        authority=pending._candidate,
                    )
                except OutboxLeaseLost as exc:
                    raise confirmation_stale from exc
                raw_confirmed = _copy_internal_authority(confirmed.authority)
                if raw_confirmed != pending._candidate:
                    raise WorkflowStoredContractError("Heartbeat confirmation changed the committed candidate")
    except _ReceiptAuthorityStale as exc:
        if exc is not confirmation_stale:
            raise
        return _build_public_result(
            presented,
            pending=pending,
            disposition="stale",
            authority=None,
        )

    if raw_confirmed is None:  # pragma: no cover - defensive context-manager invariant
        raise WorkflowStoredContractError("Heartbeat confirmation exited without executable authority")
    authority_after_commit = _copy_internal_authority(raw_confirmed)
    return _build_public_result(
        presented,
        pending=pending,
        disposition="renewed",
        authority=authority_after_commit,
    )


async def coordinate_stage_checkpoint(
    session_factory: SessionFactory,
    *,
    authority: ExecutableStageAuthority,
    checkpoint_schema_version: str,
    checkpoint: dict[str, Any],
    lease_seconds: int = 300,
) -> CoordinatedStageCheckpoint:
    """Commit one receipt-bound checkpoint and confirm it after commit."""

    presented = _copy_presented_authority(authority)
    requested_schema, requested_payload, requested_checksum = _canonical_checkpoint_request(
        checkpoint_schema_version,
        checkpoint,
    )
    duration = _lease_seconds(lease_seconds)
    if not callable(session_factory):
        raise WorkflowValidation("session_factory must create an async session context")

    mutation_session: AsyncSession | None = None
    mutation_sync_session: object | None = None
    mutation_root: object | None = None
    pending: _PendingStageCheckpoint | None = None
    mutation_stale = _ReceiptAuthorityStale()
    try:
        async with session_factory() as session:
            mutation_session = session
            async with session.begin():
                mutation_sync_session, mutation_root = _active_root_transaction(session)
                try:
                    mutation_facts = await _reserve_consume_and_checkpoint(
                        session,
                        authority=presented,
                        checkpoint_schema_version=requested_schema,
                        checkpoint=requested_payload,
                        duration=duration,
                    )
                except OutboxLeaseLost as exc:
                    raise mutation_stale from exc
                candidate = _renewed_authority(
                    presented,
                    stage_state_version=mutation_facts.stage_state_version,
                    attempt_state_version=mutation_facts.attempt_state_version,
                    checkpoint_version=mutation_facts.checkpoint_version,
                    lease_expires_at=mutation_facts.lease_expires_at,
                )
                pending = _PendingStageCheckpoint(
                    presented=presented,
                    _candidate=candidate,
                    checkpoint_schema_version=mutation_facts.checkpoint_schema_version,
                    requested_checkpoint_checksum=mutation_facts.requested_checkpoint_checksum,
                    committed_checkpoint_checksum=mutation_facts.committed_checkpoint_checksum,
                    heartbeat_at=mutation_facts.heartbeat_at,
                )
                if (
                    pending.checkpoint_schema_version != requested_schema
                    or pending.requested_checkpoint_checksum != requested_checksum
                    or pending.committed_checkpoint_checksum != requested_checksum
                ):
                    raise WorkflowStoredContractError("Checkpoint mutation changed the validated request")
    except _ReceiptAuthorityStale as exc:
        if exc is not mutation_stale:
            raise
        return _build_public_checkpoint_result(
            presented,
            checkpoint_schema_version=requested_schema,
            requested_checkpoint_checksum=requested_checksum,
            pending=None,
            disposition="stale",
            authority=None,
        )

    if (
        mutation_session is None or mutation_sync_session is None or mutation_root is None or pending is None
    ):  # pragma: no cover - defensive context-manager invariant
        raise WorkflowStoredContractError("Checkpoint mutation context exited without exact pending authority")

    raw_confirmed: ExecutableStageAuthority | None = None
    confirmation_stale = _ReceiptAuthorityStale()
    try:
        async with session_factory() as confirmation_session:
            if confirmation_session is mutation_session or getattr(confirmation_session, "sync_session", None) is mutation_sync_session:
                raise WorkflowValidation("Checkpoint confirmation requires a distinct fresh session")
            async with confirmation_session.begin():
                _confirmation_sync, confirmation_root = _active_root_transaction(confirmation_session)
                if confirmation_root is mutation_root:
                    raise WorkflowValidation("Checkpoint confirmation requires a distinct root transaction")
                try:
                    confirmed = await _reserve_and_consume_execution_receipt(
                        confirmation_session,
                        authority=pending._candidate,
                    )
                except OutboxLeaseLost as exc:
                    raise confirmation_stale from exc
                _assert_checkpoint_confirmation(confirmed, pending=pending)
                raw_confirmed = _copy_internal_authority(confirmed.authority)
                if raw_confirmed != pending._candidate:
                    raise WorkflowStoredContractError("Checkpoint confirmation changed the committed candidate")
    except _ReceiptAuthorityStale as exc:
        if exc is not confirmation_stale:
            raise
        return _build_public_checkpoint_result(
            presented,
            checkpoint_schema_version=requested_schema,
            requested_checkpoint_checksum=requested_checksum,
            pending=pending,
            disposition="stale",
            authority=None,
        )

    if raw_confirmed is None:  # pragma: no cover - defensive context-manager invariant
        raise WorkflowStoredContractError("Checkpoint confirmation exited without executable authority")
    authority_after_commit = _copy_internal_authority(raw_confirmed)
    return _build_public_checkpoint_result(
        presented,
        checkpoint_schema_version=requested_schema,
        requested_checkpoint_checksum=requested_checksum,
        pending=pending,
        disposition="renewed",
        authority=authority_after_commit,
    )


async def coordinate_stage_complete(
    session_factory: SessionFactory,
    *,
    authority: ExecutableStageAuthority,
    output_manifest: dict[str, Any],
    outcome: CompletionOutcome = "succeeded",
) -> CoordinatedStageCompletion:
    """Commit one receipt-bound completion and return capability-free facts.

    The mutation transaction's successful context exit is the commit
    confirmation.  There is no second authority read because a terminal
    worker decision must never expose another executable lease.
    """

    presented = _copy_presented_authority(authority)
    requested_payload, requested_checksum, requested_outcome = _canonical_completion_request(
        output_manifest,
        outcome=outcome,
    )
    if not callable(session_factory):
        raise WorkflowValidation("session_factory must create an async session context")

    facts: _StageCompletionMutationFacts | None = None
    completion_stale = _ReceiptAuthorityStale()
    try:
        async with session_factory() as session:
            async with session.begin():
                _active_root_transaction(session)
                facts = await _reserve_consume_and_complete(
                    session,
                    authority=presented,
                    output_manifest=requested_payload,
                    outcome=requested_outcome,
                    receipt_stale=completion_stale,
                )
    except _ReceiptAuthorityStale as exc:
        if exc is not completion_stale:
            raise
        return _build_public_completion_result(
            presented,
            outcome=requested_outcome,
            requested_output_checksum=requested_checksum,
            facts=None,
            disposition="stale",
        )

    if facts is None:  # pragma: no cover - defensive context-manager invariant
        raise WorkflowStoredContractError("Completion context exited without exact committed facts")
    if facts.outcome != requested_outcome or facts.requested_output_checksum != requested_checksum:
        raise WorkflowStoredContractError("Completion mutation changed its validated request")
    return _build_public_completion_result(
        presented,
        outcome=requested_outcome,
        requested_output_checksum=requested_checksum,
        facts=facts,
        disposition="completed",
    )


async def coordinate_stage_fail(
    session_factory: SessionFactory,
    *,
    authority: ExecutableStageAuthority,
    error_text: str,
    error_code: str,
    retryable: bool,
    error_class: str = "ExternalError",
) -> CoordinatedStageFailure:
    """Commit one receipt-bound failure and return capability-free facts.

    Only lease loss while reserving or consuming the exact delivered receipt
    graph becomes a stale acknowledgement.  Cancellation, append, flush,
    transaction-exit, and stored-contract failures propagate and therefore
    cannot construct an acknowledgement.
    """

    presented = _copy_presented_authority(authority)
    evidence = _canonical_failure_request(
        error_text,
        error_code=error_code,
        retryable=retryable,
        error_class=error_class,
    )
    if not callable(session_factory):
        raise WorkflowValidation("session_factory must create an async session context")

    facts: _StageFailureMutationFacts | None = None
    failure_stale = _ReceiptAuthorityStale()
    try:
        async with session_factory() as session:
            async with session.begin():
                _active_root_transaction(session)
                facts = await _reserve_consume_and_fail(
                    session,
                    authority=presented,
                    evidence=evidence,
                    receipt_stale=failure_stale,
                )
    except _ReceiptAuthorityStale as exc:
        if exc is not failure_stale:
            raise
        return _build_public_failure_result(
            presented,
            evidence=evidence,
            facts=None,
            disposition="stale",
        )

    if facts is None:  # pragma: no cover - defensive context-manager invariant
        raise WorkflowStoredContractError("Failure context exited without exact committed facts")
    if facts.evidence != evidence:
        raise WorkflowStoredContractError("Failure mutation changed its validated evidence")
    return _build_public_failure_result(
        presented,
        evidence=evidence,
        facts=facts,
        disposition="recorded",
    )


async def coordinate_workflow_cancel(
    session_factory: SessionFactory,
    *,
    command: WorkflowCancellationCommand,
) -> CoordinatedWorkflowCancellation:
    """Commit one explicit cancellation or confirm its exact durable replay."""

    presented = _copy_presented_cancellation_command(command)
    if not callable(session_factory):
        raise WorkflowValidation("session_factory must create an async session context")

    facts: _WorkflowCancellationMutationFacts | None = None
    async with session_factory() as session:
        async with session.begin():
            _active_root_transaction(session)
            facts = await _reserve_consume_and_cancel(
                session,
                command=presented,
            )
    if facts is None:  # pragma: no cover - defensive context-manager invariant
        raise WorkflowStoredContractError("Cancellation context exited without exact committed facts")
    if facts.command != presented:
        raise WorkflowStoredContractError("Cancellation mutation changed its validated command")
    return _build_public_cancellation_result(facts)


async def coordinate_one_expired_stage_recovery(
    session_factory: SessionFactory,
) -> CoordinatedStageRecovery | None:
    """Commit at most one auto-selected expired receipt recovery."""

    if not callable(session_factory):
        raise WorkflowValidation("session_factory must create an async session context")
    facts: _StageRecoveryMutationFacts | None = None
    completed = False
    async with session_factory() as session:
        async with session.begin():
            _active_root_transaction(session)
            facts = await _reserve_consume_and_recover_one(session)
        completed = True
    if not completed:  # pragma: no cover - defensive context-manager invariant
        raise WorkflowStoredContractError("Recovery context did not exit exactly once")
    return None if facts is None else _build_public_recovery_result(facts)


async def coordinate_expired_stage_recovery_pass(
    session_factory: SessionFactory,
    *,
    limit: int = 1,
) -> tuple[CoordinatedStageRecovery, ...]:
    """Run a bounded recovery pass with one distinct transaction per workflow."""

    bounded_limit = _bounded_int(
        limit,
        field_name="recovery pass limit",
        minimum=1,
        maximum=_MAX_RECOVERY_PASS,
    )
    if not callable(session_factory):
        raise WorkflowValidation("session_factory must create an async session context")
    results: list[CoordinatedStageRecovery] = []
    for _index in range(bounded_limit):
        result = await coordinate_one_expired_stage_recovery(session_factory)
        if result is None:
            break
        results.append(result)
    return tuple(results)


async def _reserve_and_consume_execution_receipt(
    db: AsyncSession,
    *,
    authority: ExecutableStageAuthority,
) -> LockedStageExecutionReceipt:
    reservation = await _reserve_stage_execution_receipt(
        db,
        authority=authority,
    )
    locked = await _consume_stage_execution_receipt(
        db,
        reservation=reservation,
        authority=authority,
    )
    if type(locked) is not LockedStageExecutionReceipt:
        raise OutboxStoredContractError("Receipt runtime returned invalid locked execution authority")
    if locked.authority != authority:
        raise OutboxStoredContractError("Receipt runtime changed the presented execution authority")
    return locked


async def _reserve_consume_and_heartbeat(
    db: AsyncSession,
    *,
    authority: ExecutableStageAuthority,
    duration: int,
) -> _PendingStageHeartbeat:
    """Reserve, consume, and mutate without accepting forgeable locked rows."""

    validated_duration = _lease_seconds(duration)
    locked = await _reserve_and_consume_execution_receipt(
        db,
        authority=authority,
    )
    stage = locked.stage
    attempt = locked.attempt
    now = _aware_internal_datetime(locked.observed_at, field_name="consumed heartbeat observed_at")
    if (
        locked.workflow.id != authority.workflow_run_id
        or stage.id != authority.stage_run_id
        or attempt.id != authority.stage_attempt_id
        or locked.message.id != authority.message_id
        or locked.delivery.id != authority.delivery_attempt_id
        or stage.workflow_run_id != authority.workflow_run_id
        or attempt.stage_run_id != authority.stage_run_id
        or attempt.outbox_delivery_attempt_id != authority.delivery_attempt_id
        or locked.workflow.state_version != authority.workflow_state_version
        or stage.state_version != authority.stage_state_version
        or attempt.state_version != authority.attempt_state_version
        or attempt.attempt_number != authority.attempt_number
        or locked.delivery.delivery_cycle != authority.delivery_cycle
        or locked.delivery.cycle_key != authority.cycle_key
        or stage.stage_key != authority.stage_key
        or stage.input_checksum != authority.input_checksum
        or stage.checkpoint_version != authority.checkpoint_version
        or stage.lease_owner != authority.lease_owner
        or attempt.lease_owner != authority.lease_owner
        or stage.lease_token != authority.stage_lease_token
        or attempt.lease_token != authority.stage_lease_token
        or stage.lease_expires_at != authority.lease_expires_at
        or attempt.lease_expires_at != authority.lease_expires_at
        or stage.heartbeat_at != attempt.heartbeat_at
        or stage.heartbeat_at > now
        or locked.delivery.broker_receipt_id != authority.broker_receipt_id
        or stage.state_version >= 2_147_483_647
        or attempt.state_version >= 2_147_483_647
    ):
        raise WorkflowStoredContractError("Locked heartbeat rows contradict their executable authority")
    try:
        requested_expiry = now + timedelta(seconds=validated_duration)
    except OverflowError as exc:
        raise WorkflowStoredContractError("Heartbeat lease expiry exceeds the database timestamp range") from exc
    expires_at = max(authority.lease_expires_at, requested_expiry)

    stage.heartbeat_at = now
    stage.lease_expires_at = expires_at
    stage.state_version += 1
    await db.flush([stage])

    attempt.heartbeat_at = now
    attempt.lease_expires_at = expires_at
    attempt.state_version += 1
    await db.flush([attempt])

    candidate = _renewed_authority(
        authority,
        stage_state_version=stage.state_version,
        attempt_state_version=attempt.state_version,
        lease_expires_at=expires_at,
    )
    return _PendingStageHeartbeat(
        presented=authority,
        _candidate=candidate,
        heartbeat_at=now,
    )


async def _reserve_consume_and_checkpoint(
    db: AsyncSession,
    *,
    authority: ExecutableStageAuthority,
    checkpoint_schema_version: object,
    checkpoint: object,
    duration: object,
) -> _CheckpointMutationFacts:
    """Validate, reserve, consume, and checkpoint without a DTO injection seam."""

    validated_schema, checkpoint_payload, checkpoint_checksum = _canonical_checkpoint_request(
        checkpoint_schema_version,
        checkpoint,
    )
    validated_duration = _lease_seconds(duration)
    locked = await _reserve_and_consume_execution_receipt(
        db,
        authority=authority,
    )
    stage = locked.stage
    attempt = locked.attempt
    now = _aware_internal_datetime(locked.observed_at, field_name="consumed checkpoint observed_at")
    if stage.checkpoint_schema_version != validated_schema:
        raise WorkflowCheckpointConflict("Checkpoint schema version does not match the stage authority")
    if (
        locked.workflow.id != authority.workflow_run_id
        or stage.id != authority.stage_run_id
        or attempt.id != authority.stage_attempt_id
        or locked.message.id != authority.message_id
        or locked.delivery.id != authority.delivery_attempt_id
        or stage.workflow_run_id != authority.workflow_run_id
        or attempt.stage_run_id != authority.stage_run_id
        or attempt.outbox_delivery_attempt_id != authority.delivery_attempt_id
        or locked.workflow.state_version != authority.workflow_state_version
        or stage.state_version != authority.stage_state_version
        or attempt.state_version != authority.attempt_state_version
        or attempt.attempt_number != authority.attempt_number
        or locked.delivery.delivery_cycle != authority.delivery_cycle
        or locked.delivery.cycle_key != authority.cycle_key
        or stage.stage_key != authority.stage_key
        or stage.input_checksum != authority.input_checksum
        or stage.checkpoint_version != authority.checkpoint_version
        or attempt.checkpoint_end_version != authority.checkpoint_version
        or stage.lease_owner != authority.lease_owner
        or attempt.lease_owner != authority.lease_owner
        or stage.lease_token != authority.stage_lease_token
        or attempt.lease_token != authority.stage_lease_token
        or stage.lease_expires_at != authority.lease_expires_at
        or attempt.lease_expires_at != authority.lease_expires_at
        or stage.heartbeat_at != attempt.heartbeat_at
        or stage.heartbeat_at > now
        or locked.delivery.broker_receipt_id != authority.broker_receipt_id
        or stage.checkpoint_version >= 2_147_483_647
        or stage.state_version >= 2_147_483_647
        or attempt.state_version >= 2_147_483_647
    ):
        raise WorkflowStoredContractError("Locked checkpoint rows contradict their executable authority")
    try:
        requested_expiry = now + timedelta(seconds=validated_duration)
    except OverflowError as exc:
        raise WorkflowStoredContractError("Checkpoint lease expiry exceeds the database timestamp range") from exc
    expires_at = max(authority.lease_expires_at, requested_expiry)
    next_checkpoint_version = authority.checkpoint_version + 1

    stage.checkpoint = checkpoint_payload
    stage.checkpoint_checksum = checkpoint_checksum
    stage.checkpoint_version = next_checkpoint_version
    stage.heartbeat_at = now
    stage.lease_expires_at = expires_at
    stage.state_version += 1
    await db.flush([stage])
    if (
        stage.checkpoint != checkpoint_payload
        or stage.checkpoint_checksum != checkpoint_checksum
        or stage.checkpoint_version != next_checkpoint_version
        or stage.heartbeat_at != now
        or stage.lease_expires_at != expires_at
        or stage.state_version != authority.stage_state_version + 1
    ):
        raise WorkflowStoredContractError("Stage checkpoint changed while being flushed")

    attempt.checkpoint_end_version = next_checkpoint_version
    attempt.heartbeat_at = now
    attempt.lease_expires_at = expires_at
    attempt.state_version += 1
    await db.flush([attempt])
    if (
        attempt.checkpoint_end_version != next_checkpoint_version
        or attempt.heartbeat_at != now
        or attempt.lease_expires_at != expires_at
        or attempt.state_version != authority.attempt_state_version + 1
    ):
        raise WorkflowStoredContractError("Attempt checkpoint changed while being flushed")

    return _CheckpointMutationFacts(
        checkpoint_schema_version=validated_schema,
        requested_checkpoint_checksum=checkpoint_checksum,
        committed_checkpoint_checksum=stage.checkpoint_checksum,
        checkpoint_version=stage.checkpoint_version,
        stage_state_version=stage.state_version,
        attempt_state_version=attempt.state_version,
        heartbeat_at=now,
        lease_expires_at=expires_at,
    )


async def _reserve_consume_and_complete(
    db: AsyncSession,
    *,
    authority: object,
    output_manifest: object,
    outcome: object,
    receipt_stale: object,
) -> _StageCompletionMutationFacts:
    """Validate, reserve, consume, and complete without a Locked-DTO seam."""

    if type(receipt_stale) is not _ReceiptAuthorityStale:
        raise WorkflowValidation("receipt_stale must be one exact coordinator-local sentinel")
    credential = _copy_presented_authority(authority)
    output_payload, output_checksum, completion_outcome = _canonical_completion_request(
        output_manifest,
        outcome=outcome,
    )
    try:
        reservation = await _reserve_stage_completion_graph(
            db,
            authority=credential,
        )
        locked = await _consume_stage_completion_graph(
            db,
            reservation=reservation,
            authority=credential,
        )
    except OutboxLeaseLost as exc:
        raise receipt_stale from exc

    if type(locked) is not LockedStageCompletionGraph or locked.authority != credential:
        raise WorkflowStoredContractError("Completion runtime returned invalid locked graph authority")
    workflow = locked.workflow
    stages = locked.stages
    attempt = locked.source_attempt
    if (
        type(workflow) is not WorkflowRun
        or type(stages) is not tuple
        or not stages
        or any(type(stage) is not StageRun for stage in stages)
        or type(attempt) is not StageAttempt
        or type(locked.source_stage_index) is not int
        or not 0 <= locked.source_stage_index < len(stages)
    ):
        raise WorkflowStoredContractError("Completion runtime returned invalid persistence authority")
    source = stages[locked.source_stage_index]
    now = _aware_internal_datetime(locked.observed_at, field_name="consumed completion observed_at")
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
        or source.lease_token != credential.stage_lease_token
        or source.lease_owner != credential.lease_owner
        or source.lease_expires_at != credential.lease_expires_at
        or source.lease_expires_at is None
        or source.lease_expires_at <= now
        or attempt.id != credential.stage_attempt_id
        or attempt.stage_run_id != credential.stage_run_id
        or attempt.outbox_delivery_attempt_id != credential.delivery_attempt_id
        or attempt.attempt_number != credential.attempt_number
        or attempt.status != "running"
        or attempt.state_version != credential.attempt_state_version
        or attempt.lease_token != credential.stage_lease_token
        or attempt.lease_owner != credential.lease_owner
        or attempt.input_checksum != credential.input_checksum
        or attempt.checkpoint_end_version != credential.checkpoint_version
        or attempt.lease_expires_at != credential.lease_expires_at
        or source.state_version >= 2_147_483_647
        or attempt.state_version >= 2_147_483_647
    ):
        raise WorkflowStoredContractError("Locked completion rows contradict their executable authority")
    if type(locked.intents) is not tuple:
        raise WorkflowStoredContractError("Completion runtime returned invalid fan-out intents")
    child = locked.stage_ready_reservation
    if (not locked.intents and child is not None) or (locked.intents and type(child) is not StageReadyReservation):
        raise WorkflowStoredContractError("Completion runtime returned invalid append capability shape")
    expected_message_ids_by_logical_key: dict[str, uuid.UUID] = {}
    if child is not None:
        expected_message_ids_by_logical_key = {
            intent.logical_key: message_id for intent, message_id in zip(child.intents, child.message_ids, strict=True)
        }
        if len(expected_message_ids_by_logical_key) != len(locked.intents) or set(expected_message_ids_by_logical_key) != {
            intent.logical_key for intent in locked.intents
        }:
            raise WorkflowStoredContractError("Completion append capability changed its preallocated identity map")

    targets_by_id: dict[uuid.UUID, tuple[StageRun, object]] = {}
    stages_by_id = {stage.id: stage for stage in stages}
    for intent in locked.intents:
        target = stages_by_id.get(intent.post_target.stage_run_id)
        if (
            target is None
            or target is source
            or target.id in targets_by_id
            or intent.pre_target.status != "pending"
            or intent.post_target.status != "ready"
            or intent.post_target.state_version != intent.pre_target.state_version + 1
            or intent.post_target.next_attempt_at != now
        ):
            raise WorkflowStoredContractError("Completion fan-out does not describe exact dependency transitions")
        targets_by_id[target.id] = (target, intent)
    will_finalize = (
        all(stage is source or stage.status in _TERMINAL_STAGE_STATUSES for stage in stages if stage.id not in targets_by_id)
        and not targets_by_id
    )
    if will_finalize and workflow.state_version >= 2_147_483_647:
        raise WorkflowStoredContractError("Workflow completion state version is exhausted")

    workflow_before = _worker_model_snapshot(workflow)
    stage_before = {stage.id: _worker_model_snapshot(stage) for stage in stages}
    attempt_before = _worker_model_snapshot(attempt)
    message_before = tuple((message, _worker_model_snapshot(message)) for message in getattr(locked, "locked_messages", ()))
    delivery_before = tuple((delivery, _worker_model_snapshot(delivery)) for delivery in getattr(locked, "locked_deliveries", ()))

    # Terminal attempt evidence must precede the logical stage transition.
    attempt.status = completion_outcome
    attempt.state_version += 1
    attempt.checkpoint_end_version = source.checkpoint_version
    attempt.output_checksum = output_checksum
    attempt.error_code = ""
    attempt.error_class = ""
    attempt.error_summary = ""
    attempt.retryable = False
    attempt.heartbeat_at = now
    attempt.completed_at = now
    await db.flush([attempt])
    if (
        attempt.status != completion_outcome
        or attempt.state_version != credential.attempt_state_version + 1
        or attempt.checkpoint_end_version != credential.checkpoint_version
        or attempt.output_checksum != output_checksum
        or attempt.error_code != ""
        or attempt.error_class != ""
        or attempt.error_summary != ""
        or attempt.retryable
        or attempt.heartbeat_at != now
        or attempt.completed_at != now
    ):
        raise WorkflowStoredContractError("Attempt completion changed while being flushed")

    source.status = completion_outcome
    source.state_version += 1
    source.output_manifest = output_payload
    source.output_checksum = output_checksum
    source.last_error_code = ""
    source.last_error_summary = ""
    source.last_error_retryable = False
    source.completed_at = now
    _clear_worker_stage_lease(source)
    for target, intent in targets_by_id.values():
        target.status = intent.post_target.status
        target.state_version = intent.post_target.state_version
        target.next_attempt_at = intent.post_target.next_attempt_at
    changed_stages = tuple(stage for stage in stages if stage is source or stage.id in targets_by_id)
    await db.flush(list(changed_stages))
    if (
        source.status != completion_outcome
        or source.state_version != credential.stage_state_version + 1
        or source.output_manifest != output_payload
        or source.output_checksum != output_checksum
        or source.last_error_code != ""
        or source.last_error_summary != ""
        or source.last_error_retryable
        or source.completed_at != now
        or source.lease_owner != ""
        or source.lease_token is not None
        or source.leased_at is not None
        or source.lease_expires_at is not None
        or source.heartbeat_at is not None
    ):
        raise WorkflowStoredContractError("Stage completion changed while being flushed")
    for target, intent in targets_by_id.values():
        if (
            target.status != intent.post_target.status
            or target.state_version != intent.post_target.state_version
            or target.next_attempt_at != intent.post_target.next_attempt_at
        ):
            raise WorkflowStoredContractError("Dependency-ready target changed while being flushed")

    appended: tuple[tuple[object, bool], ...] = ()
    if child is not None:
        appended = await _append_reserved_stage_ready(
            db,
            reservation=child,
            workflow=workflow,
            locked_stages=stages,
            causal_attempt=attempt,
        )
        if type(appended) is not tuple or len(appended) != len(locked.intents):
            raise WorkflowStoredContractError("Completion append returned an incomplete fan-out")
    elif locked.intents:
        raise WorkflowStoredContractError("Completion fan-out lost its append capability")

    intents_by_logical_key = {intent.logical_key: intent for intent in locked.intents}
    messages_by_logical_key: dict[str, OutboxMessage] = {}
    for item in appended:
        if type(item) is not tuple or len(item) != 2:
            raise WorkflowStoredContractError("Completion append returned an invalid result tuple")
        message, created = item
        if type(created) is not bool or not created:
            raise WorkflowStoredContractError("Completion append did not create one exact root per target")
        logical_key = getattr(message, "logical_key", None)
        intent = intents_by_logical_key.get(logical_key)
        expected_message_id = expected_message_ids_by_logical_key.get(logical_key)
        if intent is None or expected_message_id is None or logical_key in messages_by_logical_key:
            raise WorkflowStoredContractError("Completion append returned invalid message identity")
        _assert_appended_completion_message(
            message,
            intent=intent,
            expected_message_id=expected_message_id,
            workflow=workflow,
            causal_attempt=attempt,
            observed_at=now,
        )
        messages_by_logical_key[logical_key] = message
    if set(messages_by_logical_key) != set(intents_by_logical_key):
        raise WorkflowStoredContractError("Completion append omitted a projected message identity")
    emission_facts: list[_StageCompletionEmissionFacts] = []
    for intent in locked.intents:
        message = messages_by_logical_key.get(intent.logical_key)
        if (
            message is None
            or message.id != expected_message_ids_by_logical_key[intent.logical_key]
            or message.stage_run_id != intent.post_target.stage_run_id
        ):
            raise WorkflowStoredContractError("Completion append changed a projected target identity")
        emission_facts.append(
            _StageCompletionEmissionFacts(
                stage_run_id=intent.post_target.stage_run_id,
                stage_key=intent.post_target.stage_key,
                stage_state_version=intent.post_target.state_version,
                message_id=message.id,
                logical_key=intent.logical_key,
                available_at=now,
            )
        )

    workflow_completed_at: datetime | None = None
    if all(stage.status in _TERMINAL_STAGE_STATUSES for stage in stages):
        degraded = sorted(stage.stage_key for stage in stages if stage.status in _DEGRADED_STAGE_STATUSES)
        aggregate_status = "degraded" if degraded else "succeeded"
        aggregate_reason = "workflow.degraded_stages" if degraded else ""
        aggregate_summary = f"Workflow completed with degraded or unavailable stages: {', '.join(degraded)}"[:500] if degraded else ""
        workflow.status = aggregate_status
        workflow.state_version += 1
        workflow.status_reason_code = aggregate_reason
        workflow.status_summary = aggregate_summary
        workflow.completed_at = now
        await db.flush([workflow])
        workflow_completed_at = now
        if (
            workflow.status != aggregate_status
            or workflow.state_version != credential.workflow_state_version + 1
            or workflow.status_reason_code != aggregate_reason
            or workflow.status_summary != aggregate_summary
            or workflow.completed_at != now
        ):
            raise WorkflowStoredContractError("Workflow aggregate changed while being flushed")
    elif workflow.status != "running" or workflow.state_version != credential.workflow_state_version or workflow.completed_at is not None:
        raise WorkflowStoredContractError("Active workflow aggregate changed during stage completion")

    _assert_worker_model_changes(
        workflow,
        workflow_before,
        allowed=(
            {"status", "state_version", "status_reason_code", "status_summary", "completed_at"}
            if workflow_completed_at is not None
            else set()
        ),
        field_name="completion workflow",
    )
    source_allowed = {
        "status",
        "state_version",
        "output_manifest",
        "output_checksum",
        "lease_owner",
        "lease_token",
        "leased_at",
        "lease_expires_at",
        "heartbeat_at",
        "last_error_code",
        "last_error_summary",
        "last_error_retryable",
        "completed_at",
    }
    target_allowed = {"status", "state_version", "next_attempt_at"}
    for stage in stages:
        if stage is source:
            allowed = source_allowed
        elif stage.id in targets_by_id:
            allowed = target_allowed
        else:
            allowed = set()
        _assert_worker_model_changes(
            stage,
            stage_before[stage.id],
            allowed=allowed,
            field_name=f"completion stage {stage.stage_key}",
        )
    _assert_worker_model_changes(
        attempt,
        attempt_before,
        allowed={
            "status",
            "state_version",
            "checkpoint_end_version",
            "output_checksum",
            "error_code",
            "error_class",
            "error_summary",
            "retryable",
            "heartbeat_at",
            "completed_at",
        },
        field_name="completion source attempt",
    )
    for message, snapshot in message_before:
        _assert_worker_model_changes(
            message,
            snapshot,
            allowed=set(),
            field_name="completion locked message",
        )
    for delivery, snapshot in delivery_before:
        _assert_worker_model_changes(
            delivery,
            snapshot,
            allowed=set(),
            field_name="completion locked delivery",
        )

    return _StageCompletionMutationFacts(
        outcome=completion_outcome,
        requested_output_checksum=output_checksum,
        committed_output_checksum=source.output_checksum,
        workflow_state_version=workflow.state_version,
        workflow_status=workflow.status,
        stage_state_version=source.state_version,
        attempt_state_version=attempt.state_version,
        completed_at=now,
        workflow_completed_at=workflow_completed_at,
        emissions=tuple(emission_facts),
    )


async def _reserve_consume_and_fail(
    db: AsyncSession,
    *,
    authority: object,
    evidence: object,
    receipt_stale: object,
) -> _StageFailureMutationFacts:
    """Reserve, consume, and record failure without a Locked-DTO seam."""

    if type(receipt_stale) is not _ReceiptAuthorityStale:
        raise WorkflowValidation("receipt_stale must be one exact coordinator-local sentinel")
    credential = _copy_presented_authority(authority)
    safe_evidence = _copy_presented_failure_evidence(evidence)
    try:
        reservation = await _reserve_stage_failure_graph(
            db,
            authority=credential,
            evidence=safe_evidence,
        )
        locked = await _consume_stage_failure_graph(
            db,
            reservation=reservation,
            authority=credential,
            evidence=safe_evidence,
        )
    except OutboxLeaseLost as exc:
        raise receipt_stale from exc

    if type(locked) is not LockedStageFailureGraph or locked.authority != credential or locked.evidence != safe_evidence:
        raise WorkflowStoredContractError("Failure runtime returned invalid locked graph authority")
    workflow = locked.workflow
    stages = locked.stages
    attempts = locked.locked_attempts
    if (
        type(workflow) is not WorkflowRun
        or type(stages) is not tuple
        or not stages
        or any(type(stage) is not StageRun for stage in stages)
        or type(attempts) is not tuple
        or not attempts
        or any(type(attempt) is not StageAttempt for attempt in attempts)
        or type(locked.source_stage_index) is not int
        or not 0 <= locked.source_stage_index < len(stages)
    ):
        raise WorkflowStoredContractError("Failure runtime returned invalid persistence authority")
    source = stages[locked.source_stage_index]
    if len({stage.id for stage in stages}) != len(stages):
        raise WorkflowStoredContractError("Failure runtime returned duplicate stage authority")
    if len({attempt.id for attempt in attempts}) != len(attempts) or len({attempt.stage_run_id for attempt in attempts}) != len(attempts):
        raise WorkflowStoredContractError("Failure runtime returned duplicate attempt authority")
    if tuple(attempt.id for attempt in attempts) != tuple(sorted((attempt.id for attempt in attempts), key=lambda value: value.int)):
        raise WorkflowStoredContractError("Failure runtime returned attempts outside canonical UUID order")
    stages_by_id = {stage.id: stage for stage in stages}
    attempts_by_stage = {attempt.stage_run_id: attempt for attempt in attempts}
    source_attempt = attempts_by_stage.get(source.id)
    now = _aware_internal_datetime(locked.observed_at, field_name="consumed failure observed_at")
    if (
        workflow.id != credential.workflow_run_id
        or workflow.status != "running"
        or workflow.state_version != credential.workflow_state_version
        or source.id != credential.stage_run_id
        or locked.source_stage_id != credential.stage_run_id
        or source.workflow_run_id != credential.workflow_run_id
        or source.stage_key != credential.stage_key
        or source.status != "running"
        or source.state_version != credential.stage_state_version
        or source.input_checksum != credential.input_checksum
        or source.checkpoint_version != credential.checkpoint_version
        or source.lease_token != credential.stage_lease_token
        or source.lease_owner != credential.lease_owner
        or source.lease_expires_at != credential.lease_expires_at
        or source.lease_expires_at is None
        or source.lease_expires_at <= now
        or type(source_attempt) is not StageAttempt
        or locked.source_attempt_id != credential.stage_attempt_id
        or source_attempt.id != credential.stage_attempt_id
        or source_attempt.outbox_delivery_attempt_id != credential.delivery_attempt_id
        or source_attempt.attempt_number != credential.attempt_number
        or source_attempt.status != "running"
        or source_attempt.state_version != credential.attempt_state_version
        or source_attempt.lease_token != credential.stage_lease_token
        or source_attempt.lease_owner != credential.lease_owner
        or source_attempt.input_checksum != credential.input_checksum
        or source_attempt.checkpoint_end_version != credential.checkpoint_version
        or source_attempt.lease_expires_at != credential.lease_expires_at
        or source.state_version >= 2_147_483_647
        or source_attempt.state_version >= 2_147_483_647
    ):
        raise WorkflowStoredContractError("Locked failure rows contradict their executable authority")

    decision = locked.decision
    if type(source.attempt_count) is not int or type(source.max_attempts) is not int:
        raise WorkflowStoredContractError("Failure source attempt limits are invalid")
    expected_decision: FailureDecision = (
        "retry"
        if safe_evidence.retryable and source.attempt_count < source.max_attempts
        else "dead_lettered"
        if safe_evidence.retryable
        else "failed"
    )
    if decision != expected_decision:
        raise WorkflowStoredContractError("Failure runtime changed its deterministic retry decision")
    settlement = locked.settlement
    post_statuses = getattr(settlement, "post_stage_statuses", None)
    if (
        type(decision) is not str
        or decision not in {"retry", "failed", "dead_lettered"}
        or getattr(settlement, "decision", None) != decision
        or type(post_statuses) is not tuple
        or len(post_statuses) != len(stages)
        or post_statuses[locked.source_stage_index] != ("retry_wait" if decision == "retry" else decision)
    ):
        raise WorkflowStoredContractError("Failure runtime returned an invalid settlement projection")
    skipped_stage_ids = _exact_internal_uuid_tuple(
        getattr(settlement, "skipped_stage_ids", None),
        field_name="failure skipped stage ids",
    )
    cancelled_stage_ids = _exact_internal_uuid_tuple(
        getattr(settlement, "cancelled_stage_ids", None),
        field_name="failure cancelled stage ids",
    )
    cancelled_attempt_ids = _exact_internal_uuid_tuple(
        getattr(settlement, "cancelled_attempt_ids", None),
        field_name="failure cancelled attempt ids",
    )
    changed_stage_ids = {stage.id for stage, post_status in zip(stages, post_statuses, strict=True) if stage.status != post_status}
    expected_skipped = tuple(
        stage.id
        for stage, post_status in zip(stages, post_statuses, strict=True)
        if stage.status != post_status and post_status == "skipped"
    )
    expected_cancelled = tuple(
        stage.id
        for stage, post_status in zip(stages, post_statuses, strict=True)
        if stage.status != post_status and post_status == "cancelled"
    )
    if skipped_stage_ids != expected_skipped or cancelled_stage_ids != expected_cancelled or source.id not in changed_stage_ids:
        raise WorkflowStoredContractError("Failure settlement changed its exact plan-ordered stage closure")
    expected_cancelled_attempt_ids = tuple(
        sorted(
            (
                attempts_by_stage[stage.id].id
                for stage, post_status in zip(stages, post_statuses, strict=True)
                if stage.id != source.id and stage.status == "running" and post_status == "cancelled"
            ),
            key=lambda value: value.int,
        )
    )
    if cancelled_attempt_ids != expected_cancelled_attempt_ids:
        raise WorkflowStoredContractError("Failure settlement changed its running-attempt cancellation set")
    expected_attempt_stage_ids = {
        source.id,
        *(
            stage.id
            for stage, post_status in zip(stages, post_statuses, strict=True)
            if stage.id != source.id and stage.status == "running" and post_status == "cancelled"
        ),
    }
    if set(attempts_by_stage) != expected_attempt_stage_ids:
        raise WorkflowStoredContractError("Failure runtime returned the wrong current-attempt union")
    for attempt in attempts:
        if attempt.status != "running" or attempt.state_version >= 2_147_483_647 or attempt.stage_run_id not in expected_attempt_stage_ids:
            raise WorkflowStoredContractError("Failure current-attempt authority is not mutable")

    workflow_post_status = getattr(settlement, "workflow_post_status", None)
    workflow_reason_code = getattr(settlement, "workflow_reason_code", None)
    workflow_summary = getattr(settlement, "workflow_summary", None)
    if (
        type(workflow_post_status) is not str
        or workflow_post_status not in {"running", "degraded", "failed", "dead_lettered"}
        or type(workflow_reason_code) is not str
        or type(workflow_summary) is not str
        or (workflow_post_status == "running") != (workflow_reason_code == "" and workflow_summary == "")
        or (workflow_post_status != "running" and workflow.state_version >= 2_147_483_647)
    ):
        raise WorkflowStoredContractError("Failure workflow settlement authority is invalid")
    required_terminal = bool(source.required) and decision != "retry"
    if required_terminal:
        expected_workflow_status = "dead_lettered" if decision == "dead_lettered" else "failed"
        expected_reason = "workflow.required_stage_dead_lettered" if decision == "dead_lettered" else "workflow.required_stage_failed"
        if workflow_post_status != expected_workflow_status or workflow_reason_code != expected_reason:
            raise WorkflowStoredContractError("Required failure changed its terminal workflow authority")
    elif decision == "retry" and workflow_post_status != "running":
        raise WorkflowStoredContractError("Retry failure cannot terminalize its workflow")
    elif workflow_post_status not in {"running", "degraded"}:
        raise WorkflowStoredContractError("Optional failure returned an invalid workflow settlement")

    retry_intent = locked.retry_intent
    retry_child = locked.stage_ready_reservation
    cancellation_child = locked.outbox_cancellation_reservation
    next_attempt_at = locked.next_attempt_at
    if decision == "retry":
        if (
            type(retry_child) is not StageReadyReservation
            or retry_intent is None
            or next_attempt_at is None
            or type(next_attempt_at) is not datetime
            or next_attempt_at.tzinfo is None
            or cancellation_child is not None
            or locked.retry_message_id is None
            or type(retry_child.intents) is not tuple
            or retry_child.intents != (retry_intent,)
            or retry_child.message_ids != (locked.retry_message_id,)
            or retry_intent.pre_target.stage_run_id != source.id
            or retry_intent.post_target.stage_run_id != source.id
            or retry_intent.pre_target.status != "running"
            or retry_intent.post_target.status != "retry_wait"
            or retry_intent.post_target.state_version != source.state_version + 1
            or retry_intent.post_target.next_attempt_at != next_attempt_at
            or retry_intent.post_target.last_error_code != safe_evidence.code
            or retry_intent.post_target.last_error_summary != safe_evidence.summary
            or not retry_intent.post_target.last_error_retryable
        ):
            raise WorkflowStoredContractError("Failure retry append authority is not an exact fixed point")
        next_attempt_at = _aware_internal_datetime(next_attempt_at, field_name="failure next_attempt_at")
    elif (
        retry_intent is not None
        or retry_child is not None
        or next_attempt_at is not None
        or locked.retry_message_id is not None
        or (required_terminal != (type(cancellation_child) is OutboxCancellationReservation))
    ):
        raise WorkflowStoredContractError("Terminal failure child authority has an invalid shape")

    locked_messages = locked.locked_messages
    locked_deliveries = locked.locked_deliveries
    if (
        type(locked_messages) is not tuple
        or any(type(message) is not OutboxMessage for message in locked_messages)
        or type(locked_deliveries) is not tuple
        or any(type(delivery) is not OutboxDeliveryAttempt for delivery in locked_deliveries)
    ):
        raise WorkflowStoredContractError("Failure runtime returned invalid outbox persistence authority")
    workflow_before = _worker_model_snapshot(workflow)
    stage_before = {stage.id: _worker_model_snapshot(stage) for stage in stages}
    attempt_before = {attempt.id: _worker_model_snapshot(attempt) for attempt in attempts}
    message_before = {message.id: _worker_model_snapshot(message) for message in locked_messages}
    delivery_before = {delivery.id: _worker_model_snapshot(delivery) for delivery in locked_deliveries}

    cancelled_deliveries: tuple[OutboxDeliveryAttempt, ...] = ()
    cancelled_messages: tuple[OutboxMessage, ...] = ()
    if cancellation_child is not None:
        cancelled = await _cancel_reserved_outbox_messages(
            db,
            reservation=cancellation_child,
        )
        if type(cancelled) is not tuple or len(cancelled) != 2:
            raise WorkflowStoredContractError("Failure cancellation returned invalid effect facts")
        cancelled_deliveries, cancelled_messages = cancelled
        if (
            type(cancelled_deliveries) is not tuple
            or type(cancelled_messages) is not tuple
            or len(cancelled_deliveries) != len(cancellation_child.deliveries)
            or len(cancelled_messages) != len(cancellation_child.messages)
            or any(actual is not expected for actual, expected in zip(cancelled_deliveries, cancellation_child.deliveries, strict=True))
            or any(actual is not expected for actual, expected in zip(cancelled_messages, cancellation_child.messages, strict=True))
            or tuple(delivery.id for delivery in cancelled_deliveries) != cancellation_child.delivery_ids
            or tuple(message.id for message in cancelled_messages) != cancellation_child.message_ids
        ):
            raise WorkflowStoredContractError("Failure cancellation changed its reserved outbox identity set")
        _assert_cancelled_outbox_effect(
            cancellation_child,
            delivery_before=delivery_before,
            message_before=message_before,
        )

    # Attempt evidence is terminalized before any logical stage transition.
    for attempt in attempts:
        stage = stages_by_id.get(attempt.stage_run_id)
        if stage is None:
            raise WorkflowStoredContractError("Failure attempt is outside its complete stage plan")
        if stage is source:
            expected_attempt_status = "failed"
            expected_error_code = safe_evidence.code
            expected_error_class = safe_evidence.error_class
            expected_error_summary = safe_evidence.summary
            expected_retryable = safe_evidence.retryable
        else:
            expected_attempt_status = "cancelled"
            expected_error_code = workflow_reason_code
            expected_error_class = _FAILURE_CANCELLATION_CLASS
            expected_error_summary = _FAILURE_CANCELLATION_SUMMARY
            expected_retryable = False
        attempt.status = expected_attempt_status
        attempt.error_code = expected_error_code
        attempt.error_class = expected_error_class
        attempt.error_summary = expected_error_summary
        attempt.retryable = expected_retryable
        attempt.state_version += 1
        attempt.checkpoint_end_version = stage.checkpoint_version
        attempt.output_checksum = ""
        if stage is source:
            # A failed attempt can authorize a retry emission only at the
            # exact terminal heartbeat fixed point.  Collateral cancellation
            # retains its last observed heartbeat as historical evidence.
            attempt.heartbeat_at = now
        attempt.completed_at = now
        await db.flush([attempt])
        if (
            attempt.status != expected_attempt_status
            or attempt.state_version != _snapshot_field(attempt_before[attempt.id], "state_version") + 1
            or attempt.checkpoint_end_version != stage.checkpoint_version
            or attempt.output_checksum != ""
            or attempt.error_code != expected_error_code
            or attempt.error_class != expected_error_class
            or attempt.error_summary != expected_error_summary
            or attempt.retryable != expected_retryable
            or (stage is source and attempt.heartbeat_at != now)
            or attempt.completed_at != now
        ):
            raise WorkflowStoredContractError("Failure attempt changed while being flushed")

    changed_stages: list[StageRun] = []
    for stage, post_status in zip(stages, post_statuses, strict=True):
        if stage.status == post_status:
            continue
        original_status = stage.status
        stage.status = post_status
        stage.state_version += 1
        if stage is source:
            stage.output_manifest = {}
            stage.output_checksum = ""
            stage.last_error_code = safe_evidence.code
            stage.last_error_summary = safe_evidence.summary
            stage.last_error_retryable = safe_evidence.retryable
            stage.next_attempt_at = next_attempt_at if decision == "retry" else None
            stage.completed_at = None if decision == "retry" else now
            _clear_worker_stage_lease(stage)
        elif post_status == "skipped":
            if original_status != "pending":
                raise WorkflowStoredContractError("Failure skip closure changed a non-pending stage")
            stage.completed_at = now
        elif post_status == "cancelled":
            if original_status not in {"pending", "ready", "running", "retry_wait"}:
                raise WorkflowStoredContractError("Failure cancellation changed a terminal stage")
            stage.next_attempt_at = None
            stage.output_manifest = {}
            stage.output_checksum = ""
            stage.last_error_code = ""
            stage.last_error_summary = ""
            stage.last_error_retryable = False
            stage.completed_at = now
            _clear_worker_stage_lease(stage)
        else:
            raise WorkflowStoredContractError("Failure settlement requested an unsupported stage transition")
        await db.flush([stage])
        if (
            stage.status != post_status
            or stage.state_version != _snapshot_field(stage_before[stage.id], "state_version") + 1
            or (stage is source and stage.output_manifest != {})
            or (stage is source and stage.output_checksum != "")
            or (stage is source and stage.last_error_code != safe_evidence.code)
            or (stage is source and stage.last_error_summary != safe_evidence.summary)
            or (stage is source and stage.last_error_retryable != safe_evidence.retryable)
            or (stage is source and stage.next_attempt_at != (next_attempt_at if decision == "retry" else None))
            or (stage is source and stage.completed_at != (None if decision == "retry" else now))
            or (stage is not source and post_status == "skipped" and stage.completed_at != now)
            or (stage is not source and post_status == "cancelled" and stage.next_attempt_at is not None)
            or (stage is not source and post_status == "cancelled" and stage.output_manifest != {})
            or (stage is not source and post_status == "cancelled" and stage.output_checksum != "")
            or (stage is not source and post_status == "cancelled" and stage.last_error_code != "")
            or (stage is not source and post_status == "cancelled" and stage.last_error_summary != "")
            or (stage is not source and post_status == "cancelled" and stage.last_error_retryable)
            or (stage is not source and post_status == "cancelled" and stage.completed_at != now)
            or (post_status != "skipped" and stage.lease_owner != "")
            or (post_status != "skipped" and stage.lease_token is not None)
            or (post_status != "skipped" and stage.leased_at is not None)
            or (post_status != "skipped" and stage.lease_expires_at is not None)
            or (post_status != "skipped" and stage.heartbeat_at is not None)
        ):
            raise WorkflowStoredContractError("Failure stage changed while being flushed")
        changed_stages.append(stage)

    retry_emission: _StageFailureRetryEmissionFacts | None = None
    if retry_child is not None:
        appended = await _append_reserved_stage_ready(
            db,
            reservation=retry_child,
            workflow=workflow,
            locked_stages=stages,
            causal_attempt=source_attempt,
        )
        if type(appended) is not tuple or len(appended) != 1:
            raise WorkflowStoredContractError("Failure retry append returned an incomplete result")
        item = appended[0]
        if type(item) is not tuple or len(item) != 2 or type(item[1]) is not bool or not item[1]:
            raise WorkflowStoredContractError("Failure retry append did not create one exact root")
        retry_message = item[0]
        _assert_appended_failure_retry_message(
            retry_message,
            intent=retry_intent,
            expected_message_id=locked.retry_message_id,
            workflow=workflow,
            causal_attempt=source_attempt,
            available_at=next_attempt_at,
        )
        retry_emission = _StageFailureRetryEmissionFacts(
            stage_run_id=credential.stage_run_id,
            stage_key=source.stage_key,
            stage_state_version=source.state_version,
            message_id=locked.retry_message_id,
            logical_key=retry_message.logical_key,
            available_at=retry_message.available_at,
        )

    workflow_completed_at: datetime | None = None
    if workflow_post_status != "running":
        workflow.status = workflow_post_status
        workflow.state_version += 1
        workflow.status_reason_code = workflow_reason_code
        workflow.status_summary = workflow_summary
        workflow.completed_at = now
        await db.flush([workflow])
        workflow_completed_at = now
        if (
            workflow.status != workflow_post_status
            or workflow.state_version != credential.workflow_state_version + 1
            or workflow.status_reason_code != workflow_reason_code
            or workflow.status_summary != workflow_summary
            or workflow.completed_at != now
        ):
            raise WorkflowStoredContractError("Failure workflow aggregate changed while being flushed")
    elif workflow.status != "running" or workflow.state_version != credential.workflow_state_version or workflow.completed_at is not None:
        raise WorkflowStoredContractError("Active workflow aggregate changed during stage failure")

    _assert_worker_model_changes(
        workflow,
        workflow_before,
        allowed=(
            {"status", "state_version", "status_reason_code", "status_summary", "completed_at"}
            if workflow_completed_at is not None
            else set()
        ),
        field_name="failure workflow",
    )
    source_allowed = {
        "status",
        "state_version",
        "output_manifest",
        "output_checksum",
        "next_attempt_at",
        "lease_owner",
        "lease_token",
        "leased_at",
        "lease_expires_at",
        "heartbeat_at",
        "last_error_code",
        "last_error_summary",
        "last_error_retryable",
        "completed_at",
    }
    cancelled_stage_allowed = {
        "status",
        "state_version",
        "output_manifest",
        "output_checksum",
        "next_attempt_at",
        "lease_owner",
        "lease_token",
        "leased_at",
        "lease_expires_at",
        "heartbeat_at",
        "last_error_code",
        "last_error_summary",
        "last_error_retryable",
        "completed_at",
    }
    for stage in stages:
        if stage is source:
            allowed = source_allowed
        elif stage.id in skipped_stage_ids:
            allowed = {"status", "state_version", "completed_at"}
        elif stage.id in cancelled_stage_ids:
            allowed = cancelled_stage_allowed
        else:
            allowed = set()
        _assert_worker_model_changes(
            stage,
            stage_before[stage.id],
            allowed=allowed,
            field_name=f"failure stage {stage.stage_key}",
        )
    attempt_allowed = {
        "status",
        "state_version",
        "checkpoint_end_version",
        "output_checksum",
        "error_code",
        "error_class",
        "error_summary",
        "retryable",
        "completed_at",
    }
    for attempt in attempts:
        _assert_worker_model_changes(
            attempt,
            attempt_before[attempt.id],
            allowed=attempt_allowed | {"heartbeat_at"} if attempt is source_attempt else attempt_allowed,
            field_name="failure attempt",
        )
    cancelled_message_id_set = set(message.id for message in cancelled_messages)
    cancelled_delivery_id_set = set(delivery.id for delivery in cancelled_deliveries)
    message_allowed = {
        "status",
        "state_version",
        "available_at",
        "active_delivery_attempt_id",
        "lease_owner",
        "lease_token",
        "leased_at",
        "lease_expires_at",
        "heartbeat_at",
        "receipt_deadline_at",
        "cancelled_at",
        "cancelled_by",
        "cancelled_by_id",
        "cancel_reason",
    }
    delivery_allowed = {
        "status",
        "state_version",
        "receipt_deadline_at",
        "receipt_received_at",
        "completed_at",
        "error_code",
        "error_class",
        "error_summary",
        "retryable",
    }
    for message in locked_messages:
        _assert_worker_model_changes(
            message,
            message_before[message.id],
            allowed=message_allowed if message.id in cancelled_message_id_set else set(),
            field_name="failure locked message",
        )
    for delivery in locked_deliveries:
        _assert_worker_model_changes(
            delivery,
            delivery_before[delivery.id],
            allowed=delivery_allowed if delivery.id in cancelled_delivery_id_set else set(),
            field_name="failure locked delivery",
        )

    return _StageFailureMutationFacts(
        evidence=safe_evidence,
        decision=decision,
        workflow_state_version=workflow.state_version,
        workflow_status=workflow.status,
        stage_state_version=source.state_version,
        attempt_state_version=source_attempt.state_version,
        attempt_completed_at=now,
        stage_completed_at=None if decision == "retry" else now,
        workflow_completed_at=workflow_completed_at,
        next_attempt_at=next_attempt_at,
        skipped_stage_ids=skipped_stage_ids,
        cancelled_stage_ids=cancelled_stage_ids,
        cancelled_attempt_ids=cancelled_attempt_ids,
        cancelled_message_ids=(cancellation_child.message_ids if cancellation_child is not None else ()),
        cancelled_delivery_ids=(cancellation_child.delivery_ids if cancellation_child is not None else ()),
        retry_emission=retry_emission,
    )


async def _reserve_consume_and_cancel(
    db: AsyncSession,
    *,
    command: object,
) -> _WorkflowCancellationMutationFacts:
    """Reserve, consume, and apply/replay cancellation without a Locked seam."""

    safe_command = _copy_presented_cancellation_command(command)
    reservation = await _reserve_workflow_terminalization_graph(
        db,
        command=safe_command,
    )
    locked = await _consume_workflow_terminalization_graph(
        db,
        reservation=reservation,
        command=safe_command,
    )
    if (
        type(locked) is not LockedWorkflowTerminalizationGraph
        or locked.command != safe_command
        or type(locked.stages) is not tuple
        or not locked.stages
        or any(type(stage) is not StageRun for stage in locked.stages)
        or type(locked.locked_attempts) is not tuple
        or any(type(attempt) is not StageAttempt for attempt in locked.locked_attempts)
        or type(locked.locked_messages) is not tuple
        or any(type(message) is not OutboxMessage for message in locked.locked_messages)
        or type(locked.locked_deliveries) is not tuple
        or any(type(delivery) is not OutboxDeliveryAttempt for delivery in locked.locked_deliveries)
    ):
        raise WorkflowStoredContractError("Cancellation runtime returned invalid locked graph authority")
    workflow = locked.workflow
    stages = locked.stages
    attempts = locked.locked_attempts
    if type(workflow) is not WorkflowRun:
        raise WorkflowStoredContractError("Cancellation runtime returned invalid workflow authority")
    now = _aware_internal_datetime(locked.observed_at, field_name="consumed cancellation observed_at")
    projection = locked.projection
    post_statuses = getattr(projection, "post_stage_statuses", None)
    cancelled_stage_ids = _exact_internal_uuid_tuple(
        getattr(projection, "cancelled_stage_ids", None),
        field_name="cancellation projected stage ids",
    )
    cancelled_attempt_ids = _exact_internal_uuid_tuple(
        getattr(projection, "cancelled_attempt_ids", None),
        field_name="cancellation projected attempt ids",
    )
    if (
        type(post_statuses) is not tuple
        or len(post_statuses) != len(stages)
        or getattr(projection, "decision", None) != locked.decision
        or locked.decision not in {"apply", "replay"}
    ):
        raise WorkflowStoredContractError("Cancellation projection changed its complete stage fixed point")

    workflow_before = _worker_model_snapshot(workflow)
    stage_before = {stage.id: _worker_model_snapshot(stage) for stage in stages}
    attempt_before = {attempt.id: _worker_model_snapshot(attempt) for attempt in attempts}
    message_before = {message.id: _worker_model_snapshot(message) for message in locked.locked_messages}
    delivery_before = {delivery.id: _worker_model_snapshot(delivery) for delivery in locked.locked_deliveries}

    child = locked.outbox_cancellation_reservation
    if locked.decision == "replay":
        if child is not None or cancelled_stage_ids or cancelled_attempt_ids:
            raise WorkflowStoredContractError("Cancellation replay retained mutation authority")
        cancelled_at = _aware_internal_datetime(
            workflow.cancel_requested_at,
            field_name="persisted cancellation requested_at",
        )
        if (
            workflow.id != safe_command.workflow_run_id
            or workflow.status != "cancelled"
            or workflow.state_version != safe_command.expected_workflow_state_version + 1
            or workflow.cancel_request_id != safe_command.request_id
            or workflow.cancel_requested_by != safe_command.actor
            or workflow.cancel_requested_by_id != safe_command.actor_id
            or workflow.cancel_reason != safe_command.reason
            or workflow.completed_at != cancelled_at
            or tuple(stage.status for stage in stages) != post_statuses
        ):
            raise WorkflowStoredContractError("Cancellation replay changed its persisted command fixed point")
        _assert_worker_model_changes(workflow, workflow_before, allowed=set(), field_name="cancellation replay workflow")
        for stage in stages:
            _assert_worker_model_changes(
                stage,
                stage_before[stage.id],
                allowed=set(),
                field_name="cancellation replay stage",
            )
        for attempt in attempts:
            _assert_worker_model_changes(
                attempt,
                attempt_before[attempt.id],
                allowed=set(),
                field_name="cancellation replay attempt",
            )
        for message in locked.locked_messages:
            _assert_worker_model_changes(
                message,
                message_before[message.id],
                allowed=set(),
                field_name="cancellation replay message",
            )
        for delivery in locked.locked_deliveries:
            _assert_worker_model_changes(
                delivery,
                delivery_before[delivery.id],
                allowed=set(),
                field_name="cancellation replay delivery",
            )
        return _WorkflowCancellationMutationFacts(
            command=safe_command,
            decision="replay",
            workflow_state_version=workflow.state_version,
            cancelled_at=cancelled_at,
            cancelled_stage_ids=(),
            cancelled_attempt_ids=(),
            cancelled_message_ids=(),
            cancelled_delivery_ids=(),
        )

    if type(child) is not OutboxCancellationReservation:
        raise WorkflowStoredContractError("Applied cancellation lacks transferred outbox authority")
    if (
        workflow.id != safe_command.workflow_run_id
        or workflow.status not in {"queued", "running"}
        or workflow.state_version != safe_command.expected_workflow_state_version
        or workflow.cancel_request_id is not None
        or workflow.completed_at is not None
    ):
        raise WorkflowStoredContractError("Applied cancellation changed its locked workflow authority")
    _assert_mutation_version_headroom(
        (
            workflow,
            *(stage for stage, post_status in zip(stages, post_statuses, strict=True) if stage.status != post_status),
            *attempts,
            *child.messages,
            *child.deliveries,
        ),
        field_name="cancellation",
    )

    cancelled = await _cancel_reserved_outbox_messages(db, reservation=child)
    if type(cancelled) is not tuple or len(cancelled) != 2:
        raise WorkflowStoredContractError("Cancellation child returned invalid effect facts")
    cancelled_deliveries, cancelled_messages = cancelled
    if (
        type(cancelled_deliveries) is not tuple
        or type(cancelled_messages) is not tuple
        or tuple(delivery.id for delivery in cancelled_deliveries) != child.delivery_ids
        or tuple(message.id for message in cancelled_messages) != child.message_ids
        or any(actual is not expected for actual, expected in zip(cancelled_deliveries, child.deliveries, strict=True))
        or any(actual is not expected for actual, expected in zip(cancelled_messages, child.messages, strict=True))
    ):
        raise WorkflowStoredContractError("Cancellation child changed its reserved outbox identity set")
    _assert_cancelled_outbox_effect(
        child,
        delivery_before=delivery_before,
        message_before=message_before,
    )

    stages_by_id = {stage.id: stage for stage in stages}
    for attempt in attempts:
        stage = stages_by_id.get(attempt.stage_run_id)
        if stage is None or stage.status != "running":
            raise WorkflowStoredContractError("Cancellation attempt is outside one running plan stage")
        attempt.status = "cancelled"
        attempt.state_version += 1
        attempt.checkpoint_end_version = stage.checkpoint_version
        attempt.output_checksum = ""
        attempt.error_code = _EXPLICIT_CANCELLATION_CODE
        attempt.error_class = _FAILURE_CANCELLATION_CLASS
        attempt.error_summary = safe_command.reason
        attempt.retryable = False
        attempt.completed_at = now
        await db.flush([attempt])
        if (
            attempt.status != "cancelled"
            or attempt.state_version != _snapshot_field(attempt_before[attempt.id], "state_version") + 1
            or attempt.checkpoint_end_version != stage.checkpoint_version
            or attempt.output_checksum != ""
            or attempt.error_code != _EXPLICIT_CANCELLATION_CODE
            or attempt.error_class != _FAILURE_CANCELLATION_CLASS
            or attempt.error_summary != safe_command.reason
            or attempt.retryable
            or attempt.completed_at != now
        ):
            raise WorkflowStoredContractError("Cancellation attempt changed while being flushed")

    for stage, post_status in zip(stages, post_statuses, strict=True):
        if stage.status == post_status:
            continue
        if stage.status not in {"pending", "ready", "running", "retry_wait"} or post_status != "cancelled":
            raise WorkflowStoredContractError("Cancellation stage projection requested an invalid transition")
        stage.status = "cancelled"
        stage.state_version += 1
        stage.next_attempt_at = None
        stage.output_manifest = {}
        stage.output_checksum = ""
        stage.last_error_code = ""
        stage.last_error_summary = ""
        stage.last_error_retryable = False
        stage.completed_at = now
        _clear_worker_stage_lease(stage)
        await db.flush([stage])
        if (
            stage.status != "cancelled"
            or stage.state_version != _snapshot_field(stage_before[stage.id], "state_version") + 1
            or stage.next_attempt_at is not None
            or stage.output_manifest != {}
            or stage.output_checksum != ""
            or stage.last_error_code != ""
            or stage.last_error_summary != ""
            or stage.last_error_retryable
            or stage.completed_at != now
            or stage.lease_owner != ""
            or stage.lease_token is not None
            or stage.leased_at is not None
            or stage.lease_expires_at is not None
            or stage.heartbeat_at is not None
        ):
            raise WorkflowStoredContractError("Cancellation stage changed while being flushed")

    workflow.status = "cancelled"
    workflow.state_version += 1
    workflow.status_reason_code = ""
    workflow.status_summary = ""
    workflow.cancel_request_id = safe_command.request_id
    workflow.cancel_requested_by = safe_command.actor
    workflow.cancel_requested_by_id = safe_command.actor_id
    workflow.cancel_reason = safe_command.reason
    workflow.cancel_requested_at = now
    workflow.completed_at = now
    await db.flush([workflow])
    if (
        workflow.status != "cancelled"
        or workflow.state_version != safe_command.expected_workflow_state_version + 1
        or workflow.status_reason_code != ""
        or workflow.status_summary != ""
        or workflow.cancel_request_id != safe_command.request_id
        or workflow.cancel_requested_by != safe_command.actor
        or workflow.cancel_requested_by_id != safe_command.actor_id
        or workflow.cancel_reason != safe_command.reason
        or workflow.cancel_requested_at != now
        or workflow.completed_at != now
        or tuple(stage.status for stage in stages) != post_statuses
    ):
        raise WorkflowStoredContractError("Cancellation workflow changed while being flushed")

    _assert_worker_model_changes(
        workflow,
        workflow_before,
        allowed={
            "status",
            "state_version",
            "status_reason_code",
            "status_summary",
            "cancel_request_id",
            "cancel_requested_by",
            "cancel_requested_by_id",
            "cancel_reason",
            "cancel_requested_at",
            "completed_at",
        },
        field_name="cancellation workflow",
    )
    stage_allowed = {
        "status",
        "state_version",
        "output_manifest",
        "output_checksum",
        "next_attempt_at",
        "lease_owner",
        "lease_token",
        "leased_at",
        "lease_expires_at",
        "heartbeat_at",
        "last_error_code",
        "last_error_summary",
        "last_error_retryable",
        "completed_at",
    }
    cancelled_stage_set = set(cancelled_stage_ids)
    for stage in stages:
        _assert_worker_model_changes(
            stage,
            stage_before[stage.id],
            allowed=stage_allowed if stage.id in cancelled_stage_set else set(),
            field_name="cancellation stage",
        )
    attempt_allowed = {
        "status",
        "state_version",
        "checkpoint_end_version",
        "output_checksum",
        "error_code",
        "error_class",
        "error_summary",
        "retryable",
        "completed_at",
    }
    for attempt in attempts:
        _assert_worker_model_changes(
            attempt,
            attempt_before[attempt.id],
            allowed=attempt_allowed,
            field_name="cancellation attempt",
        )
    cancelled_message_set = set(child.message_ids)
    cancelled_delivery_set = set(child.delivery_ids)
    message_allowed = {
        "status",
        "state_version",
        "available_at",
        "active_delivery_attempt_id",
        "lease_owner",
        "lease_token",
        "leased_at",
        "lease_expires_at",
        "heartbeat_at",
        "receipt_deadline_at",
        "cancelled_at",
        "cancelled_by",
        "cancelled_by_id",
        "cancel_reason",
    }
    delivery_allowed = {
        "status",
        "state_version",
        "receipt_deadline_at",
        "receipt_received_at",
        "completed_at",
        "error_code",
        "error_class",
        "error_summary",
        "retryable",
    }
    for message in locked.locked_messages:
        _assert_worker_model_changes(
            message,
            message_before[message.id],
            allowed=message_allowed if message.id in cancelled_message_set else set(),
            field_name="cancellation locked message",
        )
    for delivery in locked.locked_deliveries:
        _assert_worker_model_changes(
            delivery,
            delivery_before[delivery.id],
            allowed=delivery_allowed if delivery.id in cancelled_delivery_set else set(),
            field_name="cancellation locked delivery",
        )

    return _WorkflowCancellationMutationFacts(
        command=safe_command,
        decision="apply",
        workflow_state_version=workflow.state_version,
        cancelled_at=now,
        cancelled_stage_ids=cancelled_stage_ids,
        cancelled_attempt_ids=cancelled_attempt_ids,
        cancelled_message_ids=child.message_ids,
        cancelled_delivery_ids=child.delivery_ids,
    )


async def _reserve_consume_and_recover_one(
    db: AsyncSession,
) -> _StageRecoveryMutationFacts | None:
    """Auto-select, consume, and recover one expired delivered receipt graph."""

    reservation = await _reserve_one_expired_stage_recovery(db)
    if reservation is None:
        return None
    locked = await _consume_stage_recovery_graph(
        db,
        reservation=reservation,
    )
    if (
        type(locked) is not LockedStageRecoveryGraph
        or type(locked.stages) is not tuple
        or not locked.stages
        or any(type(stage) is not StageRun for stage in locked.stages)
        or type(locked.locked_attempts) is not tuple
        or any(type(attempt) is not StageAttempt for attempt in locked.locked_attempts)
        or type(locked.locked_messages) is not tuple
        or any(type(message) is not OutboxMessage for message in locked.locked_messages)
        or type(locked.locked_deliveries) is not tuple
        or any(type(delivery) is not OutboxDeliveryAttempt for delivery in locked.locked_deliveries)
        or type(locked.source_stage_index) is not int
        or not 0 <= locked.source_stage_index < len(locked.stages)
    ):
        raise WorkflowStoredContractError("Recovery runtime returned invalid locked graph authority")
    credential = _copy_internal_authority(locked.source_authority)
    workflow = locked.workflow
    stages = locked.stages
    attempts = locked.locked_attempts
    if type(workflow) is not WorkflowRun:
        raise WorkflowStoredContractError("Recovery runtime returned invalid workflow authority")
    source = stages[locked.source_stage_index]
    attempts_by_id = {attempt.id: attempt for attempt in attempts}
    source_attempt = attempts_by_id.get(locked.source_attempt_id)
    now = _aware_internal_datetime(locked.observed_at, field_name="consumed recovery observed_at")
    if (
        source_attempt is None
        or workflow.id != credential.workflow_run_id
        or workflow.status != "running"
        or workflow.state_version != credential.workflow_state_version
        or source.id != credential.stage_run_id
        or source.stage_key != credential.stage_key
        or source.status != "running"
        or source.state_version != credential.stage_state_version
        or source.input_checksum != credential.input_checksum
        or source.checkpoint_version != credential.checkpoint_version
        or source.lease_token != credential.stage_lease_token
        or source.lease_owner != credential.lease_owner
        or source.lease_expires_at != credential.lease_expires_at
        or source.lease_expires_at is None
        or source.lease_expires_at > now
        or source_attempt.id != credential.stage_attempt_id
        or source_attempt.stage_run_id != credential.stage_run_id
        or source_attempt.outbox_delivery_attempt_id != credential.delivery_attempt_id
        or source_attempt.attempt_number != credential.attempt_number
        or source_attempt.status != "running"
        or source_attempt.state_version != credential.attempt_state_version
        or source_attempt.lease_token != credential.stage_lease_token
        or source_attempt.lease_owner != credential.lease_owner
        or source_attempt.input_checksum != credential.input_checksum
        or source_attempt.checkpoint_end_version != credential.checkpoint_version
        or source_attempt.lease_expires_at != credential.lease_expires_at
        or source.state_version >= 2_147_483_647
        or source_attempt.state_version >= 2_147_483_647
    ):
        raise WorkflowStoredContractError("Recovery rows contradict their expired receipt authority")

    settlement = locked.settlement
    decision = locked.decision
    post_statuses = getattr(settlement, "post_stage_statuses", None)
    skipped_stage_ids = _exact_internal_uuid_tuple(
        getattr(settlement, "skipped_stage_ids", None),
        field_name="recovery skipped stage ids",
    )
    cancelled_stage_ids = _exact_internal_uuid_tuple(
        getattr(settlement, "cancelled_stage_ids", None),
        field_name="recovery cancelled stage ids",
    )
    cancelled_attempt_ids = _exact_internal_uuid_tuple(
        getattr(settlement, "cancelled_attempt_ids", None),
        field_name="recovery cancelled attempt ids",
    )
    workflow_post_status = getattr(settlement, "workflow_post_status", None)
    workflow_reason_code = getattr(settlement, "workflow_reason_code", None)
    workflow_summary = getattr(settlement, "workflow_summary", None)
    if (
        decision not in {"retry", "dead_lettered"}
        or getattr(settlement, "decision", None) != decision
        or type(post_statuses) is not tuple
        or len(post_statuses) != len(stages)
        or type(workflow_post_status) is not str
        or workflow_post_status not in {"running", "degraded", "dead_lettered"}
        or type(workflow_reason_code) is not str
        or type(workflow_summary) is not str
    ):
        raise WorkflowStoredContractError("Recovery settlement changed its fixed point")
    next_attempt_at = locked.next_attempt_at
    retry_intent = locked.retry_intent
    retry_child = locked.stage_ready_reservation
    cancellation_child = locked.outbox_cancellation_reservation
    required_terminal = bool(source.required) and decision == "dead_lettered"
    if decision == "retry":
        if (
            next_attempt_at is None
            or retry_intent is None
            or type(retry_child) is not StageReadyReservation
            or cancellation_child is not None
            or locked.retry_message_id is None
            or post_statuses[locked.source_stage_index] != "retry_wait"
            or workflow_post_status != "running"
        ):
            raise WorkflowStoredContractError("Retry recovery child authority has an invalid shape")
        next_attempt_at = _aware_internal_datetime(next_attempt_at, field_name="recovery next_attempt_at")
    elif (
        next_attempt_at is not None
        or retry_intent is not None
        or retry_child is not None
        or locked.retry_message_id is not None
        or (required_terminal != (type(cancellation_child) is OutboxCancellationReservation))
        or post_statuses[locked.source_stage_index] != "dead_lettered"
    ):
        raise WorkflowStoredContractError("Exhausted recovery child authority has an invalid shape")
    attempts_by_id = {attempt.id: attempt for attempt in attempts}
    if source_attempt.id in cancelled_attempt_ids or any(attempt_id not in attempts_by_id for attempt_id in cancelled_attempt_ids):
        raise WorkflowStoredContractError("Recovery settlement changed its exact attempt identity set")
    mutated_attempt_ids = {source_attempt.id, *cancelled_attempt_ids}
    mutated_attempts = tuple(attempt for attempt in attempts if attempt.id in mutated_attempt_ids)
    if len(mutated_attempts) != len(mutated_attempt_ids):
        raise WorkflowStoredContractError("Recovery mutation attempts are outside the locked graph")
    _assert_mutation_version_headroom(
        (
            *((workflow,) if workflow_post_status != "running" else ()),
            *(stage for stage, post_status in zip(stages, post_statuses, strict=True) if stage.status != post_status),
            *mutated_attempts,
            *((cancellation_child.messages) if cancellation_child is not None else ()),
            *((cancellation_child.deliveries) if cancellation_child is not None else ()),
        ),
        field_name="recovery",
    )

    workflow_before = _worker_model_snapshot(workflow)
    stage_before = {stage.id: _worker_model_snapshot(stage) for stage in stages}
    attempt_before = {attempt.id: _worker_model_snapshot(attempt) for attempt in attempts}
    message_before = {message.id: _worker_model_snapshot(message) for message in locked.locked_messages}
    delivery_before = {delivery.id: _worker_model_snapshot(delivery) for delivery in locked.locked_deliveries}

    cancelled_deliveries: tuple[OutboxDeliveryAttempt, ...] = ()
    cancelled_messages: tuple[OutboxMessage, ...] = ()
    if cancellation_child is not None:
        cancelled = await _cancel_reserved_outbox_messages(
            db,
            reservation=cancellation_child,
        )
        if type(cancelled) is not tuple or len(cancelled) != 2:
            raise WorkflowStoredContractError("Recovery cancellation returned invalid effect facts")
        cancelled_deliveries, cancelled_messages = cancelled
        if (
            type(cancelled_deliveries) is not tuple
            or type(cancelled_messages) is not tuple
            or tuple(delivery.id for delivery in cancelled_deliveries) != cancellation_child.delivery_ids
            or tuple(message.id for message in cancelled_messages) != cancellation_child.message_ids
            or any(actual is not expected for actual, expected in zip(cancelled_deliveries, cancellation_child.deliveries, strict=True))
            or any(actual is not expected for actual, expected in zip(cancelled_messages, cancellation_child.messages, strict=True))
        ):
            raise WorkflowStoredContractError("Recovery cancellation changed its reserved identity set")
        _assert_cancelled_outbox_effect(
            cancellation_child,
            delivery_before=delivery_before,
            message_before=message_before,
        )

    stages_by_id = {stage.id: stage for stage in stages}
    for attempt in mutated_attempts:
        stage = stages_by_id.get(attempt.stage_run_id)
        if stage is None:
            raise WorkflowStoredContractError("Recovery attempt is outside its complete stage plan")
        if attempt is source_attempt:
            expected_status = "abandoned"
            error_code = _LEASE_EXPIRED_CODE
            error_class = _LEASE_EXPIRED_CLASS
            error_summary = _LEASE_EXPIRED_SUMMARY
            retryable = True
        else:
            expected_status = "cancelled"
            error_code = workflow_reason_code
            error_class = _FAILURE_CANCELLATION_CLASS
            error_summary = _FAILURE_CANCELLATION_SUMMARY
            retryable = False
        attempt.status = expected_status
        attempt.state_version += 1
        attempt.checkpoint_end_version = stage.checkpoint_version
        attempt.output_checksum = ""
        attempt.error_code = error_code
        attempt.error_class = error_class
        attempt.error_summary = error_summary
        attempt.retryable = retryable
        attempt.completed_at = now
        await db.flush([attempt])
        if (
            attempt.status != expected_status
            or attempt.state_version != _snapshot_field(attempt_before[attempt.id], "state_version") + 1
            or attempt.checkpoint_end_version != stage.checkpoint_version
            or attempt.output_checksum != ""
            or attempt.error_code != error_code
            or attempt.error_class != error_class
            or attempt.error_summary != error_summary
            or attempt.retryable != retryable
            or attempt.completed_at != now
        ):
            raise WorkflowStoredContractError("Recovery attempt changed while being flushed")

    changed_stages: list[StageRun] = []
    for stage, post_status in zip(stages, post_statuses, strict=True):
        if stage.status == post_status:
            continue
        original_status = stage.status
        stage.status = post_status
        stage.state_version += 1
        if stage is source:
            stage.output_manifest = {}
            stage.output_checksum = ""
            stage.last_error_code = _LEASE_EXPIRED_CODE
            stage.last_error_summary = _LEASE_EXPIRED_SUMMARY
            stage.last_error_retryable = True
            stage.next_attempt_at = next_attempt_at if decision == "retry" else None
            stage.completed_at = None if decision == "retry" else now
            _clear_worker_stage_lease(stage)
        elif post_status == "skipped":
            if original_status != "pending":
                raise WorkflowStoredContractError("Recovery skip closure changed a non-pending stage")
            stage.completed_at = now
        elif post_status == "cancelled":
            if original_status not in {"pending", "ready", "running", "retry_wait"}:
                raise WorkflowStoredContractError("Recovery cancellation changed a terminal stage")
            stage.next_attempt_at = None
            stage.output_manifest = {}
            stage.output_checksum = ""
            stage.last_error_code = ""
            stage.last_error_summary = ""
            stage.last_error_retryable = False
            stage.completed_at = now
            _clear_worker_stage_lease(stage)
        else:
            raise WorkflowStoredContractError("Recovery settlement requested an unsupported stage transition")
        await db.flush([stage])
        if (
            stage.status != post_status
            or stage.state_version != _snapshot_field(stage_before[stage.id], "state_version") + 1
            or (stage is source and stage.output_manifest != {})
            or (stage is source and stage.output_checksum != "")
            or (stage is source and stage.last_error_code != _LEASE_EXPIRED_CODE)
            or (stage is source and stage.last_error_summary != _LEASE_EXPIRED_SUMMARY)
            or (stage is source and not stage.last_error_retryable)
            or (stage is source and stage.next_attempt_at != (next_attempt_at if decision == "retry" else None))
            or (stage is source and stage.completed_at != (None if decision == "retry" else now))
            or (stage is not source and post_status == "skipped" and stage.completed_at != now)
            or (stage is not source and post_status == "cancelled" and stage.next_attempt_at is not None)
            or (stage is not source and post_status == "cancelled" and stage.output_manifest != {})
            or (stage is not source and post_status == "cancelled" and stage.output_checksum != "")
            or (stage is not source and post_status == "cancelled" and stage.last_error_code != "")
            or (stage is not source and post_status == "cancelled" and stage.last_error_summary != "")
            or (stage is not source and post_status == "cancelled" and stage.last_error_retryable)
            or (stage is not source and post_status == "cancelled" and stage.completed_at != now)
            or (post_status != "skipped" and stage.lease_owner != "")
            or (post_status != "skipped" and stage.lease_token is not None)
            or (post_status != "skipped" and stage.leased_at is not None)
            or (post_status != "skipped" and stage.lease_expires_at is not None)
            or (post_status != "skipped" and stage.heartbeat_at is not None)
        ):
            raise WorkflowStoredContractError("Recovery stage changed while being flushed")
        changed_stages.append(stage)

    retry_emission: _StageRecoveryRetryEmissionFacts | None = None
    if retry_child is not None:
        appended = await _append_reserved_stage_ready(
            db,
            reservation=retry_child,
            workflow=workflow,
            locked_stages=stages,
            causal_attempt=source_attempt,
        )
        if type(appended) is not tuple or len(appended) != 1:
            raise WorkflowStoredContractError("Recovery append returned an incomplete result")
        item = appended[0]
        if type(item) is not tuple or len(item) != 2 or type(item[1]) is not bool or not item[1]:
            raise WorkflowStoredContractError("Recovery append did not create one exact root")
        retry_message = item[0]
        _assert_appended_failure_retry_message(
            retry_message,
            intent=retry_intent,
            expected_message_id=locked.retry_message_id,
            workflow=workflow,
            causal_attempt=source_attempt,
            available_at=next_attempt_at,
            emission_kind="lease_recovered",
        )
        retry_emission = _StageRecoveryRetryEmissionFacts(
            stage_run_id=credential.stage_run_id,
            stage_key=source.stage_key,
            stage_state_version=source.state_version,
            message_id=locked.retry_message_id,
            logical_key=retry_message.logical_key,
            available_at=retry_message.available_at,
        )

    if workflow_post_status != "running":
        workflow.status = workflow_post_status
        workflow.state_version += 1
        workflow.status_reason_code = workflow_reason_code
        workflow.status_summary = workflow_summary
        workflow.completed_at = now
        await db.flush([workflow])
        if (
            workflow.status != workflow_post_status
            or workflow.state_version != credential.workflow_state_version + 1
            or workflow.status_reason_code != workflow_reason_code
            or workflow.status_summary != workflow_summary
            or workflow.completed_at != now
        ):
            raise WorkflowStoredContractError("Recovery workflow aggregate changed while being flushed")
    elif workflow.status != "running" or workflow.state_version != credential.workflow_state_version or workflow.completed_at is not None:
        raise WorkflowStoredContractError("Active workflow aggregate changed during recovery")

    _assert_worker_model_changes(
        workflow,
        workflow_before,
        allowed=(
            {"status", "state_version", "status_reason_code", "status_summary", "completed_at"}
            if workflow_post_status != "running"
            else set()
        ),
        field_name="recovery workflow",
    )
    source_allowed = {
        "status",
        "state_version",
        "output_manifest",
        "output_checksum",
        "next_attempt_at",
        "lease_owner",
        "lease_token",
        "leased_at",
        "lease_expires_at",
        "heartbeat_at",
        "last_error_code",
        "last_error_summary",
        "last_error_retryable",
        "completed_at",
    }
    cancelled_stage_allowed = set(source_allowed)
    skipped_set = set(skipped_stage_ids)
    cancelled_stage_set = set(cancelled_stage_ids)
    for stage in stages:
        if stage is source:
            allowed = source_allowed
        elif stage.id in skipped_set:
            allowed = {"status", "state_version", "completed_at"}
        elif stage.id in cancelled_stage_set:
            allowed = cancelled_stage_allowed
        else:
            allowed = set()
        _assert_worker_model_changes(
            stage,
            stage_before[stage.id],
            allowed=allowed,
            field_name="recovery stage",
        )
    attempt_allowed = {
        "status",
        "state_version",
        "checkpoint_end_version",
        "output_checksum",
        "error_code",
        "error_class",
        "error_summary",
        "retryable",
        "completed_at",
    }
    for attempt in attempts:
        _assert_worker_model_changes(
            attempt,
            attempt_before[attempt.id],
            allowed=attempt_allowed if attempt.id in mutated_attempt_ids else set(),
            field_name="recovery attempt",
        )
    cancelled_message_set = set(cancellation_child.message_ids if cancellation_child is not None else ())
    cancelled_delivery_set = set(cancellation_child.delivery_ids if cancellation_child is not None else ())
    message_allowed = {
        "status",
        "state_version",
        "available_at",
        "active_delivery_attempt_id",
        "lease_owner",
        "lease_token",
        "leased_at",
        "lease_expires_at",
        "heartbeat_at",
        "receipt_deadline_at",
        "cancelled_at",
        "cancelled_by",
        "cancelled_by_id",
        "cancel_reason",
    }
    delivery_allowed = {
        "status",
        "state_version",
        "receipt_deadline_at",
        "receipt_received_at",
        "completed_at",
        "error_code",
        "error_class",
        "error_summary",
        "retryable",
    }
    for message in locked.locked_messages:
        _assert_worker_model_changes(
            message,
            message_before[message.id],
            allowed=message_allowed if message.id in cancelled_message_set else set(),
            field_name="recovery locked message",
        )
    for delivery in locked.locked_deliveries:
        _assert_worker_model_changes(
            delivery,
            delivery_before[delivery.id],
            allowed=delivery_allowed if delivery.id in cancelled_delivery_set else set(),
            field_name="recovery locked delivery",
        )

    return _StageRecoveryMutationFacts(
        workflow_run_id=credential.workflow_run_id,
        stage_run_id=credential.stage_run_id,
        stage_attempt_id=credential.stage_attempt_id,
        message_id=credential.message_id,
        delivery_attempt_id=credential.delivery_attempt_id,
        stage_lease_token=credential.stage_lease_token,
        attempt_number=credential.attempt_number,
        delivery_cycle=credential.delivery_cycle,
        cycle_key=credential.cycle_key,
        broker_receipt_id=credential.broker_receipt_id,
        stage_key=credential.stage_key,
        input_checksum=credential.input_checksum,
        checkpoint_version=credential.checkpoint_version,
        lease_owner=credential.lease_owner,
        lease_expires_at=credential.lease_expires_at,
        decision=decision,
        previous_workflow_state_version=credential.workflow_state_version,
        workflow_state_version=workflow.state_version,
        workflow_status=workflow.status,
        previous_stage_state_version=credential.stage_state_version,
        stage_state_version=source.state_version,
        previous_attempt_state_version=credential.attempt_state_version,
        attempt_state_version=source_attempt.state_version,
        recovered_at=now,
        next_attempt_at=next_attempt_at,
        skipped_stage_ids=skipped_stage_ids,
        cancelled_stage_ids=cancelled_stage_ids,
        cancelled_attempt_ids=cancelled_attempt_ids,
        cancelled_message_ids=(cancellation_child.message_ids if cancellation_child is not None else ()),
        cancelled_delivery_ids=(cancellation_child.delivery_ids if cancellation_child is not None else ()),
        retry_emission=retry_emission,
    )


def _assert_checkpoint_confirmation(
    locked: LockedStageExecutionReceipt,
    *,
    pending: _PendingStageCheckpoint,
) -> None:
    if type(locked) is not LockedStageExecutionReceipt or locked.authority != pending._candidate:
        raise WorkflowStoredContractError("Checkpoint confirmation lacks its exact receipt authority")
    try:
        stored_schema, stored_payload, stored_checksum = _canonical_checkpoint_request(
            locked.stage.checkpoint_schema_version,
            locked.stage.checkpoint,
        )
    except WorkflowValidation as exc:
        raise WorkflowStoredContractError("Committed checkpoint is not bounded canonical JSON") from exc
    if (
        stored_schema != pending.checkpoint_schema_version
        or stored_payload != locked.stage.checkpoint
        or stored_checksum != pending.committed_checkpoint_checksum
        or locked.stage.checkpoint_checksum != stored_checksum
        or locked.stage.checkpoint_version != pending._candidate.checkpoint_version
        or locked.attempt.checkpoint_end_version != pending._candidate.checkpoint_version
        or locked.stage.heartbeat_at != pending.heartbeat_at
        or locked.attempt.heartbeat_at != pending.heartbeat_at
        or locked.stage.lease_expires_at != pending._candidate.lease_expires_at
        or locked.attempt.lease_expires_at != pending._candidate.lease_expires_at
    ):
        raise WorkflowStoredContractError("Committed checkpoint contradicts its pending authority")


def _build_public_result(
    presented: ExecutableStageAuthority,
    *,
    pending: _PendingStageHeartbeat | None,
    disposition: HeartbeatDisposition,
    authority: ExecutableStageAuthority | None,
) -> CoordinatedStageHeartbeat:
    if pending is None:
        result_authority = presented
        heartbeat_at = None
    else:
        if pending.presented != presented:
            raise WorkflowStoredContractError("Pending heartbeat changed its presented lineage")
        result_authority = pending._candidate
        heartbeat_at = pending.heartbeat_at
    return CoordinatedStageHeartbeat(
        workflow_run_id=presented.workflow_run_id,
        stage_run_id=presented.stage_run_id,
        stage_attempt_id=presented.stage_attempt_id,
        message_id=presented.message_id,
        delivery_attempt_id=presented.delivery_attempt_id,
        stage_lease_token=presented.stage_lease_token,
        attempt_number=presented.attempt_number,
        delivery_cycle=presented.delivery_cycle,
        cycle_key=presented.cycle_key,
        broker_receipt_id=presented.broker_receipt_id,
        stage_key=presented.stage_key,
        input_checksum=presented.input_checksum,
        checkpoint_version=presented.checkpoint_version,
        lease_owner=presented.lease_owner,
        workflow_state_version=presented.workflow_state_version,
        previous_stage_state_version=presented.stage_state_version,
        stage_state_version=result_authority.stage_state_version,
        previous_attempt_state_version=presented.attempt_state_version,
        attempt_state_version=result_authority.attempt_state_version,
        previous_lease_expires_at=presented.lease_expires_at,
        heartbeat_at=heartbeat_at,
        lease_expires_at=result_authority.lease_expires_at,
        disposition=disposition,
        authority=authority,
        should_continue=disposition == "renewed",
    )


def _build_public_checkpoint_result(
    presented: ExecutableStageAuthority,
    *,
    checkpoint_schema_version: str,
    requested_checkpoint_checksum: str,
    pending: _PendingStageCheckpoint | None,
    disposition: CheckpointDisposition,
    authority: ExecutableStageAuthority | None,
) -> CoordinatedStageCheckpoint:
    if pending is None:
        result_authority = presented
        committed_checksum = None
        heartbeat_at = None
    else:
        if (
            pending.presented != presented
            or pending.checkpoint_schema_version != checkpoint_schema_version
            or pending.requested_checkpoint_checksum != requested_checkpoint_checksum
        ):
            raise WorkflowStoredContractError("Pending checkpoint changed its request lineage")
        result_authority = pending._candidate
        committed_checksum = pending.committed_checkpoint_checksum
        heartbeat_at = pending.heartbeat_at
    return CoordinatedStageCheckpoint(
        workflow_run_id=presented.workflow_run_id,
        stage_run_id=presented.stage_run_id,
        stage_attempt_id=presented.stage_attempt_id,
        message_id=presented.message_id,
        delivery_attempt_id=presented.delivery_attempt_id,
        stage_lease_token=presented.stage_lease_token,
        attempt_number=presented.attempt_number,
        delivery_cycle=presented.delivery_cycle,
        cycle_key=presented.cycle_key,
        broker_receipt_id=presented.broker_receipt_id,
        stage_key=presented.stage_key,
        input_checksum=presented.input_checksum,
        checkpoint_schema_version=checkpoint_schema_version,
        requested_checkpoint_checksum=requested_checkpoint_checksum,
        committed_checkpoint_checksum=committed_checksum,
        lease_owner=presented.lease_owner,
        workflow_state_version=presented.workflow_state_version,
        previous_checkpoint_version=presented.checkpoint_version,
        checkpoint_version=result_authority.checkpoint_version,
        previous_stage_state_version=presented.stage_state_version,
        stage_state_version=result_authority.stage_state_version,
        previous_attempt_state_version=presented.attempt_state_version,
        attempt_state_version=result_authority.attempt_state_version,
        previous_lease_expires_at=presented.lease_expires_at,
        heartbeat_at=heartbeat_at,
        lease_expires_at=result_authority.lease_expires_at,
        disposition=disposition,
        authority=authority,
        should_continue=disposition == "renewed",
    )


def _build_public_completion_result(
    presented: ExecutableStageAuthority,
    *,
    outcome: CompletionOutcome,
    requested_output_checksum: str,
    facts: _StageCompletionMutationFacts | None,
    disposition: CompletionDisposition,
) -> CoordinatedStageCompletion:
    if facts is None:
        workflow_version = presented.workflow_state_version
        workflow_status = "running"
        stage_version = presented.stage_state_version
        attempt_version = presented.attempt_state_version
        committed_checksum = None
        completed_at = None
        workflow_completed_at = None
        emissions: tuple[CoordinatedStageEmission, ...] = ()
    else:
        if (
            facts.outcome != outcome
            or facts.requested_output_checksum != requested_output_checksum
            or facts.stage_state_version != presented.stage_state_version + 1
            or facts.attempt_state_version != presented.attempt_state_version + 1
        ):
            raise WorkflowStoredContractError("Committed completion facts changed their request lineage")
        workflow_version = facts.workflow_state_version
        workflow_status = facts.workflow_status
        stage_version = facts.stage_state_version
        attempt_version = facts.attempt_state_version
        committed_checksum = facts.committed_output_checksum
        completed_at = facts.completed_at
        workflow_completed_at = facts.workflow_completed_at
        emissions = tuple(
            CoordinatedStageEmission(
                stage_run_id=item.stage_run_id,
                stage_key=item.stage_key,
                stage_state_version=item.stage_state_version,
                message_id=item.message_id,
                logical_key=item.logical_key,
                available_at=item.available_at,
            )
            for item in facts.emissions
        )
    return CoordinatedStageCompletion(
        workflow_run_id=presented.workflow_run_id,
        stage_run_id=presented.stage_run_id,
        stage_attempt_id=presented.stage_attempt_id,
        message_id=presented.message_id,
        delivery_attempt_id=presented.delivery_attempt_id,
        stage_lease_token=presented.stage_lease_token,
        attempt_number=presented.attempt_number,
        delivery_cycle=presented.delivery_cycle,
        cycle_key=presented.cycle_key,
        broker_receipt_id=presented.broker_receipt_id,
        stage_key=presented.stage_key,
        input_checksum=presented.input_checksum,
        checkpoint_version=presented.checkpoint_version,
        lease_owner=presented.lease_owner,
        lease_expires_at=presented.lease_expires_at,
        outcome=outcome,
        requested_output_checksum=requested_output_checksum,
        committed_output_checksum=committed_checksum,
        previous_workflow_state_version=presented.workflow_state_version,
        workflow_state_version=workflow_version,
        workflow_status=workflow_status,
        previous_stage_state_version=presented.stage_state_version,
        stage_state_version=stage_version,
        previous_attempt_state_version=presented.attempt_state_version,
        attempt_state_version=attempt_version,
        completed_at=completed_at,
        workflow_completed_at=workflow_completed_at,
        emissions=emissions,
        disposition=disposition,
        should_continue=False,
        should_ack=True,
    )


def _build_public_failure_result(
    presented: ExecutableStageAuthority,
    *,
    evidence: StageFailureEvidence,
    facts: _StageFailureMutationFacts | None,
    disposition: FailureDisposition,
) -> CoordinatedStageFailure:
    safe_evidence = _copy_internal_failure_evidence(evidence)
    if facts is None:
        decision: FailureDecision | None = None
        workflow_version = presented.workflow_state_version
        workflow_status = "running"
        stage_version = presented.stage_state_version
        attempt_version = presented.attempt_state_version
        attempt_completed_at = None
        stage_completed_at = None
        workflow_completed_at = None
        next_attempt_at = None
        skipped_stage_ids: tuple[uuid.UUID, ...] = ()
        cancelled_stage_ids: tuple[uuid.UUID, ...] = ()
        cancelled_attempt_ids: tuple[uuid.UUID, ...] = ()
        cancelled_message_ids: tuple[uuid.UUID, ...] = ()
        cancelled_delivery_ids: tuple[uuid.UUID, ...] = ()
        retry_emission = None
    else:
        if (
            facts.evidence != safe_evidence
            or facts.stage_state_version != presented.stage_state_version + 1
            or facts.attempt_state_version != presented.attempt_state_version + 1
        ):
            raise WorkflowStoredContractError("Committed failure facts changed their request lineage")
        decision = facts.decision
        workflow_version = facts.workflow_state_version
        workflow_status = facts.workflow_status
        stage_version = facts.stage_state_version
        attempt_version = facts.attempt_state_version
        attempt_completed_at = facts.attempt_completed_at
        stage_completed_at = facts.stage_completed_at
        workflow_completed_at = facts.workflow_completed_at
        next_attempt_at = facts.next_attempt_at
        skipped_stage_ids = facts.skipped_stage_ids
        cancelled_stage_ids = facts.cancelled_stage_ids
        cancelled_attempt_ids = facts.cancelled_attempt_ids
        cancelled_message_ids = facts.cancelled_message_ids
        cancelled_delivery_ids = facts.cancelled_delivery_ids
        retry_emission = (
            None
            if facts.retry_emission is None
            else CoordinatedStageEmission(
                stage_run_id=facts.retry_emission.stage_run_id,
                stage_key=facts.retry_emission.stage_key,
                stage_state_version=facts.retry_emission.stage_state_version,
                message_id=facts.retry_emission.message_id,
                logical_key=facts.retry_emission.logical_key,
                available_at=facts.retry_emission.available_at,
            )
        )
    return CoordinatedStageFailure(
        workflow_run_id=presented.workflow_run_id,
        stage_run_id=presented.stage_run_id,
        stage_attempt_id=presented.stage_attempt_id,
        message_id=presented.message_id,
        delivery_attempt_id=presented.delivery_attempt_id,
        stage_lease_token=presented.stage_lease_token,
        attempt_number=presented.attempt_number,
        delivery_cycle=presented.delivery_cycle,
        cycle_key=presented.cycle_key,
        broker_receipt_id=presented.broker_receipt_id,
        stage_key=presented.stage_key,
        input_checksum=presented.input_checksum,
        checkpoint_version=presented.checkpoint_version,
        lease_owner=presented.lease_owner,
        lease_expires_at=presented.lease_expires_at,
        error_code=safe_evidence.code,
        error_class=safe_evidence.error_class,
        error_summary=safe_evidence.summary,
        retryable=safe_evidence.retryable,
        decision=decision,
        previous_workflow_state_version=presented.workflow_state_version,
        workflow_state_version=workflow_version,
        workflow_status=workflow_status,
        previous_stage_state_version=presented.stage_state_version,
        stage_state_version=stage_version,
        previous_attempt_state_version=presented.attempt_state_version,
        attempt_state_version=attempt_version,
        attempt_completed_at=attempt_completed_at,
        stage_completed_at=stage_completed_at,
        workflow_completed_at=workflow_completed_at,
        next_attempt_at=next_attempt_at,
        skipped_stage_ids=skipped_stage_ids,
        cancelled_stage_ids=cancelled_stage_ids,
        cancelled_attempt_ids=cancelled_attempt_ids,
        cancelled_message_ids=cancelled_message_ids,
        cancelled_delivery_ids=cancelled_delivery_ids,
        retry_emission=retry_emission,
        disposition=disposition,
        should_retry=disposition == "recorded" and decision == "retry",
        should_continue=False,
        should_ack=True,
    )


def _build_public_cancellation_result(
    facts: _WorkflowCancellationMutationFacts,
) -> CoordinatedWorkflowCancellation:
    if type(facts) is not _WorkflowCancellationMutationFacts:
        raise WorkflowStoredContractError("Committed cancellation facts have an invalid private type")
    command = _copy_internal_cancellation_command(facts.command)
    return CoordinatedWorkflowCancellation(
        request_id=command.request_id,
        workflow_run_id=command.workflow_run_id,
        actor=command.actor,
        actor_id=command.actor_id,
        reason=command.reason,
        previous_workflow_state_version=command.expected_workflow_state_version,
        workflow_state_version=facts.workflow_state_version,
        cancelled_at=facts.cancelled_at,
        cancelled_stage_ids=facts.cancelled_stage_ids,
        cancelled_attempt_ids=facts.cancelled_attempt_ids,
        cancelled_message_ids=facts.cancelled_message_ids,
        cancelled_delivery_ids=facts.cancelled_delivery_ids,
        disposition="applied" if facts.decision == "apply" else "replayed",
        should_apply=facts.decision == "apply",
    )


def _build_public_recovery_result(
    facts: _StageRecoveryMutationFacts,
) -> CoordinatedStageRecovery:
    if type(facts) is not _StageRecoveryMutationFacts:
        raise WorkflowStoredContractError("Committed recovery facts have an invalid private type")
    emission = (
        None
        if facts.retry_emission is None
        else CoordinatedStageEmission(
            stage_run_id=facts.retry_emission.stage_run_id,
            stage_key=facts.retry_emission.stage_key,
            stage_state_version=facts.retry_emission.stage_state_version,
            message_id=facts.retry_emission.message_id,
            logical_key=facts.retry_emission.logical_key,
            available_at=facts.retry_emission.available_at,
        )
    )
    return CoordinatedStageRecovery(
        workflow_run_id=facts.workflow_run_id,
        stage_run_id=facts.stage_run_id,
        stage_attempt_id=facts.stage_attempt_id,
        message_id=facts.message_id,
        delivery_attempt_id=facts.delivery_attempt_id,
        stage_lease_token=facts.stage_lease_token,
        attempt_number=facts.attempt_number,
        delivery_cycle=facts.delivery_cycle,
        cycle_key=facts.cycle_key,
        broker_receipt_id=facts.broker_receipt_id,
        stage_key=facts.stage_key,
        input_checksum=facts.input_checksum,
        checkpoint_version=facts.checkpoint_version,
        lease_owner=facts.lease_owner,
        lease_expires_at=facts.lease_expires_at,
        decision=facts.decision,
        previous_workflow_state_version=facts.previous_workflow_state_version,
        workflow_state_version=facts.workflow_state_version,
        workflow_status=facts.workflow_status,
        previous_stage_state_version=facts.previous_stage_state_version,
        stage_state_version=facts.stage_state_version,
        stage_status="retry_wait" if facts.decision == "retry" else "dead_lettered",
        previous_attempt_state_version=facts.previous_attempt_state_version,
        attempt_state_version=facts.attempt_state_version,
        attempt_status="abandoned",
        recovered_at=facts.recovered_at,
        next_attempt_at=facts.next_attempt_at,
        skipped_stage_ids=facts.skipped_stage_ids,
        cancelled_stage_ids=facts.cancelled_stage_ids,
        cancelled_attempt_ids=facts.cancelled_attempt_ids,
        cancelled_message_ids=facts.cancelled_message_ids,
        cancelled_delivery_ids=facts.cancelled_delivery_ids,
        retry_emission=emission,
        should_retry=facts.decision == "retry",
        should_continue=False,
    )


def _renewed_authority(
    value: ExecutableStageAuthority,
    *,
    stage_state_version: int,
    attempt_state_version: int,
    checkpoint_version: int | None = None,
    lease_expires_at: datetime,
) -> ExecutableStageAuthority:
    return ExecutableStageAuthority(
        workflow_run_id=value.workflow_run_id,
        stage_run_id=value.stage_run_id,
        stage_attempt_id=value.stage_attempt_id,
        message_id=value.message_id,
        delivery_attempt_id=value.delivery_attempt_id,
        stage_lease_token=value.stage_lease_token,
        workflow_state_version=value.workflow_state_version,
        stage_state_version=stage_state_version,
        attempt_state_version=attempt_state_version,
        attempt_number=value.attempt_number,
        delivery_cycle=value.delivery_cycle,
        cycle_key=value.cycle_key,
        stage_key=value.stage_key,
        input_checksum=value.input_checksum,
        checkpoint_version=value.checkpoint_version if checkpoint_version is None else checkpoint_version,
        lease_owner=value.lease_owner,
        lease_expires_at=lease_expires_at,
        broker_receipt_id=value.broker_receipt_id,
    )


def _copy_presented_authority(value: object) -> ExecutableStageAuthority:
    if type(value) is not ExecutableStageAuthority:
        raise OutboxValidation("authority must be exact executable stage authority")
    try:
        return _renewed_authority(
            value,
            stage_state_version=value.stage_state_version,
            attempt_state_version=value.attempt_state_version,
            lease_expires_at=value.lease_expires_at,
        )
    except AttributeError as exc:
        raise OutboxValidation("executable stage authority fields are incomplete") from exc


def _copy_internal_authority(value: object) -> ExecutableStageAuthority:
    try:
        return _copy_presented_authority(value)
    except (AttributeError, OutboxValidation) as exc:
        raise WorkflowStoredContractError("Worker runtime returned invalid executable authority") from exc


def _copy_public_authority(value: object) -> ExecutableStageAuthority:
    try:
        return _copy_presented_authority(value)
    except (AttributeError, OutboxValidation) as exc:
        raise OutboxValidation("Renewed worker authority is invalid") from exc


def _copy_presented_cancellation_command(value: object) -> WorkflowCancellationCommand:
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
        raise OutboxValidation("Workflow cancellation command is not a public fixed point") from exc


def _copy_internal_cancellation_command(value: object) -> WorkflowCancellationCommand:
    try:
        return _copy_presented_cancellation_command(value)
    except (AttributeError, OutboxValidation) as exc:
        raise WorkflowStoredContractError("Cancellation runtime returned invalid command authority") from exc


def _canonical_failure_request(
    error_text: object,
    *,
    error_code: object,
    retryable: object,
    error_class: object,
) -> StageFailureEvidence:
    """Sanitize exact caller strings into the only accepted failure evidence."""

    try:
        safe = sanitize_workflow_error(
            error_text,  # type: ignore[arg-type]
            code=error_code,  # type: ignore[arg-type]
            retryable=retryable,  # type: ignore[arg-type]
            error_class=error_class,  # type: ignore[arg-type]
        )
        if type(safe) is not SanitizedWorkflowError:
            raise WorkflowContractError("Failure sanitizer returned an invalid result type")
        return StageFailureEvidence(
            code=safe.code,
            error_class=safe.error_class,
            summary=safe.summary,
            retryable=safe.retryable,
        )
    except (AttributeError, OutboxValidation, WorkflowContractError) as exc:
        raise WorkflowValidation("Stage failure evidence is invalid") from exc


def _copy_presented_failure_evidence(value: object) -> StageFailureEvidence:
    if type(value) is not StageFailureEvidence:
        raise WorkflowValidation("evidence must be exact sanitized stage failure evidence")
    try:
        return StageFailureEvidence(
            code=value.code,
            error_class=value.error_class,
            summary=value.summary,
            retryable=value.retryable,
        )
    except (AttributeError, OutboxValidation) as exc:
        raise WorkflowValidation("Stage failure evidence is invalid") from exc


def _copy_internal_failure_evidence(value: object) -> StageFailureEvidence:
    try:
        return _copy_presented_failure_evidence(value)
    except (AttributeError, OutboxValidation, WorkflowValidation) as exc:
        raise WorkflowStoredContractError("Worker runtime returned invalid failure evidence") from exc


def _public_failure_evidence(
    *,
    code: object,
    error_class: object,
    summary: object,
    retryable: object,
) -> StageFailureEvidence:
    try:
        safe = sanitize_workflow_error(
            summary,  # type: ignore[arg-type]
            code=code,  # type: ignore[arg-type]
            retryable=retryable,  # type: ignore[arg-type]
            error_class=error_class,  # type: ignore[arg-type]
        )
        evidence = StageFailureEvidence(
            code=safe.code,
            error_class=safe.error_class,
            summary=safe.summary,
            retryable=safe.retryable,
        )
    except (AttributeError, OutboxValidation, WorkflowContractError) as exc:
        raise OutboxValidation("Public failure evidence is invalid") from exc
    if (evidence.code, evidence.error_class, evidence.summary, evidence.retryable) != (
        code,
        error_class,
        summary,
        retryable,
    ):
        raise OutboxValidation("Public failure evidence is not a sanitizer fixed point")
    return evidence


def _assert_result_authority(
    result: CoordinatedStageHeartbeat,
    authority: ExecutableStageAuthority,
) -> None:
    if (
        authority.workflow_run_id != result.workflow_run_id
        or authority.stage_run_id != result.stage_run_id
        or authority.stage_attempt_id != result.stage_attempt_id
        or authority.message_id != result.message_id
        or authority.delivery_attempt_id != result.delivery_attempt_id
        or authority.stage_lease_token != result.stage_lease_token
        or authority.attempt_number != result.attempt_number
        or authority.delivery_cycle != result.delivery_cycle
        or authority.cycle_key != result.cycle_key
        or authority.broker_receipt_id != result.broker_receipt_id
        or authority.stage_key != result.stage_key
        or authority.input_checksum != result.input_checksum
        or authority.checkpoint_version != result.checkpoint_version
        or authority.lease_owner != result.lease_owner
        or authority.workflow_state_version != result.workflow_state_version
        or authority.stage_state_version != result.stage_state_version
        or authority.attempt_state_version != result.attempt_state_version
        or authority.lease_expires_at != result.lease_expires_at
    ):
        raise OutboxValidation("Renewed heartbeat authority contradicts its public result")


def _assert_checkpoint_result_authority(
    result: CoordinatedStageCheckpoint,
    authority: ExecutableStageAuthority,
) -> None:
    if (
        authority.workflow_run_id != result.workflow_run_id
        or authority.stage_run_id != result.stage_run_id
        or authority.stage_attempt_id != result.stage_attempt_id
        or authority.message_id != result.message_id
        or authority.delivery_attempt_id != result.delivery_attempt_id
        or authority.stage_lease_token != result.stage_lease_token
        or authority.attempt_number != result.attempt_number
        or authority.delivery_cycle != result.delivery_cycle
        or authority.cycle_key != result.cycle_key
        or authority.broker_receipt_id != result.broker_receipt_id
        or authority.stage_key != result.stage_key
        or authority.input_checksum != result.input_checksum
        or authority.checkpoint_version != result.checkpoint_version
        or authority.lease_owner != result.lease_owner
        or authority.workflow_state_version != result.workflow_state_version
        or authority.stage_state_version != result.stage_state_version
        or authority.attempt_state_version != result.attempt_state_version
        or authority.lease_expires_at != result.lease_expires_at
    ):
        raise OutboxValidation("Renewed checkpoint authority contradicts its public result")


def _active_root_transaction(db: AsyncSession) -> tuple[object, object]:
    sync_session = getattr(db, "sync_session", None)
    if (
        sync_session is None
        or not hasattr(sync_session, "get_transaction")
        or not hasattr(sync_session, "get_nested_transaction")
        or not hasattr(sync_session, "in_nested_transaction")
    ):
        raise WorkflowValidation("Workflow worker coordination requires an AsyncSession root transaction")
    if sync_session.in_nested_transaction() or sync_session.get_nested_transaction() is not None:
        raise WorkflowValidation("Workflow worker coordination cannot cross a nested transaction")
    transaction = sync_session.get_transaction()
    if transaction is None:
        raise WorkflowValidation("Workflow worker coordination requires an active root transaction")
    return sync_session, transaction


def _lease_seconds(value: object) -> int:
    return _bounded_int(
        value,
        field_name="lease_seconds",
        minimum=1,
        maximum=_MAX_LEASE_SECONDS,
    )


def _canonical_checkpoint_request(
    checkpoint_schema_version: object,
    checkpoint: object,
) -> tuple[str, dict[str, Any], str]:
    schema_version = _version_identity(
        checkpoint_schema_version,
        field_name="checkpoint_schema_version",
    )
    if type(checkpoint) is not dict:
        raise WorkflowValidation("checkpoint must be an exact JSON object")
    _reject_postgres_jsonb_nul(checkpoint)
    try:
        canonical = canonical_json(checkpoint)
        payload = json.loads(canonical)
        rebuilt = canonical_json(payload)
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise WorkflowValidation("checkpoint is not valid bounded canonical JSON") from exc
    if type(payload) is not dict or rebuilt != canonical:
        raise WorkflowValidation("checkpoint is not a canonical JSON object fixed point")
    checksum = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return schema_version, payload, checksum


def _canonical_completion_request(
    output_manifest: object,
    *,
    outcome: object,
) -> tuple[dict[str, Any], str, CompletionOutcome]:
    if type(outcome) is not str or outcome not in {"succeeded", "degraded"}:
        raise WorkflowValidation("outcome must be exactly succeeded or degraded")
    if type(output_manifest) is not dict:
        raise WorkflowValidation("output_manifest must be an exact JSON object")
    _reject_postgres_jsonb_nul(output_manifest, field_name="output_manifest")
    try:
        canonical = canonical_json(output_manifest)
        payload = json.loads(canonical)
        rebuilt = canonical_json(payload)
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise WorkflowValidation("output_manifest is not valid bounded canonical JSON") from exc
    if type(payload) is not dict or rebuilt != canonical:
        raise WorkflowValidation("output_manifest is not a canonical JSON object fixed point")
    checksum = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return payload, checksum, outcome


def _reject_postgres_jsonb_nul(
    value: dict[str, Any],
    *,
    field_name: str = "checkpoint",
) -> None:
    """Reject the one canonical JSON string value PostgreSQL JSONB cannot store."""

    pending: list[tuple[object, int]] = [(value, 0)]
    item_count = 0
    while pending:
        current, depth = pending.pop()
        if issubclass(type(current), str):
            if str.find(current, "\x00") != -1:
                raise WorkflowValidation(f"{field_name} cannot contain U+0000 in JSON keys or string values")
            continue
        if depth > MAX_JSON_DEPTH:
            continue  # Canonical validation emits the deterministic depth error.
        if type(current) is list:
            item_count += len(current)
            if item_count > MAX_JSON_ITEMS:
                continue  # Canonical validation emits the deterministic item error.
            pending.extend((item, depth + 1) for item in current)
        elif type(current) is dict:
            item_count += len(current)
            if item_count > MAX_JSON_ITEMS:
                continue  # Canonical validation emits the deterministic item error.
            for key, item in current.items():
                if issubclass(type(key), str) and str.find(key, "\x00") != -1:
                    raise WorkflowValidation(f"{field_name} cannot contain U+0000 in JSON keys or string values")
                pending.append((item, depth + 1))


def _clear_worker_stage_lease(stage: StageRun) -> None:
    stage.lease_owner = ""
    stage.lease_token = None
    stage.leased_at = None
    stage.lease_expires_at = None
    stage.heartbeat_at = None


def _assert_appended_completion_message(
    message: object,
    *,
    intent: object,
    expected_message_id: uuid.UUID,
    workflow: WorkflowRun,
    causal_attempt: StageAttempt,
    observed_at: datetime,
) -> None:
    """Verify every feasible non-system column of one newly flushed root."""

    if type(message) is not OutboxMessage:
        raise WorkflowStoredContractError("Completion append returned a non-message persistence type")
    post = intent.post_target
    if (
        message.id != expected_message_id
        or message.workflow_run_id != workflow.id
        or message.stage_run_id != post.stage_run_id
        or message.aggregate_type != "workflow_stage"
        or message.aggregate_id != post.stage_run_id
        or message.aggregate_version != post.state_version
        or message.emission_kind != "dependency_ready"
        or message.topic != OUTBOX_TOPIC_WORKFLOW_STAGE_READY
        or message.schema_version != OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1
        or message.correlation_id != workflow.correlation_id
        or message.causation_id != causal_attempt.id
        or message.stage_key != post.stage_key
        or message.target_attempt_number != intent.target_attempt_number
        or message.input_checksum != post.input_checksum
        or message.plan_checksum != workflow.plan_checksum
        or message.envelope_canonical != intent.envelope_canonical
        or message.envelope_checksum != intent.envelope_checksum
        or message.envelope_bytes != len(intent.envelope_canonical.encode("utf-8"))
        or message.logical_key != intent.logical_key
        or message.redrive_of_message_id is not None
        or message.redrive_ordinal != 0
        or message.redrive_requested_by != ""
        or message.redrive_requested_by_id != ""
        or message.redrive_reason != ""
        or message.redrive_requested_at is not None
        or message.status != "pending"
        or message.state_version != 1
        or message.attempt_count != 0
        or message.max_attempts != OUTBOX_V1_MAX_ATTEMPTS
        or message.delivery_cycle != 0
        or message.cycle_key is not None
        or message.available_at != observed_at
        or message.active_delivery_attempt_id is not None
        or message.lease_owner != ""
        or message.lease_token is not None
        or message.leased_at is not None
        or message.lease_expires_at is not None
        or message.heartbeat_at is not None
        or message.receipt_deadline_at is not None
        or message.last_error_code != ""
        or message.last_error_class != ""
        or message.last_error_summary != ""
        or message.last_error_retryable
        or message.delivered_at is not None
        or message.dead_lettered_at is not None
        or message.cancelled_at is not None
        or message.cancelled_by != ""
        or message.cancelled_by_id != ""
        or message.cancel_reason != ""
    ):
        raise WorkflowStoredContractError("Completion append changed its projected message fixed point")


def _assert_appended_failure_retry_message(
    message: object,
    *,
    intent: object,
    expected_message_id: object,
    workflow: WorkflowRun,
    causal_attempt: StageAttempt,
    available_at: object,
    emission_kind: Literal["retry_scheduled", "lease_recovered"] = "retry_scheduled",
) -> None:
    """Verify every feasible non-system column of one retry root."""

    if type(message) is not OutboxMessage:
        raise WorkflowStoredContractError("Failure append returned a non-message persistence type")
    try:
        post = intent.post_target
        expected_id = _exact_uuid(expected_message_id, field_name="failure retry message id")
        schedule = _aware_internal_datetime(available_at, field_name="failure retry available_at")
    except (AttributeError, OutboxValidation, WorkflowValidation) as exc:
        raise WorkflowStoredContractError("Failure retry append projection is invalid") from exc
    if (
        message.id != expected_id
        or message.workflow_run_id != workflow.id
        or message.stage_run_id != post.stage_run_id
        or message.aggregate_type != "workflow_stage"
        or message.aggregate_id != post.stage_run_id
        or message.aggregate_version != post.state_version
        or message.emission_kind != emission_kind
        or message.topic != OUTBOX_TOPIC_WORKFLOW_STAGE_READY
        or message.schema_version != OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1
        or message.correlation_id != workflow.correlation_id
        or message.causation_id != causal_attempt.id
        or message.stage_key != post.stage_key
        or message.target_attempt_number != intent.target_attempt_number
        or message.input_checksum != post.input_checksum
        or message.plan_checksum != workflow.plan_checksum
        or message.envelope_canonical != intent.envelope_canonical
        or message.envelope_checksum != intent.envelope_checksum
        or message.envelope_bytes != len(intent.envelope_canonical.encode("utf-8"))
        or message.logical_key != intent.logical_key
        or message.redrive_of_message_id is not None
        or message.redrive_ordinal != 0
        or message.redrive_requested_by != ""
        or message.redrive_requested_by_id != ""
        or message.redrive_reason != ""
        or message.redrive_requested_at is not None
        or message.status != "pending"
        or message.state_version != 1
        or message.attempt_count != 0
        or message.max_attempts != OUTBOX_V1_MAX_ATTEMPTS
        or message.delivery_cycle != 0
        or message.cycle_key is not None
        or message.available_at != schedule
        or message.active_delivery_attempt_id is not None
        or message.lease_owner != ""
        or message.lease_token is not None
        or message.leased_at is not None
        or message.lease_expires_at is not None
        or message.heartbeat_at is not None
        or message.receipt_deadline_at is not None
        or message.last_error_code != ""
        or message.last_error_class != ""
        or message.last_error_summary != ""
        or message.last_error_retryable
        or message.delivered_at is not None
        or message.dead_lettered_at is not None
        or message.cancelled_at is not None
        or message.cancelled_by != ""
        or message.cancelled_by_id != ""
        or message.cancel_reason != ""
    ):
        raise WorkflowStoredContractError("Failure retry append changed its projected message fixed point")


def _assert_cancelled_outbox_effect(
    reservation: OutboxCancellationReservation,
    *,
    delivery_before: dict[uuid.UUID, tuple[tuple[str, object], ...]],
    message_before: dict[uuid.UUID, tuple[tuple[str, object], ...]],
) -> None:
    """Verify the exact D-then-M terminal effect of a transferred child."""

    if type(reservation) is not OutboxCancellationReservation:
        raise WorkflowStoredContractError("Failure cancellation authority has an invalid type")
    for delivery in reservation.deliveries:
        before = delivery_before.get(delivery.id)
        if before is None:
            raise WorkflowStoredContractError("Cancelled delivery was absent from the locked graph")
        if (
            delivery.status != "cancelled"
            or delivery.state_version != _snapshot_field(before, "state_version") + 1
            or delivery.receipt_deadline_at is not None
            or delivery.receipt_received_at is not None
            or delivery.completed_at != reservation.transaction_at
            or delivery.error_code != reservation.error_code
            or delivery.error_class != reservation.error_class
            or delivery.error_summary != reservation.error_summary
            or delivery.retryable
        ):
            raise WorkflowStoredContractError("Failure cancellation changed its reserved delivery effect")
    for message in reservation.messages:
        before = message_before.get(message.id)
        if before is None:
            raise WorkflowStoredContractError("Cancelled message was absent from the locked graph")
        if (
            message.status != "cancelled"
            or message.state_version != _snapshot_field(before, "state_version") + 1
            or message.available_at is not None
            or message.active_delivery_attempt_id is not None
            or message.lease_owner != ""
            or message.lease_token is not None
            or message.leased_at is not None
            or message.lease_expires_at is not None
            or message.heartbeat_at is not None
            or message.receipt_deadline_at is not None
            or message.cancelled_at != reservation.transaction_at
            or message.cancelled_by != reservation.cancelled_by
            or message.cancelled_by_id != reservation.cancelled_by_id
            or message.cancel_reason != reservation.cancel_reason
        ):
            raise WorkflowStoredContractError("Failure cancellation changed its reserved message effect")


def _worker_model_snapshot(value: object) -> tuple[tuple[str, object], ...]:
    table = getattr(type(value), "__table__", None)
    if table is None:
        raise WorkflowStoredContractError("Completion authority has no persistence column registry")
    return tuple(
        (column.key, copy.deepcopy(getattr(value, column.key)))
        for column in table.columns
        # Server/onupdate timestamps are deliberately outside business
        # authority.  SQLAlchemy may expire them after flush, and reading an
        # expired value would violate the query-free post-consume cut.
        if column.key != "updated_at"
    )


def _snapshot_field(before: tuple[tuple[str, object], ...], field_name: str) -> object:
    for name, value in before:
        if name == field_name:
            return value
    raise WorkflowStoredContractError(f"Persistence snapshot is missing {field_name}")


def _exact_internal_uuid_tuple(value: object, *, field_name: str) -> tuple[uuid.UUID, ...]:
    if type(value) is not tuple:
        raise WorkflowStoredContractError(f"{field_name} must be an exact tuple")
    try:
        copied = tuple(_exact_uuid(item, field_name=field_name) for item in value)
    except OutboxValidation as exc:
        raise WorkflowStoredContractError(f"{field_name} contains invalid identities") from exc
    if len(set(copied)) != len(copied):
        raise WorkflowStoredContractError(f"{field_name} contains duplicate identities")
    return copied


def _assert_worker_model_changes(
    value: object,
    before: tuple[tuple[str, object], ...],
    *,
    allowed: set[str],
    field_name: str,
) -> None:
    after = _worker_model_snapshot(value)
    if tuple(name for name, _item in before) != tuple(name for name, _item in after):
        raise WorkflowStoredContractError(f"{field_name} column authority changed shape")
    changed = {before_item[0] for before_item, after_item in zip(before, after, strict=True) if before_item != after_item}
    if not changed.issubset(allowed):
        raise WorkflowStoredContractError(f"{field_name} changed outside its completion allowlist")


def _assert_mutation_version_headroom(
    values: tuple[object, ...],
    *,
    field_name: str,
) -> None:
    """Fail before the first write when any projected version would overflow."""

    if type(values) is not tuple:
        raise WorkflowStoredContractError(f"{field_name} version authority is not an exact tuple")
    for value in values:
        version = getattr(value, "state_version", None)
        if type(version) is not int or not 1 <= version < 2_147_483_647:
            raise WorkflowStoredContractError(f"{field_name} state_version has no mutation headroom")


def _exact_uuid(value: object, *, field_name: str) -> uuid.UUID:
    if type(value) is not uuid.UUID:
        raise OutboxValidation(f"{field_name} must be an exact UUID")
    return value


def _lower_sha256(value: object, *, field_name: str) -> str:
    if type(value) is not str or not _LOWER_SHA256_RE.fullmatch(value):
        raise OutboxValidation(f"{field_name} must be an exact lowercase SHA-256 value")
    return value


def _identity(value: object, *, field_name: str) -> str:
    if type(value) is not str or not _IDENTITY_RE.fullmatch(value):
        raise OutboxValidation(f"{field_name} must be a lowercase identity")
    return value


def _version_identity(value: object, *, field_name: str) -> str:
    if type(value) is not str or not _VERSION_RE.fullmatch(value):
        raise WorkflowValidation(f"{field_name} must be an exact version identity up to 80 characters")
    return value


def _text(value: object, *, field_name: str, maximum: int) -> str:
    if type(value) is not str or not value or value != value.strip() or len(value) > maximum:
        raise OutboxValidation(f"{field_name} must contain exact bounded text")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise OutboxValidation(f"{field_name} must be valid UTF-8 text") from exc
    if any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in value):
        raise OutboxValidation(f"{field_name} cannot contain control characters")
    return value


def _aware_datetime(value: object, *, field_name: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise OutboxValidation(f"{field_name} must be an exact timezone-aware datetime")
    return value


def _aware_internal_datetime(value: object, *, field_name: str) -> datetime:
    try:
        return _aware_datetime(value, field_name=field_name)
    except OutboxValidation as exc:
        raise WorkflowStoredContractError(f"{field_name} is invalid persisted authority") from exc


def _bounded_int(
    value: object,
    *,
    field_name: str,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise WorkflowValidation(f"{field_name} must be an integer from {minimum} to {maximum}")
    return value


def _state_version(value: object, *, field_name: str) -> int:
    return _bounded_int(
        value,
        field_name=field_name,
        minimum=1,
        maximum=2_147_483_647,
    )
