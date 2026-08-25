"""Broker-facing orchestration for durable research workflow stages.

The persistence modules intentionally stop at commit-confirmed, detached
authority.  This module is the narrow production adapter boundary around those
primitives: publisher database work is separated from broker I/O, consumer
receipt work completes before handler lookup or execution, and only immutable
coordinator results authorize acknowledgement.

No business stage is registered here.  Deployments must explicitly register
the exact ``(stage_type, stage_version)`` contracts they implement.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import re
import threading
import uuid
from collections.abc import Awaitable, Callable, Mapping
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, fields
from datetime import datetime
from typing import Any, Literal, TypeAlias

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.research_workflow import StageRun
from app.services.outbox_coordinator import (
    CoordinatedStageReceipt,
    coordinate_stage_receipt as _coordinate_stage_receipt,
)
from app.services.outbox_engine import sanitize_outbox_error
from app.services.outbox_runtime import (
    ClaimedOutboxDelivery,
    ExecutableStageAuthority,
    OutboxDeliveryMutation,
    OutboxLeaseLost,
    OutboxNotFound,
    OutboxRecoveryResult,
    OutboxStoredContractError,
    OutboxValidation,
    StageReceiptCommand,
    claim_outbox_delivery as _claim_outbox_delivery,
    fail_outbox_delivery as _fail_outbox_delivery,
    mark_outbox_dispatched as _mark_outbox_dispatched,
    recover_expired_outbox_deliveries as _recover_expired_outbox_deliveries,
)
from app.services.workflow_engine import canonical_json
from app.services.workflow_worker import (
    CoordinatedStageCompletion,
    CoordinatedStageFailure,
    coordinate_stage_complete as _coordinate_stage_complete,
    coordinate_stage_fail as _coordinate_stage_fail,
)


SessionFactory: TypeAlias = Callable[[], AbstractAsyncContextManager[AsyncSession]]
StageHandler: TypeAlias = Callable[["StageHandlerContext"], Awaitable["StageHandlerOutcome"]]
BrokerPublisher: TypeAlias = Callable[["StageDeliveryEnvelope"], "BrokerAcceptance | Awaitable[BrokerAcceptance]"]
RecoveryAdapter: TypeAlias = Callable[[SessionFactory, int], Awaitable[int]]

_IDENTITY_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,79}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,79}$")
_LOWER_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DELIVERY_SCHEMA_VERSION = "workflow-stage-delivery-v1"
_DELIVERY_PAYLOAD_FIELDS = frozenset({"transport_schema_version", "claim", "broker"})
_BROKER_FIELDS = frozenset({"name", "message_id"})
WORKFLOW_RECOVERY_LIMIT_MAX = 500
_CLAIM_FIELDS = frozenset(
    {
        "message_id",
        "delivery_attempt_id",
        "delivery_token",
        "message_state_version",
        "delivery_state_version",
        "delivery_cycle",
        "cycle_key",
        "correlation_id",
        "topic",
        "schema_version",
        "envelope_checksum",
        "logical_key",
        "envelope_canonical",
    }
)

__all__ = (
    "BrokerAcceptance",
    "ConsumerDecision",
    "DiscardStageDelivery",
    "PublisherDecision",
    "RecoveryAdapter",
    "SessionFactory",
    "StageDeliveryEnvelope",
    "StageExecutionError",
    "StageHandler",
    "StageHandlerContext",
    "StageHandlerOutcome",
    "StageHandlerRegistry",
    "UnknownStageHandler",
    "WorkflowOrchestrationError",
    "WORKFLOW_RECOVERY_LIMIT_MAX",
    "broker_receipt_fingerprint",
    "consume_stage_delivery",
    "publish_one_outbox_delivery",
    "recover_expired_outbox_pass",
    "run_recovery_pass",
)


class WorkflowOrchestrationError(ValueError):
    """The adapter input or returned integration value violates its contract."""


class UnknownStageHandler(WorkflowOrchestrationError):
    """No explicitly registered handler implements an exact stage contract."""


class DiscardStageDelivery(WorkflowOrchestrationError):
    """The exact broker delivery is durably stale and must not be redelivered."""


class _StoredStageContractError(WorkflowOrchestrationError):
    """A loaded stage no longer agrees with detached executable authority."""


class StageExecutionError(Exception):
    """A handler-declared, bounded failure policy for durable recording."""

    def __init__(
        self,
        message: str,
        *,
        error_code: str,
        retryable: bool,
        error_class: str = "StageExecutionError",
    ) -> None:
        clean_message = _text(message, field_name="stage error message", maximum=8_192)
        self.error_code = _identity(error_code, field_name="stage error_code")
        self.retryable = _exact_bool(retryable, field_name="stage retryable")
        self.error_class = _error_class(error_class)
        super().__init__(clean_message)


@dataclass(frozen=True, slots=True)
class StageHandlerOutcome:
    """Exact successful handler result consumed by the completion coordinator."""

    output_manifest: dict[str, Any]
    outcome: Literal["succeeded", "degraded"] = "succeeded"

    def __post_init__(self) -> None:
        if type(self) is not StageHandlerOutcome:
            raise WorkflowOrchestrationError("Stage handler outcome must use its exact public type")
        object.__setattr__(
            self,
            "output_manifest",
            _json_object(self.output_manifest, field_name="output_manifest"),
        )
        if type(self.outcome) is not str or self.outcome not in {"succeeded", "degraded"}:
            raise WorkflowOrchestrationError("Stage handler outcome is outside the closed registry")


@dataclass(frozen=True, slots=True)
class StageHandlerContext:
    """Detached, JSON-safe stage input.  It carries no ORM or open session."""

    authority: ExecutableStageAuthority
    stage_type: str
    stage_version: str
    config_schema_version: str
    config: dict[str, Any]
    input_manifest: dict[str, Any]

    def __post_init__(self) -> None:
        if type(self) is not StageHandlerContext:
            raise WorkflowOrchestrationError("Stage handler context must use its exact public type")
        object.__setattr__(self, "authority", _copy_authority(self.authority))
        object.__setattr__(self, "stage_type", _identity(self.stage_type, field_name="stage_type"))
        object.__setattr__(self, "stage_version", _version(self.stage_version, field_name="stage_version"))
        object.__setattr__(
            self,
            "config_schema_version",
            _version(self.config_schema_version, field_name="config_schema_version"),
        )
        object.__setattr__(self, "config", _json_object(self.config, field_name="config"))
        object.__setattr__(
            self,
            "input_manifest",
            _json_object(self.input_manifest, field_name="input_manifest"),
        )


class StageHandlerRegistry:
    """Thread-safe exact handler allowlist that seals on first resolution."""

    __slots__ = ("_frozen", "_handlers", "_lock")

    def __init__(self) -> None:
        self._handlers: dict[tuple[str, str], StageHandler] = {}
        self._frozen = False
        self._lock = threading.RLock()

    @property
    def frozen(self) -> bool:
        with self._lock:
            return self._frozen

    def register(self, stage_type: str, stage_version: str, handler: StageHandler) -> None:
        key = (
            _identity(stage_type, field_name="stage_type"),
            _version(stage_version, field_name="stage_version"),
        )
        if not callable(handler) or not inspect.iscoroutinefunction(handler):
            raise WorkflowOrchestrationError("Stage handler must be an async callable")
        with self._lock:
            if self._frozen:
                raise WorkflowOrchestrationError("Stage handler registry is frozen")
            if key in self._handlers:
                raise WorkflowOrchestrationError("Exact stage handler is already registered")
            self._handlers[key] = handler

    def freeze(self) -> None:
        with self._lock:
            self._frozen = True

    def resolve(self, stage_type: str, stage_version: str) -> StageHandler:
        key = (
            _identity(stage_type, field_name="stage_type"),
            _version(stage_version, field_name="stage_version"),
        )
        with self._lock:
            self._frozen = True
            handler = self._handlers.get(key)
        if handler is None:
            raise UnknownStageHandler(f"No handler is registered for {key[0]}@{key[1]}")
        return handler


@dataclass(frozen=True, slots=True)
class StageDeliveryEnvelope:
    """Strict JSON transport containing every detached publisher coordinate."""

    claim: ClaimedOutboxDelivery
    broker_name: str
    broker_message_id: str
    transport_schema_version: str = _DELIVERY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if type(self) is not StageDeliveryEnvelope:
            raise WorkflowOrchestrationError("Stage delivery must use its exact public type")
        object.__setattr__(self, "claim", _copy_claim(self.claim))
        object.__setattr__(self, "broker_name", _identity(self.broker_name, field_name="broker_name"))
        object.__setattr__(
            self,
            "broker_message_id",
            _text(self.broker_message_id, field_name="broker_message_id", maximum=255),
        )
        if self.transport_schema_version != _DELIVERY_SCHEMA_VERSION:
            raise WorkflowOrchestrationError("Stage delivery schema version is unsupported")

    def as_payload(self) -> dict[str, Any]:
        claim = self.claim
        return {
            "transport_schema_version": self.transport_schema_version,
            "claim": {
                "message_id": str(claim.message_id),
                "delivery_attempt_id": str(claim.delivery_attempt_id),
                "delivery_token": str(claim.delivery_token),
                "message_state_version": claim.message_state_version,
                "delivery_state_version": claim.delivery_state_version,
                "delivery_cycle": claim.delivery_cycle,
                "cycle_key": claim.cycle_key,
                "correlation_id": str(claim.correlation_id),
                "topic": claim.topic,
                "schema_version": claim.schema_version,
                "envelope_checksum": claim.envelope_checksum,
                "logical_key": claim.logical_key,
                "envelope_canonical": claim.envelope_canonical,
            },
            "broker": {
                "name": self.broker_name,
                "message_id": self.broker_message_id,
            },
        }

    @classmethod
    def from_payload(cls, value: object) -> "StageDeliveryEnvelope":
        payload = _exact_mapping(value, field_name="stage delivery")
        _exact_fields(payload, _DELIVERY_PAYLOAD_FIELDS, field_name="stage delivery")
        if payload["transport_schema_version"] != _DELIVERY_SCHEMA_VERSION:
            raise WorkflowOrchestrationError("Stage delivery schema version is unsupported")
        claim_payload = _exact_mapping(payload["claim"], field_name="stage delivery claim")
        broker_payload = _exact_mapping(payload["broker"], field_name="stage delivery broker")
        _exact_fields(claim_payload, _CLAIM_FIELDS, field_name="stage delivery claim")
        _exact_fields(broker_payload, _BROKER_FIELDS, field_name="stage delivery broker")
        try:
            claim = ClaimedOutboxDelivery(
                message_id=_uuid_text(claim_payload["message_id"], field_name="message_id"),
                delivery_attempt_id=_uuid_text(
                    claim_payload["delivery_attempt_id"],
                    field_name="delivery_attempt_id",
                ),
                delivery_token=_uuid_text(claim_payload["delivery_token"], field_name="delivery_token"),
                message_state_version=_positive_int(
                    claim_payload["message_state_version"],
                    field_name="message_state_version",
                ),
                delivery_state_version=_positive_int(
                    claim_payload["delivery_state_version"],
                    field_name="delivery_state_version",
                ),
                delivery_cycle=_positive_int(
                    claim_payload["delivery_cycle"],
                    field_name="delivery_cycle",
                ),
                cycle_key=_lower_sha256(claim_payload["cycle_key"], field_name="cycle_key"),
                correlation_id=_uuid_text(
                    claim_payload["correlation_id"],
                    field_name="correlation_id",
                ),
                topic=_exact_string(claim_payload["topic"], field_name="topic"),
                schema_version=_exact_string(
                    claim_payload["schema_version"],
                    field_name="schema_version",
                ),
                envelope_checksum=_lower_sha256(
                    claim_payload["envelope_checksum"],
                    field_name="envelope_checksum",
                ),
                logical_key=_lower_sha256(
                    claim_payload["logical_key"],
                    field_name="logical_key",
                ),
                envelope_canonical=_exact_string(
                    claim_payload["envelope_canonical"],
                    field_name="envelope_canonical",
                ),
            )
            return cls(
                claim=claim,
                broker_name=_exact_string(
                    broker_payload["name"],
                    field_name="broker_name",
                ),
                broker_message_id=_exact_string(
                    broker_payload["message_id"],
                    field_name="broker_message_id",
                ),
            )
        except OutboxValidation:
            raise WorkflowOrchestrationError("Stage delivery claim authority is invalid") from None


@dataclass(frozen=True, slots=True)
class BrokerAcceptance:
    """Exact broker acceptance facts returned to the publisher boundary."""

    broker_name: str
    broker_message_id: str

    def __post_init__(self) -> None:
        if type(self) is not BrokerAcceptance:
            raise WorkflowOrchestrationError("Broker acceptance must use its exact public type")
        object.__setattr__(self, "broker_name", _identity(self.broker_name, field_name="broker_name"))
        object.__setattr__(
            self,
            "broker_message_id",
            _text(self.broker_message_id, field_name="broker_message_id", maximum=255),
        )


@dataclass(frozen=True, slots=True)
class PublisherDecision:
    """Capability-free durable result of one publisher pass."""

    disposition: Literal["empty", "dispatched", "publish_failed"]
    message_id: uuid.UUID | None
    delivery_attempt_id: uuid.UUID | None
    delivery_cycle: int | None
    broker_message_id: str
    durable_status: str
    replayed: bool

    def __post_init__(self) -> None:
        if type(self) is not PublisherDecision:
            raise WorkflowOrchestrationError("Publisher decision must use its exact public type")
        if self.disposition not in {"empty", "dispatched", "publish_failed"}:
            raise WorkflowOrchestrationError("Publisher disposition is unsupported")
        if type(self.replayed) is not bool:
            raise WorkflowOrchestrationError("Publisher replay flag must be an exact boolean")
        if type(self.broker_message_id) is not str or type(self.durable_status) is not str:
            raise WorkflowOrchestrationError("Publisher facts must be exact strings")
        if self.disposition == "empty":
            if any(value is not None for value in (self.message_id, self.delivery_attempt_id, self.delivery_cycle)):
                raise WorkflowOrchestrationError("Empty publisher decision cannot identify a delivery")
            if self.broker_message_id or self.durable_status or self.replayed:
                raise WorkflowOrchestrationError("Empty publisher decision has contradictory facts")
            return
        _exact_uuid(self.message_id, field_name="message_id")
        _exact_uuid(self.delivery_attempt_id, field_name="delivery_attempt_id")
        _positive_int(self.delivery_cycle, field_name="delivery_cycle")
        if self.disposition == "dispatched" and not self.broker_message_id:
            raise WorkflowOrchestrationError("Dispatched publisher decision lacks broker identity")


@dataclass(frozen=True, slots=True)
class ConsumerDecision:
    """Immutable broker acknowledgement decision derived from coordinators."""

    disposition: Literal[
        "receipt_replayed",
        "receipt_stale",
        "receipt_cancelled",
        "completed",
        "completion_stale",
        "failed",
        "failure_stale",
    ]
    workflow_run_id: uuid.UUID
    stage_run_id: uuid.UUID
    stage_attempt_id: uuid.UUID | None
    message_id: uuid.UUID
    delivery_attempt_id: uuid.UUID
    attempt_number: int
    delivery_cycle: int
    cycle_key: str
    broker_receipt_id: str
    should_ack: bool
    durable_retry: bool

    def __post_init__(self) -> None:
        if type(self) is not ConsumerDecision:
            raise WorkflowOrchestrationError("Consumer decision must use its exact public type")
        if self.disposition not in {
            "receipt_replayed",
            "receipt_stale",
            "receipt_cancelled",
            "completed",
            "completion_stale",
            "failed",
            "failure_stale",
        }:
            raise WorkflowOrchestrationError("Consumer disposition is unsupported")
        _exact_uuid(self.workflow_run_id, field_name="workflow_run_id")
        _exact_uuid(self.stage_run_id, field_name="stage_run_id")
        _exact_uuid(self.message_id, field_name="message_id")
        _exact_uuid(self.delivery_attempt_id, field_name="delivery_attempt_id")
        if self.stage_attempt_id is not None:
            _exact_uuid(self.stage_attempt_id, field_name="stage_attempt_id")
        _positive_int(self.attempt_number, field_name="attempt_number")
        _positive_int(self.delivery_cycle, field_name="delivery_cycle")
        _lower_sha256(self.cycle_key, field_name="cycle_key")
        _lower_sha256(self.broker_receipt_id, field_name="broker_receipt_id")
        if type(self.should_ack) is not bool or not self.should_ack:
            raise WorkflowOrchestrationError("Only acknowledgement-safe coordinator results may escape")
        if type(self.durable_retry) is not bool:
            raise WorkflowOrchestrationError("Consumer retry fact must be an exact boolean")
        if self.durable_retry and self.disposition != "failed":
            raise WorkflowOrchestrationError("Only a recorded failure can schedule a durable retry")
        if self.disposition in {"receipt_stale", "receipt_cancelled"}:
            if self.stage_attempt_id is not None:
                raise WorkflowOrchestrationError("Non-attempt receipt decisions cannot identify an attempt")
        elif self.stage_attempt_id is None:
            raise WorkflowOrchestrationError("Executable and terminal decisions require an attempt identity")


async def publish_one_outbox_delivery(
    session_factory: SessionFactory,
    *,
    publisher: BrokerPublisher,
    publisher_id: str,
    broker_name: str = "celery",
    lease_seconds: int = 60,
    receipt_timeout_seconds: int = 300,
) -> PublisherDecision:
    """Claim, publish, then durably mark one delivery in three disjoint scopes."""

    if not callable(session_factory):
        raise WorkflowOrchestrationError("session_factory must create an async session context")
    if not callable(publisher):
        raise WorkflowOrchestrationError("publisher must be callable")
    clean_publisher = _text(publisher_id, field_name="publisher_id", maximum=255)
    clean_broker = _identity(broker_name, field_name="broker_name")
    clean_lease = _bounded_int(lease_seconds, field_name="lease_seconds", minimum=1, maximum=3_600)
    clean_timeout = _bounded_int(
        receipt_timeout_seconds,
        field_name="receipt_timeout_seconds",
        minimum=1,
        maximum=86_400,
    )

    claim_session: AsyncSession | None = None
    raw_claim: ClaimedOutboxDelivery | None = None
    async with session_factory() as session:
        claim_session = session
        async with session.begin():
            raw_claim = await _claim_outbox_delivery(
                session,
                publisher_id=clean_publisher,
                lease_seconds=clean_lease,
            )

    if raw_claim is None:
        return PublisherDecision(
            disposition="empty",
            message_id=None,
            delivery_attempt_id=None,
            delivery_cycle=None,
            broker_message_id="",
            durable_status="",
            replayed=False,
        )
    claim = _copy_claim(raw_claim)
    broker_message_id = str(uuid.uuid4())
    delivery = StageDeliveryEnvelope(
        claim=claim,
        broker_name=clean_broker,
        broker_message_id=broker_message_id,
    )

    try:
        raw_acceptance = publisher(delivery)
        if inspect.isawaitable(raw_acceptance):
            raw_acceptance = await raw_acceptance
        acceptance = _copy_acceptance(raw_acceptance)
        if acceptance.broker_name != clean_broker or acceptance.broker_message_id != broker_message_id:
            raise WorkflowOrchestrationError("Broker acceptance changed the fixed delivery identity")
    except Exception as exc:
        error_text = _safe_exception_text(exc)
        safe_error = sanitize_outbox_error(
            error_text,
            code="outbox.publish_failed",
            retryable=True,
            error_class="BrokerPublishError",
        )
        pending: PublisherDecision | None = None
        async with session_factory() as failure_session:
            _require_fresh_session(claim_session, failure_session, purpose="publisher failure")
            async with failure_session.begin():
                mutation = await _fail_outbox_delivery(
                    failure_session,
                    message_id=claim.message_id,
                    delivery_attempt_id=claim.delivery_attempt_id,
                    delivery_token=claim.delivery_token,
                    expected_message_version=claim.message_state_version,
                    expected_delivery_version=claim.delivery_state_version,
                    error=safe_error,
                )
                pending = _publisher_mutation_decision(
                    mutation,
                    claim=claim,
                    disposition="publish_failed",
                    broker_message_id="",
                )
        if pending is None:  # pragma: no cover - context-manager invariant
            raise WorkflowOrchestrationError("Publisher failure transaction returned no decision")
        return pending

    pending = None
    async with session_factory() as mark_session:
        _require_fresh_session(claim_session, mark_session, purpose="dispatch marking")
        async with mark_session.begin():
            mutation = await _mark_outbox_dispatched(
                mark_session,
                message_id=claim.message_id,
                delivery_attempt_id=claim.delivery_attempt_id,
                delivery_token=claim.delivery_token,
                expected_message_version=claim.message_state_version,
                expected_delivery_version=claim.delivery_state_version,
                broker_name=acceptance.broker_name,
                broker_message_id=acceptance.broker_message_id,
                receipt_timeout_seconds=clean_timeout,
            )
            pending = _publisher_mutation_decision(
                mutation,
                claim=claim,
                disposition="dispatched",
                broker_message_id=acceptance.broker_message_id,
            )
    if pending is None:  # pragma: no cover - context-manager invariant
        raise WorkflowOrchestrationError("Dispatch marking transaction returned no decision")
    return pending


async def consume_stage_delivery(
    session_factory: SessionFactory,
    *,
    delivery: StageDeliveryEnvelope | Mapping[str, object],
    worker_id: str,
    handlers: StageHandlerRegistry,
    lease_seconds: int = 300,
) -> ConsumerDecision:
    """Receipt first, then execute exactly one registered handler without locks."""

    if not callable(session_factory):
        raise WorkflowOrchestrationError("session_factory must create an async session context")
    if type(handlers) is not StageHandlerRegistry:
        raise WorkflowOrchestrationError("handlers must use the exact stage registry type")
    clean_worker = _text(worker_id, field_name="worker_id", maximum=255)
    clean_lease = _bounded_int(lease_seconds, field_name="lease_seconds", minimum=1, maximum=3_600)
    transport = (
        StageDeliveryEnvelope.from_payload(delivery)
        if type(delivery) is not StageDeliveryEnvelope
        else StageDeliveryEnvelope(
            claim=delivery.claim,
            broker_name=delivery.broker_name,
            broker_message_id=delivery.broker_message_id,
            transport_schema_version=delivery.transport_schema_version,
        )
    )
    receipt_id = broker_receipt_fingerprint(transport)
    command = StageReceiptCommand(
        claim=transport.claim,
        broker_name=transport.broker_name,
        broker_message_id=transport.broker_message_id,
        broker_receipt_id=receipt_id,
        worker_id=clean_worker,
        lease_seconds=clean_lease,
    )
    try:
        raw_receipt = await _coordinate_stage_receipt(session_factory, command=command)
    except (OutboxNotFound, OutboxLeaseLost, OutboxStoredContractError):
        raise DiscardStageDelivery("Workflow delivery authority is no longer live") from None
    receipt = _fixed_dataclass_result(
        raw_receipt,
        CoordinatedStageReceipt,
        field_name="receipt coordinator result",
    )
    _assert_receipt_matches_command(receipt, command=command)
    if not receipt.should_ack:
        raise WorkflowOrchestrationError("Receipt coordinator did not authorize acknowledgement")
    if not receipt.should_execute:
        return _receipt_consumer_decision(receipt)
    if receipt.disposition != "activated" or receipt.authority is None:
        raise WorkflowOrchestrationError("Executable receipt lacks exact authority")
    authority = _copy_authority(receipt.authority)

    context: StageHandlerContext | None = None
    try:
        async with session_factory() as load_session:
            async with load_session.begin():
                context = await _load_handler_context(load_session, authority=authority)
    except _StoredStageContractError as exc:
        return await _record_stage_failure(
            session_factory,
            authority=authority,
            error_text=str(exc),
            error_code="workflow.stage_authority_changed",
            retryable=False,
            error_class="StageAuthorityChanged",
        )
    if context is None:  # pragma: no cover - context-manager invariant
        raise WorkflowOrchestrationError("Stage context transaction returned no detached input")

    try:
        handler = handlers.resolve(context.stage_type, context.stage_version)
    except UnknownStageHandler:
        return await _record_stage_failure(
            session_factory,
            authority=authority,
            error_text=f"No handler is registered for {context.stage_type}@{context.stage_version}",
            error_code="workflow.stage_handler_unregistered",
            retryable=False,
            error_class="StageHandlerNotRegistered",
        )

    try:
        raw_outcome = await handler(context)
    except StageExecutionError as exc:
        return await _record_stage_failure(
            session_factory,
            authority=authority,
            error_text=_safe_exception_text(exc),
            error_code=exc.error_code,
            retryable=exc.retryable,
            error_class=exc.error_class,
        )
    except WorkflowOrchestrationError as exc:
        return await _record_stage_failure(
            session_factory,
            authority=authority,
            error_text=_safe_exception_text(exc),
            error_code="workflow.stage_handler_contract",
            retryable=False,
            error_class="StageHandlerContractError",
        )
    except Exception as exc:
        return await _record_stage_failure(
            session_factory,
            authority=authority,
            error_text=_safe_exception_text(exc),
            error_code="workflow.stage_handler_error",
            retryable=True,
            error_class="StageHandlerError",
        )

    if type(raw_outcome) is not StageHandlerOutcome:
        return await _record_stage_failure(
            session_factory,
            authority=authority,
            error_text="Stage handler returned an invalid result contract",
            error_code="workflow.stage_handler_contract",
            retryable=False,
            error_class="StageHandlerContractError",
        )
    try:
        outcome = _fixed_dataclass_result(
            raw_outcome,
            StageHandlerOutcome,
            field_name="stage handler outcome",
        )
    except WorkflowOrchestrationError as exc:
        return await _record_stage_failure(
            session_factory,
            authority=authority,
            error_text=_safe_exception_text(exc),
            error_code="workflow.stage_handler_contract",
            retryable=False,
            error_class="StageHandlerContractError",
        )
    completion = await _coordinate_stage_complete(
        session_factory,
        authority=authority,
        output_manifest=outcome.output_manifest,
        outcome=outcome.outcome,
    )
    return _completion_consumer_decision(completion, authority=authority)


def broker_receipt_fingerprint(delivery: StageDeliveryEnvelope | Mapping[str, object]) -> str:
    """Derive one stable receipt id for every redelivery of a broker task."""

    transport = delivery if type(delivery) is StageDeliveryEnvelope else StageDeliveryEnvelope.from_payload(delivery)
    material = {
        "domain": "AdversaryGraph/workflow-stage-receipt/v1",
        "message_id": str(transport.claim.message_id),
        "delivery_attempt_id": str(transport.claim.delivery_attempt_id),
        "delivery_cycle": transport.claim.delivery_cycle,
        "cycle_key": transport.claim.cycle_key,
        "broker_name": transport.broker_name,
        "broker_message_id": transport.broker_message_id,
    }
    canonical = json.dumps(material, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


async def run_recovery_pass(
    session_factory: SessionFactory,
    *,
    adapter: RecoveryAdapter,
    limit: int = 100,
) -> int:
    """Invoke the injected recovery coordinator once its API is frozen."""

    if not callable(session_factory):
        raise WorkflowOrchestrationError("session_factory must create an async session context")
    if not callable(adapter):
        raise WorkflowOrchestrationError("recovery adapter must be callable")
    clean_limit = _bounded_int(
        limit,
        field_name="limit",
        minimum=1,
        maximum=WORKFLOW_RECOVERY_LIMIT_MAX,
    )
    recovered = await adapter(session_factory, clean_limit)
    return _bounded_int(recovered, field_name="recovered", minimum=0, maximum=clean_limit)


async def recover_expired_outbox_pass(
    session_factory: SessionFactory,
    *,
    limit: int = 100,
) -> int:
    """Commit one bounded recovery pass for expired publisher/receipt leases."""

    if not callable(session_factory):
        raise WorkflowOrchestrationError("session_factory must create an async session context")
    clean_limit = _bounded_int(
        limit,
        field_name="limit",
        minimum=1,
        maximum=WORKFLOW_RECOVERY_LIMIT_MAX,
    )
    raw_results: object = None
    async with session_factory() as session:
        async with session.begin():
            raw_results = await _recover_expired_outbox_deliveries(
                session,
                limit=clean_limit,
            )
            if type(raw_results) is not list or len(raw_results) > clean_limit:
                raise WorkflowOrchestrationError("Outbox recovery returned an invalid result batch")
            for raw_result in raw_results:
                result = _fixed_dataclass_result(
                    raw_result,
                    OutboxRecoveryResult,
                    field_name="outbox recovery result",
                )
                _exact_uuid(result.message_id, field_name="outbox recovery message_id")
                _exact_uuid(
                    result.delivery_attempt_id,
                    field_name="outbox recovery delivery_attempt_id",
                )
                if result.message_status not in {"retry_wait", "dead_lettered"}:
                    raise WorkflowOrchestrationError("Outbox recovery status is outside its closed registry")
                if result.message_status == "retry_wait":
                    _aware_datetime(
                        result.available_at,
                        field_name="outbox recovery available_at",
                    )
                elif result.available_at is not None:
                    raise WorkflowOrchestrationError("Dead-lettered outbox recovery cannot be scheduled")
    if type(raw_results) is not list:  # pragma: no cover - context-manager invariant
        raise WorkflowOrchestrationError("Outbox recovery transaction returned no batch")
    return len(raw_results)


async def _load_handler_context(
    db: AsyncSession,
    *,
    authority: ExecutableStageAuthority,
) -> StageHandlerContext:
    stage = await db.scalar(select(StageRun).where(StageRun.id == authority.stage_run_id))
    if stage is None:
        raise _StoredStageContractError("Executable stage no longer exists")
    if type(stage) is not StageRun:
        raise _StoredStageContractError("Executable stage has an invalid runtime type")
    if (
        stage.workflow_run_id != authority.workflow_run_id
        or stage.stage_key != authority.stage_key
        or stage.status != "running"
        or stage.state_version != authority.stage_state_version
        or stage.attempt_count != authority.attempt_number
        or stage.lease_token != authority.stage_lease_token
        or stage.lease_owner != authority.lease_owner
        or stage.lease_expires_at != authority.lease_expires_at
        or stage.input_checksum != authority.input_checksum
        or stage.checkpoint_version != authority.checkpoint_version
    ):
        raise _StoredStageContractError("Executable stage changed before handler dispatch")
    try:
        return StageHandlerContext(
            authority=authority,
            stage_type=stage.stage_type,
            stage_version=stage.stage_version,
            config_schema_version=stage.config_schema_version,
            config=stage.config,
            input_manifest=stage.input_manifest,
        )
    except WorkflowOrchestrationError as exc:
        raise _StoredStageContractError("Persisted stage handler contract is invalid") from exc


async def _record_stage_failure(
    session_factory: SessionFactory,
    *,
    authority: ExecutableStageAuthority,
    error_text: str,
    error_code: str,
    retryable: bool,
    error_class: str,
) -> ConsumerDecision:
    raw_failure = await _coordinate_stage_fail(
        session_factory,
        authority=authority,
        error_text=error_text,
        error_code=error_code,
        retryable=retryable,
        error_class=error_class,
    )
    failure = _fixed_dataclass_result(
        raw_failure,
        CoordinatedStageFailure,
        field_name="failure coordinator result",
    )
    _assert_worker_result_matches_authority(failure, authority=authority)
    if not failure.should_ack or failure.should_continue:
        raise WorkflowOrchestrationError("Failure coordinator did not return a terminal acknowledgement")
    return ConsumerDecision(
        disposition="failed" if failure.disposition == "recorded" else "failure_stale",
        workflow_run_id=failure.workflow_run_id,
        stage_run_id=failure.stage_run_id,
        stage_attempt_id=failure.stage_attempt_id,
        message_id=failure.message_id,
        delivery_attempt_id=failure.delivery_attempt_id,
        attempt_number=failure.attempt_number,
        delivery_cycle=failure.delivery_cycle,
        cycle_key=failure.cycle_key,
        broker_receipt_id=failure.broker_receipt_id,
        should_ack=failure.should_ack,
        durable_retry=failure.should_retry,
    )


def _receipt_consumer_decision(receipt: CoordinatedStageReceipt) -> ConsumerDecision:
    if receipt.disposition not in {"replayed", "stale", "cancelled"}:
        raise WorkflowOrchestrationError("Non-executable receipt disposition is unsupported")
    return ConsumerDecision(
        disposition=f"receipt_{receipt.disposition}",
        workflow_run_id=receipt.workflow_run_id,
        stage_run_id=receipt.stage_run_id,
        stage_attempt_id=receipt.stage_attempt_id,
        message_id=receipt.message_id,
        delivery_attempt_id=receipt.delivery_attempt_id,
        attempt_number=receipt.attempt_number,
        delivery_cycle=receipt.delivery_cycle,
        cycle_key=receipt.cycle_key,
        broker_receipt_id=receipt.broker_receipt_id,
        should_ack=receipt.should_ack,
        durable_retry=False,
    )


def _completion_consumer_decision(
    completion: object,
    *,
    authority: ExecutableStageAuthority,
) -> ConsumerDecision:
    completion = _fixed_dataclass_result(
        completion,
        CoordinatedStageCompletion,
        field_name="completion coordinator result",
    )
    _assert_worker_result_matches_authority(completion, authority=authority)
    if not completion.should_ack or completion.should_continue:
        raise WorkflowOrchestrationError("Completion coordinator did not return a terminal acknowledgement")
    return ConsumerDecision(
        disposition="completed" if completion.disposition == "completed" else "completion_stale",
        workflow_run_id=completion.workflow_run_id,
        stage_run_id=completion.stage_run_id,
        stage_attempt_id=completion.stage_attempt_id,
        message_id=completion.message_id,
        delivery_attempt_id=completion.delivery_attempt_id,
        attempt_number=completion.attempt_number,
        delivery_cycle=completion.delivery_cycle,
        cycle_key=completion.cycle_key,
        broker_receipt_id=completion.broker_receipt_id,
        should_ack=completion.should_ack,
        durable_retry=False,
    )


def _publisher_mutation_decision(
    mutation: object,
    *,
    claim: ClaimedOutboxDelivery,
    disposition: Literal["dispatched", "publish_failed"],
    broker_message_id: str,
) -> PublisherDecision:
    if type(mutation) is not OutboxDeliveryMutation:
        raise WorkflowOrchestrationError("Outbox runtime returned an invalid publisher mutation")
    message = mutation.message
    delivery = mutation.delivery
    if message.id != claim.message_id or delivery.id != claim.delivery_attempt_id or delivery.message_id != claim.message_id:
        raise WorkflowOrchestrationError("Publisher mutation changed delivery identity")
    return PublisherDecision(
        disposition=disposition,
        message_id=claim.message_id,
        delivery_attempt_id=claim.delivery_attempt_id,
        delivery_cycle=claim.delivery_cycle,
        broker_message_id=broker_message_id,
        durable_status=_exact_string(message.status, field_name="message status"),
        replayed=_exact_bool(mutation.replayed, field_name="publisher replayed"),
    )


def _assert_receipt_matches_command(
    receipt: CoordinatedStageReceipt,
    *,
    command: StageReceiptCommand,
) -> None:
    claim = command.claim
    payload = claim.envelope["payload"]
    if (
        receipt.workflow_run_id != _uuid_text(payload["workflow_run_id"], field_name="workflow_run_id")
        or receipt.stage_run_id != _uuid_text(payload["stage_run_id"], field_name="stage_run_id")
        or receipt.attempt_number != _positive_int(payload["target_attempt_number"], field_name="target_attempt_number")
        or receipt.message_id != claim.message_id
        or receipt.delivery_attempt_id != claim.delivery_attempt_id
        or receipt.delivery_cycle != claim.delivery_cycle
        or receipt.cycle_key != claim.cycle_key
        or receipt.broker_receipt_id != command.broker_receipt_id
    ):
        raise WorkflowOrchestrationError("Receipt coordinator changed the transported delivery lineage")


def _assert_worker_result_matches_authority(
    result: CoordinatedStageCompletion | CoordinatedStageFailure,
    *,
    authority: ExecutableStageAuthority,
) -> None:
    if (
        result.workflow_run_id != authority.workflow_run_id
        or result.stage_run_id != authority.stage_run_id
        or result.stage_attempt_id != authority.stage_attempt_id
        or result.message_id != authority.message_id
        or result.delivery_attempt_id != authority.delivery_attempt_id
        or result.stage_lease_token != authority.stage_lease_token
        or result.attempt_number != authority.attempt_number
        or result.delivery_cycle != authority.delivery_cycle
        or result.cycle_key != authority.cycle_key
        or result.broker_receipt_id != authority.broker_receipt_id
        or result.stage_key != authority.stage_key
        or result.input_checksum != authority.input_checksum
        or result.checkpoint_version != authority.checkpoint_version
        or result.lease_owner != authority.lease_owner
        or result.lease_expires_at != authority.lease_expires_at
        or result.previous_workflow_state_version != authority.workflow_state_version
        or result.previous_stage_state_version != authority.stage_state_version
        or result.previous_attempt_state_version != authority.attempt_state_version
    ):
        raise WorkflowOrchestrationError("Worker coordinator changed the executable receipt lineage")


def _copy_claim(value: object) -> ClaimedOutboxDelivery:
    if type(value) is not ClaimedOutboxDelivery:
        raise WorkflowOrchestrationError("Claim must use exact detached outbox authority")
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


def _fixed_dataclass_result(
    value: object,
    result_type: type[Any],
    *,
    field_name: str,
) -> Any:
    if type(value) is not result_type:
        raise WorkflowOrchestrationError(f"{field_name} has an invalid type")
    try:
        return result_type(**{field.name: getattr(value, field.name) for field in fields(result_type) if field.init})
    except Exception as exc:
        raise WorkflowOrchestrationError(f"{field_name} violates its fixed point") from exc


def _copy_authority(value: object) -> ExecutableStageAuthority:
    if type(value) is not ExecutableStageAuthority:
        raise WorkflowOrchestrationError("Execution authority has an invalid type")
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


def _copy_acceptance(value: object) -> BrokerAcceptance:
    if type(value) is not BrokerAcceptance:
        raise WorkflowOrchestrationError("Publisher returned an invalid broker acceptance")
    return BrokerAcceptance(
        broker_name=value.broker_name,
        broker_message_id=value.broker_message_id,
    )


def _require_fresh_session(previous: object, current: object, *, purpose: str) -> None:
    if previous is current:
        raise WorkflowOrchestrationError(f"{purpose} requires a distinct session")
    previous_sync = getattr(previous, "sync_session", None)
    current_sync = getattr(current, "sync_session", None)
    if previous_sync is not None and previous_sync is current_sync:
        raise WorkflowOrchestrationError(f"{purpose} requires a distinct synchronous session")


def _safe_exception_text(exc: BaseException) -> str:
    try:
        value = str(exc)
    except Exception:
        return "External operation failed"
    return value[:8_192] or "External operation failed"


def _json_object(value: object, *, field_name: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise WorkflowOrchestrationError(f"{field_name} must be an exact JSON object")
    try:
        canonical = canonical_json(value)
        decoded = json.loads(canonical)
    except (TypeError, ValueError) as exc:
        raise WorkflowOrchestrationError(f"{field_name} is not canonical JSON") from exc
    if type(decoded) is not dict:
        raise WorkflowOrchestrationError(f"{field_name} must decode to an object")
    return decoded


def _exact_mapping(value: object, *, field_name: str) -> Mapping[str, object]:
    if type(value) is not dict:
        raise WorkflowOrchestrationError(f"{field_name} must be an exact object")
    if any(type(key) is not str for key in value):
        raise WorkflowOrchestrationError(f"{field_name} keys must be exact strings")
    return value


def _exact_fields(value: Mapping[str, object], expected: frozenset[str], *, field_name: str) -> None:
    if set(value) != expected:
        raise WorkflowOrchestrationError(f"{field_name} has missing or unexpected fields")


def _uuid_text(value: object, *, field_name: str) -> uuid.UUID:
    if type(value) is not str:
        raise WorkflowOrchestrationError(f"{field_name} must be a canonical UUID string")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise WorkflowOrchestrationError(f"{field_name} must be a canonical UUID string") from exc
    if str(parsed) != value:
        raise WorkflowOrchestrationError(f"{field_name} must be a canonical UUID string")
    return parsed


def _exact_uuid(value: object, *, field_name: str) -> uuid.UUID:
    if type(value) is not uuid.UUID:
        raise WorkflowOrchestrationError(f"{field_name} must be an exact UUID")
    return value


def _exact_string(value: object, *, field_name: str) -> str:
    if type(value) is not str:
        raise WorkflowOrchestrationError(f"{field_name} must be an exact string")
    return value


def _text(value: object, *, field_name: str, maximum: int) -> str:
    if type(value) is not str or not value or len(value) > maximum or value != value.strip():
        raise WorkflowOrchestrationError(f"{field_name} must be non-empty bounded text")
    return value


def _identity(value: object, *, field_name: str) -> str:
    if type(value) is not str or _IDENTITY_RE.fullmatch(value) is None:
        raise WorkflowOrchestrationError(f"{field_name} must be a registered identity")
    return value


def _version(value: object, *, field_name: str) -> str:
    if type(value) is not str or _VERSION_RE.fullmatch(value) is None:
        raise WorkflowOrchestrationError(f"{field_name} must be a registered version")
    return value


def _error_class(value: object) -> str:
    if type(value) is not str or re.fullmatch(r"^[A-Za-z][A-Za-z0-9_.-]{0,119}$", value) is None:
        raise WorkflowOrchestrationError("error_class must be a registered error identity")
    return value


def _lower_sha256(value: object, *, field_name: str) -> str:
    if type(value) is not str or _LOWER_SHA256_RE.fullmatch(value) is None:
        raise WorkflowOrchestrationError(f"{field_name} must be lowercase SHA-256")
    return value


def _positive_int(value: object, *, field_name: str) -> int:
    return _bounded_int(value, field_name=field_name, minimum=1, maximum=2_147_483_647)


def _bounded_int(value: object, *, field_name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise WorkflowOrchestrationError(f"{field_name} must be an integer from {minimum} to {maximum}")
    return value


def _exact_bool(value: object, *, field_name: str) -> bool:
    if type(value) is not bool:
        raise WorkflowOrchestrationError(f"{field_name} must be an exact boolean")
    return value


def _aware_datetime(value: object, *, field_name: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise WorkflowOrchestrationError(f"{field_name} must be an aware datetime")
    return value
