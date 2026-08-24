"""Adapter-facing unit-of-work boundary for stage-delivery receipts.

The durable outbox runtime is deliberately flush-only.  Broker adapters must
enter through :func:`coordinate_stage_receipt` so receipt activation commits
and releases its locks before a separate confirmation transaction begins.
The confirmation transaction also exits before executable authority is
returned.

This module performs no broker, acknowledgement, network, or stage work.  A
returned :class:`ExecutableStageAuthority` is a detached snapshot, not
self-authenticating capability: every later worker mutation must lock and
revalidate its complete database fence before changing durable state.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from typing import Literal, TypeAlias

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.research_workflow import MAX_OUTBOX_DELIVERY_CYCLE
from app.services.outbox_runtime import (
    ExecutableStageAuthority,
    OutboxStoredContractError,
    OutboxValidation,
    PendingReceiptActivation,
    StageReceiptCommand,
    confirm_committed_activation as _confirm_committed_activation,
    receipt_and_claim_stage as _receipt_and_claim_stage,
)


SessionFactory: TypeAlias = Callable[[], AbstractAsyncContextManager[AsyncSession]]
ReceiptDisposition: TypeAlias = Literal["activated", "replayed", "stale", "cancelled"]

_LOWER_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

__all__ = (
    "CoordinatedStageReceipt",
    "SessionFactory",
    "StageReceiptCommand",
    "coordinate_stage_receipt",
)


@dataclass(frozen=True, slots=True)
class CoordinatedStageReceipt:
    """Ticket-free adapter decision produced after all authority locks release.

    ``authority`` is an immutable transport snapshot only.  Its presence does
    not let worker code skip database token, version, lineage, status, or
    post-lock lease-expiry validation.
    """

    workflow_run_id: uuid.UUID
    stage_run_id: uuid.UUID
    stage_attempt_id: uuid.UUID | None
    message_id: uuid.UUID
    delivery_attempt_id: uuid.UUID
    attempt_number: int
    delivery_cycle: int
    cycle_key: str
    broker_receipt_id: str
    disposition: ReceiptDisposition
    authority: ExecutableStageAuthority | None
    should_execute: bool
    should_ack: bool

    def __post_init__(self) -> None:
        if type(self) is not CoordinatedStageReceipt:
            raise OutboxValidation("Coordinated receipt must use its exact public result type")
        for field_name in (
            "workflow_run_id",
            "stage_run_id",
            "message_id",
            "delivery_attempt_id",
        ):
            _exact_uuid(getattr(self, field_name), field_name=field_name)
        if self.stage_attempt_id is not None:
            _exact_uuid(self.stage_attempt_id, field_name="stage_attempt_id")
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
            raise OutboxValidation("Coordinated receipt disposition is outside its closed registry")
        if type(self.should_execute) is not bool or type(self.should_ack) is not bool:
            raise OutboxValidation("Coordinated receipt decisions must be exact booleans")
        if not self.should_ack:
            raise OutboxValidation("Every returned coordinated receipt is acknowledgement-safe")

        if self.disposition == "activated":
            if not self.should_execute or self.stage_attempt_id is None:
                raise OutboxValidation("Activated receipt requires executable stage authority")
            authority = _copy_executable_authority(self.authority)
            _assert_authority_matches_result(self, authority)
            object.__setattr__(self, "authority", authority)
            return

        if self.should_execute or self.authority is not None:
            raise OutboxValidation("Only an activated receipt can carry executable authority")
        if (self.disposition == "replayed") != (self.stage_attempt_id is not None):
            raise OutboxValidation("Only a replayed non-executable receipt identifies a stage attempt")


async def coordinate_stage_receipt(
    session_factory: SessionFactory,
    *,
    command: StageReceiptCommand,
) -> CoordinatedStageReceipt:
    """Commit a receipt, confirm it separately, then return an adapter decision.

    The caller receives no acknowledgement decision if validation, receipt,
    transaction exit, commit, confirmation, or result validation raises.  The
    coordinator itself never acknowledges a broker message or executes stage
    work.
    """

    receipt = _copy_receipt_command(command)
    if not callable(session_factory):
        raise OutboxValidation("session_factory must create an async session context")

    receipt_session: AsyncSession
    async with session_factory() as receipt_session:
        async with receipt_session.begin():
            raw_pending = await _receipt_and_claim_stage(
                receipt_session,
                command=receipt,
            )
    pending = _copy_pending_activation(raw_pending)

    if pending.disposition != "activated":
        return _build_public_result(
            pending,
            disposition=pending.disposition,
            authority=None,
        )

    # The pending DTO proves this locally, and the fixed-point copy above makes
    # the ticket safe to retain only inside this coordinator frame.
    if pending.commit_ticket is None:  # pragma: no cover - defensive invariant
        raise OutboxStoredContractError("Activated receipt did not mint confirmation authority")

    raw_authority: ExecutableStageAuthority | None
    async with session_factory() as confirmation_session:
        if confirmation_session is receipt_session:
            raise OutboxValidation("Receipt confirmation requires a fresh session")
        async with confirmation_session.begin():
            raw_authority = await _confirm_committed_activation(
                confirmation_session,
                commit_ticket=pending.commit_ticket,
            )

    if raw_authority is None:
        return _build_public_result(
            pending,
            disposition="stale",
            authority=None,
            omit_stage_attempt=True,
        )

    authority = _copy_executable_authority(raw_authority)
    return _build_public_result(
        pending,
        disposition="activated",
        authority=authority,
    )


def _build_public_result(
    pending: PendingReceiptActivation,
    *,
    disposition: ReceiptDisposition,
    authority: ExecutableStageAuthority | None,
    omit_stage_attempt: bool = False,
) -> CoordinatedStageReceipt:
    should_execute = disposition == "activated"
    return CoordinatedStageReceipt(
        workflow_run_id=pending.workflow_run_id,
        stage_run_id=pending.stage_run_id,
        stage_attempt_id=None if omit_stage_attempt else pending.stage_attempt_id,
        message_id=pending.message_id,
        delivery_attempt_id=pending.delivery_attempt_id,
        attempt_number=pending.attempt_number,
        delivery_cycle=pending.delivery_cycle,
        cycle_key=pending.cycle_key,
        broker_receipt_id=pending.broker_receipt_id,
        disposition=disposition,
        authority=authority,
        should_execute=should_execute,
        should_ack=True,
    )


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


def _copy_pending_activation(value: object) -> PendingReceiptActivation:
    if type(value) is not PendingReceiptActivation:
        raise OutboxStoredContractError("Receipt runtime returned invalid pending authority")
    try:
        return PendingReceiptActivation(
            workflow_run_id=value.workflow_run_id,
            stage_run_id=value.stage_run_id,
            stage_attempt_id=value.stage_attempt_id,
            message_id=value.message_id,
            delivery_attempt_id=value.delivery_attempt_id,
            attempt_number=value.attempt_number,
            delivery_cycle=value.delivery_cycle,
            cycle_key=value.cycle_key,
            broker_receipt_id=value.broker_receipt_id,
            commit_ticket=value.commit_ticket,
            disposition=value.disposition,
            should_execute=value.should_execute,
        )
    except (AttributeError, OutboxValidation) as exc:
        raise OutboxStoredContractError("Receipt runtime returned invalid pending authority") from exc


def _copy_executable_authority(value: object) -> ExecutableStageAuthority:
    if type(value) is not ExecutableStageAuthority:
        raise OutboxStoredContractError("Confirmation returned invalid executable authority")
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
    except (AttributeError, OutboxValidation) as exc:
        raise OutboxStoredContractError("Confirmation returned invalid executable authority") from exc


def _assert_authority_matches_result(
    result: CoordinatedStageReceipt,
    authority: ExecutableStageAuthority,
) -> None:
    if (
        authority.workflow_run_id != result.workflow_run_id
        or authority.stage_run_id != result.stage_run_id
        or authority.stage_attempt_id != result.stage_attempt_id
        or authority.message_id != result.message_id
        or authority.delivery_attempt_id != result.delivery_attempt_id
        or authority.attempt_number != result.attempt_number
        or authority.delivery_cycle != result.delivery_cycle
        or authority.cycle_key != result.cycle_key
        or authority.broker_receipt_id != result.broker_receipt_id
    ):
        raise OutboxStoredContractError("Executable authority contradicts its coordinated receipt lineage")


def _exact_uuid(value: object, *, field_name: str) -> uuid.UUID:
    if type(value) is not uuid.UUID:
        raise OutboxValidation(f"{field_name} must be an exact UUID")
    return value


def _lower_sha256(value: object, *, field_name: str) -> str:
    if type(value) is not str or not _LOWER_SHA256_RE.fullmatch(value):
        raise OutboxValidation(f"{field_name} must be an exact lowercase SHA-256 value")
    return value


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
