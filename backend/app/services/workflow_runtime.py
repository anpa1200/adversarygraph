"""PostgreSQL-backed runtime for deterministic research workflows.

The runtime owns every durable state transition for ``WorkflowRun``,
``StageRun``, and ``StageAttempt``.  Callers own the surrounding transaction:
functions in this module flush in the order required by the database guards,
but never commit.

Worker mutations are fenced by the opaque lease token *and* optimistic state
versions for both the logical stage and its current attempt.  PostgreSQL's
transaction clock is the only clock used for claiming, lease validation,
heartbeats, checkpoints, retries, recovery, and terminal timestamps.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Literal

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.research_workflow import (
    STAGE_CHECKPOINT_SCHEMA_VERSION,
    STAGE_CONFIG_SCHEMA_VERSION,
    WORKFLOW_PLAN_SCHEMA_VERSION,
    WORKFLOW_SCHEMA_VERSION,
    ProjectRevision,
    ResearchProject,
    StageAttempt,
    StageRun,
    WorkflowRun,
)
from app.services.outbox_runtime import (
    append_reserved_stage_ready,
    project_stage_ready_intent,
    reserve_stage_ready_intents,
)
from app.services.research_projects import ResearchActor
from app.services.workflow_engine import (
    IdempotencyTokenError,
    StageDefinition,
    WorkflowStagePlan,
    canonical_json,
    checksum_json,
    hash_idempotency_token,
    normalize_stage_plan,
)


_IDENTITY_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,79}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,79}$")
_TERMINAL_WORKFLOW_STATUSES = (
    "succeeded",
    "degraded",
    "failed",
    "cancelled",
    "dead_lettered",
)
_MAX_LEASE_SECONDS = 3_600


class WorkflowRuntimeError(RuntimeError):
    """Base class for durable workflow runtime failures."""


class WorkflowNotFound(WorkflowRuntimeError):
    """A requested workflow authority record does not exist."""


class WorkflowConflict(WorkflowRuntimeError):
    """A requested transition conflicts with current durable state."""


class WorkflowAccessDenied(WorkflowRuntimeError):
    """A project cannot cross the current workflow clearance boundary."""


class WorkflowValidation(WorkflowRuntimeError):
    """A runtime command is outside the bounded workflow contract."""


class WorkflowLeaseLost(WorkflowConflict):
    """A worker no longer owns the exact live fenced attempt it presented."""


class WorkflowCheckpointConflict(WorkflowConflict):
    """A checkpoint compare-and-swap version did not match."""


class WorkflowStoredContractError(WorkflowRuntimeError):
    """Persisted workflow authority is internally inconsistent."""


@dataclass(frozen=True)
class ClaimedStage:
    """The exact workflow, stage, and attempt authority granted to a worker."""

    workflow: WorkflowRun
    stage: StageRun
    attempt: StageAttempt


@dataclass(frozen=True)
class StageMutation:
    """State returned after a fenced worker mutation."""

    workflow: WorkflowRun
    stage: StageRun
    attempt: StageAttempt


@dataclass(frozen=True)
class RecoveryResult:
    """One expired attempt recovered into retry wait or dead letter."""

    workflow_run_id: uuid.UUID
    stage_run_id: uuid.UUID
    attempt_id: uuid.UUID
    stage_status: str
    next_attempt_at: datetime | None


async def create_workflow(
    db: AsyncSession,
    actor: ResearchActor,
    *,
    project_revision_id: uuid.UUID,
    workflow_type: str,
    idempotency_token: str,
    input_manifest: dict[str, Any],
    stage_plan: WorkflowStagePlan | list[StageDefinition | dict[str, Any]] | dict[str, Any],
    trigger_type: Literal["manual", "api", "schedule", "replay"] = "api",
    priority: int = 5,
    workflow_schema_version: str = WORKFLOW_SCHEMA_VERSION,
    plan_schema_version: str = WORKFLOW_PLAN_SCHEMA_VERSION,
    correlation_id: uuid.UUID | None = None,
    replay_of_run_id: uuid.UUID | None = None,
) -> tuple[WorkflowRun, bool]:
    """Create one content-bound workflow, or return its exact idempotent replay.

    The project is locked before its current revision.  That is the same lock
    order used by project revision changes and also serializes identical
    workflow creates before the database uniqueness constraint is reached.
    """

    actor_name, actor_id = _actor(actor)
    clean_type = _identity(workflow_type, field_name="workflow_type")
    clean_workflow_schema = _version(workflow_schema_version, field_name="workflow_schema_version")
    clean_plan_schema = _version(plan_schema_version, field_name="plan_schema_version")
    if clean_workflow_schema != WORKFLOW_SCHEMA_VERSION or clean_plan_schema != WORKFLOW_PLAN_SCHEMA_VERSION:
        raise WorkflowValidation("Workflow creation requires the exact current v1 workflow and plan schemas")
    clean_priority = _bounded_int(priority, field_name="priority", minimum=0, maximum=9)
    if trigger_type not in {"manual", "api", "schedule", "replay"}:
        raise WorkflowValidation("trigger_type is not supported")
    replay_id = _optional_uuid(replay_of_run_id, field_name="replay_of_run_id")
    if (trigger_type == "replay") != (replay_id is not None):
        raise WorkflowValidation("Replay workflows require replay_of_run_id and other triggers forbid it")

    revision_id = _uuid(project_revision_id, field_name="project_revision_id")
    input_payload, input_checksum = _canonical_object(input_manifest, field_name="input_manifest")
    normalized_plan = normalize_stage_plan(stage_plan)
    if any(
        definition.config_schema_version != STAGE_CONFIG_SCHEMA_VERSION
        or definition.checkpoint_schema_version != STAGE_CHECKPOINT_SCHEMA_VERSION
        for definition in normalized_plan.stages
    ):
        raise WorkflowValidation("Workflow creation requires the exact current v1 stage schemas")
    plan_payload = normalized_plan.as_payload()
    try:
        idempotency_key = hash_idempotency_token(idempotency_token, namespace=clean_type)
    except IdempotencyTokenError as exc:
        raise WorkflowValidation("idempotency_token is outside the bounded runtime contract") from exc

    revision_snapshot = await db.get(ProjectRevision, revision_id)
    if revision_snapshot is None:
        raise WorkflowNotFound("Project revision not found")
    project = await db.scalar(
        select(ResearchProject)
        .where(ResearchProject.id == revision_snapshot.project_id)
        .execution_options(populate_existing=True, autoflush=False)
        .with_for_update()
    )
    if project is None:
        raise WorkflowNotFound("Research project not found")
    revision = await db.scalar(
        select(ProjectRevision)
        .where(ProjectRevision.id == revision_id)
        .execution_options(populate_existing=True, autoflush=False)
        .with_for_update()
    )
    if revision is None or revision.project_id != project.id:
        raise WorkflowConflict("Project revision changed while workflow creation was being authorized")
    _assert_project_authorized(project, revision)

    replay: WorkflowRun | None = None
    if replay_id is not None:
        replay = await db.scalar(
            select(WorkflowRun)
            .where(WorkflowRun.id == replay_id)
            .execution_options(populate_existing=True, autoflush=False)
            .with_for_update()
        )
        if replay is None:
            raise WorkflowNotFound("Replay source workflow not found")
        replay_revision = await db.get(ProjectRevision, replay.project_revision_id)
        if (
            replay_revision is None
            or replay_revision.project_id != project.id
            or replay.workflow_type != clean_type
            or replay.status not in _TERMINAL_WORKFLOW_STATUSES
        ):
            raise WorkflowConflict("Replay source must be a terminal workflow of the same type and project")

    existing = await db.scalar(
        select(WorkflowRun)
        .where(
            WorkflowRun.project_revision_id == revision.id,
            WorkflowRun.workflow_type == clean_type,
            WorkflowRun.idempotency_key == idempotency_key,
        )
        .execution_options(populate_existing=True, autoflush=False)
        .with_for_update()
    )
    if existing is not None:
        if not _same_workflow_content(
            existing,
            workflow_schema_version=clean_workflow_schema,
            plan_schema_version=clean_plan_schema,
            trigger_type=trigger_type,
            replay_of_run_id=replay_id,
            priority=clean_priority,
            input_manifest=input_payload,
            input_checksum=input_checksum,
            stage_plan=plan_payload,
            plan_checksum=normalized_plan.checksum,
        ):
            raise WorkflowConflict("Idempotency token is already bound to different workflow content")
        return existing, False

    run = WorkflowRun(
        id=uuid.uuid4(),
        project_revision_id=revision.id,
        replay_of_run_id=replay.id if replay is not None else None,
        workflow_type=clean_type,
        workflow_schema_version=clean_workflow_schema,
        plan_schema_version=clean_plan_schema,
        status="queued",
        trigger_type=trigger_type,
        idempotency_key=idempotency_key,
        correlation_id=_optional_uuid(correlation_id, field_name="correlation_id") or uuid.uuid4(),
        input_manifest=input_payload,
        input_checksum=input_checksum,
        stage_plan=plan_payload,
        plan_checksum=normalized_plan.checksum,
        priority=clean_priority,
        state_version=1,
        status_reason_code="",
        status_summary="",
        created_by=actor_name,
        created_by_id=actor_id,
        cancel_requested_by="",
        cancel_requested_by_id="",
        cancel_request_id=None,
        cancel_reason="",
        cancel_requested_at=None,
        started_at=None,
        completed_at=None,
    )
    db.add(run)
    await db.flush([run])

    now = await _db_now(db)
    empty_checksum = checksum_json({})
    stages: list[StageRun] = []
    for definition in normalized_plan.stages:
        stage_input = definition.input_manifest if definition.input_manifest is not None else input_payload
        stage_input_payload, stage_input_checksum = _canonical_object(stage_input, field_name="stage input_manifest")
        config_payload, config_checksum = _canonical_object(definition.config, field_name="stage config")
        stage = StageRun(
            id=uuid.uuid4(),
            workflow_run_id=run.id,
            stage_key=definition.stage_key,
            stage_type=definition.stage_type,
            stage_version=definition.stage_version,
            ordinal=definition.ordinal,
            status="ready" if not definition.depends_on else "pending",
            priority=definition.priority,
            state_version=1,
            idempotency_key=checksum_json({"workflow_run_id": str(run.id), "stage_key": definition.stage_key}),
            depends_on=list(definition.depends_on),
            required=definition.required,
            config_schema_version=definition.config_schema_version,
            config=config_payload,
            config_checksum=config_checksum,
            input_manifest=stage_input_payload,
            input_checksum=stage_input_checksum,
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
        stages.append(stage)

    locked_stages = tuple(stages)
    await db.flush(locked_stages)

    root_stages = tuple(stage for stage in locked_stages if not stage.depends_on)
    intents = tuple(
        project_stage_ready_intent(
            run,
            stage,
            emission_kind="root_ready",
            post_status="ready",
            post_state_version=stage.state_version,
            post_next_attempt_at=now,
            target_attempt_number=1,
        )
        for stage in root_stages
    )
    reservation = await reserve_stage_ready_intents(
        db,
        workflow=run,
        locked_stages=locked_stages,
        target_stages=root_stages,
        intents=intents,
    )
    await append_reserved_stage_ready(
        db,
        reservation=reservation,
        workflow=run,
        locked_stages=locked_stages,
    )
    return run, True


async def claim_stage(
    db: AsyncSession,
    *,
    worker_id: str,
    lease_seconds: int = 300,
    delivery_id: str = "",
) -> ClaimedStage | None:
    """Reject queue-independent activation before touching the database.

    Workflow stages can now become running only through the durable broker
    receipt coordinator in :mod:`app.services.outbox_runtime`.  The retained
    symbol gives old callers a deterministic cutover failure instead of a
    second, unaudited execution path.
    """

    del db, worker_id, lease_seconds, delivery_id
    raise WorkflowConflict("Direct stage claims are disabled; use receipt_and_claim_stage")


async def heartbeat_stage(
    db: AsyncSession,
    stage_run_id: uuid.UUID,
    *,
    lease_token: uuid.UUID,
    expected_stage_version: int,
    expected_attempt_version: int,
    lease_seconds: int = 300,
) -> StageMutation:
    """Reject receipt-unbound heartbeats before touching the database."""

    del (
        db,
        stage_run_id,
        lease_token,
        expected_stage_version,
        expected_attempt_version,
        lease_seconds,
    )
    raise WorkflowConflict("Direct stage heartbeats are disabled; use coordinate_stage_heartbeat")


async def checkpoint_stage(
    db: AsyncSession,
    stage_run_id: uuid.UUID,
    *,
    lease_token: uuid.UUID,
    expected_stage_version: int,
    expected_attempt_version: int,
    expected_checkpoint_version: int,
    checkpoint_schema_version: str,
    checkpoint: dict[str, Any],
    lease_seconds: int = 300,
) -> StageMutation:
    """Reject receipt-unbound checkpoints before touching the database."""

    del (
        db,
        stage_run_id,
        lease_token,
        expected_stage_version,
        expected_attempt_version,
        expected_checkpoint_version,
        checkpoint_schema_version,
        checkpoint,
        lease_seconds,
    )
    raise WorkflowConflict("Direct stage checkpoints are disabled; use coordinate_stage_checkpoint")


async def complete_stage(
    db: AsyncSession,
    stage_run_id: uuid.UUID,
    *,
    lease_token: uuid.UUID,
    expected_stage_version: int,
    expected_attempt_version: int,
    expected_checkpoint_version: int,
    output_manifest: dict[str, Any],
    outcome: Literal["succeeded", "degraded"] = "succeeded",
) -> StageMutation:
    """Reject receipt-unbound completions before touching the database."""

    del (
        db,
        stage_run_id,
        lease_token,
        expected_stage_version,
        expected_attempt_version,
        expected_checkpoint_version,
        output_manifest,
        outcome,
    )
    raise WorkflowConflict("Direct stage completions are disabled; use coordinate_stage_complete")


async def fail_stage(
    db: AsyncSession,
    stage_run_id: uuid.UUID,
    *,
    lease_token: uuid.UUID,
    expected_stage_version: int,
    expected_attempt_version: int,
    expected_checkpoint_version: int,
    error: BaseException | str,
    error_code: str,
    retryable: bool,
) -> StageMutation:
    """Reject receipt-unbound failures before touching the database."""

    del (
        db,
        stage_run_id,
        lease_token,
        expected_stage_version,
        expected_attempt_version,
        expected_checkpoint_version,
        error,
        error_code,
        retryable,
    )
    raise WorkflowConflict("Direct stage failures are disabled; use coordinate_stage_fail")


async def recover_one_expired_stage(db: AsyncSession) -> RecoveryResult | None:
    """Reject receipt-unbound lease recovery before touching the database."""

    del db
    raise WorkflowConflict("Direct lease recovery is disabled; use coordinate_one_expired_stage_recovery")


async def recover_expired_stages(
    db: AsyncSession,
    *,
    limit: int = 1,
) -> list[RecoveryResult]:
    """Reject receipt-unbound batch recovery before touching the database."""

    del db, limit
    raise WorkflowConflict("Direct batch lease recovery is disabled; use coordinate_expired_stage_recovery_pass")


async def cancel_workflow(
    db: AsyncSession,
    workflow_run_id: uuid.UUID,
    actor: ResearchActor,
    *,
    expected_state_version: int,
    reason: str,
) -> WorkflowRun:
    """Reject receipt-unbound cancellation before touching the database."""

    del db, workflow_run_id, actor, expected_state_version, reason
    raise WorkflowConflict("Direct workflow cancellation is disabled; use coordinate_workflow_cancel")


def _assert_checkpoint_version(stage: StageRun, expected: int) -> None:
    expected_version = _bounded_int(
        expected,
        field_name="expected_checkpoint_version",
        minimum=0,
        maximum=2_147_483_647,
    )
    if stage.checkpoint_version != expected_version:
        raise WorkflowCheckpointConflict(f"Checkpoint version conflict: expected {expected_version}, current {stage.checkpoint_version}")


def _same_workflow_content(
    workflow: WorkflowRun,
    *,
    workflow_schema_version: str,
    plan_schema_version: str,
    trigger_type: str,
    replay_of_run_id: uuid.UUID | None,
    priority: int,
    input_manifest: dict[str, Any],
    input_checksum: str,
    stage_plan: list[dict[str, Any]],
    plan_checksum: str,
) -> bool:
    return (
        workflow.workflow_schema_version == workflow_schema_version
        and workflow.plan_schema_version == plan_schema_version
        and workflow.trigger_type == trigger_type
        and workflow.replay_of_run_id == replay_of_run_id
        and workflow.priority == priority
        and workflow.input_checksum == input_checksum
        and workflow.input_manifest == input_manifest
        and workflow.plan_checksum == plan_checksum
        and workflow.stage_plan == stage_plan
    )


def _assert_project_authorized(project: ResearchProject, revision: ProjectRevision) -> None:
    if project.status != "active":
        raise WorkflowConflict("Archived projects cannot start workflows")
    if revision.status != "current":
        raise WorkflowConflict("Only the current project revision can start a workflow")
    revision_tlp = revision.spec.get("tlp") if isinstance(revision.spec, dict) else None
    if project.tlp == "TLP:RED" or revision_tlp == "TLP:RED":
        raise WorkflowAccessDenied("TLP:RED workflows require a clearance boundary that is not enabled")


def _extended_expiry(
    current: datetime | None,
    now: datetime,
    lease_seconds: int,
) -> datetime:
    candidate = now + timedelta(seconds=lease_seconds)
    return max(current, candidate) if current is not None else candidate


async def _db_now(db: AsyncSession, *, autoflush: bool = True) -> datetime:
    statement = select(func.transaction_timestamp())
    if not autoflush:
        statement = statement.execution_options(autoflush=False)
    value = await db.scalar(statement)
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise WorkflowStoredContractError("PostgreSQL transaction clock did not return a timezone-aware timestamp")
    return value


def _actor(actor: ResearchActor) -> tuple[str, str]:
    name = _text(getattr(actor, "name", ""), field_name="actor.name", maximum=255)
    actor_id = _text(getattr(actor, "actor_id", ""), field_name="actor.actor_id", maximum=80)
    return name, actor_id


def _canonical_object(value: object, *, field_name: str) -> tuple[dict[str, Any], str]:
    if type(value) is not dict:
        raise WorkflowValidation(f"{field_name} must be a JSON object")
    try:
        canonical = canonical_json(value)
    except ValueError as exc:
        raise WorkflowValidation(f"{field_name} is not valid bounded canonical JSON") from exc
    payload = json.loads(canonical)
    if not isinstance(payload, dict):  # Defensive; type is checked above.
        raise WorkflowValidation(f"{field_name} must be a JSON object")
    return payload, checksum_json(payload)


def _identity(value: object, *, field_name: str) -> str:
    clean = value.strip() if isinstance(value, str) else ""
    if not _IDENTITY_RE.fullmatch(clean):
        raise WorkflowValidation(f"{field_name} must be a lowercase workflow identity up to 80 characters")
    return clean


def _version(value: object, *, field_name: str) -> str:
    clean = value.strip() if isinstance(value, str) else ""
    if not _VERSION_RE.fullmatch(clean):
        raise WorkflowValidation(f"{field_name} must be a version identity up to 80 characters")
    return clean


def _text(value: object, *, field_name: str, maximum: int) -> str:
    clean = value.strip() if isinstance(value, str) else ""
    if not clean:
        raise WorkflowValidation(f"{field_name} is required")
    if len(clean) > maximum:
        raise WorkflowValidation(f"{field_name} exceeds {maximum} characters")
    return clean


def _optional_text(value: object, *, field_name: str, maximum: int) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise WorkflowValidation(f"{field_name} must be a string")
    clean = value.strip()
    if len(clean) > maximum:
        raise WorkflowValidation(f"{field_name} exceeds {maximum} characters")
    return clean


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


def _lease_seconds(value: object) -> int:
    return _bounded_int(
        value,
        field_name="lease_seconds",
        minimum=1,
        maximum=_MAX_LEASE_SECONDS,
    )


def _uuid(value: object, *, field_name: str) -> uuid.UUID:
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise WorkflowValidation(f"{field_name} must be a UUID") from exc


def _optional_uuid(value: object, *, field_name: str) -> uuid.UUID | None:
    return None if value is None else _uuid(value, field_name=field_name)
