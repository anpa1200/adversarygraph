"""Revisioned research-project API."""

from __future__ import annotations

from dataclasses import fields
from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import ConfigDict, Field, model_validator
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import async_session_factory, get_session
from app.core.payload_limits import BoundedPayloadModel
from app.models.research_workflow import ProjectRevision, ResearchProject, StageRun, WorkflowRun
from app.services import outbox_runtime
from app.services import research_projects as projects
from app.services import research_workflows, workflow_runtime, workflow_worker
from app.services.auth import TeamUser, audit, current_user, require_permission


router = APIRouter(prefix="/research/projects", tags=["Research Projects"])
manage_research_projects = require_permission("manage_intel")
_EXPECTED_CONFLICT_CONSTRAINTS = frozenset(
    {
        "uq_research_project_key",
        "uq_project_revision_current",
        "uq_project_revision_number",
    }
)


class ProjectCreateBody(BoundedPayloadModel):
    project_key: str = Field(
        min_length=1,
        max_length=80,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9-]{0,79}$",
    )
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=100_000)
    spec: projects.ResearchProjectSpec
    change_summary: str = Field(default="Initial research scope", min_length=1, max_length=2_000)


class ProjectMetadataBody(BoundedPayloadModel):
    expected_version: int = Field(ge=1)
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=100_000)

    @model_validator(mode="after")
    def _require_change(self):
        if self.name is None and self.description is None:
            raise ValueError("At least one project metadata field is required")
        return self


class ProjectRevisionBody(BoundedPayloadModel):
    expected_version: int = Field(ge=1)
    spec: projects.ResearchProjectSpec
    change_summary: str = Field(min_length=1, max_length=2_000)


class ProjectArchiveBody(BoundedPayloadModel):
    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=3, max_length=2_000)


class ProjectRevisionOut(BoundedPayloadModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: UUID
    revision: int
    parent_revision_id: UUID | None
    status: Literal["current", "superseded", "revoked"]
    schema_version: str
    spec_checksum: str
    spec: projects.ResearchProjectSpec
    change_summary: str
    created_by: str
    created_by_id: str
    revoked_by: str
    revoked_by_id: str
    revoked_at: datetime | None
    created_at: datetime | None


class ProjectOut(BoundedPayloadModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: UUID
    project_key: str
    name: str
    description: str
    status: Literal["active", "archived"]
    domain: str
    tlp: str
    version: int
    created_by: str
    created_by_id: str
    updated_by: str
    updated_by_id: str
    archive_reason: str
    archived_at: datetime | None
    created_at: datetime | None
    updated_at: datetime | None
    current_revision: ProjectRevisionOut


class ProjectListOut(BoundedPayloadModel):
    total: int
    limit: int
    offset: int
    items: list[ProjectOut]


class ProjectRevisionListOut(BoundedPayloadModel):
    project_id: UUID
    project_version: int
    items: list[ProjectRevisionOut]


class WorkflowStartBody(BoundedPayloadModel):
    idempotency_token: str = Field(min_length=1, max_length=1_024)
    priority: int = Field(default=5, ge=0, le=9, strict=True)


class WorkflowCancelBody(BoundedPayloadModel):
    request_id: UUID
    expected_workflow_state_version: int = Field(ge=1, strict=True)
    reason: str = Field(min_length=3, max_length=500)


class WorkflowRunOut(BoundedPayloadModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: UUID
    project_revision_id: UUID
    workflow_type: str
    status: Literal["queued", "running", "succeeded", "degraded", "failed", "cancelled", "dead_lettered"]
    trigger_type: Literal["manual", "api", "schedule", "replay"]
    correlation_id: UUID
    priority: int
    state_version: int
    status_reason_code: str
    status_summary: str
    created_by: str
    created_by_id: str
    cancel_requested_by: str
    cancel_requested_by_id: str
    cancel_reason: str
    cancel_request_id: UUID | None
    cancel_requested_at: datetime | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime | None
    updated_at: datetime | None


class WorkflowStageOut(BoundedPayloadModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: UUID
    stage_key: str
    stage_type: str
    stage_version: str
    ordinal: int
    status: Literal[
        "pending",
        "ready",
        "running",
        "retry_wait",
        "succeeded",
        "degraded",
        "failed",
        "cancelled",
        "skipped",
        "dead_lettered",
    ]
    required: bool
    state_version: int
    attempt_count: int
    max_attempts: int
    next_attempt_at: datetime | None
    checkpoint_version: int
    last_error_code: str
    last_error_summary: str
    last_error_retryable: bool
    first_started_at: datetime | None
    completed_at: datetime | None


class WorkflowStartOut(BoundedPayloadModel):
    created: bool
    workflow: WorkflowRunOut


class WorkflowDetailOut(BoundedPayloadModel):
    workflow: WorkflowRunOut
    stages: list[WorkflowStageOut]


class WorkflowListOut(BoundedPayloadModel):
    total: int
    limit: int
    offset: int
    items: list[WorkflowRunOut]


class WorkflowCancellationOut(BoundedPayloadModel):
    request_id: UUID
    workflow_run_id: UUID
    actor: str
    actor_id: str
    reason: str
    previous_workflow_state_version: int
    workflow_state_version: int
    cancelled_at: datetime
    cancelled_stage_ids: tuple[UUID, ...]
    cancelled_attempt_ids: tuple[UUID, ...]
    cancelled_message_ids: tuple[UUID, ...]
    cancelled_delivery_ids: tuple[UUID, ...]
    disposition: Literal["applied", "replayed"]
    should_apply: bool


def _actor(user: TeamUser) -> projects.ResearchActor:
    return projects.ResearchActor(
        name=user.name,
        actor_id=user.user_id or f"{user.auth_source}:{user.name}",
    )


def _revision_out(revision: ProjectRevision) -> ProjectRevisionOut:
    spec = projects.decode_project_spec(revision.schema_version, revision.spec)
    return ProjectRevisionOut(
        **{field: getattr(revision, field) for field in ProjectRevisionOut.model_fields if field != "spec"},
        spec=spec,
    )


def _project_out(project: ResearchProject, revision: ProjectRevision) -> ProjectOut:
    return ProjectOut(
        **{column.name: getattr(project, column.name) for column in project.__table__.columns},
        current_revision=_revision_out(revision),
    )


def _workflow_out(workflow: WorkflowRun) -> WorkflowRunOut:
    return WorkflowRunOut.model_validate(workflow)


def _workflow_stage_out(stage: StageRun) -> WorkflowStageOut:
    return WorkflowStageOut.model_validate(stage)


def _fixed_cancellation_result(value: object) -> workflow_worker.CoordinatedWorkflowCancellation:
    if type(value) is not workflow_worker.CoordinatedWorkflowCancellation:
        raise outbox_runtime.OutboxStoredContractError("Workflow cancellation coordinator returned an invalid result type")
    try:
        return workflow_worker.CoordinatedWorkflowCancellation(
            **{field.name: getattr(value, field.name) for field in fields(workflow_worker.CoordinatedWorkflowCancellation) if field.init}
        )
    except outbox_runtime.OutboxValidation as exc:
        raise outbox_runtime.OutboxStoredContractError("Workflow cancellation coordinator result violates its fixed point") from exc


async def _translate_error(db: AsyncSession, exc: projects.ResearchProjectError):
    await db.rollback()
    if isinstance(exc, projects.ResearchProjectNotFound):
        raise HTTPException(404, str(exc)) from exc
    if isinstance(exc, projects.ResearchProjectAccessDenied):
        raise HTTPException(403, str(exc)) from exc
    if isinstance(exc, projects.ResearchProjectValidation):
        raise HTTPException(422, str(exc)) from exc
    if isinstance(exc, projects.ResearchProjectStoredContractError):
        raise RuntimeError(str(exc)) from exc
    raise HTTPException(409, str(exc)) from exc


async def _commit_or_conflict(db: AsyncSession) -> None:
    await db.commit()


def _integrity_identity(exc: IntegrityError) -> tuple[str, str]:
    original = exc.orig
    sqlstate = str(getattr(original, "sqlstate", None) or getattr(original, "pgcode", None) or "")
    diagnostic = getattr(original, "diag", None)
    constraint = str(getattr(diagnostic, "constraint_name", None) or "")
    return sqlstate, constraint


async def _raise_integrity_conflict(db: AsyncSession, exc: IntegrityError) -> None:
    await db.rollback()
    sqlstate, constraint = _integrity_identity(exc)
    if sqlstate == "23505" and constraint in _EXPECTED_CONFLICT_CONSTRAINTS:
        raise HTTPException(
            409,
            "Research project conflicts with an existing key or revision; reload and retry",
        ) from exc
    raise exc


async def _translate_workflow_error(db: AsyncSession, exc: Exception) -> None:
    await db.rollback()
    if isinstance(exc, (workflow_runtime.WorkflowNotFound, research_workflows.ResearchWorkflowNotFound)):
        raise HTTPException(404, str(exc)) from exc
    if isinstance(exc, workflow_runtime.WorkflowAccessDenied):
        raise HTTPException(403, str(exc)) from exc
    if isinstance(exc, workflow_runtime.WorkflowValidation):
        raise HTTPException(422, str(exc)) from exc
    if isinstance(exc, workflow_runtime.WorkflowStoredContractError):
        raise RuntimeError(str(exc)) from exc
    if isinstance(exc, workflow_runtime.WorkflowRuntimeError):
        raise HTTPException(409, str(exc)) from exc
    raise exc


async def _translate_cancellation_error(db: AsyncSession, exc: Exception) -> None:
    if isinstance(exc, workflow_runtime.WorkflowRuntimeError):
        await _translate_workflow_error(db, exc)
    await db.rollback()
    if isinstance(exc, outbox_runtime.OutboxNotFound):
        raise HTTPException(404, str(exc)) from exc
    if isinstance(exc, outbox_runtime.OutboxValidation):
        raise HTTPException(422, str(exc)) from exc
    if isinstance(exc, outbox_runtime.OutboxStoredContractError):
        raise RuntimeError(str(exc)) from exc
    if isinstance(exc, outbox_runtime.OutboxRuntimeError):
        raise HTTPException(409, str(exc)) from exc
    raise exc


@router.get(
    "",
    response_model=ProjectListOut,
    summary="List revisioned research projects",
)
async def list_research_projects(
    status: Literal["active", "archived"] | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
) -> ProjectListOut:
    try:
        total, rows = await projects.list_projects(
            db,
            status=status,
            limit=limit,
            offset=offset,
        )
    except projects.ResearchProjectError as exc:
        await _translate_error(db, exc)
    return ProjectListOut(
        total=total,
        limit=limit,
        offset=offset,
        items=[_project_out(project, revision) for project, revision in rows],
    )


@router.post(
    "",
    response_model=ProjectOut,
    status_code=201,
    summary="Create a research project and revision one",
)
async def create_research_project(
    body: ProjectCreateBody,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(manage_research_projects),
) -> ProjectOut:
    try:
        project, revision = await projects.create_project(
            db,
            _actor(user),
            project_key=body.project_key,
            name=body.name,
            description=body.description,
            spec=body.spec,
            change_summary=body.change_summary,
        )
        await audit(
            db,
            user,
            "research_project.create",
            "research_project",
            str(project.id),
            {
                "project_key": project.project_key,
                "revision": revision.revision,
                "spec_checksum": revision.spec_checksum,
            },
        )
        await _commit_or_conflict(db)
    except IntegrityError as exc:
        await _raise_integrity_conflict(db, exc)
    except projects.ResearchProjectError as exc:
        await _translate_error(db, exc)
    return _project_out(project, revision)


@router.get(
    "/{project_id}",
    response_model=ProjectOut,
    summary="Get a research project and current revision",
)
async def get_research_project(
    project_id: UUID,
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
) -> ProjectOut:
    try:
        project, revision = await projects.get_project(db, project_id)
    except projects.ResearchProjectError as exc:
        await _translate_error(db, exc)
    return _project_out(project, revision)


@router.patch(
    "/{project_id}",
    response_model=ProjectOut,
    summary="Update research project metadata",
)
async def update_research_project(
    project_id: UUID,
    body: ProjectMetadataBody,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(manage_research_projects),
) -> ProjectOut:
    try:
        project, revision = await projects.update_project_metadata(
            db,
            project_id,
            _actor(user),
            expected_version=body.expected_version,
            name=body.name,
            description=body.description,
        )
        await audit(
            db,
            user,
            "research_project.update_metadata",
            "research_project",
            str(project.id),
            {"project_version": project.version},
        )
        await _commit_or_conflict(db)
    except IntegrityError as exc:
        await _raise_integrity_conflict(db, exc)
    except projects.ResearchProjectError as exc:
        await _translate_error(db, exc)
    return _project_out(project, revision)


@router.post(
    "/{project_id}/revisions",
    response_model=ProjectOut,
    status_code=201,
    summary="Create the next immutable project revision",
)
async def create_project_revision(
    project_id: UUID,
    body: ProjectRevisionBody,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(manage_research_projects),
) -> ProjectOut:
    try:
        project, revision = await projects.create_revision(
            db,
            project_id,
            _actor(user),
            expected_version=body.expected_version,
            spec=body.spec,
            change_summary=body.change_summary,
        )
        await audit(
            db,
            user,
            "research_project.create_revision",
            "research_project",
            str(project.id),
            {
                "project_version": project.version,
                "revision": revision.revision,
                "parent_revision_id": str(revision.parent_revision_id),
                "spec_checksum": revision.spec_checksum,
            },
        )
        await _commit_or_conflict(db)
    except IntegrityError as exc:
        await _raise_integrity_conflict(db, exc)
    except projects.ResearchProjectError as exc:
        await _translate_error(db, exc)
    return _project_out(project, revision)


@router.get(
    "/{project_id}/revisions",
    response_model=ProjectRevisionListOut,
    summary="List immutable project revisions",
)
async def list_project_revisions(
    project_id: UUID,
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
) -> ProjectRevisionListOut:
    try:
        project, revisions = await projects.list_revisions(db, project_id)
    except projects.ResearchProjectError as exc:
        await _translate_error(db, exc)
    return ProjectRevisionListOut(
        project_id=project.id,
        project_version=project.version,
        items=[_revision_out(revision) for revision in revisions],
    )


@router.get(
    "/{project_id}/revisions/{revision_number}",
    response_model=ProjectRevisionOut,
    summary="Get one immutable project revision",
)
async def get_project_revision(
    project_id: UUID,
    revision_number: int = Path(ge=1),
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
) -> ProjectRevisionOut:
    try:
        _, revision = await projects.get_revision(
            db,
            project_id,
            revision_number,
        )
    except projects.ResearchProjectError as exc:
        await _translate_error(db, exc)
    return _revision_out(revision)


@router.post(
    "/{project_id}/workflows",
    response_model=WorkflowStartOut,
    status_code=201,
    summary="Start or replay the canonical research-scope workflow",
)
async def start_research_workflow(
    project_id: UUID,
    body: WorkflowStartBody,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(manage_research_projects),
) -> WorkflowStartOut:
    try:
        workflow, created = await research_workflows.create_research_scope_workflow(
            db,
            workflow_runtime.ResearchActor(
                name=user.name,
                actor_id=user.user_id or f"{user.auth_source}:{user.name}",
            ),
            project_id=project_id,
            idempotency_token=body.idempotency_token,
            priority=body.priority,
        )
        await audit(
            db,
            user,
            "research_workflow.start" if created else "research_workflow.replay",
            "workflow_run",
            str(workflow.id),
            {
                "project_id": str(project_id),
                "project_revision_id": str(workflow.project_revision_id),
                "workflow_type": workflow.workflow_type,
                "created": created,
            },
        )
        await _commit_or_conflict(db)
    except IntegrityError:
        await db.rollback()
        raise
    except projects.ResearchProjectError as exc:
        await _translate_error(db, exc)
    except workflow_runtime.WorkflowRuntimeError as exc:
        await _translate_workflow_error(db, exc)
    return WorkflowStartOut(created=created, workflow=_workflow_out(workflow))


@router.get(
    "/{project_id}/workflows",
    response_model=WorkflowListOut,
    summary="List durable workflows for a research project",
)
async def list_project_workflows(
    project_id: UUID,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
) -> WorkflowListOut:
    try:
        total, workflows = await research_workflows.list_research_workflows(
            db,
            project_id=project_id,
            limit=limit,
            offset=offset,
        )
    except projects.ResearchProjectError as exc:
        await _translate_error(db, exc)
    return WorkflowListOut(
        total=total,
        limit=limit,
        offset=offset,
        items=[_workflow_out(workflow) for workflow in workflows],
    )


@router.get(
    "/{project_id}/workflows/{workflow_run_id}",
    response_model=WorkflowDetailOut,
    summary="Get durable workflow and ordered stage status",
)
async def get_project_workflow(
    project_id: UUID,
    workflow_run_id: UUID,
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
) -> WorkflowDetailOut:
    try:
        workflow, stages = await research_workflows.get_research_workflow(
            db,
            project_id=project_id,
            workflow_run_id=workflow_run_id,
        )
    except projects.ResearchProjectError as exc:
        await _translate_error(db, exc)
    except (workflow_runtime.WorkflowRuntimeError, research_workflows.ResearchWorkflowNotFound) as exc:
        await _translate_workflow_error(db, exc)
    return WorkflowDetailOut(
        workflow=_workflow_out(workflow),
        stages=[_workflow_stage_out(stage) for stage in stages],
    )


@router.post(
    "/{project_id}/workflows/{workflow_run_id}/cancel",
    response_model=WorkflowCancellationOut,
    summary="Cancel a durable research workflow with an idempotent command",
)
async def cancel_project_workflow(
    project_id: UUID,
    workflow_run_id: UUID,
    body: WorkflowCancelBody,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(manage_research_projects),
) -> WorkflowCancellationOut:
    try:
        await research_workflows.get_research_workflow(
            db,
            project_id=project_id,
            workflow_run_id=workflow_run_id,
        )
        actor = _actor(user)
        result = _fixed_cancellation_result(
            await workflow_worker.coordinate_workflow_cancel(
                async_session_factory,
                command=outbox_runtime.WorkflowCancellationCommand(
                    request_id=body.request_id,
                    workflow_run_id=workflow_run_id,
                    expected_workflow_state_version=body.expected_workflow_state_version,
                    actor=actor.name,
                    actor_id=actor.actor_id,
                    reason=body.reason,
                ),
            ),
        )
        await audit(
            db,
            user,
            "research_workflow.cancel" if result.should_apply else "research_workflow.cancel_replay",
            "workflow_run",
            str(result.workflow_run_id),
            {
                "project_id": str(project_id),
                "request_id": str(result.request_id),
                "disposition": result.disposition,
                "workflow_state_version": result.workflow_state_version,
            },
        )
        await _commit_or_conflict(db)
    except projects.ResearchProjectError as exc:
        await _translate_error(db, exc)
    except research_workflows.ResearchWorkflowNotFound as exc:
        await _translate_workflow_error(db, exc)
    except (outbox_runtime.OutboxRuntimeError, workflow_runtime.WorkflowRuntimeError) as exc:
        await _translate_cancellation_error(db, exc)
    return WorkflowCancellationOut(**{field_name: getattr(result, field_name) for field_name in WorkflowCancellationOut.model_fields})


@router.post(
    "/{project_id}/archive",
    response_model=ProjectOut,
    summary="Archive a research project",
)
async def archive_research_project(
    project_id: UUID,
    body: ProjectArchiveBody,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(manage_research_projects),
) -> ProjectOut:
    try:
        project, revision = await projects.archive_project(
            db,
            project_id,
            _actor(user),
            expected_version=body.expected_version,
            reason=body.reason,
        )
        await audit(
            db,
            user,
            "research_project.archive",
            "research_project",
            str(project.id),
            {
                "project_version": project.version,
                "reason": project.archive_reason,
            },
        )
        await _commit_or_conflict(db)
    except IntegrityError as exc:
        await _raise_integrity_conflict(db, exc)
    except projects.ResearchProjectError as exc:
        await _translate_error(db, exc)
    return _project_out(project, revision)
