"""Canonical executable workflow for one immutable research-project scope.

The first production workflow is intentionally small and deterministic: it
turns the exact current project revision into a bounded scope manifest.  It is
useful on its own as the authority hand-off for downstream research work, and
it exercises the complete durable outbox/receipt/worker path without granting
API callers an arbitrary stage graph or handler name.
"""

from __future__ import annotations

import uuid
from typing import Literal

from pydantic import ConfigDict, Field, ValidationError
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.payload_limits import BoundedPayloadModel
from app.models.research_workflow import (
    PROJECT_SPEC_SCHEMA_VERSION,
    ProjectRevision,
    ResearchProject,
    StageRun,
    WorkflowRun,
)
from app.services.research_projects import (
    ResearchProjectSpec,
    ResearchProjectStoredContractError,
    decode_project_spec,
    normalize_project_spec,
)
from app.services.workflow_engine import (
    STAGE_CHECKPOINT_SCHEMA_VERSION,
    STAGE_CONFIG_SCHEMA_VERSION,
    StageDefinition,
    WorkflowStagePlan,
)
from app.services.workflow_orchestrator import (
    StageExecutionError,
    StageHandlerContext,
    StageHandlerOutcome,
)
from app.services import workflow_runtime


RESEARCH_SCOPE_WORKFLOW_TYPE = "cti.research.scope"
RESEARCH_SCOPE_STAGE_KEY = "scope"
RESEARCH_SCOPE_STAGE_TYPE = "research.project.scope"
RESEARCH_SCOPE_STAGE_VERSION = "1"
RESEARCH_SCOPE_CONFIG_SCHEMA_VERSION = STAGE_CONFIG_SCHEMA_VERSION
RESEARCH_SCOPE_INPUT_SCHEMA_VERSION = "research-scope-input-v1"
RESEARCH_SCOPE_OUTPUT_SCHEMA_VERSION = "research-scope-output-v1"

__all__ = (
    "RESEARCH_SCOPE_STAGE_TYPE",
    "RESEARCH_SCOPE_STAGE_VERSION",
    "RESEARCH_SCOPE_WORKFLOW_TYPE",
    "ResearchScopeInput",
    "ResearchScopeOutput",
    "build_research_scope_input",
    "create_research_scope_workflow",
    "get_research_workflow",
    "list_research_workflows",
    "research_scope_plan",
    "run_research_scope_stage",
)


class ResearchWorkflowNotFound(RuntimeError):
    """A workflow is not bound to the requested readable project."""


class ResearchScopeInput(BoundedPayloadModel):
    """Exact immutable project authority persisted as workflow input."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["research-scope-input-v1"]
    project_id: uuid.UUID
    project_revision_id: uuid.UUID
    project_key: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,79}$")
    project_version: int = Field(ge=1, strict=True)
    revision_number: int = Field(ge=1, strict=True)
    spec_schema_version: Literal["research-project-spec-v1"]
    spec_checksum: str = Field(pattern=r"^[0-9a-f]{64}$")
    spec: ResearchProjectSpec


class ResearchScopeOutput(BoundedPayloadModel):
    """Bounded deterministic scope facts produced by the registered stage."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["research-scope-output-v1"]
    project_id: uuid.UUID
    project_revision_id: uuid.UUID
    project_key: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,79}$")
    revision_number: int = Field(ge=1, strict=True)
    spec_checksum: str = Field(pattern=r"^[0-9a-f]{64}$")
    objective: str
    intelligence_requirements: list[str]
    domains: list[str]
    source_kinds: list[str]
    output_targets: list[str]
    review_profile: str
    tlp: str


def build_research_scope_input(
    project: ResearchProject,
    revision: ProjectRevision,
) -> dict[str, object]:
    """Detach one current project revision into the workflow input contract."""

    if type(project) is not ResearchProject or type(revision) is not ProjectRevision:
        raise ResearchProjectStoredContractError("Research scope requires exact project authority rows")
    if (
        revision.project_id != project.id
        or revision.status != "current"
        or project.status != "active"
        or revision.schema_version != PROJECT_SPEC_SCHEMA_VERSION
    ):
        raise ResearchProjectStoredContractError("Research scope authority is not the active current revision")
    spec = decode_project_spec(revision.schema_version, revision.spec)
    payload, checksum = normalize_project_spec(spec)
    if payload != revision.spec or checksum != revision.spec_checksum:
        raise ResearchProjectStoredContractError("Research scope specification checksum is invalid")
    value = ResearchScopeInput(
        schema_version=RESEARCH_SCOPE_INPUT_SCHEMA_VERSION,
        project_id=project.id,
        project_revision_id=revision.id,
        project_key=project.project_key,
        project_version=project.version,
        revision_number=revision.revision,
        spec_schema_version=revision.schema_version,
        spec_checksum=revision.spec_checksum,
        spec=spec,
    )
    return value.model_dump(mode="json")


def research_scope_plan() -> WorkflowStagePlan:
    """Return a fresh exact plan containing only the registered scope stage."""

    return WorkflowStagePlan(
        stages=[
            StageDefinition(
                stage_key=RESEARCH_SCOPE_STAGE_KEY,
                stage_type=RESEARCH_SCOPE_STAGE_TYPE,
                stage_version=RESEARCH_SCOPE_STAGE_VERSION,
                ordinal=1,
                depends_on=[],
                required=True,
                priority=5,
                max_attempts=3,
                config_schema_version=RESEARCH_SCOPE_CONFIG_SCHEMA_VERSION,
                checkpoint_schema_version=STAGE_CHECKPOINT_SCHEMA_VERSION,
                config={},
                input_manifest=None,
            )
        ]
    )


async def run_research_scope_stage(context: StageHandlerContext) -> StageHandlerOutcome:
    """Compile one validated project revision into its deterministic scope."""

    if type(context) is not StageHandlerContext:
        raise StageExecutionError(
            "Research scope handler context is invalid",
            error_code="workflow.research_scope_invalid",
            retryable=False,
            error_class="ResearchScopeContractError",
        )
    if (
        context.stage_type != RESEARCH_SCOPE_STAGE_TYPE
        or context.stage_version != RESEARCH_SCOPE_STAGE_VERSION
        or context.config_schema_version != RESEARCH_SCOPE_CONFIG_SCHEMA_VERSION
        or context.config != {}
    ):
        raise StageExecutionError(
            "Research scope handler contract is invalid",
            error_code="workflow.research_scope_invalid",
            retryable=False,
            error_class="ResearchScopeContractError",
        )
    try:
        authority = ResearchScopeInput.model_validate(context.input_manifest)
        spec_payload, checksum = normalize_project_spec(authority.spec)
    except (ValidationError, ResearchProjectStoredContractError) as exc:
        raise StageExecutionError(
            "Research scope input authority is invalid",
            error_code="workflow.research_scope_invalid",
            retryable=False,
            error_class="ResearchScopeContractError",
        ) from exc
    if checksum != authority.spec_checksum or spec_payload != authority.spec.model_dump(mode="json"):
        raise StageExecutionError(
            "Research scope input checksum is invalid",
            error_code="workflow.research_scope_invalid",
            retryable=False,
            error_class="ResearchScopeContractError",
        )
    output = ResearchScopeOutput(
        schema_version=RESEARCH_SCOPE_OUTPUT_SCHEMA_VERSION,
        project_id=authority.project_id,
        project_revision_id=authority.project_revision_id,
        project_key=authority.project_key,
        revision_number=authority.revision_number,
        spec_checksum=authority.spec_checksum,
        objective=authority.spec.objective,
        intelligence_requirements=authority.spec.intelligence_requirements,
        domains=authority.spec.domains,
        source_kinds=authority.spec.source_kinds,
        output_targets=authority.spec.output_targets,
        review_profile=authority.spec.review_profile,
        tlp=authority.spec.tlp,
    )
    return StageHandlerOutcome(
        output_manifest=output.model_dump(mode="json"),
        outcome="succeeded",
    )


async def create_research_scope_workflow(
    db: AsyncSession,
    actor: workflow_runtime.ResearchActor,
    *,
    project_id: uuid.UUID,
    idempotency_token: str,
    priority: int = 5,
) -> tuple[WorkflowRun, bool]:
    """Create or replay the one registered research-scope workflow."""

    from app.services import research_projects

    project, revision = await research_projects.lock_project_workflow_authority(
        db,
        project_id,
    )
    input_manifest = build_research_scope_input(project, revision)
    return await workflow_runtime.create_workflow(
        db,
        actor,
        project_revision_id=revision.id,
        workflow_type=RESEARCH_SCOPE_WORKFLOW_TYPE,
        idempotency_token=idempotency_token,
        input_manifest=input_manifest,
        stage_plan=research_scope_plan(),
        trigger_type="api",
        priority=priority,
    )


async def get_research_workflow(
    db: AsyncSession,
    *,
    project_id: uuid.UUID,
    workflow_run_id: uuid.UUID,
) -> tuple[WorkflowRun, tuple[StageRun, ...]]:
    """Load one workflow and its complete ordered stages through project scope."""

    from app.services import research_projects

    await research_projects.get_project(db, project_id)
    workflow = await db.scalar(
        select(WorkflowRun)
        .join(ProjectRevision, ProjectRevision.id == WorkflowRun.project_revision_id)
        .where(
            WorkflowRun.id == workflow_run_id,
            ProjectRevision.project_id == project_id,
        )
    )
    if workflow is None:
        raise ResearchWorkflowNotFound("Research workflow not found")
    rows = await db.execute(
        select(StageRun).where(StageRun.workflow_run_id == workflow.id).order_by(StageRun.ordinal.asc(), StageRun.id.asc())
    )
    stages = tuple(rows.scalars().all())
    if len(stages) != len(workflow.stage_plan):
        raise workflow_runtime.WorkflowStoredContractError("Persisted research workflow stage set is incomplete")
    return workflow, stages


async def list_research_workflows(
    db: AsyncSession,
    *,
    project_id: uuid.UUID,
    limit: int,
    offset: int,
) -> tuple[int, tuple[WorkflowRun, ...]]:
    """List workflows bound to any immutable revision of one project."""

    from app.services import research_projects

    await research_projects.get_project(db, project_id)
    predicate = ProjectRevision.project_id == project_id
    total = int(
        await db.scalar(
            select(func.count(WorkflowRun.id)).join(ProjectRevision, ProjectRevision.id == WorkflowRun.project_revision_id).where(predicate)
        )
        or 0
    )
    rows = await db.execute(
        select(WorkflowRun)
        .join(ProjectRevision, ProjectRevision.id == WorkflowRun.project_revision_id)
        .where(predicate)
        .order_by(WorkflowRun.created_at.desc(), WorkflowRun.id.desc())
        .limit(limit)
        .offset(offset)
    )
    return total, tuple(rows.scalars().all())
