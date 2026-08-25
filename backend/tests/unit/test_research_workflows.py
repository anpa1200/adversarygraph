from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.models.research_workflow import ProjectRevision, ResearchProject
from app.services import research_projects, research_workflows, workflow_runtime
from app.services.outbox_runtime import ExecutableStageAuthority
from app.services.workflow_engine import STAGE_CHECKPOINT_SCHEMA_VERSION, STAGE_CONFIG_SCHEMA_VERSION
from app.services.workflow_orchestrator import StageExecutionError, StageHandlerContext


NOW = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)


def _project_authority() -> tuple[ResearchProject, ProjectRevision]:
    spec = research_projects.ResearchProjectSpec.model_validate(
        {
            "objective": "Build an evidence-backed MuddyWater detection program.",
            "intelligence_requirements": ["Which procedures are supported by primary sources?"],
            "output_targets": ["detections", "rag"],
            "tlp": "TLP:AMBER",
        }
    )
    payload, checksum = research_projects.normalize_project_spec(spec)
    project_id = uuid.uuid4()
    project = ResearchProject(
        id=project_id,
        project_key="desert-hydra",
        name="Operation Desert Hydra",
        description="MuddyWater research program.",
        status="active",
        domain="enterprise-attack",
        tlp="TLP:AMBER",
        version=3,
        created_by="Analyst",
        created_by_id="analyst-1",
        updated_by="Analyst",
        updated_by_id="analyst-1",
        archive_reason="",
        archived_at=None,
        created_at=NOW,
        updated_at=NOW,
    )
    revision = ProjectRevision(
        id=uuid.uuid4(),
        project_id=project_id,
        parent_revision_id=uuid.uuid4(),
        revision=2,
        status="current",
        schema_version="research-project-spec-v1",
        spec=payload,
        spec_checksum=checksum,
        change_summary="Bound current scope",
        created_by="Analyst",
        created_by_id="analyst-1",
        revoked_by="",
        revoked_by_id="",
        revoked_at=None,
        created_at=NOW,
    )
    return project, revision


def _context(input_manifest: dict[str, object]) -> StageHandlerContext:
    return StageHandlerContext(
        authority=ExecutableStageAuthority(
            workflow_run_id=uuid.uuid4(),
            stage_run_id=uuid.uuid4(),
            stage_attempt_id=uuid.uuid4(),
            message_id=uuid.uuid4(),
            delivery_attempt_id=uuid.uuid4(),
            stage_lease_token=uuid.uuid4(),
            workflow_state_version=2,
            stage_state_version=2,
            attempt_state_version=1,
            attempt_number=1,
            delivery_cycle=1,
            cycle_key="a" * 64,
            stage_key="scope",
            input_checksum="b" * 64,
            checkpoint_version=0,
            lease_owner="worker-1",
            lease_expires_at=NOW + timedelta(minutes=5),
            broker_receipt_id="c" * 64,
        ),
        stage_type=research_workflows.RESEARCH_SCOPE_STAGE_TYPE,
        stage_version=research_workflows.RESEARCH_SCOPE_STAGE_VERSION,
        config_schema_version=research_workflows.RESEARCH_SCOPE_CONFIG_SCHEMA_VERSION,
        config={},
        input_manifest=input_manifest,
    )


def test_scope_input_and_plan_are_exact_deterministic_authority():
    project, revision = _project_authority()

    first = research_workflows.build_research_scope_input(project, revision)
    second = research_workflows.build_research_scope_input(project, revision)
    plan = research_workflows.research_scope_plan()

    assert first == second
    assert first["project_id"] == str(project.id)
    assert first["project_revision_id"] == str(revision.id)
    assert first["spec_checksum"] == revision.spec_checksum
    assert len(plan.stages) == 1
    stage = plan.stages[0]
    assert (stage.stage_key, stage.stage_type, stage.stage_version) == (
        "scope",
        "research.project.scope",
        "1",
    )
    assert stage.config_schema_version == STAGE_CONFIG_SCHEMA_VERSION
    assert stage.checkpoint_schema_version == STAGE_CHECKPOINT_SCHEMA_VERSION
    assert stage.input_manifest is None


@pytest.mark.asyncio
async def test_scope_plan_passes_the_real_runtime_schema_gate_before_database_access():
    project, revision = _project_authority()

    class DatabaseBoundaryReached(Exception):
        pass

    class BoundaryDatabase:
        async def get(self, *_args, **_kwargs):
            raise DatabaseBoundaryReached

        async def scalar(self, *_args, **_kwargs):
            raise DatabaseBoundaryReached

    with pytest.raises(DatabaseBoundaryReached):
        await workflow_runtime.create_workflow(
            BoundaryDatabase(),
            workflow_runtime.ResearchActor(name="Analyst", actor_id="analyst-1"),
            project_revision_id=revision.id,
            workflow_type=research_workflows.RESEARCH_SCOPE_WORKFLOW_TYPE,
            idempotency_token="runtime-schema-boundary",
            input_manifest=research_workflows.build_research_scope_input(project, revision),
            stage_plan=research_workflows.research_scope_plan(),
            trigger_type="api",
            priority=5,
        )


@pytest.mark.asyncio
async def test_scope_handler_returns_bounded_deterministic_manifest():
    project, revision = _project_authority()
    context = _context(research_workflows.build_research_scope_input(project, revision))

    first = await research_workflows.run_research_scope_stage(context)
    second = await research_workflows.run_research_scope_stage(context)

    assert first == second
    assert first.outcome == "succeeded"
    assert first.output_manifest == {
        "schema_version": "research-scope-output-v1",
        "project_id": str(project.id),
        "project_revision_id": str(revision.id),
        "project_key": project.project_key,
        "revision_number": revision.revision,
        "spec_checksum": revision.spec_checksum,
        "objective": revision.spec["objective"],
        "intelligence_requirements": revision.spec["intelligence_requirements"],
        "domains": revision.spec["domains"],
        "source_kinds": revision.spec["source_kinds"],
        "output_targets": revision.spec["output_targets"],
        "review_profile": revision.spec["review_profile"],
        "tlp": revision.spec["tlp"],
    }


@pytest.mark.asyncio
async def test_scope_handler_rejects_checksum_or_registered_contract_drift():
    project, revision = _project_authority()
    payload = research_workflows.build_research_scope_input(project, revision)
    payload["spec_checksum"] = "0" * 64

    with pytest.raises(StageExecutionError, match="checksum") as checksum_error:
        await research_workflows.run_research_scope_stage(_context(payload))
    assert checksum_error.value.retryable is False

    context = _context(research_workflows.build_research_scope_input(project, revision))
    object.__setattr__(context, "config", {"unexpected": True})
    with pytest.raises(StageExecutionError, match="contract") as contract_error:
        await research_workflows.run_research_scope_stage(context)
    assert contract_error.value.error_code == "workflow.research_scope_invalid"


def test_scope_input_fails_closed_on_noncurrent_or_checksum_corruption():
    project, revision = _project_authority()
    revision.status = "superseded"
    with pytest.raises(research_projects.ResearchProjectStoredContractError, match="active current"):
        research_workflows.build_research_scope_input(project, revision)

    revision.status = "current"
    revision.spec_checksum = "0" * 64
    with pytest.raises(research_projects.ResearchProjectStoredContractError, match="checksum"):
        research_workflows.build_research_scope_input(project, revision)


@pytest.mark.asyncio
async def test_create_scope_workflow_delegates_only_the_registered_canonical_contract(
    monkeypatch,
):
    project, revision = _project_authority()
    actor = workflow_runtime.ResearchActor(name="Analyst", actor_id="analyst-1")
    expected_run = object()
    calls = []

    async def lock_project(db, project_id):
        assert db is fake_db
        assert project_id == project.id
        return project, revision

    async def create_workflow(db, received_actor, **kwargs):
        calls.append((db, received_actor, kwargs))
        return expected_run, True

    fake_db = object()
    monkeypatch.setattr(
        research_projects,
        "lock_project_workflow_authority",
        lock_project,
    )
    monkeypatch.setattr(workflow_runtime, "create_workflow", create_workflow)

    value = await research_workflows.create_research_scope_workflow(
        fake_db,
        actor,
        project_id=project.id,
        idempotency_token="api-request-42",
        priority=8,
    )

    assert value == (expected_run, True)
    assert len(calls) == 1
    db, received_actor, kwargs = calls[0]
    assert db is fake_db
    assert received_actor == actor
    assert kwargs["project_revision_id"] == revision.id
    assert kwargs["workflow_type"] == "cti.research.scope"
    assert kwargs["idempotency_token"] == "api-request-42"
    assert kwargs["trigger_type"] == "api"
    assert kwargs["priority"] == 8
    assert kwargs["stage_plan"] == research_workflows.research_scope_plan()
    assert kwargs["input_manifest"] == research_workflows.build_research_scope_input(
        project,
        revision,
    )
