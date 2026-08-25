from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi import FastAPI, HTTPException
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError

from app.api.routes import research as route
from app.models.research_workflow import ProjectRevision, ResearchProject, StageRun, WorkflowRun
from app.services import research_projects as projects
from app.services.auth import TeamUser


def _spec():
    return projects.ResearchProjectSpec.model_validate(
        {
            "objective": "Build an evidence-backed MuddyWater detection program.",
            "intelligence_requirements": ["Which concrete procedures are supported by primary sources?"],
            "output_targets": ["detections", "rag"],
            "tlp": "TLP:AMBER",
        }
    )


def _records():
    now = datetime.now(timezone.utc)
    project = ResearchProject(
        id=uuid4(),
        project_key="desert-hydra",
        name="Operation Desert Hydra",
        description="MuddyWater research program.",
        status="active",
        domain="enterprise-attack",
        tlp="TLP:AMBER",
        version=1,
        created_by="Analyst",
        created_by_id="analyst-1",
        updated_by="Analyst",
        updated_by_id="analyst-1",
        archive_reason="",
        archived_at=None,
        created_at=now,
        updated_at=now,
    )
    payload, checksum = projects.normalize_project_spec(_spec())
    revision = ProjectRevision(
        id=uuid4(),
        project_id=project.id,
        revision=1,
        parent_revision_id=None,
        status="current",
        schema_version="research-project-spec-v1",
        spec=payload,
        spec_checksum=checksum,
        change_summary="Initial scope",
        created_by="Analyst",
        created_by_id="analyst-1",
        revoked_by="",
        revoked_by_id="",
        revoked_at=None,
        created_at=now,
    )
    return project, revision


def _user():
    return TeamUser(
        name="Threat Intelligence Analyst",
        roles=["threat_intel"],
        user_id="analyst-1",
        auth_source="local",
    )


def _workflow_records(project: ResearchProject, revision: ProjectRevision):
    now = datetime.now(timezone.utc)
    workflow = WorkflowRun(
        id=uuid4(),
        project_revision_id=revision.id,
        replay_of_run_id=None,
        workflow_type="cti.research.scope",
        workflow_schema_version="research-workflow-v1",
        plan_schema_version="research-workflow-plan-v1",
        status="queued",
        trigger_type="api",
        idempotency_key="a" * 64,
        correlation_id=uuid4(),
        input_manifest={},
        input_checksum="b" * 64,
        stage_plan=[{"stage_key": "scope"}],
        plan_checksum="c" * 64,
        priority=5,
        state_version=1,
        status_reason_code="",
        status_summary="",
        created_by="Threat Intelligence Analyst",
        created_by_id="analyst-1",
        cancel_requested_by="",
        cancel_requested_by_id="",
        cancel_reason="",
        cancel_request_id=None,
        cancel_requested_at=None,
        started_at=None,
        completed_at=None,
        created_at=now,
        updated_at=now,
    )
    stage = StageRun(
        id=uuid4(),
        workflow_run_id=workflow.id,
        stage_key="scope",
        stage_type="research.project.scope",
        stage_version="1",
        ordinal=1,
        status="ready",
        priority=5,
        state_version=1,
        idempotency_key="d" * 64,
        depends_on=[],
        required=True,
        config_schema_version="research-scope-config-v1",
        config={},
        config_checksum="e" * 64,
        input_manifest={},
        input_checksum="f" * 64,
        output_manifest={},
        output_checksum="",
        checkpoint={},
        checkpoint_schema_version="stage-checkpoint-v1",
        checkpoint_version=0,
        checkpoint_checksum="0" * 64,
        attempt_count=0,
        max_attempts=3,
        next_attempt_at=now,
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
        created_at=now,
        updated_at=now,
    )
    return workflow, stage


class _DB:
    def __init__(self):
        self.commits = 0
        self.rollbacks = 0

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        self.rollbacks += 1


@pytest.mark.asyncio
async def test_create_route_audits_and_commits_one_authority_transaction(
    monkeypatch,
):
    db = _DB()
    project, revision = _records()
    events = []

    async def create(*_args, **_kwargs):
        return project, revision

    async def audit(*_args, **_kwargs):
        events.append((_args[2], _args[3], _args[4], _args[5]))

    monkeypatch.setattr(route.projects, "create_project", create)
    monkeypatch.setattr(route, "audit", audit)

    value = await route.create_research_project(
        route.ProjectCreateBody(
            project_key="Desert-Hydra",
            name="Operation Desert Hydra",
            description="MuddyWater research program.",
            spec=_spec(),
        ),
        db,
        _user(),
    )

    assert value.id == project.id
    assert value.current_revision.spec_checksum == revision.spec_checksum
    assert db.commits == 1
    assert db.rollbacks == 0
    assert events == [
        (
            "research_project.create",
            "research_project",
            str(project.id),
            {
                "project_key": "desert-hydra",
                "revision": 1,
                "spec_checksum": revision.spec_checksum,
            },
        )
    ]


@pytest.mark.asyncio
async def test_route_maps_stale_project_version_to_bounded_conflict(monkeypatch):
    db = _DB()

    async def revise(*_args, **_kwargs):
        raise projects.ResearchProjectConflict("Project version conflict: expected 2, current 3")

    monkeypatch.setattr(route.projects, "create_revision", revise)

    with pytest.raises(HTTPException) as exc_info:
        await route.create_project_revision(
            uuid4(),
            route.ProjectRevisionBody(
                expected_version=2,
                spec=_spec(),
                change_summary="Add a source policy.",
            ),
            db,
            _user(),
        )

    assert exc_info.value.status_code == 409
    assert exc_info.value.detail == "Project version conflict: expected 2, current 3"
    assert db.rollbacks == 1
    assert db.commits == 0


@pytest.mark.asyncio
async def test_start_workflow_route_audits_and_commits_created_or_replayed_authority(
    monkeypatch,
):
    db = _DB()
    project, revision = _records()
    workflow, _ = _workflow_records(project, revision)
    events = []

    async def create(*_args, **_kwargs):
        assert _kwargs == {
            "project_id": project.id,
            "idempotency_token": "request-17",
            "priority": 7,
        }
        return workflow, False

    async def audit(*_args, **_kwargs):
        events.append((_args[2], _args[3], _args[4], _args[5]))

    monkeypatch.setattr(route.research_workflows, "create_research_scope_workflow", create)
    monkeypatch.setattr(route, "audit", audit)

    value = await route.start_research_workflow(
        project.id,
        route.WorkflowStartBody(idempotency_token="request-17", priority=7),
        db,
        _user(),
    )

    assert value.created is False
    assert value.workflow.id == workflow.id
    assert db.commits == 1
    assert db.rollbacks == 0
    assert events == [
        (
            "research_workflow.replay",
            "workflow_run",
            str(workflow.id),
            {
                "project_id": str(project.id),
                "project_revision_id": str(revision.id),
                "workflow_type": "cti.research.scope",
                "created": False,
            },
        )
    ]


@pytest.mark.asyncio
async def test_workflow_list_and_detail_routes_return_detached_status(monkeypatch):
    db = _DB()
    project, revision = _records()
    workflow, stage = _workflow_records(project, revision)

    async def list_workflows(*_args, **_kwargs):
        assert _kwargs == {"project_id": project.id, "limit": 25, "offset": 5}
        return 1, (workflow,)

    async def get_workflow(*_args, **_kwargs):
        assert _kwargs == {
            "project_id": project.id,
            "workflow_run_id": workflow.id,
        }
        return workflow, (stage,)

    monkeypatch.setattr(route.research_workflows, "list_research_workflows", list_workflows)
    monkeypatch.setattr(route.research_workflows, "get_research_workflow", get_workflow)

    listed = await route.list_project_workflows(project.id, 25, 5, db, _user())
    detail = await route.get_project_workflow(project.id, workflow.id, db, _user())

    assert listed.total == 1
    assert [item.id for item in listed.items] == [workflow.id]
    assert detail.workflow.id == workflow.id
    assert [(item.stage_key, item.status) for item in detail.stages] == [("scope", "ready")]
    assert db.commits == 0
    assert db.rollbacks == 0


@pytest.mark.asyncio
async def test_cancel_workflow_route_binds_project_then_audits_commit_confirmed_result(
    monkeypatch,
):
    db = _DB()
    project, revision = _records()
    workflow, stage = _workflow_records(project, revision)
    request_id = uuid4()
    cancelled_at = datetime.now(timezone.utc)
    calls = []
    events = []

    async def get_workflow(*_args, **kwargs):
        assert kwargs == {
            "project_id": project.id,
            "workflow_run_id": workflow.id,
        }
        calls.append("project-bound")
        return workflow, (stage,)

    async def cancel(session_factory, *, command):
        assert session_factory is route.async_session_factory
        assert calls == ["project-bound"]
        assert command.request_id == request_id
        assert command.workflow_run_id == workflow.id
        assert command.expected_workflow_state_version == 1
        assert (command.actor, command.actor_id) == (
            "Threat Intelligence Analyst",
            "analyst-1",
        )
        assert command.reason == "Scope superseded by reviewed intelligence"
        return route.workflow_worker.CoordinatedWorkflowCancellation(
            request_id=request_id,
            workflow_run_id=workflow.id,
            actor=command.actor,
            actor_id=command.actor_id,
            reason=command.reason,
            previous_workflow_state_version=1,
            workflow_state_version=2,
            cancelled_at=cancelled_at,
            cancelled_stage_ids=(stage.id,),
            cancelled_attempt_ids=(),
            cancelled_message_ids=(),
            cancelled_delivery_ids=(),
            disposition="applied",
            should_apply=True,
        )

    async def audit(*args, **_kwargs):
        events.append((args[2], args[3], args[4], args[5]))

    monkeypatch.setattr(route.research_workflows, "get_research_workflow", get_workflow)
    monkeypatch.setattr(route.workflow_worker, "coordinate_workflow_cancel", cancel)
    monkeypatch.setattr(route, "audit", audit)

    result = await route.cancel_project_workflow(
        project.id,
        workflow.id,
        route.WorkflowCancelBody(
            request_id=request_id,
            expected_workflow_state_version=1,
            reason="Scope superseded by reviewed intelligence",
        ),
        db,
        _user(),
    )

    assert result.workflow_run_id == workflow.id
    assert result.disposition == "applied"
    assert result.cancelled_stage_ids == (stage.id,)
    assert db.commits == 1
    assert db.rollbacks == 0
    assert events == [
        (
            "research_workflow.cancel",
            "workflow_run",
            str(workflow.id),
            {
                "project_id": str(project.id),
                "request_id": str(request_id),
                "disposition": "applied",
                "workflow_state_version": 2,
            },
        )
    ]


@pytest.mark.asyncio
async def test_cancel_workflow_route_never_calls_coordinator_outside_project_scope(monkeypatch):
    db = _DB()
    project_id = uuid4()
    workflow_id = uuid4()

    async def get_workflow(*_args, **_kwargs):
        raise route.research_workflows.ResearchWorkflowNotFound("Research workflow not found")

    async def unexpected_cancel(*_args, **_kwargs):  # pragma: no cover - safety assertion
        raise AssertionError("Cancellation coordinator must not receive unscoped authority")

    monkeypatch.setattr(route.research_workflows, "get_research_workflow", get_workflow)
    monkeypatch.setattr(route.workflow_worker, "coordinate_workflow_cancel", unexpected_cancel)

    with pytest.raises(HTTPException) as exc_info:
        await route.cancel_project_workflow(
            project_id,
            workflow_id,
            route.WorkflowCancelBody(
                request_id=uuid4(),
                expected_workflow_state_version=1,
                reason="Project-bound workflow is not visible",
            ),
            db,
            _user(),
        )

    assert exc_info.value.status_code == 404
    assert db.rollbacks == 1
    assert db.commits == 0


@pytest.mark.asyncio
async def test_cancel_workflow_route_maps_authority_conflict_without_audit(monkeypatch):
    db = _DB()
    project, revision = _records()
    workflow, stage = _workflow_records(project, revision)

    async def get_workflow(*_args, **_kwargs):
        return workflow, (stage,)

    async def cancel(*_args, **_kwargs):
        raise route.outbox_runtime.OutboxConflict("Workflow cancellation authority is stale")

    async def unexpected_audit(*_args, **_kwargs):  # pragma: no cover - safety assertion
        raise AssertionError("Failed cancellation must not be audited as committed")

    monkeypatch.setattr(route.research_workflows, "get_research_workflow", get_workflow)
    monkeypatch.setattr(route.workflow_worker, "coordinate_workflow_cancel", cancel)
    monkeypatch.setattr(route, "audit", unexpected_audit)

    with pytest.raises(HTTPException) as exc_info:
        await route.cancel_project_workflow(
            project.id,
            workflow.id,
            route.WorkflowCancelBody(
                request_id=uuid4(),
                expected_workflow_state_version=1,
                reason="Scope superseded by reviewed intelligence",
            ),
            db,
            _user(),
        )

    assert exc_info.value.status_code == 409
    assert db.rollbacks == 1
    assert db.commits == 0


def test_cancel_workflow_result_is_reconstructed_before_it_can_authorize_audit():
    result = route.workflow_worker.CoordinatedWorkflowCancellation(
        request_id=uuid4(),
        workflow_run_id=uuid4(),
        actor="Threat Intelligence Analyst",
        actor_id="analyst-1",
        reason="Scope superseded by reviewed intelligence",
        previous_workflow_state_version=1,
        workflow_state_version=2,
        cancelled_at=datetime.now(timezone.utc),
        cancelled_stage_ids=(uuid4(),),
        cancelled_attempt_ids=(),
        cancelled_message_ids=(),
        cancelled_delivery_ids=(),
        disposition="applied",
        should_apply=True,
    )
    object.__setattr__(result, "disposition", "forged")

    with pytest.raises(route.outbox_runtime.OutboxStoredContractError, match="fixed point"):
        route._fixed_cancellation_result(result)


def test_project_requests_forbid_unknown_fields_and_empty_patch():
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        route.ProjectCreateBody.model_validate(
            {
                "project_key": "desert-hydra",
                "name": "Operation Desert Hydra",
                "spec": _spec().model_dump(mode="json"),
                "unreviewed_truth": True,
            }
        )
    with pytest.raises(ValidationError, match="At least one project metadata"):
        route.ProjectMetadataBody(expected_version=1)


def test_research_router_has_no_destructive_endpoint_and_complete_contracts():
    operations = [
        (method, api_route.path, api_route.summary, api_route.response_model)
        for api_route in route.router.routes
        for method in api_route.methods
    ]

    assert all(method != "DELETE" for method, *_ in operations)
    assert all(summary for _, _, summary, _ in operations)
    assert all(response_model is not None for _, _, _, response_model in operations)
    assert ("POST", "/research/projects", "Create a research project and revision one", route.ProjectOut) in operations


def test_research_router_openapi_has_bounded_success_schemas():
    app = FastAPI(
        openapi_tags=[
            {
                "name": "Research Projects",
                "description": "Revisioned CTI research authority.",
            }
        ]
    )
    app.include_router(route.router, prefix="/api")

    schema = app.openapi()
    research_paths = {path: item for path, item in schema["paths"].items() if path.startswith("/api/research/projects")}

    assert len(research_paths) == 8
    for path, path_item in research_paths.items():
        for method, operation in path_item.items():
            if method not in {"get", "post", "patch"}:
                continue
            assert operation["tags"] == ["Research Projects"]
            assert operation["summary"]
            success = [response for code, response in operation["responses"].items() if code.startswith("2")]
            assert success, f"{method.upper()} {path} has no success response"
            assert all(response.get("content") for response in success)


class _Diagnostic:
    def __init__(self, constraint_name: str):
        self.constraint_name = constraint_name


class _DatabaseError(Exception):
    def __init__(self, sqlstate: str, constraint_name: str):
        super().__init__("database error")
        self.sqlstate = sqlstate
        self.diag = _Diagnostic(constraint_name)


@pytest.mark.asyncio
async def test_only_expected_unique_integrity_errors_are_mapped_to_conflict():
    db = _DB()
    expected = IntegrityError(
        "insert",
        {},
        _DatabaseError("23505", "uq_research_project_key"),
    )

    with pytest.raises(HTTPException) as exc_info:
        await route._raise_integrity_conflict(db, expected)

    assert exc_info.value.status_code == 409
    assert db.rollbacks == 1


@pytest.mark.asyncio
async def test_unexpected_integrity_errors_remain_server_visible():
    db = _DB()
    unexpected = IntegrityError(
        "insert",
        {},
        _DatabaseError("23514", "ck_project_revision_immutable"),
    )

    with pytest.raises(IntegrityError) as exc_info:
        await route._raise_integrity_conflict(db, unexpected)

    assert exc_info.value is unexpected
    assert db.rollbacks == 1


def test_revision_output_rejects_unknown_persisted_schema():
    _, revision = _records()
    revision.schema_version = "research-project-spec-v99"

    with pytest.raises(projects.ResearchProjectStoredContractError, match="v99"):
        route._revision_out(revision)
