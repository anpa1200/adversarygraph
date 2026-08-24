from __future__ import annotations

import inspect
import uuid
from collections import deque
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy.dialects import postgresql

from app.models.research_workflow import (
    OutboxMessage,
    ProjectRevision,
    ResearchProject,
    StageAttempt,
    StageRun,
    WorkflowRun,
)
from app.services import outbox_runtime
from app.services import workflow_runtime as runtime
from app.services.research_projects import ResearchActor
from app.services.workflow_engine import checksum_json, normalize_stage_plan


NOW = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)
_REAL_OBJECT_SESSION = outbox_runtime.object_session
_REAL_SA_INSPECT = outbox_runtime.sa_inspect


class _UnitApp:
    def __init__(self) -> None:
        self.dependency_overrides = {}


@pytest.fixture
def app():
    """Keep global auth fixtures from importing the unrelated FastAPI surface."""

    return _UnitApp()


@pytest.fixture(autouse=True)
def _unit_outbox_authority(monkeypatch):
    """Model flushed ORM authority for the real root-emission primitives."""

    def object_session(value):
        unit_session = getattr(value, "_unit_sync_session", None)
        return unit_session if unit_session is not None else _REAL_OBJECT_SESSION(value)

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

    monkeypatch.setattr(outbox_runtime, "object_session", object_session)
    monkeypatch.setattr(outbox_runtime, "sa_inspect", sa_inspect)


def _definition(
    key: str = "collect",
    ordinal: int = 1,
    *,
    depends_on: list[str] | None = None,
    required: bool = True,
    max_attempts: int = 3,
) -> dict:
    return {
        "stage_key": key,
        "stage_type": f"{key}.worker",
        "stage_version": "1.0.0",
        "ordinal": ordinal,
        "depends_on": depends_on or [],
        "required": required,
        "priority": 5,
        "max_attempts": max_attempts,
        "config_schema_version": "research-stage-config-v1",
        "checkpoint_schema_version": "research-stage-checkpoint-v1",
        "config": {"enabled": True},
        "retry_policy": {
            "base_delay_seconds": 10,
            "max_delay_seconds": 60,
            "jitter_percent": 0,
        },
    }


def _actor() -> ResearchActor:
    return ResearchActor(name="Threat Intelligence Analyst", actor_id="analyst-1")


def _project(*, status: str = "active", tlp: str = "TLP:AMBER") -> ResearchProject:
    return ResearchProject(
        id=uuid.uuid4(),
        project_key="desert-hydra",
        name="Operation Desert Hydra",
        description="",
        status=status,
        domain="enterprise-attack",
        tlp=tlp,
        version=1,
        created_by="Analyst",
        created_by_id="analyst-1",
        updated_by="Analyst",
        updated_by_id="analyst-1",
        archive_reason="" if status == "active" else "Archived",
        archived_at=None if status == "active" else NOW,
    )


def _revision(project: ResearchProject, *, status: str = "current", tlp: str = "TLP:AMBER") -> ProjectRevision:
    return ProjectRevision(
        id=uuid.uuid4(),
        project_id=project.id,
        revision=1,
        parent_revision_id=None,
        status=status,
        schema_version="research-project-spec-v1",
        spec={"tlp": tlp},
        spec_checksum="a" * 64,
        change_summary="Initial scope",
        created_by="Analyst",
        created_by_id="analyst-1",
    )


def _workflow(
    *,
    status: str = "running",
    definitions: list[dict] | None = None,
    priority: int = 5,
) -> WorkflowRun:
    normalized = normalize_stage_plan(definitions or [_definition()])
    return WorkflowRun(
        id=uuid.uuid4(),
        project_revision_id=uuid.uuid4(),
        replay_of_run_id=None,
        workflow_type="cti.report",
        workflow_schema_version="research-workflow-v1",
        plan_schema_version="research-workflow-plan-v1",
        status=status,
        trigger_type="api",
        idempotency_key="b" * 64,
        correlation_id=uuid.uuid4(),
        input_manifest={"report_id": "report-1"},
        input_checksum=checksum_json({"report_id": "report-1"}),
        stage_plan=normalized.as_payload(),
        plan_checksum=normalized.checksum,
        priority=priority,
        state_version=1 if status == "queued" else 2,
        status_reason_code="",
        status_summary="",
        created_by="Analyst",
        created_by_id="analyst-1",
        cancel_requested_by="",
        cancel_requested_by_id="",
        cancel_reason="",
        cancel_requested_at=None,
        started_at=None if status == "queued" else NOW - timedelta(minutes=1),
        completed_at=None,
        created_at=NOW - timedelta(minutes=2),
        updated_at=NOW - timedelta(minutes=2),
    )


def _stage(
    workflow: WorkflowRun,
    *,
    key: str = "collect",
    ordinal: int = 1,
    depends_on: list[str] | None = None,
    required: bool = True,
    status: str = "running",
    attempt_count: int | None = None,
    max_attempts: int = 3,
    state_version: int = 2,
    token: uuid.UUID | None = None,
) -> StageRun:
    lease_token = token or uuid.uuid4()
    running = status == "running"
    has_attempt = attempt_count if attempt_count is not None else (1 if running or status == "retry_wait" else 0)
    terminal = status in {"succeeded", "degraded", "skipped", "failed", "cancelled", "dead_lettered"}
    output = {"ok": True} if status in {"succeeded", "degraded"} else {}
    error_code = "stage.failed" if status in {"retry_wait", "failed", "dead_lettered"} else ""
    return StageRun(
        id=uuid.uuid4(),
        workflow_run_id=workflow.id,
        stage_key=key,
        stage_type=f"{key}.worker",
        stage_version="1.0.0",
        ordinal=ordinal,
        status=status,
        priority=5,
        state_version=state_version,
        idempotency_key=checksum_json({"workflow": str(workflow.id), "stage": key}),
        depends_on=depends_on or [],
        required=required,
        config_schema_version="research-stage-config-v1",
        config={"enabled": True},
        config_checksum=checksum_json({"enabled": True}),
        input_manifest={"report_id": "report-1"},
        input_checksum=checksum_json({"report_id": "report-1"}),
        output_manifest=output,
        output_checksum=checksum_json(output) if output else "",
        checkpoint={},
        checkpoint_schema_version="research-stage-checkpoint-v1",
        checkpoint_version=0,
        checkpoint_checksum=checksum_json({}),
        attempt_count=has_attempt,
        max_attempts=max_attempts,
        next_attempt_at=NOW if status in {"ready", "retry_wait"} else None,
        lease_owner="worker-1" if running else "",
        lease_token=lease_token if running else None,
        leased_at=NOW - timedelta(seconds=30) if running else None,
        lease_expires_at=NOW + timedelta(seconds=30) if running else None,
        heartbeat_at=NOW - timedelta(seconds=30) if running else None,
        last_error_code=error_code,
        last_error_summary="failed" if error_code else "",
        last_error_retryable=status in {"retry_wait", "dead_lettered"},
        first_started_at=(NOW - timedelta(minutes=1)) if has_attempt else None,
        completed_at=NOW if terminal else None,
        created_at=NOW - timedelta(minutes=2),
        updated_at=NOW - timedelta(minutes=2),
    )


def _attempt(stage: StageRun, *, state_version: int = 1) -> StageAttempt:
    assert stage.lease_token is not None
    assert stage.leased_at is not None
    assert stage.heartbeat_at is not None
    assert stage.lease_expires_at is not None
    return StageAttempt(
        id=uuid.uuid4(),
        stage_run_id=stage.id,
        attempt_number=stage.attempt_count,
        lease_token=stage.lease_token,
        lease_owner=stage.lease_owner,
        delivery_id="delivery-1",
        status="running",
        state_version=state_version,
        input_checksum=stage.input_checksum,
        checkpoint_start_version=stage.checkpoint_version,
        checkpoint_end_version=stage.checkpoint_version,
        output_checksum="",
        error_code="",
        error_class="",
        error_summary="",
        retryable=False,
        started_at=stage.leased_at,
        heartbeat_at=stage.heartbeat_at,
        lease_expires_at=stage.lease_expires_at,
        completed_at=None,
    )


class _ScalarResult:
    def __init__(self, values):
        self._values = list(values)

    def all(self):
        return list(self._values)


class _Result:
    def __init__(self, values):
        self._values = list(values)

    def scalars(self):
        return _ScalarResult(self._values)


class _ScriptedDB:
    def __init__(self, *, scalars=(), executes=(), gets=None, fail_flush_type=None):
        scalar_values = tuple(scalars)
        execute_values = tuple(executes)
        self.scalar_values = deque(scalar_values)
        self.execute_values = deque(execute_values)
        self.gets = gets or {}
        self.scalar_statements = []
        self.execute_statements = []
        self.get_calls = []
        self.added = []
        self.flushes = []
        self.commit_calls = 0
        self.rollback_calls = 0
        self.events = []
        self.sync_session = self
        self.info = {}
        self.root_transaction = object()
        self.nested_transaction = None
        self.fail_flush_type = fail_flush_type
        for value in scalar_values:
            self._mark_persistent(value)
        for values in execute_values:
            for value in values:
                self._mark_persistent(value)
        for value in self.gets.values():
            self._mark_persistent(value)

    def get_transaction(self):
        return self.root_transaction

    def get_nested_transaction(self):
        return self.nested_transaction

    def in_nested_transaction(self):
        return self.nested_transaction is not None

    async def scalar(self, statement):
        self.scalar_statements.append(statement)
        self.events.append(("scalar", _compiled(statement)))
        assert self.scalar_values, f"Unexpected scalar query: {statement}"
        return self.scalar_values.popleft()

    async def get(self, model, key):
        self.get_calls.append((model, key))
        self.events.append(("get", model.__name__))
        return self.gets.get((model, key))

    async def execute(self, statement):
        self.execute_statements.append(statement)
        self.events.append(("execute", _compiled(statement)))
        assert self.execute_values, f"Unexpected execute query: {statement}"
        return _Result(self.execute_values.popleft())

    def add(self, value):
        self._mark_persistent(value)
        self.added.append(value)
        self.events.append(("add", type(value).__name__))

    def _mark_persistent(self, value):
        if type(value) not in {WorkflowRun, StageRun, StageAttempt, OutboxMessage}:
            return
        value._unit_sync_session = self.sync_session
        value._unit_persistent = True
        value._unit_modified = False
        value._unit_expired = False
        value._unit_expired_attributes = set()
        value._unit_unloaded = set()

    async def flush(self, objects=None):
        selected = list(objects or [])
        if self.fail_flush_type is not None and any(isinstance(value, self.fail_flush_type) for value in selected):
            self.events.append(("flush_error", self.fail_flush_type.__name__))
            raise RuntimeError("synthetic caller-transaction flush failure")
        self.flushes.append([_snapshot(value) for value in selected])
        self.events.append(("flush", tuple(type(value).__name__ for value in selected)))

    async def commit(self):  # pragma: no cover - a failure sentinel
        self.commit_calls += 1
        raise AssertionError("workflow runtime must never commit")

    async def rollback(self):  # pragma: no cover - a failure sentinel
        self.rollback_calls += 1
        raise AssertionError("workflow runtime leaves rollback to its caller")


def _snapshot(value) -> dict:
    snapshot = {
        "type": type(value).__name__,
        "status": getattr(value, "status", None),
        "state_version": getattr(value, "state_version", None),
    }
    for name in (
        "heartbeat_at",
        "lease_expires_at",
        "checkpoint_version",
        "checkpoint_end_version",
        "checkpoint_checksum",
        "completed_at",
    ):
        if hasattr(value, name):
            snapshot[name] = getattr(value, name)
    return snapshot


def _compiled(statement) -> str:
    return str(statement.compile(dialect=postgresql.dialect()))


@pytest.mark.asyncio
async def test_create_workflow_builds_content_addressed_dag_and_flushes_without_commit():
    project = _project()
    revision = _revision(project)
    plan = [
        _definition("collect", 1),
        _definition("review", 2, depends_on=["collect"]),
    ]
    db = _ScriptedDB(
        scalars=[project, revision, None, NOW, None],
        gets={(ProjectRevision, revision.id): revision},
    )

    workflow, created = await runtime.create_workflow(
        db,
        _actor(),
        project_revision_id=revision.id,
        workflow_type="cti.report",
        idempotency_token="request-123",
        input_manifest={"z": 2, "report_id": "report-1"},
        stage_plan=plan,
    )

    assert created is True
    stages = [value for value in db.added if isinstance(value, StageRun)]
    assert db.added[0] is workflow
    assert [stage.status for stage in stages] == ["ready", "pending"]
    assert stages[0].next_attempt_at == NOW
    assert stages[1].next_attempt_at is None
    assert stages[0].input_checksum == checksum_json({"report_id": "report-1", "z": 2})
    assert workflow.plan_checksum == normalize_stage_plan(plan).checksum
    assert len({workflow.idempotency_key, stages[0].idempotency_key, stages[1].idempotency_key}) == 3
    for statement in db.scalar_statements[:3]:
        options = statement.get_execution_options()
        assert options["populate_existing"] is True
        assert options["autoflush"] is False
        assert "FOR UPDATE" in _compiled(statement)
    assert db.commit_calls == 0
    assert [event[0]["type"] for event in db.flushes] == [
        "WorkflowRun",
        "StageRun",
        "OutboxMessage",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("token", ["request\nsecret", "\u20ac" * 342])
async def test_create_workflow_translates_unsafe_idempotency_tokens_before_sql(token):
    revision_id = uuid.uuid4()
    db = _ScriptedDB()

    with pytest.raises(runtime.WorkflowValidation, match="idempotency_token"):
        await runtime.create_workflow(
            db,
            _actor(),
            project_revision_id=revision_id,
            workflow_type="cti.report",
            idempotency_token=token,
            input_manifest={},
            stage_plan=[_definition()],
        )

    assert db.get_calls == []
    assert db.scalar_statements == []
    assert db.execute_statements == []
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid_field", ["workflow", "plan", "config", "checkpoint"])
async def test_create_workflow_rejects_noncurrent_schema_authority_before_sql(invalid_field):
    revision_id = uuid.uuid4()
    definition = _definition()
    kwargs = {}
    if invalid_field == "workflow":
        kwargs["workflow_schema_version"] = "research-workflow-v2"
    elif invalid_field == "plan":
        kwargs["plan_schema_version"] = "research-workflow-plan-v2"
    elif invalid_field == "config":
        definition["config_schema_version"] = "research-stage-config-v2"
    else:
        definition["checkpoint_schema_version"] = "research-stage-checkpoint-v2"
    db = _ScriptedDB()

    with pytest.raises(runtime.WorkflowValidation, match="exact current v1"):
        await runtime.create_workflow(
            db,
            _actor(),
            project_revision_id=revision_id,
            workflow_type="cti.report",
            idempotency_token="schema-rejected-before-sql",
            input_manifest={},
            stage_plan=[definition],
            **kwargs,
        )

    assert db.get_calls == []
    assert db.scalar_statements == []
    assert db.execute_statements == []
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
async def test_create_workflow_idempotency_is_content_aware_and_fail_closed(monkeypatch):
    project = _project()
    revision = _revision(project)
    plan = [_definition()]
    first_db = _ScriptedDB(
        scalars=[project, revision, None, NOW, None],
        gets={(ProjectRevision, revision.id): revision},
    )
    existing, _ = await runtime.create_workflow(
        first_db,
        _actor(),
        project_revision_id=revision.id,
        workflow_type="cti.report",
        idempotency_token="same-token",
        input_manifest={"report_id": "report-1"},
        stage_plan=plan,
    )

    def forbid_emission(*_args, **_kwargs):
        pytest.fail("Exact create replay must not reconstruct stage-ready authority")

    monkeypatch.setattr(runtime, "project_stage_ready_intent", forbid_emission)
    monkeypatch.setattr(runtime, "reserve_stage_ready_intents", forbid_emission)
    monkeypatch.setattr(runtime, "append_reserved_stage_ready", forbid_emission)

    replay_db = _ScriptedDB(
        scalars=[project, revision, existing],
        gets={(ProjectRevision, revision.id): revision},
    )
    replay, created = await runtime.create_workflow(
        replay_db,
        _actor(),
        project_revision_id=revision.id,
        workflow_type="cti.report",
        idempotency_token="same-token",
        input_manifest={"report_id": "report-1"},
        stage_plan=plan,
    )
    assert replay is existing
    assert created is False
    assert replay_db.added == []
    assert replay_db.flushes == []
    assert len(replay_db.scalar_statements) == 3

    collision_db = _ScriptedDB(
        scalars=[project, revision, existing],
        gets={(ProjectRevision, revision.id): revision},
    )
    with pytest.raises(runtime.WorkflowConflict, match="different workflow content"):
        await runtime.create_workflow(
            collision_db,
            _actor(),
            project_revision_id=revision.id,
            workflow_type="cti.report",
            idempotency_token="same-token",
            input_manifest={"report_id": "different"},
            stage_plan=plan,
        )


@pytest.mark.asyncio
async def test_create_workflow_emits_one_atomic_complete_root_fanout_after_stage_flush():
    project = _project()
    revision = _revision(project)
    plan = [
        _definition("collect", 1),
        _definition("enrich", 2),
        _definition("review", 3, depends_on=["collect", "enrich"]),
    ]
    db = _ScriptedDB(
        scalars=[project, revision, None, NOW, None, None],
        gets={(ProjectRevision, revision.id): revision},
    )

    workflow, created = await runtime.create_workflow(
        db,
        _actor(),
        project_revision_id=revision.id,
        workflow_type="cti.report",
        idempotency_token="multi-root-request",
        input_manifest={"report_id": "report-1"},
        stage_plan=plan,
    )

    assert created is True
    stages = [value for value in db.added if type(value) is StageRun]
    messages = [value for value in db.added if type(value) is OutboxMessage]
    roots = [stage for stage in stages if not stage.depends_on]
    assert [stage.stage_key for stage in stages] == ["collect", "enrich", "review"]
    assert len(messages) == len(roots) == 2
    assert {message.stage_run_id for message in messages} == {stage.id for stage in roots}
    assert all(message.workflow_run_id == workflow.id for message in messages)
    assert all(message.emission_kind == "root_ready" for message in messages)
    assert all(message.target_attempt_number == 1 for message in messages)
    assert len(db.flushes) == 3
    assert [tuple(row["type"] for row in flush) for flush in db.flushes] == [
        ("WorkflowRun",),
        ("StageRun", "StageRun", "StageRun"),
        ("OutboxMessage", "OutboxMessage"),
    ]

    stage_flush_index = db.events.index(("flush", ("StageRun", "StageRun", "StageRun")))
    message_select_indexes = [index for index, event in enumerate(db.events) if event[0] == "scalar" and "FROM outbox_messages" in event[1]]
    first_message_add = next(index for index, event in enumerate(db.events) if event == ("add", "OutboxMessage"))
    assert len(message_select_indexes) == 2
    assert stage_flush_index < min(message_select_indexes)
    assert max(message_select_indexes) < first_message_add
    assert db.events[-1] == ("flush", ("OutboxMessage", "OutboxMessage"))
    assert db.commit_calls == db.rollback_calls == 0


@pytest.mark.asyncio
async def test_create_workflow_rejects_hostile_partial_root_projection_without_message_side_effects(
    monkeypatch,
):
    project = _project()
    revision = _revision(project)
    plan = [_definition("collect", 1), _definition("enrich", 2)]
    db = _ScriptedDB(
        scalars=[project, revision, None, NOW],
        gets={(ProjectRevision, revision.id): revision},
    )
    real_project = runtime.project_stage_ready_intent
    first_intent = None

    def hostile_projection(*args, **kwargs):
        nonlocal first_intent
        projected = real_project(*args, **kwargs)
        if first_intent is None:
            first_intent = projected
            return projected
        return first_intent

    monkeypatch.setattr(runtime, "project_stage_ready_intent", hostile_projection)

    with pytest.raises(outbox_runtime.OutboxValidation, match="order disagrees"):
        await runtime.create_workflow(
            db,
            _actor(),
            project_revision_id=revision.id,
            workflow_type="cti.report",
            idempotency_token="hostile-partial-fanout",
            input_manifest={"report_id": "report-1"},
            stage_plan=plan,
        )

    assert [tuple(row["type"] for row in flush) for flush in db.flushes] == [
        ("WorkflowRun",),
        ("StageRun", "StageRun"),
    ]
    assert not any(type(value) is OutboxMessage for value in db.added)
    assert not any("FROM outbox_messages" in _compiled(statement) for statement in db.scalar_statements)
    assert db.commit_calls == db.rollback_calls == 0


@pytest.mark.asyncio
async def test_create_workflow_propagates_message_flush_failure_to_caller_transaction():
    project = _project()
    revision = _revision(project)
    db = _ScriptedDB(
        scalars=[project, revision, None, NOW, None],
        gets={(ProjectRevision, revision.id): revision},
        fail_flush_type=OutboxMessage,
    )

    with pytest.raises(RuntimeError, match="caller-transaction flush failure"):
        await runtime.create_workflow(
            db,
            _actor(),
            project_revision_id=revision.id,
            workflow_type="cti.report",
            idempotency_token="rollback-required",
            input_manifest={"report_id": "report-1"},
            stage_plan=[_definition()],
        )

    assert [tuple(row["type"] for row in flush) for flush in db.flushes] == [
        ("WorkflowRun",),
        ("StageRun",),
    ]
    assert any(type(value) is OutboxMessage for value in db.added)
    assert db.events[-1] == ("flush_error", "OutboxMessage")
    assert db.commit_calls == db.rollback_calls == 0


@pytest.mark.asyncio
async def test_replay_accepts_older_terminal_origin_from_same_project_revision_lineage():
    project = _project()
    source_revision = _revision(project, status="superseded")
    target_revision = _revision(project)
    target_revision.revision = 2
    target_revision.parent_revision_id = source_revision.id
    origin = _workflow(status="succeeded")
    origin.project_revision_id = source_revision.id
    origin.state_version = 3
    origin.completed_at = NOW - timedelta(seconds=30)
    plan = [_definition()]
    db = _ScriptedDB(
        scalars=[project, target_revision, origin, None, NOW, None],
        gets={
            (ProjectRevision, target_revision.id): target_revision,
            (ProjectRevision, source_revision.id): source_revision,
        },
    )

    replay, created = await runtime.create_workflow(
        db,
        _actor(),
        project_revision_id=target_revision.id,
        workflow_type="cti.report",
        idempotency_token="same-project-replay",
        input_manifest={"report_id": "report-1"},
        stage_plan=plan,
        trigger_type="replay",
        replay_of_run_id=origin.id,
    )

    assert created is True
    assert replay.project_revision_id == target_revision.id
    assert replay.replay_of_run_id == origin.id


@pytest.mark.asyncio
async def test_create_workflow_rejects_noncurrent_archived_and_tlp_red_authority():
    for project, revision, error in (
        (_project(status="archived"), None, runtime.WorkflowConflict),
        (_project(), None, runtime.WorkflowConflict),
        (_project(tlp="TLP:RED"), None, runtime.WorkflowAccessDenied),
    ):
        if revision is None:
            revision = _revision(
                project,
                status="superseded" if project.status == "active" and project.tlp != "TLP:RED" else "current",
            )
        db = _ScriptedDB(
            scalars=[project, revision],
            gets={(ProjectRevision, revision.id): revision},
        )
        with pytest.raises(error):
            await runtime.create_workflow(
                db,
                _actor(),
                project_revision_id=revision.id,
                workflow_type="cti.report",
                idempotency_token="request-123",
                input_manifest={},
                stage_plan=[_definition()],
            )


@pytest.mark.asyncio
async def test_direct_claim_is_hard_fenced_before_any_database_access():
    db = _ScriptedDB()

    with pytest.raises(runtime.WorkflowConflict, match="receipt_and_claim_stage"):
        await runtime.claim_stage(
            db,
            worker_id="worker-1",
            lease_seconds=120,
            delivery_id="delivery-99",
        )

    assert db.scalar_statements == []
    assert db.execute_statements == []
    assert db.get_calls == []
    assert db.added == []
    assert db.flushes == []
    assert db.commit_calls == 0
    source = inspect.getsource(runtime.claim_stage)
    assert ".scalar(" not in source
    assert ".execute(" not in source
    assert ".flush(" not in source


@pytest.mark.asyncio
async def test_direct_claim_fence_cannot_be_bypassed_with_legacy_arguments():
    db = _ScriptedDB()
    with pytest.raises(runtime.WorkflowConflict):
        await runtime.claim_stage(
            db,
            worker_id="",
            lease_seconds=0,
            delivery_id="legacy-unbound-delivery",
        )
    assert db.scalar_statements == []


@pytest.mark.asyncio
async def test_direct_heartbeat_is_hard_fenced_before_any_database_access():
    stage_id = uuid.uuid4()
    db = _ScriptedDB()

    with pytest.raises(runtime.WorkflowConflict, match="coordinate_stage_heartbeat"):
        await runtime.heartbeat_stage(
            db,
            stage_id,
            lease_token=uuid.uuid4(),
            expected_stage_version=2,
            expected_attempt_version=1,
            lease_seconds=120,
        )

    assert db.scalar_statements == []
    assert db.execute_statements == []
    assert db.get_calls == []
    assert db.added == []
    assert db.flushes == []
    assert db.commit_calls == 0
    source = inspect.getsource(runtime.heartbeat_stage)
    assert ".scalar(" not in source
    assert ".execute(" not in source
    assert ".flush(" not in source


@pytest.mark.asyncio
async def test_direct_heartbeat_fence_cannot_be_bypassed_with_legacy_arguments():
    db = _ScriptedDB()
    with pytest.raises(runtime.WorkflowConflict, match="coordinate_stage_heartbeat"):
        await runtime.heartbeat_stage(
            db,
            uuid.uuid4(),
            lease_token=uuid.uuid4(),
            expected_stage_version=-1,
            expected_attempt_version=0,
            lease_seconds=0,
        )
    assert db.scalar_statements == []
    assert db.execute_statements == []
    assert db.get_calls == []
    assert db.added == []
    assert db.flushes == []


@pytest.mark.asyncio
async def test_direct_checkpoint_is_hard_fenced_before_any_database_access():
    db = _ScriptedDB()

    with pytest.raises(runtime.WorkflowConflict, match="coordinate_stage_checkpoint"):
        await runtime.checkpoint_stage(
            db,
            uuid.uuid4(),
            lease_token=uuid.uuid4(),
            expected_stage_version=2,
            expected_attempt_version=1,
            expected_checkpoint_version=0,
            checkpoint_schema_version="research-stage-checkpoint-v1",
            checkpoint={"cursor": 7, "pages": [1, 2]},
            lease_seconds=120,
        )

    assert db.scalar_statements == []
    assert db.execute_statements == []
    assert db.get_calls == []
    assert db.added == []
    assert db.flushes == []
    assert db.commit_calls == 0
    source = inspect.getsource(runtime.checkpoint_stage)
    assert ".scalar(" not in source
    assert ".execute(" not in source
    assert ".flush(" not in source


@pytest.mark.asyncio
async def test_direct_checkpoint_fence_cannot_be_bypassed_with_legacy_arguments():
    db = _ScriptedDB()
    with pytest.raises(runtime.WorkflowConflict, match="coordinate_stage_checkpoint"):
        await runtime.checkpoint_stage(
            db,
            uuid.uuid4(),
            lease_token=uuid.uuid4(),
            expected_stage_version=-1,
            expected_attempt_version=0,
            expected_checkpoint_version=-1,
            checkpoint_schema_version="",
            checkpoint={"unsupported": object()},
            lease_seconds=0,
        )
    assert db.scalar_statements == []
    assert db.execute_statements == []
    assert db.get_calls == []
    assert db.added == []
    assert db.flushes == []
    assert db.commit_calls == 0


@pytest.mark.asyncio
async def test_direct_completion_is_fenced_before_sql_and_mutation():
    # Receipt-unbound completion coverage moved with the authority boundary:
    # - A -> changed-S -> M -> optional-W ordering, exact row diffs, zero/multi
    #   fan-out, rollback, context failure, and output validation now live in
    #   test_workflow_worker's coordinate_stage_complete cases.
    # - complete-plan locking, last-prerequisite eligibility, stale W/S/M/D/A
    #   fencing, collision/expiry/chronology, and transferred append authority
    #   live in test_outbox_runtime's completion-graph cases and exact-0003 PG.
    # - Outbox non-lease errors propagate from the coordinator; only receipt
    #   reserve/consume OutboxLeaseLost becomes a post-rollback stale ACK.
    db = _ScriptedDB()
    with pytest.raises(runtime.WorkflowConflict, match="coordinate_stage_complete"):
        await runtime.complete_stage(
            db,
            uuid.uuid4(),
            lease_token=uuid.uuid4(),
            expected_stage_version=1,
            expected_attempt_version=1,
            expected_checkpoint_version=0,
            output_manifest={"claims": 1},
        )
    assert db.scalar_statements == []
    assert db.execute_statements == []
    assert db.get_calls == []
    assert db.added == []
    assert db.flushes == []
    assert db.commit_calls == 0
    source = inspect.getsource(runtime.complete_stage)
    assert ".scalar(" not in source
    assert ".execute(" not in source
    assert ".flush(" not in source
    assert not any(name.startswith("_legacy_completion") for name in globals())
    module_source = inspect.getsource(runtime)
    for dead_name in (
        "_PrelockedCompletionGraph",
        "_lock_completion_graph",
        "_dependency_targets_for_completion",
        "_aggregate_prelocked_completion",
    ):
        assert not hasattr(runtime, dead_name)
        assert dead_name not in module_source


@pytest.mark.asyncio
async def test_direct_completion_fence_cannot_be_bypassed_with_hostile_legacy_arguments():
    db = _ScriptedDB()
    with pytest.raises(runtime.WorkflowConflict, match="coordinate_stage_complete"):
        await runtime.complete_stage(
            db,
            object(),
            lease_token=object(),
            expected_stage_version=True,
            expected_attempt_version=0,
            expected_checkpoint_version=-1,
            output_manifest={"unsupported": object()},
            outcome="failed",
        )
    assert db.scalar_statements == []
    assert db.execute_statements == []
    assert db.get_calls == []
    assert db.added == []
    assert db.flushes == []
    assert db.commit_calls == 0


# Receipt-bound failure invariant coverage after retiring the direct writer:
# - retry/backoff and retry-root authority: outbox
#   test_failure_retry_reserves_consumes_and_transfers_exact_stage_ready_child
#   plus worker test_failure_records_exact_branch_and_flush_order_after_receipt_consumption;
# - optional/required settlement and dead-letter closure: outbox optional/required
#   terminal graph tests plus the worker branch matrix;
# - sanitizer/error fixed point: outbox test_stage_failure_evidence_is_exact_sanitizer_fixed_point
#   plus worker pre-factory rejection and redaction tests;
# - rollback/no-ACK and stale receipt handling: worker late-error and receipt-loss tests;
# - token/version/single-use authority: Phase-A failure capability tests and real-PG acceptance.
@pytest.mark.asyncio
async def test_direct_failure_is_fenced_before_database_access():
    workflow = _workflow()
    stage = _stage(workflow)
    attempt = _attempt(stage)
    db = _ScriptedDB()

    with pytest.raises(runtime.WorkflowConflict, match="coordinate_stage_fail"):
        await runtime.fail_stage(
            db,
            stage.id,
            lease_token=stage.lease_token,
            expected_stage_version=stage.state_version,
            expected_attempt_version=attempt.state_version,
            expected_checkpoint_version=stage.checkpoint_version,
            error="upstream timeout",
            error_code="source.timeout",
            retryable=True,
        )

    assert db.scalar_statements == []
    assert db.execute_statements == []
    assert db.get_calls == []
    assert db.added == []
    assert db.flushes == []
    assert db.commit_calls == db.rollback_calls == 0
    source = inspect.getsource(runtime.fail_stage)
    assert ".scalar(" not in source
    assert ".execute(" not in source
    assert ".flush(" not in source
    module_source = inspect.getsource(runtime)
    for dead_name in ("_PrelockedFailureGraph", "_lock_failure_graph"):
        assert not hasattr(runtime, dead_name)
        assert dead_name not in module_source


@pytest.mark.asyncio
async def test_direct_failure_fence_cannot_be_bypassed_with_hostile_legacy_arguments():
    db = _ScriptedDB()
    with pytest.raises(runtime.WorkflowConflict, match="coordinate_stage_fail"):
        await runtime.fail_stage(
            db,
            object(),
            lease_token=object(),
            expected_stage_version=True,
            expected_attempt_version=0,
            expected_checkpoint_version=-1,
            error=object(),
            error_code=object(),
            retryable=1,
        )
    assert db.scalar_statements == []
    assert db.execute_statements == []
    assert db.get_calls == []
    assert db.added == []
    assert db.flushes == []
    assert db.commit_calls == db.rollback_calls == 0


# The retired mutation specs below are covered at their new authority boundaries:
# W/S/M/D/A lock order, receipt lineage, expiry/retry/exhaustion, child transfer,
# rollback, and one-slot selection live in outbox_runtime + workflow_worker tests.
@pytest.mark.asyncio
async def test_direct_recovery_entrypoints_are_pre_sql_fences_and_dead_helpers_are_removed():
    db = _ScriptedDB()

    with pytest.raises(runtime.WorkflowConflict, match="coordinate_one_expired_stage_recovery"):
        await runtime.recover_one_expired_stage(db)
    with pytest.raises(runtime.WorkflowConflict, match="coordinate_expired_stage_recovery_pass"):
        await runtime.recover_expired_stages(db, limit=object())

    assert db.scalar_statements == []
    assert db.execute_statements == []
    assert db.get_calls == []
    assert db.added == []
    assert db.flushes == []
    source = inspect.getsource(runtime)
    for dead_name in (
        "_begin_single_recovery_transaction",
        "_bind_single_recovery_transaction",
        "_lock_live_attempt",
        "_settle_workflow",
        "_terminalize_running_attempt_for_cancel",
        "_cancel_stage",
        "_stage_definition",
    ):
        assert not hasattr(runtime, dead_name)
        assert dead_name not in source


@pytest.mark.asyncio
async def test_direct_cancel_entrypoint_is_a_pre_sql_fence_for_hostile_arguments():
    db = _ScriptedDB()

    with pytest.raises(runtime.WorkflowConflict, match="coordinate_workflow_cancel"):
        await runtime.cancel_workflow(
            db,
            object(),
            object(),
            expected_state_version=True,
            reason=object(),
        )

    assert db.scalar_statements == []
    assert db.execute_statements == []
    assert db.get_calls == []
    assert db.added == []
    assert db.flushes == []
    cancel_source = inspect.getsource(runtime.cancel_workflow)
    assert ".scalar(" not in cancel_source
    assert ".execute(" not in cancel_source
    assert ".flush(" not in cancel_source


def test_runtime_has_no_commit_or_application_clock_escape_hatch():
    source = inspect.getsource(runtime)
    assert ".commit(" not in source
    assert "datetime.now(" not in source
    assert "datetime.utcnow(" not in source
    assert "time.time(" not in source
    assert "transaction_timestamp" in source
