"""Real-PostgreSQL workflow authority and transition constraints.

Run only against a disposable database. Authority rows deliberately remain in
that database because the production guards reject physical deletion.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from app.core.database import async_session_factory, engine
from app.models.research_workflow import (
    ProjectRevision,
    ResearchProject,
    StageAttempt,
    StageRun,
    WorkflowRun,
)
from app.services import research_projects as projects


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_POSTGRES_TESTS") != "1",
    reason="requires an explicitly authorized disposable PostgreSQL database",
)

EMPTY_OBJECT_CHECKSUM = hashlib.sha256(b"{}").hexdigest()
EMPTY_LIST_CHECKSUM = hashlib.sha256(b"[]").hexdigest()


@pytest_asyncio.fixture
async def _require_pre_receipt_workflow_revision():
    await engine.dispose()
    async with engine.connect() as connection:
        schema_revision = await connection.scalar(
            text("SELECT version_num FROM alembic_version"),
        )
    if schema_revision != "20260823_0002":
        pytest.skip(
            "raw W/S/A protocol fixtures require exact revision 0002; revision 0004 requires delivered receipt authority",
        )
    try:
        yield
    finally:
        await engine.dispose()


def _spec(*, objective: str = "Validate durable workflow authority constraints.") -> dict:
    return {
        "objective": objective,
        "intelligence_requirements": ["Which impossible workflow states does PostgreSQL reject?"],
        "output_targets": ["canonical_intelligence"],
        "tlp": "TLP:AMBER",
    }


def _workflow(
    revision_id,
    *,
    workflow_type: str = "cti.report",
    trigger_type: str = "api",
    replay_of_run_id=None,
) -> WorkflowRun:
    return WorkflowRun(
        project_revision_id=revision_id,
        replay_of_run_id=replay_of_run_id,
        workflow_type=workflow_type,
        status="queued",
        trigger_type=trigger_type,
        idempotency_key=uuid4().hex + uuid4().hex,
        correlation_id=uuid4(),
        input_manifest={},
        input_checksum=EMPTY_OBJECT_CHECKSUM,
        stage_plan=[],
        plan_checksum=EMPTY_LIST_CHECKSUM,
        priority=5,
        state_version=1,
        created_by="PostgreSQL Workflow Test",
        created_by_id="postgres-workflow-test",
    )


def _ready_stage(workflow_id, *, stage_key: str = "collect") -> StageRun:
    return StageRun(
        workflow_run_id=workflow_id,
        stage_key=stage_key,
        stage_type="deterministic.test",
        stage_version="v1",
        ordinal=1,
        status="ready",
        priority=5,
        state_version=1,
        idempotency_key=uuid4().hex + uuid4().hex,
        depends_on=[],
        required=True,
        config={},
        config_checksum=EMPTY_OBJECT_CHECKSUM,
        input_manifest={},
        input_checksum=EMPTY_OBJECT_CHECKSUM,
        output_manifest={},
        output_checksum="",
        checkpoint={},
        checkpoint_version=0,
        checkpoint_checksum=EMPTY_OBJECT_CHECKSUM,
        attempt_count=0,
        max_attempts=3,
        next_attempt_at=datetime.now(timezone.utc),
    )


async def _create_project(db, *, label: str):
    actor = projects.ResearchActor("PostgreSQL Workflow Test", "postgres-workflow-test")
    project, revision = await projects.create_project(
        db,
        actor,
        project_key=f"{label}-{uuid4().hex[:12]}",
        name=f"{label} Project",
        description="Disposable PostgreSQL authority test.",
        spec=_spec(),
    )
    await db.commit()
    return project, revision


async def _start_workflow(db, workflow_id):
    workflow = await db.get(WorkflowRun, workflow_id)
    workflow.status = "running"
    workflow.state_version += 1
    workflow.started_at = datetime.now(timezone.utc)
    await db.commit()
    return workflow


async def _claim_stage(db, stage_id):
    stage = await db.get(StageRun, stage_id)
    now = datetime.now(timezone.utc)
    lease_token = uuid4()
    stage.status = "running"
    stage.state_version += 1
    stage.attempt_count += 1
    stage.first_started_at = now
    stage.next_attempt_at = None
    stage.lease_owner = "worker-a"
    stage.lease_token = lease_token
    stage.leased_at = now
    stage.heartbeat_at = now
    stage.lease_expires_at = now + timedelta(minutes=5)
    await db.flush()
    attempt = StageAttempt(
        stage_run_id=stage.id,
        attempt_number=stage.attempt_count,
        lease_token=lease_token,
        lease_owner=stage.lease_owner,
        delivery_id=f"delivery-{uuid4().hex}",
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
        started_at=stage.leased_at,
        heartbeat_at=stage.heartbeat_at,
        lease_expires_at=stage.lease_expires_at,
    )
    db.add(attempt)
    await db.commit()
    return stage, attempt


async def _heartbeat_stage(db, stage_id):
    stage = await db.get(StageRun, stage_id)
    attempt = await db.scalar(
        select(StageAttempt).where(
            StageAttempt.stage_run_id == stage.id,
            StageAttempt.status == "running",
        )
    )
    now = max(datetime.now(timezone.utc), stage.heartbeat_at + timedelta(microseconds=1))
    expires = max(stage.lease_expires_at, now + timedelta(minutes=5))
    stage.state_version += 1
    stage.heartbeat_at = now
    stage.lease_expires_at = expires
    await db.flush([stage])
    attempt.state_version += 1
    attempt.heartbeat_at = now
    attempt.lease_expires_at = expires
    await db.commit()
    return stage, attempt


async def _succeed_stage(db, stage_id):
    stage = await db.get(StageRun, stage_id)
    attempt = await db.scalar(
        select(StageAttempt).where(
            StageAttempt.stage_run_id == stage.id,
            StageAttempt.status == "running",
        )
    )
    completed_at = max(datetime.now(timezone.utc), attempt.heartbeat_at + timedelta(microseconds=1))
    attempt.status = "succeeded"
    attempt.state_version += 1
    attempt.output_checksum = EMPTY_OBJECT_CHECKSUM
    attempt.completed_at = completed_at
    await db.flush([attempt])

    stage.status = "succeeded"
    stage.state_version += 1
    stage.output_manifest = {}
    stage.output_checksum = EMPTY_OBJECT_CHECKSUM
    stage.completed_at = completed_at
    stage.lease_owner = ""
    stage.lease_token = None
    stage.leased_at = None
    stage.heartbeat_at = None
    stage.lease_expires_at = None
    await db.commit()
    return stage, attempt


async def _succeed_workflow(db, workflow_id):
    workflow = await db.get(WorkflowRun, workflow_id)
    workflow.status = "succeeded"
    workflow.state_version += 1
    workflow.completed_at = max(datetime.now(timezone.utc), workflow.started_at + timedelta(microseconds=1))
    await db.commit()
    return workflow


async def _create_valid_running_protocol(*, label: str):
    async with async_session_factory() as db:
        project, revision = await _create_project(db, label=label)
        workflow = _workflow(revision.id)
        db.add(workflow)
        await db.commit()
        await _start_workflow(db, workflow.id)
        stage = _ready_stage(workflow.id)
        db.add(stage)
        await db.commit()
        await _claim_stage(db, stage.id)
        return project.id, revision.id, workflow.id, stage.id


@pytest.mark.asyncio
async def test_project_create_revise_archive_service_path_respects_guards():
    await engine.dispose()
    actor = projects.ResearchActor("PostgreSQL Workflow Test", "postgres-workflow-test")
    try:
        async with async_session_factory() as db:
            project, revision_one = await _create_project(db, label="project-lifecycle")
            project, revision_two = await projects.create_revision(
                db,
                project.id,
                actor,
                expected_version=1,
                spec=_spec(objective="Validate a revised durable authority scope."),
                change_summary="Exercise revision lineage under database guards.",
            )
            await db.commit()
            assert revision_one.status == "superseded"
            assert revision_two.revision == 2
            assert revision_two.parent_revision_id == revision_one.id

            project, current = await projects.archive_project(
                db,
                project.id,
                actor,
                expected_version=2,
                reason="Disposable authority lifecycle completed.",
            )
            await db.commit()
            assert project.status == "archived"
            assert project.version == 3
            assert current.id == revision_two.id

        async with async_session_factory() as db:
            archived = await db.get(ResearchProject, project.id)
            archived.name = "Forbidden terminal rewrite"
            archived.version += 1
            with pytest.raises(IntegrityError):
                await db.flush()
            await db.rollback()

        async with async_session_factory() as db:
            archived = await db.get(ResearchProject, project.id)
            await db.delete(archived)
            with pytest.raises(IntegrityError):
                await db.flush()
            await db.rollback()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.usefixtures("_require_pre_receipt_workflow_revision")
async def test_valid_workflow_stage_attempt_heartbeat_and_completion_protocol():
    await engine.dispose()
    try:
        _, _, workflow_id, stage_id = await _create_valid_running_protocol(label="valid-protocol")
        async with async_session_factory() as db:
            stage, attempt = await _heartbeat_stage(db, stage_id)
            assert stage.state_version == 3
            assert attempt.state_version == 2
            assert stage.heartbeat_at == attempt.heartbeat_at
            assert stage.lease_expires_at == attempt.lease_expires_at

            stage, attempt = await _succeed_stage(db, stage_id)
            assert stage.status == attempt.status == "succeeded"
            assert stage.output_checksum == attempt.output_checksum

            workflow = await _succeed_workflow(db, workflow_id)
            assert workflow.status == "succeeded"
            assert workflow.state_version == 3
    finally:
        await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.usefixtures("_require_pre_receipt_workflow_revision")
async def test_deferred_guard_rejects_running_stage_without_attempt_at_commit():
    await engine.dispose()
    try:
        async with async_session_factory() as db:
            _, revision = await _create_project(db, label="missing-attempt")
            workflow = _workflow(revision.id)
            db.add(workflow)
            await db.commit()
            await _start_workflow(db, workflow.id)
            stage = _ready_stage(workflow.id)
            db.add(stage)
            await db.commit()

            now = datetime.now(timezone.utc)
            stage.status = "running"
            stage.state_version += 1
            stage.attempt_count = 1
            stage.first_started_at = now
            stage.next_attempt_at = None
            stage.lease_owner = "worker-orphan"
            stage.lease_token = uuid4()
            stage.leased_at = now
            stage.heartbeat_at = now
            stage.lease_expires_at = now + timedelta(minutes=5)
            await db.flush()
            with pytest.raises(IntegrityError):
                await db.commit()
            await db.rollback()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.usefixtures("_require_pre_receipt_workflow_revision")
async def test_deferred_guard_rejects_one_sided_heartbeat_drift_at_commit():
    await engine.dispose()
    try:
        _, _, _, stage_id = await _create_valid_running_protocol(label="heartbeat-drift")
        async with async_session_factory() as db:
            stage = await db.get(StageRun, stage_id)
            stage.state_version += 1
            stage.heartbeat_at = stage.heartbeat_at + timedelta(seconds=1)
            stage.lease_expires_at = stage.lease_expires_at + timedelta(seconds=1)
            await db.flush()
            with pytest.raises(IntegrityError):
                await db.commit()
            await db.rollback()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.usefixtures("_require_pre_receipt_workflow_revision")
async def test_duplicate_running_attempt_and_illegal_state_version_are_rejected():
    await engine.dispose()
    try:
        _, _, workflow_id, stage_id = await _create_valid_running_protocol(label="duplicate-attempt")
        async with async_session_factory() as db:
            stage = await db.get(StageRun, stage_id)
            duplicate = StageAttempt(
                stage_run_id=stage.id,
                attempt_number=stage.attempt_count,
                lease_token=stage.lease_token,
                lease_owner=stage.lease_owner,
                delivery_id=f"duplicate-{uuid4().hex}",
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
                started_at=stage.leased_at,
                heartbeat_at=stage.heartbeat_at,
                lease_expires_at=stage.lease_expires_at,
            )
            db.add(duplicate)
            with pytest.raises(IntegrityError):
                await db.flush()
            await db.rollback()

        async with async_session_factory() as db:
            workflow = await db.get(WorkflowRun, workflow_id)
            workflow.status = "failed"
            workflow.completed_at = datetime.now(timezone.utc)
            workflow.status_reason_code = "workflow.failed"
            workflow.status_summary = "Rejected stale transition."
            with pytest.raises(IntegrityError):
                await db.flush()
            await db.rollback()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.usefixtures("_require_pre_receipt_workflow_revision")
async def test_terminal_attempt_mutation_and_authority_deletion_are_rejected():
    await engine.dispose()
    try:
        _, _, workflow_id, stage_id = await _create_valid_running_protocol(label="terminal-evidence")
        async with async_session_factory() as db:
            _, attempt = await _succeed_stage(db, stage_id)
            await _succeed_workflow(db, workflow_id)
            attempt_id = attempt.id

        async with async_session_factory() as db:
            attempt = await db.get(StageAttempt, attempt_id)
            attempt.output_checksum = hashlib.sha256(b"rewritten").hexdigest()
            attempt.state_version += 1
            with pytest.raises(IntegrityError):
                await db.flush()
            await db.rollback()

        async with async_session_factory() as db:
            attempt = await db.get(StageAttempt, attempt_id)
            await db.delete(attempt)
            with pytest.raises(IntegrityError):
                await db.flush()
            await db.rollback()

        async with async_session_factory() as db:
            workflow = await db.get(WorkflowRun, workflow_id)
            await db.delete(workflow)
            with pytest.raises(IntegrityError):
                await db.flush()
            await db.rollback()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.usefixtures("_require_pre_receipt_workflow_revision")
async def test_replay_requires_exact_same_project_type_and_older_terminal_origin():
    await engine.dispose()
    actor = projects.ResearchActor("PostgreSQL Workflow Test", "postgres-workflow-test")
    try:
        async with async_session_factory() as db:
            project, revision_one = await _create_project(db, label="replay-lineage")
            origin = _workflow(revision_one.id)
            db.add(origin)
            await db.commit()
            await _start_workflow(db, origin.id)
            await _succeed_workflow(db, origin.id)
            origin_created_at = origin.created_at

            project, revision_two = await projects.create_revision(
                db,
                project.id,
                actor,
                expected_version=1,
                spec=_spec(objective="Replay the same project under its next revision."),
                change_summary="Exercise same-project replay lineage.",
            )
            await db.commit()

            replay = _workflow(
                revision_two.id,
                trigger_type="replay",
                replay_of_run_id=origin.id,
            )
            db.add(replay)
            await db.commit()
            assert replay.replay_of_run_id == origin.id

        async with async_session_factory() as db:
            wrong_type = _workflow(
                revision_two.id,
                workflow_type="cti.different",
                trigger_type="replay",
                replay_of_run_id=origin.id,
            )
            db.add(wrong_type)
            with pytest.raises(IntegrityError):
                await db.flush()
            await db.rollback()

        async with async_session_factory() as db:
            _, other_revision = await _create_project(db, label="replay-other-project")
            cross_project = _workflow(
                other_revision.id,
                trigger_type="replay",
                replay_of_run_id=origin.id,
            )
            db.add(cross_project)
            with pytest.raises(IntegrityError):
                await db.flush()
            await db.rollback()

        async with async_session_factory() as db:
            not_older = _workflow(
                revision_two.id,
                trigger_type="replay",
                replay_of_run_id=origin.id,
            )
            not_older.created_at = origin_created_at
            db.add(not_older)
            with pytest.raises(IntegrityError):
                await db.flush()
            await db.rollback()

        async with async_session_factory() as db:
            missing_origin = _workflow(revision_two.id, trigger_type="replay")
            db.add(missing_origin)
            with pytest.raises(IntegrityError):
                await db.flush()
            await db.rollback()

        async with async_session_factory() as db:
            revision = await db.get(ProjectRevision, revision_two.id)
            revision.status = "revoked"
            revision.revoked_by = "PostgreSQL Workflow Test"
            revision.revoked_by_id = "postgres-workflow-test"
            revision.revoked_at = datetime.now(timezone.utc)
            await db.commit()
            revision.spec_checksum = hashlib.sha256(b"rewritten").hexdigest()
            with pytest.raises(IntegrityError):
                await db.flush()
            await db.rollback()
    finally:
        await engine.dispose()
