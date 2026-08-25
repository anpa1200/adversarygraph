"""Test-only builders for commit-owning workflow authority coordinators."""

from __future__ import annotations

import uuid

from app.models.research_workflow import WorkflowRun
from app.services.outbox_runtime import WorkflowCancellationCommand
from app.services.research_projects import ResearchActor
from app.services.workflow_worker import (
    CoordinatedWorkflowCancellation,
    SessionFactory,
    coordinate_workflow_cancel,
)


def cancellation_command(
    *,
    workflow_run_id: uuid.UUID,
    expected_workflow_state_version: int,
    actor: ResearchActor,
    reason: str,
    request_id: uuid.UUID | None = None,
) -> WorkflowCancellationCommand:
    """Build one exact cancellation command without retaining an ORM row."""

    return WorkflowCancellationCommand(
        request_id=uuid.UUID(str(request_id)) if request_id is not None else uuid.uuid4(),
        workflow_run_id=uuid.UUID(str(workflow_run_id)),
        expected_workflow_state_version=expected_workflow_state_version,
        actor=actor.name,
        actor_id=actor.actor_id,
        reason=reason,
    )


async def cancel_active_workflow(
    session_factory: SessionFactory,
    *,
    workflow_run_id: uuid.UUID,
    actor: ResearchActor,
    reason: str,
) -> CoordinatedWorkflowCancellation | None:
    """Cancel active test authority through the commit-owning coordinator."""

    async with session_factory() as db:
        workflow = await db.get(WorkflowRun, workflow_run_id)
        if workflow is None or workflow.status not in {"queued", "running"}:
            return None
        command = cancellation_command(
            workflow_run_id=uuid.UUID(str(workflow.id)),
            expected_workflow_state_version=workflow.state_version,
            actor=actor,
            reason=reason,
        )
    return await coordinate_workflow_cancel(session_factory, command=command)
