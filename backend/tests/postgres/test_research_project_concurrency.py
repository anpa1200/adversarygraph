"""Real-PostgreSQL invariants for revision allocation.

Run only against a disposable database:

    RUN_POSTGRES_TESTS=1 python -m pytest -q \
      -o addopts='' --confcutdir=tests/postgres \
      tests/postgres/test_research_project_concurrency.py
"""

from __future__ import annotations

import asyncio
import os
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from app.core.database import async_session_factory, engine
from app.models.research_workflow import ProjectRevision, ResearchProject
from app.services import research_projects as projects


pytestmark = pytest.mark.skipif(
    os.getenv("RUN_POSTGRES_TESTS") != "1",
    reason="requires an explicitly authorized disposable PostgreSQL database",
)


def _spec(objective: str) -> dict:
    return {
        "objective": objective,
        "intelligence_requirements": [
            "Which concrete procedures are supported by primary sources?"
        ],
        "output_targets": ["detections"],
        "tlp": "TLP:AMBER",
    }


@pytest.mark.asyncio
async def test_concurrent_next_revision_has_one_winner_and_one_stale_client():
    await engine.dispose()
    actor = projects.ResearchActor("PostgreSQL Test Analyst", "postgres-test")
    project_key = f"concurrency-{uuid4().hex[:16]}"
    try:
        async with async_session_factory() as db:
            project, _ = await projects.create_project(
                db,
                actor,
                project_key=project_key,
                name="Concurrency Test",
                description="Disposable row-lock validation.",
                spec=_spec("Create the initial evidence-backed research scope."),
            )
            project_id = project.id
            await db.commit()

        ready = asyncio.Event()
        waiting = 0
        waiting_lock = asyncio.Lock()

        async def revise(objective: str) -> str:
            nonlocal waiting
            async with waiting_lock:
                waiting += 1
                if waiting == 2:
                    ready.set()
            await ready.wait()
            async with async_session_factory() as db:
                try:
                    await projects.create_revision(
                        db,
                        project_id,
                        actor,
                        expected_version=1,
                        spec=_spec(objective),
                        change_summary="Concurrent revision attempt.",
                    )
                    await db.commit()
                    return "committed"
                except projects.ResearchProjectConflict:
                    await db.rollback()
                    return "conflict"

        results = await asyncio.gather(
            revise("Create evidence-backed research scope variant alpha."),
            revise("Create evidence-backed research scope variant bravo."),
        )

        assert sorted(results) == ["committed", "conflict"]
        async with async_session_factory() as db:
            project = await db.get(ResearchProject, project_id)
            revisions = list(
                (
                    await db.execute(
                        select(ProjectRevision)
                        .where(ProjectRevision.project_id == project_id)
                        .order_by(ProjectRevision.revision.asc())
                    )
                )
                .scalars()
                .all()
            )
            assert project.version == 2
            assert [revision.revision for revision in revisions] == [1, 2]
            assert [revision.status for revision in revisions] == [
                "superseded",
                "current",
            ]
            assert revisions[1].parent_revision_id == revisions[0].id
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_database_rejects_revision_authority_mutation_and_cross_project_parent():
    await engine.dispose()
    actor = projects.ResearchActor("PostgreSQL Test Analyst", "postgres-test")
    try:
        async with async_session_factory() as db:
            first, first_revision = await projects.create_project(
                db,
                actor,
                project_key=f"lineage-a-{uuid4().hex[:12]}",
                name="Lineage Project A",
                description="Disposable trigger validation.",
                spec=_spec("Build the first evidence-backed lineage scope."),
            )
            second, _ = await projects.create_project(
                db,
                actor,
                project_key=f"lineage-b-{uuid4().hex[:12]}",
                name="Lineage Project B",
                description="Disposable trigger validation.",
                spec=_spec("Build the second evidence-backed lineage scope."),
            )
            await db.commit()

        async with async_session_factory() as db:
            with pytest.raises(IntegrityError):
                await db.execute(
                    text("""
                        UPDATE project_revisions
                        SET spec = jsonb_build_object('tampered', true)
                        WHERE id = :revision_id
                    """),
                    {"revision_id": first_revision.id},
                )
                await db.flush()
            await db.rollback()

        async with async_session_factory() as db:
            invalid = ProjectRevision(
                project_id=second.id,
                revision=2,
                parent_revision_id=first_revision.id,
                status="current",
                schema_version="research-project-spec-v1",
                spec=_spec("Build an invalid cross-project lineage scope."),
                spec_checksum="a" * 64,
                change_summary="Invalid cross-project parent.",
                created_by=actor.name,
                created_by_id=actor.actor_id,
            )
            db.add(invalid)
            with pytest.raises(IntegrityError):
                await db.flush()
            await db.rollback()
    finally:
        await engine.dispose()
