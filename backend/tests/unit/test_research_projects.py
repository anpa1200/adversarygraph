from __future__ import annotations

import inspect
from datetime import date
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.models.research_workflow import ProjectRevision, ResearchProject
from app.services import research_projects as projects


def _spec(**overrides):
    value = {
        "objective": "Build an evidence-backed MuddyWater detection program.",
        "intelligence_requirements": ["Which concrete procedures are supported by primary sources?"],
        "domains": ["enterprise-attack"],
        "actor_scope": ["MuddyWater"],
        "technique_scope": ["t1059.001"],
        "source_kinds": ["url", "file"],
        "output_targets": ["detections", "rag", "detections"],
        "review_profile": "external_cti",
        "tlp": "TLP:AMBER",
        "tags": ["MuddyWater", "muddywater"],
    }
    value.update(overrides)
    return value


def _actor():
    return projects.ResearchActor(
        name="Threat Intelligence Analyst",
        actor_id="analyst-1",
    )


class _CreateDB:
    def __init__(self):
        self.added = []
        self.flushes = 0

    def add(self, value):
        if value.id is None:
            value.id = uuid4()
        self.added.append(value)

    async def flush(self):
        self.flushes += 1


def _project(*, version=1, status="active"):
    return ResearchProject(
        id=uuid4(),
        project_key="desert-hydra",
        name="Operation Desert Hydra",
        description="",
        status=status,
        domain="enterprise-attack",
        tlp="TLP:AMBER",
        version=version,
        created_by="Analyst",
        created_by_id="analyst-1",
        updated_by="Analyst",
        updated_by_id="analyst-1",
    )


def _revision(project, *, checksum="a" * 64, revision=1):
    return ProjectRevision(
        id=uuid4(),
        project_id=project.id,
        revision=revision,
        status="current",
        schema_version="research-project-spec-v1",
        spec=_spec(),
        spec_checksum=checksum,
        change_summary="Initial scope",
        created_by="Analyst",
        created_by_id="analyst-1",
    )


def test_project_spec_is_canonical_and_checksum_is_deterministic():
    first_payload, first_checksum = projects.normalize_project_spec(_spec())
    second_payload, second_checksum = projects.normalize_project_spec(
        {
            **_spec(),
            "technique_scope": ["T1059.001", "t1059.001"],
            "output_targets": ["rag", "detections"],
        }
    )

    assert first_payload["technique_scope"] == ["T1059.001"]
    assert first_payload["tags"] == ["MuddyWater"]
    assert first_payload["output_targets"] == [
        "canonical_intelligence",
        "detections",
        "rag",
    ]
    assert second_payload["output_targets"] == [
        "canonical_intelligence",
        "detections",
        "rag",
    ]
    assert second_payload == first_payload
    assert first_checksum == second_checksum
    repeated_payload, repeated_checksum = projects.normalize_project_spec(first_payload)
    assert repeated_payload == first_payload
    assert repeated_checksum == first_checksum


def test_project_spec_defaults_and_model_instances_are_revalidated_canonically():
    model = projects.ResearchProjectSpec.model_validate(
        {
            "objective": "Build an evidence-backed MuddyWater detection program.",
            "intelligence_requirements": ["Which concrete procedures are supported by primary sources?"],
        }
    )
    # The default itself is canonical, and instance input still takes the
    # complete validation path rather than being trusted by identity.
    assert model.source_kinds == ["file", "text", "url"]
    model.source_kinds = ["url", "file", "text"]

    payload, checksum = projects.normalize_project_spec(model)

    assert payload["source_kinds"] == ["file", "text", "url"]
    assert projects.normalize_project_spec(payload) == (payload, checksum)


def test_project_spec_rejects_invalid_window_and_attack_id():
    with pytest.raises(ValidationError, match="date_from must not be after"):
        projects.ResearchProjectSpec.model_validate(_spec(date_from=date(2026, 5, 24), date_to=date(2026, 5, 23)))
    with pytest.raises(ValidationError, match="Invalid ATT&CK/ATLAS"):
        projects.ResearchProjectSpec.model_validate(_spec(technique_scope=["T-NOT-REAL"]))


def test_project_spec_rejects_tlp_red_until_clearance_is_enforced():
    with pytest.raises(ValidationError, match="Input should be"):
        projects.ResearchProjectSpec.model_validate(_spec(tlp="TLP:RED"))


def test_persisted_spec_decoder_is_explicitly_versioned():
    decoded = projects.decode_project_spec("research-project-spec-v1", _spec())
    assert decoded.objective.startswith("Build an evidence-backed")

    with pytest.raises(projects.ResearchProjectStoredContractError, match="v99"):
        projects.decode_project_spec("research-project-spec-v99", _spec())


def test_tlp_red_rows_fail_closed_at_read_boundary():
    project = _project()
    project.tlp = "TLP:RED"

    with pytest.raises(projects.ResearchProjectAccessDenied, match="clearance"):
        projects._assert_readable(project)


@pytest.mark.asyncio
async def test_create_project_persists_one_current_checksum_bound_revision():
    db = _CreateDB()

    project, revision = await projects.create_project(
        db,
        _actor(),
        project_key="Desert-Hydra",
        name="Operation Desert Hydra",
        description="MuddyWater research and detection program.",
        spec=_spec(),
    )

    assert project.project_key == "desert-hydra"
    assert project.version == 1
    assert project.tlp == "TLP:AMBER"
    assert revision.project_id == project.id
    assert revision.revision == 1
    assert revision.status == "current"
    assert len(revision.spec_checksum) == 64
    assert revision.spec["technique_scope"] == ["T1059.001"]
    assert db.added == [project, revision]
    assert db.flushes == 2


@pytest.mark.asyncio
async def test_create_revision_supersedes_parent_and_increments_project_version(
    monkeypatch,
):
    db = _CreateDB()
    project = _project(version=4)
    current = _revision(project, revision=3)

    async def lock(_db, project_id):
        assert project_id == project.id
        return project

    async def current_revision(_db, project_id, *, for_update=False):
        assert project_id == project.id
        assert for_update is True
        return current

    monkeypatch.setattr(projects, "_lock_project", lock)
    monkeypatch.setattr(projects, "_current_revision", current_revision)

    updated, revision = await projects.create_revision(
        db,
        project.id,
        _actor(),
        expected_version=4,
        spec=_spec(objective="Build a revised, evidence-backed detection program."),
        change_summary="Clarify the validation objective.",
    )

    assert current.status == "superseded"
    assert revision.parent_revision_id == current.id
    assert revision.revision == 4
    assert revision.status == "current"
    assert updated.version == 5
    assert db.flushes == 2


@pytest.mark.asyncio
async def test_workflow_authority_locks_active_project_before_fresh_current_revision(
    monkeypatch,
):
    project = _project(version=4)
    current = _revision(project, revision=3)
    events: list[str] = []
    assert "populate_existing=True" in inspect.getsource(projects._lock_project)
    assert "populate_existing=True" in inspect.getsource(projects._current_revision)

    async def lock(_db, project_id):
        events.append("project")
        assert project_id == project.id
        return project

    async def current_revision(_db, project_id, *, for_update=False):
        events.append("revision")
        assert project_id == project.id
        assert for_update is True
        return current

    monkeypatch.setattr(projects, "_lock_project", lock)
    monkeypatch.setattr(projects, "_current_revision", current_revision)

    assert await projects.lock_project_workflow_authority(object(), project.id) == (
        project,
        current,
    )
    assert events == ["project", "revision"]

    project.status = "archived"
    events.clear()
    with pytest.raises(projects.ResearchProjectConflict, match="cannot start workflows"):
        await projects.lock_project_workflow_authority(object(), project.id)
    assert events == ["project"]


@pytest.mark.asyncio
async def test_create_revision_rejects_stale_client_before_mutation(monkeypatch):
    db = _CreateDB()
    project = _project(version=7)

    async def lock(_db, _project_id):
        return project

    monkeypatch.setattr(projects, "_lock_project", lock)

    with pytest.raises(projects.ResearchProjectConflict, match="expected 6, current 7"):
        await projects.create_revision(
            db,
            project.id,
            _actor(),
            expected_version=6,
            spec=_spec(objective="Build another evidence-backed detection program."),
            change_summary="Stale change",
        )
    assert db.added == []
    assert project.version == 7


@pytest.mark.asyncio
async def test_create_revision_rejects_unchanged_spec_and_archived_project(
    monkeypatch,
):
    db = _CreateDB()
    payload, checksum = projects.normalize_project_spec(_spec())
    project = _project(version=3)
    current = _revision(project, checksum=checksum, revision=2)
    current.spec = payload

    async def lock(_db, _project_id):
        return project

    async def current_revision(_db, _project_id, *, for_update=False):
        assert for_update is True
        return current

    monkeypatch.setattr(projects, "_lock_project", lock)
    monkeypatch.setattr(projects, "_current_revision", current_revision)

    with pytest.raises(projects.ResearchProjectConflict, match="identical"):
        await projects.create_revision(
            db,
            project.id,
            _actor(),
            expected_version=3,
            spec=_spec(),
            change_summary="No actual change",
        )
    assert current.status == "current"
    assert project.version == 3

    project.status = "archived"
    with pytest.raises(projects.ResearchProjectConflict, match="cannot be revised"):
        await projects.create_revision(
            db,
            project.id,
            _actor(),
            expected_version=3,
            spec=_spec(objective="Build a different evidence-backed program."),
            change_summary="Attempt after archive",
        )


def test_project_spec_strips_before_enforcing_objective_minimum():
    with pytest.raises(ValidationError):
        projects.ResearchProjectSpec.model_validate(_spec(objective="          x          "))


@pytest.mark.asyncio
async def test_archive_is_terminal_and_requires_reason(monkeypatch):
    db = _CreateDB()
    project = _project(version=2)
    current = _revision(project)

    async def lock(_db, _project_id):
        return project

    async def current_revision(_db, _project_id, *, for_update=False):
        assert for_update is False
        return current

    monkeypatch.setattr(projects, "_lock_project", lock)
    monkeypatch.setattr(projects, "_current_revision", current_revision)

    archived, returned_revision = await projects.archive_project(
        db,
        project.id,
        _actor(),
        expected_version=2,
        reason="Research program completed and released.",
    )

    assert returned_revision is current
    assert archived.status == "archived"
    assert archived.version == 3
    assert archived.archived_at is not None
    assert archived.archive_reason == "Research program completed and released."
    with pytest.raises(projects.ResearchProjectConflict, match="already archived"):
        await projects.archive_project(
            db,
            project.id,
            _actor(),
            expected_version=3,
            reason="Again",
        )
