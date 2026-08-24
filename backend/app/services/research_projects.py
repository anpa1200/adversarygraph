"""Deterministic lifecycle for revisioned CTI research projects."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, ValidationError, field_validator, model_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.payload_limits import BoundedPayloadModel
from app.models.research_workflow import (
    PROJECT_SPEC_SCHEMA_VERSION,
    ProjectRevision,
    ResearchProject,
)


PROJECT_DOMAINS = (
    "enterprise-attack",
    "mobile-attack",
    "ics-attack",
    "atlas",
)
PROJECT_SOURCE_KINDS = (
    "url",
    "file",
    "text",
    "rss",
    "taxii",
    "misp",
    "stix",
    "opencti",
)
PROJECT_OUTPUT_TARGETS = (
    "canonical_intelligence",
    "knowledge",
    "rag",
    "hunting",
    "detections",
    "exports",
)
PROJECT_REVIEW_PROFILES = ("external_cti", "internal_ir")
PROJECT_TLPS = (
    "TLP:CLEAR",
    "TLP:GREEN",
    "TLP:AMBER",
    "TLP:AMBER+STRICT",
)

_PROJECT_KEY_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,79}")
_TECHNIQUE_ID_RE = re.compile(r"(?:T\d{4}(?:\.\d{3})?|AML\.T\d{4}(?:\.\d{3})?)")

RequirementText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=1_000)]
ScopeText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)]


class ResearchProjectSpec(BoundedPayloadModel):
    """Versioned, strict input contract for one research revision."""

    objective: str = Field(min_length=10, max_length=5_000)
    intelligence_requirements: list[RequirementText] = Field(min_length=1, max_length=50)
    domains: list[Literal["enterprise-attack", "mobile-attack", "ics-attack", "atlas"]] = Field(
        default_factory=lambda: ["enterprise-attack"], min_length=1, max_length=4
    )
    actor_scope: list[ScopeText] = Field(default_factory=list, max_length=200)
    technique_scope: list[str] = Field(default_factory=list, max_length=500)
    sectors: list[ScopeText] = Field(default_factory=list, max_length=100)
    regions: list[ScopeText] = Field(default_factory=list, max_length=100)
    source_kinds: list[Literal["url", "file", "text", "rss", "taxii", "misp", "stix", "opencti"]] = Field(
        default_factory=lambda: ["file", "text", "url"],
        min_length=1,
        max_length=8,
    )
    output_targets: list[
        Literal[
            "canonical_intelligence",
            "knowledge",
            "rag",
            "hunting",
            "detections",
            "exports",
        ]
    ] = Field(default_factory=lambda: ["canonical_intelligence"], min_length=1, max_length=6)
    review_profile: Literal["external_cti", "internal_ir"] = "external_cti"
    tlp: Literal[
        "TLP:CLEAR",
        "TLP:GREEN",
        "TLP:AMBER",
        "TLP:AMBER+STRICT",
    ] = "TLP:AMBER+STRICT"
    date_from: date | None = None
    date_to: date | None = None
    tags: list[ScopeText] = Field(default_factory=list, max_length=100)

    @field_validator("objective", mode="before")
    @classmethod
    def _clean_objective(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value

    @field_validator(
        "actor_scope",
        "sectors",
        "regions",
        "tags",
    )
    @classmethod
    def _dedupe_text(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for value in values:
            item = value.strip()
            identity = item.casefold()
            if identity not in seen:
                cleaned.append(item)
                seen.add(identity)
        return sorted(cleaned, key=lambda item: (item.casefold(), item))

    @field_validator("intelligence_requirements")
    @classmethod
    def _dedupe_ordered_requirements(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for value in values:
            item = value.strip()
            identity = item.casefold()
            if identity not in seen:
                cleaned.append(item)
                seen.add(identity)
        return cleaned

    @field_validator("domains", "source_kinds")
    @classmethod
    def _dedupe_enums(cls, values: list[str]) -> list[str]:
        return sorted(set(values))

    @field_validator("technique_scope")
    @classmethod
    def _normalize_techniques(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            attack_id = str(value).strip().upper()
            if not _TECHNIQUE_ID_RE.fullmatch(attack_id):
                raise ValueError(f"Invalid ATT&CK/ATLAS technique identifier: {value}")
            if attack_id not in normalized:
                normalized.append(attack_id)
        return sorted(normalized)

    @field_validator("output_targets")
    @classmethod
    def _normalize_targets(cls, values: list[str]) -> list[str]:
        selected = set(values)
        selected.add("canonical_intelligence")
        return ["canonical_intelligence", *sorted(selected - {"canonical_intelligence"})]

    @model_validator(mode="after")
    def _validate_date_window(self):
        if self.date_from and self.date_to and self.date_from > self.date_to:
            raise ValueError("date_from must not be after date_to")
        return self


@dataclass(frozen=True)
class ResearchActor:
    name: str
    actor_id: str


class ResearchProjectError(RuntimeError):
    pass


class ResearchProjectNotFound(ResearchProjectError):
    pass


class ResearchProjectConflict(ResearchProjectError):
    pass


class ResearchProjectAccessDenied(ResearchProjectError):
    pass


class ResearchProjectValidation(ResearchProjectError):
    pass


class ResearchProjectStoredContractError(ResearchProjectError):
    pass


def normalize_project_key(value: str) -> str:
    key = str(value or "").strip().lower()
    if not _PROJECT_KEY_RE.fullmatch(key):
        raise ResearchProjectValidation("project_key must be 1-80 lowercase letters, numbers, or hyphens and start with a letter or number")
    return key


def normalize_project_spec(
    value: ResearchProjectSpec | dict,
) -> tuple[dict, str]:
    try:
        # Revalidate model instances too.  Pydantic does not validate default
        # values unless configured to do so, and a caller can also mutate an
        # otherwise valid model before presenting it.  Persisted authority must
        # therefore always pass through the same canonical validators.
        raw = value.model_dump(mode="python") if isinstance(value, ResearchProjectSpec) else value
        spec = ResearchProjectSpec.model_validate(raw)
    except ValidationError as exc:
        raise ResearchProjectValidation("Project specification is invalid") from exc
    payload = spec.model_dump(mode="json")
    checksum = hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    return payload, checksum


def decode_project_spec(schema_version: str, value: dict) -> ResearchProjectSpec:
    """Decode persisted revisions through an explicit version registry."""

    decoders = {PROJECT_SPEC_SCHEMA_VERSION: ResearchProjectSpec}
    decoder = decoders.get(str(schema_version or ""))
    if decoder is None:
        raise ResearchProjectStoredContractError(f"Unsupported persisted project specification schema: {schema_version or 'missing'}")
    try:
        return decoder.model_validate(value)
    except ValidationError as exc:
        raise ResearchProjectStoredContractError(f"Persisted {schema_version} project specification is invalid") from exc


def _assert_readable(project: ResearchProject) -> None:
    # The current deployment is a single workspace without per-user clearance.
    # Never expose TLP:RED through that boundary until explicit clearance exists.
    if project.tlp == "TLP:RED":
        raise ResearchProjectAccessDenied("TLP:RED research projects require a clearance boundary that is not enabled")


def _actor(actor: ResearchActor) -> tuple[str, str]:
    name = actor.name.strip()[:255]
    actor_id = actor.actor_id.strip()[:80]
    if not name or not actor_id:
        raise ResearchProjectValidation("A stable authenticated actor is required")
    return name, actor_id


async def _lock_project(db: AsyncSession, project_id: uuid.UUID) -> ResearchProject:
    project = await db.scalar(
        select(ResearchProject).where(ResearchProject.id == project_id).with_for_update().execution_options(populate_existing=True)
    )
    if project is None:
        raise ResearchProjectNotFound("Research project not found")
    _assert_readable(project)
    return project


async def _current_revision(
    db: AsyncSession,
    project_id: uuid.UUID,
    *,
    for_update: bool = False,
) -> ProjectRevision:
    query = (
        select(ProjectRevision)
        .where(
            ProjectRevision.project_id == project_id,
            ProjectRevision.status == "current",
        )
        .order_by(ProjectRevision.revision.desc())
        .limit(1)
    )
    if for_update:
        query = query.with_for_update().execution_options(populate_existing=True)
    revision = await db.scalar(query)
    if revision is None:
        raise ResearchProjectConflict("Project has no current specification revision")
    return revision


async def lock_project_workflow_authority(
    db: AsyncSession,
    project_id: uuid.UUID,
) -> tuple[ResearchProject, ProjectRevision]:
    """Lock one active project and its exact current revision in canonical order."""

    project = await _lock_project(db, project_id)
    if project.status != "active":
        raise ResearchProjectConflict("Archived projects cannot start workflows")
    revision = await _current_revision(db, project.id, for_update=True)
    return project, revision


async def create_project(
    db: AsyncSession,
    actor: ResearchActor,
    *,
    project_key: str,
    name: str,
    description: str,
    spec: ResearchProjectSpec | dict,
    change_summary: str = "Initial research scope",
) -> tuple[ResearchProject, ProjectRevision]:
    actor_name, actor_id = _actor(actor)
    key = normalize_project_key(project_key)
    clean_name = name.strip()[:255]
    if not clean_name:
        raise ResearchProjectValidation("Project name is required")
    payload, checksum = normalize_project_spec(spec)
    clean_change_summary = change_summary.strip()[:2_000]
    if not clean_change_summary:
        raise ResearchProjectValidation("Revision change summary is required")

    project = ResearchProject(
        project_key=key,
        name=clean_name,
        description=description.strip()[:100_000],
        status="active",
        domain=payload["domains"][0],
        tlp=payload["tlp"],
        version=1,
        created_by=actor_name,
        created_by_id=actor_id,
        updated_by=actor_name,
        updated_by_id=actor_id,
    )
    db.add(project)
    await db.flush()
    revision = ProjectRevision(
        project_id=project.id,
        revision=1,
        parent_revision_id=None,
        status="current",
        schema_version=PROJECT_SPEC_SCHEMA_VERSION,
        spec=payload,
        spec_checksum=checksum,
        change_summary=clean_change_summary,
        created_by=actor_name,
        created_by_id=actor_id,
    )
    db.add(revision)
    await db.flush()
    return project, revision


async def create_revision(
    db: AsyncSession,
    project_id: uuid.UUID,
    actor: ResearchActor,
    *,
    expected_version: int,
    spec: ResearchProjectSpec | dict,
    change_summary: str,
) -> tuple[ResearchProject, ProjectRevision]:
    actor_name, actor_id = _actor(actor)
    payload, checksum = normalize_project_spec(spec)
    clean_change_summary = change_summary.strip()[:2_000]
    if not clean_change_summary:
        raise ResearchProjectValidation("Revision change summary is required")

    project = await _lock_project(db, project_id)
    if project.status != "active":
        raise ResearchProjectConflict("Archived projects cannot be revised")
    if project.version != expected_version:
        raise ResearchProjectConflict(f"Project version conflict: expected {expected_version}, current {project.version}")
    current = await _current_revision(db, project.id, for_update=True)
    if current.spec_checksum == checksum:
        raise ResearchProjectConflict("The proposed specification is identical to the current revision")

    # Flush the supersession before inserting the replacement so PostgreSQL's
    # partial unique current-revision index is never order-dependent.
    current.status = "superseded"
    await db.flush()
    revision = ProjectRevision(
        project_id=project.id,
        revision=current.revision + 1,
        parent_revision_id=current.id,
        status="current",
        schema_version=PROJECT_SPEC_SCHEMA_VERSION,
        spec=payload,
        spec_checksum=checksum,
        change_summary=clean_change_summary,
        created_by=actor_name,
        created_by_id=actor_id,
    )
    db.add(revision)
    project.version += 1
    project.domain = payload["domains"][0]
    project.tlp = payload["tlp"]
    project.updated_by = actor_name
    project.updated_by_id = actor_id
    await db.flush()
    return project, revision


async def update_project_metadata(
    db: AsyncSession,
    project_id: uuid.UUID,
    actor: ResearchActor,
    *,
    expected_version: int,
    name: str | None = None,
    description: str | None = None,
) -> tuple[ResearchProject, ProjectRevision]:
    actor_name, actor_id = _actor(actor)
    project = await _lock_project(db, project_id)
    if project.status != "active":
        raise ResearchProjectConflict("Archived projects cannot be changed")
    if project.version != expected_version:
        raise ResearchProjectConflict(f"Project version conflict: expected {expected_version}, current {project.version}")
    changed = False
    if name is not None:
        clean_name = name.strip()[:255]
        if not clean_name:
            raise ResearchProjectValidation("Project name is required")
        if clean_name != project.name:
            project.name = clean_name
            changed = True
    if description is not None:
        clean_description = description.strip()[:100_000]
        if clean_description != project.description:
            project.description = clean_description
            changed = True
    if not changed:
        raise ResearchProjectConflict("Project metadata is unchanged")
    project.version += 1
    project.updated_by = actor_name
    project.updated_by_id = actor_id
    revision = await _current_revision(db, project.id)
    await db.flush()
    return project, revision


async def archive_project(
    db: AsyncSession,
    project_id: uuid.UUID,
    actor: ResearchActor,
    *,
    expected_version: int,
    reason: str,
) -> tuple[ResearchProject, ProjectRevision]:
    actor_name, actor_id = _actor(actor)
    clean_reason = reason.strip()[:2_000]
    if not clean_reason:
        raise ResearchProjectValidation("Archive reason is required")
    project = await _lock_project(db, project_id)
    if project.status == "archived":
        raise ResearchProjectConflict("Project is already archived")
    if project.version != expected_version:
        raise ResearchProjectConflict(f"Project version conflict: expected {expected_version}, current {project.version}")
    project.status = "archived"
    project.version += 1
    project.archive_reason = clean_reason
    project.archived_at = datetime.now(timezone.utc)
    project.updated_by = actor_name
    project.updated_by_id = actor_id
    revision = await _current_revision(db, project.id)
    await db.flush()
    return project, revision


async def get_project(db: AsyncSession, project_id: uuid.UUID) -> tuple[ResearchProject, ProjectRevision]:
    project = await db.get(ResearchProject, project_id)
    if project is None:
        raise ResearchProjectNotFound("Research project not found")
    _assert_readable(project)
    return project, await _current_revision(db, project.id)


async def list_projects(
    db: AsyncSession,
    *,
    status: str | None,
    limit: int,
    offset: int,
) -> tuple[int, list[tuple[ResearchProject, ProjectRevision]]]:
    query = select(ResearchProject).where(ResearchProject.tlp != "TLP:RED")
    count_query = select(func.count(ResearchProject.id)).where(ResearchProject.tlp != "TLP:RED")
    if status is not None:
        query = query.where(ResearchProject.status == status)
        count_query = count_query.where(ResearchProject.status == status)
    total = int(await db.scalar(count_query) or 0)
    rows = await db.execute(query.order_by(ResearchProject.updated_at.desc(), ResearchProject.id.desc()).limit(limit).offset(offset))
    projects = list(rows.scalars().all())
    if not projects:
        return total, []
    revision_rows = await db.execute(
        select(ProjectRevision).where(
            ProjectRevision.project_id.in_([project.id for project in projects]),
            ProjectRevision.status == "current",
        )
    )
    revisions = {revision.project_id: revision for revision in revision_rows.scalars().all()}
    missing = [project.id for project in projects if project.id not in revisions]
    if missing:
        raise ResearchProjectConflict("One or more projects have no current revision")
    return total, [(project, revisions[project.id]) for project in projects]


async def list_revisions(db: AsyncSession, project_id: uuid.UUID) -> tuple[ResearchProject, list[ProjectRevision]]:
    project = await db.get(ResearchProject, project_id)
    if project is None:
        raise ResearchProjectNotFound("Research project not found")
    _assert_readable(project)
    rows = await db.execute(
        select(ProjectRevision).where(ProjectRevision.project_id == project.id).order_by(ProjectRevision.revision.desc())
    )
    return project, list(rows.scalars().all())


async def get_revision(
    db: AsyncSession,
    project_id: uuid.UUID,
    revision_number: int,
) -> tuple[ResearchProject, ProjectRevision]:
    project = await db.get(ResearchProject, project_id)
    if project is None:
        raise ResearchProjectNotFound("Research project not found")
    _assert_readable(project)
    revision = await db.scalar(
        select(ProjectRevision).where(
            ProjectRevision.project_id == project.id,
            ProjectRevision.revision == revision_number,
        )
    )
    if revision is None:
        raise ResearchProjectNotFound("Project revision not found")
    return project, revision
