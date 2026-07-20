from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.core.version import APP_VERSION
from app.models.threat_hunting import ThreatHuntFinding, ThreatHuntQueryVersion
from app.models.threat_radar import ThreatHuntRequest
from app.services import threat_hunting as hunts
from app.services.auth import TeamUser, analyst, audit, require_permission

router = APIRouter(prefix="/threat-hunting", tags=["Threat Hunting"])
export_threat_hunt = require_permission("export_data")

HuntStatus = Literal[
    "queued",
    "draft",
    "planned",
    "running",
    "review",
    "completed",
    "cancelled",
    "archived",
]
HuntPriority = Literal[
    "P0 Emergency",
    "P1 High",
    "P2 Medium",
    "P3 Monitor",
    "P4 Low/Archive",
]
HuntDisposition = Literal[
    "undetermined",
    "no_matches",
    "benign",
    "benign_policy_relevant",
    "suspicious",
    "confirmed_malicious",
    "inconclusive",
    "telemetry_gap",
    "query_failure",
]
FindingVerdict = Literal["supports", "refutes", "inconclusive", "benign"]
FindingStatus = Literal["new", "reviewed", "escalated", "closed"]
FindingSeverity = Literal["informational", "low", "medium", "high", "critical"]
QueryLanguage = Literal[
    "generic",
    "sigma",
    "kql",
    "spl",
    "eql",
    "lucene",
    "sql",
    "osquery",
    "yara",
    "yaral",
    "other",
]
TLP = Literal["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"]

ATTACK_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def clean_list(values: list[str], *, max_item_length: int = 500) -> list[str]:
    cleaned = list(dict.fromkeys(value.strip() for value in values if value and value.strip()))
    if any(len(value) > max_item_length for value in cleaned):
        raise ValueError(f"List values must be at most {max_item_length} characters")
    return cleaned


def clean_techniques(values: list[str]) -> list[str]:
    cleaned = [value.upper() for value in clean_list(values, max_item_length=20)]
    invalid = [value for value in cleaned if not ATTACK_ID.fullmatch(value)]
    if invalid:
        raise ValueError(f"Invalid ATT&CK technique IDs: {', '.join(invalid)}")
    return cleaned


class HuntBody(BaseModel):
    model_config = {"extra": "forbid"}

    title: str = Field(..., min_length=3, max_length=500)
    hypothesis: str = Field(..., min_length=10, max_length=10_000)
    description: str = Field("", max_length=20_000)
    scope: str = Field("", max_length=10_000)
    status: HuntStatus = "draft"
    priority: HuntPriority = "P3 Monitor"
    owner: str = Field("", max_length=255)
    technique_ids: list[str] = Field(default_factory=list, max_length=100)
    tactics: list[str] = Field(default_factory=list, max_length=50)
    telemetry_sources: list[str] = Field(default_factory=list, max_length=100)
    required_fields: list[str] = Field(default_factory=list, max_length=200)
    tags: list[str] = Field(default_factory=list, max_length=100)
    query_language: QueryLanguage = "generic"
    query_text: str = Field("", max_length=100_000)
    time_range_start: datetime | None = None
    time_range_end: datetime | None = None
    expected_evidence: str = Field("", max_length=20_000)
    false_positive_notes: str = Field("", max_length=20_000)
    assumptions: str = Field("", max_length=20_000)
    result_summary: str = Field("", max_length=50_000)
    disposition: HuntDisposition = "undetermined"
    tlp: TLP = "TLP:AMBER"

    @field_validator("technique_ids")
    @classmethod
    def validate_techniques(cls, value: list[str]) -> list[str]:
        return clean_techniques(value)

    @field_validator("tactics", "telemetry_sources", "required_fields", "tags")
    @classmethod
    def normalize_lists(cls, value: list[str]) -> list[str]:
        return clean_list(value)

    @field_validator("time_range_start", "time_range_end")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("Hunt time ranges must include an explicit timezone")
        return value

    @model_validator(mode="after")
    def validate_time_range(self):
        if self.time_range_start and self.time_range_end and self.time_range_end <= self.time_range_start:
            raise ValueError("time_range_end must be later than time_range_start")
        return self


class HuntPatch(BaseModel):
    model_config = {"extra": "forbid"}

    title: str | None = Field(None, min_length=3, max_length=500)
    hypothesis: str | None = Field(None, min_length=10, max_length=10_000)
    description: str | None = Field(None, max_length=20_000)
    scope: str | None = Field(None, max_length=10_000)
    status: HuntStatus | None = None
    priority: HuntPriority | None = None
    owner: str | None = Field(None, max_length=255)
    technique_ids: list[str] | None = Field(None, max_length=100)
    tactics: list[str] | None = Field(None, max_length=50)
    telemetry_sources: list[str] | None = Field(None, max_length=100)
    required_fields: list[str] | None = Field(None, max_length=200)
    tags: list[str] | None = Field(None, max_length=100)
    query_language: QueryLanguage | None = None
    query_text: str | None = Field(None, max_length=100_000)
    time_range_start: datetime | None = None
    time_range_end: datetime | None = None
    expected_evidence: str | None = Field(None, max_length=20_000)
    false_positive_notes: str | None = Field(None, max_length=20_000)
    assumptions: str | None = Field(None, max_length=20_000)
    result_summary: str | None = Field(None, max_length=50_000)
    disposition: HuntDisposition | None = None
    tlp: TLP | None = None

    @field_validator("technique_ids")
    @classmethod
    def validate_techniques(cls, value: list[str] | None) -> list[str] | None:
        return clean_techniques(value) if value is not None else None

    @field_validator("tactics", "telemetry_sources", "required_fields", "tags")
    @classmethod
    def normalize_lists(cls, value: list[str] | None) -> list[str] | None:
        return clean_list(value) if value is not None else None

    @field_validator("time_range_start", "time_range_end")
    @classmethod
    def require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("Hunt time ranges must include an explicit timezone")
        return value

    @model_validator(mode="after")
    def reject_explicit_nulls(self):
        nullable = {"time_range_start", "time_range_end"}
        invalid = sorted(
            field
            for field in self.model_fields_set
            if field not in nullable and getattr(self, field) is None
        )
        if invalid:
            raise ValueError(f"Fields cannot be null: {', '.join(invalid)}")
        return self


class HuntOut(HuntBody):
    id: UUID
    case_id: UUID | None
    source_type: str
    source_ref: str
    created_by: str
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None
    archived_at: datetime | None

    model_config = {"from_attributes": True}


class FindingBody(BaseModel):
    model_config = {"extra": "forbid"}

    title: str = Field(..., min_length=3, max_length=500)
    summary: str = Field("", max_length=20_000)
    severity: FindingSeverity = "informational"
    confidence: int = Field(50, ge=0, le=100)
    status: FindingStatus = "new"
    verdict: FindingVerdict = "inconclusive"
    evidence_type: str = Field("event", min_length=2, max_length=80)
    evidence_ref: str = Field("", max_length=500)
    event_time: datetime | None = None
    observables: list[str] = Field(default_factory=list, max_length=500)
    technique_ids: list[str] = Field(default_factory=list, max_length=100)
    query_version_id: UUID | None = None
    tlp: TLP | None = None
    notes: str = Field("", max_length=20_000)

    @field_validator("technique_ids")
    @classmethod
    def validate_techniques(cls, value: list[str]) -> list[str]:
        return clean_techniques(value)

    @field_validator("observables")
    @classmethod
    def normalize_observables(cls, value: list[str]) -> list[str]:
        return clean_list(value, max_item_length=1_000)

    @field_validator("event_time")
    @classmethod
    def require_event_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("event_time must include an explicit timezone")
        return value


class FindingPatch(BaseModel):
    model_config = {"extra": "forbid"}

    title: str | None = Field(None, min_length=3, max_length=500)
    summary: str | None = Field(None, max_length=20_000)
    severity: FindingSeverity | None = None
    confidence: int | None = Field(None, ge=0, le=100)
    status: FindingStatus | None = None
    verdict: FindingVerdict | None = None
    evidence_type: str | None = Field(None, min_length=2, max_length=80)
    evidence_ref: str | None = Field(None, max_length=500)
    event_time: datetime | None = None
    observables: list[str] | None = Field(None, max_length=500)
    technique_ids: list[str] | None = Field(None, max_length=100)
    query_version_id: UUID | None = None
    tlp: TLP | None = None
    notes: str | None = Field(None, max_length=20_000)

    @field_validator("technique_ids")
    @classmethod
    def validate_techniques(cls, value: list[str] | None) -> list[str] | None:
        return clean_techniques(value) if value is not None else None

    @field_validator("observables")
    @classmethod
    def normalize_observables(cls, value: list[str] | None) -> list[str] | None:
        return clean_list(value, max_item_length=1_000) if value is not None else None

    @field_validator("event_time")
    @classmethod
    def require_event_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("event_time must include an explicit timezone")
        return value

    @model_validator(mode="after")
    def reject_explicit_nulls(self):
        nullable = {"event_time", "query_version_id"}
        invalid = sorted(
            field
            for field in self.model_fields_set
            if field not in nullable and getattr(self, field) is None
        )
        if invalid:
            raise ValueError(f"Fields cannot be null: {', '.join(invalid)}")
        return self


class FindingOut(FindingBody):
    id: UUID
    hunt_id: UUID
    analyst: str
    tlp: TLP
    created_at: datetime
    updated_at: datetime
    archived_at: datetime | None

    model_config = {"from_attributes": True}


class QueryVersionOut(BaseModel):
    id: UUID
    hunt_id: UUID
    version: int
    language: str
    query_text: str
    backend_assumptions: str
    checksum: str
    created_by: str
    created_at: datetime

    model_config = {"from_attributes": True}


class HuntDetail(HuntOut):
    findings: list[FindingOut]
    query_versions: list[QueryVersionOut]


class HuntStats(BaseModel):
    total_hunts: int
    active_hunts: int
    completed_hunts: int
    total_findings: int
    high_priority_findings: int
    by_status: dict[str, int]
    by_priority: dict[str, int]


class HuntTemplate(BaseModel):
    id: str
    title: str
    hypothesis: str
    description: str
    technique_ids: list[str]
    tactics: list[str]
    telemetry_sources: list[str]
    required_fields: list[str]
    query_language: str
    query_text: str
    query_note: str
    expected_evidence: str
    false_positive_notes: str
    tags: list[str]


@router.get("/templates", response_model=list[HuntTemplate])
async def templates(_: TeamUser = Depends(analyst)) -> list[dict[str, Any]]:
    note = (
        "Implementation-independent example only. Review fields, syntax, scope, and cost "
        "before translating it for an approved telemetry backend."
    )
    return [{**template, "query_note": note} for template in hunts.HUNT_TEMPLATES]


@router.get("/stats", response_model=HuntStats)
async def stats(
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
) -> dict[str, Any]:
    return await hunts.get_stats(db)


@router.get("/hunts", response_model=list[HuntOut])
async def list_hunts(
    q: str = Query("", max_length=500),
    status: HuntStatus | None = None,
    priority: HuntPriority | None = None,
    technique_id: str = Query("", max_length=20),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
) -> list[ThreatHuntRequest]:
    if technique_id and not ATTACK_ID.fullmatch(technique_id.upper()):
        raise HTTPException(422, "technique_id must be an ATT&CK technique ID such as T1059.001")
    return await hunts.list_hunts(
        db,
        q=q,
        status=status or "",
        priority=priority or "",
        technique_id=technique_id,
        limit=limit,
        offset=offset,
    )


@router.post("/hunts", response_model=HuntOut, status_code=201)
async def create_hunt(
    body: HuntBody,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
) -> ThreatHuntRequest:
    hunt = await hunts.create_hunt(db, body.model_dump(), user.name)
    await audit(
        db,
        user,
        "threat_hunting.create",
        "threat_hunt",
        str(hunt.id),
        {"source_type": hunt.source_type, "technique_ids": hunt.technique_ids},
    )
    await db.commit()
    await db.refresh(hunt)
    return hunt


@router.get("/hunts/{hunt_id}", response_model=HuntDetail)
async def get_hunt(
    hunt_id: UUID,
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
) -> dict[str, Any]:
    hunt = await hunts.get_hunt(db, hunt_id)
    findings = await hunts.list_findings(db, hunt_id)
    versions = await hunts.list_query_versions(db, hunt_id)
    payload = HuntOut.model_validate(hunt).model_dump()
    payload["findings"] = [FindingOut.model_validate(item).model_dump() for item in findings]
    payload["query_versions"] = [QueryVersionOut.model_validate(item).model_dump() for item in versions]
    return payload


@router.patch("/hunts/{hunt_id}", response_model=HuntOut)
async def update_hunt(
    hunt_id: UUID,
    body: HuntPatch,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
) -> ThreatHuntRequest:
    hunt = await hunts.update_hunt(
        db,
        hunt_id,
        body.model_dump(exclude_unset=True),
        user.name,
    )
    await audit(
        db,
        user,
        "threat_hunting.update",
        "threat_hunt",
        str(hunt.id),
        {"status": hunt.status, "disposition": hunt.disposition, "tlp": hunt.tlp},
    )
    await db.commit()
    await db.refresh(hunt)
    return hunt


@router.post("/hunts/{hunt_id}/archive", response_model=HuntOut)
async def archive_hunt(
    hunt_id: UUID,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
) -> ThreatHuntRequest:
    hunt = await hunts.archive_hunt(db, hunt_id)
    await audit(db, user, "threat_hunting.archive", "threat_hunt", str(hunt.id))
    await db.commit()
    await db.refresh(hunt)
    return hunt


@router.delete("/hunts/{hunt_id}", status_code=204, deprecated=True)
async def archive_hunt_legacy(
    hunt_id: UUID,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
) -> Response:
    await hunts.archive_hunt(db, hunt_id)
    await audit(db, user, "threat_hunting.archive", "threat_hunt", str(hunt_id))
    await db.commit()
    return Response(status_code=204, headers={"Deprecation": "true"})


@router.get("/hunts/{hunt_id}/query-versions", response_model=list[QueryVersionOut])
async def query_versions(
    hunt_id: UUID,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
) -> list[ThreatHuntQueryVersion]:
    return await hunts.list_query_versions(db, hunt_id, limit=limit, offset=offset)


@router.get("/hunts/{hunt_id}/findings", response_model=list[FindingOut])
async def list_findings(
    hunt_id: UUID,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
) -> list[ThreatHuntFinding]:
    return await hunts.list_findings(db, hunt_id, limit=limit, offset=offset)


@router.post("/hunts/{hunt_id}/findings", response_model=FindingOut, status_code=201)
async def create_finding(
    hunt_id: UUID,
    body: FindingBody,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
) -> ThreatHuntFinding:
    finding = await hunts.create_finding(db, hunt_id, body.model_dump(), user.name)
    await audit(
        db,
        user,
        "threat_hunting.finding.create",
        "threat_hunt_finding",
        str(finding.id),
        {"hunt_id": str(hunt_id), "verdict": finding.verdict},
    )
    await db.commit()
    await db.refresh(finding)
    return finding


@router.patch("/hunts/{hunt_id}/findings/{finding_id}", response_model=FindingOut)
async def update_finding(
    hunt_id: UUID,
    finding_id: UUID,
    body: FindingPatch,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
) -> ThreatHuntFinding:
    finding = await hunts.update_finding(
        db,
        hunt_id,
        finding_id,
        body.model_dump(exclude_unset=True),
    )
    await audit(
        db,
        user,
        "threat_hunting.finding.update",
        "threat_hunt_finding",
        str(finding.id),
        {"hunt_id": str(hunt_id), "status": finding.status, "verdict": finding.verdict},
    )
    await db.commit()
    await db.refresh(finding)
    return finding


@router.post("/hunts/{hunt_id}/findings/{finding_id}/archive", response_model=FindingOut)
async def archive_finding(
    hunt_id: UUID,
    finding_id: UUID,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
) -> ThreatHuntFinding:
    finding = await hunts.archive_finding(db, hunt_id, finding_id, user.name)
    await audit(
        db,
        user,
        "threat_hunting.finding.archive",
        "threat_hunt_finding",
        str(finding.id),
        {"hunt_id": str(hunt_id)},
    )
    await db.commit()
    await db.refresh(finding)
    return finding


@router.delete("/hunts/{hunt_id}/findings/{finding_id}", status_code=204, deprecated=True)
async def archive_finding_legacy(
    hunt_id: UUID,
    finding_id: UUID,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
) -> Response:
    await hunts.archive_finding(db, hunt_id, finding_id, user.name)
    await audit(
        db,
        user,
        "threat_hunting.finding.archive",
        "threat_hunt_finding",
        str(finding_id),
        {"hunt_id": str(hunt_id)},
    )
    await db.commit()
    return Response(status_code=204, headers={"Deprecation": "true"})


@router.get("/hunts/{hunt_id}/export")
async def export_hunt(
    hunt_id: UUID,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(export_threat_hunt),
) -> dict[str, Any]:
    hunt = await hunts.get_hunt(db, hunt_id)
    findings = await hunts.list_findings(db, hunt_id, include_archived=True)
    versions = await hunts.list_query_versions(db, hunt_id)
    await audit(
        db,
        user,
        "threat_hunting.export",
        "threat_hunt",
        str(hunt.id),
        {"tlp": hunt.tlp, "query_versions": len(versions), "findings": len(findings)},
    )
    await db.commit()
    return {
        "schema": "adversarygraph-threat-hunt-v1",
        "platform_version": APP_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "execution_boundary": (
            "AdversaryGraph preserved this hunt plan and evidence; it did not execute the query "
            "unless a separately recorded connector run is attached."
        ),
        "hunt": HuntOut.model_validate(hunt).model_dump(mode="json"),
        "query_versions": [
            QueryVersionOut.model_validate(item).model_dump(mode="json") for item in versions
        ],
        "findings": [FindingOut.model_validate(item).model_dump(mode="json") for item in findings],
    }
