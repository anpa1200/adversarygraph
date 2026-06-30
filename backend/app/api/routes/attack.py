from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_session
from app.models.attack import AttackVersion, StixObject, StixRelationship, Tactic, Technique
from app.services.auth import TeamUser, current_user
from app.services.telemetry_readiness import build_telemetry_readiness

router = APIRouter(prefix="/attack", tags=["ATT&CK"])

# ── Canonical ATT&CK kill-chain tactic order ──────────────────────────────────
# Shortname → sort position (0-based).
# Two-level fallback for unknown tactics:
#   1. TA0043 (Reconnaissance) and TA0042 (Resource Development) → prepend
#   2. All other unknown IDs → numeric order after known tactics
_TACTIC_SHORTNAME_POS: dict[str, int] = {
    # Enterprise pre-attack
    "reconnaissance":              0,
    "resource-development":        1,
    # Enterprise main chain
    "initial-access":              2,
    "execution":                   3,
    "persistence":                 4,
    "privilege-escalation":        5,
    "stealth":                     6,   # v19: new tactic after priv-esc
    "defense-evasion":             7,
    "defense-impairment":          8,   # v19: new tactic near defense-evasion
    "credential-access":           9,
    "discovery":                   10,
    "lateral-movement":            11,
    "collection":                  12,
    "command-and-control":         13,
    "exfiltration":                14,
    "impact":                      15,
    # Mobile-specific
    "network-based-exploitation":  2,
    "supply-chain-compromise":     1,
    # ICS-specific
    "impair-process-control":      13,
    "inhibit-response-function":   14,
    "evasion":                     7,
}

# TA ID number → forced sort position for well-known cases
# (covers tactics whose shortname may differ across STIX versions)
_TACTIC_ID_POS: dict[int, int] = {
    43: 0,   # Reconnaissance
    42: 1,   # Resource Development
    1:  2,   # Initial Access
    2:  3,   # Execution
    3:  4,   # Persistence
    4:  5,   # Privilege Escalation
    5:  7,   # Defense Evasion
    6:  9,   # Credential Access
    7:  10,  # Discovery
    8:  11,  # Lateral Movement
    9:  12,  # Collection
    11: 13,  # Command and Control
    10: 14,  # Exfiltration
    40: 15,  # Impact
}


def _tactic_sort_key(shortname: str, attack_id: str) -> tuple[int, str]:
    """
    Returns (position, attack_id) so tactics render left→right in kill-chain order.
    Prefers shortname lookup; falls back to numeric TA-ID lookup; then appends at end.
    """
    # 1. Exact shortname match
    pos = _TACTIC_SHORTNAME_POS.get(shortname)
    if pos is not None:
        return (pos, attack_id)

    # 2. TA ID number fallback
    try:
        num = int(attack_id[2:])   # "TA0043" → 43
        id_pos = _TACTIC_ID_POS.get(num)
        if id_pos is not None:
            return (id_pos, attack_id)
        # Unknown ID: append after known tactics
        return (50 + num, attack_id)
    except (ValueError, IndexError):
        pass

    return (999, attack_id)


# ── Pydantic response schemas ─────────────────────────────────────────────────

class VersionOut(BaseModel):
    domain: str
    version: str
    is_latest: bool

    model_config = {"from_attributes": True}


class TacticOut(BaseModel):
    attack_id: str
    name: str
    shortname: str
    description: str
    url: str
    domain: str
    technique_count: int = 0

    model_config = {"from_attributes": True}


class TechniqueListItem(BaseModel):
    attack_id: str
    name: str
    is_subtechnique: bool
    parent_attack_id: str | None
    tactics: list[str]
    platforms: list[str]
    domain: str

    model_config = {"from_attributes": True}


class TelemetryReadinessOut(BaseModel):
    required_data_components: list[str]
    available_logs: list[str]
    missing_telemetry: list[str]
    detection_feasibility: str
    readiness_score: int
    gaps: list[str]


class TechniqueDetail(TechniqueListItem):
    stix_id: str
    description: str
    url: str
    data_sources: list[str]
    detection: str
    telemetry_readiness: TelemetryReadinessOut


class StixObjectOut(BaseModel):
    stix_id: str
    stix_type: str
    attack_id: str | None
    name: str
    domain: str
    is_deprecated: bool
    is_revoked: bool
    raw: dict


class StixRelationshipOut(BaseModel):
    stix_id: str
    relationship_type: str
    source_stix_id: str
    target_stix_id: str
    description: str
    references: list[dict]
    domain: str
    raw: dict


class StixGraphOut(BaseModel):
    object: StixObjectOut
    incoming: list[StixRelationshipOut]
    outgoing: list[StixRelationshipOut]


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/versions", response_model=list[VersionOut])
async def list_versions(session: AsyncSession = Depends(get_session), _: TeamUser = Depends(current_user)):
    rows = await session.execute(select(AttackVersion).order_by(AttackVersion.domain))
    return [VersionOut(domain=v.domain, version=v.version, is_latest=v.is_latest)
            for v in rows.scalars()]


@router.get("/tactics", response_model=list[TacticOut])
async def list_tactics(
    domain: str = Query("enterprise-attack"),
    version: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
):
    ver_id = await _resolve_version_id(session, domain, version)

    rows = await session.execute(
        select(Tactic)
        .where(Tactic.version_id == ver_id)
        .options(selectinload(Tactic.techniques))
    )
    tactics = rows.scalars().all()

    # Sort by official ATT&CK kill-chain order, not alphabetically
    tactics = sorted(
        tactics,
        key=lambda t: _tactic_sort_key(t.shortname, t.attack_id),
    )

    return [
        TacticOut(
            attack_id=t.attack_id,
            name=t.name,
            shortname=t.shortname,
            description=t.description,
            url=t.url,
            domain=t.domain,
            technique_count=len(t.techniques),
        )
        for t in tactics
    ]


@router.get("/techniques", response_model=list[TechniqueListItem])
async def list_techniques(
    domain: str = Query("enterprise-attack"),
    version: str | None = Query(None),
    tactic: str | None = Query(None, description="Filter by tactic shortname, e.g. initial-access"),
    platform: str | None = Query(None, description="Filter by platform, e.g. Windows"),
    subtechniques: bool = Query(True),
    search: str | None = Query(None, description="Partial name/ID search"),
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
):
    ver_id = await _resolve_version_id(session, domain, version)

    stmt = (
        select(Technique)
        .where(Technique.version_id == ver_id)
        .options(selectinload(Technique.tactics))
    )

    if not subtechniques:
        stmt = stmt.where(Technique.is_subtechnique.is_(False))

    if search:
        term = f"%{search}%"
        stmt = stmt.where(
            Technique.name.ilike(term) | Technique.attack_id.ilike(term)
        )

    if platform:
        stmt = stmt.where(Technique.platforms.contains([platform]))

    rows = await session.execute(stmt.order_by(Technique.attack_id))
    all_techs = rows.scalars().all()

    # Filter by tactic after loading (avoids complex join for now)
    if tactic:
        all_techs = [
            t for t in all_techs
            if any(tc.shortname == tactic for tc in t.tactics)
        ]

    return [_technique_to_list_item(t) for t in all_techs]


@router.get("/techniques/{attack_id}", response_model=TechniqueDetail)
async def get_technique(
    attack_id: str,
    domain: str = Query("enterprise-attack"),
    version: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
):
    ver_id = await _resolve_version_id(session, domain, version)

    row = await session.execute(
        select(Technique)
        .where(
            Technique.attack_id == attack_id.upper(),
            Technique.version_id == ver_id,
        )
        .options(selectinload(Technique.tactics))
    )
    tech = row.scalar_one_or_none()
    if not tech:
        raise HTTPException(404, f"Technique {attack_id} not found")

    tactics = [t.shortname for t in tech.tactics]
    platforms = tech.platforms or []
    data_sources = tech.data_sources or []
    readiness = build_telemetry_readiness(
        tech.attack_id,
        tech.name,
        tactics,
        platforms,
        data_sources,
    )

    return TechniqueDetail(
        attack_id=tech.attack_id,
        stix_id=tech.stix_id,
        name=tech.name,
        description=tech.description,
        url=tech.url,
        is_subtechnique=tech.is_subtechnique,
        parent_attack_id=tech.parent_attack_id,
        tactics=tactics,
        platforms=platforms,
        data_sources=data_sources,
        detection=tech.detection or "",
        domain=tech.domain,
        telemetry_readiness=TelemetryReadinessOut(
            required_data_components=readiness.required_data_components,
            available_logs=readiness.available_logs,
            missing_telemetry=readiness.missing_telemetry,
            detection_feasibility=readiness.detection_feasibility,
            readiness_score=readiness.readiness_score,
            gaps=readiness.gaps,
        ),
    )


@router.get("/stix/objects/{stix_id}", response_model=StixObjectOut)
async def get_stix_object(
    stix_id: str,
    domain: str = Query("enterprise-attack"),
    version: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
):
    ver_id = await _resolve_version_id(session, domain, version)
    row = await session.execute(
        select(StixObject).where(
            StixObject.stix_id == stix_id,
            StixObject.version_id == ver_id,
        )
    )
    obj = row.scalar_one_or_none()
    if not obj:
        raise HTTPException(404, f"STIX object {stix_id} not found")
    return _stix_object_out(obj)


@router.get("/stix/objects/{stix_id}/graph", response_model=StixGraphOut)
async def get_stix_object_graph(
    stix_id: str,
    domain: str = Query("enterprise-attack"),
    version: str | None = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
):
    ver_id = await _resolve_version_id(session, domain, version)
    row = await session.execute(
        select(StixObject).where(
            StixObject.stix_id == stix_id,
            StixObject.version_id == ver_id,
        )
    )
    obj = row.scalar_one_or_none()
    if not obj:
        raise HTTPException(404, f"STIX object {stix_id} not found")

    incoming_rows = await session.execute(
        select(StixRelationship)
        .where(
            StixRelationship.target_stix_id == stix_id,
            StixRelationship.version_id == ver_id,
        )
        .order_by(StixRelationship.relationship_type, StixRelationship.stix_id)
        .limit(limit)
    )
    outgoing_rows = await session.execute(
        select(StixRelationship)
        .where(
            StixRelationship.source_stix_id == stix_id,
            StixRelationship.version_id == ver_id,
        )
        .order_by(StixRelationship.relationship_type, StixRelationship.stix_id)
        .limit(limit)
    )
    return StixGraphOut(
        object=_stix_object_out(obj),
        incoming=[_stix_relationship_out(rel) for rel in incoming_rows.scalars()],
        outgoing=[_stix_relationship_out(rel) for rel in outgoing_rows.scalars()],
    )


@router.get("/stix/relationships", response_model=list[StixRelationshipOut])
async def list_stix_relationships(
    domain: str = Query("enterprise-attack"),
    version: str | None = Query(None),
    source_stix_id: str | None = Query(None),
    target_stix_id: str | None = Query(None),
    relationship_type: str | None = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
):
    ver_id = await _resolve_version_id(session, domain, version)
    stmt = select(StixRelationship).where(StixRelationship.version_id == ver_id)
    if source_stix_id:
        stmt = stmt.where(StixRelationship.source_stix_id == source_stix_id)
    if target_stix_id:
        stmt = stmt.where(StixRelationship.target_stix_id == target_stix_id)
    if relationship_type:
        stmt = stmt.where(StixRelationship.relationship_type == relationship_type)
    rows = await session.execute(
        stmt.order_by(StixRelationship.relationship_type, StixRelationship.stix_id).limit(limit)
    )
    return [_stix_relationship_out(rel) for rel in rows.scalars()]


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _resolve_version_id(
    session: AsyncSession, domain: str, version: str | None
) -> int:
    if version:
        row = await session.execute(
            select(AttackVersion.id).where(
                AttackVersion.domain == domain,
                AttackVersion.version == version,
            )
        )
    else:
        row = await session.execute(
            select(AttackVersion.id).where(
                AttackVersion.domain == domain,
                AttackVersion.is_latest.is_(True),
            )
        )
    ver_id = row.scalar_one_or_none()
    if not ver_id:
        raise HTTPException(404, f"No ATT&CK data for domain '{domain}'. Run ingestion first.")
    return ver_id


def _technique_to_list_item(t: Technique) -> TechniqueListItem:
    return TechniqueListItem(
        attack_id=t.attack_id,
        name=t.name,
        is_subtechnique=t.is_subtechnique,
        parent_attack_id=t.parent_attack_id,
        tactics=[tc.shortname for tc in t.tactics],
        platforms=t.platforms or [],
        domain=t.domain,
    )


def _stix_object_out(obj: StixObject) -> StixObjectOut:
    return StixObjectOut(
        stix_id=obj.stix_id,
        stix_type=obj.stix_type,
        attack_id=obj.attack_id,
        name=obj.name,
        domain=obj.domain,
        is_deprecated=obj.is_deprecated,
        is_revoked=obj.is_revoked,
        raw=obj.raw or {},
    )


def _stix_relationship_out(rel: StixRelationship) -> StixRelationshipOut:
    return StixRelationshipOut(
        stix_id=rel.stix_id,
        relationship_type=rel.relationship_type,
        source_stix_id=rel.source_stix_id,
        target_stix_id=rel.target_stix_id,
        description=rel.description or "",
        references=rel.references or [],
        domain=rel.domain,
        raw=rel.raw or {},
    )
