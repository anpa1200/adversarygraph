from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_session
from app.models.attack import AttackVersion, Tactic, Technique

router = APIRouter(prefix="/attack", tags=["ATT&CK"])


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


class TechniqueDetail(TechniqueListItem):
    stix_id: str
    description: str
    url: str
    data_sources: list[str]
    detection: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/versions", response_model=list[VersionOut])
async def list_versions(session: AsyncSession = Depends(get_session)):
    rows = await session.execute(select(AttackVersion).order_by(AttackVersion.domain))
    return [VersionOut(domain=v.domain, version=v.version, is_latest=v.is_latest)
            for v in rows.scalars()]


@router.get("/tactics", response_model=list[TacticOut])
async def list_tactics(
    domain: str = Query("enterprise-attack"),
    version: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
):
    ver_id = await _resolve_version_id(session, domain, version)

    rows = await session.execute(
        select(Tactic)
        .where(Tactic.version_id == ver_id)
        .options(selectinload(Tactic.techniques))
        .order_by(Tactic.name)
    )
    result = []
    for tactic in rows.scalars():
        result.append(TacticOut(
            attack_id=tactic.attack_id,
            name=tactic.name,
            shortname=tactic.shortname,
            description=tactic.description,
            url=tactic.url,
            domain=tactic.domain,
            technique_count=len(tactic.techniques),
        ))
    return result


@router.get("/techniques", response_model=list[TechniqueListItem])
async def list_techniques(
    domain: str = Query("enterprise-attack"),
    version: str | None = Query(None),
    tactic: str | None = Query(None, description="Filter by tactic shortname, e.g. initial-access"),
    platform: str | None = Query(None, description="Filter by platform, e.g. Windows"),
    subtechniques: bool = Query(True),
    search: str | None = Query(None, description="Partial name/ID search"),
    session: AsyncSession = Depends(get_session),
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

    return TechniqueDetail(
        attack_id=tech.attack_id,
        stix_id=tech.stix_id,
        name=tech.name,
        description=tech.description,
        url=tech.url,
        is_subtechnique=tech.is_subtechnique,
        parent_attack_id=tech.parent_attack_id,
        tactics=[t.shortname for t in tech.tactics],
        platforms=tech.platforms or [],
        data_sources=tech.data_sources or [],
        detection=tech.detection or "",
        domain=tech.domain,
    )


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
