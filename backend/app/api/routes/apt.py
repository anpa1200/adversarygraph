from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_session
from app.models.attack import AttackVersion, AptGroup, AptGroupTechnique, Technique

router = APIRouter(prefix="/apt", tags=["APT Groups"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class GroupListItem(BaseModel):
    attack_id: str
    name: str
    aliases: list[str]
    domain: str
    technique_count: int

    model_config = {"from_attributes": True}


class TechniqueUsage(BaseModel):
    attack_id: str
    name: str
    tactics: list[str]
    platforms: list[str]
    is_subtechnique: bool
    use_description: str

    model_config = {"from_attributes": True}


class GroupDetail(BaseModel):
    attack_id: str
    name: str
    aliases: list[str]
    description: str
    url: str
    domain: str
    technique_count: int
    techniques: list[TechniqueUsage]

    model_config = {"from_attributes": True}


class CompareResult(BaseModel):
    group_attack_id: str
    group_name: str
    similarity: float          # Jaccard index 0-1
    shared_count: int
    shared_techniques: list[str]   # ATT&CK IDs


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/groups", response_model=list[GroupListItem])
async def list_groups(
    domain: str = Query("enterprise-attack"),
    version: str | None = Query(None),
    search: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
):
    ver_id = await _resolve_version_id(session, domain, version)

    stmt = (
        select(
            AptGroup,
            func.count(AptGroupTechnique.id).label("technique_count"),
        )
        .outerjoin(AptGroupTechnique, AptGroupTechnique.group_id == AptGroup.id)
        .where(AptGroup.version_id == ver_id)
        .group_by(AptGroup.id)
        .order_by(AptGroup.name)
    )

    if search:
        term = f"%{search}%"
        stmt = stmt.where(
            AptGroup.name.ilike(term) | AptGroup.attack_id.ilike(term)
        )

    rows = await session.execute(stmt)
    result = []
    for group, tech_count in rows:
        result.append(GroupListItem(
            attack_id=group.attack_id,
            name=group.name,
            aliases=group.aliases or [],
            domain=group.domain,
            technique_count=tech_count,
        ))
    return result


@router.get("/groups/{attack_id}", response_model=GroupDetail)
async def get_group(
    attack_id: str,
    domain: str = Query("enterprise-attack"),
    version: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
):
    ver_id = await _resolve_version_id(session, domain, version)

    row = await session.execute(
        select(AptGroup)
        .where(
            AptGroup.attack_id == attack_id.upper(),
            AptGroup.version_id == ver_id,
        )
        .options(
            selectinload(AptGroup.technique_usages).selectinload(
                AptGroupTechnique.technique
            ).selectinload(Technique.tactics)
        )
    )
    group = row.scalar_one_or_none()
    if not group:
        raise HTTPException(404, f"Group {attack_id} not found")

    usages = []
    for agt in group.technique_usages:
        t = agt.technique
        usages.append(TechniqueUsage(
            attack_id=t.attack_id,
            name=t.name,
            tactics=[tc.shortname for tc in t.tactics],
            platforms=t.platforms or [],
            is_subtechnique=t.is_subtechnique,
            use_description=agt.use_description or "",
        ))
    usages.sort(key=lambda u: u.attack_id)

    return GroupDetail(
        attack_id=group.attack_id,
        name=group.name,
        aliases=group.aliases or [],
        description=group.description or "",
        url=group.url or "",
        domain=group.domain,
        technique_count=len(usages),
        techniques=usages,
    )


class CompareRequest(BaseModel):
    technique_ids: list[str] = Field(..., min_length=1, max_length=500)


@router.post("/compare", response_model=list[CompareResult])
async def compare_ttps(
    req: CompareRequest,
    domain: str = Query("enterprise-attack"),
    version: str | None = Query(None),
    top_n: int = Query(10, le=50),
    session: AsyncSession = Depends(get_session),
):
    """
    Given a list of ATT&CK technique IDs, return the top-N APT groups
    ranked by Jaccard similarity.
    """
    technique_ids = req.technique_ids

    ver_id = await _resolve_version_id(session, domain, version)
    user_set = set(t.upper() for t in technique_ids)

    # Load all group→technique mappings for this version in one query
    rows = await session.execute(
        select(AptGroup.attack_id, AptGroup.name, Technique.attack_id)
        .join(AptGroupTechnique, AptGroupTechnique.group_id == AptGroup.id)
        .join(Technique, Technique.id == AptGroupTechnique.technique_id)
        .where(AptGroup.version_id == ver_id)
    )

    group_techs: dict[str, dict] = {}
    for g_attack_id, g_name, t_attack_id in rows:
        if g_attack_id not in group_techs:
            group_techs[g_attack_id] = {"name": g_name, "techniques": set()}
        group_techs[g_attack_id]["techniques"].add(t_attack_id)

    results = []
    for g_attack_id, info in group_techs.items():
        group_set = info["techniques"]
        intersection = user_set & group_set
        union = user_set | group_set
        jaccard = len(intersection) / len(union) if union else 0.0
        results.append(CompareResult(
            group_attack_id=g_attack_id,
            group_name=info["name"],
            similarity=round(jaccard, 4),
            shared_count=len(intersection),
            shared_techniques=sorted(intersection),
        ))

    results.sort(key=lambda r: r.similarity, reverse=True)
    return results[:top_n]


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
        raise HTTPException(
            404,
            f"No ATT&CK data for domain '{domain}'. Trigger ingestion first.",
        )
    return ver_id
