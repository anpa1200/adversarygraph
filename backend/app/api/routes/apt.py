from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import String, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_session
from app.models.attack import (
    AptGroup, AptGroupTechnique, AptGroupCampaign,
    AttackVersion, Campaign, CampaignTechnique, Technique,
)

router = APIRouter(prefix="/apt", tags=["ATT&CK Group Profiles"])


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class GroupListItem(BaseModel):
    attack_id: str
    name: str
    aliases: list[str]
    description: str = ""
    modified: str = ""
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
    references: list[dict] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class ExternalReference(BaseModel):
    source_name: str
    url: str = ""
    description: str = ""


class CountItem(BaseModel):
    name: str
    count: int


class GroupDetail(BaseModel):
    attack_id: str
    stix_id: str
    name: str
    aliases: list[str]
    description: str
    url: str
    created: str
    modified: str
    attack_version: str
    contributors: list[str]
    external_references: list[ExternalReference]
    domain: str
    technique_count: int
    campaign_count: int
    tactic_counts: list[CountItem]
    platform_counts: list[CountItem]
    source_names: list[str]
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
            AptGroup.name.ilike(term)
            | AptGroup.attack_id.ilike(term)
            | AptGroup.description.ilike(term)
            | cast(AptGroup.aliases, String).ilike(term)
        )

    rows = await session.execute(stmt)
    result = []
    for group, tech_count in rows:
        result.append(GroupListItem(
            attack_id=group.attack_id,
            name=group.name,
            aliases=group.aliases or [],
            description=group.description or "",
            modified=group.modified or "",
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
    tactic_counts: dict[str, int] = {}
    platform_counts: dict[str, int] = {}
    source_names: set[str] = set()
    for agt in group.technique_usages:
        t = agt.technique
        tactics = [tc.shortname for tc in t.tactics]
        for tactic in tactics:
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
        for platform in t.platforms or []:
            platform_counts[platform] = platform_counts.get(platform, 0) + 1
        for ref in agt.references or []:
            if ref.get("source_name"):
                source_names.add(str(ref["source_name"]))
        usages.append(TechniqueUsage(
            attack_id=t.attack_id,
            name=t.name,
            tactics=tactics,
            platforms=t.platforms or [],
            is_subtechnique=t.is_subtechnique,
            use_description=agt.use_description or "",
            references=agt.references or [],
        ))
    usages.sort(key=lambda u: u.attack_id)

    campaign_count = await session.scalar(
        select(func.count(AptGroupCampaign.id)).where(AptGroupCampaign.group_id == group.id)
    )

    return GroupDetail(
        attack_id=group.attack_id,
        stix_id=group.stix_id,
        name=group.name,
        aliases=group.aliases or [],
        description=group.description or "",
        url=group.url or "",
        created=group.created or "",
        modified=group.modified or "",
        attack_version=group.attack_version or "",
        contributors=group.contributors or [],
        external_references=[
            ExternalReference(
                source_name=str(ref.get("source_name", "")),
                url=str(ref.get("url", "")),
                description=str(ref.get("description", "")),
            )
            for ref in (group.external_references or [])
        ],
        domain=group.domain,
        technique_count=len(usages),
        campaign_count=campaign_count or 0,
        tactic_counts=[
            CountItem(name=name, count=count)
            for name, count in sorted(tactic_counts.items(), key=lambda item: item[1], reverse=True)
        ],
        platform_counts=[
            CountItem(name=name, count=count)
            for name, count in sorted(platform_counts.items(), key=lambda item: item[1], reverse=True)
        ],
        source_names=sorted(source_names),
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
    Given a list of ATT&CK technique IDs, return the top-N group profiles
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


# ── Campaign schemas ──────────────────────────────────────────────────────────

class CampaignListItem(BaseModel):
    attack_id: str
    name: str
    description: str
    url: str
    first_seen: str | None
    last_seen: str | None
    domain: str
    technique_count: int
    group_names: list[str]


class CampaignTechniqueOut(BaseModel):
    attack_id: str
    name: str
    tactics: list[str]
    platforms: list[str]
    is_subtechnique: bool
    use_description: str


class CampaignDetail(CampaignListItem):
    techniques: list[CampaignTechniqueOut]


class CampaignResult(BaseModel):
    campaign_attack_id: str
    campaign_name: str
    group_names: list[str]
    first_seen: str | None
    last_seen: str | None
    similarity: float
    shared_count: int
    shared_techniques: list[str]


class CampaignCompareRequest(BaseModel):
    technique_ids: list[str] = Field(..., min_length=1, max_length=500)


# ── Campaign endpoints ────────────────────────────────────────────────────────

@router.get("/campaigns", response_model=list[CampaignListItem])
async def list_campaigns(
    domain: str = Query("enterprise-attack"),
    version: str | None = Query(None),
    group_id: str | None = Query(None, description="Filter by group ATT&CK ID, e.g. G0016"),
    search: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
):
    """
    List ATT&CK campaigns (DB 1 — named MITRE operations).
    Optionally filter by attributed group or search by name.
    """
    ver_id = await _resolve_version_id(session, domain, version)

    stmt = (
        select(Campaign)
        .where(Campaign.version_id == ver_id)
        .options(
            selectinload(Campaign.technique_usages).selectinload(CampaignTechnique.technique),
            selectinload(Campaign.groups),
        )
    )

    if search:
        stmt = stmt.where(Campaign.name.ilike(f"%{search}%"))

    rows = await session.execute(stmt)
    all_campaigns = rows.scalars().all()

    # Filter by attributed group after loading
    if group_id:
        gid_upper = group_id.upper()
        all_campaigns = [c for c in all_campaigns if any(g.attack_id == gid_upper for g in c.groups)]

    return [
        CampaignListItem(
            attack_id=c.attack_id,
            name=c.name,
            description=c.description,
            url=c.url,
            first_seen=c.first_seen,
            last_seen=c.last_seen,
            domain=c.domain,
            technique_count=len(c.technique_usages),
            group_names=[g.name for g in c.groups],
        )
        for c in sorted(all_campaigns, key=lambda c: c.name)
    ]


@router.get("/campaigns/{attack_id}", response_model=CampaignDetail)
async def get_campaign(
    attack_id: str,
    domain: str = Query("enterprise-attack"),
    version: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
):
    """Full campaign detail with all techniques and attributed groups."""
    ver_id = await _resolve_version_id(session, domain, version)

    row = await session.execute(
        select(Campaign)
        .where(Campaign.attack_id == attack_id.upper(), Campaign.version_id == ver_id)
        .options(
            selectinload(Campaign.technique_usages)
            .selectinload(CampaignTechnique.technique)
            .selectinload(Technique.tactics),
            selectinload(Campaign.groups),
        )
    )
    camp = row.scalar_one_or_none()
    if not camp:
        raise HTTPException(404, f"Campaign {attack_id} not found")

    techniques = sorted(
        [
            CampaignTechniqueOut(
                attack_id=ct.technique.attack_id,
                name=ct.technique.name,
                tactics=[tc.shortname for tc in ct.technique.tactics],
                platforms=ct.technique.platforms or [],
                is_subtechnique=ct.technique.is_subtechnique,
                use_description=ct.use_description or "",
            )
            for ct in camp.technique_usages
        ],
        key=lambda t: t.attack_id,
    )

    return CampaignDetail(
        attack_id=camp.attack_id,
        name=camp.name,
        description=camp.description,
        url=camp.url,
        first_seen=camp.first_seen,
        last_seen=camp.last_seen,
        domain=camp.domain,
        technique_count=len(techniques),
        group_names=[g.name for g in camp.groups],
        techniques=techniques,
    )


@router.post("/campaigns/compare", response_model=list[CampaignResult])
async def compare_campaigns(
    req: CampaignCompareRequest,
    domain: str = Query("enterprise-attack"),
    version: str | None = Query(None),
    top_n: int = Query(20, le=100),
    session: AsyncSession = Depends(get_session),
):
    """
    Given a list of technique IDs, rank every ATT&CK campaign (DB 1)
    by Jaccard similarity.  Returns at most top_n results.
    """
    ver_id = await _resolve_version_id(session, domain, version)
    user_set = {t.upper() for t in req.technique_ids}

    # Load all campaign→technique mappings + group names in one query
    rows = await session.execute(
        select(Campaign.attack_id, Campaign.name, Campaign.first_seen, Campaign.last_seen,
               AptGroup.name, Technique.attack_id)
        .join(CampaignTechnique, CampaignTechnique.campaign_id == Campaign.id)
        .join(Technique, Technique.id == CampaignTechnique.technique_id)
        .outerjoin(AptGroupCampaign, AptGroupCampaign.campaign_id == Campaign.id)
        .outerjoin(AptGroup, AptGroup.id == AptGroupCampaign.group_id)
        .where(Campaign.version_id == ver_id)
    )

    camp_data: dict[str, dict] = {}
    for c_id, c_name, c_first, c_last, g_name, t_id in rows:
        if c_id not in camp_data:
            camp_data[c_id] = {
                "name": c_name,
                "first_seen": c_first,
                "last_seen": c_last,
                "groups": set(),
                "techs": set(),
            }
        camp_data[c_id]["techs"].add(t_id)
        if g_name:
            camp_data[c_id]["groups"].add(g_name)

    results = []
    for c_id, info in camp_data.items():
        shared = user_set & info["techs"]
        union  = user_set | info["techs"]
        if not union:
            continue
        results.append(CampaignResult(
            campaign_attack_id=c_id,
            campaign_name=info["name"],
            group_names=sorted(info["groups"]),
            first_seen=info["first_seen"],
            last_seen=info["last_seen"],
            similarity=round(len(shared) / len(union), 4),
            shared_count=len(shared),
            shared_techniques=sorted(shared),
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
