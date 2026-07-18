from __future__ import annotations

import logging
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any

import httpx
from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.attack import (
    AptGroup,
    AptGroupCampaign,
    AptGroupTechnique,
    AttackVersion,
    Campaign,
    Technique,
)
from app.models.sector import ActorIntelObservation, IntelSource

logger = logging.getLogger(__name__)

MISP_THREAT_ACTOR_URL = (
    "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
)

SECTOR_ALIASES: dict[str, str] = {
    "banking": "finance",
    "bank": "finance",
    "financial services": "finance",
    "fintech": "finance",
    "telecommunications": "telecom",
    "telecoms": "telecom",
    "telecomms": "telecom",
    "telco": "telecom",
    "communications": "telecom",
    "government": "government",
    "gov": "government",
    "public sector": "government",
    "defense": "government",
    "military": "government",
    "energy": "energy",
    "oil and gas": "energy",
    "utilities": "energy",
    "health": "healthcare",
    "medical": "healthcare",
    "pharma": "healthcare",
    "pharmaceutical": "healthcare",
    "manufacturing": "manufacturing",
    "industrial": "manufacturing",
    "chemical": "manufacturing",
    "education": "education",
    "university": "education",
    "technology": "technology",
    "software": "technology",
    "saas": "technology",
    "private sector": "private sector",
}

DEFAULT_SECTORS = [
    "telecom",
    "finance",
    "healthcare",
    "energy",
    "government",
    "manufacturing",
    "technology",
    "education",
    "transportation",
    "retail",
    "media",
    "private sector",
]

TECHNOLOGY_OPTIONS = [
    "cloud",
    "kubernetes",
    "microsoft 365",
    "windows",
    "linux",
    "macos",
    "active directory",
    "network devices",
    "containers",
    "identity",
    "email",
    "web",
    "saas",
]

TECHNOLOGY_ALIASES: dict[str, set[str]] = {
    "cloud": {"cloud", "iaas", "paas", "saas", "azure", "aws", "gcp", "office 365", "microsoft 365"},
    "kubernetes": {"kubernetes", "k8s", "container", "containers", "docker"},
    "microsoft 365": {"microsoft 365", "office 365", "m365", "o365", "exchange", "sharepoint", "onedrive", "teams"},
    "windows": {"windows", "powershell", "wmi", "winrm", "registry", "active directory", "domain"},
    "linux": {"linux", "unix", "bash", "ssh", "systemd"},
    "macos": {"macos", "osx", "darwin"},
    "active directory": {"active directory", "domain", "kerberos", "ldap", "windows"},
    "network devices": {"network device", "network devices", "router", "switch", "firewall", "vpn", "esxi"},
    "containers": {"container", "containers", "docker", "kubernetes", "k8s"},
    "identity": {"identity", "credential", "credentials", "account", "oauth", "saml", "kerberos"},
    "email": {"email", "phishing", "smtp", "imap", "exchange", "outlook"},
    "web": {"web", "http", "browser", "application", "public-facing"},
    "saas": {"saas", "cloud", "microsoft 365", "office 365", "google workspace"},
}


@dataclass
class RelevanceInput:
    sectors: list[str]
    regions: list[str] | None = None
    technologies: list[str] | None = None
    days: int = 365
    domain: str = "enterprise-attack"
    limit: int = 25


def normalize_label(value: str) -> str:
    clean = re.sub(r"\s+", " ", value.strip().lower())
    clean = clean.replace("&", "and")
    return SECTOR_ALIASES.get(clean, clean)


def _confidence(meta: dict[str, Any], default: int = 60) -> int:
    try:
        return max(0, min(100, int(meta.get("attribution-confidence", default))))
    except (TypeError, ValueError):
        return default


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    return [str(value)] if str(value).strip() else []


def _actor_keys(group: AptGroup) -> set[str]:
    keys = {normalize_label(group.name), group.attack_id.lower()}
    keys.update(normalize_label(alias) for alias in group.aliases or [])
    return keys


async def ensure_sources(session: AsyncSession) -> None:
    stmt = insert(IntelSource).values(
        source_id="misp-galaxy-threat-actors",
        label="MISP Galaxy Threat Actors",
        kind="github-json",
        url=MISP_THREAT_ACTOR_URL,
        enabled=True,
        sync_status="configured",
    ).on_conflict_do_update(
        index_elements=["source_id"],
        set_={"label": "MISP Galaxy Threat Actors", "url": MISP_THREAT_ACTOR_URL, "enabled": True},
    )
    await session.execute(stmt)
    await session.commit()


async def sync_misp_galaxy(session: AsyncSession) -> dict[str, int | str]:
    """Fetch MISP Galaxy threat actors and store sector/region observations locally."""
    await ensure_sources(session)
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.get(MISP_THREAT_ACTOR_URL)
            response.raise_for_status()
            payload = response.json()
    except Exception as exc:
        await _mark_source(session, "misp-galaxy-threat-actors", "error", str(exc))
        raise

    groups = await _latest_groups(session, "enterprise-attack")
    group_lookup: dict[str, AptGroup] = {}
    for group in groups:
        for key in _actor_keys(group):
            group_lookup[key] = group

    await session.execute(
        delete(ActorIntelObservation).where(
            ActorIntelObservation.source_id == "misp-galaxy-threat-actors"
        )
    )

    inserted = 0
    matched = 0
    for item in payload.get("values", []):
        actor_name = str(item.get("value", "")).strip()
        if not actor_name:
            continue
        meta = item.get("meta") or {}
        aliases = _as_list(meta.get("synonyms"))
        match = None
        for key in [actor_name, *aliases]:
            match = group_lookup.get(normalize_label(key))
            if match:
                break
        if match:
            matched += 1

        refs = _as_list(meta.get("refs"))
        source_url = refs[0] if refs else ""
        confidence = _confidence(meta)
        raw = {
            "uuid": item.get("uuid"),
            "country": meta.get("country"),
            "refs": refs[:8],
            "synonyms": aliases,
        }

        observations: list[tuple[str, str, str]] = []
        for sector in _as_list(meta.get("targeted-sector")):
            observations.append(("sector", sector, f"MISP Galaxy targeted-sector for {actor_name}: {sector}"))
        for sector in _as_list(meta.get("cfr-target-category")):
            observations.append(("sector", sector, f"CFR target category for {actor_name}: {sector}"))
        for victim in _as_list(meta.get("cfr-suspected-victims")):
            observations.append(("region", victim, f"CFR suspected victim geography for {actor_name}: {victim}"))
        if meta.get("country"):
            observations.append(("origin", str(meta["country"]), f"MISP Galaxy actor country/origin metadata: {meta['country']}"))
        if meta.get("cfr-type-of-incident"):
            observations.append(("motivation", str(meta["cfr-type-of-incident"]), f"CFR incident type: {meta['cfr-type-of-incident']}"))

        for obs_type, value, evidence in observations:
            stmt = insert(ActorIntelObservation).values(
                source_id="misp-galaxy-threat-actors",
                actor_attack_id=match.attack_id if match else None,
                actor_name=match.name if match else actor_name,
                observation_type=obs_type,
                value=value,
                normalized_value=normalize_label(value),
                confidence=confidence,
                source_url=source_url,
                evidence=evidence,
                raw=raw,
            ).on_conflict_do_nothing(constraint="uq_actor_intel_observation")
            result = await session.execute(stmt)
            inserted += int(result.rowcount or 0)

    await _mark_source(session, "misp-galaxy-threat-actors", "ok", "")
    await session.commit()
    return {"source": "misp-galaxy-threat-actors", "actors": len(payload.get("values", [])), "matched": matched, "observations": inserted}


async def _mark_source(session: AsyncSession, source_id: str, status: str, error: str) -> None:
    stmt = insert(IntelSource).values(
        source_id=source_id,
        label="MISP Galaxy Threat Actors",
        kind="github-json",
        url=MISP_THREAT_ACTOR_URL,
        enabled=True,
        last_synced_at=datetime.now(timezone.utc),
        sync_status=status,
        sync_error=error[:1000],
    ).on_conflict_do_update(
        index_elements=["source_id"],
        set_={
            "last_synced_at": datetime.now(timezone.utc),
            "sync_status": status,
            "sync_error": error[:1000],
        },
    )
    await session.execute(stmt)


async def _latest_version_id(session: AsyncSession, domain: str) -> int | None:
    row = await session.execute(
        select(AttackVersion.id).where(
            AttackVersion.domain == domain,
            AttackVersion.is_latest.is_(True),
        )
    )
    return row.scalar_one_or_none()


async def _latest_groups(session: AsyncSession, domain: str) -> list[AptGroup]:
    version_id = await _latest_version_id(session, domain)
    if not version_id:
        return []
    rows = await session.execute(
        select(AptGroup)
        .where(AptGroup.version_id == version_id)
        .options(
            selectinload(AptGroup.campaigns),
            selectinload(AptGroup.technique_usages)
            .selectinload(AptGroupTechnique.technique)
            .selectinload(Technique.tactics),
        )
    )
    return list(rows.scalars().all())


async def list_sources(session: AsyncSession) -> list[IntelSource]:
    await ensure_sources(session)
    rows = await session.execute(select(IntelSource).order_by(IntelSource.label))
    return list(rows.scalars().all())


async def list_sectors(session: AsyncSession) -> list[dict[str, Any]]:
    rows = await session.execute(
        select(
            ActorIntelObservation.normalized_value,
            func.count(func.distinct(ActorIntelObservation.actor_name)),
        )
        .where(ActorIntelObservation.observation_type == "sector")
        .group_by(ActorIntelObservation.normalized_value)
        .order_by(ActorIntelObservation.normalized_value)
    )
    counts = {sector: count for sector, count in rows}
    sectors = sorted(set(DEFAULT_SECTORS) | set(counts))
    return [{"id": item, "label": item.title(), "actor_count": counts.get(item, 0)} for item in sectors]


async def list_regions(session: AsyncSession) -> list[dict[str, Any]]:
    rows = await session.execute(
        select(
            ActorIntelObservation.normalized_value,
            ActorIntelObservation.value,
            func.count(func.distinct(ActorIntelObservation.actor_name)),
        )
        .where(ActorIntelObservation.observation_type == "region")
        .group_by(ActorIntelObservation.normalized_value, ActorIntelObservation.value)
        .order_by(func.count(func.distinct(ActorIntelObservation.actor_name)).desc())
        .limit(250)
    )
    options = []
    seen: set[str] = set()
    for normalized, value, count in rows:
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        options.append({"id": normalized, "label": value, "actor_count": count})
    return options


async def list_technologies() -> list[dict[str, Any]]:
    return [{"id": item, "label": item.title()} for item in TECHNOLOGY_OPTIONS]


async def rank_actor_relevance(session: AsyncSession, params: RelevanceInput) -> list[dict[str, Any]]:
    sectors = {normalize_label(item) for item in params.sectors if item.strip()}
    regions = {normalize_label(item) for item in (params.regions or []) if item.strip()}
    tech_filter = {normalize_label(item) for item in (params.technologies or []) if item.strip()}
    cutoff = date.today() - timedelta(days=params.days)
    if not sectors:
        return []

    groups = await _latest_groups(session, params.domain)
    if not groups:
        return []

    group_ids = [group.id for group in groups]
    obs_rows = await session.execute(
        select(ActorIntelObservation).where(
            (ActorIntelObservation.actor_attack_id.in_([g.attack_id for g in groups]))
            | (ActorIntelObservation.actor_name.in_([g.name for g in groups]))
        )
    )
    observations_by_actor: dict[str, list[ActorIntelObservation]] = defaultdict(list)
    for observation in obs_rows.scalars().all():
        key = observation.actor_attack_id or observation.actor_name
        observations_by_actor[key].append(observation)

    campaign_rows = await session.execute(
        select(AptGroup.attack_id, Campaign.name, Campaign.attack_id, Campaign.first_seen, Campaign.last_seen)
        .join(AptGroupCampaign, AptGroupCampaign.group_id == AptGroup.id)
        .join(Campaign, Campaign.id == AptGroupCampaign.campaign_id)
        .where(AptGroup.id.in_(group_ids))
    )
    campaigns_by_actor: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for actor_id, name, campaign_id, first_seen, last_seen in campaign_rows:
        seen = _parse_date(last_seen) or _parse_date(first_seen)
        campaigns_by_actor[actor_id].append(
            {"name": name, "campaign_id": campaign_id, "first_seen": first_seen, "last_seen": last_seen, "seen": seen}
        )

    results = []
    for group in groups:
        actor_observations = (
            observations_by_actor.get(group.attack_id, [])
            + observations_by_actor.get(group.name, [])
        )
        sector_hits = [
            o
            for o in actor_observations
            if o.observation_type == "sector"
            and any(_sector_matches(sector, o.normalized_value) for sector in sectors)
        ]
        direct_sector_hits = [o for o in sector_hits if o.normalized_value != "private sector"]
        broad_sector_hits = [o for o in sector_hits if o.normalized_value == "private sector"]
        region_hits = [
            o
            for o in actor_observations
            if regions
            and o.observation_type == "region"
            and any(region in o.normalized_value or o.normalized_value in region for region in regions)
        ]
        motivation_hits = [
            observation
            for observation in actor_observations
            if observation.observation_type == "motivation"
        ]
        campaigns = campaigns_by_actor.get(group.attack_id, [])
        recent_campaigns = [c for c in campaigns if c["seen"] and c["seen"] >= cutoff]
        strict_sector_hits = sector_hits if sectors == {"private sector"} else direct_sector_hits
        if not strict_sector_hits:
            continue
        if regions and not region_hits:
            continue

        techniques = sorted(
            [
                {
                    "attack_id": usage.technique.attack_id,
                    "name": usage.technique.name,
                    "tactics": [tactic.shortname for tactic in usage.technique.tactics],
                    "usage": usage,
                }
                for usage in (group.technique_usages or [])
                if usage.technique and (not tech_filter or _technique_matches(usage, tech_filter))
            ],
            key=lambda item: str(item["attack_id"]),
        )
        if tech_filter and not techniques:
            continue

        technique_count = len(techniques)
        score = 0
        reasons = []
        if direct_sector_hits:
            score += 42
            reasons.append(
                f"{len(direct_sector_hits)} direct sector evidence item(s) match {_format_filter_values(sectors)}"
            )
        elif broad_sector_hits:
            score += 12
            reasons.append("broad private-sector targeting evidence exists")
        if region_hits:
            score += 18
            reasons.append(
                f"{len(region_hits)} region evidence item(s) match {_format_filter_values(regions)}"
            )
        if recent_campaigns:
            score += min(25, 10 + len(recent_campaigns) * 5)
            reasons.append(f"{len(recent_campaigns)} ATT&CK campaign(s) observed inside last {params.days} days")
        elif campaigns:
            score += 5
            reasons.append("historical ATT&CK campaign context exists")
        if technique_count:
            score += min(10, technique_count // 8)
            reasons.append(f"{technique_count} ATT&CK technique relationship(s)")
        if motivation_hits:
            score += 3

        if tech_filter:
            score += min(12, 4 + technique_count)
            reasons.append(f"{technique_count} selected technology/environment TTP(s) match")

        evidence = []
        for item in [*direct_sector_hits[:3], *broad_sector_hits[:1], *region_hits[:2], *motivation_hits[:1]]:
            evidence.append(
                {
                    "type": item.observation_type,
                    "value": item.value,
                    "source": item.source_id,
                    "url": item.source_url,
                    "confidence": item.confidence,
                    "evidence": item.evidence,
                }
            )
        for campaign in sorted(recent_campaigns, key=lambda c: c["seen"] or date.min, reverse=True)[:3]:
            evidence.append(
                {
                    "type": "recent-campaign",
                    "value": campaign["name"],
                    "source": "mitre-attack",
                    "url": "",
                    "confidence": 70,
                    "evidence": f"ATT&CK campaign {campaign['campaign_id']} last seen {campaign['last_seen'] or campaign['first_seen']}",
                }
            )

        results.append(
            {
                "actor_attack_id": group.attack_id,
                "actor_name": group.name,
                "aliases": group.aliases or [],
                "score": min(score, 100),
                "relevance": _bucket(score),
                "technique_count": technique_count,
                "recent_campaign_count": len(recent_campaigns),
                "campaign_count": len(campaigns),
                "last_activity": max([c["seen"] for c in campaigns if c["seen"]] or [None]),
                "reasons": reasons,
                "evidence": evidence,
                "techniques": [
                    {key: value for key, value in item.items() if key != "usage"}
                    for item in techniques
                ],
            }
        )

    results.sort(key=lambda item: (item["score"], item["recent_campaign_count"], item["technique_count"]), reverse=True)
    return results[: params.limit]


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value[:10]).date()
    except ValueError:
        return None


def _sector_matches(requested: str, observed: str) -> bool:
    if requested == observed:
        return True
    if requested == "private sector" and observed == "private sector":
        return True
    return requested in observed or observed in requested


def _technology_terms(filters: set[str]) -> set[str]:
    terms: set[str] = set()
    for item in filters:
        normalized = normalize_label(item)
        terms.add(normalized)
        terms.update(TECHNOLOGY_ALIASES.get(normalized, set()))
    return {term for term in terms if term}


def _format_filter_values(values: set[str]) -> str:
    return ", ".join(sorted(values))


def _technique_matches(usage: AptGroupTechnique, filters: set[str]) -> bool:
    technique = usage.technique
    terms = _technology_terms(filters)
    haystack = " ".join(
        [
            technique.attack_id,
            technique.name,
            technique.description or "",
            technique.detection or "",
            usage.use_description or "",
            " ".join(str(item) for item in (technique.platforms or [])),
            " ".join(str(item) for item in (technique.data_sources or [])),
            " ".join(tactic.shortname for tactic in technique.tactics),
        ]
    ).lower()
    return any(term in haystack for term in terms)


def _bucket(score: int) -> str:
    if score >= 75:
        return "high"
    if score >= 45:
        return "medium"
    return "low"
