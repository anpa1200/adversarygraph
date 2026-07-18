from __future__ import annotations

import re
import uuid
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset_surface import AssetIntelMatch, AssetRegistryItem
from app.models.attack import AptGroup, AptGroupTechnique, Technique
from app.models.cve import CVEActorLink, CVERecord, CVETechniqueLink
from app.models.operations import ReportIntake
from app.services.taxonomy import asset_labels, canonical_tag, canonical_tags, canonical_value, labels_to_tags, split_multi


TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._+-]{1,}", re.IGNORECASE)


async def upsert_assets_from_surface_case(
    session: AsyncSession,
    *,
    case_id: uuid.UUID | None,
    inventory_name: str,
    assets: list[dict[str, Any]],
) -> dict[str, Any]:
    """Persist normalized inventory rows as reusable asset intelligence records."""
    created = 0
    updated = 0
    asset_ids: list[uuid.UUID] = []
    for row in assets:
        fingerprint = asset_fingerprint(row)
        existing = await session.scalar(select(AssetRegistryItem).where(AssetRegistryItem.fingerprint == fingerprint))
        values = _asset_values(row, fingerprint=fingerprint, case_id=case_id, inventory_name=inventory_name)
        if existing:
            for key, value in values.items():
                setattr(existing, key, value)
            updated += 1
            asset_ids.append(existing.id)
        else:
            asset = AssetRegistryItem(**values)
            session.add(asset)
            await session.flush()
            created += 1
            asset_ids.append(asset.id)
    return {"created": created, "updated": updated, "asset_ids": [str(item) for item in asset_ids]}


async def retrohunt_assets(
    session: AsyncSession,
    *,
    asset_ids: list[str] | None = None,
    limit_per_type: int = 2000,
) -> dict[str, Any]:
    """Match owned assets against currently stored CVE, actor, and report intelligence."""
    assets = await _load_assets(session, asset_ids)
    created = 0
    updated = 0
    by_type: dict[str, int] = {"cve": 0, "actor": 0, "report": 0}
    asset_match_counts: dict[str, int] = {}

    cves = list((await session.execute(select(CVERecord).limit(limit_per_type))).scalars().all())
    cve_technique_links = list((await session.execute(select(CVETechniqueLink).limit(limit_per_type * 5))).scalars().all())
    cve_actor_links = list((await session.execute(select(CVEActorLink).limit(limit_per_type * 5))).scalars().all())
    reports = list((await session.execute(select(ReportIntake).limit(limit_per_type))).scalars().all())
    actor_rows = (await session.execute(
        select(AptGroup, Technique.attack_id)
        .join(AptGroupTechnique, AptGroupTechnique.group_id == AptGroup.id)
        .join(Technique, Technique.id == AptGroupTechnique.technique_id)
        .limit(limit_per_type * 10)
    )).all()

    cve_to_techniques: dict[str, set[str]] = {}
    for technique_link in cve_technique_links:
        cve_to_techniques.setdefault(technique_link.cve_id.upper(), set()).add(
            technique_link.attack_id.upper()
        )
    cve_to_actors: dict[str, list[CVEActorLink]] = {}
    for actor_link in cve_actor_links:
        cve_to_actors.setdefault(actor_link.cve_id.upper(), []).append(actor_link)
    actor_to_techniques: dict[str, set[str]] = {}
    actor_names: dict[str, str] = {}
    for group, attack_id in actor_rows:
        actor_to_techniques.setdefault(group.attack_id.upper(), set()).add(str(attack_id).upper())
        actor_names[group.attack_id.upper()] = group.name

    for asset in assets:
        await session.execute(delete(AssetIntelMatch).where(AssetIntelMatch.asset_id == asset.id))
        matches: dict[tuple[str, str, str, str], AssetIntelMatch] = {}
        for cve in cves:
            match = _match_cve(asset, cve, cve_to_techniques.get(cve.cve_id.upper(), set()))
            if match:
                _collect_match(matches, match)
                for actor_link in cve_to_actors.get(cve.cve_id.upper(), [])[:5]:
                    actor_match = _actor_from_cve_match(asset, cve, actor_link)
                    _collect_match(matches, actor_match)
        for actor_id, techniques in actor_to_techniques.items():
            match = _match_actor(asset, actor_id, actor_names.get(actor_id, actor_id), techniques)
            if match:
                _collect_match(matches, match)
        for report in reports:
            match = _match_report(asset, report)
            if match:
                _collect_match(matches, match)
        for match in matches.values():
            session.add(match)
            by_type[match.source_type] = by_type.get(match.source_type, 0) + 1
        count = len(matches)
        asset_match_counts[str(asset.id)] = count
        created += count
    return {
        "assets_checked": len(assets),
        "matches_created": created,
        "matches_updated": updated,
        "by_type": by_type,
        "asset_match_counts": asset_match_counts,
    }


def _collect_match(
    matches: dict[tuple[str, str, str, str], AssetIntelMatch],
    match: AssetIntelMatch,
) -> None:
    key = (
        str(match.asset_id),
        match.source_type,
        match.source_id,
        match.relationship,
    )
    existing = matches.get(key)
    if not existing:
        matches[key] = match
        return

    existing.relevance_score = max(existing.relevance_score or 0, match.relevance_score or 0)
    existing.confidence = max(existing.confidence or 0, match.confidence or 0)
    if match.severity and not existing.severity:
        existing.severity = match.severity
    existing.evidence = _merged_list(existing.evidence or [], match.evidence or [], limit=20)
    existing.tags = _merged_list(existing.tags or [], match.tags or [], limit=50)
    if match.reason and match.reason not in existing.reason:
        existing.reason = f"{existing.reason} Additional evidence: {match.reason}"[:2000]


def _merged_list(left: list[Any], right: list[Any], *, limit: int) -> list[Any]:
    merged = []
    seen = set()
    for item in [*left, *right]:
        key = str(item)
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
        if len(merged) >= limit:
            break
    return merged


async def list_assets(session: AsyncSession, *, search: str = "", limit: int = 200, offset: int = 0) -> list[dict[str, Any]]:
    stmt = select(AssetRegistryItem).order_by(AssetRegistryItem.last_seen_at.desc()).limit(limit).offset(offset)
    if search:
        like = f"%{search.lower()}%"
        stmt = stmt.where(AssetRegistryItem.name.ilike(like))
    rows = list((await session.execute(stmt)).scalars().all())
    return [asset_to_dict(row) for row in rows]


async def list_asset_matches(
    session: AsyncSession,
    *,
    asset_id: str | None = None,
    source_type: str = "",
    limit: int = 200,
    offset: int = 0,
) -> list[dict[str, Any]]:
    stmt = select(AssetIntelMatch).order_by(AssetIntelMatch.relevance_score.desc(), AssetIntelMatch.created_at.desc())
    if asset_id:
        stmt = stmt.where(AssetIntelMatch.asset_id == uuid.UUID(asset_id))
    if source_type:
        stmt = stmt.where(AssetIntelMatch.source_type == source_type)
    stmt = stmt.limit(limit).offset(offset)
    rows = list((await session.execute(stmt)).scalars().all())
    return [match_to_dict(row) for row in rows]


def asset_to_dict(asset: AssetRegistryItem) -> dict[str, Any]:
    return {
        "id": str(asset.id),
        "fingerprint": asset.fingerprint,
        "inventory_asset_id": asset.inventory_asset_id,
        "name": asset.name,
        "asset_type": asset.asset_type,
        "environment": asset.environment,
        "owner": asset.owner,
        "exposure": asset.exposure,
        "criticality": asset.criticality,
        "ip_addresses": asset.ip_addresses or [],
        "domains": asset.domains or [],
        "ports": asset.ports or [],
        "technologies": asset.technologies or [],
        "products": asset.products or [],
        "suppliers": asset.suppliers or [],
        "dependencies": asset.dependencies or [],
        "technique_ids": asset.technique_ids or [],
        "tags": asset.tags or [],
        "labels": asset.labels or {},
        "risk_score": asset.risk_score or 0,
        "risk_level": asset.risk_level or "low",
        "source_case_id": str(asset.source_case_id) if asset.source_case_id else None,
        "source_inventory_name": asset.source_inventory_name,
        "first_seen_at": asset.first_seen_at,
        "last_seen_at": asset.last_seen_at,
    }


def match_to_dict(match: AssetIntelMatch) -> dict[str, Any]:
    return {
        "id": str(match.id),
        "asset_id": str(match.asset_id),
        "source_type": match.source_type,
        "source_id": match.source_id,
        "title": match.title,
        "relationship": match.relationship,
        "relevance_score": match.relevance_score,
        "confidence": match.confidence,
        "severity": match.severity,
        "route": match.route,
        "reason": match.reason,
        "evidence": match.evidence or [],
        "tags": match.tags or [],
        "status": match.status,
        "created_at": match.created_at,
        "updated_at": match.updated_at,
    }


def asset_fingerprint(row: dict[str, Any]) -> str:
    domains = [str(x).lower() for x in row.get("domains", []) if x]
    ips = [str(x) for x in row.get("ip_addresses", []) if x]
    if domains:
        return f"domain:{domains[0]}"
    if ips:
        return f"ip:{ips[0]}"
    return "asset:" + "|".join([
        str(row.get("asset_id") or "").lower(),
        str(row.get("asset") or "").lower(),
        str(row.get("environment") or "").lower(),
        str(row.get("owner") or "").lower(),
    ])[:450]


def _asset_values(row: dict[str, Any], *, fingerprint: str, case_id: uuid.UUID | None, inventory_name: str) -> dict[str, Any]:
    technologies = _clean_list(row.get("technologies", []))
    products = _clean_list(row.get("products", []))
    suppliers = _clean_list(row.get("suppliers", []))
    dependencies = _clean_list(row.get("dependencies", []))
    labels = asset_labels(
        asset_type=row.get("asset_type") or "unknown",
        environment=row.get("environment") or "unknown",
        exposure=row.get("exposure") or "unknown",
        criticality=row.get("ai_risk_level") or row.get("risk_level") or row.get("criticality") or "medium",
        technologies=technologies,
        products=[*products, *technologies],
        suppliers=suppliers,
        dependencies=[*dependencies, *technologies],
        ttps=_technique_ids(row),
        extra_tags=row.get("tags", []),
    )
    tags = labels_to_tags(labels)
    return {
        "fingerprint": fingerprint,
        "inventory_asset_id": str(row.get("asset_id") or ""),
        "name": str(row.get("asset") or row.get("name") or row.get("asset_id") or "unknown asset")[:500],
        "asset_type": canonical_value("asset_type", row.get("asset_type") or "unknown")[:120],
        "environment": canonical_value("environment", row.get("environment") or "unknown")[:120],
        "owner": str(row.get("owner") or "")[:255],
        "exposure": canonical_value("exposure", row.get("exposure") or "unknown")[:80],
        "criticality": canonical_value("risk", row.get("criticality") or "medium")[:80],
        "ip_addresses": _clean_list(row.get("ip_addresses", [])),
        "domains": _clean_list(row.get("domains", [])),
        "ports": [int(port) for port in row.get("ports", []) if str(port).isdigit()],
        "technologies": technologies,
        "products": sorted(set([*technologies, *products])),
        "suppliers": suppliers,
        "dependencies": sorted(set([*technologies, *dependencies])),
        "technique_ids": _technique_ids(row),
        "tags": tags,
        "labels": labels,
        "risk_score": int(row.get("risk_score") or 0),
        "risk_level": canonical_value("risk", row.get("ai_risk_level") or row.get("risk_level") or "low")[:40],
        "source_case_id": case_id,
        "source_inventory_name": inventory_name[:255],
        "raw": row,
    }


async def _load_assets(session: AsyncSession, asset_ids: list[str] | None) -> list[AssetRegistryItem]:
    stmt = select(AssetRegistryItem)
    if asset_ids:
        ids = []
        for item in asset_ids:
            try:
                ids.append(uuid.UUID(str(item)))
            except ValueError:
                continue
        if not ids:
            return []
        stmt = stmt.where(AssetRegistryItem.id.in_(ids))
    return list((await session.execute(stmt)).scalars().all())


def _match_cve(asset: AssetRegistryItem, cve: CVERecord, linked_techniques: set[str]) -> AssetIntelMatch | None:
    asset_tokens = _asset_tokens(asset)
    cve_text = " ".join([
        cve.cve_id,
        cve.description or "",
        " ".join(cve.cpe_matches or []),
        " ".join(cve.tags or []),
        " ".join(cve.cwe_ids or []),
    ]).lower()
    cve_tokens = set(TOKEN_RE.findall(cve_text))
    token_hits = sorted((asset_tokens & cve_tokens) - _weak_tokens())
    ttp_hits = sorted(set(asset.technique_ids or []) & linked_techniques)
    if not token_hits and not ttp_hits:
        return None
    score = min(100, 35 + len(token_hits[:8]) * 7 + len(ttp_hits) * 12)
    if cve.known_exploited:
        score += 15
    if asset.exposure == "internet":
        score += 10
    score = min(100, score)
    evidence = []
    if token_hits:
        evidence.append(f"Asset technology/product tokens matched CVE text/CPE: {', '.join(token_hits[:8])}")
    if ttp_hits:
        evidence.append(f"Asset TTP candidates overlap CVE-linked techniques: {', '.join(ttp_hits)}")
    if cve.known_exploited:
        evidence.append("CVE is marked as known exploited.")
    return AssetIntelMatch(
        asset_id=asset.id,
        source_type="cve",
        source_id=cve.cve_id,
        title=cve.description[:500] or cve.cve_id,
        relationship="asset-may-be-affected-by-cve",
        relevance_score=score,
        confidence=min(95, 55 + len(token_hits[:5]) * 8 + len(ttp_hits) * 10),
        severity=cve.cvss_severity or ("KEV" if cve.known_exploited else ""),
        route=f"/cve?cve={cve.cve_id}",
        reason="CVE matched asset labels, product/dependency tokens, or ATT&CK technique context.",
        evidence=evidence,
        tags=[
            canonical_tag("tag", "retrohunt"),
            canonical_tag("cve", cve.cve_id),
            *canonical_tags("tag", cve.tags or []),
            *( [canonical_tag("tag", "kev")] if cve.known_exploited else [] ),
        ],
    )


def _actor_from_cve_match(asset: AssetRegistryItem, cve: CVERecord, link: CVEActorLink) -> AssetIntelMatch:
    return AssetIntelMatch(
        asset_id=asset.id,
        source_type="actor",
        source_id=link.actor_attack_id,
        title=link.actor_name or link.actor_attack_id,
        relationship="actor-reported-with-relevant-cve",
        relevance_score=75 if cve.known_exploited else 62,
        confidence=link.confidence or 70,
        severity=cve.cvss_severity or "",
        route=f"/apt?group={link.actor_attack_id}",
        reason=f"{link.actor_name or link.actor_attack_id} is linked to {cve.cve_id}, which is relevant to this asset.",
        evidence=[link.evidence or f"CVE actor link from {link.source_id}", f"Relevant CVE: {cve.cve_id}"],
        tags=[canonical_tag("tag", "retrohunt"), canonical_tag("actor", link.actor_attack_id), canonical_tag("cve", cve.cve_id)],
    )


def _match_actor(asset: AssetRegistryItem, actor_id: str, actor_name: str, techniques: set[str]) -> AssetIntelMatch | None:
    overlap = sorted(set(asset.technique_ids or []) & techniques)
    if not overlap:
        return None
    score = min(100, 45 + len(overlap) * 10 + (10 if asset.exposure == "internet" else 0))
    return AssetIntelMatch(
        asset_id=asset.id,
        source_type="actor",
        source_id=actor_id,
        title=actor_name,
        relationship="actor-ttp-overlaps-asset-surface",
        relevance_score=score,
        confidence=min(90, 50 + len(overlap) * 10),
        route=f"/apt?group={actor_id}",
        reason="Actor technique set overlaps likely techniques derived from this asset inventory.",
        evidence=[f"Overlapping ATT&CK techniques: {', '.join(overlap[:12])}"],
        tags=[canonical_tag("tag", "retrohunt"), canonical_tag("actor", actor_id), *canonical_tags("ttp", overlap[:8])],
    )


def _match_report(asset: AssetRegistryItem, report: ReportIntake) -> AssetIntelMatch | None:
    report_techniques = {str(item).upper() for item in (report.technique_ids or [])}
    ttp_hits = sorted(set(asset.technique_ids or []) & report_techniques)
    report_text = " ".join([
        report.title or "",
        report.summary or "",
        report.publisher or "",
        report.analyst_notes or "",
    ]).lower()
    token_hits = sorted((_asset_tokens(asset) & set(TOKEN_RE.findall(report_text))) - _weak_tokens())
    ioc_hits = _ioc_hits(asset, report.indicators or [])
    if not ttp_hits and not token_hits and not ioc_hits:
        return None
    score = min(100, 30 + len(ttp_hits) * 12 + len(token_hits[:6]) * 6 + len(ioc_hits) * 15)
    return AssetIntelMatch(
        asset_id=asset.id,
        source_type="report",
        source_id=str(report.id),
        title=report.title,
        relationship="report-relevant-to-asset",
        relevance_score=score,
        confidence=min(90, 45 + len(ttp_hits) * 10 + len(token_hits[:5]) * 7 + len(ioc_hits) * 10),
        route=f"/reports-research",
        reason="Report matched asset TTPs, technology labels, or observables.",
        evidence=[
            *( [f"Overlapping ATT&CK techniques: {', '.join(ttp_hits)}"] if ttp_hits else [] ),
            *( [f"Technology/product token hits: {', '.join(token_hits[:8])}"] if token_hits else [] ),
            *( [f"Observable hits: {', '.join(ioc_hits[:8])}"] if ioc_hits else [] ),
        ],
        tags=[canonical_tag("tag", "retrohunt"), canonical_tag("tag", "report"), *canonical_tags("ttp", ttp_hits[:8])],
    )


def _asset_tokens(asset: AssetRegistryItem) -> set[str]:
    values = [
        asset.name,
        asset.asset_type,
        asset.environment,
        asset.owner,
        asset.exposure,
        asset.criticality,
        *(asset.technologies or []),
        *(asset.products or []),
        *(asset.suppliers or []),
        *(asset.dependencies or []),
        *(asset.tags or []),
        *(asset.domains or []),
    ]
    return {token.lower() for value in values for token in TOKEN_RE.findall(str(value))}


def _ioc_hits(asset: AssetRegistryItem, indicators: list[Any]) -> list[str]:
    observables = {*(asset.ip_addresses or []), *(asset.domains or [])}
    hits = []
    for item in indicators:
        value = ""
        if isinstance(item, dict):
            value = str(item.get("value") or item.get("indicator") or "")
        else:
            value = str(item)
        if value and value in observables:
            hits.append(value)
    return sorted(set(hits))


def _technique_ids(row: dict[str, Any]) -> list[str]:
    ids = []
    for item in row.get("ttp_candidates", []) or []:
        if isinstance(item, dict) and item.get("attack_id"):
            ids.append(str(item["attack_id"]).upper())
        elif isinstance(item, str):
            ids.append(item.upper())
    return sorted(set(ids))


def _labels_for_asset(row: dict[str, Any], technologies: list[str]) -> dict[str, Any]:
    return asset_labels(
        asset_type=row.get("asset_type") or "unknown",
        environment=row.get("environment") or "unknown",
        exposure=row.get("exposure") or "unknown",
        criticality=row.get("ai_risk_level") or row.get("risk_level") or row.get("criticality") or "low",
        technologies=technologies,
        products=row.get("products", []),
        suppliers=row.get("suppliers", []),
        dependencies=row.get("dependencies", []),
        ttps=_technique_ids(row),
        extra_tags=row.get("tags", []),
    )


def _clean_list(value: Any) -> list[str]:
    return sorted({canonical_value("tag", item) for item in split_multi(value, limit=100) if str(item).strip()})[:100]


def _weak_tokens() -> set[str]:
    return {
        "the", "and", "for", "with", "from", "this", "that", "asset", "server", "service",
        "application", "system", "internal", "external", "prod", "production", "unknown",
        "critical", "high", "medium", "low", "tech", "type", "env", "exposure",
    }
