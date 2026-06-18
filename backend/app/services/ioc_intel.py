from __future__ import annotations

import csv
import json
import re
from io import StringIO
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Any

import requests
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.models.attack import AptGroup, AttackVersion
from app.models.ioc import IOCActorLink, IOCIndicator, IOCSource
from app.services.sector_intel import normalize_label

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
OTX_API_URL = "https://otx.alienvault.com/api/v1"
MALPEDIA_API_URL = "https://malpedia.caad.fkie.fraunhofer.de/api"
THREATFOX_SOURCE_ID = "abusech-threatfox"
OTX_SOURCE_ID = "alienvault-otx"
MALPEDIA_SOURCE_ID = "malpedia"
MANUAL_SOURCE_ID = "manual-report-import"
CUSTOM_FEED_KINDS = {"custom-json", "custom-csv", "custom-txt"}


@dataclass
class IOCImportItem:
    value: str
    indicator_type: str
    actor_attack_id: str | None = None
    actor_name: str | None = None
    malware_family: str = ""
    campaign: str = ""
    source: str = MANUAL_SOURCE_ID
    source_url: str = ""
    first_seen: str | None = None
    last_seen: str | None = None
    confidence: int = 60
    tlp: str = "clear"
    tags: list[str] | None = None
    description: str = ""
    raw: dict[str, Any] | None = None


async def ensure_ioc_sources(session: AsyncSession) -> None:
    for source_id, label, kind, url in [
        (THREATFOX_SOURCE_ID, "abuse.ch ThreatFox", "api", THREATFOX_API_URL),
        (OTX_SOURCE_ID, "AlienVault OTX Pulses", "api", OTX_API_URL),
        (MALPEDIA_SOURCE_ID, "Malpedia Malware Families", "api", MALPEDIA_API_URL),
        (MANUAL_SOURCE_ID, "Manual Report Import", "manual", ""),
    ]:
        stmt = insert(IOCSource).values(
            source_id=source_id,
            label=label,
            kind=kind,
            url=url,
            enabled=True,
            sync_status="configured",
        ).on_conflict_do_update(
            index_elements=["source_id"],
            set_={"label": label, "kind": kind, "url": url, "enabled": True},
        )
        await session.execute(stmt)
    await session.commit()


async def list_ioc_sources(session: AsyncSession) -> list[IOCSource]:
    await ensure_ioc_sources(session)
    rows = await session.execute(select(IOCSource).order_by(IOCSource.label))
    return list(rows.scalars().all())


async def create_ioc_source(
    session: AsyncSession,
    label: str,
    url: str,
    kind: str = "custom-json",
    source_id: str | None = None,
) -> IOCSource:
    await ensure_ioc_sources(session)
    if kind not in CUSTOM_FEED_KINDS:
        raise ValueError(f"Unsupported custom feed kind: {kind}")
    source_id = source_id or f"custom-{_slugify(label or url)}"
    stmt = (
        insert(IOCSource)
        .values(
            source_id=source_id,
            label=label.strip() or source_id,
            kind=kind,
            url=url.strip(),
            enabled=True,
            sync_status="configured",
        )
        .on_conflict_do_update(
            index_elements=["source_id"],
            set_={
                "label": label.strip() or source_id,
                "kind": kind,
                "url": url.strip(),
                "enabled": True,
                "sync_status": "configured",
                "sync_error": "",
            },
        )
        .returning(IOCSource)
    )
    source = (await session.execute(stmt)).scalar_one()
    await session.commit()
    return source


async def sync_custom_source(
    session: AsyncSession,
    source_id: str,
    domain: str = "enterprise-attack",
) -> dict[str, int | str | None]:
    await ensure_ioc_sources(session)
    source = await session.get(IOCSource, source_id)
    if not source:
        raise ValueError(f"IOC source not found: {source_id}")
    if source.kind not in CUSTOM_FEED_KINDS:
        raise ValueError(f"IOC source {source_id} is not a custom feed")
    if not source.url:
        raise ValueError(f"IOC source {source_id} has no URL")

    try:
        response = requests.get(source.url, timeout=90)
        response.raise_for_status()
        items = _parse_custom_feed(response.text, source.kind, source_id, source.url)
    except Exception as exc:
        await _mark_existing_source(session, source, "error", str(exc))
        await session.commit()
        raise

    groups = await _latest_groups(session, domain)
    inserted = 0
    updated = 0
    linked = 0
    for item in items:
        indicator_id, was_inserted = await _upsert_indicator(session, item)
        inserted += int(was_inserted)
        updated += int(not was_inserted)
        for group, evidence in _actor_link_targets(item, groups):
            if await _upsert_actor_link(
                session=session,
                indicator_id=indicator_id,
                actor_attack_id=group.attack_id,
                actor_name=group.name,
                source_id=source_id,
                confidence=item.confidence,
                evidence=evidence,
            ):
                linked += 1

    await _mark_existing_source(session, source, "ok", "")
    await session.commit()
    return {"source": source_id, "days": None, "inserted": inserted, "updated": updated, "actor_links": linked}


async def sync_all_ioc_sources(session: AsyncSession, days: int = 7, domain: str = "enterprise-attack") -> dict[str, Any]:
    """Synchronize ThreatFox, OTX, and all enabled custom IOC feeds."""
    await ensure_ioc_sources(session)
    sources = await list_ioc_sources(session)
    results: list[dict[str, Any]] = []
    totals = {"inserted": 0, "updated": 0, "actor_links": 0}

    try:
        result = await sync_threatfox(session, days=days, domain=domain)
        results.append({**result, "status": "ok"})
        totals["inserted"] += int(result.get("inserted", 0))
        totals["updated"] += int(result.get("updated", 0))
        totals["actor_links"] += int(result.get("actor_links", 0))
    except Exception as exc:
        results.append({"source": THREATFOX_SOURCE_ID, "status": "error", "error": str(exc)})

    try:
        result = await sync_malpedia_families(session, domain=domain)
        results.append({**result, "status": "ok"})
        totals["inserted"] += int(result.get("inserted", 0))
        totals["updated"] += int(result.get("updated", 0))
        totals["actor_links"] += int(result.get("actor_links", 0))
    except Exception as exc:
        results.append({"source": MALPEDIA_SOURCE_ID, "status": "error", "error": str(exc)})

    try:
        result = await sync_otx_subscribed_pulses(session, domain=domain)
        results.append({**result, "status": "ok"})
        totals["inserted"] += int(result.get("inserted", 0))
        totals["updated"] += int(result.get("updated", 0))
        totals["actor_links"] += int(result.get("actor_links", 0))
    except Exception as exc:
        results.append({"source": OTX_SOURCE_ID, "status": "error", "error": str(exc)})

    for source in sources:
        if not source.enabled or source.kind not in CUSTOM_FEED_KINDS:
            continue
        try:
            result = await sync_custom_source(session, source_id=source.source_id, domain=domain)
            results.append({**result, "status": "ok"})
            totals["inserted"] += int(result.get("inserted", 0))
            totals["updated"] += int(result.get("updated", 0))
            totals["actor_links"] += int(result.get("actor_links", 0))
        except Exception as exc:
            results.append({"source": source.source_id, "status": "error", "error": str(exc)})

    return {"days": max(1, min(days, 7)), "totals": totals, "sources": results}


async def sync_malpedia_families(
    session: AsyncSession,
    domain: str = "enterprise-attack",
) -> dict[str, int | str | None]:
    """Sync public Malpedia malware family metadata and actor attributions."""
    await ensure_ioc_sources(session)
    try:
        payload = _malpedia_get_families()
    except Exception as exc:
        await _mark_ioc_source(session, MALPEDIA_SOURCE_ID, "error", str(exc))
        await session.commit()
        raise

    if not isinstance(payload, dict):
        error = "Unexpected Malpedia response: expected a family metadata object."
        await _mark_ioc_source(session, MALPEDIA_SOURCE_ID, "error", error)
        await session.commit()
        raise RuntimeError(error)

    groups = await _latest_groups(session, domain)
    inserted = 0
    updated = 0
    linked = 0
    families = 0
    attributed = 0

    for family_id, family in payload.items():
        if not isinstance(family, dict):
            continue
        item = _malpedia_family_to_import_item(str(family_id), family)
        if not item.value:
            continue
        families += 1
        indicator_id, was_inserted = await _upsert_indicator(session, item)
        inserted += int(was_inserted)
        updated += int(not was_inserted)
        targets = _actor_link_targets(item, groups)
        if targets:
            attributed += 1
        for group, evidence in targets:
            if await _upsert_actor_link(
                session=session,
                indicator_id=indicator_id,
                actor_attack_id=group.attack_id,
                actor_name=group.name,
                source_id=MALPEDIA_SOURCE_ID,
                confidence=82,
                evidence=evidence.replace("Feed record", "Malpedia family metadata"),
            ):
                linked += 1

    await _mark_ioc_source(session, MALPEDIA_SOURCE_ID, "ok", "")
    await session.commit()
    return {
        "source": MALPEDIA_SOURCE_ID,
        "days": None,
        "inserted": inserted,
        "updated": updated,
        "actor_links": linked,
        "families": families,
        "attributed_families": attributed,
    }


async def sync_otx_actor_pulses(
    session: AsyncSession,
    domain: str = "enterprise-attack",
    max_groups: int = 220,
    aliases_per_group: int = 4,
    pulses_per_alias: int = 5,
) -> dict[str, int | str | None]:
    await ensure_ioc_sources(session)
    if not settings.otx_api_key:
        error = "OTX_API_KEY is required for AlienVault OTX sync."
        await _mark_ioc_source(session, OTX_SOURCE_ID, "error", error)
        await session.commit()
        raise RuntimeError(error)

    groups = await _latest_groups(session, domain)
    inserted = 0
    updated = 0
    linked = 0
    searched_aliases = 0
    seen_pulses: set[str] = set()

    for group in groups[:max_groups]:
        for alias in _group_search_aliases(group)[:aliases_per_group]:
            searched_aliases += 1
            try:
                pulses = _otx_search_pulses(alias, limit=pulses_per_alias)
            except Exception as exc:
                await _mark_ioc_source(session, OTX_SOURCE_ID, "error", str(exc))
                await session.commit()
                raise
            for pulse in pulses:
                pulse_id = str(pulse.get("id") or "")
                if not pulse_id or pulse_id in seen_pulses:
                    continue
                seen_pulses.add(pulse_id)
                detail = _otx_pulse_detail(pulse_id)
                if not _pulse_matches_group(detail, group):
                    continue
                for item in _otx_pulse_to_import_items(detail):
                    indicator_id, was_inserted = await _upsert_indicator(session, item)
                    inserted += int(was_inserted)
                    updated += int(not was_inserted)
                    if await _upsert_actor_link(
                        session=session,
                        indicator_id=indicator_id,
                        actor_attack_id=group.attack_id,
                        actor_name=group.name,
                        source_id=OTX_SOURCE_ID,
                        confidence=_otx_confidence(detail, group),
                        evidence=_otx_evidence(detail, group),
                    ):
                        linked += 1

    await _mark_ioc_source(session, OTX_SOURCE_ID, "ok", "")
    await session.commit()
    return {
        "source": OTX_SOURCE_ID,
        "days": None,
        "inserted": inserted,
        "updated": updated,
        "actor_links": linked,
        "searched_aliases": searched_aliases,
        "pulses": len(seen_pulses),
    }


async def enrich_actor_from_otx(
    session: AsyncSession,
    actor_id: str,
    domain: str = "enterprise-attack",
    aliases_per_group: int = 6,
    pulses_per_alias: int = 5,
) -> dict[str, int | str | None]:
    await ensure_ioc_sources(session)
    if not settings.otx_api_key:
        error = "OTX_API_KEY is required for AlienVault OTX sync."
        await _mark_ioc_source(session, OTX_SOURCE_ID, "error", error)
        await session.commit()
        raise RuntimeError(error)

    group = await _group_by_attack_id(session, actor_id, domain)
    if not group:
        raise ValueError(f"Actor not found: {actor_id}")

    inserted = 0
    updated = 0
    linked = 0
    searched_aliases = 0
    matched_pulses = 0
    seen_pulses: set[str] = set()
    for alias in _group_search_aliases(group)[:aliases_per_group]:
        searched_aliases += 1
        pulses = _otx_search_pulses(alias, limit=pulses_per_alias)
        for pulse in pulses:
            pulse_id = str(pulse.get("id") or "")
            if not pulse_id or pulse_id in seen_pulses:
                continue
            seen_pulses.add(pulse_id)
            detail = _otx_pulse_detail(pulse_id)
            if not _pulse_matches_group(detail, group):
                continue
            matched_pulses += 1
            for item in _otx_pulse_to_import_items(detail):
                indicator_id, was_inserted = await _upsert_indicator(session, item)
                inserted += int(was_inserted)
                updated += int(not was_inserted)
                if await _upsert_actor_link(
                    session=session,
                    indicator_id=indicator_id,
                    actor_attack_id=group.attack_id,
                    actor_name=group.name,
                    source_id=OTX_SOURCE_ID,
                    confidence=_otx_confidence(detail, group),
                    evidence=_otx_evidence(detail, group),
                ):
                    linked += 1

    await _mark_ioc_source(session, OTX_SOURCE_ID, "ok", "")
    await session.commit()
    return {
        "source": OTX_SOURCE_ID,
        "actor_attack_id": group.attack_id,
        "actor_name": group.name,
        "days": None,
        "inserted": inserted,
        "updated": updated,
        "actor_links": linked,
        "searched_aliases": searched_aliases,
        "pulses": len(seen_pulses),
        "matched_pulses": matched_pulses,
    }


async def sync_otx_subscribed_pulses(
    session: AsyncSession,
    domain: str = "enterprise-attack",
    limit: int = 100,
) -> dict[str, int | str | None]:
    await ensure_ioc_sources(session)
    if not settings.otx_api_key:
        error = "OTX_API_KEY is required for AlienVault OTX sync."
        await _mark_ioc_source(session, OTX_SOURCE_ID, "error", error)
        await session.commit()
        raise RuntimeError(error)

    groups = await _latest_groups(session, domain)
    try:
        pulses = _otx_subscribed_pulses(limit=limit)
    except Exception as exc:
        await _mark_ioc_source(session, OTX_SOURCE_ID, "error", str(exc))
        await session.commit()
        raise

    inserted = 0
    updated = 0
    linked = 0
    matched_pulses = 0
    for pulse in pulses:
        matched_groups = [group for group in groups if _pulse_matches_group(pulse, group)]
        if not matched_groups:
            continue
        matched_pulses += 1
        for item in _otx_pulse_to_import_items(pulse):
            indicator_id, was_inserted = await _upsert_indicator(session, item)
            inserted += int(was_inserted)
            updated += int(not was_inserted)
            for group in matched_groups:
                if await _upsert_actor_link(
                    session=session,
                    indicator_id=indicator_id,
                    actor_attack_id=group.attack_id,
                    actor_name=group.name,
                    source_id=OTX_SOURCE_ID,
                    confidence=_otx_confidence(pulse, group),
                    evidence=_otx_evidence(pulse, group),
                ):
                    linked += 1

    await _mark_ioc_source(session, OTX_SOURCE_ID, "ok", "")
    await session.commit()
    return {
        "source": OTX_SOURCE_ID,
        "days": None,
        "inserted": inserted,
        "updated": updated,
        "actor_links": linked,
        "pulses": len(pulses),
        "matched_pulses": matched_pulses,
    }


async def sync_threatfox(session: AsyncSession, days: int = 7, domain: str = "enterprise-attack") -> dict[str, int | str]:
    await ensure_ioc_sources(session)
    days = max(1, min(days, 7))
    if not settings.threatfox_auth_key:
        error = "THREATFOX_AUTH_KEY is required for ThreatFox API sync."
        await _mark_ioc_source(session, THREATFOX_SOURCE_ID, "error", error)
        await session.commit()
        raise RuntimeError(error)
    try:
        response = requests.post(
            THREATFOX_API_URL,
            json={"query": "get_iocs", "days": days},
            headers={"Auth-Key": settings.threatfox_auth_key},
            timeout=90,
        )
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        await _mark_ioc_source(session, THREATFOX_SOURCE_ID, "error", str(exc))
        raise

    if payload.get("query_status") not in {"ok", "no_result"}:
        error = str(payload.get("query_status") or "unknown ThreatFox response")
        await _mark_ioc_source(session, THREATFOX_SOURCE_ID, "error", error)
        raise RuntimeError(error)

    groups = await _latest_groups(session, domain)
    inserted = 0
    updated = 0
    linked = 0

    for item in payload.get("data") or []:
        import_item = _threatfox_item_to_import(item)
        indicator_id, was_inserted = await _upsert_indicator(session, import_item)
        inserted += int(was_inserted)
        updated += int(not was_inserted)
        matches = _match_actors(import_item, groups)
        for group, evidence in matches:
            if await _upsert_actor_link(
                session=session,
                indicator_id=indicator_id,
                actor_attack_id=group.attack_id,
                actor_name=group.name,
                source_id=THREATFOX_SOURCE_ID,
                confidence=min(85, max(35, import_item.confidence)),
                evidence=evidence,
            ):
                linked += 1

    await _mark_ioc_source(session, THREATFOX_SOURCE_ID, "ok", "")
    await session.commit()
    return {
        "source": THREATFOX_SOURCE_ID,
        "days": days,
        "inserted": inserted,
        "updated": updated,
        "actor_links": linked,
    }


async def import_iocs(session: AsyncSession, items: list[IOCImportItem]) -> dict[str, int | str]:
    await ensure_ioc_sources(session)
    groups = await _latest_groups(session, "enterprise-attack")
    inserted = 0
    updated = 0
    linked = 0
    for item in items:
        indicator_id, was_inserted = await _upsert_indicator(session, item)
        inserted += int(was_inserted)
        updated += int(not was_inserted)
        targets = _actor_link_targets(item, groups)
        if targets:
            for group, evidence in targets:
                if await _upsert_actor_link(
                    session=session,
                    indicator_id=indicator_id,
                    actor_attack_id=group.attack_id,
                    actor_name=group.name,
                    source_id=item.source,
                    confidence=item.confidence,
                    evidence=evidence,
                ):
                    linked += 1
        elif item.actor_attack_id or item.actor_name:
            if await _upsert_actor_link(
                session=session,
                indicator_id=indicator_id,
                actor_attack_id=item.actor_attack_id or item.actor_name or "",
                actor_name=item.actor_name or item.actor_attack_id or "",
                source_id=item.source,
                confidence=item.confidence,
                evidence=item.description or "Manual source mapped this IOC to the actor.",
            ):
                linked += 1
    await session.commit()
    return {"source": MANUAL_SOURCE_ID, "inserted": inserted, "updated": updated, "actor_links": linked}


async def actor_iocs(
    session: AsyncSession,
    actor_id: str,
    days: int = 180,
    active_only: bool = True,
    limit: int = 250,
) -> list[dict[str, Any]]:
    await ensure_ioc_sources(session)
    rows = await session.execute(
        select(IOCActorLink)
        .where(IOCActorLink.actor_attack_id == actor_id)
        .options(selectinload(IOCActorLink.indicator))
        .order_by(IOCActorLink.id.desc())
        .limit(max(1, min(limit, 1000)))
    )
    cutoff = date.today() - timedelta(days=max(1, min(days, 1825)))
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for link in rows.scalars().all():
        indicator = link.indicator
        last_seen = _parse_date(indicator.last_seen) or _parse_date(indicator.first_seen)
        if active_only and last_seen and last_seen < cutoff:
            continue
        key = (indicator.value, indicator.indicator_type)
        if key in seen:
            continue
        seen.add(key)
        result.append(
            {
                "value": indicator.value,
                "type": indicator.indicator_type,
                "source": indicator.source_id,
                "source_url": indicator.source_url,
                "first_seen": indicator.first_seen,
                "last_seen": indicator.last_seen,
                "confidence": min(link.confidence, indicator.confidence),
                "tlp": indicator.tlp,
                "malware_family": indicator.malware_family,
                "campaign": indicator.campaign,
                "tags": indicator.tags or [],
                "description": indicator.description,
                "relationship": link.relationship_type,
                "evidence": link.evidence,
            }
        )
    return sorted(result, key=lambda item: (item["last_seen"] or item["first_seen"] or ""), reverse=True)


async def actor_ioc_summary(session: AsyncSession, actor_id: str, days: int = 180) -> dict[str, Any]:
    items = await actor_iocs(session, actor_id, days=days, active_only=True, limit=1000)
    by_type: dict[str, int] = {}
    sources: dict[str, int] = {}
    for item in items:
        by_type[item["type"]] = by_type.get(item["type"], 0) + 1
        sources[item["source"]] = sources.get(item["source"], 0) + 1
    return {"actor_attack_id": actor_id, "count": len(items), "by_type": by_type, "sources": sources}


async def actor_ioc_counts(
    session: AsyncSession,
    actor_ids: list[str],
    days: int = 180,
    active_only: bool = True,
) -> dict[str, int]:
    await ensure_ioc_sources(session)
    ids = [actor_id for actor_id in dict.fromkeys(actor_ids) if actor_id]
    if not ids:
        return {}
    cutoff = date.today() - timedelta(days=max(1, min(days, 1825)))
    stmt = (
        select(
            IOCActorLink.actor_attack_id,
            func.count(func.distinct(IOCIndicator.id)),
        )
        .join(IOCIndicator, IOCIndicator.id == IOCActorLink.indicator_id)
        .where(IOCActorLink.actor_attack_id.in_(ids))
        .group_by(IOCActorLink.actor_attack_id)
    )
    if active_only:
        stmt = stmt.where(
            (func.substr(IOCIndicator.last_seen, 1, 10) >= cutoff.isoformat())
            | (
                IOCIndicator.last_seen.is_(None)
                & (func.substr(IOCIndicator.first_seen, 1, 10) >= cutoff.isoformat())
            )
            | (IOCIndicator.last_seen.is_(None) & IOCIndicator.first_seen.is_(None))
        )
    rows = await session.execute(stmt)
    counts = {actor_id: count for actor_id, count in rows}
    return {actor_id: counts.get(actor_id, 0) for actor_id in ids}


async def _latest_groups(session: AsyncSession, domain: str) -> list[AptGroup]:
    version_row = await session.execute(
        select(AttackVersion.id).where(AttackVersion.domain == domain, AttackVersion.is_latest.is_(True))
    )
    version_id = version_row.scalar_one_or_none()
    if not version_id:
        return []
    rows = await session.execute(select(AptGroup).where(AptGroup.version_id == version_id))
    return list(rows.scalars().all())


async def _group_by_attack_id(session: AsyncSession, actor_id: str, domain: str) -> AptGroup | None:
    version_row = await session.execute(
        select(AttackVersion.id).where(AttackVersion.domain == domain, AttackVersion.is_latest.is_(True))
    )
    version_id = version_row.scalar_one_or_none()
    if not version_id:
        return None
    row = await session.execute(
        select(AptGroup).where(AptGroup.version_id == version_id, AptGroup.attack_id == actor_id)
    )
    return row.scalar_one_or_none()


async def _mark_ioc_source(session: AsyncSession, source_id: str, status: str, error: str) -> None:
    labels = {
        THREATFOX_SOURCE_ID: ("abuse.ch ThreatFox", "api", THREATFOX_API_URL),
        OTX_SOURCE_ID: ("AlienVault OTX Pulses", "api", OTX_API_URL),
        MALPEDIA_SOURCE_ID: ("Malpedia Malware Families", "api", MALPEDIA_API_URL),
    }
    label, kind, url = labels.get(source_id, (source_id, "api", ""))
    stmt = insert(IOCSource).values(
        source_id=source_id,
        label=label,
        kind=kind,
        url=url,
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


async def _mark_existing_source(session: AsyncSession, source: IOCSource, status: str, error: str) -> None:
    stmt = insert(IOCSource).values(
        source_id=source.source_id,
        label=source.label,
        kind=source.kind,
        url=source.url,
        enabled=source.enabled,
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


def _threatfox_item_to_import(item: dict[str, Any]) -> IOCImportItem:
    return IOCImportItem(
        value=str(item.get("ioc") or "").strip(),
        indicator_type=str(item.get("ioc_type") or "unknown").strip().lower(),
        malware_family=str(item.get("malware_printable") or item.get("malware") or "").strip(),
        source=THREATFOX_SOURCE_ID,
        source_url=str(item.get("reference") or item.get("link") or "").strip(),
        first_seen=item.get("first_seen"),
        last_seen=item.get("last_seen"),
        confidence=_safe_int(item.get("confidence_level"), 50),
        tlp=str(item.get("tlp") or "clear").lower(),
        tags=[str(tag) for tag in (item.get("tags") or []) if str(tag).strip()],
        description=str(item.get("threat_type_desc") or item.get("threat_type") or "").strip(),
        raw=item,
    )


def _malpedia_get_families() -> dict[str, Any]:
    response = requests.get(f"{MALPEDIA_API_URL}/get/families", timeout=120)
    response.raise_for_status()
    payload = response.json()
    return payload if isinstance(payload, dict) else {}


def _malpedia_family_to_import_item(family_id: str, family: dict[str, Any]) -> IOCImportItem:
    common_name = _optional_str(family.get("common_name")) or family_id
    alt_names = _as_tags(family.get("alt_names"))
    attribution = _as_tags(family.get("attribution"))
    urls = _as_tags(family.get("urls"))
    sources = _as_tags(family.get("sources"))
    notes = _as_tags(family.get("notes"))
    description = _optional_str(family.get("description"))
    detail_url = f"https://malpedia.caad.fkie.fraunhofer.de/details/{family_id}"
    source_url = urls[0] if urls else detail_url
    evidence_bits = [
        f"Malpedia family {family_id} ({common_name})",
        f"attribution: {', '.join(attribution)}" if attribution else "",
        f"aliases: {', '.join(alt_names[:8])}" if alt_names else "",
        description[:300] if description else "",
    ]
    return IOCImportItem(
        value=family_id,
        indicator_type="malware-family",
        actor_name=", ".join(attribution),
        malware_family=common_name,
        campaign="",
        source=MALPEDIA_SOURCE_ID,
        source_url=source_url,
        first_seen=None,
        last_seen=_optional_str(family.get("updated")) or None,
        confidence=82 if attribution else 65,
        tlp="clear",
        tags=_dedupe_tags([*alt_names, *attribution, *sources, "malpedia", "malware-family"]),
        description="; ".join(bit for bit in evidence_bits if bit),
        raw={
            "family_id": family_id,
            "common_name": common_name,
            "alt_names": alt_names,
            "attribution": attribution,
            "urls": urls[:12],
            "sources": sources[:12],
            "notes": notes[:8],
            "updated": family.get("updated"),
            "uuid": family.get("uuid"),
            "library_entries": family.get("library_entries") or [],
            "malpedia_url": detail_url,
        },
    )


def _otx_search_pulses(alias: str, limit: int = 5) -> list[dict[str, Any]]:
    response = requests.get(
        f"{OTX_API_URL}/search/pulses",
        params={"q": alias, "limit": limit},
        headers={"X-OTX-API-KEY": settings.otx_api_key},
        timeout=45,
    )
    response.raise_for_status()
    payload = response.json()
    return [item for item in payload.get("results", []) if isinstance(item, dict)]


def _otx_subscribed_pulses(limit: int = 100) -> list[dict[str, Any]]:
    response = requests.get(
        f"{OTX_API_URL}/pulses/subscribed",
        params={"limit": max(1, min(limit, 500))},
        headers={"X-OTX-API-KEY": settings.otx_api_key},
        timeout=20,
    )
    response.raise_for_status()
    payload = response.json()
    return [item for item in payload.get("results", []) if isinstance(item, dict)]


def _otx_pulse_detail(pulse_id: str) -> dict[str, Any]:
    response = requests.get(
        f"{OTX_API_URL}/pulses/{pulse_id}",
        headers={"X-OTX-API-KEY": settings.otx_api_key},
        timeout=45,
    )
    response.raise_for_status()
    payload = response.json()
    return payload if isinstance(payload, dict) else {}


def _group_search_aliases(group: AptGroup) -> list[str]:
    aliases = [group.name, *(group.aliases or [])]
    normalized_seen: set[str] = set()
    result = []
    for alias in aliases:
        clean = str(alias).strip()
        normalized = normalize_label(clean)
        if len(clean) < 4 or normalized in normalized_seen:
            continue
        normalized_seen.add(normalized)
        result.append(clean)
    return result


def _pulse_matches_group(pulse: dict[str, Any], group: AptGroup) -> bool:
    haystack = normalize_label(
        " ".join(
            [
                str(pulse.get("name") or ""),
                str(pulse.get("adversary") or ""),
                " ".join(str(tag) for tag in (pulse.get("tags") or [])),
                str(pulse.get("description") or ""),
            ]
        )
    )
    return any(
        len(normalize_label(alias)) >= 4 and normalize_label(alias) in haystack
        for alias in [group.name, group.attack_id, *(group.aliases or [])]
        if alias
    )


def _otx_pulse_to_import_items(pulse: dict[str, Any]) -> list[IOCImportItem]:
    items = []
    pulse_name = str(pulse.get("name") or "").strip()
    pulse_id = str(pulse.get("id") or "").strip()
    pulse_url = f"https://otx.alienvault.com/pulse/{pulse_id}" if pulse_id else ""
    tags = [str(tag) for tag in (pulse.get("tags") or []) if str(tag).strip()]
    adversary = str(pulse.get("adversary") or "").strip()
    for indicator in pulse.get("indicators") or []:
        if not isinstance(indicator, dict):
            continue
        value = str(indicator.get("indicator") or "").strip()
        if not value:
            continue
        items.append(
            IOCImportItem(
                value=value,
                indicator_type=str(indicator.get("type") or _infer_ioc_type(value)).lower(),
                actor_name=adversary,
                campaign=pulse_name,
                source=OTX_SOURCE_ID,
                source_url=pulse_url,
                first_seen=indicator.get("created") or pulse.get("created"),
                last_seen=pulse.get("modified") or indicator.get("created"),
                confidence=70 if adversary else 60,
                tlp="clear",
                tags=tags,
                description=str(indicator.get("description") or pulse.get("description") or pulse_name),
                raw={"pulse": {k: pulse.get(k) for k in ("id", "name", "adversary", "created", "modified", "tags")}, "indicator": indicator},
            )
        )
    return items


def _otx_confidence(pulse: dict[str, Any], group: AptGroup) -> int:
    adversary = normalize_label(str(pulse.get("adversary") or ""))
    aliases = {normalize_label(alias) for alias in [group.name, group.attack_id, *(group.aliases or [])] if alias}
    if adversary and any(alias in adversary or adversary in alias for alias in aliases):
        return 80
    return 65


def _otx_evidence(pulse: dict[str, Any], group: AptGroup) -> str:
    adversary = str(pulse.get("adversary") or "").strip()
    name = str(pulse.get("name") or "").strip()
    if adversary:
        return f"OTX pulse adversary '{adversary}' matched {group.name}; pulse: {name}"
    return f"OTX pulse title/tags matched {group.name}; pulse: {name}"


def _parse_custom_feed(text: str, kind: str, source_id: str, source_url: str) -> list[IOCImportItem]:
    if kind == "custom-json":
        payload = json.loads(text)
        records = _json_records(payload)
        return [_record_to_import(record, source_id, source_url) for record in records if _record_value(record)]
    if kind == "custom-csv":
        reader = csv.DictReader(StringIO(text))
        return [_record_to_import(dict(row), source_id, source_url) for row in reader if _record_value(row)]
    if kind == "custom-txt":
        items = []
        for line in text.splitlines():
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            items.append(
                IOCImportItem(
                    value=value,
                    indicator_type=_infer_ioc_type(value),
                    source=source_id,
                    source_url=source_url,
                    confidence=40,
                    description="Custom TXT feed line",
                    raw={"line": value},
                )
            )
        return items
    raise ValueError(f"Unsupported custom feed kind: {kind}")


def _json_records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("indicators", "iocs", "data", "observables", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        return [payload]
    return []


def _record_to_import(record: dict[str, Any], source_id: str, default_source_url: str) -> IOCImportItem:
    value = str(_first(record, "value", "ioc", "indicator", "observable", "artifact") or "").strip()
    tags = _as_tags(_first(record, "tags", "tag", "labels"))
    return IOCImportItem(
        value=value,
        indicator_type=str(_first(record, "type", "indicator_type", "ioc_type") or _infer_ioc_type(value)).lower(),
        actor_attack_id=_optional_str(_first(record, "actor_attack_id", "group_attack_id", "attack_id")),
        actor_name=_optional_str(_first(record, "actor_name", "threat_actor", "intrusion_set", "group")),
        malware_family=_optional_str(_first(record, "malware_family", "malware", "family")),
        campaign=_optional_str(_first(record, "campaign", "operation")),
        source=source_id,
        source_url=_optional_str(_first(record, "source_url", "url", "reference", "link")) or default_source_url,
        first_seen=_optional_str(_first(record, "first_seen", "firstSeen", "created")),
        last_seen=_optional_str(_first(record, "last_seen", "lastSeen", "modified", "date")),
        confidence=_safe_int(_first(record, "confidence", "confidence_level", "score"), 50),
        tlp=_optional_str(_first(record, "tlp", "marking")) or "clear",
        tags=tags,
        description=_optional_str(_first(record, "description", "comment", "evidence")) or "Custom IOC feed record",
        raw=record,
    )


def _record_value(record: dict[str, Any]) -> str:
    return str(_first(record, "value", "ioc", "indicator", "observable", "artifact") or "").strip()


def _first(record: dict[str, Any], *keys: str) -> Any:
    lowered = {str(key).lower(): value for key, value in record.items()}
    for key in keys:
        if key in record and record[key] not in (None, ""):
            return record[key]
        value = lowered.get(key.lower())
        if value not in (None, ""):
            return value
    return None


def _optional_str(value: Any) -> str:
    return str(value).strip() if value not in (None, "") else ""


def _as_tags(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in str(value).split(",") if item.strip()]


def _dedupe_tags(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result = []
    for value in values:
        clean = str(value).strip()
        key = normalize_label(clean)
        if clean and key not in seen:
            seen.add(key)
            result.append(clean)
    return result[:80]


async def _upsert_indicator(session: AsyncSession, item: IOCImportItem) -> tuple[int, bool]:
    stmt = (
        insert(IOCIndicator)
        .values(
            value=item.value,
            indicator_type=item.indicator_type,
            source_id=item.source,
            source_url=item.source_url,
            first_seen=item.first_seen,
            last_seen=item.last_seen,
            confidence=max(0, min(100, item.confidence)),
            tlp=item.tlp,
            malware_family=item.malware_family,
            campaign=item.campaign,
            description=item.description,
            tags=item.tags or [],
            raw=item.raw or {},
        )
        .on_conflict_do_update(
            constraint="uq_ioc_value_type_source",
            set_={
                "source_url": item.source_url,
                "last_seen": item.last_seen,
                "confidence": max(0, min(100, item.confidence)),
                "tlp": item.tlp,
                "malware_family": item.malware_family,
                "campaign": item.campaign,
                "description": item.description,
                "tags": item.tags or [],
                "raw": item.raw or {},
                "updated_at": datetime.now(timezone.utc),
            },
        )
        .returning(IOCIndicator.id)
    )
    indicator_id = (await session.execute(stmt)).scalar_one()
    exists = await session.execute(
        select(IOCIndicator.id).where(
            IOCIndicator.id == indicator_id,
            IOCIndicator.created_at != IOCIndicator.updated_at,
        )
    )
    return indicator_id, exists.scalar_one_or_none() is None


async def _upsert_actor_link(
    session: AsyncSession,
    indicator_id: int,
    actor_attack_id: str,
    actor_name: str,
    source_id: str,
    confidence: int,
    evidence: str,
) -> bool:
    if not actor_attack_id and not actor_name:
        return False
    stmt = insert(IOCActorLink).values(
        indicator_id=indicator_id,
        actor_attack_id=actor_attack_id,
        actor_name=actor_name,
        source_id=source_id,
        relationship_type="attributed-to",
        confidence=max(0, min(100, confidence)),
        evidence=evidence,
    ).on_conflict_do_nothing(constraint="uq_ioc_actor_source")
    result = await session.execute(stmt)
    return bool(result.rowcount)


def _match_actors(item: IOCImportItem, groups: list[AptGroup]) -> list[tuple[AptGroup, str]]:
    haystack = normalize_label(
        " ".join(
            [
                item.malware_family,
                item.campaign,
                item.source_url,
                item.description,
                " ".join(item.tags or []),
            ]
        )
    )
    if not haystack:
        return []
    matches: list[tuple[AptGroup, str]] = []
    for group in groups:
        aliases = [group.name, group.attack_id, *(group.aliases or [])]
        for alias in sorted({normalize_label(alias) for alias in aliases if alias}, key=len, reverse=True):
            if len(alias) < 4:
                continue
            if alias in haystack:
                matches.append((group, f"Source metadata matched actor alias '{alias}'."))
                break
    return matches


def _actor_link_targets(item: IOCImportItem, groups: list[AptGroup]) -> list[tuple[AptGroup, str]]:
    explicit = normalize_label(" ".join([item.actor_attack_id or "", item.actor_name or ""]))
    targets: list[tuple[AptGroup, str]] = []
    matched_ids: set[str] = set()
    if explicit:
        for group in groups:
            aliases = [group.attack_id, group.name, *(group.aliases or [])]
            if group.attack_id not in matched_ids and any(normalize_label(alias) in explicit or explicit in normalize_label(alias) for alias in aliases if alias):
                targets.append((group, "Feed record explicitly mapped this IOC to the actor."))
                matched_ids.add(group.attack_id)
    for group, evidence in _match_actors(item, groups):
        if group.attack_id not in matched_ids:
            targets.append((group, evidence))
            matched_ids.add(group.attack_id)
    return targets


def _infer_ioc_type(value: str) -> str:
    lower = value.lower()
    if re.fullmatch(r"[a-f0-9]{64}", lower):
        return "sha256"
    if re.fullmatch(r"[a-f0-9]{40}", lower):
        return "sha1"
    if re.fullmatch(r"[a-f0-9]{32}", lower):
        return "md5"
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value):
        return "ipv4"
    if lower.startswith(("http://", "https://")):
        return "url"
    if "@" in value and "." in value:
        return "email"
    if "." in value:
        return "domain"
    return "unknown"


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:80] or "feed"


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value[:10]).date()
    except ValueError:
        return None


def _safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
