from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat_radar import (
    ThreatAlert,
    ThreatCase,
    ThreatCompanySpace,
    ThreatEntity,
    ThreatProductMapping,
    ThreatSignal,
    ThreatSpaceAsset,
)
from app.services.taxonomy import canonical_value, normalize_freeform_tags


CANONICAL_ENTITY_TYPES = {
    "actor",
    "alert",
    "asset",
    "asset_type",
    "case",
    "component",
    "company_space",
    "cpe",
    "cve",
    "dependency",
    "domain",
    "environment",
    "exposure",
    "ioc",
    "ip",
    "product",
    "purl",
    "sector",
    "signal",
    "supplier",
    "technology",
    "ttp",
    "url",
}

TAXONOMY_ENTITY_KINDS = {
    "actor": "actor",
    "asset_type": "asset_type",
    "component": "dependency",
    "cve": "cve",
    "dependency": "dependency",
    "environment": "environment",
    "exposure": "exposure",
    "product": "product",
    "sector": "sector",
    "supplier": "supplier",
    "technology": "technology",
    "ttp": "ttp",
}

ASSET_INVENTORY_RELATIONSHIPS = {
    "has-asset-type",
    "runs-in",
    "has-exposure",
    "runs-product",
    "contains-component",
    "uses-technology",
    "has-ip",
    "has-domain",
    "has-cpe",
    "has-purl",
    "depends-on",
    "supplied-by",
    "asset-relevant-ttp",
}


async def upsert_entity(
    session: AsyncSession,
    entity_type: str,
    value: Any,
    *,
    label: str = "",
    tags: list[str] | set[str] | tuple[str, ...] | None = None,
    metadata: dict[str, Any] | None = None,
) -> ThreatEntity | None:
    entity_type = _entity_type(entity_type)
    canonical = _entity_value(entity_type, value)
    if not canonical:
        return None
    existing = (
        await session.execute(
            select(ThreatEntity).where(
                ThreatEntity.entity_type == entity_type,
                ThreatEntity.value == canonical,
            )
        )
    ).scalar_one_or_none()
    row = existing or ThreatEntity(entity_type=entity_type, value=canonical)
    if label and (not row.label or row.label == row.value):
        row.label = str(label)[:500]
    elif not row.label:
        row.label = canonical
    row.tags = _merge_tags(row.tags or [], tags or [], [f"entity:{entity_type}"])
    row.metadata_json = _merge_metadata(row.metadata_json or {}, metadata or {})
    session.add(row)
    await session.flush()
    return row


async def forward_space_asset_to_unified_model(
    session: AsyncSession,
    space: ThreatCompanySpace,
    asset: ThreatSpaceAsset,
) -> None:
    space_entity = await upsert_entity(
        session,
        "company_space",
        f"space:{space.slug or space.id}",
        label=space.name,
        tags=["scope:company-space", *list(space.tags or [])],
        metadata={
            "model": "threat_radar.company_space",
            "space_id": str(space.id),
            "slug": space.slug,
            "owner": space.owner,
            "sector": space.sector,
            "region": space.region,
        },
    )
    asset_value = f"space:{space.slug or space.id}:asset:{asset.asset_id}"
    asset_entity = await upsert_entity(
        session,
        "asset",
        asset_value,
        label=asset.name,
        tags=[
            f"space:{space.slug or space.id}",
            f"criticality:{asset.criticality}",
            f"environment:{asset.environment}",
            f"exposure:{asset.exposure}",
            *list(asset.tags or []),
        ],
        metadata={
            "model": "threat_radar.asset",
            "space_id": str(space.id),
            "asset_uuid": str(asset.id),
            "asset_id": asset.asset_id,
            "asset_type": asset.asset_type,
            "owner": asset.owner,
            "criticality": asset.criticality,
            "environment": asset.environment,
            "exposure": asset.exposure,
            "products": asset.products or [],
            "components": asset.components or [],
            "technologies": asset.technologies or [],
            "ip_addresses": asset.ip_addresses or [],
            "domains": asset.domains or [],
            "raw_metadata": asset.metadata_json or {},
        },
    )
    if not asset_entity:
        return
    asset_entity.label = asset.name
    asset_entity.tags = normalize_freeform_tags([
        "entity:asset",
        f"space:{space.slug or space.id}",
        f"criticality:{asset.criticality}",
        f"environment:{asset.environment}",
        f"exposure:{asset.exposure}",
        *list(asset.tags or []),
    ])
    asset_metadata = dict(asset_entity.metadata_json or {})
    asset_metadata.update({
        "model": "threat_radar.asset",
        "space_id": str(space.id),
        "asset_uuid": str(asset.id),
        "asset_id": asset.asset_id,
        "asset_type": asset.asset_type,
        "owner": asset.owner,
        "criticality": asset.criticality,
        "environment": asset.environment,
        "exposure": asset.exposure,
        "products": asset.products or [],
        "components": asset.components or [],
        "technologies": asset.technologies or [],
        "ip_addresses": asset.ip_addresses or [],
        "domains": asset.domains or [],
        "raw_metadata": asset.metadata_json or {},
    })
    relationships = asset_metadata.get("relationships")
    asset_metadata["relationships"] = [
        row for row in (relationships if isinstance(relationships, list) else [])
        if not isinstance(row, dict)
        or row.get("relationship") not in ASSET_INVENTORY_RELATIONSHIPS
    ]
    asset_entity.metadata_json = asset_metadata
    await _link(space_entity, asset_entity, "contains-asset")
    await _link_asset_values(session, asset_entity, "asset_type", [asset.asset_type], "has-asset-type")
    await _link_asset_values(session, asset_entity, "environment", [asset.environment], "runs-in")
    await _link_asset_values(session, asset_entity, "exposure", [asset.exposure], "has-exposure")
    await _link_asset_values(session, asset_entity, "product", asset.products or [], "runs-product")
    await _link_asset_values(session, asset_entity, "component", asset.components or [], "contains-component")
    await _link_asset_values(session, asset_entity, "technology", asset.technologies or [], "uses-technology")
    await _link_asset_values(session, asset_entity, "ip", asset.ip_addresses or [], "has-ip")
    await _link_asset_values(session, asset_entity, "domain", asset.domains or [], "has-domain")
    metadata = asset.metadata_json or {}
    await _link_asset_values(session, asset_entity, "cpe", _metadata_values(metadata, {"cpe", "cpes"}), "has-cpe")
    await _link_asset_values(session, asset_entity, "purl", _metadata_values(metadata, {"purl", "purls"}), "has-purl")
    await _link_asset_values(session, asset_entity, "dependency", _metadata_values(metadata, {"dependency", "dependencies", "package", "packages"}), "depends-on")
    await _link_asset_values(session, asset_entity, "supplier", _metadata_values(metadata, {"supplier", "suppliers", "vendor", "vendors"}), "supplied-by")
    await _link_asset_values(session, asset_entity, "ttp", _metadata_values(metadata, {"ttp", "ttps", "technique", "techniques", "technique_ids"}), "asset-relevant-ttp")


async def forward_signal_to_unified_model(
    session: AsyncSession,
    signal: ThreatSignal,
    mappings: list[ThreatProductMapping] | None = None,
) -> None:
    mappings = mappings or []
    signal_entity = await upsert_entity(
        session,
        "signal",
        f"signal:{signal.id}",
        label=signal.title,
        tags=[
            f"signal_type:{signal.signal_type}",
            f"severity:{signal.severity}",
            f"confidence:{signal.confidence}",
            *list(signal.tags or []),
        ],
        metadata={
            "model": "threat_radar.signal",
            "signal_id": str(signal.id),
            "signal_type": signal.signal_type,
            "status": signal.status,
            "source_id": str(signal.source_id) if signal.source_id else "",
            "source_name": signal.source_name,
            "source_url": signal.source_url,
            "tlp": signal.tlp,
            "legal_sensitive": signal.legal_sensitive,
            "confidence": signal.confidence,
            "severity": signal.severity,
        },
    )
    await _link_signal_values(session, signal_entity, "cve", signal.cve_ids or [], "mentions-cve")
    await _link_signal_values(session, signal_entity, "ttp", signal.technique_ids or [], "maps-to-technique")
    await _link_signal_values(session, signal_entity, "actor", signal.actors or [], "reported-actor-context")
    await _link_signal_values(session, signal_entity, "sector", signal.sectors or [], "targets-sector")
    for ioc in signal.iocs or []:
        if not isinstance(ioc, dict):
            await _link_signal_values(session, signal_entity, "ioc", [str(ioc)], "observed-indicator")
            continue
        value = str(ioc.get("value") or ioc.get("indicator") or ioc.get("observable") or ioc.get("ioc") or "")
        if not value:
            continue
        ioc_type = str(ioc.get("type") or ioc.get("ioc_type") or "ioc")
        await _link_signal_values(session, signal_entity, ioc_type, [value], "observed-indicator")
    for mapping in mappings:
        await _link_signal_values(session, signal_entity, "product", [mapping.product], "affects-product")
        await _link_signal_values(session, signal_entity, "component", [mapping.component], "affects-component")
        await _link_signal_values(session, signal_entity, "dependency", [mapping.dependency], "affects-dependency")
        await _link_signal_values(session, signal_entity, "exposure", [mapping.exposure], "requires-exposure")
        await _link_signal_values(session, signal_entity, "environment", [mapping.environment], "observed-in-environment")
        await _link_signal_values(session, signal_entity, "ttp", _mapping_techniques(mapping), "maps-to-technique")
    metadata = signal.raw_metadata or {}
    await _link_signal_values(session, signal_entity, "cpe", _metadata_values(metadata, {"cpe", "cpes"}), "mentions-cpe")
    await _link_signal_values(session, signal_entity, "purl", _metadata_values(metadata, {"purl", "purls"}), "mentions-purl")
    await _link_signal_values(session, signal_entity, "supplier", _metadata_values(metadata, {"supplier", "suppliers", "vendor", "vendors"}), "mentions-supplier")


async def forward_case_to_unified_model(
    session: AsyncSession,
    case: ThreatCase,
    signal: ThreatSignal | None = None,
    mappings: list[ThreatProductMapping] | None = None,
) -> None:
    case_entity = await upsert_entity(
        session,
        "case",
        f"case:{case.id}",
        label=case.title,
        tags=[f"priority:{case.priority.split()[0].lower()}", f"status:{case.status}", *list(case.tags or [])],
        metadata={
            "model": "threat_radar.case",
            "case_id": str(case.id),
            "signal_id": str(case.signal_id) if case.signal_id else "",
            "priority": case.priority,
            "risk_score": case.risk_score,
            "status": case.status,
            "legal_sensitive": case.legal_sensitive,
        },
    )
    if signal:
        signal_entity = await upsert_entity(session, "signal", f"signal:{signal.id}", label=signal.title)
        await _link(signal_entity, case_entity, "creates-case")
        await _link(case_entity, signal_entity, "derived-from-signal")
        await forward_signal_to_unified_model(session, signal, mappings or [])


async def forward_alert_to_unified_model(
    session: AsyncSession,
    space: ThreatCompanySpace,
    alert: ThreatAlert,
    signal: ThreatSignal | None = None,
) -> None:
    alert_entity = await upsert_entity(
        session,
        "alert",
        f"alert:{alert.id}",
        label=alert.title,
        tags=[
            f"priority:{alert.priority.split()[0].lower()}",
            f"severity:{alert.severity}",
            f"status:{alert.status}",
            f"match_type:{alert.match_type}",
        ],
        metadata={
            "model": "threat_radar.alert",
            "alert_id": str(alert.id),
            "space_id": str(space.id),
            "signal_id": str(alert.signal_id) if alert.signal_id else "",
            "case_id": str(alert.case_id) if alert.case_id else "",
            "score": alert.score,
            "dedup_key": alert.dedup_key,
            "matches": alert.matches or [],
        },
    )
    space_entity = await upsert_entity(session, "company_space", f"space:{space.slug or space.id}", label=space.name)
    await _link(space_entity, alert_entity, "has-alert")
    if signal:
        signal_entity = await upsert_entity(session, "signal", f"signal:{signal.id}", label=signal.title)
        await _link(signal_entity, alert_entity, "triggered-alert")
        await _link(alert_entity, signal_entity, "alert-source")
    for match in alert.matches or []:
        if not isinstance(match, dict):
            continue
        asset_id = str(match.get("asset_id") or "").strip()
        asset_uuid = str(match.get("asset_uuid") or "").strip()
        asset_name = str(match.get("inventory_entity") or match.get("asset_name") or asset_id).strip()
        if asset_id:
            asset_entity = await upsert_entity(
                session,
                "asset",
                f"space:{space.slug or space.id}:asset:{asset_id}",
                label=asset_name,
                metadata={"asset_uuid": asset_uuid, "space_id": str(space.id)},
            )
            await _link(alert_entity, asset_entity, "matches-asset")
        entity_value = str(match.get("signal_entity") or "").strip()
        if entity_value:
            matched = await upsert_entity(
                session,
                _infer_entity_type(entity_value),
                entity_value,
                tags=[f"match_type:{alert.match_type}"],
            )
            await _link(alert_entity, matched, "matched-entity")


async def forward_existing_threat_radar_to_unified_model(session: AsyncSession) -> dict[str, int]:
    counts = {"spaces": 0, "assets": 0, "signals": 0, "cases": 0, "alerts": 0}
    spaces = list((await session.execute(select(ThreatCompanySpace))).scalars().all())
    space_by_id = {space.id: space for space in spaces}
    for company_space in spaces:
        await upsert_entity(
            session,
            "company_space",
            f"space:{company_space.slug or company_space.id}",
            label=company_space.name,
            tags=["scope:company-space", *list(company_space.tags or [])],
            metadata={
                "model": "threat_radar.company_space",
                "space_id": str(company_space.id),
                "slug": company_space.slug,
            },
        )
        counts["spaces"] += 1
    assets = list((await session.execute(select(ThreatSpaceAsset))).scalars().all())
    for asset in assets:
        asset_space = space_by_id.get(asset.space_id)
        if not asset_space:
            continue
        await forward_space_asset_to_unified_model(session, asset_space, asset)
        counts["assets"] += 1
    signals = list((await session.execute(select(ThreatSignal))).scalars().all())
    for radar_signal in signals:
        mappings = list(
            (
                await session.execute(
                    select(ThreatProductMapping).where(
                        ThreatProductMapping.signal_id == radar_signal.id
                    )
                )
            ).scalars().all()
        )
        await forward_signal_to_unified_model(session, radar_signal, mappings)
        counts["signals"] += 1
    cases = list((await session.execute(select(ThreatCase))).scalars().all())
    signal_by_id = {signal.id: signal for signal in signals}
    for case in cases:
        case_signal = signal_by_id.get(case.signal_id) if case.signal_id else None
        mappings = []
        if case_signal:
            mappings = list(
                (
                    await session.execute(
                        select(ThreatProductMapping).where(
                            ThreatProductMapping.signal_id == case_signal.id
                        )
                    )
                ).scalars().all()
            )
        await forward_case_to_unified_model(session, case, case_signal, mappings)
        counts["cases"] += 1
    alerts = list((await session.execute(select(ThreatAlert))).scalars().all())
    for alert in alerts:
        alert_space = space_by_id.get(alert.space_id)
        if not alert_space:
            continue
        alert_signal = signal_by_id.get(alert.signal_id) if alert.signal_id else None
        await forward_alert_to_unified_model(session, alert_space, alert, alert_signal)
        counts["alerts"] += 1
    return counts


async def _link_asset_values(
    session: AsyncSession,
    source: ThreatEntity | None,
    entity_type: str,
    values: list[Any],
    relationship: str,
) -> None:
    for value in values:
        target = await upsert_entity(session, entity_type, value)
        await _link(source, target, relationship)


async def _link_signal_values(
    session: AsyncSession,
    source: ThreatEntity | None,
    entity_type: str,
    values: list[Any],
    relationship: str,
) -> None:
    for value in values:
        target = await upsert_entity(session, entity_type, value)
        await _link(source, target, relationship)


async def _link(source: ThreatEntity | None, target: ThreatEntity | None, relationship: str) -> None:
    if not source or not target:
        return
    metadata = dict(source.metadata_json or {})
    relationships = metadata.get("relationships")
    if not isinstance(relationships, list):
        relationships = []
    item = {
        "relationship": relationship,
        "target_type": target.entity_type,
        "target_value": target.value,
        "target_label": target.label or target.value,
    }
    key = (item["relationship"], item["target_type"], item["target_value"])
    if not any((row.get("relationship"), row.get("target_type"), row.get("target_value")) == key for row in relationships if isinstance(row, dict)):
        relationships.append(item)
    metadata["relationships"] = relationships[-500:]
    source.metadata_json = metadata


def _entity_type(value: str) -> str:
    normalized = str(value or "ioc").strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "ipv4": "ip",
        "ipv4_addr": "ip",
        "ipv6": "ip",
        "ipv6_addr": "ip",
        "hash_sha256": "ioc",
        "sha256": "ioc",
        "attack": "ttp",
        "technique": "ttp",
        "technique_id": "ttp",
        "group": "actor",
        "threat_actor": "actor",
    }
    normalized = aliases.get(normalized, normalized)
    return normalized if normalized in CANONICAL_ENTITY_TYPES else "ioc"


def _entity_value(entity_type: str, value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    taxonomy_kind = TAXONOMY_ENTITY_KINDS.get(entity_type)
    if taxonomy_kind:
        return canonical_value(taxonomy_kind, raw)
    if entity_type == "ip":
        return raw.lower()
    if entity_type in {"domain", "url", "ioc", "cpe", "purl", "signal", "alert", "case", "asset", "company_space"}:
        return raw.strip().lower()
    return raw.strip().lower()


def _merge_tags(*groups: Any) -> list[str]:
    values: list[str] = []
    for group in groups:
        if group is None:
            continue
        if isinstance(group, str):
            values.append(group)
            continue
        try:
            values.extend(str(item) for item in group if item)
        except TypeError:
            values.append(str(group))
    return normalize_freeform_tags(values, limit=160)


def _merge_metadata(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing or {})
    for key, value in (incoming or {}).items():
        if value in (None, "", [], {}):
            continue
        if key == "relationships" and isinstance(value, list):
            current = merged.get("relationships")
            merged["relationships"] = [*(current if isinstance(current, list) else []), *value][-500:]
            continue
        merged[key] = value
    return merged


def _metadata_values(metadata: dict[str, Any], keys: set[str]) -> list[str]:
    result: list[str] = []
    lowered = {str(key).lower() for key in keys}
    for key, value in (metadata or {}).items():
        if str(key).lower() not in lowered:
            continue
        result.extend(_listify(value))
    return [str(item).strip() for item in result if str(item).strip()]


def _mapping_techniques(mapping: ThreatProductMapping) -> list[str]:
    values: list[str] = []
    for tag in mapping.tags or []:
        text = str(tag)
        if text.startswith("ttp:"):
            values.append(text.split(":", 1)[1])
        elif text.upper().startswith("T") and len(text) >= 5:
            values.append(text)
    return values


def _infer_entity_type(value: str) -> str:
    text = value.strip().lower()
    if text.startswith("cve-"):
        return "cve"
    if text.startswith("t") and len(text) >= 5 and text[1:5].isdigit():
        return "ttp"
    if text.startswith("pkg:"):
        return "purl"
    if text.startswith("cpe:"):
        return "cpe"
    if text.startswith(("http://", "https://")):
        return "url"
    if text.count(".") == 3 and all(part.isdigit() for part in text.split(".")):
        return "ip"
    if "." in text and " " not in text and "/" not in text:
        return "domain"
    return "ioc"


def _listify(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple | set):
        return list(value)
    if isinstance(value, str):
        return [part.strip() for part in value.replace("\n", ",").replace(";", ",").split(",") if part.strip()]
    return [value]


def entity_reference(entity_type: str, entity_id: uuid.UUID | str) -> str:
    return f"{_entity_type(entity_type)}:{entity_id}"
