from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analysis import AnalysisResult
from app.models.asset_surface import AssetIntelMatch, AssetRegistryItem, AssetSurfaceCase
from app.models.cve import CVERecord
from app.models.evidence_graph import EvidenceGraphNode
from app.models.ioc import IOCIndicator
from app.models.knowledge import KnowledgeArticle
from app.models.pipeline import Observable
from app.models.retrohunt import RetroHuntSignal
from app.models.sector import ActorIntelObservation, ClientProfile
from app.models.threat_radar import ThreatCase, ThreatEntity, ThreatProductMapping, ThreatSignal
from app.services.taxonomy import (
    asset_labels,
    canonical_value,
    canonical_values,
    labels_to_tags,
    normalize_freeform_tags,
)
from app.services.unified_model import forward_existing_threat_radar_to_unified_model


async def normalize_existing_taxonomy(session: AsyncSession, *, commit: bool = True) -> dict[str, Any]:
    """Normalize existing DB rows to the shared namespace:value taxonomy."""
    stats: dict[str, Any] = {"tables": {}, "rows_changed": 0}
    await _normalize_analysis_results(session, stats)
    await _normalize_iocs(session, stats)
    await _normalize_cves(session, stats)
    await _normalize_assets(session, stats)
    await _normalize_asset_cases(session, stats)
    await _normalize_knowledge(session, stats)
    await _normalize_pipeline(session, stats)
    await _normalize_evidence_graph(session, stats)
    await _normalize_retrohunt(session, stats)
    await _normalize_sector_intel(session, stats)
    await _normalize_threat_radar(session, stats)
    if commit:
        await session.commit()
    return stats


async def taxonomy_normalization_status(session: AsyncSession) -> dict[str, Any]:
    """Return a lightweight status summary for self-test and troubleshooting."""
    tables = {
        "ioc_indicators": (IOCIndicator, "tags"),
        "cve_records": (CVERecord, "tags"),
        "asset_registry_items": (AssetRegistryItem, "tags"),
        "asset_intel_matches": (AssetIntelMatch, "tags"),
        "knowledge_articles": (KnowledgeArticle, "tags"),
        "observables": (Observable, "tags"),
        "evidence_graph_nodes": (EvidenceGraphNode, "tags"),
        "threat_signals": (ThreatSignal, "tags"),
        "threat_entities": (ThreatEntity, "tags"),
        "threat_cases": (ThreatCase, "tags"),
        "threat_product_mappings": (ThreatProductMapping, "tags"),
    }
    checked = 0
    raw_examples: dict[str, list[str]] = {}
    for table_name, (model, attr) in tables.items():
        rows = list((await session.execute(select(model).limit(500))).scalars().all())
        checked += len(rows)
        examples: list[str] = []
        for row in rows:
            for value in getattr(row, attr, None) or []:
                text = str(value)
                if text and ":" not in text and len(examples) < 5:
                    examples.append(text)
        if examples:
            raw_examples[table_name] = examples
    return {
        "checked_rows": checked,
        "normalized": not raw_examples,
        "raw_tag_examples": raw_examples,
        "convention": "namespace:value",
    }


async def _normalize_analysis_results(session: AsyncSession, stats: dict[str, Any]) -> None:
    changed = 0
    rows = list((await session.execute(select(AnalysisResult))).scalars().all())
    for row in rows:
        techniques = []
        for item in row.extracted_techniques or []:
            if not isinstance(item, dict):
                continue
            new_item = dict(item)
            new_item["attack_id"] = canonical_value("ttp", item.get("attack_id"))
            techniques.append(new_item)
        apt_matches = []
        for item in row.apt_matches or []:
            if not isinstance(item, dict):
                continue
            new_item = dict(item)
            if new_item.get("group_attack_id"):
                new_item["group_attack_id"] = canonical_value("actor", new_item.get("group_attack_id"))
            if isinstance(new_item.get("shared_techniques"), list):
                new_item["shared_techniques"] = canonical_values("ttp", new_item["shared_techniques"])
            apt_matches.append(new_item)
        if techniques != (row.extracted_techniques or []) or apt_matches != (row.apt_matches or []):
            row.extracted_techniques = techniques
            row.apt_matches = apt_matches
            changed += 1
    _record(stats, "analysis_results", len(rows), changed)


async def _normalize_iocs(session: AsyncSession, stats: dict[str, Any]) -> None:
    changed = 0
    rows = list((await session.execute(select(IOCIndicator))).scalars().all())
    for row in rows:
        tags = normalize_freeform_tags(row.tags or [])
        technique_ids = canonical_values("ttp", row.technique_ids or [])
        raw = dict(row.raw or {})
        if row.tags and row.tags != tags:
            raw.setdefault("original_tags", row.tags)
        if tags != (row.tags or []) or technique_ids != (row.technique_ids or []):
            row.tags = tags
            row.technique_ids = technique_ids
            row.raw = raw
            changed += 1
    _record(stats, "ioc_indicators", len(rows), changed)


async def _normalize_cves(session: AsyncSession, stats: dict[str, Any]) -> None:
    changed = 0
    rows = list((await session.execute(select(CVERecord))).scalars().all())
    for row in rows:
        tags = normalize_freeform_tags(row.tags or [])
        raw = dict(row.raw or {})
        if row.tags and row.tags != tags:
            raw.setdefault("original_tags", row.tags)
        if tags != (row.tags or []):
            row.tags = tags
            row.raw = raw
            changed += 1
    _record(stats, "cve_records", len(rows), changed)


async def _normalize_assets(session: AsyncSession, stats: dict[str, Any]) -> None:
    changed_assets = 0
    assets = list((await session.execute(select(AssetRegistryItem))).scalars().all())
    for row in assets:
        technologies = canonical_values("technology", row.technologies or [])
        products = canonical_values("product", row.products or [])
        suppliers = canonical_values("supplier", row.suppliers or [])
        dependencies = canonical_values("dependency", row.dependencies or [])
        technique_ids = canonical_values("ttp", row.technique_ids or [])
        labels = asset_labels(
            asset_type=row.asset_type,
            environment=row.environment,
            exposure=row.exposure,
            criticality=row.criticality,
            technologies=technologies,
            products=products,
            suppliers=suppliers,
            dependencies=dependencies,
            ttps=technique_ids,
            extra_tags=row.tags or [],
        )
        tags = labels_to_tags(labels)
        new_values = {
            "asset_type": canonical_value("asset_type", row.asset_type) or "unknown",
            "environment": canonical_value("environment", row.environment) or "unknown",
            "exposure": canonical_value("exposure", row.exposure) or "unknown",
            "criticality": canonical_value("risk", row.criticality) or "medium",
            "risk_level": canonical_value("risk", row.risk_level) or "low",
            "technologies": technologies,
            "products": products,
            "suppliers": suppliers,
            "dependencies": dependencies,
            "technique_ids": technique_ids,
            "labels": labels,
            "tags": tags,
        }
        if any(getattr(row, key) != value for key, value in new_values.items()):
            raw = dict(row.raw or {})
            raw.setdefault("taxonomy_original", {
                "asset_type": row.asset_type,
                "environment": row.environment,
                "exposure": row.exposure,
                "criticality": row.criticality,
                "risk_level": row.risk_level,
                "technologies": row.technologies,
                "products": row.products,
                "suppliers": row.suppliers,
                "dependencies": row.dependencies,
                "technique_ids": row.technique_ids,
                "tags": row.tags,
            })
            for key, value in new_values.items():
                setattr(row, key, value)
            row.raw = raw
            changed_assets += 1
    _record(stats, "asset_registry_items", len(assets), changed_assets)

    changed_matches = 0
    matches = list((await session.execute(select(AssetIntelMatch))).scalars().all())
    for match in matches:
        tags = normalize_freeform_tags(match.tags or [])
        if tags != (match.tags or []):
            match.tags = tags
            changed_matches += 1
    _record(stats, "asset_intel_matches", len(matches), changed_matches)


async def _normalize_asset_cases(session: AsyncSession, stats: dict[str, Any]) -> None:
    changed = 0
    rows = list((await session.execute(select(AssetSurfaceCase))).scalars().all())
    for row in rows:
        technique_ids = canonical_values("ttp", row.technique_ids or [])
        result = _normalize_asset_surface_result(row.result or {})
        if technique_ids != (row.technique_ids or []) or result != (row.result or {}):
            row.technique_ids = technique_ids
            row.result = result
            changed += 1
    _record(stats, "asset_surface_cases", len(rows), changed)


async def _normalize_knowledge(session: AsyncSession, stats: dict[str, Any]) -> None:
    changed = 0
    rows = list((await session.execute(select(KnowledgeArticle))).scalars().all())
    for row in rows:
        tags = normalize_freeform_tags(row.tags or [])
        meta = dict(row.meta or {})
        if row.tags and row.tags != tags:
            meta.setdefault("original_tags", row.tags)
        if tags != (row.tags or []):
            row.tags = tags
            row.meta = meta
            changed += 1
    _record(stats, "knowledge_articles", len(rows), changed)


async def _normalize_pipeline(session: AsyncSession, stats: dict[str, Any]) -> None:
    changed = 0
    rows = list((await session.execute(select(Observable))).scalars().all())
    for row in rows:
        tags = normalize_freeform_tags(row.tags or [])
        if tags != (row.tags or []):
            row.tags = tags
            changed += 1
    _record(stats, "observables", len(rows), changed)


async def _normalize_evidence_graph(session: AsyncSession, stats: dict[str, Any]) -> None:
    changed = 0
    rows = list((await session.execute(select(EvidenceGraphNode))).scalars().all())
    for row in rows:
        tags = normalize_freeform_tags(row.tags or [])
        attack_techniques = canonical_values("ttp", row.attack_techniques or [])
        metadata = dict(row.metadata_json or {})
        if row.tags and row.tags != tags:
            metadata.setdefault("original_tags", row.tags)
        if tags != (row.tags or []) or attack_techniques != (row.attack_techniques or []):
            row.tags = tags
            row.attack_techniques = attack_techniques
            row.metadata_json = metadata
            changed += 1
    _record(stats, "evidence_graph_nodes", len(rows), changed)


async def _normalize_retrohunt(session: AsyncSession, stats: dict[str, Any]) -> None:
    changed = 0
    rows = list((await session.execute(select(RetroHuntSignal))).scalars().all())
    for row in rows:
        sector_tags = canonical_values("sector", row.sector_tags or [])
        tech_tags = canonical_values("technology", row.tech_tags or [])
        cve_ids = canonical_values("cve", row.cve_ids or [])
        product_tags = canonical_values("product", row.product_tags or [])
        if (
            sector_tags != (row.sector_tags or [])
            or tech_tags != (row.tech_tags or [])
            or cve_ids != (row.cve_ids or [])
            or product_tags != (row.product_tags or [])
        ):
            raw = dict(row.raw_json or {})
            raw.setdefault("taxonomy_original", {
                "sector_tags": row.sector_tags,
                "tech_tags": row.tech_tags,
                "cve_ids": row.cve_ids,
                "product_tags": row.product_tags,
            })
            # RetroHuntSignal currently uses legacy ``Column`` declarations;
            # apply the normalized mapping dynamically so this migration also
            # remains compatible once that model moves to typed mappings.
            normalized_fields = {
                "sector_tags": sector_tags,
                "tech_tags": tech_tags,
                "cve_ids": cve_ids,
                "product_tags": product_tags,
                "raw_json": raw,
            }
            for field_name, field_value in normalized_fields.items():
                setattr(row, field_name, field_value)
            changed += 1
    _record(stats, "retrohunt_signals", len(rows), changed)


async def _normalize_sector_intel(session: AsyncSession, stats: dict[str, Any]) -> None:
    changed_profiles = 0
    profiles = list((await session.execute(select(ClientProfile))).scalars().all())
    for profile in profiles:
        sector = canonical_value("sector", profile.sector)
        technologies = canonical_values("technology", profile.technologies or [])
        if sector != profile.sector or technologies != (profile.technologies or []):
            profile.sector = sector
            profile.technologies = technologies
            changed_profiles += 1
    _record(stats, "client_profiles", len(profiles), changed_profiles)

    changed_observations = 0
    observations = list((await session.execute(select(ActorIntelObservation))).scalars().all())
    for observation in observations:
        actor_attack_id = (
            canonical_value("actor", observation.actor_attack_id)
            if observation.actor_attack_id
            else observation.actor_attack_id
        )
        normalized_value = _observation_value(
            observation.observation_type,
            observation.normalized_value or observation.value,
        )
        if (
            actor_attack_id != observation.actor_attack_id
            or normalized_value != observation.normalized_value
        ):
            observation.actor_attack_id = actor_attack_id
            observation.normalized_value = normalized_value
            changed_observations += 1
    _record(stats, "actor_intel_observations", len(observations), changed_observations)


async def _normalize_threat_radar(session: AsyncSession, stats: dict[str, Any]) -> None:
    changed_signals = 0
    signals = list((await session.execute(select(ThreatSignal))).scalars().all())
    for signal in signals:
        values = {
            "cve_ids": canonical_values("cve", signal.cve_ids or []),
            "technique_ids": canonical_values("ttp", signal.technique_ids or []),
            "actors": canonical_values("actor", signal.actors or []),
            "sectors": canonical_values("sector", signal.sectors or []),
            "tags": normalize_freeform_tags(signal.tags or []),
        }
        if any(getattr(signal, key) != value for key, value in values.items()):
            raw = dict(signal.raw_metadata or {})
            raw.setdefault("taxonomy_original", {
                "cve_ids": signal.cve_ids,
                "technique_ids": signal.technique_ids,
                "actors": signal.actors,
                "sectors": signal.sectors,
                "tags": signal.tags,
            })
            for key, value in values.items():
                setattr(signal, key, value)
            signal.raw_metadata = raw
            changed_signals += 1
    _record(stats, "threat_signals", len(signals), changed_signals)

    changed_entities = 0
    entities = list((await session.execute(select(ThreatEntity))).scalars().all())
    for entity in entities:
        tags = normalize_freeform_tags(entity.tags or [])
        if tags != (entity.tags or []):
            metadata = dict(entity.metadata_json or {})
            metadata.setdefault("original_tags", entity.tags)
            entity.tags = tags
            entity.metadata_json = metadata
            changed_entities += 1
    _record(stats, "threat_entities", len(entities), changed_entities)

    changed_cases = 0
    cases = list((await session.execute(select(ThreatCase))).scalars().all())
    for case in cases:
        tags = normalize_freeform_tags(case.tags or [])
        if tags != (case.tags or []):
            case.tags = tags
            changed_cases += 1
    _record(stats, "threat_cases", len(cases), changed_cases)

    changed_mappings = 0
    mappings = list((await session.execute(select(ThreatProductMapping))).scalars().all())
    for mapping in mappings:
        product = canonical_value("product", mapping.product) if mapping.product else mapping.product
        component = (
            canonical_value("dependency", mapping.component)
            if mapping.component
            else mapping.component
        )
        dependency = (
            canonical_value("dependency", mapping.dependency)
            if mapping.dependency
            else mapping.dependency
        )
        exposure = canonical_value("exposure", mapping.exposure)
        environment = canonical_value("environment", mapping.environment)
        tags = normalize_freeform_tags(
            [
                *(mapping.tags or []),
                f"product:{product}" if product else "",
                f"dependency:{component}" if component else "",
                f"dependency:{dependency}" if dependency else "",
                f"exposure:{exposure}" if exposure else "",
                f"environment:{environment}" if environment else "",
            ]
        )
        if (
            tags != (mapping.tags or [])
            or product != mapping.product
            or component != mapping.component
            or dependency != mapping.dependency
            or exposure != mapping.exposure
            or environment != mapping.environment
        ):
            mapping.tags = tags
            mapping.product = product
            mapping.component = component
            mapping.dependency = dependency
            mapping.exposure = exposure
            mapping.environment = environment
            changed_mappings += 1
    _record(stats, "threat_product_mappings", len(mappings), changed_mappings)

    stats["unified_model_forwarding"] = await forward_existing_threat_radar_to_unified_model(session)


def _normalize_asset_surface_result(result: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(result, dict):
        return result
    updated = dict(result)
    assets = []
    for asset in updated.get("assets") or []:
        if not isinstance(asset, dict):
            assets.append(asset)
            continue
        row = dict(asset)
        row["asset_type"] = canonical_value("asset_type", row.get("asset_type")) or "unknown"
        row["environment"] = canonical_value("environment", row.get("environment")) or "unknown"
        row["exposure"] = canonical_value("exposure", row.get("exposure")) or "unknown"
        row["criticality"] = canonical_value("risk", row.get("criticality")) or "medium"
        row["risk_level"] = canonical_value("risk", row.get("risk_level")) or "low"
        row["technologies"] = canonical_values("technology", row.get("technologies") or [])
        row["products"] = canonical_values("product", row.get("products") or [])
        row["suppliers"] = canonical_values("supplier", row.get("suppliers") or [])
        row["dependencies"] = canonical_values("dependency", row.get("dependencies") or [])
        ttp_ids = [item.get("attack_id") for item in row.get("ttp_candidates") or [] if isinstance(item, dict)]
        row["labels"] = asset_labels(
            asset_type=row["asset_type"],
            environment=row["environment"],
            exposure=row["exposure"],
            criticality=row["criticality"],
            technologies=row["technologies"],
            products=row["products"],
            suppliers=row["suppliers"],
            dependencies=row["dependencies"],
            ttps=ttp_ids,
            extra_tags=row.get("tags") or [],
        )
        assets.append(row)
    updated["assets"] = assets
    return updated


def _observation_value(kind: str, value: Any) -> str:
    normalized_kind = str(kind or "").lower()
    if normalized_kind in {"sector", "industry"}:
        return canonical_value("sector", value)
    if normalized_kind in {"technology", "tech"}:
        return canonical_value("technology", value)
    if normalized_kind in {"product", "vendor", "supplier"}:
        return canonical_value("product", value)
    if normalized_kind in {"region", "geo"}:
        return canonical_value("region", value)
    return canonical_value("tag", value)


def _record(stats: dict[str, Any], table: str, scanned: int, changed: int) -> None:
    stats["tables"][table] = {"scanned": scanned, "changed": changed}
    stats["rows_changed"] += changed
