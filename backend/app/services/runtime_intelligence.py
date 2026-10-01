"""Persistence, asset linking, and governed promotion for runtime topology."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.asset_surface import AssetRegistryItem
from app.models.evidence_graph import EvidenceGraphEdge, EvidenceGraphNode
from app.models.runtime_intelligence import (
    RuntimeAssetLink,
    RuntimeCall,
    RuntimeService,
    RuntimeTopologySnapshot,
)
from app.services import evidence_graph

_TOKEN_STOPWORDS = frozenset({
    "app", "application", "cloud", "com", "dev", "development", "http",
    "https", "internal", "io", "local", "net", "org", "prod",
    "production", "service", "stage", "staging", "unknown",
})


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _tokens(*values: Any) -> set[str]:
    output: set[str] = set()
    for value in values:
        items = value if isinstance(value, list) else [value]
        for item in items:
            text = str(item or "").casefold()
            output.update(
                part
                for part in text.replace("::", ".").replace("/", ".").split(".")
                if len(part) >= 3 and part not in _TOKEN_STOPWORDS
            )
    return output


async def persist_topology(
    db: AsyncSession,
    topology: dict[str, Any],
    *,
    actor: str,
    tlp: str = "TLP:AMBER+STRICT",
) -> dict[str, Any]:
    observed_to = _now()
    observed_from = observed_to - timedelta(minutes=int(topology.get("window_minutes") or 60))
    snapshot = RuntimeTopologySnapshot(
        source="apache_skywalking",
        scope=str(topology.get("scope") or "global")[:500],
        query=str(topology.get("query") or "")[:500],
        window_minutes=int(topology.get("window_minutes") or 60),
        observed_from=observed_from,
        observed_to=observed_to,
        node_count=len(topology.get("nodes") or []),
        edge_count=len(topology.get("edges") or []),
        truncated=bool(topology.get("truncated")),
        synced_by=actor[:255],
        provenance=dict(topology.get("provenance") or {}),
    )
    db.add(snapshot)
    await db.flush()

    external_ids = [str(node.get("id")) for node in topology.get("nodes", []) if node.get("id")]
    existing = list((await db.execute(
        select(RuntimeService).where(
            RuntimeService.source == "apache_skywalking",
            RuntimeService.external_id.in_(external_ids),
        )
    )).scalars().all()) if external_ids else []
    services = {row.external_id: row for row in existing}
    created = 0
    updated = 0
    for node in topology.get("nodes", []):
        external_id = str(node.get("id") or "")
        if not external_id:
            continue
        row = services.get(external_id)
        tags = sorted({
            "source:apache-skywalking",
            "evidence:runtime-observation",
            *(f"runtime-layer:{str(layer).casefold()}" for layer in (node.get("layers") or [])),
            f"technology:{str(node.get('technology') or 'unknown').casefold()}",
        })
        if row is None:
            row = RuntimeService(
                source="apache_skywalking",
                external_id=external_id,
                name=str(node.get("label") or external_id)[:500],
                technology=str(node.get("technology") or "unknown")[:160],
                layers=list(node.get("layers") or [])[:20],
                observed=bool(node.get("observed")),
                first_observed_at=observed_from,
                last_observed_at=observed_to,
                tlp=tlp,
                tags=tags,
                metadata_json={"latest_snapshot_id": str(snapshot.id)},
            )
            db.add(row)
            services[external_id] = row
            created += 1
        else:
            row.name = str(node.get("label") or row.name)[:500]
            row.technology = str(node.get("technology") or row.technology)[:160]
            row.layers = list(node.get("layers") or [])[:20]
            row.observed = bool(node.get("observed"))
            row.last_observed_at = observed_to
            row.observation_count = int(row.observation_count or 0) + 1
            row.tags = tags
            row.metadata_json = {**(row.metadata_json or {}), "latest_snapshot_id": str(snapshot.id)}
            updated += 1
    await db.flush()

    edge_ids = [str(edge.get("id")) for edge in topology.get("edges", []) if edge.get("id")]
    existing_calls = list((await db.execute(
        select(RuntimeCall).where(
            RuntimeCall.source == "apache_skywalking",
            RuntimeCall.external_id.in_(edge_ids),
        )
    )).scalars().all()) if edge_ids else []
    calls = {row.external_id: row for row in existing_calls}
    call_created = 0
    call_updated = 0
    for edge in topology.get("edges", []):
        external_id = str(edge.get("id") or "")
        source_row = services.get(str(edge.get("source") or ""))
        target_row = services.get(str(edge.get("target") or ""))
        if not external_id or source_row is None or target_row is None:
            continue
        row = calls.get(external_id)
        if row is None:
            row = RuntimeCall(
                source="apache_skywalking",
                external_id=external_id,
                source_service_id=source_row.id,
                target_service_id=target_row.id,
                source_components=list(edge.get("source_components") or [])[:30],
                target_components=list(edge.get("target_components") or [])[:30],
                detect_points=list(edge.get("detect_points") or [])[:10],
                first_observed_at=observed_from,
                last_observed_at=observed_to,
                metadata_json={"latest_snapshot_id": str(snapshot.id)},
            )
            db.add(row)
            call_created += 1
        else:
            row.last_observed_at = observed_to
            row.observation_count = int(row.observation_count or 0) + 1
            row.source_components = list(edge.get("source_components") or [])[:30]
            row.target_components = list(edge.get("target_components") or [])[:30]
            row.detect_points = list(edge.get("detect_points") or [])[:10]
            row.metadata_json = {**(row.metadata_json or {}), "latest_snapshot_id": str(snapshot.id)}
            call_updated += 1
    await db.flush()

    asset_links = await _link_assets(db, list(services.values()))
    return {
        "snapshot_id": str(snapshot.id),
        "services_created": created,
        "services_updated": updated,
        "calls_created": call_created,
        "calls_updated": call_updated,
        "asset_links_created": asset_links,
    }


async def _link_assets(db: AsyncSession, services: list[RuntimeService]) -> int:
    assets = list((await db.execute(select(AssetRegistryItem).order_by(AssetRegistryItem.id))).scalars().all())
    created = 0
    for service in services:
        service_tokens = _tokens(service.name, service.technology)
        if not service_tokens:
            continue
        for asset in assets:
            asset_tokens = _tokens(
                asset.name, asset.inventory_asset_id, asset.domains,
                asset.ip_addresses, asset.technologies, asset.products,
            )
            overlap = sorted(service_tokens & asset_tokens)
            if not overlap:
                continue
            existing = await db.scalar(select(RuntimeAssetLink).where(
                RuntimeAssetLink.runtime_service_id == service.id,
                RuntimeAssetLink.asset_id == asset.id,
            ))
            if existing is None:
                db.add(RuntimeAssetLink(
                    runtime_service_id=service.id,
                    asset_id=asset.id,
                    match_basis=f"Shared normalized inventory/runtime tokens: {', '.join(overlap[:10])}",
                    confidence=min(90, 50 + len(overlap) * 10),
                    review_status="candidate",
                ))
                created += 1
    await db.flush()
    return created


async def list_runtime_graph(db: AsyncSession, query: str = "", limit: int = 200) -> dict[str, Any]:
    statement = select(RuntimeService).order_by(RuntimeService.last_observed_at.desc()).limit(limit)
    if query.strip():
        pattern = f"%{query.strip()}%"
        statement = statement.where(or_(RuntimeService.name.ilike(pattern), RuntimeService.technology.ilike(pattern)))
    services = list((await db.execute(statement)).scalars().all())
    ids = {row.id for row in services}
    calls = list((await db.execute(
        select(RuntimeCall).where(
            RuntimeCall.source_service_id.in_(ids),
            RuntimeCall.target_service_id.in_(ids),
        ).order_by(RuntimeCall.last_observed_at.desc()).limit(limit * 4)
    )).scalars().all()) if ids else []
    links = list((await db.execute(
        select(RuntimeAssetLink).where(RuntimeAssetLink.runtime_service_id.in_(ids))
    )).scalars().all()) if ids else []
    asset_ids = {link.asset_id for link in links}
    assets = list((await db.execute(
        select(AssetRegistryItem).where(AssetRegistryItem.id.in_(asset_ids))
    )).scalars().all()) if asset_ids else []
    assets_by_id = {asset.id: asset for asset in assets}
    return {
        "nodes": [{
            "id": str(row.id), "external_id": row.external_id, "label": row.name,
            "technology": row.technology, "layers": row.layers, "tags": row.tags,
            "first_observed_at": row.first_observed_at.isoformat(),
            "last_observed_at": row.last_observed_at.isoformat(),
            "observation_count": row.observation_count, "tlp": row.tlp,
        } for row in services],
        "edges": [{
            "id": str(row.id), "source": str(row.source_service_id),
            "target": str(row.target_service_id), "source_components": row.source_components,
            "target_components": row.target_components, "detect_points": row.detect_points,
            "last_observed_at": row.last_observed_at.isoformat(),
            "observation_count": row.observation_count,
        } for row in calls],
        "counts": {"nodes": len(services), "edges": len(calls)},
        "asset_links": [{
            "runtime_service_id": str(link.runtime_service_id),
            "asset_id": str(link.asset_id),
            "asset_name": assets_by_id[link.asset_id].name if link.asset_id in assets_by_id else "",
            "match_basis": link.match_basis,
            "confidence": link.confidence,
            "review_status": link.review_status,
            "route": f"/asset-surface?asset={link.asset_id}",
        } for link in links],
        "source": "adversarygraph_runtime_store",
    }


async def promote_to_evidence_graph(
    db: AsyncSession,
    service_ids: list[str],
    *,
    actor: str,
) -> dict[str, Any]:
    selected = list((await db.execute(
        select(RuntimeService).where(RuntimeService.id.in_(service_ids))
    )).scalars().all())
    if not selected:
        return {"nodes_created": 0, "edges_created": 0}
    existing_nodes = list((await db.execute(
        select(EvidenceGraphNode).where(EvidenceGraphNode.source_type == "skywalking_runtime")
    )).scalars().all())
    by_ref = {row.source_ref: row for row in existing_nodes}
    promoted: dict[Any, EvidenceGraphNode] = {}
    created_nodes = 0
    for service in selected:
        ref = f"runtime-service:{service.id}"
        node = by_ref.get(ref)
        if node is None:
            node = await evidence_graph.create_node(db, {
                "node_type": "evidence",
                "title": f"Observed runtime service: {service.name}",
                "description": (
                    f"Apache SkyWalking observed this service as {service.technology}. "
                    "This is runtime telemetry, not proof of malicious activity."
                ),
                "source_type": "skywalking_runtime",
                "source_ref": ref,
                "timestamp_observed": service.last_observed_at,
                "availability_status": "available",
                "review_status": "needs_evidence",
                "confidence": 70,
                "tags": service.tags,
                "metadata_json": {
                    "runtime_service_id": str(service.id),
                    "external_id": service.external_id,
                    "layers": service.layers,
                    "tlp": service.tlp,
                },
            }, actor)
            created_nodes += 1
        promoted[service.id] = node
    calls = list((await db.execute(select(RuntimeCall).where(
        RuntimeCall.source_service_id.in_(promoted),
        RuntimeCall.target_service_id.in_(promoted),
    ))).scalars().all())
    promoted_node_ids = {node.id for node in promoted.values()}
    existing_edges = list((await db.execute(select(EvidenceGraphEdge).where(
        EvidenceGraphEdge.source_node_id.in_(promoted_node_ids),
        EvidenceGraphEdge.target_node_id.in_(promoted_node_ids),
        EvidenceGraphEdge.edge_type == "SUPPORTS",
    ))).scalars().all()) if promoted_node_ids else []
    existing_pairs = {(edge.source_node_id, edge.target_node_id) for edge in existing_edges}
    created_edges = 0
    for call in calls:
        pair = (promoted[call.source_service_id].id, promoted[call.target_service_id].id)
        if pair in existing_pairs:
            continue
        await evidence_graph.create_edge(db, {
            "source_node_id": str(pair[0]),
            "target_node_id": str(pair[1]),
            "edge_type": "SUPPORTS",
            "rationale": "Apache SkyWalking observed a directed runtime call between these services.",
            "confidence": 70,
            "review_status": "draft",
            "metadata_json": {
                "runtime_call_id": str(call.id),
                "evidence_kind": "runtime_observation",
                "last_observed_at": call.last_observed_at.isoformat(),
            },
        }, actor)
        existing_pairs.add(pair)
        created_edges += 1
    return {"nodes_created": created_nodes, "edges_created": created_edges}


async def enforce_retention(db: AsyncSession, retention_days: int) -> dict[str, int]:
    cutoff = _now() - timedelta(days=retention_days)
    deleted_calls = await db.execute(delete(RuntimeCall).where(RuntimeCall.last_observed_at < cutoff))
    deleted_services = await db.execute(delete(RuntimeService).where(RuntimeService.last_observed_at < cutoff))
    deleted_snapshots = await db.execute(delete(RuntimeTopologySnapshot).where(RuntimeTopologySnapshot.created_at < cutoff))
    return {
        "calls_deleted": int(deleted_calls.rowcount or 0),
        "services_deleted": int(deleted_services.rowcount or 0),
        "snapshots_deleted": int(deleted_snapshots.rowcount or 0),
    }
