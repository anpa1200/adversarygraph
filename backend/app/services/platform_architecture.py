"""Build a provenance-rich operational architecture snapshot.

The snapshot deliberately separates measured values, SkyWalking observations,
database state, and configured dependencies. It never promotes topology or
traffic telemetry into a security finding.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.core.observability import observability_state
from app.core.redaction import redact_sensitive_text
from app.services import skywalking, threat_hunting_ai


_COUNT_QUERIES = {
    "ioc": ("IOC stream", "ioc_indicators"),
    "cve": ("CVE stream", "cve_records"),
    "kev": ("Known exploited", "cve_records", "known_exploited IS TRUE"),
    "attack": ("ATT&CK techniques", "techniques"),
    "actors": ("ATT&CK groups", "apt_groups"),
    "reports": ("Research sessions", "analysis_sessions"),
    "assets": ("Inventory assets", "asset_registry_items"),
    "rag_documents": ("RAG documents", "rag_documents", "is_active IS TRUE"),
    "rag_chunks": ("RAG chunks", "rag_chunks"),
    "evidence_nodes": ("Evidence nodes", "evidence_graph_nodes"),
    "evidence_edges": ("Evidence relations", "evidence_graph_edges"),
    "query_rules": ("Hunt queries", "hunt_query_library"),
    "attack_flows": ("Attack flows", "simulation_attack_flows"),
    "synthetic_runs": ("Synthetic evidence runs", "synthetic_evidence_runs"),
    "radar_signals": ("Threat Radar signals", "threat_signals"),
    "radar_alerts": ("Threat Radar alerts", "threat_alerts"),
    "ioc_tagged": (
        "Tagged IOCs",
        "ioc_indicators",
        "jsonb_array_length(COALESCE(tags, '[]'::jsonb)) > 0",
    ),
    "ioc_ttp_tagged": (
        "IOCs mapped to ATT&CK",
        "ioc_indicators",
        "jsonb_array_length(COALESCE(technique_ids, '[]'::jsonb)) > 0",
    ),
    "cve_tagged": (
        "Tagged CVEs",
        "cve_records",
        "jsonb_array_length(COALESCE(tags, '[]'::jsonb)) > 0",
    ),
    "cve_cwe": (
        "CVEs with CWE",
        "cve_records",
        "jsonb_array_length(COALESCE(cwe_ids, '[]'::jsonb)) > 0",
    ),
    "cve_cpe": (
        "CVEs with CPE",
        "cve_records",
        "jsonb_array_length(COALESCE(cpe_matches, '[]'::jsonb)) > 0",
    ),
    "rag_assistance": ("Grounded AI assistance", "rag_assistance"),
}

_CORRELATION_QUERIES = {
    "ioc_actor": ("IOC ↔ actor", "ioc_actor_links"),
    "cve_ttp": ("CVE ↔ ATT&CK", "cve_technique_links"),
    "cve_ioc": ("CVE ↔ IOC", "cve_ioc_links"),
    "cve_actor": ("CVE ↔ actor", "cve_actor_links"),
}

_ROUTE_TARGETS = (
    ("/api/ioc", "ioc"),
    ("/api/cve", "cve"),
    ("/api/rag", "rag"),
    ("/api/threat-radar", "radar"),
    ("/api/asset", "assets"),
    ("/api/evidence", "evidence"),
    ("/api/simulation", "simulation"),
    ("/api/attack", "attack"),
    ("/api/analy", "reports"),
    ("/api/query", "queries"),
    ("/api/observability", "skywalking"),
)


async def _safe_count(
    db: AsyncSession, table: str, where: str = ""
) -> tuple[int | None, str]:
    try:
        exists = await db.scalar(text("SELECT to_regclass(:table)"), {"table": table})
        if not exists:
            return None, "not_migrated"
        clause = f" WHERE {where}" if where else ""
        value = await db.scalar(text(f"SELECT count(*) FROM {table}{clause}"))
        return int(value or 0), "measured"
    except SQLAlchemyError:
        return None, "unavailable"


async def _source_health(db: AsyncSession, table: str) -> dict[str, Any]:
    try:
        exists = await db.scalar(text("SELECT to_regclass(:table)"), {"table": table})
        if not exists:
            return {"configured": 0, "enabled": 0, "degraded": 0, "latest_sync": None}
        row = (
            await db.execute(
                text(
                    f"""
                    SELECT count(*) AS configured,
                           count(*) FILTER (WHERE enabled IS TRUE) AS enabled,
                           count(*) FILTER (
                             WHERE enabled IS TRUE
                               AND sync_status NOT IN ('ok', 'configured', 'complete')
                           ) AS degraded,
                           max(last_synced_at) AS latest_sync
                    FROM {table}
                    """
                )
            )
        ).mappings().one()
        return {
            "configured": int(row["configured"] or 0),
            "enabled": int(row["enabled"] or 0),
            "degraded": int(row["degraded"] or 0),
            "latest_sync": row["latest_sync"].isoformat() if row["latest_sync"] else None,
        }
    except SQLAlchemyError:
        return {"configured": None, "enabled": None, "degraded": None, "latest_sync": None}


async def _rag_logic(db: AsyncSession) -> dict[str, Any]:
    try:
        source_rows = (
            await db.execute(
                text(
                    """
                    SELECT source_type, count(*) AS documents
                    FROM rag_documents
                    WHERE is_active IS TRUE AND sanitized IS TRUE
                    GROUP BY source_type
                    ORDER BY documents DESC, source_type
                    """
                )
            )
        ).mappings().all()
        run = (
            await db.execute(
                text(
                    """
                    SELECT status, documents_seen, documents_created, documents_updated,
                           documents_removed, chunks_created, embeddings_created,
                           embeddings_failed, started_at, completed_at
                    FROM rag_index_runs
                    ORDER BY created_at DESC
                    LIMIT 1
                    """
                )
            )
        ).mappings().first()
        return {
            "source_types": [
                {"source_type": row["source_type"], "documents": int(row["documents"] or 0)}
                for row in source_rows
            ],
            "latest_run": {
                key: value.isoformat() if hasattr(value, "isoformat") else value
                for key, value in dict(run or {}).items()
            } or None,
        }
    except SQLAlchemyError:
        return {"source_types": [], "latest_run": None}


def _node(
    node_id: str,
    label: str,
    layer: str,
    kind: str,
    *,
    status: str = "configured",
    metric: int | float | None = None,
    metric_label: str = "",
    source: str = "deployment_configuration",
    observed: bool = False,
    technology: str = "",
) -> dict[str, Any]:
    return {
        "id": node_id,
        "label": label,
        "layer": layer,
        "kind": kind,
        "status": status,
        "metric": metric,
        "metric_label": metric_label,
        "source": source,
        "observed": observed,
        "technology": technology,
    }


def _edge(
    source: str,
    target: str,
    kind: str,
    label: str,
    *,
    count: int | float | None = None,
    observed: bool = False,
    evidence: str = "deployment_configuration",
) -> dict[str, Any]:
    return {
        "id": f"{kind}:{source}:{target}:{label}",
        "source": source,
        "target": target,
        "kind": kind,
        "label": label,
        "count": count,
        "observed": observed,
        "evidence": evidence,
    }


def _log_activity(limit: int = 80) -> dict[str, Any]:
    path = Path(settings.log_dir) / "adversarygraph-api.log"
    if not path.exists():
        return {"path": str(path), "exists": False, "sampled_lines": 0, "levels": {}}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]
    except OSError:
        return {"path": str(path), "exists": False, "sampled_lines": 0, "levels": {}}
    levels = {"error": 0, "warning": 0, "info": 0}
    recent: list[str] = []
    for raw in lines:
        line = redact_sensitive_text(raw)
        lowered = line.casefold()
        if "error" in lowered or "exception" in lowered:
            levels["error"] += 1
        elif "warn" in lowered:
            levels["warning"] += 1
        else:
            levels["info"] += 1
        if len(recent) < 8:
            recent.append(line[:500])
    return {
        "path": str(path),
        "exists": True,
        "sampled_lines": len(lines),
        "levels": levels,
        "recent": recent,
    }


async def snapshot(db: AsyncSession, *, minutes: int = 60) -> dict[str, Any]:
    counts: dict[str, dict[str, Any]] = {}
    for key, definition in _COUNT_QUERIES.items():
        label, table, *where = definition
        value, status = await _safe_count(db, table, where[0] if where else "")
        counts[key] = {"label": label, "value": value, "status": status}

    correlations: list[dict[str, Any]] = []
    for key, (label, table) in _CORRELATION_QUERIES.items():
        value, status = await _safe_count(db, table)
        correlations.append(
            {"id": key, "label": label, "count": value, "status": status, "source": table}
        )

    ioc_sources = await _source_health(db, "ioc_sources")
    cve_sources = await _source_health(db, "cve_sources")
    rag_logic = await _rag_logic(db)
    ai_providers = threat_hunting_ai.provider_catalog()
    api = observability_state.snapshot()

    nodes = [
        _node("frontend", "Analyst workbench", "experience", "frontend", technology="React"),
        _node("api", "AdversaryGraph API", "application", "api", status="observed", metric=api["requests_total"], metric_label="requests since start", source="api_middleware", observed=True, technology="FastAPI"),
        _node("worker", "Background workers", "application", "worker", technology="Celery"),
        _node("mcp", "Intelligence MCP", "application", "mcp", technology="AdversaryGraph MCP"),
        _node("scanner", "Asset scanner MCP", "application", "mcp", technology="scanner tool gateway"),
        _node("malwaregraph", "MalwareGraph", "application", "analysis_service", technology="malware analysis"),
        _node("evidenceforge", "EvidenceForge", "application", "simulation_service", technology="synthetic telemetry"),
        _node("attack_lab", "Attack lab", "application", "validation_target", technology="isolated lab targets"),
        _node("skywalking", "SkyWalking OAP", "telemetry", "observability", technology="Apache SkyWalking"),
        _node("postgres", "PostgreSQL", "storage", "database", status="measured", source="database_queries", observed=True, technology="PostgreSQL + pgvector"),
        _node("redis", "Redis", "storage", "cache", technology="Redis"),
    ]
    stream_defs = (
        ("ioc", "IOC intelligence", "ioc", "indicators"),
        ("cve", "Vulnerability intelligence", "cve", "CVEs"),
        ("attack", "ATT&CK knowledge", "attack", "techniques"),
        ("reports", "Reports / research", "reports", "sessions"),
        ("rag", "Unified intelligence RAG", "rag_documents", "documents"),
        ("assets", "Asset intelligence", "assets", "assets"),
        ("evidence", "Evidence graph", "evidence_edges", "relations"),
        ("queries", "Hunt query library", "query_rules", "queries"),
        ("simulation", "Attack simulation", "attack_flows", "flows"),
        ("radar", "Threat Radar", "radar_signals", "signals"),
    )
    for node_id, label, count_key, metric_label in stream_defs:
        item = counts[count_key]
        nodes.append(
            _node(
                node_id, label, "intelligence", "stream",
                status=item["status"], metric=item["value"], metric_label=metric_label,
                source="database_count", observed=item["status"] == "measured",
            )
        )

    edges = [
        _edge("frontend", "api", "configured_dependency", "HTTPS API"),
        _edge("api", "postgres", "configured_dependency", "SQLAlchemy"),
        _edge("api", "redis", "configured_dependency", "cache / queue"),
        _edge("api", "mcp", "configured_dependency", "local tool calls"),
        _edge("api", "scanner", "configured_dependency", "authorized scans"),
        _edge("api", "malwaregraph", "configured_dependency", "sample analysis"),
        _edge("api", "evidenceforge", "configured_dependency", "synthetic generation"),
        _edge("api", "attack_lab", "configured_dependency", "safe validation"),
        _edge("worker", "postgres", "configured_dependency", "ingest / reconcile"),
        _edge("worker", "redis", "configured_dependency", "task queue"),
        _edge("api", "skywalking", "telemetry", "OTLP traces / metrics"),
        _edge("ioc", "rag", "index_flow", "normalized corpus", count=counts["ioc"]["value"], observed=counts["ioc"]["status"] == "measured", evidence="database_state"),
        _edge("cve", "rag", "index_flow", "normalized corpus", count=counts["cve"]["value"], observed=counts["cve"]["status"] == "measured", evidence="database_state"),
        _edge("reports", "rag", "index_flow", "reviewed content", count=counts["reports"]["value"], observed=counts["reports"]["status"] == "measured", evidence="database_state"),
        _edge("rag", "evidence", "correlation", "retrieval context", count=counts["rag_chunks"]["value"], observed=counts["rag_chunks"]["status"] == "measured", evidence="database_state"),
        _edge("simulation", "evidence", "validation_flow", "synthetic evidence", count=counts["synthetic_runs"]["value"], observed=counts["synthetic_runs"]["status"] == "measured", evidence="database_state"),
        _edge("assets", "radar", "correlation", "business context", observed=counts["assets"]["status"] == "measured", evidence="database_state"),
        _edge("scanner", "assets", "configured_dependency", "scan findings"),
        _edge("malwaregraph", "ioc", "configured_dependency", "extracted observables"),
        _edge("evidenceforge", "simulation", "configured_dependency", "synthetic events"),
        _edge("attack_lab", "simulation", "configured_dependency", "validation telemetry"),
        _edge("mcp", "rag", "configured_dependency", "grounded retrieval"),
    ]

    correlation_edges = {
        "ioc_actor": ("ioc", "attack", "actor evidence"),
        "cve_ttp": ("cve", "attack", "technique mappings"),
        "cve_ioc": ("cve", "ioc", "co-observations"),
        "cve_actor": ("cve", "attack", "reported actor use"),
    }
    for item in correlations:
        source, target, label = correlation_edges[item["id"]]
        edges.append(
            _edge(
                source,
                target,
                "correlation",
                label,
                count=item["count"],
                observed=item["status"] == "measured",
                evidence="normalized_link_table",
            )
        )

    for node_id, _, count_key, _ in stream_defs:
        item = counts[count_key]
        edges.append(
            _edge(
                node_id,
                "postgres",
                "data_store",
                "persisted records",
                count=item["value"],
                observed=item["status"] == "measured",
                evidence="database_state",
            )
        )

    route_rows = api.get("top_routes", [])
    route_totals: dict[str, int] = {}
    for row in route_rows:
        route = str(row.get("route") or "")
        for prefix, target in _ROUTE_TARGETS:
            if route.startswith(prefix):
                route_totals[target] = route_totals.get(target, 0) + int(row.get("count") or 0)
                break
    for target, value in route_totals.items():
        edges.append(
            _edge("api", target, "api_traffic", "measured requests", count=value, observed=True, evidence="api_middleware")
        )

    sw_health = await skywalking.health()
    sw_topology: dict[str, Any] | None = None
    if sw_health.get("connected"):
        try:
            sw_topology = await skywalking.topology(minutes=minutes)
        except skywalking.SkyWalkingError:
            sw_topology = None
    if sw_topology:
        runtime_ids: dict[str, str] = {}
        for item in sw_topology["nodes"]:
            node_id = f"runtime:{item['id']}"
            runtime_ids[item["id"]] = node_id
            nodes.append(
                _node(
                    node_id, item["label"], "runtime", "runtime_service",
                    status="observed", source="apache_skywalking", observed=True,
                    technology=item.get("technology", ""),
                )
            )
        for item in sw_topology["edges"]:
            if item["source"] in runtime_ids and item["target"] in runtime_ids:
                edges.append(
                    _edge(
                        runtime_ids[item["source"]], runtime_ids[item["target"]],
                        "runtime_call", ", ".join(item.get("components") or []) or "observed call",
                        observed=True, evidence="apache_skywalking",
                    )
                )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "window_minutes": minutes,
        "nodes": nodes,
        "edges": edges,
        "counts": counts,
        "correlations": correlations,
        "streams": {
            "ioc": {**ioc_sources, "records": counts["ioc"]["value"]},
            "cve": {**cve_sources, "records": counts["cve"]["value"], "known_exploited": counts["kev"]["value"]},
            "rag": {"documents": counts["rag_documents"]["value"], "chunks": counts["rag_chunks"]["value"]},
        },
        "data_logic": {
            "stages": [
                {"id": "collect", "label": "Collect", "detail": "Scheduled and manual IOC/CVE/report ingestion with source identity and timestamps."},
                {"id": "parse", "label": "Parse", "detail": "Type-specific adapters extract bounded allowlisted fields while retaining reviewable raw provenance."},
                {"id": "normalize", "label": "Normalize + deduplicate", "detail": "Canonical IOC types, CVE IDs, TLP, confidence, source keys, and uniqueness constraints prevent silent duplication."},
                {"id": "tag", "label": "Tag + correlate", "detail": "Tags, malware, campaign, CWE/CPE, ATT&CK, actor, IOC↔CVE, and evidence-backed relationship tables build the knowledge mesh."},
                {"id": "store", "label": "Persist", "detail": "PostgreSQL is authoritative; Redis coordinates bounded background jobs and short-lived cache state."},
                {"id": "rag", "label": "RAG reconcile", "detail": "Sanitized canonical records become deterministic documents and chunks with lexical search and optional governed embeddings."},
                {"id": "mcp", "label": "MCP tools", "detail": "Five advisory-only stdio tools call three allowlisted RAG API operations; database credentials and arbitrary API access are not exposed."},
                {"id": "assist", "label": "AI assistant", "detail": "Policy selects a configured provider, retrieves scoped evidence, binds citations, validates structured output, and requires human acceptance."},
            ],
            "coverage": {
                "ioc_tagged": counts["ioc_tagged"]["value"],
                "ioc_ttp_tagged": counts["ioc_ttp_tagged"]["value"],
                "cve_tagged": counts["cve_tagged"]["value"],
                "cve_cwe": counts["cve_cwe"]["value"],
                "cve_cpe": counts["cve_cpe"]["value"],
            },
            "rag": {
                **rag_logic,
                "documents": counts["rag_documents"]["value"],
                "chunks": counts["rag_chunks"]["value"],
                "assistance_records": counts["rag_assistance"]["value"],
                "embedding_enabled": settings.rag_embedding_enabled,
                "embedding_provider": settings.rag_embedding_provider if settings.rag_embedding_enabled else None,
            },
            "mcp": {
                "transport": "stdio",
                "tool_count": 5,
                "api_operations": ["RAG search", "RAG assist", "indexed entity lookup"],
                "advisory_only": True,
                "database_credentials_exposed": False,
            },
            "ai": {
                "enabled": settings.threat_hunting_ai_enabled,
                "cloud_enabled": settings.threat_hunting_ai_cloud_enabled,
                "providers": [
                    {
                        "id": row["id"],
                        "label": row["label"],
                        "model": row["model"],
                        "configured": row["configured"],
                        "available": row["available"],
                        "status": row["status"],
                        "remote": row["remote"],
                    }
                    for row in ai_providers
                ],
                "configured_count": sum(1 for row in ai_providers if row["configured"]),
                "assistance_records": counts["rag_assistance"]["value"],
                "human_review_required": True,
            },
            "boundaries": [
                "Raw provider payloads are retained for review but are not automatically placed into prompts.",
                "Unsanitized, TLP-restricted, or tenant-inaccessible records are excluded by policy before retrieval.",
                "MCP and AI outputs are advisory leads, not evidence, attribution, verdicts, or executed response actions.",
                "Observed correlation counts show stored relationships; they do not prove causality or compromise.",
            ],
        },
        "api": {
            "uptime_seconds": api["uptime_seconds"],
            "requests_total": api["requests_total"],
            "requests_by_status": api["requests_by_status"],
            "latency": api["latency"],
            "top_routes": route_rows,
            "recent_traces": api["recent_traces"][:20],
        },
        "logs": _log_activity(),
        "skywalking": {
            "health": sw_health,
            "topology_counts": sw_topology["counts"] if sw_topology else None,
        },
        "provenance": {
            "measured": ["database counts", "API middleware counters", "redacted API log activity"],
            "observed": ["SkyWalking topology when OAP is connected"],
            "configured": ["deployment dependencies shown with dashed edges"],
            "boundary": "Runtime telemetry and correlations are operational evidence, not proof of compromise or attribution.",
        },
    }
