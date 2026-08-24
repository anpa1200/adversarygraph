from __future__ import annotations

import csv
import io
import json
import re
import uuid
import zipfile
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analysis import AnalysisSession
from app.models.asset_surface import AssetSurfaceCase
from app.models.evidence_graph import EvidenceGraphEdge, EvidenceGraphNode
from app.models.ioc import IOCIndicator, IOCInvestigationSession
from app.models.operations import ReportIntake
from app.models.attack import AttackVersion, Technique
from app.services.report_promotion import accepted_claims, promotion_allows
from app.services.report_review import active_promotion


NODE_TYPES = {
    "evidence",
    "claim",
    "behavior",
    "attack_technique",
    "required_telemetry",
    "detection_candidate",
    "detection_rule",
    "validation_scenario",
    "siem_result",
    "analyst_decision",
}

EDGE_TYPES = {
    "SUPPORTS",
    "EXTRACTED_FROM",
    "DESCRIBES",
    "MAPS_TO",
    "REQUIRES_TELEMETRY",
    "ENABLES_DETECTION",
    "IMPLEMENTED_AS",
    "VALIDATED_BY",
    "PRODUCED_RESULT",
    "REVIEWED_AS",
    "RELATED_IOC",
    "RELATED_MALWARE_FINDING",
    "RELATED_ASSET",
    "RELATED_REPORT",
    "CONTRADICTS",
    "WEAKENS",
    "GAP_BLOCKS",
    "DERIVED_RULE",
    "AI_SUGGESTED",
}

REVIEW_STATUSES = {"draft", "analyst_reviewed", "rejected", "needs_evidence"}
EDGE_REVIEW_STATUSES = {"draft", "analyst_reviewed", "rejected"}
AVAILABILITY = {"unknown", "unavailable", "partial", "available", "validated"}
SENSITIVE_KEYS = re.compile(r"(api[_-]?key|token|secret|password|credential|authorization)", re.I)

ORDERED_PATH_TYPES = [
    "evidence",
    "claim",
    "behavior",
    "attack_technique",
    "required_telemetry",
    "detection_candidate",
    "detection_rule",
    "validation_scenario",
    "siem_result",
    "analyst_decision",
]

REPORT_GRAPH_ORIGIN = "from-report"
REPORT_GRAPH_SOURCE_TYPE = "uploaded_report"
REPORT_GRAPH_AUTHORITY_ERROR = "Evidence-graph report import requires an active current Review Gate promotion"


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def row_to_dict(row: EvidenceGraphNode | EvidenceGraphEdge) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for column in row.__table__.columns:
        value = getattr(row, column.name)
        if isinstance(value, uuid.UUID):
            value = str(value)
        elif isinstance(value, datetime):
            value = value.isoformat()
        data[column.name] = value
    return data


def clamp_confidence(value: Any) -> int:
    try:
        return max(0, min(100, int(value)))
    except (TypeError, ValueError):
        return 50


def _payload_claims_report_origin(payload: dict[str, Any]) -> bool:
    metadata = payload.get("metadata_json")
    return str(payload.get("source_type") or "").strip().casefold() == REPORT_GRAPH_SOURCE_TYPE or (
        isinstance(metadata, dict) and str(metadata.get("origin") or "").strip().casefold() == REPORT_GRAPH_ORIGIN
    )


def _row_claims_report_origin(row: EvidenceGraphNode | EvidenceGraphEdge) -> bool:
    metadata = row.metadata_json if isinstance(row.metadata_json, dict) else {}
    return (
        str(getattr(row, "source_type", "") or "").strip().casefold() == REPORT_GRAPH_SOURCE_TYPE
        or str(metadata.get("origin") or "").strip().casefold() == REPORT_GRAPH_ORIGIN
    )


def validate_node_payload(
    payload: dict[str, Any],
    partial: bool = False,
    *,
    allow_report_origin: bool = False,
) -> dict[str, Any]:
    cleaned = dict(payload)
    if _payload_claims_report_origin(cleaned) and not allow_report_origin:
        raise HTTPException(409, "Report-derived graph provenance is reserved")
    if not partial or "node_type" in cleaned:
        node_type = str(cleaned.get("node_type", "")).strip().lower()
        if node_type not in NODE_TYPES:
            raise HTTPException(422, f"node_type must be one of: {', '.join(sorted(NODE_TYPES))}")
        cleaned["node_type"] = node_type
    if not partial or "title" in cleaned:
        title = str(cleaned.get("title", "")).strip()
        if not title:
            raise HTTPException(422, "title is required")
        cleaned["title"] = title[:500]
    if "confidence" in cleaned:
        cleaned["confidence"] = clamp_confidence(cleaned["confidence"])
    if "review_status" in cleaned and cleaned["review_status"] not in REVIEW_STATUSES:
        raise HTTPException(422, f"review_status must be one of: {', '.join(sorted(REVIEW_STATUSES))}")
    if "availability_status" in cleaned and cleaned["availability_status"] not in AVAILABILITY:
        raise HTTPException(422, f"availability_status must be one of: {', '.join(sorted(AVAILABILITY))}")
    if cleaned.get("ai_generated"):
        cleaned.setdefault("review_status", "draft")
    return cleaned


def validate_edge_payload(
    payload: dict[str, Any],
    partial: bool = False,
    *,
    allow_report_origin: bool = False,
) -> dict[str, Any]:
    cleaned = dict(payload)
    if _payload_claims_report_origin(cleaned) and not allow_report_origin:
        raise HTTPException(409, "Report-derived graph provenance is reserved")
    if not partial or "edge_type" in cleaned:
        edge_type = str(cleaned.get("edge_type", "")).strip().upper()
        if edge_type not in EDGE_TYPES:
            raise HTTPException(422, f"edge_type must be one of: {', '.join(sorted(EDGE_TYPES))}")
        cleaned["edge_type"] = edge_type
    if "confidence" in cleaned:
        cleaned["confidence"] = clamp_confidence(cleaned["confidence"])
    if "review_status" in cleaned and cleaned["review_status"] not in EDGE_REVIEW_STATUSES:
        raise HTTPException(422, f"review_status must be one of: {', '.join(sorted(EDGE_REVIEW_STATUSES))}")
    if cleaned.get("ai_generated"):
        cleaned.setdefault("review_status", "draft")
    return cleaned


async def create_node(
    db: AsyncSession,
    payload: dict[str, Any],
    actor: str,
    *,
    allow_report_origin: bool = False,
) -> EvidenceGraphNode:
    cleaned = validate_node_payload(payload, allow_report_origin=allow_report_origin)
    cleaned.setdefault("created_by", actor)
    row = EvidenceGraphNode(**_node_columns(cleaned))
    db.add(row)
    await db.flush()
    return row


async def update_node(db: AsyncSession, node_id: str, payload: dict[str, Any]) -> EvidenceGraphNode:
    row = await get_node(db, node_id)
    if _row_claims_report_origin(row):
        raise HTTPException(409, "Promotion-derived graph nodes are immutable")
    cleaned = validate_node_payload(payload, partial=True)
    for key, value in _node_columns(cleaned).items():
        setattr(row, key, value)
    return row


async def delete_node(db: AsyncSession, node_id: str) -> None:
    row = await get_node(db, node_id)
    await db.execute(delete(EvidenceGraphEdge).where(or_(
        EvidenceGraphEdge.source_node_id == row.id,
        EvidenceGraphEdge.target_node_id == row.id,
    )))
    await db.delete(row)


async def get_node(db: AsyncSession, node_id: str) -> EvidenceGraphNode:
    try:
        uid = uuid.UUID(str(node_id))
    except ValueError:
        raise HTTPException(400, "Invalid node ID")
    row = await db.get(EvidenceGraphNode, uid)
    if not row:
        raise HTTPException(404, "Node not found")
    return row


async def create_edge(
    db: AsyncSession,
    payload: dict[str, Any],
    actor: str,
    *,
    allow_report_origin: bool = False,
) -> EvidenceGraphEdge:
    cleaned = validate_edge_payload(payload, allow_report_origin=allow_report_origin)
    source = await get_node(db, cleaned.get("source_node_id", ""))
    target = await get_node(db, cleaned.get("target_node_id", ""))
    cleaned["source_node_id"] = source.id
    cleaned["target_node_id"] = target.id
    cleaned.setdefault("created_by", actor)
    row = EvidenceGraphEdge(**_edge_columns(cleaned))
    db.add(row)
    await db.flush()
    return row


async def update_edge(db: AsyncSession, edge_id: str, payload: dict[str, Any]) -> EvidenceGraphEdge:
    row = await get_edge(db, edge_id)
    if _row_claims_report_origin(row):
        raise HTTPException(409, "Promotion-derived graph edges are immutable")
    cleaned = validate_edge_payload(payload, partial=True)
    if "source_node_id" in cleaned:
        cleaned["source_node_id"] = (
            await get_node(db, str(cleaned["source_node_id"]))
        ).id
    if "target_node_id" in cleaned:
        cleaned["target_node_id"] = (
            await get_node(db, str(cleaned["target_node_id"]))
        ).id
    for key, value in _edge_columns(cleaned).items():
        setattr(row, key, value)
    return row


async def delete_edge(db: AsyncSession, edge_id: str) -> None:
    row = await get_edge(db, edge_id)
    await db.delete(row)


async def get_edge(db: AsyncSession, edge_id: str) -> EvidenceGraphEdge:
    try:
        uid = uuid.UUID(str(edge_id))
    except ValueError:
        raise HTTPException(400, "Invalid edge ID")
    row = await db.get(EvidenceGraphEdge, uid)
    if not row:
        raise HTTPException(404, "Edge not found")
    return row


async def query_graph(
    db: AsyncSession,
    *,
    node_type: str = "",
    technique_id: str = "",
    review_status: str = "",
    validation_status: str = "",
    include_ai_suggestions: bool = True,
    include_rejected: bool = False,
    search: str = "",
    limit: int = 500,
) -> dict[str, Any]:
    limit = max(1, min(limit, 1000))
    stmt = select(EvidenceGraphNode)
    if node_type:
        stmt = stmt.where(EvidenceGraphNode.node_type == node_type)
    if technique_id:
        stmt = stmt.where(EvidenceGraphNode.technique_id == technique_id)
    if review_status:
        stmt = stmt.where(EvidenceGraphNode.review_status == review_status)
    if validation_status:
        stmt = stmt.where(or_(EvidenceGraphNode.test_status == validation_status, EvidenceGraphNode.forwarding_status == validation_status))
    if not include_ai_suggestions:
        stmt = stmt.where(EvidenceGraphNode.ai_generated.is_(False))
    if not include_rejected:
        stmt = stmt.where(EvidenceGraphNode.review_status != "rejected")
    if search:
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(or_(
            EvidenceGraphNode.title.ilike(pattern),
            EvidenceGraphNode.description.ilike(pattern),
            EvidenceGraphNode.raw_excerpt.ilike(pattern),
            EvidenceGraphNode.technique_id.ilike(pattern),
        ))
    rows = await db.execute(stmt.order_by(EvidenceGraphNode.updated_at.desc()).limit(limit))
    candidate_nodes = list(rows.scalars().all())
    authorized_ids = await authorized_report_graph_node_ids(
        db,
        candidate_nodes,
        target="canonical_intelligence",
    )
    nodes = [node for node in candidate_nodes if node.id in authorized_ids]
    node_ids = [row.id for row in nodes]
    edge_rows = []
    if node_ids:
        result = await db.execute(select(EvidenceGraphEdge).where(
            EvidenceGraphEdge.source_node_id.in_(node_ids),
            EvidenceGraphEdge.target_node_id.in_(node_ids),
        ).limit(1500))
        candidate_edges = list(result.scalars().all())
        authorized_edge_ids = await authorized_report_graph_edge_ids(
            db,
            candidate_edges,
            target="canonical_intelligence",
        )
        edge_rows = [edge for edge in candidate_edges if edge.id in authorized_edge_ids]
    grouped_paths = build_grouped_paths(nodes, edge_rows)
    warnings = []
    if len(nodes) == limit:
        warnings.append(f"Result limited to {limit} nodes. Narrow filters for complete graph review.")
    return {
        "nodes": [row_to_dict(row) for row in nodes],
        "edges": [row_to_dict(row) for row in edge_rows],
        "grouped_paths": grouped_paths,
        "warnings": warnings,
    }


async def summary(db: AsyncSession) -> dict[str, Any]:
    graph = await query_graph(db, include_rejected=False, limit=1000)
    nodes = graph["nodes"]
    edges = graph["edges"]
    gaps = await gap_analysis(db)
    decisions = [node for node in nodes if node["node_type"] == "analyst_decision"]
    decisions.sort(key=lambda item: item.get("reviewed_at") or item.get("created_at") or "", reverse=True)
    validation_nodes = [node for node in nodes if node["node_type"] == "validation_scenario"]
    siem_results = [node for node in nodes if node["node_type"] == "siem_result"]
    return {
        "node_counts": dict(Counter(node["node_type"] for node in nodes)),
        "edge_counts": dict(Counter(edge["edge_type"] for edge in edges)),
        "detection_readiness_score": detection_readiness_score(nodes, edges),
        "unresolved_gaps": len(gaps["gaps"]),
        "unreviewed_ai_suggestions": sum(1 for node in nodes if node.get("ai_generated") and node.get("review_status") == "draft")
        + sum(1 for edge in edges if edge.get("ai_generated") and edge.get("review_status") == "draft"),
        "validation_coverage": {
            "validation_scenarios": len(validation_nodes),
            "siem_results": len(siem_results),
            "coverage_percent": round((len(siem_results) / len(validation_nodes) * 100), 1) if validation_nodes else 0,
        },
        "top_techniques_by_detection_gap": top_gap_techniques(nodes, gaps["gaps"]),
        "latest_analyst_decisions": decisions[:10],
    }


async def gap_analysis(db: AsyncSession) -> dict[str, Any]:
    graph = await query_graph(db, include_rejected=False, limit=1000)
    nodes = graph["nodes"]
    edges = graph["edges"]
    by_id = {node["id"]: node for node in nodes}
    outgoing: dict[str, list[dict[str, Any]]] = defaultdict(list)
    incoming: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in edges:
        outgoing[edge["source_node_id"]].append(edge)
        incoming[edge["target_node_id"]].append(edge)
    gaps: list[dict[str, Any]] = []

    for node in nodes:
        ntype = node["node_type"]
        title = node["title"]
        technique = node.get("technique_id") or title
        if ntype == "attack_technique":
            if not any(edge["edge_type"] == "REQUIRES_TELEMETRY" for edge in outgoing[node["id"]]):
                gaps.append(_gap(node, "required_telemetry_missing", "Add RequiredTelemetry for this ATT&CK mapping."))
            if not _has_downstream_type(node["id"], "detection_candidate", outgoing, by_id):
                gaps.append(_gap(node, "detection_candidate_missing", "Create a detection candidate or reject the mapping."))
        if ntype == "required_telemetry" and node.get("availability_status") in {"unknown", "unavailable", "partial"}:
            gaps.append(_gap(node, "telemetry_not_validated", f"Telemetry availability is {node.get('availability_status') or 'unknown'}."))
        if ntype == "detection_candidate":
            if node.get("status") in {"needs_telemetry", "needs_parser"}:
                gaps.append(_gap(node, "candidate_blocked", "Resolve telemetry/parser blocker before rule work."))
            if not _has_downstream_type(node["id"], "detection_rule", outgoing, by_id):
                gaps.append(_gap(node, "rule_missing", "Create or link a concrete detection rule."))
        if ntype == "detection_rule" and not _has_downstream_type(node["id"], "validation_scenario", outgoing, by_id):
            gaps.append(_gap(node, "validation_missing", "Create a validation scenario before production use."))
        if ntype == "validation_scenario" and not _has_downstream_type(node["id"], "siem_result", outgoing, by_id):
            gaps.append(_gap(node, "siem_result_missing", "Attach SIEM or collector result."))
        if ntype == "siem_result":
            if not node.get("detection_matched"):
                gaps.append(_gap(node, "detection_not_matched", "Investigate parser, telemetry, or rule logic."))
            if not _has_downstream_type(node["id"], "analyst_decision", outgoing, by_id):
                gaps.append(_gap(node, "analyst_decision_missing", "Record analyst decision for this result."))
        if node.get("ai_generated") and node.get("review_status") == "draft":
            gaps.append({
                "technique": technique,
                "evidence": title,
                "missing_step": "ai_review",
                "required_telemetry": node.get("data_component") or "",
                "detection_candidate": "",
                "rule_status": node.get("test_status") or "",
                "validation_status": node.get("forwarding_status") or "",
                "analyst_decision": "",
                "recommended_next_action": "Analyst must approve, reject, or request more evidence.",
                "node_id": node["id"],
            })
    return {"gaps": gaps}


async def reasoning_paths(
    db: AsyncSession,
    *,
    from_node_id: str = "",
    to_node_type: str = "",
    technique_id: str = "",
    detection_rule_id: str = "",
    analyst_decision_id: str = "",
    max_depth: int = 12,
) -> dict[str, Any]:
    graph = await query_graph(db, technique_id=technique_id, include_rejected=False, limit=1000)
    nodes = graph["nodes"]
    edges = graph["edges"]
    if detection_rule_id:
        from_node_id = detection_rule_id
    if analyst_decision_id:
        to_node_type = "analyst_decision"
    paths = find_paths(nodes, edges, from_node_id=from_node_id, to_node_type=to_node_type, max_depth=max_depth)
    return {"paths": paths, "warnings": graph["warnings"]}


def find_paths(nodes: list[dict[str, Any]], edges: list[dict[str, Any]], *, from_node_id: str = "", to_node_type: str = "", max_depth: int = 12) -> list[list[dict[str, Any]]]:
    by_id = {node["id"]: node for node in nodes}
    outgoing: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in edges:
        outgoing[edge["source_node_id"]].append(edge)
    starts = [from_node_id] if from_node_id else [node["id"] for node in nodes if node["node_type"] == "evidence"]
    results: list[list[dict[str, Any]]] = []
    for start in starts:
        if start not in by_id:
            continue
        queue = deque([(start, [start])])
        while queue and len(results) < 50:
            current, path = queue.popleft()
            node = by_id[current]
            if (to_node_type and node["node_type"] == to_node_type) or (not to_node_type and node["node_type"] == "analyst_decision"):
                results.append([by_id[item] for item in path])
                continue
            if len(path) >= max(1, min(max_depth, 20)):
                continue
            for edge in outgoing[current]:
                target = edge["target_node_id"]
                if target in by_id and target not in path:
                    queue.append((target, path + [target]))
    if not results:
        grouped = build_grouped_paths([_node_to_obj(n) for n in nodes], [_edge_to_obj(e) for e in edges])
        return [[step for step in path["steps"]] for path in grouped[:20]]
    return results


def detection_readiness_score(nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> int:
    active_nodes = [node for node in nodes if node.get("review_status") != "rejected"]
    types = {node["node_type"] for node in active_nodes}
    reviewed = {node["node_type"] for node in active_nodes if node.get("review_status") == "analyst_reviewed"}
    score = 0
    if "evidence" in types:
        score += 15
    if "claim" in reviewed:
        score += 15
    if "attack_technique" in reviewed:
        score += 15
    if any(node["node_type"] == "required_telemetry" and node.get("availability_status") in {"available", "validated"} for node in active_nodes):
        score += 20
    if "detection_rule" in types:
        score += 15
    if "validation_scenario" in types:
        score += 10
    if any(node["node_type"] == "siem_result" and node.get("forwarding_status") == "sent" and node.get("detection_matched") for node in active_nodes):
        score += 5
    if any(node["node_type"] == "analyst_decision" and node.get("decision") in {"accepted", "production_ready"} for node in active_nodes):
        score += 5
    return min(score, 100)


async def export_graph(db: AsyncSession, fmt: str = "json") -> tuple[str, str, bytes]:
    graph = await query_graph(db, include_rejected=True, limit=1000)
    safe = redact_sensitive(graph)
    if fmt == "json":
        return "application/json", "evidence-graph.json", json.dumps(safe, indent=2, default=str).encode()
    if fmt == "markdown":
        return "text/markdown", "evidence-graph-report.md", markdown_report(safe).encode()
    if fmt == "csv":
        return "text/csv", "evidence-graph-nodes.csv", nodes_csv(safe["nodes"]).encode()
    if fmt == "evidence-pack":
        buffer = io.BytesIO()
        gaps = await gap_analysis(db)
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("evidence-pack/graph.json", json.dumps(safe, indent=2, default=str))
            zf.writestr("evidence-pack/nodes.csv", nodes_csv(safe["nodes"]))
            zf.writestr("evidence-pack/edges.csv", edges_csv(safe["edges"]))
            zf.writestr("evidence-pack/gaps.csv", gaps_csv(gaps["gaps"]))
            zf.writestr("evidence-pack/report.md", markdown_report(safe))
            zf.writestr("evidence-pack/metadata.json", json.dumps({
                "warning": "May contain sensitive report excerpts. Secrets and malware binaries are excluded/redacted.",
                "generated_at": now_utc().isoformat(),
            }, indent=2))
        return "application/zip", "evidence-pack.zip", buffer.getvalue()
    raise HTTPException(422, "format must be one of: json, markdown, csv, evidence-pack")


def _normalized_uuid(value: Any) -> uuid.UUID | None:
    try:
        return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
    except (TypeError, ValueError):
        return None


async def _resolve_report_session_id(
    db: AsyncSession,
    report_id: uuid.UUID | str,
) -> uuid.UUID:
    requested_id = _normalized_uuid(report_id)
    if requested_id is None:
        raise HTTPException(422, "report_id must be a UUID")

    direct_session = await db.get(AnalysisSession, requested_id)
    intake = await db.get(ReportIntake, requested_id)
    if direct_session is not None:
        if intake is None:
            return requested_id
        linked_id = _normalized_uuid(intake.analysis_session_id)
        if linked_id == requested_id:
            return requested_id
        raise HTTPException(409, "Report identifier is ambiguous or unlinked")

    if intake is None:
        raise HTTPException(404, "Report not found")
    linked_id = _normalized_uuid(intake.analysis_session_id)
    if linked_id is None:
        raise HTTPException(409, "Report identifier is ambiguous or unlinked")
    linked_session = await db.get(AnalysisSession, linked_id)
    if linked_session is None:
        raise HTTPException(409, "Report identifier is ambiguous or unlinked")
    return linked_id


def _claim_text(claim: dict[str, Any], key: str, limit: int) -> str:
    return str(claim.get(key) or "").strip()[:limit]


def _report_graph_provenance(
    session_id: uuid.UUID,
    promotion: Any,
    *,
    claim_key: str = "",
) -> dict[str, Any]:
    metadata = {
        "origin": REPORT_GRAPH_ORIGIN,
        "report_id": str(session_id),
        "analysis_session_id": str(session_id),
        "promotion_id": str(promotion.id),
        "review_id": str(promotion.review_id),
        "review_revision": promotion.review_revision,
        "promotion_manifest_checksum": promotion.manifest_checksum,
    }
    if claim_key:
        metadata["accepted_claim_key"] = claim_key
    return metadata


def report_graph_provenance_matches(
    metadata: Any,
    promotion: Any,
) -> bool:
    """Bind a stored report-origin projection to its exact live promotion."""

    if not isinstance(metadata, dict):
        return False
    session_id = metadata.get("analysis_session_id") or metadata.get("report_id")
    return (
        str(metadata.get("origin") or "").strip().casefold() == REPORT_GRAPH_ORIGIN
        and str(session_id or "") == str(promotion.session_id)
        and str(metadata.get("promotion_id") or "") == str(promotion.id)
        and str(metadata.get("review_id") or "") == str(promotion.review_id)
        and str(metadata.get("review_revision") or "") == str(promotion.review_revision)
        and str(metadata.get("promotion_manifest_checksum") or "") == str(promotion.manifest_checksum)
    )


async def _authorized_report_graph_row_ids(
    db: AsyncSession,
    rows: list[EvidenceGraphNode] | list[EvidenceGraphEdge],
    *,
    target: str,
) -> set[uuid.UUID]:
    """Return non-report rows plus exact current authorized report projections."""

    report_session_ids = {
        _normalized_uuid((row.metadata_json or {}).get("analysis_session_id") or (row.metadata_json or {}).get("report_id"))
        for row in rows
        if _row_claims_report_origin(row)
    }
    promotions: dict[uuid.UUID, Any] = {}
    for session_id in sorted(
        (value for value in report_session_ids if value is not None),
        key=str,
    ):
        promotion = await active_promotion(db, session_id)
        if promotion is not None and promotion_allows(promotion, target):
            promotions[session_id] = promotion

    authorized: set[uuid.UUID] = set()
    for row in rows:
        if not _row_claims_report_origin(row):
            authorized.add(row.id)
            continue
        metadata = row.metadata_json if isinstance(row.metadata_json, dict) else {}
        session_id = _normalized_uuid(metadata.get("analysis_session_id") or metadata.get("report_id"))
        promotion = promotions.get(session_id) if session_id is not None else None
        if promotion is not None and report_graph_provenance_matches(
            metadata,
            promotion,
        ):
            authorized.add(row.id)
    return authorized


async def authorized_report_graph_node_ids(
    db: AsyncSession,
    nodes: list[EvidenceGraphNode],
    *,
    target: str,
) -> set[uuid.UUID]:
    return await _authorized_report_graph_row_ids(db, nodes, target=target)


async def authorized_report_graph_edge_ids(
    db: AsyncSession,
    edges: list[EvidenceGraphEdge],
    *,
    target: str,
) -> set[uuid.UUID]:
    return await _authorized_report_graph_row_ids(db, edges, target=target)


async def graph_from_report(
    db: AsyncSession,
    report_id: uuid.UUID | str,
    actor: str,
) -> dict[str, Any]:
    session_id = await _resolve_report_session_id(db, report_id)
    promotion = await active_promotion(db, session_id)
    if promotion is None or not promotion_allows(
        promotion,
        "canonical_intelligence",
    ):
        raise HTTPException(409, REPORT_GRAPH_AUTHORITY_ERROR)

    accepted = accepted_claims(promotion)
    statements = [_claim_text(claim, "statement", 4_000) or _claim_text(claim, "evidence_text", 2_000) for claim in accepted]
    summary = "\n".join(statement for statement in statements if statement)[:100_000]
    procedures = [claim for claim in accepted if str(claim.get("claim_type") or "") == "procedure" and _claim_text(claim, "attack_id", 40)][
        :25
    ]
    authority = _report_graph_provenance(session_id, promotion)
    evidence = await create_node(
        db,
        {
            "node_type": "evidence",
            "title": f"Promoted report evidence {session_id}",
            "description": "Accepted-claim projection from a Review Gate promotion.",
            "source_type": REPORT_GRAPH_SOURCE_TYPE,
            "source_ref": str(session_id),
            "raw_excerpt": summary[:4_000],
            "normalized_summary": summary[:2_000],
            "confidence": 70,
            "review_status": "analyst_reviewed",
            "ai_generated": True,
            "metadata_json": authority,
        },
        actor,
        allow_report_origin=True,
    )
    created = [evidence]
    created_edges: list[EvidenceGraphEdge] = []
    for claim_item in procedures:
        technique_id = _claim_text(claim_item, "attack_id", 40).upper()
        technique_name = _claim_text(claim_item, "object", 255) or technique_id
        statement = _claim_text(claim_item, "statement", 4_000) or _claim_text(claim_item, "evidence_text", 2_000)
        claim_metadata = claim_item.get("metadata") if isinstance(claim_item.get("metadata"), dict) else {}
        confidence = claim_metadata.get("confidence", 70)
        claim_key = _claim_text(claim_item, "claim_key", 128)
        provenance = _report_graph_provenance(
            session_id,
            promotion,
            claim_key=claim_key,
        )
        claim = await create_node(
            db,
            {
                "node_type": "claim",
                "title": f"Accepted claim: {technique_name}",
                "statement": statement,
                "claim_type": "accepted_procedure_claim",
                "confidence": confidence,
                "review_status": "analyst_reviewed",
                "ai_generated": True,
                "metadata_json": provenance,
            },
            actor,
            allow_report_origin=True,
        )
        behavior = await create_node(
            db,
            {
                "node_type": "behavior",
                "title": f"Accepted behavior for {technique_id}",
                "behavior_description": statement,
                "tactic_hint": str(claim_metadata.get("tactic") or "")[:120],
                "confidence": confidence,
                "review_status": "analyst_reviewed",
                "ai_generated": True,
                "metadata_json": provenance,
            },
            actor,
            allow_report_origin=True,
        )
        attack = await create_node(
            db,
            {
                "node_type": "attack_technique",
                "title": f"{technique_id} {technique_name}".strip(),
                "framework": "attack_enterprise",
                "technique_id": technique_id,
                "technique_name": technique_name,
                "tactic": str(claim_metadata.get("tactic") or "")[:120],
                "mapping_rationale": statement,
                "confidence": confidence,
                "review_status": "analyst_reviewed",
                "ai_generated": True,
                "metadata_json": provenance,
            },
            actor,
            allow_report_origin=True,
        )
        created.extend([claim, behavior, attack])
        for source_id, target_id, edge_type, rationale in [
            (
                evidence.id,
                claim.id,
                "SUPPORTS",
                "Promoted report projection supports this accepted claim.",
            ),
            (
                claim.id,
                behavior.id,
                "DESCRIBES",
                "Accepted claim describes this reviewed behavior.",
            ),
            (
                behavior.id,
                attack.id,
                "MAPS_TO",
                "Accepted procedure claim maps this behavior to ATT&CK.",
            ),
        ]:
            created_edges.append(
                await create_edge(
                    db,
                    {
                        "source_node_id": str(source_id),
                        "target_node_id": str(target_id),
                        "edge_type": edge_type,
                        "rationale": rationale,
                        "confidence": confidence,
                        "review_status": "analyst_reviewed",
                        "ai_generated": True,
                        "metadata_json": provenance,
                    },
                    actor,
                    allow_report_origin=True,
                )
            )
    return {
        "nodes_created": len(created),
        "edges_created": len(created_edges),
        "nodes": [row_to_dict(node) for node in created],
        "edges": [row_to_dict(edge) for edge in created_edges],
    }


async def graph_from_simulation(db: AsyncSession, simulation_run_id: str, actor: str) -> dict[str, Any]:
    technique = _extract_technique(simulation_run_id)
    scenario = await create_node(db, {
        "node_type": "validation_scenario",
        "title": f"Attack Simulation run {simulation_run_id}",
        "scenario_type": "attack_simulation",
        "scenario_description": "Defensive validation scenario generated by AdversaryGraph Attack Simulation.",
        "attack_techniques": [technique] if technique else [],
        "expected_detection_outcome": "Detection rule should match expected telemetry if parser and fields are present.",
        "safety_boundary": "Defensive lab validation only. No arbitrary command execution is represented by this graph node.",
        "review_status": "draft",
        "metadata_json": {"origin": "from-simulation", "simulation_run_id": simulation_run_id},
    }, actor)
    result = await create_node(db, {
        "node_type": "siem_result",
        "title": f"SIEM result placeholder for {simulation_run_id}",
        "destination_type": "local_collector",
        "forwarding_status": "not_sent",
        "detection_matched": False,
        "failure_reason": "No collector result attached yet.",
        "review_status": "draft",
        "metadata_json": {"origin": "from-simulation", "simulation_run_id": simulation_run_id},
    }, actor)
    edge = await create_edge(db, {
        "source_node_id": str(scenario.id),
        "target_node_id": str(result.id),
        "edge_type": "PRODUCED_RESULT",
        "rationale": "Simulation run should produce SIEM or collector validation result.",
        "review_status": "draft",
    }, actor)
    return {"nodes_created": 2, "edges_created": 1, "nodes": [row_to_dict(scenario), row_to_dict(result)], "edges": [row_to_dict(edge)]}


async def graph_from_ioc(db: AsyncSession, ioc_id: str, actor: str) -> dict[str, Any]:
    row: Any = None
    try:
        row = await db.get(IOCIndicator, int(ioc_id))
    except ValueError:
        try:
            row = await db.get(IOCInvestigationSession, uuid.UUID(ioc_id))
        except ValueError:
            row = None
    title = getattr(row, "value", None) or getattr(row, "artifact", None) or f"IOC {ioc_id}"
    evidence = await create_node(db, {
        "node_type": "evidence",
        "title": f"IOC evidence: {title}",
        "source_type": "ioc",
        "source_ref": ioc_id,
        "normalized_summary": getattr(row, "description", "") if row else "",
        "confidence": getattr(row, "confidence", 50) if row else 50,
        "metadata_json": {"origin": "from-ioc", "ioc_id": ioc_id},
    }, actor)
    return {"nodes_created": 1, "edges_created": 0, "nodes": [row_to_dict(evidence)], "edges": []}


async def graph_from_asset(db: AsyncSession, asset_id: str, actor: str) -> dict[str, Any]:
    row = None
    try:
        row = await db.get(AssetSurfaceCase, uuid.UUID(asset_id))
    except ValueError:
        pass
    techniques = getattr(row, "technique_ids", []) or []
    evidence = await create_node(db, {
        "node_type": "evidence",
        "title": f"Asset exposure: {getattr(row, 'name', asset_id)}",
        "source_type": "asset_observation",
        "source_ref": asset_id,
        "normalized_summary": getattr(row, "summary", "") if row else "",
        "metadata_json": {"origin": "from-asset", "asset_id": asset_id},
    }, actor)
    created = [evidence]
    edges = []
    for technique_id in techniques[:25]:
        attack = await create_node(db, {
            "node_type": "attack_technique",
            "title": str(technique_id),
            "framework": "attack_enterprise",
            "technique_id": str(technique_id),
            "review_status": "draft",
            "metadata_json": {"origin": "from-asset", "asset_id": asset_id},
        }, actor)
        telemetry = await telemetry_from_attack(db, str(technique_id), str(technique_id), actor)
        created.append(attack)
        edges.append(await create_edge(db, {"source_node_id": str(evidence.id), "target_node_id": str(attack.id), "edge_type": "RELATED_ASSET", "rationale": "Asset exposure maps to this technique.", "review_status": "draft"}, actor))
        if telemetry:
            created.append(telemetry)
            edges.append(await create_edge(db, {"source_node_id": str(attack.id), "target_node_id": str(telemetry.id), "edge_type": "REQUIRES_TELEMETRY", "review_status": "draft"}, actor))
    return {"nodes_created": len(created), "edges_created": len(edges), "nodes": [row_to_dict(n) for n in created], "edges": [row_to_dict(e) for e in edges]}


async def graph_from_malware(db: AsyncSession, case_id: str, actor: str) -> dict[str, Any]:
    evidence = await create_node(db, {
        "node_type": "evidence",
        "title": f"Malware finding evidence: {case_id}",
        "source_type": "malware_finding",
        "source_ref": case_id,
        "normalized_summary": "Static-first malware finding placeholder. Dynamic behavior must be validated separately.",
        "confidence": 45,
        "metadata_json": {"origin": "from-malware", "malware_case_id": case_id, "limitation": "Static finding is not behavior proof by itself."},
    }, actor)
    return {"nodes_created": 1, "edges_created": 0, "nodes": [row_to_dict(evidence)], "edges": []}


async def telemetry_from_attack(db: AsyncSession, technique_id: str, technique_name: str, actor: str) -> EvidenceGraphNode | None:
    if not technique_id:
        return None
    latest = await db.scalar(select(AttackVersion.id).where(AttackVersion.domain == "enterprise-attack", AttackVersion.is_latest.is_(True)))
    technique = None
    if latest:
        technique = await db.scalar(select(Technique).where(Technique.version_id == latest, Technique.attack_id == technique_id))
    data_sources = getattr(technique, "data_sources", []) or []
    required_fields = ["timestamp", "host", "user", "process", "event.action"]
    return await create_node(db, {
        "node_type": "required_telemetry",
        "title": f"Required telemetry for {technique_id}",
        "data_source": ", ".join(data_sources[:3]) if data_sources else "Unknown ATT&CK data source",
        "data_component": data_sources[0] if data_sources else "To be defined by analyst",
        "required_fields": required_fields,
        "example_sources": ["Sysmon", "Windows Event Log", "EDR", "web/proxy/firewall logs"],
        "schema_target": "raw",
        "availability_status": "unknown",
        "gap_description": "Telemetry must be confirmed before detection can be marked ready.",
        "review_status": "draft",
        "created_by": actor,
        "metadata_json": {"technique_id": technique_id, "technique_name": technique_name},
    }, actor)


def build_grouped_paths(nodes: list[Any], edges: list[Any]) -> list[dict[str, Any]]:
    node_dicts = [row_to_dict(node) if hasattr(node, "__table__") else node for node in nodes]
    edge_dicts = [row_to_dict(edge) if hasattr(edge, "__table__") else edge for edge in edges]
    by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for node in node_dicts:
        by_type[node["node_type"]].append(node)
    if not node_dicts:
        return []
    return [{
        "label": "Evidence-to-Detection reasoning chain",
        "steps": [by_type[item][0] for item in ORDERED_PATH_TYPES if by_type.get(item)],
        "edge_count": len(edge_dicts),
    }]


def markdown_report(graph: dict[str, Any]) -> str:
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])
    score = detection_readiness_score(nodes, edges)
    lines = [
        "# Evidence-to-Detection Graph Report",
        "",
        "## Summary",
        f"- Nodes: {len(nodes)}",
        f"- Edges: {len(edges)}",
        f"- Detection Readiness Score: {score}/100",
        "",
        "## Detection Readiness Score",
        "Operational readiness score, not scientific proof.",
        "",
        "## Validated Paths",
    ]
    for node in nodes:
        if node.get("node_type") in {"siem_result", "analyst_decision"}:
            lines.append(f"- {node.get('title')} ({node.get('node_type')})")
    lines.extend(["", "## Open Gaps", "Run `/api/evidence-graph/gaps` for structured gaps.", "", "## Analyst Decisions"])
    for node in nodes:
        if node.get("node_type") == "analyst_decision":
            lines.append(f"- {node.get('decision')}: {node.get('rationale')}")
    lines.extend(["", "## Evidence Paths"])
    for node in nodes:
        lines.append(f"- {node.get('node_type')}: {node.get('title')}")
    lines.extend(["", "## Limitations", "- AI-generated nodes and edges are draft until analyst-reviewed.", "- TTP overlap is not attribution proof.", "- Static malware indicators are not dynamic behavior proof.", "- Sensitive excerpts may require handling controls."])
    return "\n".join(lines) + "\n"


def nodes_csv(nodes: list[dict[str, Any]]) -> str:
    fields = ["id", "node_type", "title", "technique_id", "confidence", "review_status", "ai_generated", "created_at"]
    return _csv(fields, nodes)


def edges_csv(edges: list[dict[str, Any]]) -> str:
    fields = ["id", "source_node_id", "target_node_id", "edge_type", "confidence", "review_status", "ai_generated", "created_at"]
    return _csv(fields, edges)


def gaps_csv(gaps: list[dict[str, Any]]) -> str:
    fields = ["technique", "evidence", "missing_step", "required_telemetry", "detection_candidate", "rule_status", "validation_status", "analyst_decision", "recommended_next_action"]
    return _csv(fields, gaps)


def _csv(fields: list[str], rows: list[dict[str, Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buffer.getvalue()


def redact_sensitive(value: Any) -> Any:
    if isinstance(value, dict):
        clean = {}
        for key, item in value.items():
            if SENSITIVE_KEYS.search(str(key)):
                clean[key] = "[REDACTED]"
            else:
                clean[key] = redact_sensitive(item)
        return clean
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, str) and SENSITIVE_KEYS.search(value[:80]):
        return "[REDACTED]"
    return value


def top_gap_techniques(nodes: list[dict[str, Any]], gaps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts = Counter(gap.get("technique") or "unknown" for gap in gaps)
    names = {node.get("technique_id"): node.get("technique_name") or node.get("title") for node in nodes if node.get("technique_id")}
    return [{"technique": key, "name": names.get(key, key), "gap_count": value} for key, value in counts.most_common(10)]


def _has_downstream_type(node_id: str, target_type: str, outgoing: dict[str, list[dict[str, Any]]], by_id: dict[str, dict[str, Any]]) -> bool:
    for edge in outgoing.get(node_id, []):
        target = by_id.get(edge["target_node_id"])
        if target and target.get("node_type") == target_type:
            return True
    return False


def _gap(node: dict[str, Any], missing_step: str, action: str) -> dict[str, Any]:
    return {
        "technique": node.get("technique_id") or node.get("title") or "",
        "evidence": node.get("raw_excerpt") or node.get("statement") or node.get("title") or "",
        "missing_step": missing_step,
        "required_telemetry": node.get("data_component") or "",
        "detection_candidate": node.get("detection_hypothesis") or "",
        "rule_status": node.get("test_status") or node.get("deployment_status") or "",
        "validation_status": node.get("forwarding_status") or "",
        "analyst_decision": node.get("decision") or "",
        "recommended_next_action": action,
        "node_id": node.get("id"),
    }


def _node_columns(payload: dict[str, Any]) -> dict[str, Any]:
    columns = EvidenceGraphNode.__table__.columns.keys()
    return {key: value for key, value in payload.items() if key in columns and key != "id"}


def _edge_columns(payload: dict[str, Any]) -> dict[str, Any]:
    columns = EvidenceGraphEdge.__table__.columns.keys()
    return {key: value for key, value in payload.items() if key in columns and key != "id"}


def _extract_technique(value: str) -> str:
    match = re.search(r"T\d{4}(?:\.\d{3})?", value)
    return match.group(0) if match else ""


def _node_to_obj(data: dict[str, Any]):
    return type("NodeObject", (), {"__table__": EvidenceGraphNode.__table__, **data})()


def _edge_to_obj(data: dict[str, Any]):
    return type("EdgeObject", (), {"__table__": EvidenceGraphEdge.__table__, **data})()
