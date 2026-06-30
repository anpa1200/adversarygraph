from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.services.auth import TeamUser, admin, analyst, audit
from app.services import evidence_graph as graph

router = APIRouter(prefix="/evidence-graph", tags=["Evidence-to-Detection Graph"])


class NodeBody(BaseModel):
    node_type: str = Field(..., min_length=2, max_length=50)
    title: str = Field(..., min_length=1, max_length=500)
    description: str = ""
    source_type: str = ""
    source_ref: str = ""
    raw_excerpt: str = ""
    normalized_summary: str = ""
    timestamp_observed: datetime | None = None
    statement: str = ""
    claim_type: str = ""
    behavior_description: str = ""
    tactic_hint: str = ""
    observable_pattern: str = ""
    framework: str = ""
    technique_id: str = ""
    technique_name: str = ""
    tactic: str = ""
    mapping_rationale: str = ""
    data_source: str = ""
    data_component: str = ""
    required_fields: list[Any] = Field(default_factory=list)
    example_sources: list[Any] = Field(default_factory=list)
    schema_target: str = "raw"
    availability_status: str = "unknown"
    gap_description: str = ""
    detection_hypothesis: str = ""
    detection_type: str = ""
    severity: str = "medium"
    expected_false_positives: str = ""
    required_telemetry_ids: list[Any] = Field(default_factory=list)
    status: str = ""
    rule_format: str = ""
    rule_body: str = ""
    rule_version: str = ""
    backend_assumptions: str = ""
    test_status: str = "not_tested"
    deployment_status: str = "draft"
    scenario_type: str = ""
    scenario_description: str = ""
    attack_techniques: list[Any] = Field(default_factory=list)
    expected_telemetry: str = ""
    expected_detection_outcome: str = ""
    safety_boundary: str = ""
    destination_type: str = ""
    destination_label: str = ""
    forwarding_status: str = "not_sent"
    collector_response: str = ""
    parsed_fields: dict[str, Any] = Field(default_factory=dict)
    detection_matched: bool = False
    dashboard_updated: bool = False
    correlation_triggered: bool = False
    failure_reason: str = ""
    evidence_ref: str = ""
    decision: str = ""
    rationale: str = ""
    reviewer: str = ""
    reviewed_at: datetime | None = None
    next_action: str = ""
    confidence: int = 50
    review_status: str = "draft"
    ai_generated: bool = False
    ai_provider: str = ""
    ai_model: str = ""
    ai_prompt_version: str = ""
    tags: list[Any] = Field(default_factory=list)
    metadata_json: dict[str, Any] = Field(default_factory=dict)


class NodePatch(BaseModel):
    node_type: str | None = None
    title: str | None = None
    description: str | None = None
    source_type: str | None = None
    source_ref: str | None = None
    raw_excerpt: str | None = None
    normalized_summary: str | None = None
    timestamp_observed: datetime | None = None
    statement: str | None = None
    claim_type: str | None = None
    behavior_description: str | None = None
    tactic_hint: str | None = None
    observable_pattern: str | None = None
    framework: str | None = None
    technique_id: str | None = None
    technique_name: str | None = None
    tactic: str | None = None
    mapping_rationale: str | None = None
    data_source: str | None = None
    data_component: str | None = None
    required_fields: list[Any] | None = None
    example_sources: list[Any] | None = None
    schema_target: str | None = None
    availability_status: str | None = None
    gap_description: str | None = None
    detection_hypothesis: str | None = None
    detection_type: str | None = None
    severity: str | None = None
    expected_false_positives: str | None = None
    required_telemetry_ids: list[Any] | None = None
    status: str | None = None
    rule_format: str | None = None
    rule_body: str | None = None
    rule_version: str | None = None
    backend_assumptions: str | None = None
    test_status: str | None = None
    deployment_status: str | None = None
    scenario_type: str | None = None
    scenario_description: str | None = None
    attack_techniques: list[Any] | None = None
    expected_telemetry: str | None = None
    expected_detection_outcome: str | None = None
    safety_boundary: str | None = None
    destination_type: str | None = None
    destination_label: str | None = None
    forwarding_status: str | None = None
    collector_response: str | None = None
    parsed_fields: dict[str, Any] | None = None
    detection_matched: bool | None = None
    dashboard_updated: bool | None = None
    correlation_triggered: bool | None = None
    failure_reason: str | None = None
    evidence_ref: str | None = None
    decision: str | None = None
    rationale: str | None = None
    reviewer: str | None = None
    reviewed_at: datetime | None = None
    next_action: str | None = None
    confidence: int | None = None
    review_status: str | None = None
    ai_generated: bool | None = None
    ai_provider: str | None = None
    ai_model: str | None = None
    ai_prompt_version: str | None = None
    tags: list[Any] | None = None
    metadata_json: dict[str, Any] | None = None


class EdgeBody(BaseModel):
    source_node_id: str
    target_node_id: str
    edge_type: str
    rationale: str = ""
    confidence: int = 50
    review_status: str = "draft"
    ai_generated: bool = False
    metadata_json: dict[str, Any] = Field(default_factory=dict)


class EdgePatch(BaseModel):
    source_node_id: str | None = None
    target_node_id: str | None = None
    edge_type: str | None = None
    rationale: str | None = None
    confidence: int | None = None
    review_status: str | None = None
    ai_generated: bool | None = None
    metadata_json: dict[str, Any] | None = None


@router.get("/summary")
async def summary(db: AsyncSession = Depends(get_session)):
    return await graph.summary(db)


@router.get("")
async def query(
    case_id: str = "",
    report_id: str = "",
    technique_id: str = "",
    ioc_id: str = "",
    asset_id: str = "",
    malware_case_id: str = "",
    validation_status: str = "",
    review_status: str = "",
    node_type: str = "",
    max_depth: int = Query(6, ge=1, le=20),
    include_ai_suggestions: bool = True,
    include_rejected: bool = False,
    search: str = "",
    db: AsyncSession = Depends(get_session),
):
    # Current implementation keeps entity links in node source refs and metadata.
    # These filters are accepted for API stability and mapped to source/search terms
    # until typed foreign-key link tables are added.
    filter_search = search or case_id or report_id or ioc_id or asset_id or malware_case_id
    result = await graph.query_graph(
        db,
        node_type=node_type,
        technique_id=technique_id,
        review_status=review_status,
        validation_status=validation_status,
        include_ai_suggestions=include_ai_suggestions,
        include_rejected=include_rejected,
        search=filter_search,
        limit=max(100, max_depth * 100),
    )
    result["warnings"].append("AI-generated graph items are hypotheses until analyst-reviewed.")
    return result


@router.post("/nodes", status_code=201)
async def create_node(body: NodeBody, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    row = await graph.create_node(db, body.model_dump(), user.name)
    await audit(db, user, "evidence_graph.create_node", "evidence_graph_node", str(row.id), {"node_type": row.node_type})
    await db.commit(); await db.refresh(row)
    return graph.row_to_dict(row)


@router.patch("/nodes/{node_id}")
async def update_node(node_id: str, body: NodePatch, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    row = await graph.update_node(db, node_id, body.model_dump(exclude_unset=True))
    await audit(db, user, "evidence_graph.update_node", "evidence_graph_node", str(row.id), {"node_type": row.node_type})
    await db.commit(); await db.refresh(row)
    return graph.row_to_dict(row)


@router.delete("/nodes/{node_id}", status_code=204)
async def delete_node(node_id: str, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(admin)):
    await graph.delete_node(db, node_id)
    await audit(db, user, "evidence_graph.delete_node", "evidence_graph_node", node_id)
    await db.commit()


@router.post("/edges", status_code=201)
async def create_edge(body: EdgeBody, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    row = await graph.create_edge(db, body.model_dump(), user.name)
    await audit(db, user, "evidence_graph.create_edge", "evidence_graph_edge", str(row.id), {"edge_type": row.edge_type})
    await db.commit(); await db.refresh(row)
    return graph.row_to_dict(row)


@router.patch("/edges/{edge_id}")
async def update_edge(edge_id: str, body: EdgePatch, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    row = await graph.update_edge(db, edge_id, body.model_dump(exclude_unset=True))
    await audit(db, user, "evidence_graph.update_edge", "evidence_graph_edge", str(row.id), {"edge_type": row.edge_type})
    await db.commit(); await db.refresh(row)
    return graph.row_to_dict(row)


@router.delete("/edges/{edge_id}", status_code=204)
async def delete_edge(edge_id: str, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(admin)):
    await graph.delete_edge(db, edge_id)
    await audit(db, user, "evidence_graph.delete_edge", "evidence_graph_edge", edge_id)
    await db.commit()


@router.get("/paths")
async def paths(
    from_node_id: str = "",
    to_node_type: str = "",
    technique_id: str = "",
    detection_rule_id: str = "",
    analyst_decision_id: str = "",
    max_depth: int = Query(12, ge=1, le=20),
    db: AsyncSession = Depends(get_session),
):
    return await graph.reasoning_paths(
        db,
        from_node_id=from_node_id,
        to_node_type=to_node_type,
        technique_id=technique_id,
        detection_rule_id=detection_rule_id,
        analyst_decision_id=analyst_decision_id,
        max_depth=max_depth,
    )


@router.get("/gaps")
async def gaps(db: AsyncSession = Depends(get_session)):
    return await graph.gap_analysis(db)


@router.post("/from-report/{report_id}")
async def from_report(report_id: str, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    result = await graph.graph_from_report(db, report_id, user.name)
    await audit(db, user, "evidence_graph.from_report", "report", report_id, result)
    await db.commit()
    return result


@router.post("/from-malware/{case_id}")
async def from_malware(case_id: str, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    result = await graph.graph_from_malware(db, case_id, user.name)
    await audit(db, user, "evidence_graph.from_malware", "malware_case", case_id, result)
    await db.commit()
    return result


@router.post("/from-simulation/{simulation_run_id}")
async def from_simulation(simulation_run_id: str, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    result = await graph.graph_from_simulation(db, simulation_run_id, user.name)
    await audit(db, user, "evidence_graph.from_simulation", "simulation_run", simulation_run_id, result)
    await db.commit()
    return result


@router.post("/from-ioc/{ioc_id}")
async def from_ioc(ioc_id: str, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    result = await graph.graph_from_ioc(db, ioc_id, user.name)
    await audit(db, user, "evidence_graph.from_ioc", "ioc", ioc_id, result)
    await db.commit()
    return result


@router.post("/from-asset/{asset_id}")
async def from_asset(asset_id: str, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(analyst)):
    result = await graph.graph_from_asset(db, asset_id, user.name)
    await audit(db, user, "evidence_graph.from_asset", "asset", asset_id, result)
    await db.commit()
    return result


@router.get("/export")
async def export(fmt: str = Query("json", pattern="^(json|markdown|csv|evidence-pack)$"), db: AsyncSession = Depends(get_session), _: TeamUser = Depends(analyst)):
    media_type, filename, content = await graph.export_graph(db, fmt)
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-AdversaryGraph-Export-Warning": "May contain sensitive report excerpts; secrets are redacted and malware binaries are excluded.",
        },
    )
