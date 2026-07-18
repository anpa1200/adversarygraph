from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Response
from pydantic import Field, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.core.payload_limits import BoundedPayloadModel
from app.services.auth import TeamUser, audit, current_user, require_permission
from app.services import evidence_graph as graph

manage_evidence = require_permission("manage_intel")
export_evidence = require_permission("export_data")

router = APIRouter(prefix="/evidence-graph", tags=["Evidence-to-Detection Graph"])


class NodeBody(BoundedPayloadModel):
    node_type: str = Field(..., min_length=2, max_length=50)
    title: str = Field(..., min_length=1, max_length=500)
    description: str = Field("", max_length=100_000)
    source_type: str = Field("", max_length=80)
    source_ref: str = Field("", max_length=500)
    raw_excerpt: str = Field("", max_length=250_000)
    normalized_summary: str = Field("", max_length=100_000)
    timestamp_observed: datetime | None = None
    statement: str = Field("", max_length=100_000)
    claim_type: str = Field("", max_length=80)
    behavior_description: str = Field("", max_length=100_000)
    tactic_hint: str = Field("", max_length=120)
    observable_pattern: str = Field("", max_length=100_000)
    framework: str = Field("", max_length=80)
    technique_id: str = Field("", max_length=40)
    technique_name: str = Field("", max_length=255)
    tactic: str = Field("", max_length=120)
    mapping_rationale: str = Field("", max_length=100_000)
    data_source: str = Field("", max_length=255)
    data_component: str = Field("", max_length=255)
    required_fields: list[Any] = Field(default_factory=list, max_length=2000)
    example_sources: list[Any] = Field(default_factory=list, max_length=2000)
    schema_target: str = Field("raw", max_length=80)
    availability_status: str = Field("unknown", max_length=40)
    gap_description: str = Field("", max_length=100_000)
    detection_hypothesis: str = Field("", max_length=100_000)
    detection_type: str = Field("", max_length=80)
    severity: str = Field("medium", max_length=40)
    expected_false_positives: str = Field("", max_length=100_000)
    required_telemetry_ids: list[Any] = Field(default_factory=list, max_length=2000)
    status: str = Field("", max_length=80)
    rule_format: str = Field("", max_length=80)
    rule_body: str = Field("", max_length=250_000)
    rule_version: str = Field("", max_length=80)
    backend_assumptions: str = Field("", max_length=100_000)
    test_status: str = Field("not_tested", max_length=40)
    deployment_status: str = Field("draft", max_length=40)
    scenario_type: str = Field("", max_length=80)
    scenario_description: str = Field("", max_length=100_000)
    attack_techniques: list[Any] = Field(default_factory=list, max_length=2000)
    expected_telemetry: str = Field("", max_length=100_000)
    expected_detection_outcome: str = Field("", max_length=100_000)
    safety_boundary: str = Field("", max_length=100_000)
    destination_type: str = Field("", max_length=80)
    destination_label: str = Field("", max_length=255)
    forwarding_status: str = Field("not_sent", max_length=40)
    collector_response: str = Field("", max_length=100_000)
    parsed_fields: dict[str, Any] = Field(default_factory=dict, max_length=2000)
    detection_matched: bool = False
    dashboard_updated: bool = False
    correlation_triggered: bool = False
    failure_reason: str = Field("", max_length=100_000)
    evidence_ref: str = Field("", max_length=500)
    decision: str = Field("", max_length=80)
    rationale: str = Field("", max_length=100_000)
    reviewer: str = Field("", max_length=255)
    reviewed_at: datetime | None = None
    next_action: str = Field("", max_length=100_000)
    confidence: int = Field(50, ge=0, le=100)
    review_status: str = Field("draft", max_length=40)
    ai_generated: bool = False
    ai_provider: str = Field("", max_length=80)
    ai_model: str = Field("", max_length=120)
    ai_prompt_version: str = Field("", max_length=80)
    tags: list[Any] = Field(default_factory=list, max_length=2000)
    metadata_json: dict[str, Any] = Field(default_factory=dict, max_length=2000)


class NodePatch(BoundedPayloadModel):
    node_type: str | None = Field(None, min_length=2, max_length=50)
    title: str | None = Field(None, min_length=1, max_length=500)
    description: str | None = None
    source_type: str | None = Field(None, max_length=80)
    source_ref: str | None = Field(None, max_length=500)
    raw_excerpt: str | None = None
    normalized_summary: str | None = None
    timestamp_observed: datetime | None = None
    statement: str | None = None
    claim_type: str | None = Field(None, max_length=80)
    behavior_description: str | None = None
    tactic_hint: str | None = Field(None, max_length=120)
    observable_pattern: str | None = None
    framework: str | None = Field(None, max_length=80)
    technique_id: str | None = Field(None, max_length=40)
    technique_name: str | None = Field(None, max_length=255)
    tactic: str | None = Field(None, max_length=120)
    mapping_rationale: str | None = None
    data_source: str | None = Field(None, max_length=255)
    data_component: str | None = Field(None, max_length=255)
    required_fields: list[Any] | None = None
    example_sources: list[Any] | None = None
    schema_target: str | None = Field(None, max_length=80)
    availability_status: str | None = Field(None, max_length=40)
    gap_description: str | None = None
    detection_hypothesis: str | None = None
    detection_type: str | None = Field(None, max_length=80)
    severity: str | None = Field(None, max_length=40)
    expected_false_positives: str | None = None
    required_telemetry_ids: list[Any] | None = None
    status: str | None = Field(None, max_length=80)
    rule_format: str | None = Field(None, max_length=80)
    rule_body: str | None = None
    rule_version: str | None = Field(None, max_length=80)
    backend_assumptions: str | None = None
    test_status: str | None = Field(None, max_length=40)
    deployment_status: str | None = Field(None, max_length=40)
    scenario_type: str | None = Field(None, max_length=80)
    scenario_description: str | None = None
    attack_techniques: list[Any] | None = None
    expected_telemetry: str | None = None
    expected_detection_outcome: str | None = None
    safety_boundary: str | None = None
    destination_type: str | None = Field(None, max_length=80)
    destination_label: str | None = Field(None, max_length=255)
    forwarding_status: str | None = Field(None, max_length=40)
    collector_response: str | None = None
    parsed_fields: dict[str, Any] | None = None
    detection_matched: bool | None = None
    dashboard_updated: bool | None = None
    correlation_triggered: bool | None = None
    failure_reason: str | None = None
    evidence_ref: str | None = Field(None, max_length=500)
    decision: str | None = Field(None, max_length=80)
    rationale: str | None = None
    reviewer: str | None = Field(None, max_length=255)
    reviewed_at: datetime | None = None
    next_action: str | None = None
    confidence: int | None = Field(None, ge=0, le=100)
    review_status: str | None = Field(None, max_length=40)
    ai_generated: bool | None = None
    ai_provider: str | None = Field(None, max_length=80)
    ai_model: str | None = Field(None, max_length=120)
    ai_prompt_version: str | None = Field(None, max_length=80)
    tags: list[Any] | None = None
    metadata_json: dict[str, Any] | None = None

    @model_validator(mode="after")
    def reject_nonnullable_nulls(self):
        nullable = {"timestamp_observed", "reviewed_at"}
        invalid = sorted(
            field
            for field in self.model_fields_set
            if field not in nullable and getattr(self, field) is None
        )
        if invalid:
            raise ValueError(f"Fields cannot be null: {', '.join(invalid)}")
        return self


class EdgeBody(BoundedPayloadModel):
    source_node_id: str = Field(..., min_length=1, max_length=64)
    target_node_id: str = Field(..., min_length=1, max_length=64)
    edge_type: str = Field(..., min_length=1, max_length=80)
    rationale: str = Field("", max_length=100_000)
    confidence: int = Field(50, ge=0, le=100)
    review_status: str = Field("draft", max_length=40)
    ai_generated: bool = False
    metadata_json: dict[str, Any] = Field(default_factory=dict, max_length=2000)


class EdgePatch(BoundedPayloadModel):
    source_node_id: str | None = Field(None, min_length=1, max_length=64)
    target_node_id: str | None = Field(None, min_length=1, max_length=64)
    edge_type: str | None = Field(None, min_length=1, max_length=80)
    rationale: str | None = None
    confidence: int | None = Field(None, ge=0, le=100)
    review_status: str | None = Field(None, max_length=40)
    ai_generated: bool | None = None
    metadata_json: dict[str, Any] | None = None

    @model_validator(mode="after")
    def reject_nulls(self):
        invalid = sorted(
            field for field in self.model_fields_set if getattr(self, field) is None
        )
        if invalid:
            raise ValueError(f"Fields cannot be null: {', '.join(invalid)}")
        return self


@router.get("/summary")
async def summary(
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
):
    return await graph.summary(db)


@router.get("")
async def query(
    case_id: str = Query("", max_length=255),
    report_id: str = Query("", max_length=255),
    technique_id: str = Query("", max_length=40),
    ioc_id: str = Query("", max_length=255),
    asset_id: str = Query("", max_length=255),
    malware_case_id: str = Query("", max_length=255),
    validation_status: str = Query("", max_length=40),
    review_status: str = Query("", max_length=40),
    node_type: str = Query("", max_length=50),
    max_depth: int = Query(6, ge=1, le=20),
    include_ai_suggestions: bool = True,
    include_rejected: bool = False,
    search: str = Query("", max_length=500),
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
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
async def create_node(body: NodeBody, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_evidence)):
    row = await graph.create_node(db, body.model_dump(), user.name)
    await audit(db, user, "evidence_graph.create_node", "evidence_graph_node", str(row.id), {"node_type": row.node_type})
    await db.commit(); await db.refresh(row)
    return graph.row_to_dict(row)


@router.patch("/nodes/{node_id}")
async def update_node(node_id: str, body: NodePatch, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_evidence)):
    row = await graph.update_node(db, node_id, body.model_dump(exclude_unset=True))
    await audit(db, user, "evidence_graph.update_node", "evidence_graph_node", str(row.id), {"node_type": row.node_type})
    await db.commit(); await db.refresh(row)
    return graph.row_to_dict(row)


@router.delete("/nodes/{node_id}", status_code=204)
async def delete_node(node_id: str, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_evidence)):
    await graph.delete_node(db, node_id)
    await audit(db, user, "evidence_graph.delete_node", "evidence_graph_node", node_id)
    await db.commit()


@router.post("/edges", status_code=201)
async def create_edge(body: EdgeBody, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_evidence)):
    row = await graph.create_edge(db, body.model_dump(), user.name)
    await audit(db, user, "evidence_graph.create_edge", "evidence_graph_edge", str(row.id), {"edge_type": row.edge_type})
    await db.commit(); await db.refresh(row)
    return graph.row_to_dict(row)


@router.patch("/edges/{edge_id}")
async def update_edge(edge_id: str, body: EdgePatch, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_evidence)):
    row = await graph.update_edge(db, edge_id, body.model_dump(exclude_unset=True))
    await audit(db, user, "evidence_graph.update_edge", "evidence_graph_edge", str(row.id), {"edge_type": row.edge_type})
    await db.commit(); await db.refresh(row)
    return graph.row_to_dict(row)


@router.delete("/edges/{edge_id}", status_code=204)
async def delete_edge(edge_id: str, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_evidence)):
    await graph.delete_edge(db, edge_id)
    await audit(db, user, "evidence_graph.delete_edge", "evidence_graph_edge", edge_id)
    await db.commit()


@router.get("/paths")
async def paths(
    from_node_id: str = Query("", max_length=64),
    to_node_type: str = Query("", max_length=50),
    technique_id: str = Query("", max_length=40),
    detection_rule_id: str = Query("", max_length=64),
    analyst_decision_id: str = Query("", max_length=64),
    max_depth: int = Query(12, ge=1, le=20),
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
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
async def gaps(
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
):
    return await graph.gap_analysis(db)


@router.post("/from-report/{report_id}")
async def from_report(report_id: str, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_evidence)):
    result = await graph.graph_from_report(db, report_id, user.name)
    await audit(db, user, "evidence_graph.from_report", "report", report_id, result)
    await db.commit()
    return result


@router.post("/from-malware/{case_id}")
async def from_malware(case_id: str, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_evidence)):
    result = await graph.graph_from_malware(db, case_id, user.name)
    await audit(db, user, "evidence_graph.from_malware", "malware_case", case_id, result)
    await db.commit()
    return result


@router.post("/from-simulation/{simulation_run_id}")
async def from_simulation(simulation_run_id: str, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_evidence)):
    result = await graph.graph_from_simulation(db, simulation_run_id, user.name)
    await audit(db, user, "evidence_graph.from_simulation", "simulation_run", simulation_run_id, result)
    await db.commit()
    return result


@router.post("/from-ioc/{ioc_id}")
async def from_ioc(ioc_id: str, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_evidence)):
    result = await graph.graph_from_ioc(db, ioc_id, user.name)
    await audit(db, user, "evidence_graph.from_ioc", "ioc", ioc_id, result)
    await db.commit()
    return result


@router.post("/from-asset/{asset_id}")
async def from_asset(asset_id: str, db: AsyncSession = Depends(get_session), user: TeamUser = Depends(manage_evidence)):
    result = await graph.graph_from_asset(db, asset_id, user.name)
    await audit(db, user, "evidence_graph.from_asset", "asset", asset_id, result)
    await db.commit()
    return result


@router.get("/export")
async def export(fmt: str = Query("json", pattern="^(json|markdown|csv|evidence-pack)$"), db: AsyncSession = Depends(get_session), _: TeamUser = Depends(export_evidence)):
    media_type, filename, content = await graph.export_graph(db, fmt)
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-AdversaryGraph-Export-Warning": "May contain sensitive report excerpts; secrets are redacted and malware binaries are excluded.",
        },
    )
