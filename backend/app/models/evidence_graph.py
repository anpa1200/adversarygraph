from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class EvidenceGraphNode(Base):
    """A typed node in the evidence-to-detection reasoning graph."""

    __tablename__ = "evidence_graph_nodes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    node_type: Mapped[str] = mapped_column(String(50), index=True)
    title: Mapped[str] = mapped_column(String(500), index=True)
    description: Mapped[str] = mapped_column(Text, default="")

    # Evidence / claim / behavior fields.
    source_type: Mapped[str] = mapped_column(String(80), default="", index=True)
    source_ref: Mapped[str] = mapped_column(String(500), default="", index=True)
    raw_excerpt: Mapped[str] = mapped_column(Text, default="")
    normalized_summary: Mapped[str] = mapped_column(Text, default="")
    timestamp_observed: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    statement: Mapped[str] = mapped_column(Text, default="")
    claim_type: Mapped[str] = mapped_column(String(80), default="")
    behavior_description: Mapped[str] = mapped_column(Text, default="")
    tactic_hint: Mapped[str] = mapped_column(String(120), default="")
    observable_pattern: Mapped[str] = mapped_column(Text, default="")

    # ATT&CK / telemetry / detection fields.
    framework: Mapped[str] = mapped_column(String(80), default="")
    technique_id: Mapped[str] = mapped_column(String(40), default="", index=True)
    technique_name: Mapped[str] = mapped_column(String(255), default="")
    tactic: Mapped[str] = mapped_column(String(120), default="")
    mapping_rationale: Mapped[str] = mapped_column(Text, default="")
    data_source: Mapped[str] = mapped_column(String(255), default="")
    data_component: Mapped[str] = mapped_column(String(255), default="")
    required_fields: Mapped[list] = mapped_column(JSONB, default=list)
    example_sources: Mapped[list] = mapped_column(JSONB, default=list)
    schema_target: Mapped[str] = mapped_column(String(80), default="raw")
    availability_status: Mapped[str] = mapped_column(String(40), default="unknown", index=True)
    gap_description: Mapped[str] = mapped_column(Text, default="")
    detection_hypothesis: Mapped[str] = mapped_column(Text, default="")
    detection_type: Mapped[str] = mapped_column(String(80), default="")
    severity: Mapped[str] = mapped_column(String(40), default="medium")
    expected_false_positives: Mapped[str] = mapped_column(Text, default="")
    required_telemetry_ids: Mapped[list] = mapped_column(JSONB, default=list)
    status: Mapped[str] = mapped_column(String(80), default="", index=True)
    rule_format: Mapped[str] = mapped_column(String(80), default="")
    rule_body: Mapped[str] = mapped_column(Text, default="")
    rule_version: Mapped[str] = mapped_column(String(80), default="")
    backend_assumptions: Mapped[str] = mapped_column(Text, default="")
    test_status: Mapped[str] = mapped_column(String(40), default="not_tested", index=True)
    deployment_status: Mapped[str] = mapped_column(String(40), default="draft", index=True)

    # Validation / SIEM / analyst decision fields.
    scenario_type: Mapped[str] = mapped_column(String(80), default="")
    scenario_description: Mapped[str] = mapped_column(Text, default="")
    attack_techniques: Mapped[list] = mapped_column(JSONB, default=list)
    expected_telemetry: Mapped[str] = mapped_column(Text, default="")
    expected_detection_outcome: Mapped[str] = mapped_column(Text, default="")
    safety_boundary: Mapped[str] = mapped_column(Text, default="")
    destination_type: Mapped[str] = mapped_column(String(80), default="")
    destination_label: Mapped[str] = mapped_column(String(255), default="")
    forwarding_status: Mapped[str] = mapped_column(String(40), default="not_sent", index=True)
    collector_response: Mapped[str] = mapped_column(Text, default="")
    parsed_fields: Mapped[dict] = mapped_column(JSONB, default=dict)
    detection_matched: Mapped[bool] = mapped_column(Boolean, default=False)
    dashboard_updated: Mapped[bool] = mapped_column(Boolean, default=False)
    correlation_triggered: Mapped[bool] = mapped_column(Boolean, default=False)
    failure_reason: Mapped[str] = mapped_column(Text, default="")
    evidence_ref: Mapped[str] = mapped_column(String(500), default="")
    decision: Mapped[str] = mapped_column(String(80), default="", index=True)
    rationale: Mapped[str] = mapped_column(Text, default="")
    reviewer: Mapped[str] = mapped_column(String(255), default="")
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_action: Mapped[str] = mapped_column(Text, default="")

    # Governance.
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    review_status: Mapped[str] = mapped_column(String(40), default="draft", index=True)
    ai_generated: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    ai_provider: Mapped[str] = mapped_column(String(80), default="")
    ai_model: Mapped[str] = mapped_column(String(120), default="")
    ai_prompt_version: Mapped[str] = mapped_column(String(80), default="")
    created_by: Mapped[str] = mapped_column(String(255), default="local")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    tags: Mapped[list] = mapped_column(JSONB, default=list)
    metadata_json: Mapped[dict] = mapped_column(JSONB, default=dict)


class EvidenceGraphEdge(Base):
    """A reviewed or draft relationship between two evidence graph nodes."""

    __tablename__ = "evidence_graph_edges"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_node_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    target_node_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    edge_type: Mapped[str] = mapped_column(String(80), index=True)
    rationale: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    created_by: Mapped[str] = mapped_column(String(255), default="local")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    review_status: Mapped[str] = mapped_column(String(40), default="draft", index=True)
    ai_generated: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    metadata_json: Mapped[dict] = mapped_column(JSONB, default=dict)
