from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class ThreatSource(Base):
    __tablename__ = "threat_sources"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), index=True)
    source_type: Mapped[str] = mapped_column(String(80), default="manual")
    url: Mapped[str] = mapped_column(String(1000), default="")
    reliability: Mapped[int] = mapped_column(Integer, default=3)
    tlp: Mapped[str] = mapped_column(String(20), default="TLP:AMBER")
    legal_sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ThreatSignal(Base):
    __tablename__ = "threat_signals"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(500), index=True)
    signal_type: Mapped[str] = mapped_column(String(80), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(60), default="new", index=True)
    source_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    source_name: Mapped[str] = mapped_column(String(255), default="")
    source_url: Mapped[str] = mapped_column(String(1000), default="")
    tlp: Mapped[str] = mapped_column(String(20), default="TLP:AMBER")
    legal_sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    severity: Mapped[str] = mapped_column(String(40), default="unknown")
    cve_ids: Mapped[list[str]] = mapped_column(JSONB, default=list)
    technique_ids: Mapped[list[str]] = mapped_column(JSONB, default=list)
    iocs: Mapped[list[dict]] = mapped_column(JSONB, default=list)
    actors: Mapped[list[str]] = mapped_column(JSONB, default=list)
    sectors: Mapped[list[str]] = mapped_column(JSONB, default=list)
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list)
    raw_metadata: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_by: Mapped[str] = mapped_column(String(255), default="local")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ThreatClaim(Base):
    __tablename__ = "threat_claims"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    signal_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    claim_type: Mapped[str] = mapped_column(String(80), default="threat-claim")
    statement: Mapped[str] = mapped_column(Text, default="")
    credibility: Mapped[int] = mapped_column(Integer, default=3)
    status: Mapped[str] = mapped_column(String(60), default="unvalidated")
    tlp: Mapped[str] = mapped_column(String(20), default="TLP:AMBER")
    legal_sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ThreatEvidence(Base):
    __tablename__ = "threat_evidence"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    signal_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    case_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    source_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    evidence_type: Mapped[str] = mapped_column(String(80), default="note")
    title: Mapped[str] = mapped_column(String(500), default="")
    summary: Mapped[str] = mapped_column(Text, default="")
    url: Mapped[str] = mapped_column(String(1000), default="")
    observed_at: Mapped[str] = mapped_column(String(80), default="")
    tlp: Mapped[str] = mapped_column(String(20), default="TLP:AMBER")
    legal_sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    sanitized: Mapped[bool] = mapped_column(Boolean, default=True)
    metadata_json: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ThreatEntity(Base):
    __tablename__ = "threat_entities"
    __table_args__ = (UniqueConstraint("entity_type", "value", name="uq_threat_entity_type_value"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    entity_type: Mapped[str] = mapped_column(String(80), index=True)
    value: Mapped[str] = mapped_column(String(500), index=True)
    label: Mapped[str] = mapped_column(String(500), default="")
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list)
    metadata_json: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ThreatCase(Base):
    __tablename__ = "threat_cases"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    signal_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(500), index=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(60), default="open", index=True)
    priority: Mapped[str] = mapped_column(String(40), default="P3 Monitor", index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    tlp: Mapped[str] = mapped_column(String(20), default="TLP:AMBER")
    legal_sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    recommended_actions: Mapped[list[dict]] = mapped_column(JSONB, default=list)
    product_context: Mapped[list[dict]] = mapped_column(JSONB, default=list)
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list)
    created_by: Mapped[str] = mapped_column(String(255), default="local")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ThreatCaseLink(Base):
    __tablename__ = "threat_case_links"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    target_type: Mapped[str] = mapped_column(String(80), index=True)
    target_id: Mapped[str] = mapped_column(String(255), index=True)
    relationship: Mapped[str] = mapped_column(String(120), default="related-to")
    evidence: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[int] = mapped_column(Integer, default=70)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ThreatProductMapping(Base):
    __tablename__ = "threat_product_mappings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    signal_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    case_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    product: Mapped[str] = mapped_column(String(255), index=True)
    component: Mapped[str] = mapped_column(String(255), default="")
    dependency: Mapped[str] = mapped_column(String(255), default="")
    version: Mapped[str] = mapped_column(String(120), default="")
    exposure: Mapped[str] = mapped_column(String(80), default="unknown")
    environment: Mapped[str] = mapped_column(String(80), default="unknown")
    relevance: Mapped[int] = mapped_column(Integer, default=3)
    blast_radius: Mapped[int] = mapped_column(Integer, default=3)
    evidence: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ThreatScore(Base):
    __tablename__ = "threat_scores"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    signal_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    case_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    score: Mapped[int] = mapped_column(Integer, default=0)
    priority: Mapped[str] = mapped_column(String(40), default="P4 Low/Archive")
    factors: Mapped[dict] = mapped_column(JSONB, default=dict)
    rationale: Mapped[list[str]] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ThreatAction(Base):
    __tablename__ = "threat_actions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    action_type: Mapped[str] = mapped_column(String(80), index=True)
    title: Mapped[str] = mapped_column(String(500))
    owner_team: Mapped[str] = mapped_column(String(120), default="")
    status: Mapped[str] = mapped_column(String(60), default="open", index=True)
    priority: Mapped[str] = mapped_column(String(40), default="P3 Monitor")
    description: Mapped[str] = mapped_column(Text, default="")
    metadata_json: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ThreatHuntRequest(Base):
    __tablename__ = "threat_hunt_requests"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    title: Mapped[str] = mapped_column(String(500))
    hypothesis: Mapped[str] = mapped_column(Text, default="")
    telemetry: Mapped[list[str]] = mapped_column(JSONB, default=list)
    technique_ids: Mapped[list[str]] = mapped_column(JSONB, default=list)
    status: Mapped[str] = mapped_column(String(60), default="queued")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ThreatIREscalation(Base):
    __tablename__ = "threat_ir_escalations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    title: Mapped[str] = mapped_column(String(500))
    reason: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(40), default="high")
    legal_sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(60), default="queued")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ThreatPSIRTTask(Base):
    __tablename__ = "threat_psirt_tasks"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    title: Mapped[str] = mapped_column(String(500))
    product: Mapped[str] = mapped_column(String(255), default="")
    component: Mapped[str] = mapped_column(String(255), default="")
    priority: Mapped[str] = mapped_column(String(40), default="P2 Medium")
    status: Mapped[str] = mapped_column(String(60), default="queued")
    validation_steps: Mapped[list[str]] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ThreatDetectionRequirement(Base):
    __tablename__ = "threat_detection_requirements"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    title: Mapped[str] = mapped_column(String(500))
    technique_ids: Mapped[list[str]] = mapped_column(JSONB, default=list)
    telemetry: Mapped[list[str]] = mapped_column(JSONB, default=list)
    logic: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(60), default="draft")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ThreatMarketplaceListing(Base):
    __tablename__ = "threat_marketplace_listings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    signal_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    case_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    listing_type: Mapped[str] = mapped_column(String(80), default="marketplace")
    product: Mapped[str] = mapped_column(String(255), default="")
    summary: Mapped[str] = mapped_column(Text, default="")
    sanitized_metadata: Mapped[dict] = mapped_column(JSONB, default=dict)
    tlp: Mapped[str] = mapped_column(String(20), default="TLP:AMBER")
    legal_sensitive: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ThreatSupplyChainFinding(Base):
    __tablename__ = "threat_supply_chain_findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    signal_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    case_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    package_name: Mapped[str] = mapped_column(String(255), default="")
    ecosystem: Mapped[str] = mapped_column(String(80), default="")
    affected_versions: Mapped[list[str]] = mapped_column(JSONB, default=list)
    sbom_match: Mapped[bool] = mapped_column(Boolean, default=False)
    summary: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ThreatReport(Base):
    __tablename__ = "threat_reports"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    report_type: Mapped[str] = mapped_column(String(80), index=True)
    title: Mapped[str] = mapped_column(String(500))
    markdown: Mapped[str] = mapped_column(Text, default="")
    metadata_json: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    created_by: Mapped[str] = mapped_column(String(255), default="local")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ThreatAuditLog(Base):
    __tablename__ = "threat_audit_log"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    actor: Mapped[str] = mapped_column(String(255), default="local")
    action: Mapped[str] = mapped_column(String(120), index=True)
    object_type: Mapped[str] = mapped_column(String(80), index=True)
    object_id: Mapped[str] = mapped_column(String(255), default="")
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
