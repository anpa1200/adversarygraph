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


class ThreatCompanySpace(Base):
    __tablename__ = "threat_company_spaces"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), index=True)
    slug: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    owner: Mapped[str] = mapped_column(String(255), default="")
    sector: Mapped[str] = mapped_column(String(120), default="")
    region: Mapped[str] = mapped_column(String(120), default="")
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list)
    settings: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_by: Mapped[str] = mapped_column(String(255), default="local")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ThreatSpaceAsset(Base):
    __tablename__ = "threat_space_assets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    space_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    asset_id: Mapped[str] = mapped_column(String(255), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    asset_type: Mapped[str] = mapped_column(String(80), default="asset", index=True)
    environment: Mapped[str] = mapped_column(String(80), default="unknown", index=True)
    owner: Mapped[str] = mapped_column(String(255), default="")
    criticality: Mapped[str] = mapped_column(String(40), default="medium")
    exposure: Mapped[str] = mapped_column(String(80), default="unknown")
    products: Mapped[list[str]] = mapped_column(JSONB, default=list)
    components: Mapped[list[str]] = mapped_column(JSONB, default=list)
    technologies: Mapped[list[str]] = mapped_column(JSONB, default=list)
    ip_addresses: Mapped[list[str]] = mapped_column(JSONB, default=list)
    domains: Mapped[list[str]] = mapped_column(JSONB, default=list)
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list)
    metadata_json: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ThreatAssetScan(Base):
    """Auditable, inventory-bound passive and active asset assessment."""

    __tablename__ = "threat_asset_scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    space_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    target: Mapped[str] = mapped_column(String(2048))
    target_host: Mapped[str] = mapped_column(String(255), index=True)
    target_type: Mapped[str] = mapped_column(String(40), index=True)
    status: Mapped[str] = mapped_column(String(40), default="running", index=True)
    scan_profile: Mapped[str] = mapped_column(String(80), default="safe-service-discovery")
    requested_providers: Mapped[list[str]] = mapped_column(JSONB, default=list)
    passive_results: Mapped[list[dict]] = mapped_column(JSONB, default=list)
    nmap_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    nmap_result: Mapped[dict] = mapped_column(JSONB, default=dict)
    web_probe_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    web_probe_result: Mapped[dict] = mapped_column(JSONB, default=dict)
    inventory_update: Mapped[dict] = mapped_column(JSONB, default=dict)
    findings: Mapped[list[dict]] = mapped_column(JSONB, default=list)
    ai_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    ai_provider: Mapped[str] = mapped_column(String(40), default="")
    ai_model: Mapped[str] = mapped_column(String(160), default="")
    ai_analysis: Mapped[dict] = mapped_column(JSONB, default=dict)
    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    cloud_processing_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    warnings: Mapped[list[str]] = mapped_column(JSONB, default=list)
    error: Mapped[str] = mapped_column(Text, default="")
    requested_by: Mapped[str] = mapped_column(String(255), default="local")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ThreatInventoryAsset(Base):
    __tablename__ = "threat_inv_assets"
    __table_args__ = (UniqueConstraint("space_id", "asset_id", name="uq_threat_inv_asset_space_asset_id"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    space_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    legacy_asset_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    asset_id: Mapped[str] = mapped_column(String(255), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    asset_type: Mapped[str] = mapped_column(String(80), default="asset", index=True)
    environment: Mapped[str] = mapped_column(String(80), default="unknown", index=True)
    owner: Mapped[str] = mapped_column(String(255), default="")
    criticality: Mapped[str] = mapped_column(String(40), default="medium", index=True)
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list)
    metadata_json: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ThreatInventoryProduct(Base):
    __tablename__ = "threat_inv_products"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    space_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    asset_ref_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    vendor: Mapped[str] = mapped_column(String(255), default="", index=True)
    version: Mapped[str] = mapped_column(String(120), default="")
    cpe: Mapped[str] = mapped_column(String(500), default="", index=True)
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list)
    metadata_json: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ThreatInventoryComponent(Base):
    __tablename__ = "threat_inv_components"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    space_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    product_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    component_type: Mapped[str] = mapped_column(String(120), default="")
    version: Mapped[str] = mapped_column(String(120), default="")
    cpe: Mapped[str] = mapped_column(String(500), default="", index=True)
    purl: Mapped[str] = mapped_column(String(500), default="", index=True)
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list)
    metadata_json: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ThreatInventoryDependency(Base):
    __tablename__ = "threat_inv_dependencies"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    space_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    component_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    package_name: Mapped[str] = mapped_column(String(255), index=True)
    package_version: Mapped[str] = mapped_column(String(120), default="")
    package_type: Mapped[str] = mapped_column(String(80), default="")
    purl: Mapped[str] = mapped_column(String(500), default="", index=True)
    cpe: Mapped[str] = mapped_column(String(500), default="", index=True)
    supplier: Mapped[str] = mapped_column(String(255), default="", index=True)
    relationship: Mapped[str] = mapped_column(String(80), default="unknown")
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list)
    metadata_json: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ThreatInventoryExposure(Base):
    __tablename__ = "threat_inv_exposures"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    space_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    target_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    target_type: Mapped[str] = mapped_column(String(80), default="asset", index=True)
    kind: Mapped[str] = mapped_column(String(80), default="unknown", index=True)
    ip: Mapped[str] = mapped_column(String(120), default="", index=True)
    domain: Mapped[str] = mapped_column(String(255), default="", index=True)
    port: Mapped[str] = mapped_column(String(40), default="")
    protocol: Mapped[str] = mapped_column(String(40), default="")
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list)
    metadata_json: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ThreatInventoryEdge(Base):
    __tablename__ = "threat_inv_edges"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    space_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    src_id: Mapped[str] = mapped_column(String(255), index=True)
    src_type: Mapped[str] = mapped_column(String(80), index=True)
    dst_id: Mapped[str] = mapped_column(String(255), index=True)
    dst_type: Mapped[str] = mapped_column(String(80), index=True)
    relationship: Mapped[str] = mapped_column(String(120), default="related-to", index=True)
    metadata_json: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ThreatSpaceDashboard(Base):
    __tablename__ = "threat_space_dashboards"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    space_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    name: Mapped[str] = mapped_column(String(255), default="Executive risk dashboard")
    dashboard_type: Mapped[str] = mapped_column(String(80), default="risk")
    layout: Mapped[dict] = mapped_column(JSONB, default=dict)
    widgets: Mapped[list[dict]] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ThreatSpaceMonitor(Base):
    __tablename__ = "threat_space_monitors"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    space_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    monitor_type: Mapped[str] = mapped_column(String(80), default="asset-relevance")
    cadence: Mapped[str] = mapped_column(String(80), default="daily")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    query: Mapped[dict] = mapped_column(JSONB, default=dict)
    alert_threshold: Mapped[int] = mapped_column(Integer, default=70)
    last_status: Mapped[str] = mapped_column(String(80), default="not-run")
    last_result: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ThreatDetectionRule(Base):
    __tablename__ = "threat_detection_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    space_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    query: Mapped[str] = mapped_column(Text, default="status:new")
    schedule: Mapped[str] = mapped_column(String(80), default="daily")
    severity: Mapped[str] = mapped_column(String(40), default="medium")
    threshold: Mapped[int] = mapped_column(Integer, default=70)
    suppression: Mapped[dict] = mapped_column(JSONB, default=dict)
    last_run: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str] = mapped_column(String(80), default="not-run")
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ThreatSpaceAIStep(Base):
    __tablename__ = "threat_space_ai_steps"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    space_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    step: Mapped[str] = mapped_column(String(120), index=True)
    title: Mapped[str] = mapped_column(String(255), default="")
    guidance: Mapped[str] = mapped_column(Text, default="")
    checklist: Mapped[list[str]] = mapped_column(JSONB, default=list)
    created_by: Mapped[str] = mapped_column(String(255), default="local")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


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


class ThreatSignalEntity(Base):
    __tablename__ = "threat_signal_entities"
    __table_args__ = (UniqueConstraint("signal_id", "entity_type", "value", name="uq_threat_signal_entity"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    signal_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    entity_type: Mapped[str] = mapped_column(String(80), index=True)
    value: Mapped[str] = mapped_column(String(500), index=True)
    confidence: Mapped[int] = mapped_column(Integer, default=70)
    source: Mapped[str] = mapped_column(String(120), default="signal")
    metadata_json: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ThreatAlert(Base):
    __tablename__ = "threat_alerts"
    __table_args__ = (UniqueConstraint("space_id", "dedup_key", name="uq_threat_alert_space_dedup"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    space_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), index=True)
    rule_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    signal_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    case_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(500), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(60), default="new", index=True)
    priority: Mapped[str] = mapped_column(String(40), default="P4 Low/Archive", index=True)
    severity: Mapped[str] = mapped_column(String(40), default="unknown", index=True)
    score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    score_rationale: Mapped[dict] = mapped_column(JSONB, default=dict)
    dedup_key: Mapped[str] = mapped_column(String(128), index=True)
    match_type: Mapped[str] = mapped_column(String(80), default="contextual", index=True)
    matches: Mapped[list[dict]] = mapped_column(JSONB, default=list)
    assignee: Mapped[str] = mapped_column(String(255), default="")
    suppression: Mapped[dict] = mapped_column(JSONB, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
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
    case_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(500))
    hypothesis: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    scope: Mapped[str] = mapped_column(Text, default="")
    priority: Mapped[str] = mapped_column(String(40), default="P3 Monitor", index=True)
    owner: Mapped[str] = mapped_column(String(255), default="", index=True)
    source_type: Mapped[str] = mapped_column(String(80), default="manual", index=True)
    source_ref: Mapped[str] = mapped_column(String(500), default="")
    telemetry: Mapped[list[str]] = mapped_column(JSONB, default=list)
    technique_ids: Mapped[list[str]] = mapped_column(JSONB, default=list)
    tactics: Mapped[list[str]] = mapped_column(JSONB, default=list)
    required_fields: Mapped[list[str]] = mapped_column(JSONB, default=list)
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list)
    query_language: Mapped[str] = mapped_column(String(40), default="generic")
    query_text: Mapped[str] = mapped_column(Text, default="")
    time_range_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    time_range_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expected_evidence: Mapped[str] = mapped_column(Text, default="")
    false_positive_notes: Mapped[str] = mapped_column(Text, default="")
    assumptions: Mapped[str] = mapped_column(Text, default="")
    result_summary: Mapped[str] = mapped_column(Text, default="")
    disposition: Mapped[str] = mapped_column(String(60), default="undetermined", index=True)
    tlp: Mapped[str] = mapped_column(String(20), default="TLP:AMBER")
    status: Mapped[str] = mapped_column(String(60), default="queued", index=True)
    created_by: Mapped[str] = mapped_column(String(255), default="local")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)

    @property
    def telemetry_sources(self) -> list[str]:
        """Expose the legacy telemetry column through the canonical hunt name."""
        return self.telemetry or []

    @telemetry_sources.setter
    def telemetry_sources(self, values: list[str]) -> None:
        self.telemetry = values


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
