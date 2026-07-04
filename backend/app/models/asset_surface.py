import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class AssetSurfaceCase(Base):
    __tablename__ = "asset_surface_cases"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), index=True)
    filename: Mapped[str] = mapped_column(String(500), default="")
    provider: Mapped[str] = mapped_column(String(30), default="baseline")
    model: Mapped[str] = mapped_column(String(100), default="")
    use_ai: Mapped[bool] = mapped_column(Boolean, default=False)
    asset_count: Mapped[int] = mapped_column(Integer, default=0)
    technique_ids: Mapped[list] = mapped_column(JSONB, default=list)
    high_or_critical_count: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[str] = mapped_column(Text, default="")
    result: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class AssetRegistryItem(Base):
    """Normalized asset/product/supply-chain inventory item used for retrohunt matching."""

    __tablename__ = "asset_registry_items"
    __table_args__ = (UniqueConstraint("fingerprint", name="uq_asset_registry_fingerprint"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    fingerprint: Mapped[str] = mapped_column(String(500), index=True)
    inventory_asset_id: Mapped[str] = mapped_column(String(255), index=True)
    name: Mapped[str] = mapped_column(String(500), index=True)
    asset_type: Mapped[str] = mapped_column(String(120), default="unknown", index=True)
    environment: Mapped[str] = mapped_column(String(120), default="unknown", index=True)
    owner: Mapped[str] = mapped_column(String(255), default="")
    exposure: Mapped[str] = mapped_column(String(80), default="unknown", index=True)
    criticality: Mapped[str] = mapped_column(String(80), default="medium", index=True)
    ip_addresses: Mapped[list] = mapped_column(JSONB, default=list)
    domains: Mapped[list] = mapped_column(JSONB, default=list)
    ports: Mapped[list] = mapped_column(JSONB, default=list)
    technologies: Mapped[list] = mapped_column(JSONB, default=list)
    products: Mapped[list] = mapped_column(JSONB, default=list)
    suppliers: Mapped[list] = mapped_column(JSONB, default=list)
    dependencies: Mapped[list] = mapped_column(JSONB, default=list)
    technique_ids: Mapped[list] = mapped_column(JSONB, default=list)
    tags: Mapped[list] = mapped_column(JSONB, default=list)
    labels: Mapped[dict] = mapped_column(JSONB, default=dict)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    risk_level: Mapped[str] = mapped_column(String(40), default="low", index=True)
    source_case_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("asset_surface_cases.id", ondelete="SET NULL"), nullable=True, index=True)
    source_inventory_name: Mapped[str] = mapped_column(String(255), default="")
    raw: Mapped[dict] = mapped_column(JSONB, default=dict)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class AssetIntelMatch(Base):
    """Relevance match between an owned asset and CVE, actor, report, TTP, or IOC intelligence."""

    __tablename__ = "asset_intel_matches"
    __table_args__ = (UniqueConstraint("asset_id", "source_type", "source_id", "relationship", name="uq_asset_intel_match"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("asset_registry_items.id", ondelete="CASCADE"), index=True)
    source_type: Mapped[str] = mapped_column(String(80), index=True)
    source_id: Mapped[str] = mapped_column(String(255), index=True)
    title: Mapped[str] = mapped_column(String(500), default="")
    relationship: Mapped[str] = mapped_column(String(120), default="relevant-to-asset", index=True)
    relevance_score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    severity: Mapped[str] = mapped_column(String(60), default="")
    route: Mapped[str] = mapped_column(String(500), default="")
    reason: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[list] = mapped_column(JSONB, default=list)
    tags: Mapped[list] = mapped_column(JSONB, default=list)
    status: Mapped[str] = mapped_column(String(60), default="new", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
