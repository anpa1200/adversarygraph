"""Persisted runtime observations imported from governed telemetry sources."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class RuntimeTopologySnapshot(Base):
    __tablename__ = "runtime_topology_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source: Mapped[str] = mapped_column(String(80), default="apache_skywalking", index=True)
    scope: Mapped[str] = mapped_column(String(500), default="global")
    query: Mapped[str] = mapped_column(String(500), default="")
    window_minutes: Mapped[int] = mapped_column(Integer, default=60)
    observed_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    observed_to: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    node_count: Mapped[int] = mapped_column(Integer, default=0)
    edge_count: Mapped[int] = mapped_column(Integer, default=0)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(40), default="completed", index=True)
    synced_by: Mapped[str] = mapped_column(String(255), default="system")
    provenance: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)


class RuntimeService(Base):
    __tablename__ = "runtime_services"
    __table_args__ = (
        UniqueConstraint("source", "external_id", name="uq_runtime_service_source_external"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source: Mapped[str] = mapped_column(String(80), default="apache_skywalking", index=True)
    external_id: Mapped[str] = mapped_column(String(500), index=True)
    name: Mapped[str] = mapped_column(String(500), index=True)
    technology: Mapped[str] = mapped_column(String(160), default="unknown", index=True)
    layers: Mapped[list] = mapped_column(JSONB, default=list)
    observed: Mapped[bool] = mapped_column(Boolean, default=True)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    observation_count: Mapped[int] = mapped_column(Integer, default=1)
    tlp: Mapped[str] = mapped_column(String(24), default="TLP:AMBER+STRICT", index=True)
    tags: Mapped[list] = mapped_column(JSONB, default=list)
    metadata_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class RuntimeCall(Base):
    __tablename__ = "runtime_calls"
    __table_args__ = (
        UniqueConstraint("source", "external_id", name="uq_runtime_call_source_external"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source: Mapped[str] = mapped_column(String(80), default="apache_skywalking", index=True)
    external_id: Mapped[str] = mapped_column(String(500), index=True)
    source_service_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("runtime_services.id", ondelete="CASCADE"), index=True
    )
    target_service_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("runtime_services.id", ondelete="CASCADE"), index=True
    )
    source_components: Mapped[list] = mapped_column(JSONB, default=list)
    target_components: Mapped[list] = mapped_column(JSONB, default=list)
    detect_points: Mapped[list] = mapped_column(JSONB, default=list)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    observation_count: Mapped[int] = mapped_column(Integer, default=1)
    metadata_json: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class RuntimeAssetLink(Base):
    __tablename__ = "runtime_asset_links"
    __table_args__ = (
        UniqueConstraint("runtime_service_id", "asset_id", name="uq_runtime_asset_link"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    runtime_service_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("runtime_services.id", ondelete="CASCADE"), index=True
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("asset_registry_items.id", ondelete="CASCADE"), index=True
    )
    match_basis: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    review_status: Mapped[str] = mapped_column(String(40), default="candidate", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
