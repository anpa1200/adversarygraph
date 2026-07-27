import uuid
from datetime import datetime

from sqlalchemy import DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(30), default="active")
    domain: Mapped[str] = mapped_column(String(50), default="enterprise-attack")
    actor_ids: Mapped[list] = mapped_column(JSONB, default=list)
    technique_ids: Mapped[list] = mapped_column(JSONB, default=list)
    report_ids: Mapped[list] = mapped_column(JSONB, default=list)
    evidence_nodes: Mapped[list] = mapped_column(JSONB, default=list)
    evidence_edges: Mapped[list] = mapped_column(JSONB, default=list)
    timeline: Mapped[list] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ReportIntake(Base):
    __tablename__ = "report_intake"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(500))
    url: Mapped[str] = mapped_column(String(1000), default="")
    publisher: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(30), default="pending")
    summary: Mapped[str] = mapped_column(Text, default="")
    source_reliability: Mapped[str] = mapped_column(String(30), default="unknown")
    actor_ids: Mapped[list] = mapped_column(JSONB, default=list)
    technique_ids: Mapped[list] = mapped_column(JSONB, default=list)
    indicators: Mapped[list] = mapped_column(JSONB, default=list)
    tags: Mapped[list] = mapped_column(JSONB, default=list)
    provenance: Mapped[dict] = mapped_column(JSONB, default=dict)
    analyst_notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class DetectionCandidate(Base):
    __tablename__ = "detection_candidates"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(500))
    technique_id: Mapped[str] = mapped_column(String(30), index=True)
    status: Mapped[str] = mapped_column(String(30), default="idea")
    owner: Mapped[str] = mapped_column(String(255), default="")
    telemetry: Mapped[list] = mapped_column(JSONB, default=list)
    query_language: Mapped[str] = mapped_column(String(50), default="")
    query: Mapped[str] = mapped_column(Text, default="")
    validation_notes: Mapped[str] = mapped_column(Text, default="")
    source_refs: Mapped[list] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class TrackedActor(Base):
    __tablename__ = "tracked_actors"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    actor_id: Mapped[str] = mapped_column(String(30), unique=True, index=True)
    actor_name: Mapped[str] = mapped_column(String(255), default="")
    last_snapshot: Mapped[dict] = mapped_column(JSONB, default=dict)
    change_log: Mapped[list] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
