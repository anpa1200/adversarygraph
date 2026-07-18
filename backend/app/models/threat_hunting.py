from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class ThreatHuntQueryVersion(Base):
    """Append-only query revision used to make a hunt reproducible."""

    __tablename__ = "threat_hunt_query_versions"
    __table_args__ = (UniqueConstraint("hunt_id", "version", name="uq_hunt_query_version"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hunt_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_hunt_requests.id", ondelete="RESTRICT"),
        index=True,
    )
    version: Mapped[int] = mapped_column(Integer)
    language: Mapped[str] = mapped_column(String(40), default="generic")
    query_text: Mapped[str] = mapped_column(Text, default="")
    backend_assumptions: Mapped[str] = mapped_column(Text, default="")
    checksum: Mapped[str] = mapped_column(String(64), index=True)
    created_by: Mapped[str] = mapped_column(String(255), default="local")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ThreatHuntFinding(Base):
    """Evidence or a reviewed analyst decision recorded during a threat hunt."""

    __tablename__ = "threat_hunt_findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hunt_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_hunt_requests.id", ondelete="RESTRICT"),
        index=True,
    )
    query_version_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_hunt_query_versions.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    title: Mapped[str] = mapped_column(String(500))
    summary: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(20), default="informational", index=True)
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    status: Mapped[str] = mapped_column(String(40), default="new", index=True)
    verdict: Mapped[str] = mapped_column(String(40), default="inconclusive", index=True)
    evidence_type: Mapped[str] = mapped_column(String(80), default="event")
    evidence_ref: Mapped[str] = mapped_column(String(500), default="")
    event_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    observables: Mapped[list[str]] = mapped_column(JSONB, default=list)
    technique_ids: Mapped[list[str]] = mapped_column(JSONB, default=list)
    tlp: Mapped[str] = mapped_column(String(20), default="TLP:AMBER")
    analyst: Mapped[str] = mapped_column(String(255), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    archived_by: Mapped[str] = mapped_column(String(255), default="")


class ThreatHuntAIAssistance(Base):
    """Append-only, sanitized record of an AI-generated hunt suggestion.

    The record intentionally stores hashes, identifiers, and the validated
    structured suggestion. Raw source documents, prompts, provider responses,
    and provider errors must never be written to this table.
    """

    __tablename__ = "threat_hunt_ai_assistance"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hunt_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("threat_hunt_requests.id", ondelete="RESTRICT"),
        nullable=True,
        index=True,
    )
    source_session_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis_sessions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    task: Mapped[str] = mapped_column(String(40), index=True)
    stage: Mapped[str] = mapped_column(String(40), index=True)
    lifecycle_status: Mapped[str] = mapped_column(String(40), default="suggested", index=True)
    provider: Mapped[str] = mapped_column(String(40), index=True)
    model: Mapped[str] = mapped_column(String(160), default="")
    cloud_processing_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    prompt_version: Mapped[str] = mapped_column(String(80), index=True)
    effective_tlp: Mapped[str] = mapped_column(String(20), default="TLP:AMBER")
    source_refs: Mapped[list[dict]] = mapped_column(JSONB, default=list)
    input_checksum: Mapped[str] = mapped_column(String(64), index=True)
    output_checksum: Mapped[str] = mapped_column(String(64), index=True)
    structured_output: Mapped[dict] = mapped_column(JSONB, default=dict)
    warnings: Mapped[list[str]] = mapped_column(JSONB, default=list)
    created_by: Mapped[str] = mapped_column(String(255), default="local", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
