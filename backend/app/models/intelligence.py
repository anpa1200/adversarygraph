"""Canonical tags, provenance, and cross-entity intelligence relationships."""

from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class IntelligenceTag(Base):
    __tablename__ = "intelligence_tags"
    __table_args__ = (
        UniqueConstraint("namespace", "value", name="uq_intelligence_tag"),
        CheckConstraint("namespace <> '' AND value <> ''", name="ck_intelligence_tag_nonempty"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    namespace: Mapped[str] = mapped_column(String(40), index=True)
    value: Mapped[str] = mapped_column(String(500), index=True)
    canonical: Mapped[str] = mapped_column(String(550), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class IntelligenceEntityTag(Base):
    __tablename__ = "intelligence_entity_tags"
    __table_args__ = (
        UniqueConstraint("entity_type", "entity_id", "tag", name="uq_intelligence_entity_tag"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(40), index=True)
    entity_id: Mapped[str] = mapped_column(String(255), index=True)
    tag: Mapped[str] = mapped_column(
        ForeignKey("intelligence_tags.canonical", ondelete="CASCADE"), index=True
    )
    source_type: Mapped[str] = mapped_column(String(40), default="")
    source_id: Mapped[str] = mapped_column(String(500), default="")
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    evidence: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class IntelligenceRelationship(Base):
    """Source-backed directed edge between two canonical platform entities."""

    __tablename__ = "intelligence_relationships"
    __table_args__ = (
        UniqueConstraint(
            "source_type", "source_id", "relationship_type",
            "target_type", "target_id", "provenance_type", "provenance_id",
            name="uq_intelligence_relationship_provenance",
        ),
        CheckConstraint("confidence >= 0 AND confidence <= 100", name="ck_intelligence_relationship_confidence"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source_type: Mapped[str] = mapped_column(String(40), index=True)
    source_id: Mapped[str] = mapped_column(String(255), index=True)
    relationship_type: Mapped[str] = mapped_column(String(80), index=True)
    target_type: Mapped[str] = mapped_column(String(40), index=True)
    target_id: Mapped[str] = mapped_column(String(255), index=True)
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    provenance_type: Mapped[str] = mapped_column(String(40), default="", index=True)
    provenance_id: Mapped[str] = mapped_column(String(500), default="", index=True)
    evidence: Mapped[str] = mapped_column(Text, default="")
    attributes: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
