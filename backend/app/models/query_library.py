import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class HuntQueryLibraryItem(Base):
    """A normalized, source-backed hunt query or detection rule."""

    __tablename__ = "hunt_query_library"
    __table_args__ = (
        UniqueConstraint("stable_key", name="uq_hunt_query_library_stable_key"),
        Index("ix_hunt_query_library_techniques_gin", "technique_ids", postgresql_using="gin"),
        Index("ix_hunt_query_library_tags_gin", "tags", postgresql_using="gin"),
        Index("ix_hunt_query_library_language_quality", "language", "quality_score"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    stable_key: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str] = mapped_column(String(500), index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    language: Mapped[str] = mapped_column(String(40), index=True)
    query_text: Mapped[str] = mapped_column(Text)
    technique_ids: Mapped[list] = mapped_column(JSONB, default=list)
    tactics: Mapped[list] = mapped_column(JSONB, default=list)
    tags: Mapped[list] = mapped_column(JSONB, default=list)
    data_sources: Mapped[list] = mapped_column(JSONB, default=list)
    platforms: Mapped[list] = mapped_column(JSONB, default=list)
    ioc_types: Mapped[list] = mapped_column(JSONB, default=list)
    source_name: Mapped[str] = mapped_column(String(255), index=True, default="AdversaryGraph")
    source_url: Mapped[str] = mapped_column(String(1000), default="")
    source_license: Mapped[str] = mapped_column(String(120), default="")
    source_rule_id: Mapped[str] = mapped_column(String(255), default="")
    quality_score: Mapped[int] = mapped_column(Integer, default=70)
    validation: Mapped[dict] = mapped_column(JSONB, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    community: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
