from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class PcapAnalysis(Base):
    """Durable authority record for one deterministic PCAP result."""

    __tablename__ = "pcap_analyses"
    __table_args__ = (
        UniqueConstraint("analysis_key", name="uq_pcap_analysis_key"),
        UniqueConstraint("session_id", name="uq_pcap_analysis_session"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analysis_sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="processing", index=True)
    filename: Mapped[str] = mapped_column(String(500), nullable=False, default="capture")
    source_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    storage_path: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    analysis_key: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(80), nullable=False, default="pcap-analysis-v1")
    semantic_sha256: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    analyzer_manifest: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    result: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    report_text: Mapped[str] = mapped_column(Text, nullable=False, default="")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
