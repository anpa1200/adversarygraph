import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class AnalysisSession(Base):
    """One LLM analysis job: a text paste or uploaded file."""

    __tablename__ = "analysis_sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    status: Mapped[str] = mapped_column(String(20), default="pending")
    # pending | processing | completed | failed
    input_type: Mapped[str] = mapped_column(String(10))   # text | file
    filename: Mapped[str | None] = mapped_column(String(500), nullable=True)
    llm_provider: Mapped[str] = mapped_column(String(20))  # claude | openai | gemini
    model: Mapped[str] = mapped_column(String(100), default="")
    domain: Mapped[str] = mapped_column(String(50), default="enterprise-attack")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    result: Mapped["AnalysisResult | None"] = relationship(
        back_populates="session", uselist=False
    )


class AnalysisResult(Base):
    """Structured output from an LLM analysis session."""

    __tablename__ = "analysis_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("analysis_sessions.id", ondelete="CASCADE")
    )
    # JSON array of {attack_id, name, tactic, confidence, evidence}
    extracted_techniques: Mapped[list] = mapped_column(JSONB, default=list)
    # JSON array of {group_attack_id, name, similarity, shared_count, shared_techniques}
    apt_matches: Mapped[list] = mapped_column(JSONB, default=list)
    summary: Mapped[str] = mapped_column(Text, default="")
    raw_response: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    session: Mapped["AnalysisSession"] = relationship(back_populates="result")


class UserLayer(Base):
    """A saved ATT&CK Navigator-compatible layer."""

    __tablename__ = "user_layers"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255))
    domain: Mapped[str] = mapped_column(String(50))  # enterprise-attack
    # Full ATT&CK Navigator layer JSON
    layer_data: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
