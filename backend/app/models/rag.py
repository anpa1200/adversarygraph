"""Unified, provenance-preserving retrieval corpus and AI suggestion records."""

from __future__ import annotations

import uuid
from datetime import datetime

from pgvector.sqlalchemy import VECTOR
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Computed,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, TSVECTOR, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.config import settings
from app.core.database import Base


class RAGDocument(Base):
    """One canonical source record represented in the retrieval corpus."""

    __tablename__ = "rag_documents"
    __table_args__ = (
        UniqueConstraint(
            "source_type", "source_id", "source_version", name="uq_rag_document_source"
        ),
        Index("ix_rag_documents_source", "source_type", "source_id"),
        Index("ix_rag_documents_tlp", "tlp"),
        Index("ix_rag_documents_space", "space_id"),
        Index("ix_rag_documents_policy", "sanitized", "legal_sensitive"),
        Index("ix_rag_documents_active_updated", "is_active", "source_updated_at"),
        CheckConstraint(
            "tlp IN ('TLP:CLEAR', 'TLP:GREEN', 'TLP:AMBER', 'TLP:AMBER+STRICT', 'TLP:RED')",
            name="ck_rag_documents_tlp",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    source_type: Mapped[str] = mapped_column(String(40))
    source_id: Mapped[str] = mapped_column(String(255))
    source_version: Mapped[str] = mapped_column(String(120), default="current")
    logical_key: Mapped[str] = mapped_column(String(500), index=True)
    title: Mapped[str] = mapped_column(String(700))
    canonical_route: Mapped[str] = mapped_column(String(1_000), default="")
    domain: Mapped[str] = mapped_column(String(80), default="")
    tlp: Mapped[str] = mapped_column(String(24), default="TLP:CLEAR")
    # Nullable until the wider platform has tenant ownership on every source.
    # Search must never infer a caller's space from prompt text.
    space_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    legal_sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    # Only allowlisted, reviewed fields are indexed. False is a hard retrieval
    # exclusion and is never overridden by similarity score.
    sanitized: Mapped[bool] = mapped_column(Boolean, default=True)
    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    source_updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    indexed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    chunks: Mapped[list["RAGChunk"]] = relationship(
        back_populates="document", cascade="all, delete-orphan"
    )


class RAGChunk(Base):
    """A bounded source excerpt with lexical and optional vector indexes."""

    __tablename__ = "rag_chunks"
    __table_args__ = (
        UniqueConstraint("document_id", "ordinal", name="uq_rag_chunk_ordinal"),
        Index("ix_rag_chunks_search_vector", "search_vector", postgresql_using="gin"),
        Index(
            "ix_rag_chunks_embedding_hnsw",
            "embedding",
            postgresql_using="hnsw",
            postgresql_ops={"embedding": "vector_cosine_ops"},
            postgresql_where=text("embedding IS NOT NULL"),
        ),
        Index("ix_rag_chunks_embedding_status", "embedding_status"),
        CheckConstraint(
            "embedding_status IN ('pending', 'not_requested', 'complete', 'failed', 'blocked')",
            name="ck_rag_chunks_embedding_status",
        ),
        CheckConstraint(
            "embedding_dimensions IS NULL OR embedding_dimensions > 0",
            name="ck_rag_chunks_embedding_dimensions",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    document_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("rag_documents.id", ondelete="CASCADE"), index=True
    )
    ordinal: Mapped[int] = mapped_column(Integer)
    content: Mapped[str] = mapped_column(Text)
    content_hash: Mapped[str] = mapped_column(String(64), index=True)
    token_count: Mapped[int] = mapped_column(Integer, default=0)
    search_vector: Mapped[object] = mapped_column(
        TSVECTOR,
        Computed("to_tsvector('simple', coalesce(content, ''))", persisted=True),
    )
    embedding: Mapped[list[float] | None] = mapped_column(
        VECTOR(settings.rag_embedding_dimensions), nullable=True
    )
    embedding_provider: Mapped[str] = mapped_column(String(40), default="")
    embedding_model: Mapped[str] = mapped_column(String(160), default="")
    embedding_dimensions: Mapped[int | None] = mapped_column(Integer, nullable=True)
    embedding_status: Mapped[str] = mapped_column(String(20), default="pending")
    embedding_error: Mapped[str] = mapped_column(String(200), default="")
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    document: Mapped[RAGDocument] = relationship(back_populates="chunks")


class RAGIndexRun(Base):
    """Persisted status for a queued or completed corpus reconciliation."""

    __tablename__ = "rag_index_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued', 'running', 'completed', 'degraded', 'failed', 'skipped')",
            name="ck_rag_index_runs_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    status: Mapped[str] = mapped_column(String(20), default="queued", index=True)
    source_types: Mapped[list] = mapped_column(JSONB, default=list)
    include_embeddings: Mapped[bool] = mapped_column(Boolean, default=True)
    documents_seen: Mapped[int] = mapped_column(Integer, default=0)
    documents_created: Mapped[int] = mapped_column(Integer, default=0)
    documents_updated: Mapped[int] = mapped_column(Integer, default=0)
    documents_removed: Mapped[int] = mapped_column(Integer, default=0)
    chunks_created: Mapped[int] = mapped_column(Integer, default=0)
    embeddings_created: Mapped[int] = mapped_column(Integer, default=0)
    embeddings_failed: Mapped[int] = mapped_column(Integer, default=0)
    failure_summary: Mapped[str] = mapped_column(String(500), default="")
    created_by: Mapped[str] = mapped_column(String(255), default="system")
    worker_task_id: Mapped[str] = mapped_column(String(100), default="")
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class RAGAssistance(Base):
    """Append-only, sanitized retrieval/generation provenance."""

    __tablename__ = "rag_assistance"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    provider: Mapped[str] = mapped_column(String(40))
    model: Mapped[str] = mapped_column(String(160))
    cloud_processing_acknowledged: Mapped[bool] = mapped_column(Boolean, default=False)
    retrieval_mode: Mapped[str] = mapped_column(String(40))
    effective_tlp: Mapped[str] = mapped_column(String(24))
    prompt_version: Mapped[str] = mapped_column(String(80))
    query_checksum: Mapped[str] = mapped_column(String(64), index=True)
    output_checksum: Mapped[str] = mapped_column(String(64))
    filters: Mapped[dict] = mapped_column(JSONB, default=dict)
    source_refs: Mapped[list] = mapped_column(JSONB, default=list)
    structured_output: Mapped[dict] = mapped_column(JSONB, default=dict)
    warnings: Mapped[list] = mapped_column(JSONB, default=list)
    created_by: Mapped[str] = mapped_column(String(255), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class RAGNavigatorProposal(Base):
    """A non-mutating, expiring Navigator action awaiting human confirmation."""

    __tablename__ = "rag_navigator_proposals"
    __table_args__ = (
        CheckConstraint(
            "status IN ('suggested', 'confirmed', 'expired')",
            name="ck_rag_navigator_proposals_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    assistance_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("rag_assistance.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(20), default="suggested", index=True)
    name: Mapped[str] = mapped_column(String(255))
    domain: Mapped[str] = mapped_column(String(80))
    attack_version: Mapped[str] = mapped_column(String(40), default="")
    technique_ids: Mapped[list] = mapped_column(JSONB, default=list)
    rationale: Mapped[str] = mapped_column(Text, default="")
    source_refs: Mapped[list] = mapped_column(JSONB, default=list)
    proposal_checksum: Mapped[str] = mapped_column(String(64))
    created_by: Mapped[str] = mapped_column(String(255), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    confirmed_by: Mapped[str] = mapped_column(String(255), default="")
    confirmation_mode: Mapped[str] = mapped_column(String(20), default="")
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
