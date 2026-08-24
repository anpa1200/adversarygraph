"""Persistence model for report-level intelligence review and promotion.

The review tables deliberately separate advisory machine output from analyst
decisions.  A machine (including an AI provider) can populate candidates and a
preflight verdict, but only an authenticated analyst decision can make a gate
or claim eligible for promotion.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


REVIEW_STATES = (
    "draft",
    "in_review",
    "changes_requested",
    "approved",
    "promoted",
    "stale",
    "rejected",
    "revoked",
)
GATE_KEYS = (
    "source_provenance",
    "publication_date",
    "procedure_relevance",
    "procedure_level_claim",
    "actor_identification",
)
MACHINE_VERDICTS = ("not_run", "pass", "fail", "warning")
ANALYST_VERDICTS = (
    "pending",
    "pass",
    "fail",
    "needs_information",
    "not_applicable",
)
CLAIM_TYPES = (
    "procedure",
    "actor",
    "publication_date",
    "indicator",
    "vulnerability",
)
CLAIM_STATUSES = ("suggested", "accepted", "rejected", "needs_evidence")


def _quoted(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{value}'" for value in values)


class ReportReview(Base):
    """A mutable review revision bound to immutable source fingerprints.

    ``revision`` changes when the reviewed source/analysis changes or a
    terminal review is reopened. ``version`` changes on every mutation and is
    the optimistic-concurrency token supplied by clients.
    """

    __tablename__ = "report_reviews"
    __table_args__ = (
        UniqueConstraint("session_id", "revision", name="uq_report_review_session_revision"),
        CheckConstraint(f"state IN ({_quoted(REVIEW_STATES)})", name="ck_report_review_state"),
        CheckConstraint("revision >= 1", name="ck_report_review_revision"),
        CheckConstraint("version >= 1", name="ck_report_review_version"),
        CheckConstraint("source_char_count >= 0", name="ck_report_review_source_chars"),
        CheckConstraint("analyzed_char_count >= 0", name="ck_report_review_analyzed_chars"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        # Draft review history belongs to its analysis session.  A promoted
        # review remains deletion-protected through ReportPromotion's
        # RESTRICT references below.
        ForeignKey("analysis_sessions.id", ondelete="CASCADE"),
        index=True,
    )
    revision: Mapped[int] = mapped_column(Integer)
    version: Mapped[int] = mapped_column(Integer, default=1)
    policy_version: Mapped[str] = mapped_column(String(80), index=True)
    profile: Mapped[str] = mapped_column(String(40), default="external_cti")
    state: Mapped[str] = mapped_column(String(40), default="draft", index=True)

    source_checksum: Mapped[str] = mapped_column(String(64), index=True)
    analysis_checksum: Mapped[str] = mapped_column(String(64), index=True)
    source_char_count: Mapped[int] = mapped_column(Integer, default=0)
    analyzed_char_count: Mapped[int] = mapped_column(Integer, default=0)
    coverage_complete: Mapped[bool] = mapped_column(Boolean, default=False)
    coverage_exception_reason: Mapped[str] = mapped_column(Text, default="")
    coverage_exception_by: Mapped[str] = mapped_column(String(255), default="")
    coverage_exception_by_id: Mapped[str] = mapped_column(String(80), default="")
    coverage_exception_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    created_by: Mapped[str] = mapped_column(String(255))
    created_by_id: Mapped[str] = mapped_column(String(80), default="")
    submitted_by: Mapped[str] = mapped_column(String(255), default="")
    submitted_by_id: Mapped[str] = mapped_column(String(80), default="")
    submitted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    approved_by: Mapped[str] = mapped_column(String(255), default="")
    approved_by_id: Mapped[str] = mapped_column(String(80), default="")
    approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    promoted_by: Mapped[str] = mapped_column(String(255), default="")
    promoted_by_id: Mapped[str] = mapped_column(String(80), default="")
    promoted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_by: Mapped[str] = mapped_column(String(255), default="")
    revoked_by_id: Mapped[str] = mapped_column(String(80), default="")
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ReportReviewGate(Base):
    """One of the five required report review gates."""

    __tablename__ = "report_review_gates"
    __table_args__ = (
        UniqueConstraint("review_id", "gate_key", name="uq_report_review_gate_key"),
        UniqueConstraint("review_id", "ordinal", name="uq_report_review_gate_ordinal"),
        CheckConstraint(f"gate_key IN ({_quoted(GATE_KEYS)})", name="ck_report_review_gate_key"),
        CheckConstraint(
            f"machine_verdict IN ({_quoted(MACHINE_VERDICTS)})",
            name="ck_report_review_machine_verdict",
        ),
        CheckConstraint(
            f"analyst_verdict IN ({_quoted(ANALYST_VERDICTS)})",
            name="ck_report_review_analyst_verdict",
        ),
        CheckConstraint("ordinal BETWEEN 1 AND 5", name="ck_report_review_gate_ordinal"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    review_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("report_reviews.id", ondelete="CASCADE"),
        index=True,
    )
    gate_key: Mapped[str] = mapped_column(String(50))
    ordinal: Mapped[int] = mapped_column(Integer)
    required: Mapped[bool] = mapped_column(Boolean, default=True)

    # Machine findings are advisory. They are never copied into the analyst
    # decision columns and are never sufficient for readiness.
    machine_verdict: Mapped[str] = mapped_column(String(30), default="not_run")
    machine_details: Mapped[dict] = mapped_column(JSONB, default=dict)
    machine_evidence_refs: Mapped[list] = mapped_column(JSONB, default=list)
    machine_evaluator: Mapped[str] = mapped_column(String(100), default="")
    machine_evaluated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    analyst_verdict: Mapped[str] = mapped_column(String(30), default="pending")
    reason_code: Mapped[str] = mapped_column(String(80), default="")
    rationale: Mapped[str] = mapped_column(Text, default="")
    evidence_refs: Mapped[list] = mapped_column(JSONB, default=list)
    reviewed_by: Mapped[str] = mapped_column(String(255), default="")
    reviewed_by_id: Mapped[str] = mapped_column(String(80), default="")
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ReportReviewClaim(Base):
    """A source-bound intelligence candidate reviewed independently of gates."""

    __tablename__ = "report_review_claims"
    __table_args__ = (
        UniqueConstraint("review_id", "claim_key", name="uq_report_review_claim_key"),
        CheckConstraint(f"claim_type IN ({_quoted(CLAIM_TYPES)})", name="ck_report_review_claim_type"),
        CheckConstraint(f"status IN ({_quoted(CLAIM_STATUSES)})", name="ck_report_review_claim_status"),
        CheckConstraint(
            "evidence_start IS NULL OR evidence_start >= 0",
            name="ck_report_review_claim_evidence_start",
        ),
        CheckConstraint(
            "evidence_end IS NULL OR evidence_end > evidence_start",
            name="ck_report_review_claim_evidence_end",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    review_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("report_reviews.id", ondelete="CASCADE"),
        index=True,
    )
    claim_key: Mapped[str] = mapped_column(String(64))
    claim_type: Mapped[str] = mapped_column(String(40), index=True)
    subject: Mapped[str] = mapped_column(String(500), default="")
    predicate: Mapped[str] = mapped_column(String(255), default="")
    object: Mapped[str] = mapped_column(Text, default="")
    statement: Mapped[str] = mapped_column(Text, default="")
    attack_id: Mapped[str] = mapped_column(String(30), default="", index=True)
    actor_id: Mapped[str] = mapped_column(String(120), default="", index=True)
    evidence_text: Mapped[str] = mapped_column(Text, default="")
    evidence_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    evidence_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
    extraction_method: Mapped[str] = mapped_column(String(40), default="deterministic")
    status: Mapped[str] = mapped_column(String(30), default="suggested", index=True)
    reason_code: Mapped[str] = mapped_column(String(80), default="")
    rationale: Mapped[str] = mapped_column(Text, default="")
    evidence_refs: Mapped[list] = mapped_column(JSONB, default=list)
    claim_metadata: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    reviewed_by: Mapped[str] = mapped_column(String(255), default="")
    reviewed_by_id: Mapped[str] = mapped_column(String(80), default="")
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ReportPromotion(Base):
    """Append-only accepted-claim manifest.

    Revocation is stored in ``ReportPromotionRevocation`` so this row never
    needs to be edited after insertion.
    """

    __tablename__ = "report_promotions"
    __table_args__ = (
        UniqueConstraint("review_id", name="uq_report_promotion_review"),
        UniqueConstraint("idempotency_key", name="uq_report_promotion_idempotency"),
        UniqueConstraint("manifest_checksum", name="uq_report_promotion_manifest_checksum"),
        CheckConstraint("review_revision >= 1", name="ck_report_promotion_revision"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    review_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("report_reviews.id", ondelete="RESTRICT"),
        index=True,
    )
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis_sessions.id", ondelete="RESTRICT"),
        index=True,
    )
    review_revision: Mapped[int] = mapped_column(Integer)
    policy_version: Mapped[str] = mapped_column(String(80), index=True)
    source_checksum: Mapped[str] = mapped_column(String(64), index=True)
    analysis_checksum: Mapped[str] = mapped_column(String(64), index=True)
    targets: Mapped[list] = mapped_column(JSONB, default=list)
    manifest: Mapped[dict] = mapped_column(JSONB)
    manifest_checksum: Mapped[str] = mapped_column(String(64), index=True)
    idempotency_key: Mapped[str] = mapped_column(String(64), index=True)
    promoted_by: Mapped[str] = mapped_column(String(255))
    promoted_by_id: Mapped[str] = mapped_column(String(80), default="")
    promoted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class ReportPromotionRevocation(Base):
    """Append-only revocation record for an immutable promotion."""

    __tablename__ = "report_promotion_revocations"
    __table_args__ = (UniqueConstraint("promotion_id", name="uq_report_promotion_revocation"),)

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    promotion_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("report_promotions.id", ondelete="RESTRICT"),
        index=True,
    )
    reason: Mapped[str] = mapped_column(Text)
    revoked_by: Mapped[str] = mapped_column(String(255))
    revoked_by_id: Mapped[str] = mapped_column(String(80), default="")
    revoked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class ReportReviewEvent(Base):
    """Append-only lifecycle history without raw report contents."""

    __tablename__ = "report_review_events"
    __table_args__ = (
        CheckConstraint("review_revision >= 1", name="ck_report_review_event_revision"),
        CheckConstraint("version >= 1", name="ck_report_review_event_version"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    review_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("report_reviews.id", ondelete="CASCADE"),
        index=True,
    )
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analysis_sessions.id", ondelete="CASCADE"),
        index=True,
    )
    review_revision: Mapped[int] = mapped_column(Integer)
    version: Mapped[int] = mapped_column(Integer)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    actor: Mapped[str] = mapped_column(String(255))
    actor_id: Mapped[str] = mapped_column(String(80), default="")
    details: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
