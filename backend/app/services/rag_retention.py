"""Bounded, audited retention for derived unified-intelligence RAG data."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.rag import RAGAssistance, RAGDocument
from app.services.auth import audit_event


# Retention and reconciliation both change the derived corpus. Tasks using this
# key must hold the PostgreSQL session advisory lock for their whole operation.
RAG_CORPUS_ADVISORY_LOCK_ID = 1_200_006_000
RAG_RETENTION_ACTOR = "system:rag-retention"


@dataclass(frozen=True, slots=True)
class RAGRetentionBatchResult:
    """Outcome of one bounded deletion transaction."""

    tombstoned_documents_deleted: int
    assistance_records_deleted: int
    tombstone_retention_days: int
    assistance_retention_days: int
    tombstone_cutoff: datetime | None
    assistance_cutoff: datetime | None
    batch_size: int
    has_more: bool
    legal_hold_mode: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "tombstoned_documents_deleted": self.tombstoned_documents_deleted,
            "assistance_records_deleted": self.assistance_records_deleted,
            "tombstone_retention_days": self.tombstone_retention_days,
            "assistance_retention_days": self.assistance_retention_days,
            "tombstone_cutoff": (
                self.tombstone_cutoff.isoformat() if self.tombstone_cutoff else None
            ),
            "assistance_cutoff": (
                self.assistance_cutoff.isoformat() if self.assistance_cutoff else None
            ),
            "batch_size": self.batch_size,
            "has_more": self.has_more,
            "legal_hold_mode": self.legal_hold_mode,
        }


async def purge_rag_retention_batch(
    db: AsyncSession,
    *,
    now: datetime | None = None,
    tombstone_retention_days: int | None = None,
    assistance_retention_days: int | None = None,
    batch_size: int | None = None,
    run_id: str = "scheduled",
    batch_number: int = 1,
) -> RAGRetentionBatchResult:
    """Delete one bounded batch and append its audit event in the same transaction.

    A retention value of zero disables automated deletion for that family. The
    caller owns the transaction so deletion and its audit event commit or roll
    back together. PostgreSQL foreign keys cascade document deletion to chunks
    and assistance deletion to any associated Navigator proposal.
    """

    tombstone_days = _retention_days(
        settings.rag_tombstone_retention_days
        if tombstone_retention_days is None
        else tombstone_retention_days,
        "tombstone_retention_days",
    )
    assistance_days = _retention_days(
        settings.rag_assistance_retention_days
        if assistance_retention_days is None
        else assistance_retention_days,
        "assistance_retention_days",
    )
    selected_batch_size = _bounded_integer(
        settings.rag_retention_batch_size if batch_size is None else batch_size,
        "batch_size",
        minimum=1,
        maximum=10_000,
    )
    selected_batch_number = _bounded_integer(
        batch_number,
        "batch_number",
        minimum=1,
        maximum=100,
    )
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    else:
        current = current.astimezone(timezone.utc)

    tombstone_cutoff = (
        current - timedelta(days=tombstone_days) if tombstone_days else None
    )
    assistance_cutoff = (
        current - timedelta(days=assistance_days) if assistance_days else None
    )

    tombstones_deleted = 0
    if tombstone_cutoff is not None:
        eligible_document_ids = (
            select(RAGDocument.id)
            .where(
                RAGDocument.is_active.is_(False),
                RAGDocument.indexed_at < tombstone_cutoff,
            )
            .order_by(RAGDocument.indexed_at.asc(), RAGDocument.id.asc())
            .limit(selected_batch_size)
        )
        deleted = await db.execute(
            delete(RAGDocument)
            .where(
                RAGDocument.id.in_(eligible_document_ids),
                # Recheck the retention predicate in the outer DELETE. If a
                # concurrent transaction reactivates a document, PostgreSQL's
                # row recheck must not delete the new active version.
                RAGDocument.is_active.is_(False),
                RAGDocument.indexed_at < tombstone_cutoff,
            )
            .returning(RAGDocument.id)
            .execution_options(synchronize_session=False)
        )
        tombstones_deleted = len(deleted.scalars().all())

    assistance_deleted = 0
    if assistance_cutoff is not None:
        eligible_assistance_ids = (
            select(RAGAssistance.id)
            .where(RAGAssistance.created_at < assistance_cutoff)
            .order_by(RAGAssistance.created_at.asc(), RAGAssistance.id.asc())
            .limit(selected_batch_size)
        )
        deleted = await db.execute(
            delete(RAGAssistance)
            .where(
                RAGAssistance.id.in_(eligible_assistance_ids),
                RAGAssistance.created_at < assistance_cutoff,
            )
            .returning(RAGAssistance.id)
            .execution_options(synchronize_session=False)
        )
        assistance_deleted = len(deleted.scalars().all())

    result = RAGRetentionBatchResult(
        tombstoned_documents_deleted=tombstones_deleted,
        assistance_records_deleted=assistance_deleted,
        tombstone_retention_days=tombstone_days,
        assistance_retention_days=assistance_days,
        tombstone_cutoff=tombstone_cutoff,
        assistance_cutoff=assistance_cutoff,
        batch_size=selected_batch_size,
        has_more=(
            (tombstone_days > 0 and tombstones_deleted == selected_batch_size)
            or (assistance_days > 0 and assistance_deleted == selected_batch_size)
        ),
        legal_hold_mode=tombstone_days == 0 and assistance_days == 0,
    )
    await audit_event(
        db,
        RAG_RETENTION_ACTOR,
        (
            "rag.retention.legal_hold"
            if result.legal_hold_mode
            else "rag.retention.purge"
        ),
        "rag_retention",
        _bounded_audit_id(run_id, selected_batch_number),
        {
            **result.to_dict(),
            "batch_number": selected_batch_number,
            "chunk_delete_cascade": tombstones_deleted > 0,
            "proposal_delete_cascade": assistance_deleted > 0,
            "backup_retention_unchanged": True,
        },
    )
    return result


def _retention_days(value: Any, label: str) -> int:
    return _bounded_integer(value, label, minimum=0, maximum=36_500)


def _bounded_integer(
    value: Any,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return value


def _bounded_audit_id(run_id: str, batch_number: int) -> str:
    safe = "".join(
        character
        for character in str(run_id or "scheduled")
        if ord(character) >= 32 and ord(character) != 127
    ).strip()[:220]
    return f"{safe or 'scheduled'}:batch-{batch_number}"[:255]
