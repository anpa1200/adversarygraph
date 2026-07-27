"""Idempotent canonical tagging and provenance-preserving entity linkage."""

from __future__ import annotations

from typing import Any, Iterable

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.intelligence import IntelligenceEntityTag, IntelligenceRelationship, IntelligenceTag
from app.services.taxonomy import normalize_freeform_tags


async def tag_entity(
    db: AsyncSession,
    *,
    entity_type: str,
    entity_id: str | int,
    tags: Iterable[str],
    source_type: str = "",
    source_id: str = "",
    confidence: int = 50,
    evidence: str = "",
) -> list[str]:
    canonical_tags = normalize_freeform_tags(list(tags), limit=200)
    for canonical in canonical_tags:
        namespace, value = canonical.split(":", 1)
        await db.execute(
            insert(IntelligenceTag)
            .values(namespace=namespace, value=value, canonical=canonical)
            .on_conflict_do_nothing(constraint="uq_intelligence_tag")
        )
        await db.execute(
            insert(IntelligenceEntityTag)
            .values(
                entity_type=entity_type[:40],
                entity_id=str(entity_id)[:255],
                tag=canonical,
                source_type=str(source_type or "")[:40],
                source_id=str(source_id or "")[:500],
                confidence=max(0, min(100, confidence)),
                evidence=evidence,
            )
            .on_conflict_do_update(
                constraint="uq_intelligence_entity_tag",
                set_={
                    "source_type": str(source_type or "")[:40],
                    "source_id": str(source_id or "")[:500],
                    "confidence": max(0, min(100, confidence)),
                    "evidence": evidence,
                },
            )
        )
    return canonical_tags


async def link_entities(
    db: AsyncSession,
    *,
    source_type: str,
    source_id: str | int,
    relationship_type: str,
    target_type: str,
    target_id: str | int,
    provenance_type: str,
    provenance_id: str | int,
    confidence: int = 50,
    evidence: str = "",
    attributes: dict[str, Any] | None = None,
) -> None:
    values = {
        "source_type": source_type[:40],
        "source_id": str(source_id)[:255],
        "relationship_type": relationship_type[:80],
        "target_type": target_type[:40],
        "target_id": str(target_id)[:255],
        "confidence": max(0, min(100, confidence)),
        "provenance_type": provenance_type[:40],
        "provenance_id": str(provenance_id)[:500],
        "evidence": evidence,
        "attributes": attributes or {},
    }
    await db.execute(
        insert(IntelligenceRelationship)
        .values(**values)
        .on_conflict_do_update(
            constraint="uq_intelligence_relationship_provenance",
            set_={
                "confidence": values["confidence"],
                "evidence": values["evidence"],
                "attributes": values["attributes"],
            },
        )
    )


async def link_tagged_entities(
    db: AsyncSession,
    *,
    entity_type: str,
    entity_id: str | int,
    tags: Iterable[str],
    provenance_type: str,
    provenance_id: str | int,
    confidence: int = 50,
    evidence: str = "",
) -> list[str]:
    canonical_tags = await tag_entity(
        db,
        entity_type=entity_type,
        entity_id=entity_id,
        tags=tags,
        source_type=provenance_type,
        source_id=str(provenance_id),
        confidence=confidence,
        evidence=evidence,
    )
    for tag in canonical_tags:
        namespace, value = tag.split(":", 1)
        target_type = {
            "actor": "attack_group",
            "ttp": "attack_technique",
            "tactic": "attack_tactic",
            "campaign": "attack_campaign",
            "cve": "cve",
        }.get(namespace, "tag")
        await link_entities(
            db,
            source_type=entity_type,
            source_id=entity_id,
            relationship_type="tagged-with" if target_type == "tag" else "related-to",
            target_type=target_type,
            target_id=value if target_type != "tag" else tag,
            provenance_type=provenance_type,
            provenance_id=provenance_id,
            confidence=confidence,
            evidence=evidence,
        )
    return canonical_tags
