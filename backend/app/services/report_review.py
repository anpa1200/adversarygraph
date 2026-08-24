"""Deterministic report Review Gate workflow.

The service owns the review state machine and promotion manifest.  Machine
preflight and optional AI assistance are advisory inputs only: readiness is
computed exclusively from explicit analyst decisions and source-bound claims.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any, Iterable
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analysis import AnalysisResult, AnalysisSession
from app.models.attack import AptGroup, AttackVersion, Technique
from app.models.operations import ReportIntake
from app.models.report_review import (
    ANALYST_VERDICTS,
    CLAIM_STATUSES,
    CLAIM_TYPES,
    GATE_KEYS,
    MACHINE_VERDICTS,
    ReportPromotion,
    ReportPromotionRevocation,
    ReportReview,
    ReportReviewClaim,
    ReportReviewEvent,
    ReportReviewGate,
)


POLICY_VERSION = "report-review-policy-v1.0"
MANIFEST_SCHEMA_VERSION = "report-promotion-manifest-v1"
SUPPORTED_PROFILES = ("external_cti", "internal_ir")
PROMOTION_TARGETS = ("canonical_intelligence", "rag", "hunting", "exports")

_SOURCE_EVIDENCE_KINDS = {"source_text", "source_span", "report_excerpt", "source-bound", "analyst-source-text"}
_METADATA_EVIDENCE_KINDS = {"metadata", "source_metadata", "retrieval_metadata", "publication_metadata"}
_METADATA_EVIDENCE_ROOTS = {
    "input_type",
    "filename",
    "domain",
    "tlp",
    "session_created_at",
    "report_intake_id",
    "title",
    "source_url",
    "publisher",
    "source_kind",
    "canonical_url",
    "requested_url",
    "retrieved_url",
    "http_status",
    "content_sha256",
    "extracted_text_sha256",
    "retrieved_at",
    "retrieval_superseded",
    "acquisition_text_sha256",
    "acquisition_content_sha256",
    "acquisition_size_bytes",
    "acquisition_char_count",
    "acquired_at",
    "acquisition_superseded",
    "publication_date_candidates",
    "source_checksum",
    "source_text_sha256",
    "analysis_checksum",
}
_TEXT_CLAIM_TYPES = {"procedure", "actor", "indicator", "vulnerability"}
_EDITABLE_STATES = {"draft", "changes_requested"}
_TERMINAL_STATES = {"rejected", "revoked", "stale"}
_ATTACK_ID = re.compile(r"^(?:T\d{4}(?:\.\d{3})?|AML\.T\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_GROUP_ID = re.compile(r"^G\d{4}$", re.IGNORECASE)
_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_DOMAIN_VALUE = re.compile(
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}"
)
_EMAIL_VALUE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}")
_NETWORK_FINGERPRINT = re.compile(
    r"(?=[A-Za-z0-9]{3,32}_)(?=[A-Za-z0-9]*\d)[A-Za-z0-9]{3,32}_[A-Fa-f0-9]{8,64}"
    r"(?:_[A-Fa-f0-9]{8,64}){0,3}"
)
_METADATA_PATH_TOKEN = re.compile(r"([a-zA-Z0-9_]+)|\[(\d+)\]")
_PROCEDURE_ACTION = re.compile(
    r"\b(?:access(?:ed|ing)?|collect(?:ed|ing)?|connect(?:ed|ing)?|copied|creat(?:ed|ing)|"
    r"deploy(?:ed|ing)?|download(?:ed|ing)?|dump(?:ed|ing)?|execut(?:ed|ing)|exfiltrat(?:ed|ing)?|"
    r"inject(?:ed|ing)?|install(?:ed|ing)?|launch(?:ed|ing)?|load(?:ed|ing)?|modif(?:ied|ying)|"
    r"quer(?:ied|ying)|read|schedul(?:ed|ing)?|sent|spawn(?:ed|ing)?|upload(?:ed|ing)?|wrote|written)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ReviewActor:
    """Authenticated human identity used in persisted decisions."""

    name: str
    actor_id: str = ""


@dataclass(frozen=True)
class ReviewContext:
    session: AnalysisSession
    result: AnalysisResult | None
    intake: ReportIntake | None
    source_text: str
    source_checksum: str
    analysis_checksum: str
    source_metadata: dict[str, Any]


class ReportReviewError(Exception):
    """Base class for expected workflow failures."""

    status_code = 422

    def __init__(self, message: str, *, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ReviewNotFoundError(ReportReviewError):
    status_code = 404


class ReviewConflictError(ReportReviewError):
    status_code = 409


class ReviewStateError(ReviewConflictError):
    pass


class ReviewValidationError(ReportReviewError):
    pass


GATE_CATALOG: dict[str, dict[str, Any]] = {
    "source_provenance": {
        "ordinal": 1,
        "title": "Source provenance",
        "question": "Is the source real, retrievable, and bound to this stored report?",
        "description": "Validate the canonical URL or internal source record, retrieval result, and content checksum.",
        "reason_codes": {
            "source_verified",
            "internal_source_verified",
            "archived_source_verified",
            "source_unreachable",
            "source_mismatch",
            "insufficient_provenance",
        },
    },
    "publication_date": {
        "ordinal": 2,
        "title": "Publication date",
        "question": "Is the report publication or authoritative record date accurate?",
        "description": "Resolve conflicting date candidates and preserve the evidence used for the selected date.",
        "reason_codes": {
            "date_verified",
            "internal_record_date_verified",
            "internal_record_no_publication",
            "date_conflict",
            "date_missing",
            "date_unverified",
        },
    },
    "procedure_relevance": {
        "ordinal": 3,
        "title": "Procedure relevance",
        "question": "Does the content describe adversary or incident procedures?",
        "description": "A name, product, malware, or actor mention alone is not procedure evidence.",
        "reason_codes": {
            "procedure_relevant",
            "name_only_mention",
            "not_security_procedure",
            "insufficient_procedure_context",
        },
    },
    "procedure_level_claim": {
        "ordinal": 4,
        "title": "Procedure-level claim",
        "question": "Is at least one specific, source-bound procedure claim accepted?",
        "description": "The claim must state a behavior and object or outcome, not merely a tool or ATT&CK label.",
        "reason_codes": {
            "source_bound_claims",
            "generic_tool_only",
            "claim_not_source_bound",
            "insufficient_procedure_detail",
        },
    },
    "actor_identification": {
        "ordinal": 5,
        "title": "Actor identification",
        "question": "Is actor identification explicit, source-reported, absent, or only inferred?",
        "description": "Shared tooling, malware similarity, or ATT&CK overlap cannot independently establish attribution.",
        "reason_codes": {
            "explicit_attribution",
            "source_reported_attribution",
            "no_actor_claim",
            "tooling_overlap_only",
            "inferred_attribution",
            "conflicting_attribution",
        },
    },
}

GATE_REASON_CODES_BY_VERDICT: dict[str, dict[str, set[str]]] = {
    "source_provenance": {
        "pass": {"source_verified", "internal_source_verified", "archived_source_verified"},
        "fail": {"source_unreachable", "source_mismatch"},
        "needs_information": {"source_unreachable", "insufficient_provenance"},
        "not_applicable": set(),
    },
    "publication_date": {
        "pass": {"date_verified", "internal_record_date_verified"},
        "fail": {"date_conflict", "date_unverified"},
        "needs_information": {"date_conflict", "date_missing", "date_unverified"},
        "not_applicable": {"internal_record_no_publication"},
    },
    "procedure_relevance": {
        "pass": {"procedure_relevant"},
        "fail": {"name_only_mention", "not_security_procedure"},
        "needs_information": {"insufficient_procedure_context"},
        "not_applicable": set(),
    },
    "procedure_level_claim": {
        "pass": {"source_bound_claims"},
        "fail": {"generic_tool_only", "claim_not_source_bound"},
        "needs_information": {"insufficient_procedure_detail", "claim_not_source_bound"},
        "not_applicable": set(),
    },
    "actor_identification": {
        "pass": {"explicit_attribution", "source_reported_attribution"},
        "fail": {"tooling_overlap_only", "inferred_attribution", "conflicting_attribution"},
        "needs_information": {"inferred_attribution", "conflicting_attribution"},
        "not_applicable": {"no_actor_claim"},
    },
}


def canonical_json(value: Any) -> str:
    """Return the stable representation used by every persisted checksum."""

    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def checksum_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def checksum_json(value: Any) -> str:
    return checksum_text(canonical_json(value))


def source_fingerprint(source_text: str, source_metadata: dict[str, Any]) -> str:
    """Bind report content and review-relevant provenance into one checksum."""

    return checksum_json(
        {
            "source_text_sha256": checksum_text(source_text),
            "source_metadata": source_metadata,
        }
    )


def analysis_fingerprint(result: AnalysisResult | None, session_status: str) -> str:
    """Fingerprint only review-relevant analysis fields, never raw provider output."""

    payload = {
        "session_status": session_status,
        "result": None
        if result is None
        else {
            "summary": result.summary or "",
            "extracted_techniques": result.extracted_techniques or [],
            # Similarity is deliberately fingerprinted for staleness but never
            # becomes an actor claim or accepted promotion content.
            "apt_matches": result.apt_matches or [],
        },
    }
    return checksum_json(payload)


def promotion_manifest_checksum(manifest: dict[str, Any], targets: list[str]) -> str:
    """Bind the immutable manifest and its separately stored targets."""

    return checksum_json({"manifest": manifest, "targets": targets})


def _promotion_integrity_matches_review(
    promotion: ReportPromotion,
    review: ReportReview,
) -> bool:
    manifest = promotion.manifest if isinstance(promotion.manifest, dict) else {}
    targets = list(promotion.targets or [])
    return (
        manifest.get("schema_version") == MANIFEST_SCHEMA_VERSION
        and manifest.get("targets") == targets
        and manifest.get("session_id") == str(promotion.session_id)
        and manifest.get("review_id") == str(promotion.review_id)
        and manifest.get("review_revision") == promotion.review_revision
        and manifest.get("policy_version") == promotion.policy_version
        and manifest.get("profile") == review.profile
        and manifest.get("source_checksum") == promotion.source_checksum
        and manifest.get("analysis_checksum") == promotion.analysis_checksum
        and promotion.review_id == review.id
        and promotion.session_id == review.session_id
        and promotion.review_revision == review.revision
        and promotion.policy_version == review.policy_version
        and promotion.source_checksum == review.source_checksum
        and promotion.analysis_checksum == review.analysis_checksum
        and promotion.manifest_checksum == promotion_manifest_checksum(manifest, targets)
    )


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _clean_string(value: Any, limit: int) -> str:
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", str(value or "")).strip()[:limit]


def _bounded_json(value: Any, *, depth: int = 0) -> Any:
    """Keep advisory metadata bounded and JSON-safe before persistence."""

    if depth >= 6:
        return None
    if isinstance(value, dict):
        return {
            _clean_string(key, 100): _bounded_json(item, depth=depth + 1)
            for key, item in list(value.items())[:100]
            if _clean_string(key, 100)
        }
    if isinstance(value, (list, tuple)):
        return [_bounded_json(item, depth=depth + 1) for item in list(value)[:100]]
    if isinstance(value, str):
        return _clean_string(value, 8_000)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return _clean_string(value, 1_000)


def _json_object(value: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


async def _load_intake(
    db: AsyncSession,
    session_id: uuid.UUID,
    *,
    lock: bool = False,
) -> ReportIntake | None:
    """Resolve the normalized provenance link used by URL report intake."""

    direct_statement = (
        select(ReportIntake)
        .where(ReportIntake.analysis_session_id == session_id)
        .order_by(ReportIntake.updated_at.desc(), ReportIntake.id.desc())
        .limit(1)
    )
    if lock:
        direct_statement = direct_statement.with_for_update()
    direct_row = await db.execute(direct_statement)
    direct = direct_row.scalar_one_or_none()
    if direct is not None:
        return direct

    session_key = str(session_id)
    statement = (
        select(ReportIntake)
        .where(ReportIntake.provenance["analysis_session_id"].astext == session_key)
        .order_by(ReportIntake.updated_at.desc(), ReportIntake.id.desc())
        .limit(1)
    )
    if lock:
        statement = statement.with_for_update()
    row = await db.execute(statement)
    return row.scalar_one_or_none()


async def lock_review_source(
    db: AsyncSession,
    session_id: uuid.UUID,
) -> AnalysisSession:
    """Serialize report edits and review mutations in a stable lock order."""

    session_row = await db.execute(
        select(AnalysisSession)
        .where(AnalysisSession.id == session_id)
        .with_for_update()
    )
    session = session_row.scalar_one_or_none()
    if session is None:
        raise ReviewNotFoundError("Analysis session not found")
    await _load_intake(db, session_id, lock=True)
    return session


def _source_metadata(session: AnalysisSession, intake: ReportIntake | None) -> dict[str, Any]:
    session_provenance = (
        session.source_provenance
        if isinstance(session.source_provenance, dict)
        else {}
    )
    acquisition = (
        session_provenance.get("acquisition")
        if isinstance(session_provenance.get("acquisition"), dict)
        else {}
    )
    metadata: dict[str, Any] = {
        "input_type": session.input_type,
        "filename": session.filename or "",
        "domain": session.domain,
        "tlp": session.tlp,
        "session_created_at": session.created_at.isoformat() if session.created_at else "",
        "source_kind": session_provenance.get("source_kind") or session.input_type,
        "acquisition_text_sha256": acquisition.get("extracted_text_sha256") or "",
        "acquisition_content_sha256": acquisition.get("content_sha256") or "",
        "acquisition_size_bytes": acquisition.get("content_size_bytes"),
        "acquisition_char_count": acquisition.get("extracted_text_chars"),
        "acquired_at": acquisition.get("acquired_at") or "",
        "acquisition_superseded": bool(acquisition.get("superseded")),
    }
    if intake is None:
        return metadata

    notes = _json_object(intake.analyst_notes)
    provenance = intake.provenance if isinstance(intake.provenance, dict) else {}
    provenance_retrieval = provenance.get("retrieval") if isinstance(provenance.get("retrieval"), dict) else {}
    note_metadata = notes.get("metadata") if isinstance(notes.get("metadata"), dict) else {}
    # Structured provenance is authoritative; analyst notes retain a legacy
    # copy for presentation but cannot override a superseded/current receipt.
    fetched = {**note_metadata, **provenance_retrieval}
    has_source_provenance = bool(
        intake.url
        or provenance.get("source_url")
        or provenance.get("source_kind")
        or notes.get("source_kind")
        or fetched
    )
    # Canonical promotion creates a projection intake for file/text reports.
    # That derived row is not source provenance and must not make the freshly
    # promoted fingerprint stale merely by coming into existence.
    if not has_source_provenance:
        return _bounded_json(metadata)
    metadata.update(
        {
            "report_intake_id": str(intake.id),
            "title": intake.title or "",
            "source_url": intake.url or provenance.get("source_url") or "",
            "publisher": intake.publisher or "",
            "source_kind": provenance.get("source_kind") or notes.get("source_kind") or "",
            "canonical_url": fetched.get("canonical_url") or "",
            "requested_url": fetched.get("requested_url") or "",
            "retrieved_url": fetched.get("retrieved_url") or "",
            "http_status": fetched.get("http_status"),
            "content_sha256": fetched.get("content_sha256") or "",
            "extracted_text_sha256": fetched.get("extracted_text_sha256") or "",
            "retrieved_at": fetched.get("retrieved_at") or "",
            "retrieval_superseded": bool(fetched.get("superseded")),
            "publication_date_candidates": fetched.get("publication_date_candidates") or [],
        }
    )
    return _bounded_json(metadata)


async def load_review_context(db: AsyncSession, session_id: uuid.UUID) -> ReviewContext:
    session = await db.get(AnalysisSession, session_id)
    if session is None:
        raise ReviewNotFoundError("Analysis session not found")
    result_row = await db.execute(select(AnalysisResult).where(AnalysisResult.session_id == session_id).limit(1))
    result = result_row.scalar_one_or_none()
    intake = await _load_intake(db, session_id)
    source_text = session.source_text or ""
    source_metadata = _source_metadata(session, intake)
    return ReviewContext(
        session=session,
        result=result,
        intake=intake,
        source_text=source_text,
        source_checksum=source_fingerprint(source_text, source_metadata),
        analysis_checksum=analysis_fingerprint(result, session.status),
        source_metadata=source_metadata,
    )


def _source_ref(source_text: str, evidence: str, start: Any = None, end: Any = None) -> dict[str, Any] | None:
    clean = _clean_string(evidence, 2_000)
    if len(clean) < 4:
        return None
    try:
        parsed_start = int(start) if start is not None else None
        parsed_end = int(end) if end is not None else None
    except (TypeError, ValueError):
        parsed_start = parsed_end = None
    if parsed_start is not None and parsed_end is not None:
        if 0 <= parsed_start < parsed_end <= len(source_text) and source_text[parsed_start:parsed_end] == clean:
            found_start = parsed_start
        else:
            found_start = -1
    else:
        found_start = source_text.find(clean)
        if found_start >= 0 and source_text.rfind(clean) != found_start:
            found_start = -1
    if found_start < 0:
        return None
    excerpt = source_text[found_start : found_start + len(clean)]
    return {
        "id": f"source:{found_start}:{found_start + len(excerpt)}",
        "kind": "source_text",
        "label": "Stored report excerpt",
        "excerpt": excerpt,
        "source": "analysis_session.source_text",
        "evidence_start": found_start,
        "evidence_end": found_start + len(excerpt),
        "metadata": {"locally_verified": True},
    }


def _claim_key(claim_type: str, *parts: Any) -> str:
    return checksum_json([claim_type, *[_clean_string(part, 2_000).casefold() for part in parts]])


def _candidate_claims(context: ReviewContext) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    result = context.result
    for item in list(result.extracted_techniques or [])[:500] if result else []:
        if not isinstance(item, dict):
            continue
        attack_id = _clean_string(item.get("attack_id"), 30).upper()
        if not _ATTACK_ID.fullmatch(attack_id):
            continue
        technique_name = _clean_string(item.get("name"), 255)
        evidence_text = _clean_string(item.get("evidence"), 2_000)
        evidence = _source_ref(
            context.source_text,
            evidence_text,
            item.get("evidence_start"),
            item.get("evidence_end"),
        )
        statement = _clean_string(
            item.get("procedure") or evidence_text or f"Report maps behavior to {attack_id} {technique_name}",
            4_000,
        )
        claims.append(
            {
                "claim_key": _claim_key("procedure", attack_id, statement, evidence_text),
                "claim_type": "procedure",
                "subject": _clean_string(item.get("subject"), 500) or "report-described adversary",
                "predicate": _clean_string(item.get("action"), 255) or "performed procedure",
                "object": technique_name or attack_id,
                "statement": statement,
                "attack_id": attack_id,
                "actor_id": "",
                "evidence_text": evidence["excerpt"] if evidence else evidence_text,
                "evidence_start": evidence.get("evidence_start") if evidence else None,
                "evidence_end": evidence.get("evidence_end") if evidence else None,
                "evidence_refs": [evidence] if evidence else [],
                "extraction_method": "analysis-extraction",
                "metadata": {
                    "confidence": item.get("confidence"),
                    "tactic": _clean_string(item.get("tactic"), 120),
                    "llm_verified": bool(item.get("llm_verified", False)),
                    "candidate_review_status": _clean_string(item.get("review_status"), 30) or "suggested",
                },
            }
        )

    candidates = context.source_metadata.get("publication_date_candidates") or []
    for candidate_index, item in enumerate(list(candidates)[:20]):
        if not isinstance(item, dict):
            continue
        value = _clean_string(item.get("value"), 100)
        source = _clean_string(item.get("source"), 120) or "retrieval metadata"
        if not value:
            continue
        claims.append(
            {
                "claim_key": _claim_key("publication_date", value, source),
                "claim_type": "publication_date",
                "subject": "report",
                "predicate": "published on",
                "object": value,
                "statement": f"The report publication date is {value}.",
                "attack_id": "",
                "actor_id": "",
                "evidence_text": "",
                "evidence_start": None,
                "evidence_end": None,
                "evidence_refs": [
                    {
                        "id": f"metadata:publication-date:{checksum_text(value)[:16]}",
                        "kind": "publication_metadata",
                        "label": source,
                        "path": f"source_metadata.publication_date_candidates[{candidate_index}]",
                        "value": value,
                        "source": source,
                        "metadata": {"locally_verified": True},
                    }
                ],
                "extraction_method": "deterministic-metadata",
                "metadata": {"date_candidate": value, "date_source": source},
            }
        )

    intake = context.intake
    if intake is not None:
        for actor_id_value in list(intake.actor_ids or [])[:100]:
            actor_id = _clean_string(actor_id_value, 120)
            if not actor_id:
                continue
            evidence = _source_ref(context.source_text, actor_id)
            claims.append(
                {
                    "claim_key": _claim_key("actor", actor_id),
                    "claim_type": "actor",
                    "subject": "report",
                    "predicate": "attributes activity to",
                    "object": actor_id,
                    "statement": f"The source identifies {actor_id} as the responsible actor.",
                    "attack_id": "",
                    "actor_id": actor_id,
                    "evidence_text": evidence["excerpt"] if evidence else "",
                    "evidence_start": evidence.get("evidence_start") if evidence else None,
                    "evidence_end": evidence.get("evidence_end") if evidence else None,
                    "evidence_refs": [evidence] if evidence else [],
                    "extraction_method": "report-intake-candidate",
                    "metadata": {"attribution_basis": "source_reported" if evidence else "unverified"},
                }
            )
        for indicator in list(intake.indicators or [])[:200]:
            if not isinstance(indicator, dict):
                continue
            value = _clean_string(indicator.get("value") or indicator.get("indicator") or indicator.get("observable"), 2_000)
            if not value:
                continue
            evidence = _source_ref(context.source_text, value)
            claims.append(
                {
                    "claim_key": _claim_key("indicator", indicator.get("type"), value),
                    "claim_type": "indicator",
                    "subject": "report",
                    "predicate": "contains indicator",
                    "object": value,
                    "statement": f"The report contains the indicator {value}.",
                    "attack_id": "",
                    "actor_id": "",
                    "evidence_text": evidence["excerpt"] if evidence else "",
                    "evidence_start": evidence.get("evidence_start") if evidence else None,
                    "evidence_end": evidence.get("evidence_end") if evidence else None,
                    "evidence_refs": [evidence] if evidence else [],
                    "extraction_method": "deterministic-ioc-extraction",
                    "metadata": {
                        "indicator_type": _clean_string(indicator.get("indicator_type") or indicator.get("type"), 80),
                        "confidence": indicator.get("confidence"),
                    },
                }
            )

    for match in list(_CVE_ID.finditer(context.source_text))[:200]:
        value = match.group(0).upper()
        evidence = _source_ref(context.source_text, match.group(0), match.start(), match.end())
        claims.append(
            {
                "claim_key": _claim_key("vulnerability", value),
                "claim_type": "vulnerability",
                "subject": "report",
                "predicate": "references vulnerability",
                "object": value,
                "statement": f"The report references {value}.",
                "attack_id": "",
                "actor_id": "",
                "evidence_text": evidence["excerpt"] if evidence else value,
                "evidence_start": evidence.get("evidence_start") if evidence else match.start(),
                "evidence_end": evidence.get("evidence_end") if evidence else match.end(),
                "evidence_refs": [evidence] if evidence else [],
                "extraction_method": "deterministic-cve-pattern",
                "metadata": {},
            }
        )

    # Keep deterministic first occurrence ordering while removing duplicates
    # produced by overlapping intake and text extractors.
    return list({item["claim_key"]: item for item in claims}.values())


async def _catalog_actors(
    db: AsyncSession,
    domain: str,
    actor_ids: Iterable[str],
) -> dict[str, AptGroup]:
    """Resolve ATT&CK group IDs from the active local catalog only."""

    requested = {
        _clean_string(actor_id, 20).upper()
        for actor_id in actor_ids
        if _GROUP_ID.fullmatch(_clean_string(actor_id, 20))
    }
    if not requested:
        return {}
    rows = await db.execute(
        select(AptGroup)
        .join(AttackVersion, AptGroup.version_id == AttackVersion.id)
        .where(
            AptGroup.attack_id.in_(requested),
            AptGroup.domain == domain,
            AttackVersion.is_latest.is_(True),
        )
        .order_by(AptGroup.version_id.desc())
    )
    return {str(group.attack_id).upper(): group for group in rows.scalars().all()}


def _apply_catalog_actor_metadata(candidate: dict[str, Any], group: AptGroup | None) -> None:
    metadata = candidate.get("metadata") if isinstance(candidate.get("metadata"), dict) else {}
    for key in ("catalog_verified", "catalog_name", "catalog_aliases", "catalog_url"):
        metadata.pop(key, None)
    if group is not None:
        metadata.update(
            {
                "catalog_verified": True,
                "catalog_name": _clean_string(group.name, 255),
                "catalog_aliases": [
                    _clean_string(alias, 255)
                    for alias in list(group.aliases or [])[:50]
                    if _clean_string(alias, 255)
                ],
                "catalog_url": _clean_string(group.url, 500),
            }
        )
    else:
        metadata["catalog_verified"] = False
    candidate["metadata"] = metadata


async def _enrich_catalog_actor_candidates(
    db: AsyncSession,
    domain: str,
    candidates: list[dict[str, Any]],
) -> None:
    actor_candidates = [
        candidate
        for candidate in candidates
        if candidate.get("claim_type") == "actor"
        and _GROUP_ID.fullmatch(_clean_string(candidate.get("actor_id"), 20))
    ]
    catalog = await _catalog_actors(
        db,
        domain,
        [str(candidate.get("actor_id") or "") for candidate in actor_candidates],
    )
    for candidate in actor_candidates:
        actor_id = _clean_string(candidate.get("actor_id"), 20).upper()
        candidate["actor_id"] = actor_id
        _apply_catalog_actor_metadata(candidate, catalog.get(actor_id))


def _new_gate(review_id: uuid.UUID, gate_key: str, *, now: datetime) -> ReportReviewGate:
    definition = GATE_CATALOG[gate_key]
    return ReportReviewGate(
        id=uuid.uuid4(),
        review_id=review_id,
        gate_key=gate_key,
        ordinal=definition["ordinal"],
        required=True,
        machine_verdict="not_run",
        machine_details={},
        machine_evidence_refs=[],
        machine_evaluator="",
        analyst_verdict="pending",
        reason_code="",
        rationale="",
        evidence_refs=[],
        reviewed_by="",
        reviewed_by_id="",
        created_at=now,
        updated_at=now,
    )


def _new_claim(review_id: uuid.UUID, candidate: dict[str, Any], *, now: datetime) -> ReportReviewClaim:
    return ReportReviewClaim(
        id=uuid.uuid4(),
        review_id=review_id,
        claim_key=candidate["claim_key"],
        claim_type=candidate["claim_type"],
        subject=candidate["subject"],
        predicate=candidate["predicate"],
        object=candidate["object"],
        statement=candidate["statement"],
        attack_id=candidate["attack_id"],
        actor_id=candidate["actor_id"],
        evidence_text=candidate["evidence_text"],
        evidence_start=candidate["evidence_start"],
        evidence_end=candidate["evidence_end"],
        extraction_method=candidate["extraction_method"],
        status="suggested",
        reason_code="",
        rationale="",
        evidence_refs=candidate["evidence_refs"],
        claim_metadata=_bounded_json(candidate["metadata"]),
        reviewed_by="",
        reviewed_by_id="",
        created_at=now,
        updated_at=now,
    )


async def _latest_review(db: AsyncSession, session_id: uuid.UUID, *, lock: bool = False) -> ReportReview | None:
    statement = select(ReportReview).where(ReportReview.session_id == session_id).order_by(ReportReview.revision.desc()).limit(1)
    if lock:
        statement = statement.with_for_update()
    row = await db.execute(statement)
    return row.scalar_one_or_none()


async def _review_rows(
    db: AsyncSession, review_id: uuid.UUID, *, lock: bool = False
) -> tuple[list[ReportReviewGate], list[ReportReviewClaim]]:
    gate_statement = select(ReportReviewGate).where(ReportReviewGate.review_id == review_id).order_by(ReportReviewGate.ordinal)
    claim_statement = (
        select(ReportReviewClaim)
        .where(ReportReviewClaim.review_id == review_id)
        .order_by(ReportReviewClaim.claim_type, ReportReviewClaim.created_at, ReportReviewClaim.claim_key)
    )
    if lock:
        gate_statement = gate_statement.with_for_update()
        claim_statement = claim_statement.with_for_update()
    gate_rows = await db.execute(gate_statement)
    claim_rows = await db.execute(claim_statement)
    return list(gate_rows.scalars().all()), list(claim_rows.scalars().all())


def _add_event(
    db: AsyncSession,
    review: ReportReview,
    actor: ReviewActor,
    event_type: str,
    details: dict[str, Any] | None = None,
) -> None:
    db.add(
        ReportReviewEvent(
            id=uuid.uuid4(),
            review_id=review.id,
            session_id=review.session_id,
            review_revision=review.revision,
            version=review.version,
            event_type=event_type,
            actor=actor.name,
            actor_id=actor.actor_id,
            details=_bounded_json(details or {}),
            created_at=_utcnow(),
        )
    )


def _touch(review: ReportReview, *, now: datetime | None = None) -> None:
    review.version += 1
    review.updated_at = now or _utcnow()


def _assert_version(review: ReportReview, expected_version: int) -> None:
    if review.version != expected_version:
        raise ReviewConflictError(
            "Review was changed by another user; reload before saving",
            details={"expected_version": expected_version, "current_version": review.version},
        )


def _assert_current(review: ReportReview, context: ReviewContext) -> None:
    stale: list[str] = []
    if review.source_checksum != context.source_checksum:
        stale.append("source_checksum_changed")
    if review.analysis_checksum != context.analysis_checksum:
        stale.append("analysis_checksum_changed")
    if stale:
        raise ReviewConflictError(
            "The stored source or analysis changed; start a new review revision",
            details={"stale_reasons": stale, "review_revision": review.revision},
        )


async def start_review(
    db: AsyncSession,
    session_id: uuid.UUID,
    actor: ReviewActor,
    *,
    profile: str = "external_cti",
    expected_source_checksum: str | None = None,
) -> ReportReview:
    if profile not in SUPPORTED_PROFILES:
        raise ReviewValidationError(f"Profile must be one of: {', '.join(SUPPORTED_PROFILES)}")
    context = await load_review_context(db, session_id)
    if context.session.status != "completed" or context.result is None:
        raise ReviewValidationError("A completed, stored analysis result is required before review")
    if not context.source_text.strip():
        raise ReviewValidationError("Stored source text is required before review")
    if expected_source_checksum and expected_source_checksum != context.source_checksum:
        raise ReviewConflictError(
            "Stored source changed before the review could start",
            details={"current_source_checksum": context.source_checksum},
        )

    previous = await _latest_review(db, session_id, lock=True)
    if (
        previous is not None
        and previous.source_checksum == context.source_checksum
        and previous.analysis_checksum == context.analysis_checksum
        and previous.profile == profile
        and previous.policy_version == POLICY_VERSION
        and previous.state not in _TERMINAL_STATES
    ):
        return previous
    if previous is not None and previous.state == "promoted":
        raise ReviewStateError(
            "A promoted review must be revoked by an authorized promoter before a new revision can start"
        )

    now = _utcnow()
    next_revision = (previous.revision + 1) if previous else 1
    if previous is not None and previous.state not in _TERMINAL_STATES:
        from_state = previous.state
        previous.state = "stale"
        _touch(previous, now=now)
        _add_event(
            db,
            previous,
            actor,
            "review_staled",
            {"from_state": from_state, "to_state": "stale", "replacement_revision": next_revision},
        )

    result_is_current = previous is None or previous.analysis_checksum != context.analysis_checksum
    # Core extraction binds evidence only inside ai.base's 40k input window.
    # Never claim full coverage merely because a result row exists.
    analyzed_chars = min(len(context.source_text), 40_000) if context.session.llm_provider != "none" and result_is_current else 0
    coverage_complete = analyzed_chars == len(context.source_text)
    review = ReportReview(
        id=uuid.uuid4(),
        session_id=session_id,
        revision=next_revision,
        version=1,
        policy_version=POLICY_VERSION,
        profile=profile,
        state="draft",
        source_checksum=context.source_checksum,
        analysis_checksum=context.analysis_checksum,
        source_char_count=len(context.source_text),
        analyzed_char_count=analyzed_chars,
        coverage_complete=coverage_complete,
        coverage_exception_reason="",
        coverage_exception_by="",
        coverage_exception_by_id="",
        created_by=actor.name,
        created_by_id=actor.actor_id,
        submitted_by="",
        submitted_by_id="",
        approved_by="",
        approved_by_id="",
        promoted_by="",
        promoted_by_id="",
        revoked_by="",
        revoked_by_id="",
        created_at=now,
        updated_at=now,
    )
    db.add(review)
    gates = [_new_gate(review.id, gate_key, now=now) for gate_key in GATE_KEYS]
    for gate in gates:
        db.add(gate)
    candidates = _candidate_claims(context)
    await _enrich_catalog_actor_candidates(db, context.session.domain, candidates)
    claims = [_new_claim(review.id, candidate, now=now) for candidate in candidates]
    for claim in claims:
        db.add(claim)
    _add_event(
        db,
        review,
        actor,
        "review_started",
        {
            "profile": profile,
            "policy_version": POLICY_VERSION,
            "gate_count": len(gates),
            "candidate_claim_count": len(claims),
            "coverage_complete": coverage_complete,
        },
    )
    await db.flush()
    return review


async def invalidate_review(
    db: AsyncSession,
    session_id: uuid.UUID,
    actor: ReviewActor,
    *,
    reason: str,
) -> ReportReview | None:
    """Mark the current revision stale after an in-scope source/analysis edit."""

    review = await _latest_review(db, session_id, lock=True)
    if review is None or review.state in _TERMINAL_STATES:
        return review
    from_state = review.state
    review.state = "stale"
    _touch(review)
    _add_event(
        db,
        review,
        actor,
        "review_staled",
        {"from_state": from_state, "to_state": "stale", "reason": _clean_string(reason, 500)},
    )
    await db.flush()
    return review


async def grant_coverage_exception(
    db: AsyncSession,
    session_id: uuid.UUID,
    actor: ReviewActor,
    *,
    expected_version: int,
    reason: str,
) -> ReportReview:
    """Record an explicit privileged exception to the full-source rule."""

    review = await _latest_review(db, session_id, lock=True)
    if review is None:
        raise ReviewNotFoundError("Start a report review before granting an exception")
    _assert_version(review, expected_version)
    if review.state not in _EDITABLE_STATES:
        raise ReviewStateError(f"Coverage exceptions cannot be changed while review state is {review.state}")
    context = await load_review_context(db, session_id)
    _assert_current(review, context)
    clean_reason = _clean_string(reason, 4_000)
    if len(clean_reason) < 30:
        raise ReviewValidationError("Coverage exception requires a specific justification of at least 30 characters")
    if actor.actor_id == review.created_by_id:
        raise ReviewValidationError("Coverage exception must be granted by a second authorized reviewer")
    now = _utcnow()
    review.coverage_exception_reason = clean_reason
    review.coverage_exception_by = actor.name
    review.coverage_exception_by_id = actor.actor_id
    review.coverage_exception_at = now
    _touch(review, now=now)
    _add_event(
        db,
        review,
        actor,
        "coverage_exception_granted",
        {
            "analyzed_char_count": review.analyzed_char_count,
            "source_char_count": review.source_char_count,
            "reason": clean_reason,
        },
    )
    await db.flush()
    return review


_MISSING_METADATA = object()


def _metadata_path_value(
    metadata: dict[str, Any],
    path: str,
) -> Any:
    clean_path = _clean_string(path, 300)
    prefix = "source_metadata."
    if clean_path.startswith(prefix):
        clean_path = clean_path[len(prefix):]
    if not re.fullmatch(r"[A-Za-z0-9_]+(?:\[\d+\])?(?:\.[A-Za-z0-9_]+(?:\[\d+\])?)*", clean_path):
        return _MISSING_METADATA
    tokens = _METADATA_PATH_TOKEN.findall(clean_path)
    if not tokens:
        return _MISSING_METADATA
    root = tokens[0][0]
    if root not in _METADATA_EVIDENCE_ROOTS:
        return _MISSING_METADATA
    current: Any = metadata
    for name, index in tokens:
        if name:
            if not isinstance(current, dict) or name not in current:
                return _MISSING_METADATA
            current = current[name]
        else:
            if not isinstance(current, list):
                return _MISSING_METADATA
            position = int(index)
            if position < 0 or position >= len(current):
                return _MISSING_METADATA
            current = current[position]
    return current


def _metadata_value_matches(actual: Any, supplied: str) -> bool:
    if len(supplied) < 2:
        return False
    if isinstance(actual, dict):
        actual = actual.get("value", actual.get("date", _MISSING_METADATA))
    if isinstance(actual, list):
        return any(_metadata_value_matches(item, supplied) for item in actual)
    if actual is _MISSING_METADATA or isinstance(actual, (dict, list)):
        return False
    return _clean_string(actual, 2_000) == supplied


def _normalize_evidence_refs(refs: Iterable[dict[str, Any]] | None, context: ReviewContext) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    metadata_values = {
        **context.source_metadata,
        "source_checksum": context.source_checksum,
        "source_text_sha256": checksum_text(context.source_text),
        "analysis_checksum": context.analysis_checksum,
    }
    for item in list(refs or [])[:20]:
        if not isinstance(item, dict):
            continue
        kind = _clean_string(item.get("kind") or item.get("type"), 80).casefold().replace("-", "_")
        excerpt = _clean_string(item.get("excerpt") or item.get("quote") or item.get("value"), 2_000)
        start = item.get("evidence_start", item.get("start"))
        end = item.get("evidence_end", item.get("end"))
        locator = item.get("locator")
        if isinstance(locator, dict):
            start = locator.get("start", start)
            end = locator.get("end", end)
        if kind in {value.replace("-", "_") for value in _SOURCE_EVIDENCE_KINDS} or (excerpt and not kind):
            bound = _source_ref(context.source_text, excerpt, start, end)
            if bound:
                bound["label"] = _clean_string(item.get("label"), 200) or bound["label"]
                normalized.append(bound)
            continue
        if kind in _METADATA_EVIDENCE_KINDS:
            value = _clean_string(item.get("value") or item.get("excerpt"), 2_000)
            path = _clean_string(item.get("path"), 300)
            actual = _metadata_path_value(metadata_values, path)
            if value and path and _metadata_value_matches(actual, value):
                normalized.append(
                    {
                        "id": _clean_string(item.get("id"), 120) or f"metadata:{checksum_text(value)[:16]}",
                        "kind": kind,
                        "label": _clean_string(item.get("label") or path, 200) or "Stored source metadata",
                        "path": path,
                        "value": value,
                        "source": f"stored source metadata:{path}",
                        "metadata": {"locally_verified": True, "path": path},
                    }
                )
    return normalized


def _has_text_evidence(claim: ReportReviewClaim, context: ReviewContext) -> bool:
    if _source_ref(context.source_text, claim.evidence_text, claim.evidence_start, claim.evidence_end):
        return True
    return any(ref.get("kind") == "source_text" for ref in _normalize_evidence_refs(claim.evidence_refs, context))


def _parse_iso_calendar_date(value: Any) -> date | None:
    clean = _clean_string(value, 20)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", clean):
        return None
    try:
        return date.fromisoformat(clean)
    except ValueError:
        return None


def _text_supports_publication_date(excerpt: str, candidate: date) -> bool:
    normalized = excerpt.casefold()
    month = candidate.strftime("%B").casefold()
    abbreviated_month = candidate.strftime("%b").casefold()
    variants = {
        candidate.isoformat(),
        candidate.strftime("%Y/%m/%d"),
        f"{candidate.day} {month} {candidate.year}",
        f"{candidate.day:02d} {month} {candidate.year}",
        f"{month} {candidate.day}, {candidate.year}",
        f"{month} {candidate.day:02d}, {candidate.year}",
        f"{candidate.day} {abbreviated_month} {candidate.year}",
        f"{abbreviated_month} {candidate.day}, {candidate.year}",
    }
    return any(value in normalized for value in variants)


def _source_acquisition_date(context: ReviewContext) -> date:
    candidates: list[date] = []
    retrieved_at = _clean_string(context.source_metadata.get("retrieved_at"), 80)
    if retrieved_at:
        try:
            candidates.append(datetime.fromisoformat(retrieved_at.replace("Z", "+00:00")).date())
        except ValueError:
            pass
    if context.session.created_at is not None:
        candidates.append(context.session.created_at.date())
    return min(candidates) if candidates else _utcnow().date()


def _exact_phrase_in_evidence(phrase: str, evidence: str) -> bool:
    clean = _clean_string(phrase, 255)
    if len(clean) < 3 or len(re.sub(r"[^A-Za-z0-9]", "", clean)) < 3:
        return False
    return re.search(
        rf"(?<![A-Za-z0-9]){re.escape(clean)}(?![A-Za-z0-9])",
        evidence,
        re.IGNORECASE,
    ) is not None


def _exact_value_in_evidence(value: str, evidence: str) -> bool:
    clean = _clean_string(value, 2_000)
    if len(clean) < 2:
        return False
    prefix = r"(?<![A-Za-z0-9])" if clean[0].isalnum() else ""
    suffix = r"(?![A-Za-z0-9])" if clean[-1].isalnum() else ""
    return re.search(f"{prefix}{re.escape(clean)}{suffix}", evidence, re.IGNORECASE) is not None


def _claim_text_evidence(claim: ReportReviewClaim, context: ReviewContext) -> str:
    excerpts = [claim.evidence_text]
    excerpts.extend(
        str(item.get("excerpt") or "")
        for item in _normalize_evidence_refs(claim.evidence_refs, context)
        if item.get("kind") == "source_text"
    )
    return "\n".join(excerpt for excerpt in excerpts if excerpt)


def _normalize_indicator_type(value: Any) -> str:
    clean = _clean_string(value, 80).casefold().replace(" ", "_")
    return {
        "ip": "ipv4",
        "hostname": "domain",
        "sha-256": "sha256",
        "sha-1": "sha1",
        "filehash-sha256": "sha256",
        "filehash-sha1": "sha1",
        "filehash-md5": "md5",
        "ipv4:port": "ip:port",
        "ip_port": "ip:port",
        "ja3_hash": "ja3",
        "ja3s_hash": "ja3s",
        "ja4-ssh": "ja4ssh",
        "ja4_ssh": "ja4ssh",
    }.get(clean, clean)


def _indicator_value_valid(value: str, indicator_type: str) -> bool:
    clean = _clean_string(value, 2_000)
    kind = _normalize_indicator_type(indicator_type)
    if not clean or any(ord(character) < 32 for character in clean):
        return False
    if kind in {"ipv4", "ipv6"}:
        try:
            address = ipaddress.ip_address(clean)
        except ValueError:
            return False
        return address.version == (4 if kind == "ipv4" else 6)
    if kind == "ip:port":
        match = re.fullmatch(r"(?:\[([^]]+)\]|([^:]+)):(\d{1,5})", clean)
        if match is None:
            return False
        try:
            ipaddress.ip_address(match.group(1) or match.group(2))
        except ValueError:
            return False
        return 1 <= int(match.group(3)) <= 65_535
    if kind == "domain":
        return len(clean) <= 253 and _DOMAIN_VALUE.fullmatch(clean.rstrip(".")) is not None
    if kind == "url":
        try:
            parsed = urlsplit(clean)
            _ = parsed.port
        except ValueError:
            return False
        return parsed.scheme.casefold() in {"http", "https"} and bool(parsed.hostname) and not any(
            character.isspace() for character in clean
        )
    if kind == "email":
        return _EMAIL_VALUE.fullmatch(clean) is not None
    if kind in {"md5", "ja3", "ja3s"}:
        return re.fullmatch(r"[A-Fa-f0-9]{32}", clean) is not None
    if kind == "sha1":
        return re.fullmatch(r"[A-Fa-f0-9]{40}", clean) is not None
    if kind == "sha256":
        return re.fullmatch(r"[A-Fa-f0-9]{64}", clean) is not None
    if kind in {"ja4", "ja4s", "ja4h", "ja4l", "ja4ls", "ja4x", "ja4ssh", "ja4t"}:
        return _NETWORK_FINGERPRINT.fullmatch(clean) is not None
    return False


def claim_acceptance_errors(claim: ReportReviewClaim, context: ReviewContext) -> list[str]:
    """Return deterministic blockers for an accepted claim."""

    errors: list[str] = []
    if claim.claim_type not in CLAIM_TYPES:
        return ["unsupported_claim_type"]
    if not claim.statement.strip() or not claim.object.strip():
        errors.append("claim_is_not_specific")
    normalized_refs = _normalize_evidence_refs(claim.evidence_refs, context)
    if claim.claim_type in _TEXT_CLAIM_TYPES and not _has_text_evidence(claim, context):
        errors.append("claim_not_source_bound")
    if claim.claim_type == "procedure":
        if not _ATTACK_ID.fullmatch(claim.attack_id or ""):
            errors.append("procedure_attack_id_invalid")
        if (claim.claim_metadata or {}).get("llm_verified") is not True:
            errors.append("procedure_attack_id_not_catalog_verified")
        procedure_text = f"{claim.predicate} {claim.statement}"
        if not claim.predicate.strip() or not _PROCEDURE_ACTION.search(procedure_text):
            errors.append("procedure_is_tool_or_label_only")
    if claim.claim_type == "actor":
        basis = _clean_string((claim.claim_metadata or {}).get("attribution_basis"), 50)
        if basis not in {"explicit", "source_reported"}:
            errors.append("actor_attribution_is_inferred")
        if not claim.actor_id.strip():
            errors.append("actor_identifier_missing")
        actor_id = _clean_string(claim.actor_id, 120)
        metadata = claim.claim_metadata or {}
        if not _GROUP_ID.fullmatch(actor_id) and (
            len(actor_id) < 3
            or len(re.sub(r"[^A-Za-z0-9]", "", actor_id)) < 3
        ):
            errors.append("actor_identifier_too_short")
        if _GROUP_ID.fullmatch(actor_id) and metadata.get("catalog_verified") is not True:
            errors.append("actor_catalog_identifier_unverified")
        if not _GROUP_ID.fullmatch(actor_id) and claim.object.casefold() != actor_id.casefold():
            errors.append("actor_object_identifier_mismatch")
        actor_evidence = _claim_text_evidence(claim, context)
        actor_names = [actor_id]
        catalog_name = _clean_string(metadata.get("catalog_name"), 255)
        if catalog_name:
            actor_names.append(catalog_name)
        catalog_aliases = metadata.get("catalog_aliases")
        if isinstance(catalog_aliases, list):
            actor_names.extend(_clean_string(value, 255) for value in catalog_aliases[:50])
        if actor_id and not any(
            _exact_phrase_in_evidence(name, actor_evidence)
            for name in actor_names
            if name
        ):
            errors.append("actor_not_named_in_evidence")
        if re.search(r"\b(?:not attributed|no attribution|cannot attribute|unconfirmed|misattributed)\b", actor_evidence, re.IGNORECASE):
            errors.append("actor_evidence_is_negated")
    if claim.claim_type == "indicator":
        indicator_type = _normalize_indicator_type(
            (claim.claim_metadata or {}).get("indicator_type")
            or (claim.claim_metadata or {}).get("type")
        )
        if not _indicator_value_valid(claim.object, indicator_type):
            errors.append("indicator_value_or_type_invalid")
        if not _exact_value_in_evidence(claim.object, _claim_text_evidence(claim, context)):
            errors.append("indicator_not_named_in_evidence")
    if claim.claim_type == "vulnerability":
        vulnerability_id = _clean_string(claim.object, 100)
        if _CVE_ID.fullmatch(vulnerability_id) is None:
            errors.append("vulnerability_identifier_invalid")
        if not _exact_value_in_evidence(vulnerability_id, _claim_text_evidence(claim, context)):
            errors.append("vulnerability_not_named_in_evidence")
    if claim.claim_type == "publication_date":
        object_value = _clean_string(claim.object, 100)
        metadata_candidate = _clean_string((claim.claim_metadata or {}).get("date_candidate"), 100)
        candidate = _parse_iso_calendar_date(object_value)
        if candidate is None:
            errors.append("publication_date_invalid")
        if metadata_candidate and metadata_candidate != object_value:
            errors.append("publication_date_candidate_mismatch")
        if candidate is not None and candidate > _source_acquisition_date(context):
            errors.append("publication_date_after_acquisition")
        publication_bound = False
        if candidate is not None:
            for ref in normalized_refs:
                if ref.get("kind") == "source_text" and _text_supports_publication_date(
                    str(ref.get("excerpt") or ""),
                    candidate,
                ):
                    publication_bound = True
                    break
                if ref.get("kind") in _METADATA_EVIDENCE_KINDS and str(ref.get("value") or "") == object_value:
                    publication_bound = True
                    break
        if not publication_bound:
            errors.append("publication_date_not_source_bound")
    return list(dict.fromkeys(errors))


async def update_gate(
    db: AsyncSession,
    session_id: uuid.UUID,
    gate_key: str,
    actor: ReviewActor,
    *,
    expected_version: int,
    verdict: str,
    reason_code: str,
    rationale: str = "",
    evidence_refs: list[dict[str, Any]] | None = None,
) -> ReportReview:
    if gate_key not in GATE_KEYS:
        raise ReviewValidationError("Unknown report review gate")
    if verdict not in set(ANALYST_VERDICTS) - {"pending"}:
        raise ReviewValidationError("Analyst verdict is invalid")
    definition = GATE_CATALOG[gate_key]
    if reason_code not in definition["reason_codes"]:
        raise ReviewValidationError(f"Reason code is invalid for {gate_key}")
    allowed_for_verdict = GATE_REASON_CODES_BY_VERDICT[gate_key].get(verdict, set())
    if reason_code not in allowed_for_verdict:
        raise ReviewValidationError(
            f"Reason code {reason_code} contradicts verdict {verdict} for {gate_key}"
        )

    review = await _latest_review(db, session_id, lock=True)
    if review is None:
        raise ReviewNotFoundError("Start a report review before recording gate decisions")
    _assert_version(review, expected_version)
    if review.state not in _EDITABLE_STATES:
        raise ReviewStateError(f"Gate decisions cannot be edited while review state is {review.state}")
    context = await load_review_context(db, session_id)
    _assert_current(review, context)
    gates, _ = await _review_rows(db, review.id, lock=True)
    gate = next((item for item in gates if item.gate_key == gate_key), None)
    if gate is None:
        raise ReviewNotFoundError("Review gate record is missing")

    if verdict == "not_applicable":
        allowed = gate_key == "actor_identification" and reason_code == "no_actor_claim"
        allowed = allowed or (
            review.profile == "internal_ir"
            and gate_key == "publication_date"
            and reason_code == "internal_record_no_publication"
        )
        if not allowed:
            raise ReviewValidationError("This gate cannot be marked not applicable under the selected profile")
    clean_rationale = _clean_string(rationale, 4_000)
    if len(clean_rationale) < 8:
        raise ReviewValidationError("A specific analyst rationale of at least 8 characters is required")
    normalized_refs = _normalize_evidence_refs(evidence_refs, context)

    gate.analyst_verdict = verdict
    gate.reason_code = reason_code
    gate.rationale = clean_rationale
    gate.evidence_refs = normalized_refs
    gate.reviewed_by = actor.name
    gate.reviewed_by_id = actor.actor_id
    gate.reviewed_at = _utcnow()
    gate.updated_at = gate.reviewed_at
    _touch(review, now=gate.reviewed_at)
    _add_event(
        db,
        review,
        actor,
        "gate_decision_recorded",
        {"gate_key": gate_key, "verdict": verdict, "reason_code": reason_code, "evidence_ref_count": len(normalized_refs)},
    )
    await db.flush()
    return review


async def update_claim(
    db: AsyncSession,
    session_id: uuid.UUID,
    claim_id: uuid.UUID,
    actor: ReviewActor,
    *,
    expected_version: int,
    status: str,
    rationale: str = "",
    evidence_refs: list[dict[str, Any]] | None = None,
) -> ReportReview:
    if status not in CLAIM_STATUSES:
        raise ReviewValidationError("Claim status is invalid")
    review = await _latest_review(db, session_id, lock=True)
    if review is None:
        raise ReviewNotFoundError("Start a report review before adjudicating claims")
    _assert_version(review, expected_version)
    if review.state not in _EDITABLE_STATES:
        raise ReviewStateError(f"Claims cannot be edited while review state is {review.state}")
    context = await load_review_context(db, session_id)
    _assert_current(review, context)
    _, claims = await _review_rows(db, review.id, lock=True)
    claim = next((item for item in claims if item.id == claim_id), None)
    if claim is None:
        raise ReviewNotFoundError("Review claim not found")

    clean_rationale = _clean_string(rationale, 4_000)
    if status in {"accepted", "rejected", "needs_evidence"} and len(clean_rationale) < 8:
        raise ReviewValidationError("A specific analyst rationale of at least 8 characters is required")
    if evidence_refs is not None:
        claim.evidence_refs = _normalize_evidence_refs(evidence_refs, context)
        source_ref = next((item for item in claim.evidence_refs if item.get("kind") == "source_text"), None)
        if source_ref:
            claim.evidence_text = source_ref["excerpt"]
            claim.evidence_start = source_ref["evidence_start"]
            claim.evidence_end = source_ref["evidence_end"]
    if status == "accepted":
        errors = claim_acceptance_errors(claim, context)
        if errors:
            raise ReviewValidationError(
                "Claim cannot be accepted until its deterministic checks pass",
                details={"claim_id": str(claim.id), "blockers": errors},
            )

    claim.status = status
    claim.rationale = clean_rationale
    claim.reason_code = {
        "accepted": "analyst_accepted",
        "rejected": "analyst_rejected",
        "needs_evidence": "analyst_needs_evidence",
        "suggested": "",
    }[status]
    claim.reviewed_by = actor.name if status != "suggested" else ""
    claim.reviewed_by_id = actor.actor_id if status != "suggested" else ""
    claim.reviewed_at = _utcnow() if status != "suggested" else None
    claim.updated_at = _utcnow()
    _touch(review, now=claim.updated_at)
    _add_event(
        db,
        review,
        actor,
        "claim_decision_recorded",
        {"claim_id": str(claim.id), "claim_type": claim.claim_type, "status": status},
    )
    await db.flush()
    return review


async def create_claim(
    db: AsyncSession,
    session_id: uuid.UUID,
    actor: ReviewActor,
    *,
    expected_version: int,
    claim_type: str,
    subject: str,
    predicate: str,
    object_value: str,
    statement: str,
    attack_id: str = "",
    actor_id: str = "",
    rationale: str = "",
    evidence_refs: list[dict[str, Any]] | None = None,
    metadata: dict[str, Any] | None = None,
) -> tuple[ReportReview, ReportReviewClaim]:
    """Add a human-authored candidate without implicitly accepting it."""

    if claim_type not in CLAIM_TYPES:
        raise ReviewValidationError(f"Claim type must be one of: {', '.join(CLAIM_TYPES)}")
    review = await _latest_review(db, session_id, lock=True)
    if review is None:
        raise ReviewNotFoundError("Start a report review before adding claims")
    _assert_version(review, expected_version)
    if review.state not in _EDITABLE_STATES:
        raise ReviewStateError(f"Claims cannot be added while review state is {review.state}")
    context = await load_review_context(db, session_id)
    _assert_current(review, context)
    gates, claims = await _review_rows(db, review.id, lock=True)

    clean_subject = _clean_string(subject, 500)
    clean_predicate = _clean_string(predicate, 255)
    clean_object = _clean_string(object_value, 8_000)
    clean_statement = _clean_string(statement, 8_000)
    clean_attack_id = _clean_string(attack_id, 30).upper()
    clean_actor_id = _clean_string(actor_id, 120)
    if _GROUP_ID.fullmatch(clean_actor_id):
        clean_actor_id = clean_actor_id.upper()
    clean_rationale = _clean_string(rationale, 4_000)
    if not clean_subject or not clean_predicate or not clean_object or len(clean_statement) < 8:
        raise ReviewValidationError("A claim requires a subject, action, object, and specific statement")
    if claim_type == "procedure" and not _ATTACK_ID.fullmatch(clean_attack_id):
        raise ReviewValidationError("A procedure claim requires a valid ATT&CK or ATLAS technique ID")
    if claim_type == "actor" and not clean_actor_id:
        raise ReviewValidationError("An actor claim requires an actor identifier or exact source-reported name")
    if claim_type == "actor" and not _GROUP_ID.fullmatch(clean_actor_id):
        if len(clean_actor_id) < 3 or len(re.sub(r"[^A-Za-z0-9]", "", clean_actor_id)) < 3:
            raise ReviewValidationError("A source-reported actor name must contain at least three meaningful characters")
        if clean_object.casefold() != clean_actor_id.casefold():
            raise ReviewValidationError("A source-reported actor claim object must equal the actor name")
    if claim_type == "vulnerability" and _CVE_ID.fullmatch(clean_object) is None:
        raise ReviewValidationError("A vulnerability claim requires a valid CVE identifier")
    if claim_type == "publication_date":
        if _parse_iso_calendar_date(clean_object) is None:
            raise ReviewValidationError("A publication-date claim requires an ISO calendar date")

    normalized_refs = _normalize_evidence_refs(evidence_refs, context)
    claim_metadata = _bounded_json(metadata or {})
    if not isinstance(claim_metadata, dict):
        claim_metadata = {}
    if claim_type == "procedure":
        catalog_match = await db.scalar(
            select(Technique.attack_id)
            .where(
                Technique.attack_id == clean_attack_id,
                Technique.domain == context.session.domain,
                Technique.is_deprecated.is_(False),
            )
            .limit(1)
        )
        claim_metadata["llm_verified"] = bool(catalog_match)
        if not catalog_match:
            raise ReviewValidationError("Technique ID is not present in the active local ATT&CK catalog")
    if claim_type == "actor":
        basis = _clean_string(claim_metadata.get("attribution_basis"), 50)
        if basis not in {"explicit", "source_reported", "inferred", "tooling_overlap_only", "none", "conflicting"}:
            raise ReviewValidationError("Actor claim metadata requires an explicit attribution_basis")
        for key in ("catalog_verified", "catalog_name", "catalog_aliases", "catalog_url"):
            claim_metadata.pop(key, None)
        claim_metadata["attribution_basis"] = basis
        if _GROUP_ID.fullmatch(clean_actor_id):
            catalog = await _catalog_actors(db, context.session.domain, [clean_actor_id])
            group = catalog.get(clean_actor_id)
            if group is None:
                raise ReviewValidationError("Actor ID is not present in the active local ATT&CK catalog")
            candidate_metadata = {"metadata": claim_metadata}
            _apply_catalog_actor_metadata(candidate_metadata, group)
            claim_metadata = candidate_metadata["metadata"]
    if claim_type == "publication_date":
        claim_metadata["date_candidate"] = clean_object
        claim_metadata.setdefault("date_source", "analyst-source-bound")
        claim_metadata["publication_date_candidates"] = [clean_object]
    if claim_type == "indicator":
        claim_metadata["value"] = clean_object
        indicator_type = _normalize_indicator_type(
            claim_metadata.get("indicator_type") or claim_metadata.get("type")
        )
        if not _indicator_value_valid(clean_object, indicator_type):
            raise ReviewValidationError("Indicator value does not match a supported indicator type")
        claim_metadata["indicator_type"] = indicator_type

    source_ref = next((item for item in normalized_refs if item.get("kind") == "source_text"), None)
    key = _claim_key(claim_type, clean_subject, clean_predicate, clean_object, clean_statement, clean_attack_id, clean_actor_id)
    duplicate = next((claim for claim in claims if claim.claim_key == key), None)
    if duplicate is not None:
        raise ReviewConflictError("An equivalent claim already exists", details={"claim_id": str(duplicate.id)})

    now = _utcnow()
    claim = ReportReviewClaim(
        id=uuid.uuid4(),
        review_id=review.id,
        claim_key=key,
        claim_type=claim_type,
        subject=clean_subject,
        predicate=clean_predicate,
        object=clean_object,
        statement=clean_statement,
        attack_id=clean_attack_id,
        actor_id=clean_actor_id,
        evidence_text=source_ref.get("excerpt", "") if source_ref else "",
        evidence_start=source_ref.get("evidence_start") if source_ref else None,
        evidence_end=source_ref.get("evidence_end") if source_ref else None,
        extraction_method="analyst-created",
        status="suggested",
        reason_code="",
        rationale=clean_rationale,
        evidence_refs=normalized_refs,
        claim_metadata=claim_metadata,
        reviewed_by="",
        reviewed_by_id="",
        created_at=now,
        updated_at=now,
    )
    db.add(claim)
    _mark_preflight_stale(gates, "analyst_claim_created", now=now)
    _touch(review, now=now)
    _add_event(
        db,
        review,
        actor,
        "claim_created",
        {"claim_id": str(claim.id), "claim_type": claim_type, "extraction_method": "analyst-created"},
    )
    await db.flush()
    return review, claim


def _gate_map(gates: list[ReportReviewGate]) -> dict[str, ReportReviewGate]:
    return {gate.gate_key: gate for gate in gates}


def _mark_preflight_stale(gates: list[ReportReviewGate], reason: str, *, now: datetime) -> None:
    for gate in gates:
        details = dict(gate.machine_details or {})
        advisory = details.get("ai_advisory")
        gate.machine_verdict = "not_run"
        gate.machine_details = {"summary": "Deterministic preflight must be rerun.", "stale_reason": reason}
        if advisory:
            gate.machine_details["ai_advisory"] = advisory
        gate.machine_evidence_refs = []
        gate.machine_evaluator = ""
        gate.machine_evaluated_at = None
        gate.updated_at = now


def review_readiness(
    review: ReportReview,
    gates: list[ReportReviewGate],
    claims: list[ReportReviewClaim],
    context: ReviewContext,
) -> dict[str, Any]:
    blockers: list[str] = []
    stale_reasons: list[str] = []
    if review.state in {"stale", "rejected", "revoked"}:
        blockers.append(f"review_state_{review.state}")
    if review.source_checksum != context.source_checksum:
        stale_reasons.append("source_checksum_changed")
    if review.analysis_checksum != context.analysis_checksum:
        stale_reasons.append("analysis_checksum_changed")
    blockers.extend(stale_reasons)
    if review.policy_version != POLICY_VERSION:
        blockers.append("policy_version_stale")
    if not review.coverage_complete and not review.coverage_exception_reason:
        blockers.append("source_analysis_coverage_incomplete")

    by_key = _gate_map(gates)
    accepted = [claim for claim in claims if claim.status == "accepted"]
    accepted_procedures = [claim for claim in accepted if claim.claim_type == "procedure"]
    accepted_dates = [claim for claim in accepted if claim.claim_type == "publication_date"]
    accepted_actors = [claim for claim in accepted if claim.claim_type == "actor"]
    for gate_key in GATE_KEYS:
        gate = by_key.get(gate_key)
        if gate is None:
            blockers.append(f"gate_missing:{gate_key}")
            continue
        if (
            gate.machine_verdict == "not_run"
            or not gate.machine_evaluated_at
            or not gate.machine_evaluator.startswith("deterministic:")
        ):
            blockers.append(f"deterministic_preflight_required:{gate_key}")
        if gate.analyst_verdict == "pending":
            blockers.append(f"gate_pending:{gate_key}")
        elif gate.analyst_verdict == "needs_information":
            blockers.append(f"gate_needs_information:{gate_key}")
        elif gate.analyst_verdict == "fail":
            blockers.append(f"gate_failed:{gate_key}")
        elif gate.analyst_verdict == "not_applicable":
            allowed = gate_key == "actor_identification" and gate.reason_code == "no_actor_claim"
            allowed = allowed or (
                review.profile == "internal_ir"
                and gate_key == "publication_date"
                and gate.reason_code == "internal_record_no_publication"
            )
            if not allowed:
                blockers.append(f"gate_not_applicable_disallowed:{gate_key}")
        elif gate.analyst_verdict == "pass":
            has_verified_evidence = bool(_normalize_evidence_refs(gate.evidence_refs, context))
            if gate_key in {"procedure_relevance", "procedure_level_claim"}:
                has_verified_evidence = bool(accepted_procedures)
            elif gate_key == "publication_date":
                has_verified_evidence = bool(accepted_dates)
            elif gate_key == "actor_identification":
                has_verified_evidence = bool(accepted_actors)
            if not has_verified_evidence:
                blockers.append(f"gate_verified_evidence_required:{gate_key}")

    unresolved = [claim for claim in claims if claim.status in {"suggested", "needs_evidence"}]
    if unresolved:
        blockers.append(f"claims_unresolved:{len(unresolved)}")
    invalid_accepted: list[str] = []
    for claim in accepted:
        if claim_acceptance_errors(claim, context):
            invalid_accepted.append(str(claim.id))
    if invalid_accepted:
        blockers.append(f"accepted_claims_invalid:{len(invalid_accepted)}")

    if not accepted_procedures:
        blockers.append("accepted_procedure_claim_required")
    publication_gate = by_key.get("publication_date")
    publication_na = bool(publication_gate and publication_gate.analyst_verdict == "not_applicable")
    if publication_na and accepted_dates:
        blockers.append("accepted_publication_date_conflicts_with_not_applicable_gate")
    if not publication_na and not accepted_dates:
        blockers.append("accepted_publication_date_claim_required")
    actor_gate = by_key.get("actor_identification")
    if actor_gate and actor_gate.analyst_verdict == "not_applicable" and accepted_actors:
        blockers.append("accepted_actor_claim_conflicts_with_no_actor_claim")
    if actor_gate and actor_gate.analyst_verdict == "pass" and not accepted_actors:
        blockers.append("accepted_actor_claim_required_for_pass")

    required_gate_count = sum(1 for gate in gates if gate.required)
    reviewed_gate_count = sum(1 for gate in gates if gate.required and gate.analyst_verdict != "pending")
    return {
        "ready": not blockers,
        "blockers": list(dict.fromkeys(blockers)),
        "accepted_claim_count": len(accepted),
        "required_gate_count": required_gate_count,
        "reviewed_gate_count": reviewed_gate_count,
        "failed_gate_count": sum(1 for gate in gates if gate.required and gate.analyst_verdict == "fail"),
        "pending_claim_count": len(unresolved),
        "stale_reasons": stale_reasons,
    }


def _assessment_complete(gates: list[ReportReviewGate], claims: list[ReportReviewClaim]) -> tuple[bool, list[str]]:
    blockers = [f"gate_pending:{gate.gate_key}" for gate in gates if gate.required and gate.analyst_verdict == "pending"]
    blockers.extend(f"claim_unresolved:{claim.id}" for claim in claims if claim.status == "suggested")
    return not blockers, blockers


async def run_preflight(
    db: AsyncSession,
    session_id: uuid.UUID,
    actor: ReviewActor,
    *,
    expected_version: int,
) -> ReportReview:
    review = await _latest_review(db, session_id, lock=True)
    if review is None:
        raise ReviewNotFoundError("Start a report review before running preflight")
    _assert_version(review, expected_version)
    if review.state not in _EDITABLE_STATES:
        raise ReviewStateError(f"Preflight cannot run while review state is {review.state}")
    context = await load_review_context(db, session_id)
    _assert_current(review, context)
    gates, claims = await _review_rows(db, review.id, lock=True)
    try:
        from app.services.report_review_preflight import evaluate_report_preflight
    except ImportError as exc:
        raise ReviewValidationError("Deterministic report preflight is not installed") from exc

    findings = evaluate_report_preflight(
        source_text=context.source_text,
        source_metadata=context.source_metadata,
        claims=[_claim_dict(claim) for claim in claims],
        context={
            "profile": review.profile,
            "source_text_sha256": checksum_text(context.source_text),
            "source_checksum": review.source_checksum,
            "analyzed_char_count": review.analyzed_char_count,
            "coverage_complete": review.coverage_complete,
            # Similarity is exposed only so deterministic attribution checks can
            # flag overlap-only reasoning; it is never promoted as a claim.
            "apt_matches": list(context.result.apt_matches or []) if context.result else [],
            "publication_date_candidates": context.source_metadata.get("publication_date_candidates") or [],
        },
    )
    if not isinstance(findings, dict):
        raise ReviewValidationError("Deterministic preflight returned an invalid result")
    for gate in gates:
        finding = findings.get(gate.gate_key) if isinstance(findings.get(gate.gate_key), dict) else {}
        verdict = _clean_string(finding.get("machine_verdict"), 30)
        if verdict not in MACHINE_VERDICTS:
            verdict = "warning"
        previous_details = gate.machine_details if isinstance(gate.machine_details, dict) else {}
        details = _bounded_json(finding.get("details") if isinstance(finding.get("details"), dict) else {})
        if previous_details.get("ai_advisory"):
            details["ai_advisory"] = previous_details["ai_advisory"]
        gate.machine_verdict = verdict
        gate.machine_details = details
        gate.machine_evidence_refs = _bounded_json(finding.get("evidence_refs") if isinstance(finding.get("evidence_refs"), list) else [])
        gate.machine_evaluator = _clean_string(finding.get("evaluator"), 100) or "deterministic-preflight"
        gate.machine_evaluated_at = _utcnow()
        gate.updated_at = gate.machine_evaluated_at
    _touch(review)
    _add_event(
        db,
        review,
        actor,
        "deterministic_preflight_completed",
        {"evaluator_count": len({gate.machine_evaluator for gate in gates}), "authoritative": False},
    )
    await db.flush()
    return review


async def apply_ai_advisory(
    db: AsyncSession,
    session_id: uuid.UUID,
    actor: ReviewActor,
    *,
    expected_version: int,
    expected_source_checksum: str,
    expected_analysis_checksum: str,
    suggestions: dict[str, Any],
) -> tuple[ReportReview, int]:
    """Persist only revalidated AI candidates and a namespaced advisory.

    This function runs after the provider call.  It reacquires the review lock
    and checks the optimistic token and both content fingerprints, preventing
    an expensive response for an old source from being attached to a newer
    revision.
    """

    review = await _latest_review(db, session_id, lock=True)
    if review is None:
        raise ReviewNotFoundError("Review not found")
    _assert_version(review, expected_version)
    if review.state not in _EDITABLE_STATES:
        raise ReviewStateError(f"AI suggestions cannot be attached while review state is {review.state}")
    context = await load_review_context(db, session_id)
    _assert_current(review, context)
    if review.source_checksum != expected_source_checksum or review.analysis_checksum != expected_analysis_checksum:
        raise ReviewConflictError("Source or analysis changed while AI assistance was running")
    gates, claims = await _review_rows(db, review.id, lock=True)
    existing_keys = {claim.claim_key for claim in claims}

    parts = suggestions.get("parts") if isinstance(suggestions.get("parts"), list) else []
    procedure_items = [
        item
        for part in parts[:10]
        if isinstance(part, dict)
        for item in list(part.get("procedure_claims") or [])[:20]
        if isinstance(item, dict)
    ]
    requested_attack_ids = {
        _clean_string(item.get("attack_id"), 30).upper()
        for item in procedure_items
        if _ATTACK_ID.fullmatch(_clean_string(item.get("attack_id"), 30))
    }
    verified_attack_ids: set[str] = set()
    if requested_attack_ids:
        verified_rows = await db.execute(
            select(Technique.attack_id).where(
                Technique.attack_id.in_(requested_attack_ids),
                Technique.domain == context.session.domain,
                Technique.is_deprecated.is_(False),
            )
        )
        verified_attack_ids = {str(item).upper() for item in verified_rows.scalars().all()}

    requested_actor_ids = {
        _clean_string(actor.get("actor_name"), 20).upper()
        for part in parts[:10]
        if isinstance(part, dict)
        for actor in [part.get("actor_identification")]
        if isinstance(actor, dict)
        and _GROUP_ID.fullmatch(_clean_string(actor.get("actor_name"), 20))
    }
    verified_actors = await _catalog_actors(db, context.session.domain, requested_actor_ids)

    now = _utcnow()
    added: list[ReportReviewClaim] = []

    def add_candidate(candidate: dict[str, Any]) -> None:
        if candidate["claim_key"] in existing_keys:
            return
        claim = _new_claim(review.id, candidate, now=now)
        db.add(claim)
        added.append(claim)
        existing_keys.add(candidate["claim_key"])

    for item in procedure_items:
        evidence_value = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
        bound = _source_ref(
            context.source_text,
            evidence_value.get("quote"),
            evidence_value.get("start"),
            evidence_value.get("end"),
        )
        action = _clean_string(item.get("action"), 255)
        object_value = _clean_string(item.get("object"), 8_000)
        attack_id = _clean_string(item.get("attack_id"), 30).upper()
        if bound is None or len(action) < 3 or len(object_value) < 2:
            continue
        statement = _clean_string(
            " ".join(
                clean
                for value in (item.get("subject"), action, object_value, item.get("context"))
                for clean in [_clean_string(value, 2_000)]
                if clean
            ),
            8_000,
        )
        add_candidate(
            {
                "claim_key": _claim_key("procedure", attack_id, statement, bound["excerpt"]),
                "claim_type": "procedure",
                "subject": _clean_string(item.get("subject"), 500) or "report-described adversary",
                "predicate": action,
                "object": object_value,
                "statement": statement,
                "attack_id": attack_id,
                "actor_id": "",
                "evidence_text": bound["excerpt"],
                "evidence_start": bound["evidence_start"],
                "evidence_end": bound["evidence_end"],
                "evidence_refs": [bound],
                "extraction_method": "ai-advisory-source-bound",
                "metadata": {
                    "llm_verified": attack_id in verified_attack_ids,
                    "provider": _clean_string(suggestions.get("provider"), 40),
                    "model": _clean_string(suggestions.get("model"), 160),
                    "prompt_version": _clean_string(suggestions.get("prompt_version"), 100),
                    "authoritative": False,
                },
            }
        )

    for part in parts[:10]:
        if not isinstance(part, dict):
            continue
        for item in list(part.get("publication_date_candidates") or [])[:10]:
            if not isinstance(item, dict):
                continue
            evidence_value = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
            bound = _source_ref(
                context.source_text,
                evidence_value.get("quote"),
                evidence_value.get("start"),
                evidence_value.get("end"),
            )
            date_value = _clean_string(item.get("value"), 100)
            try:
                date.fromisoformat(date_value[:10])
            except ValueError:
                continue
            if bound is None:
                continue
            add_candidate(
                {
                    "claim_key": _claim_key("publication_date", date_value, bound["excerpt"]),
                    "claim_type": "publication_date",
                    "subject": "report",
                    "predicate": "published on",
                    "object": date_value,
                    "statement": f"The report publication date is {date_value}.",
                    "attack_id": "",
                    "actor_id": "",
                    "evidence_text": bound["excerpt"],
                    "evidence_start": bound["evidence_start"],
                    "evidence_end": bound["evidence_end"],
                    "evidence_refs": [bound],
                    "extraction_method": "ai-advisory-source-bound",
                    "metadata": {
                        "date_candidate": date_value,
                        "date_source": "ai-advisory-source-bound",
                        "publication_date_candidates": [date_value],
                        "authoritative": False,
                    },
                }
            )

        actor = part.get("actor_identification") if isinstance(part.get("actor_identification"), dict) else {}
        actor_name = _clean_string(actor.get("actor_name"), 120)
        if _GROUP_ID.fullmatch(actor_name):
            actor_name = actor_name.upper()
        basis = _clean_string(actor.get("basis"), 50)
        actor_evidence = list(actor.get("evidence") or [])[:4]
        bound_actor = next(
            (
                bound
                for item in actor_evidence
                if isinstance(item, dict)
                for bound in [
                    _source_ref(context.source_text, item.get("quote"), item.get("start"), item.get("end"))
                ]
                if bound is not None
            ),
            None,
        )
        if actor_name and basis in {"explicit", "source_reported", "inferred", "tooling_overlap_only", "conflicting"} and bound_actor:
            actor_candidate = {
                    "claim_key": _claim_key("actor", actor_name, basis, bound_actor["excerpt"]),
                    "claim_type": "actor",
                    "subject": "report",
                    "predicate": "attributes activity to",
                    "object": actor_name,
                    "statement": f"The source identifies {actor_name} as the responsible actor.",
                    "attack_id": "",
                    "actor_id": actor_name,
                    "evidence_text": bound_actor["excerpt"],
                    "evidence_start": bound_actor["evidence_start"],
                    "evidence_end": bound_actor["evidence_end"],
                    "evidence_refs": [bound_actor],
                    "extraction_method": "ai-advisory-source-bound",
                    "metadata": {"attribution_basis": basis, "authoritative": False},
                }
            if _GROUP_ID.fullmatch(actor_name):
                _apply_catalog_actor_metadata(actor_candidate, verified_actors.get(actor_name))
            add_candidate(actor_candidate)

    # The deterministic fields are preserved; only a bounded advisory
    # namespace is merged into machine_details.
    try:
        from app.services.report_review_preflight import merge_ai_advisory
    except ImportError:
        merge_ai_advisory = None
    if merge_ai_advisory is not None:
        preflight = {
            gate.gate_key: {
                "machine_verdict": gate.machine_verdict,
                "details": gate.machine_details or {},
                "evidence_refs": gate.machine_evidence_refs or [],
                "evaluator": gate.machine_evaluator,
            }
            for gate in gates
        }
        merged = merge_ai_advisory(preflight, suggestions)
        for gate in gates:
            merged_gate = merged.get(gate.gate_key) if isinstance(merged.get(gate.gate_key), dict) else {}
            details = merged_gate.get("details") if isinstance(merged_gate.get("details"), dict) else gate.machine_details
            gate.machine_details = _bounded_json(details or {})
            gate.updated_at = now

    complete_coverage = (
        suggestions.get("complete_coverage") is True
        and int(suggestions.get("coverage_chars") or 0) >= len(context.source_text)
        and int(suggestions.get("source_chars") or -1) == len(context.source_text)
        and len(parts) > 0
    )
    coverage_changed = complete_coverage and not review.coverage_complete
    if complete_coverage:
        review.analyzed_char_count = len(context.source_text)
        review.coverage_complete = True
        review.coverage_exception_reason = ""
        review.coverage_exception_by = ""
        review.coverage_exception_by_id = ""
        review.coverage_exception_at = None

    if added or coverage_changed:
        _mark_preflight_stale(gates, "ai_candidates_or_coverage_changed", now=now)

    _touch(review, now=now)
    _add_event(
        db,
        review,
        actor,
        "ai_advisory_attached",
        {
            "provider": _clean_string(suggestions.get("provider"), 40),
            "model": _clean_string(suggestions.get("model"), 160),
            "prompt_version": _clean_string(suggestions.get("prompt_version"), 100),
            "suggested_claim_count": len(added),
            "complete_coverage": complete_coverage,
            "authoritative": False,
        },
    )
    await db.flush()
    return review, len(added)


async def submit_review(
    db: AsyncSession,
    session_id: uuid.UUID,
    actor: ReviewActor,
    *,
    expected_version: int,
) -> ReportReview:
    review = await _latest_review(db, session_id, lock=True)
    if review is None:
        raise ReviewNotFoundError("Start a report review before submitting it")
    _assert_version(review, expected_version)
    if review.state not in _EDITABLE_STATES:
        raise ReviewStateError(f"Review cannot be submitted from state {review.state}")
    context = await load_review_context(db, session_id)
    _assert_current(review, context)
    gates, claims = await _review_rows(db, review.id, lock=True)
    complete, incomplete = _assessment_complete(gates, claims)
    if not complete:
        raise ReviewValidationError("Complete every gate and adjudicate every claim before submission", details={"blockers": incomplete})
    readiness = review_readiness(review, gates, claims, context)
    from_state = review.state
    review.state = "in_review" if readiness["ready"] else "changes_requested"
    now = _utcnow()
    review.submitted_by = actor.name
    review.submitted_by_id = actor.actor_id
    review.submitted_at = now
    _touch(review, now=now)
    _add_event(
        db,
        review,
        actor,
        "review_submitted" if readiness["ready"] else "review_changes_required",
        {"from_state": from_state, "to_state": review.state, "blockers": readiness["blockers"]},
    )
    await db.flush()
    return review


async def approve_review(
    db: AsyncSession,
    session_id: uuid.UUID,
    actor: ReviewActor,
    *,
    expected_version: int,
    decision_note: str = "",
) -> ReportReview:
    review = await _latest_review(db, session_id, lock=True)
    if review is None:
        raise ReviewNotFoundError("Review not found")
    _assert_version(review, expected_version)
    if review.state != "in_review":
        raise ReviewStateError(f"Only an in-review assessment can be approved; current state is {review.state}")
    if actor.actor_id and review.submitted_by_id and actor.actor_id == review.submitted_by_id:
        raise ReviewValidationError("Four-eyes policy requires approval by a different authorized human")
    context = await load_review_context(db, session_id)
    _assert_current(review, context)
    gates, claims = await _review_rows(db, review.id, lock=True)
    readiness = review_readiness(review, gates, claims, context)
    if not readiness["ready"]:
        raise ReviewValidationError("Review is not promotion-ready", details={"blockers": readiness["blockers"]})
    now = _utcnow()
    review.state = "approved"
    review.approved_by = actor.name
    review.approved_by_id = actor.actor_id
    review.approved_at = now
    _touch(review, now=now)
    _add_event(
        db,
        review,
        actor,
        "review_approved",
        {"from_state": "in_review", "to_state": "approved", "decision_note": _clean_string(decision_note, 1_000)},
    )
    await db.flush()
    return review


async def request_changes(
    db: AsyncSession,
    session_id: uuid.UUID,
    actor: ReviewActor,
    *,
    expected_version: int,
    reason: str,
) -> ReportReview:
    review = await _latest_review(db, session_id, lock=True)
    if review is None:
        raise ReviewNotFoundError("Review not found")
    _assert_version(review, expected_version)
    if review.state not in {"in_review", "approved"}:
        raise ReviewStateError(f"Changes cannot be requested from state {review.state}")
    clean_reason = _clean_string(reason, 2_000)
    if len(clean_reason) < 8:
        raise ReviewValidationError("A specific reason of at least 8 characters is required")
    from_state = review.state
    review.state = "changes_requested"
    review.approved_by = ""
    review.approved_by_id = ""
    review.approved_at = None
    _touch(review)
    _add_event(
        db,
        review,
        actor,
        "review_changes_requested",
        {"from_state": from_state, "to_state": "changes_requested", "reason": clean_reason},
    )
    await db.flush()
    return review


async def reject_review(
    db: AsyncSession,
    session_id: uuid.UUID,
    actor: ReviewActor,
    *,
    expected_version: int,
    reason: str,
) -> ReportReview:
    review = await _latest_review(db, session_id, lock=True)
    if review is None:
        raise ReviewNotFoundError("Review not found")
    _assert_version(review, expected_version)
    if review.state not in {"in_review", "changes_requested", "approved"}:
        raise ReviewStateError(f"Review cannot be rejected from state {review.state}")
    clean_reason = _clean_string(reason, 2_000)
    if len(clean_reason) < 8:
        raise ReviewValidationError("A specific rejection reason of at least 8 characters is required")
    from_state = review.state
    review.state = "rejected"
    _touch(review)
    _add_event(
        db,
        review,
        actor,
        "review_rejected",
        {"from_state": from_state, "to_state": "rejected", "reason": clean_reason},
    )
    await db.flush()
    return review


def _evidence_for_manifest(claim: ReportReviewClaim, context: ReviewContext) -> list[dict[str, Any]]:
    refs = _normalize_evidence_refs(claim.evidence_refs, context)
    direct = _source_ref(context.source_text, claim.evidence_text, claim.evidence_start, claim.evidence_end)
    if direct and not any(item.get("id") == direct["id"] for item in refs):
        refs.insert(0, direct)
    for ref in refs:
        metadata = ref.get("metadata") if isinstance(ref.get("metadata"), dict) else {}
        ref["metadata"] = {**metadata, "source_checksum": context.source_checksum, "locally_verified": True}
    return refs


def _accepted_claim_manifest(claim: ReportReviewClaim, context: ReviewContext) -> dict[str, Any]:
    metadata = _bounded_json(claim.claim_metadata or {})
    return {
        "id": str(claim.id),
        "claim_key": claim.claim_key,
        "claim_type": claim.claim_type,
        "status": "accepted",
        "subject": claim.subject,
        "predicate": claim.predicate,
        "object": claim.object,
        "value": claim.object if claim.claim_type in {"indicator", "vulnerability", "publication_date"} else "",
        "statement": claim.statement,
        "attack_id": claim.attack_id,
        "actor_id": claim.actor_id,
        "evidence_text": claim.evidence_text,
        "evidence_start": claim.evidence_start,
        "evidence_end": claim.evidence_end,
        "evidence_refs": _evidence_for_manifest(claim, context),
        "extraction_method": claim.extraction_method,
        "rationale": claim.rationale,
        "reviewed_by": claim.reviewed_by,
        "reviewed_by_id": claim.reviewed_by_id,
        "reviewed_at": claim.reviewed_at.isoformat() if claim.reviewed_at else "",
        "indicator_type": metadata.get("indicator_type", "") if isinstance(metadata, dict) else "",
        "publication_date": metadata.get("date_candidate", "") if isinstance(metadata, dict) else "",
        "metadata": metadata,
    }


def build_promotion_manifest(
    review: ReportReview,
    gates: list[ReportReviewGate],
    claims: list[ReportReviewClaim],
    context: ReviewContext,
    *,
    generated_at: datetime,
    targets: list[str] | None = None,
) -> dict[str, Any]:
    """Build the canonical accepted-only projection used by downstream modules."""

    accepted_claims = [_accepted_claim_manifest(claim, context) for claim in claims if claim.status == "accepted"]
    gate_decisions = [
        {
            "gate_key": gate.gate_key,
            "required": gate.required,
            "analyst_verdict": gate.analyst_verdict,
            "reason_code": gate.reason_code,
            "rationale": gate.rationale,
            "evidence_refs": _normalize_evidence_refs(gate.evidence_refs, context),
            "reviewed_by": gate.reviewed_by,
            "reviewed_by_id": gate.reviewed_by_id,
            "reviewed_at": gate.reviewed_at.isoformat() if gate.reviewed_at else "",
        }
        for gate in sorted(gates, key=lambda item: item.ordinal)
    ]
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "session_id": str(review.session_id),
        "review_id": str(review.id),
        "review_revision": review.revision,
        "review_version": review.version,
        "policy_version": review.policy_version,
        "profile": review.profile,
        "source_checksum": review.source_checksum,
        "analysis_checksum": review.analysis_checksum,
        "targets": list(targets or []),
        "source_char_count": review.source_char_count,
        "analyzed_char_count": review.analyzed_char_count,
        "coverage_complete": review.coverage_complete,
        "coverage_exception_reason": review.coverage_exception_reason or "",
        "coverage_exception_by": review.coverage_exception_by or None,
        "coverage_exception_at": review.coverage_exception_at.isoformat() if review.coverage_exception_at else None,
        "accepted_claims": accepted_claims,
        "gate_decisions": gate_decisions,
        "approved_by": review.approved_by,
        "approved_by_id": review.approved_by_id,
        "approved_at": review.approved_at.isoformat() if review.approved_at else "",
        "generated_at": generated_at.isoformat(),
    }


def _normalize_targets(target: str | None, targets: list[str] | None = None) -> list[str]:
    requested = [item for item in list(targets or []) if item]
    if target:
        requested.extend(target.split(","))
    if not requested:
        return ["canonical_intelligence"]
    values = sorted({_clean_string(item, 80) for item in requested if _clean_string(item, 80)})
    invalid = [item for item in values if item not in PROMOTION_TARGETS]
    if invalid:
        raise ReviewValidationError(f"Unknown promotion targets: {', '.join(invalid)}")
    if "canonical_intelligence" not in values:
        values.insert(0, "canonical_intelligence")
    return values


async def promote_review(
    db: AsyncSession,
    session_id: uuid.UUID,
    actor: ReviewActor,
    *,
    expected_version: int,
    target: str | None = None,
    targets: list[str] | None = None,
    note: str = "",
) -> tuple[ReportReview, ReportPromotion]:
    review = await _latest_review(db, session_id, lock=True)
    if review is None:
        raise ReviewNotFoundError("Review not found")
    normalized_targets = _normalize_targets(target, targets)
    if review.state == "promoted":
        retry_row = await db.execute(select(ReportPromotion).where(ReportPromotion.review_id == review.id).limit(1))
        retry_promotion = retry_row.scalar_one_or_none()
        if expected_version not in {review.version, review.version - 1}:
            _assert_version(review, expected_version)
        if retry_promotion is None:
            raise ReviewConflictError("Promoted review is missing its immutable promotion record")
        if sorted(retry_promotion.targets or []) != sorted(normalized_targets):
            raise ReviewConflictError("Promotion targets are immutable; revoke before changing them")
        context = await load_review_context(db, session_id)
        _assert_current(review, context)
        gates, claims = await _review_rows(db, review.id, lock=True)
        readiness = review_readiness(review, gates, claims, context)
        if not readiness["ready"]:
            raise ReviewValidationError(
                "Promoted review no longer passes deterministic readiness checks",
                details={"blockers": readiness["blockers"]},
            )
        if not _promotion_integrity_matches_review(retry_promotion, review):
            raise ReviewConflictError("Promotion manifest integrity verification failed")
        return review, retry_promotion
    _assert_version(review, expected_version)
    if review.state != "approved":
        raise ReviewStateError(f"Only an approved review can be promoted; current state is {review.state}")
    context = await load_review_context(db, session_id)
    _assert_current(review, context)
    gates, claims = await _review_rows(db, review.id, lock=True)
    readiness = review_readiness(review, gates, claims, context)
    if not readiness["ready"]:
        raise ReviewValidationError("Review is not promotion-ready", details={"blockers": readiness["blockers"]})

    existing_row = await db.execute(select(ReportPromotion).where(ReportPromotion.review_id == review.id).limit(1))
    existing = existing_row.scalar_one_or_none()
    if existing:
        raise ReviewConflictError("An immutable promotion already exists for this review")

    now = _utcnow()
    manifest = build_promotion_manifest(
        review,
        gates,
        claims,
        context,
        generated_at=now,
        targets=normalized_targets,
    )
    manifest_checksum = promotion_manifest_checksum(manifest, normalized_targets)
    idempotency_key = checksum_json(
        {
            "review_id": str(review.id),
            "review_revision": review.revision,
            "source_checksum": review.source_checksum,
            "analysis_checksum": review.analysis_checksum,
            "targets": normalized_targets,
        }
    )
    promotion = ReportPromotion(
        id=uuid.uuid4(),
        review_id=review.id,
        session_id=session_id,
        review_revision=review.revision,
        policy_version=review.policy_version,
        source_checksum=review.source_checksum,
        analysis_checksum=review.analysis_checksum,
        targets=normalized_targets,
        manifest=manifest,
        manifest_checksum=manifest_checksum,
        idempotency_key=idempotency_key,
        promoted_by=actor.name,
        promoted_by_id=actor.actor_id,
        promoted_at=now,
    )
    db.add(promotion)
    review.state = "promoted"
    review.promoted_by = actor.name
    review.promoted_by_id = actor.actor_id
    review.promoted_at = now
    _touch(review, now=now)
    _add_event(
        db,
        review,
        actor,
        "review_promoted",
        {
            "from_state": "approved",
            "to_state": "promoted",
            "promotion_id": str(promotion.id),
            "targets": normalized_targets,
            "manifest_checksum": manifest_checksum,
            "note": _clean_string(note, 1_000),
        },
    )
    await db.flush()
    return review, promotion


async def active_promotion(
    db: AsyncSession,
    session_id: uuid.UUID,
    *,
    verify_current: bool = True,
) -> ReportPromotion | None:
    """Return the current, unrevoked, version-matched promotion."""

    review = await _latest_review(db, session_id)
    if review is None or review.state != "promoted":
        return None
    if verify_current:
        context = await load_review_context(db, session_id)
        if review.source_checksum != context.source_checksum or review.analysis_checksum != context.analysis_checksum:
            return None
    promotion_row = await db.execute(select(ReportPromotion).where(ReportPromotion.review_id == review.id).limit(1))
    promotion = promotion_row.scalar_one_or_none()
    if promotion is None:
        return None
    if verify_current:
        if not _promotion_integrity_matches_review(promotion, review):
            return None
    revocation_row = await db.execute(
        select(ReportPromotionRevocation).where(ReportPromotionRevocation.promotion_id == promotion.id).limit(1)
    )
    return None if revocation_row.scalar_one_or_none() else promotion


async def revoke_promotion(
    db: AsyncSession,
    session_id: uuid.UUID,
    actor: ReviewActor,
    *,
    expected_version: int,
    reason: str,
) -> tuple[ReportReview, ReportPromotionRevocation]:
    review = await _latest_review(db, session_id, lock=True)
    if review is None:
        raise ReviewNotFoundError("Review not found")
    clean_reason = _clean_string(reason, 2_000)
    if review.state == "revoked":
        retry_promotion_row = await db.execute(select(ReportPromotion).where(ReportPromotion.review_id == review.id).limit(1))
        retry_promotion = retry_promotion_row.scalar_one_or_none()
        if retry_promotion is not None:
            retry_revocation_row = await db.execute(
                select(ReportPromotionRevocation)
                .where(ReportPromotionRevocation.promotion_id == retry_promotion.id)
                .limit(1)
            )
            retry_revocation = retry_revocation_row.scalar_one_or_none()
            if (
                retry_revocation is not None
                and retry_revocation.reason == clean_reason
                and expected_version in {review.version, review.version - 1}
            ):
                return review, retry_revocation
    _assert_version(review, expected_version)
    if review.state != "promoted":
        raise ReviewStateError(f"Only an active promotion can be revoked; current state is {review.state}")
    if len(clean_reason) < 8:
        raise ReviewValidationError("A specific revocation reason of at least 8 characters is required")
    promotion_row = await db.execute(select(ReportPromotion).where(ReportPromotion.review_id == review.id).with_for_update())
    promotion = promotion_row.scalar_one_or_none()
    if promotion is None:
        raise ReviewNotFoundError("Promotion record not found")
    existing_row = await db.execute(
        select(ReportPromotionRevocation).where(ReportPromotionRevocation.promotion_id == promotion.id).limit(1)
    )
    if existing_row.scalar_one_or_none():
        raise ReviewConflictError("Promotion is already revoked")
    now = _utcnow()
    revocation = ReportPromotionRevocation(
        id=uuid.uuid4(),
        promotion_id=promotion.id,
        reason=clean_reason,
        revoked_by=actor.name,
        revoked_by_id=actor.actor_id,
        revoked_at=now,
    )
    db.add(revocation)
    review.state = "revoked"
    review.revoked_by = actor.name
    review.revoked_by_id = actor.actor_id
    review.revoked_at = now
    _touch(review, now=now)
    _add_event(
        db,
        review,
        actor,
        "promotion_revoked",
        {
            "from_state": "promoted",
            "to_state": "revoked",
            "promotion_id": str(promotion.id),
            "reason": clean_reason,
        },
    )
    await db.flush()
    return review, revocation


def _gate_dict(gate: ReportReviewGate, *, stale_reasons: list[str]) -> dict[str, Any]:
    definition = GATE_CATALOG[gate.gate_key]
    details = gate.machine_details if isinstance(gate.machine_details, dict) else {}
    return {
        "id": str(gate.id),
        "gate_key": gate.gate_key,
        "ordinal": gate.ordinal,
        "title": definition["title"],
        "question": definition["question"],
        "description": definition["description"],
        "required": gate.required,
        "allowed_reason_codes": sorted(definition["reason_codes"]),
        "allowed_reason_codes_by_verdict": {
            verdict: sorted(reason_codes)
            for verdict, reason_codes in GATE_REASON_CODES_BY_VERDICT[gate.gate_key].items()
        },
        "machine_verdict": gate.machine_verdict,
        "machine_summary": _clean_string(details.get("summary") or details.get("reason"), 2_000),
        "machine_details": details,
        "machine_evidence": gate.machine_evidence_refs or [],
        "machine_evidence_refs": gate.machine_evidence_refs or [],
        "machine_evaluator": gate.machine_evaluator,
        "machine_evaluated_at": gate.machine_evaluated_at.isoformat() if gate.machine_evaluated_at else None,
        "analyst_verdict": gate.analyst_verdict,
        "reason_code": gate.reason_code,
        "rationale": gate.rationale,
        "evidence_refs": gate.evidence_refs or [],
        "reviewed_by": gate.reviewed_by or None,
        "reviewed_at": gate.reviewed_at.isoformat() if gate.reviewed_at else None,
        "stale": bool(stale_reasons),
        "stale_reasons": stale_reasons,
    }


def _claim_dict(claim: ReportReviewClaim) -> dict[str, Any]:
    metadata = claim.claim_metadata if isinstance(claim.claim_metadata, dict) else {}
    confidence = metadata.get("confidence")
    return {
        "id": str(claim.id),
        "claim_key": claim.claim_key,
        "claim_type": claim.claim_type,
        "title": claim.statement or claim.object,
        "claim": claim.statement,
        "subject": claim.subject,
        "action": claim.predicate,
        "predicate": claim.predicate,
        "object": claim.object,
        "status": claim.status,
        "reason_code": claim.reason_code,
        "rationale": claim.rationale,
        "evidence_text": claim.evidence_text,
        "evidence_start": claim.evidence_start,
        "evidence_end": claim.evidence_end,
        "evidence_refs": claim.evidence_refs or [],
        "attack_id": claim.attack_id or None,
        "actor_id": claim.actor_id or None,
        "attack_ids": [claim.attack_id] if claim.attack_id else [],
        "actor_ids": [claim.actor_id] if claim.actor_id else [],
        "confidence": confidence if isinstance(confidence, (int, float)) else None,
        "extraction_method": claim.extraction_method,
        "reviewed_by": claim.reviewed_by or None,
        "reviewed_at": claim.reviewed_at.isoformat() if claim.reviewed_at else None,
        "metadata": metadata,
    }


async def _promotion_dict(db: AsyncSession, review: ReportReview) -> dict[str, Any] | None:
    row = await db.execute(select(ReportPromotion).where(ReportPromotion.review_id == review.id).limit(1))
    promotion = row.scalar_one_or_none()
    if promotion is None:
        return None
    revoked_row = await db.execute(
        select(ReportPromotionRevocation).where(ReportPromotionRevocation.promotion_id == promotion.id).limit(1)
    )
    revoked = revoked_row.scalar_one_or_none()
    return {
        "id": str(promotion.id),
        "status": "revoked" if revoked else "active",
        "target": ",".join(promotion.targets or []),
        "targets": promotion.targets or [],
        "manifest_checksum": promotion.manifest_checksum,
        "promoted_by": promotion.promoted_by or None,
        "promoted_at": promotion.promoted_at.isoformat() if promotion.promoted_at else None,
        "revoked_by": revoked.revoked_by if revoked else None,
        "revoked_at": revoked.revoked_at.isoformat() if revoked and revoked.revoked_at else None,
        "reason": revoked.reason if revoked else "",
        "manifest": promotion.manifest,
    }


async def assessment(db: AsyncSession, session_id: uuid.UUID) -> dict[str, Any]:
    review = await _latest_review(db, session_id)
    if review is None:
        raise ReviewNotFoundError("No report review exists for this analysis session")
    context = await load_review_context(db, session_id)
    gates, claims = await _review_rows(db, review.id)
    readiness = review_readiness(review, gates, claims, context)
    effective_state = "stale" if readiness["stale_reasons"] and review.state not in {"revoked", "rejected"} else review.state
    promotion = await _promotion_dict(db, review)
    active = promotion if promotion and promotion["status"] == "active" and effective_state == "promoted" else None
    return {
        "id": str(review.id),
        "session_id": str(review.session_id),
        "revision": review.revision,
        "source_revision": review.revision,
        "analysis_revision": review.revision,
        "profile": review.profile,
        "policy_version": review.policy_version,
        "state": effective_state,
        "version": review.version,
        "source_checksum": review.source_checksum,
        "analysis_checksum": review.analysis_checksum,
        "source_char_count": review.source_char_count,
        "analyzed_char_count": review.analyzed_char_count,
        "coverage_complete": review.coverage_complete,
        "coverage_exception_reason": review.coverage_exception_reason or "",
        "coverage_exception_by": review.coverage_exception_by or None,
        "coverage_exception_at": review.coverage_exception_at.isoformat() if review.coverage_exception_at else None,
        "gates": [_gate_dict(gate, stale_reasons=readiness["stale_reasons"]) for gate in gates],
        "claims": [_claim_dict(claim) for claim in claims],
        "readiness": {key: value for key, value in readiness.items() if key != "stale_reasons"},
        "active_promotion": active,
        "promotion_history": [promotion] if promotion else [],
        "created_by": review.created_by or None,
        "created_at": review.created_at.isoformat() if review.created_at else None,
        "updated_at": review.updated_at.isoformat() if review.updated_at else None,
        "submitted_by": review.submitted_by or None,
        "submitted_at": review.submitted_at.isoformat() if review.submitted_at else None,
        "approved_by": review.approved_by or None,
        "approved_at": review.approved_at.isoformat() if review.approved_at else None,
    }


async def review_history(db: AsyncSession, session_id: uuid.UUID) -> list[dict[str, Any]]:
    row = await db.execute(
        select(ReportReviewEvent)
        .where(ReportReviewEvent.session_id == session_id)
        .order_by(ReportReviewEvent.created_at, ReportReviewEvent.review_revision, ReportReviewEvent.version)
    )
    return [
        {
            "id": str(event.id),
            "action": event.event_type,
            "event_type": event.event_type,
            "actor": event.actor,
            "reviewer": event.actor,
            "review_id": str(event.review_id),
            "review_revision": event.review_revision,
            "version": event.version,
            "from_state": (event.details or {}).get("from_state"),
            "to_state": (event.details or {}).get("to_state"),
            "summary": event.event_type.replace("_", " ").capitalize(),
            "details": event.details or {},
            "created_at": event.created_at.isoformat() if event.created_at else None,
            "occurred_at": event.created_at.isoformat() if event.created_at else None,
        }
        for event in row.scalars().all()
    ]


def collection_summary(assessment_value: dict[str, Any] | None) -> dict[str, Any]:
    if not assessment_value:
        return {
            "state": "unreviewed",
            "ready": False,
            "reviewed_gate_count": 0,
            "required_gate_count": len(GATE_KEYS),
            "accepted_claim_count": 0,
            "blocker_count": len(GATE_KEYS),
            "blockers": ["review_not_started"],
        }
    readiness = assessment_value["readiness"]
    return {
        "state": assessment_value["state"],
        "ready": readiness["ready"],
        "reviewed_gate_count": readiness["reviewed_gate_count"],
        "required_gate_count": readiness["required_gate_count"],
        "accepted_claim_count": readiness["accepted_claim_count"],
        "blocker_count": len(readiness["blockers"]),
        "blockers": readiness["blockers"],
    }


async def try_assessment(db: AsyncSession, session_id: uuid.UUID) -> dict[str, Any] | None:
    """Read an assessment without turning an unreviewed report into an error."""

    try:
        return await assessment(db, session_id)
    except ReviewNotFoundError:
        return None


async def collection_summaries(
    db: AsyncSession,
    session_ids: Iterable[uuid.UUID | str],
) -> dict[str, dict[str, Any]]:
    """Load exact collection badges in bounded bulk queries.

    The function intentionally omits promotion manifests and evidence payloads;
    it computes the same readiness rules from the latest review, current
    fingerprints, gate decisions, and claim decisions.
    """

    normalized: list[uuid.UUID] = []
    for value in session_ids:
        try:
            item = value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))
        except (TypeError, ValueError):
            continue
        if item not in normalized:
            normalized.append(item)
    if not normalized:
        return {}

    review_rows = await db.execute(
        select(ReportReview)
        .where(ReportReview.session_id.in_(normalized))
        .order_by(ReportReview.session_id, ReportReview.revision.desc())
    )
    latest: dict[uuid.UUID, ReportReview] = {}
    for review in review_rows.scalars().all():
        latest.setdefault(review.session_id, review)
    unreviewed = collection_summary(None)
    output = {str(session_id): dict(unreviewed) for session_id in normalized}
    if not latest:
        return output

    review_ids = [review.id for review in latest.values()]
    gate_rows = await db.execute(select(ReportReviewGate).where(ReportReviewGate.review_id.in_(review_ids)))
    claim_rows = await db.execute(select(ReportReviewClaim).where(ReportReviewClaim.review_id.in_(review_ids)))
    session_rows = await db.execute(select(AnalysisSession).where(AnalysisSession.id.in_(list(latest))))
    result_rows = await db.execute(select(AnalysisResult).where(AnalysisResult.session_id.in_(list(latest))))
    intake_rows = await db.execute(
        select(ReportIntake)
        .where(ReportIntake.analysis_session_id.in_(list(latest)))
        .order_by(
            ReportIntake.analysis_session_id,
            ReportIntake.updated_at.desc(),
            ReportIntake.id.desc(),
        )
    )

    gates_by_review: dict[uuid.UUID, list[ReportReviewGate]] = {review_id: [] for review_id in review_ids}
    claims_by_review: dict[uuid.UUID, list[ReportReviewClaim]] = {review_id: [] for review_id in review_ids}
    for gate in gate_rows.scalars().all():
        gates_by_review.setdefault(gate.review_id, []).append(gate)
    for claim in claim_rows.scalars().all():
        claims_by_review.setdefault(claim.review_id, []).append(claim)
    sessions = {session.id: session for session in session_rows.scalars().all()}
    results = {result.session_id: result for result in result_rows.scalars().all()}
    intakes: dict[uuid.UUID, ReportIntake] = {}
    for intake in intake_rows.scalars().all():
        if intake.analysis_session_id:
            intakes.setdefault(intake.analysis_session_id, intake)

    for session_id, review in latest.items():
        session = sessions.get(session_id)
        if session is None:
            continue
        result = results.get(session_id)
        source_text = session.source_text or ""
        source_metadata = _source_metadata(session, intakes.get(session_id))
        context = ReviewContext(
            session=session,
            result=result,
            intake=intakes.get(session_id),
            source_text=source_text,
            source_checksum=source_fingerprint(source_text, source_metadata),
            analysis_checksum=analysis_fingerprint(result, session.status),
            source_metadata=source_metadata,
        )
        readiness = review_readiness(
            review,
            gates_by_review.get(review.id, []),
            claims_by_review.get(review.id, []),
            context,
        )
        state = "stale" if readiness["stale_reasons"] and review.state not in {"revoked", "rejected"} else review.state
        output[str(session_id)] = {
            "state": state,
            "ready": readiness["ready"],
            "reviewed_gate_count": readiness["reviewed_gate_count"],
            "required_gate_count": readiness["required_gate_count"],
            "accepted_claim_count": readiness["accepted_claim_count"],
            "blocker_count": len(readiness["blockers"]),
            "blockers": readiness["blockers"],
        }
    return output
