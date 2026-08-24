from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from app.models.analysis import AnalysisResult, AnalysisSession
from app.models.report_review import ReportPromotion
from app.services.report_promotion import accepted_claims

STIX_NAMESPACE = uuid.UUID("4f16fdd8-5c89-4a8f-8e1f-67ea7e4d6ec1")
ATTACK_GROUP_ID_RE = re.compile(r"G\d{4}", re.IGNORECASE)


def build_analysis_stix_bundle(
    session: AnalysisSession,
    result: AnalysisResult,
    *,
    technique_lookup: dict[str, dict[str, Any]] | None = None,
    group_lookup: dict[str, dict[str, Any]] | None = None,
    promotion: ReportPromotion | None = None,
) -> dict[str, Any]:
    """Build a STIX 2.1 bundle suitable for OpenCTI import.

    AdversaryGraph is TTP/report-centric, not IOC-centric. The export therefore
    models reviewed analysis as a STIX report linked to ATT&CK attack-patterns
    and optional intrusion-set similarity leads. Similarity leads are not
    attribution claims.
    """
    technique_lookup = technique_lookup or {}
    group_lookup = group_lookup or {}
    now = _stix_time(
        promotion.promoted_at
        if promotion is not None and promotion.promoted_at is not None
        else datetime.now(timezone.utc)
    )
    session_id = str(session.id)

    identity_id = _stix_id("identity", "adversarygraph-source")
    report_id = _stix_id("report", f"analysis:{session_id}")
    objects: list[dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": "AdversaryGraph",
            "identity_class": "system",
            "description": "Self-hosted CTI-to-ATT&CK analysis workbench.",
        }
    ]

    object_refs: list[str] = []
    # A STIX bundle is a downstream intelligence projection, not a draft
    # analysis view.  Suggested, rejected, and needs-evidence mappings stay in
    # the report workspace and are never emitted as ATT&CK objects.
    manifest_claims = accepted_claims(promotion) if promotion is not None else []
    extracted = (
        [_procedure_claim_to_mapping(item) for item in manifest_claims if item.get("claim_type") == "procedure" and item.get("attack_id")]
        if promotion is not None
        else [
            item for item in (result.extracted_techniques or [])
            if item.get("review_status") == "accepted"
            and item.get("evidence_source") in {"source-text", "analyst-source-text"}
        ]
    )
    for item in extracted:
        attack_id = str(item.get("attack_id", "")).upper()
        if not attack_id:
            continue
        tech_meta = technique_lookup.get(attack_id, {})
        attack_pattern_id = tech_meta.get("stix_id") or _stix_id("attack-pattern", f"attack-pattern:{attack_id}")
        object_refs.append(attack_pattern_id)
        objects.append(_attack_pattern_object(attack_pattern_id, attack_id, item, tech_meta, now, identity_id))

    # ``apt_matches`` are Jaccard/TTP-overlap leads and are never exported.
    # Only explicit, accepted actor claims in the immutable promotion manifest
    # can create intrusion-set objects.
    for claim in manifest_claims:
        if claim.get("claim_type") != "actor":
            continue
        actor_key = str(claim.get("actor_id") or claim.get("object") or "").strip()
        if not actor_key:
            continue
        attack_id = actor_key.upper() if ATTACK_GROUP_ID_RE.fullmatch(actor_key) else actor_key
        actor_meta = group_lookup.get(attack_id, {}) if ATTACK_GROUP_ID_RE.fullmatch(attack_id) else {}
        actor_id = actor_meta.get("stix_id") or _stix_id(
            "intrusion-set",
            f"reviewed-actor:{attack_id.casefold()}",
        )
        object_refs.append(actor_id)
        objects.append(
            _reviewed_actor_object(
                actor_id,
                attack_id,
                claim,
                actor_meta,
                now,
                identity_id,
            )
        )

    report_name = session.name or session.filename or f"AdversaryGraph analysis {session_id[:8]}"
    accepted_narrative = "\n".join(
        str(claim.get("statement") or "").strip()
        for claim in manifest_claims
        if str(claim.get("statement") or "").strip()
    )[:20_000]
    report = {
        "type": "report",
        "spec_version": "2.1",
        "id": report_id,
        "created": now,
        "modified": now,
        "created_by_ref": identity_id,
        "name": report_name,
        "description": accepted_narrative or (
            result.summary if promotion is None else "Promoted AdversaryGraph source assessment."
        ),
        "published": _reviewed_publication_time(manifest_claims)
        or (_stix_time(session.created_at) if session.created_at else now),
        "report_types": ["threat-report"],
        "object_refs": sorted(set(object_refs)) or [identity_id],
        "external_references": [
            {
                "source_name": "AdversaryGraph",
                "description": "Local AdversaryGraph analysis session",
                "external_id": session_id,
            }
        ],
        "x_adversarygraph_session_id": session_id,
        "x_adversarygraph_domain": session.domain,
        "x_adversarygraph_provider": session.llm_provider,
        "x_adversarygraph_model": session.model,
        "x_adversarygraph_note": (
            "Only accepted source-bound mappings are included. Similarity leads are not attribution claims and are excluded."
        ),
    }
    if promotion is not None:
        report.update({
            "x_adversarygraph_review_id": str(promotion.review_id),
            "x_adversarygraph_review_revision": promotion.review_revision,
            "x_adversarygraph_policy_version": promotion.policy_version,
            "x_adversarygraph_promotion_id": str(promotion.id),
            "x_adversarygraph_manifest_checksum": promotion.manifest_checksum,
            "x_adversarygraph_source_checksum": promotion.source_checksum,
            "x_adversarygraph_analysis_checksum": promotion.analysis_checksum,
        })
    objects.append(report)

    return {
        "type": "bundle",
        "id": _stix_id("bundle", f"bundle:{session_id}:{_fingerprint(objects)}"),
        "objects": objects,
    }


def _attack_pattern_object(
    stix_id: str,
    attack_id: str,
    item: dict[str, Any],
    meta: dict[str, Any],
    now: str,
    identity_id: str,
) -> dict[str, Any]:
    refs = [
        {
            "source_name": "mitre-attack",
            "external_id": attack_id,
            "url": meta.get("url") or f"https://attack.mitre.org/techniques/{attack_id.replace('.', '/')}/",
        }
    ]
    evidence = item.get("evidence")
    if evidence:
        refs.append({"source_name": "AdversaryGraph evidence", "description": str(evidence)[:500]})
    return {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": stix_id,
        "created": now,
        "modified": now,
        "created_by_ref": identity_id,
        "name": meta.get("name") or item.get("name") or attack_id,
        "description": meta.get("description") or item.get("evidence") or "",
        "external_references": refs,
        "x_mitre_id": attack_id,
        "x_adversarygraph_tactic": item.get("tactic") or "",
        "x_adversarygraph_confidence": item.get("confidence"),
        "x_adversarygraph_review_status": item.get("review_status", "suggested"),
        "x_adversarygraph_evidence_source": item.get("evidence_source", "llm"),
    }


def _procedure_claim_to_mapping(claim: dict[str, Any]) -> dict[str, Any]:
    metadata = claim.get("metadata") if isinstance(claim.get("metadata"), dict) else {}
    return {
        "attack_id": str(claim.get("attack_id") or "").upper(),
        "name": str(claim.get("object") or claim.get("subject") or ""),
        "tactic": str(metadata.get("tactic") or ""),
        "confidence": metadata.get("confidence"),
        "evidence": _claim_evidence(claim),
        "review_status": "accepted",
        "evidence_source": "promotion-manifest",
    }


def _claim_evidence(claim: dict[str, Any]) -> str:
    direct = str(claim.get("evidence_text") or "").strip()
    if direct:
        return direct[:500]
    refs = claim.get("evidence_refs") if isinstance(claim.get("evidence_refs"), list) else []
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        value = str(ref.get("excerpt") or ref.get("quote") or ref.get("value") or "").strip()
        if value:
            return value[:500]
    return str(claim.get("statement") or "")[:500]


def _reviewed_actor_object(
    stix_id: str,
    attack_id: str,
    claim: dict[str, Any],
    meta: dict[str, Any],
    now: str,
    identity_id: str,
) -> dict[str, Any]:
    claim_metadata = claim.get("metadata") if isinstance(claim.get("metadata"), dict) else {}
    is_attack_group = ATTACK_GROUP_ID_RE.fullmatch(attack_id) is not None
    actor = {
        "type": "intrusion-set",
        "spec_version": "2.1",
        "id": stix_id,
        "created": now,
        "modified": now,
        "created_by_ref": identity_id,
        "name": (
            meta.get("name")
            or claim_metadata.get("catalog_name")
            or claim.get("object")
            or attack_id
        ),
        "description": claim.get("statement") or _claim_evidence(claim),
        "aliases": meta.get("aliases") or claim_metadata.get("catalog_aliases") or [],
        "x_adversarygraph_review_status": "accepted",
        "x_adversarygraph_evidence": _claim_evidence(claim),
        "x_adversarygraph_note": "Explicit source-bound actor claim from an approved report promotion.",
    }
    if is_attack_group:
        actor["external_references"] = [{
            "source_name": "mitre-attack",
            "external_id": attack_id,
            "url": meta.get("url") or claim_metadata.get("catalog_url") or f"https://attack.mitre.org/groups/{attack_id}/",
        }]
        actor["x_mitre_id"] = attack_id
    else:
        actor["x_adversarygraph_source_reported_name"] = True
    return actor


def _reviewed_publication_time(claims: list[dict[str, Any]]) -> str | None:
    for claim in claims:
        if claim.get("claim_type") != "publication_date":
            continue
        candidates = (
            claim.get("object"),
            claim.get("statement"),
            claim.get("subject"),
        )
        for candidate in candidates:
            value = str(candidate or "").strip()
            match = re.search(r"\b(\d{4}-\d{2}-\d{2})\b", value)
            if not match:
                continue
            try:
                parsed = datetime.fromisoformat(match.group(1)).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            return _stix_time(parsed)
    return None


def _intrusion_set_object(
    stix_id: str,
    attack_id: str,
    name: str,
    match: dict[str, Any],
    meta: dict[str, Any],
    now: str,
    identity_id: str,
) -> dict[str, Any]:
    aliases = meta.get("aliases") or []
    return {
        "type": "intrusion-set",
        "spec_version": "2.1",
        "id": stix_id,
        "created": now,
        "modified": now,
        "created_by_ref": identity_id,
        "name": meta.get("name") or name,
        "description": meta.get("description") or (
            "AdversaryGraph similarity lead based on ATT&CK TTP overlap. "
            "This is not an attribution claim."
        ),
        "aliases": aliases,
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": attack_id,
                "url": meta.get("url") or f"https://attack.mitre.org/groups/{attack_id}/",
            }
        ],
        "x_mitre_id": attack_id,
        "x_adversarygraph_similarity": match.get("similarity"),
        "x_adversarygraph_shared_count": match.get("shared_count"),
        "x_adversarygraph_shared_techniques": match.get("shared_techniques", []),
        "x_adversarygraph_note": "TTP-overlap lead only; validate independently before attribution.",
    }


def _stix_id(stix_type: str, key: str) -> str:
    return f"{stix_type}--{uuid.uuid5(STIX_NAMESPACE, key)}"


def _stix_time(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _fingerprint(objects: list[dict[str, Any]]) -> str:
    raw = "|".join(sorted(obj["id"] for obj in objects))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
