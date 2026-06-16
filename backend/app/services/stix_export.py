from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any

from app.models.analysis import AnalysisResult, AnalysisSession

STIX_NAMESPACE = uuid.UUID("4f16fdd8-5c89-4a8f-8e1f-67ea7e4d6ec1")


def build_analysis_stix_bundle(
    session: AnalysisSession,
    result: AnalysisResult,
    *,
    technique_lookup: dict[str, dict[str, Any]] | None = None,
    group_lookup: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a STIX 2.1 bundle suitable for OpenCTI import.

    ThreatMapper is TTP/report-centric, not IOC-centric. The export therefore
    models reviewed analysis as a STIX report linked to ATT&CK attack-patterns
    and optional intrusion-set similarity leads. Similarity leads are not
    attribution claims.
    """
    technique_lookup = technique_lookup or {}
    group_lookup = group_lookup or {}
    now = _stix_time(datetime.now(timezone.utc))
    session_id = str(session.id)

    identity_id = _stix_id("identity", "threatmapper-source")
    report_id = _stix_id("report", f"analysis:{session_id}")
    objects: list[dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": "ThreatMapper",
            "identity_class": "system",
            "description": "Self-hosted CTI-to-ATT&CK analysis workbench.",
        }
    ]

    object_refs: list[str] = []
    extracted = result.extracted_techniques or []
    for item in extracted:
        attack_id = str(item.get("attack_id", "")).upper()
        if not attack_id:
            continue
        tech_meta = technique_lookup.get(attack_id, {})
        attack_pattern_id = tech_meta.get("stix_id") or _stix_id("attack-pattern", f"attack-pattern:{attack_id}")
        object_refs.append(attack_pattern_id)
        objects.append(_attack_pattern_object(attack_pattern_id, attack_id, item, tech_meta, now, identity_id))

    for match in result.apt_matches or []:
        group_attack_id = str(match.get("group_attack_id", "")).upper()
        group_name = str(match.get("group_name") or group_attack_id or "ATT&CK group similarity lead")
        if not group_attack_id:
            continue
        group_meta = group_lookup.get(group_attack_id, {})
        intrusion_set_id = group_meta.get("stix_id") or _stix_id("intrusion-set", f"intrusion-set:{group_attack_id}")
        object_refs.append(intrusion_set_id)
        objects.append(_intrusion_set_object(intrusion_set_id, group_attack_id, group_name, match, group_meta, now, identity_id))

    report_name = session.name or session.filename or f"ThreatMapper analysis {session_id[:8]}"
    report = {
        "type": "report",
        "spec_version": "2.1",
        "id": report_id,
        "created": now,
        "modified": now,
        "created_by_ref": identity_id,
        "name": report_name,
        "description": result.summary or "ThreatMapper ATT&CK mapping analysis.",
        "published": _stix_time(session.created_at) if session.created_at else now,
        "report_types": ["threat-report"],
        "object_refs": sorted(set(object_refs)) or [identity_id],
        "external_references": [
            {
                "source_name": "ThreatMapper",
                "description": "Local ThreatMapper analysis session",
                "external_id": session_id,
            }
        ],
        "x_threatmapper_session_id": session_id,
        "x_threatmapper_domain": session.domain,
        "x_threatmapper_provider": session.llm_provider,
        "x_threatmapper_model": session.model,
        "x_threatmapper_note": (
            "Similarity leads are TTP-overlap investigation leads, not attribution claims."
        ),
    }
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
        refs.append({"source_name": "ThreatMapper evidence", "description": str(evidence)[:500]})
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
        "x_threatmapper_tactic": item.get("tactic") or "",
        "x_threatmapper_confidence": item.get("confidence"),
        "x_threatmapper_review_status": item.get("review_status", "suggested"),
        "x_threatmapper_evidence_source": item.get("evidence_source", "llm"),
    }


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
            "ThreatMapper similarity lead based on ATT&CK TTP overlap. "
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
        "x_threatmapper_similarity": match.get("similarity"),
        "x_threatmapper_shared_count": match.get("shared_count"),
        "x_threatmapper_shared_techniques": match.get("shared_techniques", []),
        "x_threatmapper_note": "TTP-overlap lead only; validate independently before attribution.",
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
