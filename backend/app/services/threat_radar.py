from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat_radar import (
    ThreatAction,
    ThreatAuditLog,
    ThreatCase,
    ThreatCaseLink,
    ThreatClaim,
    ThreatDetectionRequirement,
    ThreatEvidence,
    ThreatHuntRequest,
    ThreatIREscalation,
    ThreatMarketplaceListing,
    ThreatProductMapping,
    ThreatPSIRTTask,
    ThreatReport,
    ThreatScore,
    ThreatSignal,
    ThreatSource,
    ThreatSupplyChainFinding,
)


SIGNAL_TYPES = {
    "cve_disclosure",
    "cisa_kev_active_exploitation",
    "public_poc",
    "zero_day_claim",
    "exploit_sale_claim",
    "darknet_provider_mention",
    "marketplace_hardware_listing",
    "firmware_dump_claim",
    "source_code_leak_claim",
    "credential_exposure",
    "supplier_breach",
    "malicious_package",
    "critical_dependency_vulnerability",
    "customer_report",
    "internal_telemetry_anomaly",
}

HUNT_PRIORITIES = {
    "P0 Emergency",
    "P1 High",
    "P2 Medium",
    "P3 Monitor",
    "P4 Low/Archive",
}
HUNT_TLPS = {
    "TLP:CLEAR",
    "TLP:GREEN",
    "TLP:AMBER",
    "TLP:AMBER+STRICT",
    "TLP:RED",
}


def _bounded_text(value: Any, limit: int) -> str:
    return str(value or "").strip()[:limit]


def _bounded_strings(values: Any, *, count: int, length: int) -> list[str]:
    if not isinstance(values, list):
        return []
    cleaned = dict.fromkeys(
        item
        for value in values
        if (item := _bounded_text(value, length))
    )
    return list(cleaned)[:count]


def _canonical_hunt_priority(value: Any) -> str:
    candidate = _bounded_text(value, 40)
    return candidate if candidate in HUNT_PRIORITIES else "P2 Medium"


def _canonical_hunt_tlp(value: Any) -> str:
    candidate = _bounded_text(value, 20).upper()
    if not candidate:
        return "TLP:AMBER"
    # Unknown legacy labels fail closed so conversion cannot silently lower handling.
    return candidate if candidate in HUNT_TLPS else "TLP:RED"

LEGAL_SENSITIVE_TYPES = {
    "exploit_sale_claim",
    "darknet_provider_mention",
    "marketplace_hardware_listing",
    "firmware_dump_claim",
    "source_code_leak_claim",
    "credential_exposure",
    "supplier_breach",
}

REPORT_TYPES = {
    "flash_note": "Flash Intelligence Note",
    "product_impact": "Product Impact Assessment",
    "hunt_pack": "Threat Hunt Pack",
    "psirt_appendix": "PSIRT Intelligence Appendix",
    "executive_summary": "Executive Summary",
}

SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.I),
    re.compile(r"\b(password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*['\"]?[^\\s,'\"]{8,}", re.I),
    re.compile(r"\b[A-Za-z0-9._%+-]+:[^\\s:@]{6,}@", re.I),
]


@dataclass(frozen=True)
class ScoreResult:
    score: int
    priority: str
    factors: dict[str, int]
    rationale: list[str]


def normalize_signal_type(value: str) -> str:
    normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
    if normalized not in SIGNAL_TYPES:
        raise ValueError(f"Unsupported signal type: {value}")
    return normalized


def sanitize_metadata(signal_type: str, metadata: dict[str, Any] | None) -> dict[str, Any]:
    metadata = dict(metadata or {})
    sanitized: dict[str, Any] = {}
    for key, value in metadata.items():
        key_text = str(key).strip()[:120]
        if _looks_sensitive_key(key_text):
            sanitized[key_text] = "[redacted]"
        elif isinstance(value, str):
            sanitized[key_text] = _redact_sensitive_text(value[:4000])
        elif isinstance(value, (int, float, bool)) or value is None:
            sanitized[key_text] = value
        elif isinstance(value, list):
            sanitized[key_text] = [_redact_sensitive_text(str(item)[:1000]) for item in value[:50]]
        else:
            sanitized[key_text] = _redact_sensitive_text(str(value)[:2000])
    if signal_type in LEGAL_SENSITIVE_TYPES:
        sanitized["restricted_intelligence_handling"] = (
            "Sanitized metadata only. Do not store exploit material, stolen data, credentials, "
            "or instructions for accessing illegal sources."
        )
    return sanitized


def sanitize_evidence_summary(text: str, legal_sensitive: bool = False) -> str:
    text = _redact_sensitive_text((text or "").strip()[:8000])
    if legal_sensitive:
        return (
            "Legal-sensitive sanitized summary: "
            + text
            + "\n\nHandling note: raw source material, credentials, exploit payloads, stolen data, and marketplace access details are intentionally not stored."
        )
    return text


def score_signal(
    signal: ThreatSignal,
    mappings: list[ThreatProductMapping] | None = None,
    source: ThreatSource | None = None,
    claim: ThreatClaim | None = None,
) -> ScoreResult:
    mappings = mappings or []
    source_reliability = _clamp_factor(source.reliability if source else _source_factor(signal))
    claim_credibility = _clamp_factor(claim.credibility if claim else _claim_factor(signal))
    product_relevance = _clamp_factor(max([m.relevance for m in mappings], default=_metadata_factor(signal.raw_metadata, "product_relevance", 2)))
    exploitability = _clamp_factor(_exploitability_factor(signal))
    exposure = _clamp_factor(max([_exposure_factor(m.exposure) for m in mappings], default=_metadata_factor(signal.raw_metadata, "exposure", 2)))
    blast_radius = _clamp_factor(max([m.blast_radius for m in mappings], default=_metadata_factor(signal.raw_metadata, "blast_radius", 2)))

    weights = {
        "source_reliability": 15,
        "claim_credibility": 15,
        "product_relevance": 25,
        "exploitability": 20,
        "exposure": 15,
        "blast_radius": 10,
    }
    factors = {
        "source_reliability": source_reliability,
        "claim_credibility": claim_credibility,
        "product_relevance": product_relevance,
        "exploitability": exploitability,
        "exposure": exposure,
        "blast_radius": blast_radius,
    }
    score = round(sum((factors[name] / 5) * weight for name, weight in weights.items()))
    rationale = [
        f"source reliability {source_reliability}/5",
        f"claim credibility {claim_credibility}/5",
        f"product relevance {product_relevance}/5",
        f"exploitability {exploitability}/5",
        f"exposure {exposure}/5",
        f"blast radius {blast_radius}/5",
    ]
    return ScoreResult(score=score, priority=priority_for_score(score), factors=factors, rationale=rationale)


def priority_for_score(score: int) -> str:
    if score >= 90:
        return "P0 Emergency"
    if score >= 75:
        return "P1 High"
    if score >= 55:
        return "P2 Medium"
    if score >= 30:
        return "P3 Monitor"
    return "P4 Low/Archive"


def recommended_actions(signal: ThreatSignal, score: ScoreResult, mappings: list[ThreatProductMapping]) -> list[dict[str, Any]]:
    factors = score.factors
    actions: list[dict[str, Any]] = []
    signal_type = signal.signal_type
    products = [m.product for m in mappings if m.product]
    product_label = ", ".join(products[:3]) or "mapped product"

    if signal_type == "cisa_kev_active_exploitation" and factors["product_relevance"] >= 4:
        actions.extend([
            _action("psirt", "Create PSIRT task for active exploitation", "PSIRT", "Validate affected versions and remediation timeline."),
            _action("hunt", "Create threat hunt request for active exploitation", "Threat Hunt", "Search telemetry for exploitation indicators and post-exploitation behavior."),
            _action("engineering_notify", f"Notify engineering owner for {product_label}", "Engineering", "Confirm exposure and patch/control owner."),
        ])
    if signal_type == "zero_day_claim" and factors["product_relevance"] >= 4 and factors["claim_credibility"] >= 3:
        actions.extend([
            _action("validation_case", "Create zero-day validation case", "Product Security", "Validate claim against product surface without using exploit material."),
            _action("psirt", "Create PSIRT candidate", "PSIRT", "Prepare advisory decision record and evidence checklist."),
        ])
    if signal_type == "marketplace_hardware_listing":
        actions.extend([
            _action("legal_review", "Open Legal/IP review", "Legal", "Review sanitized listing metadata and authenticity risk."),
            _action("authenticity_check", "Create product authenticity check", "Product Security", "Validate serial, prototype, firmware, or supply-chain exposure signals."),
        ])
    if signal_type == "malicious_package" and any("sbom-match" in m.tags for m in mappings):
        actions.extend([
            _action("supply_chain_review", "Create supply-chain review", "AppSec", "Check dependency graph, lockfiles, build artifacts, and package provenance."),
            _action("ci_cd_hunt", "Create CI/CD hunt", "Detection", "Search CI/CD logs for package install, build, publish, and token use events."),
        ])
    if signal_type in {"source_code_leak_claim", "credential_exposure", "supplier_breach"} and factors["claim_credibility"] >= 3:
        actions.extend([
            _action("ir", "Create IR escalation", "IR", "Coordinate containment, account review, supplier validation, and legal handling."),
            _action("legal_review", "Create legal-sensitive case review", "Legal", "Use sanitized metadata only; do not store stolen data or credentials."),
        ])
    if factors["exploitability"] >= 3 and factors["product_relevance"] >= 3:
        actions.append(_action("detection", "Create detection requirement", "Detection", "Define telemetry, correlation logic, and validation query for the likely attack path."))

    if not actions:
        actions.append(_action("monitor", "Monitor and enrich signal", "CTI", "Track source updates, product mapping, exploitability, and confidence changes."))
    return _dedupe_actions(actions)


async def create_case_from_signal(
    session: AsyncSession,
    signal: ThreatSignal,
    actor: str = "local",
    mappings: list[ThreatProductMapping] | None = None,
) -> ThreatCase:
    mappings = mappings or await mappings_for_signal(session, signal.id)
    source = await session.get(ThreatSource, signal.source_id) if signal.source_id else None
    claim = await first_claim_for_signal(session, signal.id)
    score = score_signal(signal, mappings, source, claim)
    actions = recommended_actions(signal, score, mappings)
    case = ThreatCase(
        signal_id=signal.id,
        title=signal.title,
        summary=signal.description,
        status="open",
        priority=score.priority,
        risk_score=score.score,
        tlp=signal.tlp,
        legal_sensitive=signal.legal_sensitive,
        recommended_actions=actions,
        product_context=[mapping_to_dict(m) for m in mappings],
        tags=_case_tags(signal, score, mappings),
        created_by=actor,
    )
    session.add(case)
    await session.flush()
    for mapping in mappings:
        mapping.case_id = case.id
    session.add(ThreatScore(signal_id=signal.id, case_id=case.id, score=score.score, priority=score.priority, factors=score.factors, rationale=score.rationale))
    await _create_case_links(session, case, signal)
    await audit_log(session, actor, "threat_radar.create_case", "threat_case", str(case.id), {"signal_id": str(signal.id), "score": score.score})
    return case


async def create_action(session: AsyncSession, case: ThreatCase, action_type: str, actor: str = "local") -> Any:
    obj: Any
    if action_type == "hunt":
        telemetry = _bounded_strings(_telemetry_for_case(case), count=100, length=500)
        techniques = _techniques_for_case(case)[:100]
        owner = _bounded_text(actor, 255) or "local"
        obj = ThreatHuntRequest(
            case_id=case.id,
            title=_bounded_text(f"Hunt: {case.title}", 500),
            hypothesis=_bounded_text(
                f"Activity related to {case.title} may be visible in product, identity, endpoint, network, or CI/CD telemetry.",
                10_000,
            ),
            description=_bounded_text(case.summary, 20_000),
            scope="Validate the mapped product and environment context against organization-owned telemetry.",
            priority=_canonical_hunt_priority(case.priority),
            owner=owner,
            source_type="threat_radar",
            source_ref=str(case.id),
            telemetry=telemetry,
            technique_ids=techniques,
            tactics=[],
            required_fields=[],
            tags=_bounded_strings(case.tags, count=100, length=500),
            query_language="generic",
            query_text="",
            expected_evidence=(
                "Correlated product, identity, endpoint, network, or CI/CD telemetry that supports or weakens the hypothesis."
            ),
            false_positive_notes=(
                "Validate expected administrative, maintenance, deployment, monitoring, and security-tool activity before escalation."
            ),
            assumptions="Threat Radar context is a hunt trigger and must be validated against local telemetry before disposition.",
            result_summary="",
            disposition="undetermined",
            tlp=_canonical_hunt_tlp(case.tlp),
            status="queued",
            created_by=owner,
        )
    elif action_type == "psirt":
        product = (case.product_context or [{}])[0]
        obj = ThreatPSIRTTask(
            case_id=case.id,
            title=f"PSIRT review: {case.title}",
            product=str(product.get("product", "")),
            component=str(product.get("component", "")),
            priority=case.priority,
            validation_steps=[
                "Confirm affected product/component/version range.",
                "Validate exposure and exploitability without using unsafe exploit material.",
                "Document remediation, detection, and customer communication decision.",
            ],
        )
    elif action_type == "ir":
        obj = ThreatIREscalation(
            case_id=case.id,
            title=f"IR escalation: {case.title}",
            reason="Credible legal-sensitive or active-exploitation signal requires incident-response review.",
            severity="critical" if case.priority.startswith(("P0", "P1")) else "high",
            legal_sensitive=case.legal_sensitive,
        )
    elif action_type == "detection":
        obj = ThreatDetectionRequirement(
            case_id=case.id,
            title=f"Detection requirement: {case.title}",
            technique_ids=_techniques_for_case(case),
            telemetry=_telemetry_for_case(case),
            logic="Correlate source-specific telemetry with product exposure and exploitability evidence. Avoid generic keyword-only rules.",
        )
    else:
        raise ValueError(f"Unsupported action type: {action_type}")
    session.add(obj)
    action = ThreatAction(
        case_id=case.id,
        action_type=action_type,
        title=getattr(obj, "title", f"{action_type}: {case.title}"),
        owner_team={
            "hunt": "Threat Hunt",
            "psirt": "PSIRT",
            "ir": "IR",
            "detection": "Detection",
        }.get(action_type, "CTI"),
        priority=case.priority,
        description=getattr(obj, "hypothesis", "") or getattr(obj, "reason", "") or getattr(obj, "logic", ""),
        metadata_json={"workflow_object": type(obj).__name__},
    )
    session.add(action)
    await audit_log(session, actor, f"threat_radar.create_{action_type}", "threat_case", str(case.id), {"title": action.title})
    return obj


async def generate_report(session: AsyncSession, case: ThreatCase, report_type: str, actor: str = "local") -> ThreatReport:
    if report_type not in REPORT_TYPES:
        raise ValueError(f"Unsupported report type: {report_type}")
    markdown = _report_markdown(case, report_type)
    report = ThreatReport(
        case_id=case.id,
        report_type=report_type,
        title=f"{REPORT_TYPES[report_type]} - {case.title}",
        markdown=markdown,
        metadata_json={"priority": case.priority, "risk_score": case.risk_score, "legal_sensitive": case.legal_sensitive},
        created_by=actor,
    )
    session.add(report)
    await audit_log(session, actor, "threat_radar.generate_report", "threat_case", str(case.id), {"report_type": report_type})
    return report


async def mappings_for_signal(session: AsyncSession, signal_id: uuid.UUID) -> list[ThreatProductMapping]:
    rows = await session.execute(select(ThreatProductMapping).where(ThreatProductMapping.signal_id == signal_id))
    return list(rows.scalars().all())


async def first_claim_for_signal(session: AsyncSession, signal_id: uuid.UUID) -> ThreatClaim | None:
    rows = await session.execute(select(ThreatClaim).where(ThreatClaim.signal_id == signal_id).limit(1))
    return rows.scalar_one_or_none()


async def audit_log(session: AsyncSession, actor: str, action: str, object_type: str, object_id: str = "", details: dict[str, Any] | None = None) -> None:
    session.add(ThreatAuditLog(actor=actor, action=action, object_type=object_type, object_id=object_id, details=details or {}))


def signal_to_dict(signal: ThreatSignal) -> dict[str, Any]:
    return {
        "id": str(signal.id),
        "title": signal.title,
        "signal_type": signal.signal_type,
        "description": signal.description,
        "status": signal.status or "new",
        "source_id": str(signal.source_id) if signal.source_id else None,
        "source_name": signal.source_name,
        "source_url": signal.source_url,
        "tlp": signal.tlp or "TLP:AMBER",
        "legal_sensitive": signal.legal_sensitive,
        "confidence": signal.confidence or 0,
        "severity": signal.severity or "unknown",
        "cve_ids": signal.cve_ids or [],
        "technique_ids": signal.technique_ids or [],
        "iocs": signal.iocs or [],
        "actors": signal.actors or [],
        "sectors": signal.sectors or [],
        "tags": signal.tags or [],
        "raw_metadata": signal.raw_metadata or {},
        "created_by": signal.created_by or "local",
        "created_at": signal.created_at,
        "updated_at": signal.updated_at,
    }


def case_to_dict(case: ThreatCase) -> dict[str, Any]:
    return {
        "id": str(case.id),
        "signal_id": str(case.signal_id) if case.signal_id else None,
        "title": case.title,
        "summary": case.summary,
        "status": case.status or "open",
        "priority": case.priority or "P3 Monitor",
        "risk_score": case.risk_score or 0,
        "tlp": case.tlp or "TLP:AMBER",
        "legal_sensitive": case.legal_sensitive,
        "recommended_actions": case.recommended_actions or [],
        "product_context": case.product_context or [],
        "tags": case.tags or [],
        "created_by": case.created_by or "local",
        "created_at": case.created_at,
        "updated_at": case.updated_at,
    }


def mapping_to_dict(mapping: ThreatProductMapping) -> dict[str, Any]:
    return {
        "id": str(mapping.id),
        "signal_id": str(mapping.signal_id) if mapping.signal_id else None,
        "case_id": str(mapping.case_id) if mapping.case_id else None,
        "product": mapping.product,
        "component": mapping.component,
        "dependency": mapping.dependency,
        "version": mapping.version,
        "exposure": mapping.exposure,
        "environment": mapping.environment,
        "relevance": mapping.relevance,
        "blast_radius": mapping.blast_radius,
        "evidence": mapping.evidence,
        "tags": mapping.tags or [],
        "created_at": mapping.created_at,
    }


def _action(action_type: str, title: str, owner_team: str, description: str) -> dict[str, str]:
    return {"type": action_type, "title": title, "owner_team": owner_team, "description": description}


def _dedupe_actions(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str]] = set()
    unique = []
    for action in actions:
        key = (str(action.get("type")), str(action.get("title")))
        if key not in seen:
            seen.add(key)
            unique.append(action)
    return unique


def _source_factor(signal: ThreatSignal) -> int:
    if signal.signal_type in {"cisa_kev_active_exploitation", "internal_telemetry_anomaly", "customer_report"}:
        return 4
    if signal.signal_type in {"darknet_provider_mention", "exploit_sale_claim", "marketplace_hardware_listing"}:
        return 2
    return 3


def _claim_factor(signal: ThreatSignal) -> int:
    confidence = signal.confidence or 50
    if confidence >= 85:
        return 5
    if confidence >= 70:
        return 4
    if confidence >= 45:
        return 3
    if confidence >= 25:
        return 2
    return 1


def _exploitability_factor(signal: ThreatSignal) -> int:
    base = {
        "cisa_kev_active_exploitation": 5,
        "public_poc": 4,
        "zero_day_claim": 4,
        "malicious_package": 4,
        "critical_dependency_vulnerability": 3,
        "cve_disclosure": 2,
        "internal_telemetry_anomaly": 3,
        "customer_report": 2,
    }.get(signal.signal_type, 2)
    if signal.severity.lower() in {"critical", "high"}:
        base += 1
    return _clamp_factor(base)


def _metadata_factor(metadata: dict[str, Any] | None, key: str, default: int) -> int:
    try:
        return _clamp_factor(int((metadata or {}).get(key, default)))
    except (TypeError, ValueError):
        return default


def _exposure_factor(exposure: str) -> int:
    normalized = (exposure or "").lower()
    if normalized in {"internet", "external", "public", "customer-facing"}:
        return 5
    if normalized in {"partner", "third-party", "dmz"}:
        return 4
    if normalized in {"internal", "corp"}:
        return 3
    if normalized in {"lab", "dev", "staging"}:
        return 2
    return 2


def _clamp_factor(value: int) -> int:
    return max(0, min(5, int(value)))


def _looks_sensitive_key(key: str) -> bool:
    return any(part in key.lower() for part in ("password", "secret", "token", "private_key", "credential", "dump", "stolen"))


def _redact_sensitive_text(value: str) -> str:
    result = value
    for pattern in SECRET_PATTERNS:
        result = pattern.sub("[redacted]", result)
    return result


def _case_tags(signal: ThreatSignal, score: ScoreResult, mappings: list[ThreatProductMapping]) -> list[str]:
    tags = set(signal.tags or [])
    tags.add(score.priority.split()[0].lower())
    tags.add(signal.signal_type)
    if signal.legal_sensitive:
        tags.add("legal-sensitive")
    for mapping in mappings:
        tags.update(mapping.tags or [])
        if mapping.exposure:
            tags.add(f"exposure:{mapping.exposure}")
    return sorted(tags)


async def _create_case_links(session: AsyncSession, case: ThreatCase, signal: ThreatSignal) -> None:
    for cve_id in signal.cve_ids or []:
        session.add(ThreatCaseLink(case_id=case.id, target_type="cve", target_id=str(cve_id).upper(), relationship="mentions-cve", confidence=80))
    for attack_id in signal.technique_ids or []:
        session.add(ThreatCaseLink(case_id=case.id, target_type="ttp", target_id=str(attack_id).upper(), relationship="maps-to-technique", confidence=70))
    for actor in signal.actors or []:
        session.add(ThreatCaseLink(case_id=case.id, target_type="actor", target_id=str(actor), relationship="reported-actor-context", confidence=60))
    for ioc in signal.iocs or []:
        value = ioc.get("value") if isinstance(ioc, dict) else str(ioc)
        if value:
            session.add(ThreatCaseLink(case_id=case.id, target_type="ioc", target_id=str(value), relationship="observed-indicator", confidence=60))


def _telemetry_for_case(case: ThreatCase) -> list[str]:
    tags = set(case.tags or [])
    telemetry = {"vulnerability_management", "asset_inventory", "siem_case_notes"}
    if any(t in tags for t in ("malicious_package", "critical_dependency_vulnerability", "sbom-match")):
        telemetry.update({"sbom", "ci_cd_logs", "package_manager_logs"})
    if any(t in tags for t in ("credential_exposure", "supplier_breach")):
        telemetry.update({"identity_logs", "vpn_logs", "edr_process", "cloud_audit"})
    if any(str(t).startswith("exposure:internet") for t in tags):
        telemetry.update({"waf_logs", "web_access_logs", "netflow"})
    return sorted(telemetry)


def _techniques_for_case(case: ThreatCase) -> list[str]:
    techniques: set[str] = set()
    for item in case.product_context or []:
        techniques.update(
            str(value).upper()
            for value in item.get("technique_ids", [])
            if value and re.fullmatch(r"T\d{4}(?:\.\d{3})?", str(value), re.I)
        )
    techniques.update(
        str(tag).upper()
        for tag in case.tags or []
        if re.fullmatch(r"T\d{4}(?:\.\d{3})?", str(tag), re.I)
    )
    return sorted(techniques)


def _report_markdown(case: ThreatCase, report_type: str) -> str:
    product_lines = "\n".join(
        f"- {item.get('product', 'unknown')} / {item.get('component', '-') or '-'} / {item.get('dependency', '-') or '-'} "
        f"(relevance {item.get('relevance', '-')}/5, exposure {item.get('exposure', 'unknown')})"
        for item in case.product_context or []
    ) or "- No product mapping recorded yet."
    action_lines = "\n".join(
        f"- **{item.get('owner_team', 'CTI')}**: {item.get('title')} - {item.get('description')}"
        for item in case.recommended_actions or []
    ) or "- Monitor and enrich."
    legal = "\n\n> Legal-sensitive handling: use sanitized metadata only. Do not attach stolen data, credentials, exploit payloads, or illegal-source access material." if case.legal_sensitive else ""
    sections = {
        "flash_note": "## Analyst Judgment\nThis signal requires triage against product exposure and exploitability evidence.",
        "product_impact": "## Product Impact\nReview affected components, dependencies, versions, and customer exposure.",
        "hunt_pack": "## Hunt Hypotheses\nSearch for exploitation, staging, credential use, CI/CD abuse, and post-exploitation behavior tied to the mapped products.",
        "psirt_appendix": "## PSIRT Appendix\nDocument source reliability, claim validation, affected-version decision, customer impact, and remediation state.",
        "executive_summary": "## Executive Summary\nThis note summarizes priority, business exposure, recommended owners, and current validation gaps.",
    }
    return f"""# {REPORT_TYPES[report_type]}: {case.title}

Priority: **{case.priority}**
Risk score: **{case.risk_score}/100**
TLP: **{case.tlp}**

{case.summary}
{legal}

{sections[report_type]}

## Product / Component Exposure
{product_lines}

## Recommended Actions
{action_lines}

## Validation Gaps
- Confirm source reliability and claim credibility.
- Confirm affected products, versions, dependencies, and customer exposure.
- Confirm telemetry coverage before claiming detection coverage.
"""
