from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.threat_radar import (
    ThreatClaim,
    ThreatEvidence,
    ThreatMarketplaceListing,
    ThreatProductMapping,
    ThreatSignal,
    ThreatSource,
    ThreatSupplyChainFinding,
)
from app.services.taxonomy import canonical_value, normalize_freeform_tags
from app.services.threat_radar import (
    audit_log,
    create_case_from_signal,
    sanitize_evidence_summary,
    sanitize_metadata,
    score_signal,
)
from app.services.unified_model import forward_case_to_unified_model, forward_signal_to_unified_model


@dataclass(frozen=True)
class ExposureProvider:
    id: str
    label: str
    category: str
    env_var: str
    source_type: str
    purpose: str
    legal_sensitive: bool = False
    requires_key: bool = True


EXPOSURE_PROVIDERS: tuple[ExposureProvider, ...] = (
    ExposureProvider("recorded-future", "Recorded Future", "threat-intel", "RECORDED_FUTURE_API_KEY", "commercial_cti", "Finished intelligence, vulnerability intelligence, leaked credential and dark-web risk context.", True),
    ExposureProvider("virustotal-retrohunt", "VirusTotal Retrohunt", "malware-retrohunt", "VIRUSTOTAL_API_KEY", "malware_intel", "Retroactively match YARA rules against historical malware samples connected to products, suppliers, or leaked components."),
    ExposureProvider("virustotal-livehunt", "VirusTotal Livehunt", "malware-livehunt", "VIRUSTOTAL_API_KEY", "malware_intel", "Continuously monitor new uploaded files for product, supplier, driver, firmware, or package indicators."),
    ExposureProvider("hibp", "Have I Been Pwned", "breach", "HIBP_API_KEY", "breach_monitoring", "Domain breach and exposed-account monitoring for corporate identities."),
    ExposureProvider("spycloud", "SpyCloud", "breach", "SPYCLOUD_API_KEY", "breach_monitoring", "Credential exposure, malware-exfiltrated account data, and botnet credential reuse risk.", True),
    ExposureProvider("flare", "Flare", "dark-web", "FLARE_API_KEY", "darkweb_monitoring", "Dark web, stealer-log, and leaked credential monitoring.", True),
    ExposureProvider("darkowl", "DarkOwl", "dark-web", "DARKOWL_API_KEY", "darkweb_monitoring", "Darknet, leak-site, and cybercrime marketplace intelligence.", True),
    ExposureProvider("intel471", "Intel 471", "dark-web", "INTEL471_API_KEY", "cybercrime_intel", "Actor, marketplace, access broker, and credential exposure intelligence.", True),
    ExposureProvider("kela", "KELA", "dark-web", "KELA_API_KEY", "cybercrime_intel", "Cybercrime intelligence for compromised accounts, access broker listings, and marketplace mentions.", True),
    ExposureProvider("leakix", "LeakIX", "external-exposure", "LEAKIX_API_KEY", "exposure_scan", "Internet-exposed services, leaked files, and accidental exposure monitoring."),
    ExposureProvider("shodan", "Shodan", "external-exposure", "SHODAN_API_KEY", "exposure_scan", "Internet exposure for services, products, banners, versions, and management interfaces."),
    ExposureProvider("censys", "Censys", "external-exposure", "CENSYS_API_KEY", "exposure_scan", "Certificate, host, service, and internet exposure search."),
    ExposureProvider("urlscan", "urlscan.io", "web-intel", "URLSCAN_API_KEY", "web_intel", "Suspicious URL, phishing infrastructure, domain, page, and brand monitoring."),
    ExposureProvider("otx", "AlienVault OTX", "open-cti", "OTX_API_KEY", "open_cti", "Open pulse intelligence for domains, URLs, files, malware, and infrastructure."),
    ExposureProvider("threatfox", "ThreatFox", "open-cti", "THREATFOX_AUTH_KEY", "open_cti", "Malware IOC and malware-family intelligence tied to infrastructure and samples."),
    ExposureProvider("github-code-search", "GitHub Code Search", "source-leak", "GITHUB_TOKEN", "source_monitoring", "Authorized search for accidental public source, key, product codename, or prototype mentions."),
    ExposureProvider("gitlab-search", "GitLab Search", "source-leak", "GITLAB_TOKEN", "source_monitoring", "Authorized search for accidental public GitLab source, key, product codename, or component mentions."),
    ExposureProvider("socket", "Socket", "supply-chain", "SOCKET_TOKEN", "supply_chain", "Package risk, maintainer compromise, suspicious release, and dependency behavior monitoring."),
    ExposureProvider("snyk", "Snyk", "supply-chain", "SNYK_TOKEN", "supply_chain", "Dependency vulnerability and supply-chain monitoring."),
    ExposureProvider("vulncheck", "VulnCheck", "exploit-intel", "VULNCHECK_API_KEY", "exploit_intel", "Exploit intelligence, KEV-like context, and vulnerability prioritization."),
)

PROTOTYPE_TERMS = {
    "prototype",
    "engineering sample",
    "es sample",
    "dev board",
    "pre-release",
    "pre release",
    "unreleased",
    "qualification sample",
    "eval board",
    "bringup",
}
SALE_TERMS = {"for sale", "selling", "sell", "auction", "escrow", "price", "buyer", "broker", "available"}
LEAK_TERMS = {"leak", "leaked", "dump", "source code", "firmware dump", "database", "breach", "exfil", "stolen"}
CREDENTIAL_TERMS = {"credential", "password", "combo", "stealer", "cookie", "session", "vpn", "sso", "rdp", "admin panel"}
SUPPLIER_TERMS = {"supplier", "vendor", "third party", "contractor", "oem", "odm", "build server", "ci/cd", "package"}
EXPLOIT_TERMS = {"0day", "zero day", "exploit", "rce", "poc", "weaponized", "bypass", "privilege escalation"}


def provider_readiness() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for provider in EXPOSURE_PROVIDERS:
        setting_name = provider.env_var.lower()
        configured = bool(str(getattr(settings, setting_name, "") or "").strip())
        rows.append(
            {
                "id": provider.id,
                "label": provider.label,
                "category": provider.category,
                "source_type": provider.source_type,
                "purpose": provider.purpose,
                "env_var": provider.env_var,
                "configured": configured,
                "requires_key": provider.requires_key,
                "enabled": configured or not provider.requires_key,
                "legal_sensitive": provider.legal_sensitive,
                "status": "ready" if configured or not provider.requires_key else "missing_key",
            }
        )
    return rows


def monitoring_plan(providers: list[str] | None, terms: list[dict[str, Any]] | None) -> dict[str, Any]:
    selected = {item.strip().lower() for item in providers or [] if item.strip()} or {provider.id for provider in EXPOSURE_PROVIDERS}
    readiness = [row for row in provider_readiness() if row["id"] in selected]
    watch_terms = normalize_watch_terms(terms or [])
    configured = [row for row in readiness if row["enabled"]]
    missing = [row for row in readiness if not row["enabled"]]
    return {
        "providers": readiness,
        "configured_count": len(configured),
        "missing_key_count": len(missing),
        "watch_terms": watch_terms,
        "playbooks": [
            "Monitor product, component, supplier, domain, and codename terms in configured providers.",
            "Create sanitized Threat Radar signals only from provider summaries or analyst-approved excerpts.",
            "Escalate prototype-sale, source-code leak, firmware dump, credential exposure, access-broker, and supplier-breach signals to legal/IR/PSIRT.",
            "Do not store credentials, stolen files, exploit payloads, or instructions for accessing illegal sources.",
        ],
        "generated_at": datetime.now(UTC).isoformat(),
    }


def normalize_watch_terms(terms: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in terms[:500]:
        value = str(item.get("value", "")).strip()[:255]
        if not value:
            continue
        term_type = str(item.get("type") or item.get("term_type") or "keyword").strip().lower().replace(" ", "-")[:80]
        normalized.append(
            {
                "value": value,
                "type": term_type,
                "products": [canonical_value("product", str(v)) for v in _listify(item.get("products"))],
                "components": [canonical_value("dependency", str(v)) for v in _listify(item.get("components"))],
                "criticality": str(item.get("criticality", "unknown")).strip().lower()[:40],
                "tags": normalize_freeform_tags(_listify(item.get("tags"))),
            }
        )
    return normalized


def classify_exposure_hit(hit: dict[str, Any]) -> dict[str, Any]:
    text = " ".join(
        str(hit.get(key, ""))
        for key in ("provider", "title", "summary", "source_type", "product", "component", "supplier", "handle", "url")
    ).lower()
    metadata_value = hit.get("metadata")
    metadata = metadata_value if isinstance(metadata_value, dict) else {}
    metadata_text = " ".join(str(value) for value in metadata.values()).lower()
    text = f"{text} {metadata_text}"

    tags: set[str] = {"external-exposure-monitoring"}
    signal_type = "darknet_provider_mention"
    severity = "medium"
    confidence = _int_between(hit.get("confidence"), 35, 0, 100)
    relevance = 3
    blast_radius = 3
    legal_sensitive = True
    rationale: list[str] = []

    if _contains_any(text, PROTOTYPE_TERMS) and _contains_any(text, SALE_TERMS):
        signal_type = "marketplace_hardware_listing"
        severity = "high"
        confidence = max(confidence, 75)
        relevance = 5
        blast_radius = 4
        tags.update({"prototype-sale", "engineering-sample", "marketplace-listing", "hardware-risk"})
        rationale.append("Prototype or engineering-sample language appears together with sale/broker language.")
    elif _contains_any(text, LEAK_TERMS) and "firmware" in text:
        signal_type = "firmware_dump_claim"
        severity = "high"
        confidence = max(confidence, 70)
        relevance = 4
        blast_radius = 4
        tags.update({"firmware-leak", "restricted-source", "ip-risk"})
        rationale.append("Firmware leak/dump language detected.")
    elif _contains_any(text, LEAK_TERMS) and ("source" in text or "repository" in text or "repo" in text):
        signal_type = "source_code_leak_claim"
        severity = "high"
        confidence = max(confidence, 70)
        relevance = 4
        blast_radius = 4
        tags.update({"source-code-leak", "repository-exposure", "ip-risk"})
        rationale.append("Source-code or repository leak language detected.")
    elif _contains_any(text, CREDENTIAL_TERMS):
        signal_type = "credential_exposure"
        severity = "high"
        confidence = max(confidence, 70)
        relevance = 4
        blast_radius = 4
        tags.update({"credential-exposure", "account-risk", "identity-risk"})
        rationale.append("Credential, session, stealer, or access-token language detected.")
    elif _contains_any(text, SUPPLIER_TERMS) and _contains_any(text, LEAK_TERMS | CREDENTIAL_TERMS):
        signal_type = "supplier_breach"
        severity = "high"
        confidence = max(confidence, 65)
        relevance = 4
        blast_radius = 4
        tags.update({"supplier-risk", "third-party-risk", "supply-chain"})
        rationale.append("Supplier or third-party compromise context detected.")
    elif _contains_any(text, EXPLOIT_TERMS):
        signal_type = "zero_day_claim"
        severity = "high"
        confidence = max(confidence, 60)
        relevance = 3
        blast_radius = 3
        tags.update({"exploit-intel", "zero-day-claim"})
        rationale.append("Exploit, 0day, PoC, or bypass language detected.")
    elif "package" in text or "dependency" in text or "npm" in text or "pypi" in text:
        signal_type = "malicious_package"
        severity = "medium"
        confidence = max(confidence, 55)
        legal_sensitive = False
        tags.update({"package-risk", "supply-chain"})
        rationale.append("Package or dependency risk language detected.")
    else:
        tags.update({"provider-mention", "needs-analyst-review"})
        rationale.append("No strong specialized exposure pattern matched; classify as provider mention.")

    if hit.get("product"):
        tags.add(f"product:{canonical_value('product', str(hit['product']))}")
    if hit.get("component"):
        tags.add(f"dependency:{canonical_value('dependency', str(hit['component']))}")
    if hit.get("supplier"):
        tags.add(f"supplier:{canonical_value('supplier', str(hit['supplier']))}")

    return {
        "signal_type": signal_type,
        "severity": severity,
        "confidence": confidence,
        "legal_sensitive": legal_sensitive,
        "product_relevance": relevance,
        "blast_radius": blast_radius,
        "tags": sorted(normalize_freeform_tags(tags)),
        "rationale": rationale,
        "recommended_handling": (
            "Legal-sensitive sanitized metadata only. Do not store credentials, stolen files, exploit payloads, or raw illegal-source content."
            if legal_sensitive
            else "Standard product-security handling; preserve source reference and validation steps."
        ),
    }


async def ingest_exposure_hit(session: AsyncSession, hit: dict[str, Any], actor: str = "local") -> dict[str, Any]:
    classification = classify_exposure_hit(hit)
    provider_id = str(hit.get("provider", "manual-exposure")).strip().lower()[:120] or "manual-exposure"
    provider = next((row for row in provider_readiness() if row["id"] == provider_id), None)
    provider_name = provider["label"] if provider else str(hit.get("provider_label") or provider_id)
    legal_sensitive_value = hit.get("legal_sensitive")
    legal_sensitive = bool(classification["legal_sensitive"] if legal_sensitive_value is None else legal_sensitive_value)
    metadata = {
        "provider": provider_id,
        "provider_category": provider.get("category") if provider else str(hit.get("source_type", "manual")),
        "source_type": hit.get("source_type", ""),
        "product": hit.get("product", ""),
        "component": hit.get("component", ""),
        "supplier": hit.get("supplier", ""),
        "handle": hit.get("handle", ""),
        "price": hit.get("price", ""),
        "currency": hit.get("currency", ""),
        "classification": classification,
        "raw_metadata": hit.get("metadata", {}),
    }
    source = ThreatSource(
        name=provider_name,
        source_type=(provider["source_type"] if provider else "manual_exposure"),
        url=str(hit.get("url", ""))[:1000],
        reliability=_provider_reliability(provider_id),
        tlp="TLP:AMBER" if legal_sensitive else "TLP:CLEAR",
        legal_sensitive=legal_sensitive,
        notes="Exposure monitoring provider. Raw restricted material is not stored.",
    )
    session.add(source)
    await session.flush()

    title = str(hit.get("title") or _default_title(classification["signal_type"], hit)).strip()[:500]
    summary = sanitize_evidence_summary(str(hit.get("summary", "")), legal_sensitive)
    signal = ThreatSignal(
        title=title,
        signal_type=classification["signal_type"],
        description=summary,
        source_id=source.id,
        source_name=source.name,
        source_url=source.url,
        tlp=source.tlp,
        legal_sensitive=legal_sensitive,
        confidence=classification["confidence"],
        severity=classification["severity"],
        cve_ids=[str(item).upper() for item in _listify(hit.get("cve_ids")) if str(item).strip()],
        technique_ids=[str(item).upper() for item in _listify(hit.get("technique_ids")) if str(item).strip()],
        iocs=[item for item in _listify(hit.get("iocs")) if isinstance(item, dict)],
        actors=[canonical_value("actor", str(item)) for item in _listify(hit.get("actors")) if str(item).strip()],
        sectors=[canonical_value("sector", str(item)) for item in _listify(hit.get("sectors")) if str(item).strip()],
        tags=classification["tags"],
        raw_metadata=sanitize_metadata(classification["signal_type"], metadata),
        created_by=actor,
    )
    session.add(signal)
    await session.flush()

    claim_text = str(hit.get("claim") or summary or title)
    session.add(
        ThreatClaim(
            signal_id=signal.id,
            claim_type="exposure-monitoring-claim",
            statement=sanitize_evidence_summary(claim_text, legal_sensitive),
            credibility=_credibility_from_confidence(classification["confidence"]),
            status="unvalidated",
            tlp=source.tlp,
            legal_sensitive=legal_sensitive,
        )
    )
    session.add(
        ThreatEvidence(
            signal_id=signal.id,
            source_id=source.id,
            evidence_type="provider_summary",
            title=f"{provider_name} sanitized hit",
            summary=summary,
            url=source.url,
            observed_at=str(hit.get("observed_at") or datetime.now(UTC).isoformat()),
            tlp=source.tlp,
            legal_sensitive=legal_sensitive,
            sanitized=True,
            metadata_json=sanitize_metadata(classification["signal_type"], metadata),
        )
    )

    mapping = _product_mapping_from_hit(signal, hit, classification)
    if mapping:
        session.add(mapping)
        await session.flush()

    case = await create_case_from_signal(session, signal, actor, [mapping] if mapping else [])
    await forward_signal_to_unified_model(session, signal, [mapping] if mapping else [])
    await forward_case_to_unified_model(session, case, signal, [mapping] if mapping else [])

    if classification["signal_type"] in {"marketplace_hardware_listing", "firmware_dump_claim", "source_code_leak_claim", "credential_exposure", "darknet_provider_mention"}:
        session.add(
            ThreatMarketplaceListing(
                signal_id=signal.id,
                case_id=case.id,
                listing_type=classification["signal_type"],
                product=canonical_value("product", str(hit.get("product", ""))) if hit.get("product") else "",
                summary=summary,
                sanitized_metadata=sanitize_metadata(classification["signal_type"], metadata),
                tlp=source.tlp,
                legal_sensitive=True,
            )
        )
    if classification["signal_type"] in {"supplier_breach", "malicious_package", "critical_dependency_vulnerability"}:
        session.add(
            ThreatSupplyChainFinding(
                signal_id=signal.id,
                case_id=case.id,
                package_name=canonical_value("dependency", str(hit.get("component", ""))) if hit.get("component") else "",
                ecosystem=str(hit.get("ecosystem", ""))[:80],
                affected_versions=[str(item)[:120] for item in _listify(hit.get("affected_versions"))],
                sbom_match=bool(hit.get("sbom_match", False)),
                summary=summary,
            )
        )

    score = score_signal(signal, [mapping] if mapping else [], source)
    await audit_log(
        session,
        actor,
        "threat_radar.exposure_ingest",
        "threat_signal",
        str(signal.id),
        {"provider": provider_id, "signal_type": signal.signal_type, "score": score.score, "case_id": str(case.id)},
    )
    await session.commit()
    return {
        "classification": classification,
        "signal_id": str(signal.id),
        "case_id": str(case.id),
        "score": {"score": score.score, "priority": score.priority, "factors": score.factors, "rationale": score.rationale},
        "source_id": str(source.id),
    }


def _product_mapping_from_hit(hit_signal: ThreatSignal, hit: dict[str, Any], classification: dict[str, Any]) -> ThreatProductMapping | None:
    product = canonical_value("product", str(hit.get("product", "")).strip()) if hit.get("product") else ""
    component = canonical_value("dependency", str(hit.get("component", "")).strip()) if hit.get("component") else ""
    supplier = canonical_value("supplier", str(hit.get("supplier", "")).strip()) if hit.get("supplier") else ""
    if not any((product, component, supplier)):
        return None
    tags = normalize_freeform_tags(
        [
            *classification["tags"],
            f"product:{product}" if product else "",
            f"dependency:{component}" if component else "",
            f"supplier:{supplier}" if supplier else "",
            "exposure:external-monitoring",
        ]
    )
    return ThreatProductMapping(
        signal_id=hit_signal.id,
        product=product or supplier or "unknown-product",
        component=component,
        dependency=component,
        version=str(hit.get("version", ""))[:120],
        exposure=str(hit.get("exposure", "external-monitoring"))[:80],
        environment=str(hit.get("environment", "unknown"))[:80],
        relevance=int(classification["product_relevance"]),
        blast_radius=int(classification["blast_radius"]),
        evidence=sanitize_evidence_summary(str(hit.get("summary", "")), bool(classification["legal_sensitive"]))[:4000],
        tags=tags,
    )


def _provider_reliability(provider_id: str) -> int:
    if provider_id in {"recorded-future", "virustotal-retrohunt", "virustotal-livehunt", "spycloud", "flare", "darkowl", "intel471", "kela"}:
        return 4
    if provider_id in {"hibp", "leakix", "shodan", "censys", "urlscan", "otx", "threatfox"}:
        return 3
    return 2


def _credibility_from_confidence(confidence: int) -> int:
    if confidence >= 85:
        return 5
    if confidence >= 70:
        return 4
    if confidence >= 45:
        return 3
    return 2


def _contains_any(text: str, terms: set[str]) -> bool:
    return any(term in text for term in terms)


def _int_between(value: Any, default: int, low: int, high: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, parsed))


def _listify(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple | set):
        return list(value)
    if isinstance(value, str):
        return [item.strip() for item in re.split(r"[,;\n]+", value) if item.strip()]
    return [value]


def _default_title(signal_type: str, hit: dict[str, Any]) -> str:
    product = str(hit.get("product") or hit.get("component") or "product").strip()
    labels = {
        "marketplace_hardware_listing": "Possible prototype or engineering sample listing",
        "firmware_dump_claim": "Possible firmware dump claim",
        "source_code_leak_claim": "Possible source-code leak claim",
        "credential_exposure": "Possible credential exposure",
        "supplier_breach": "Possible supplier breach",
        "zero_day_claim": "Possible zero-day or exploit claim",
        "malicious_package": "Possible package supply-chain issue",
        "darknet_provider_mention": "Closed-source exposure provider mention",
    }
    return f"{labels.get(signal_type, 'Exposure monitoring hit')} for {product}"[:500]
