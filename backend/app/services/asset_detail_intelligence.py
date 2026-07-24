from __future__ import annotations

import ipaddress
import re
from collections import defaultdict
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import Text, cast, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.attack import Technique
from app.models.cve import CVEIOCLink, CVERecord, CVETechniqueLink
from app.models.ioc import IOCIndicator
from app.models.threat_radar import (
    ThreatAlert,
    ThreatAssetScan,
    ThreatSignal,
    ThreatSpaceAsset,
)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_TTP_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
_GENERIC_PRODUCT_TERMS = {
    "api",
    "app",
    "application",
    "cloud",
    "database",
    "device",
    "firmware",
    "gateway",
    "host",
    "http",
    "https",
    "linux",
    "network",
    "server",
    "service",
    "software",
    "system",
    "web",
    "windows",
}


async def build_asset_intelligence(
    session: AsyncSession,
    asset: ThreatSpaceAsset,
    *,
    alert_limit: int = 1000,
    item_limit: int = 200,
) -> dict[str, Any]:
    """Build evidence-labelled intelligence for one exact inventory asset."""

    alerts = (
        await session.execute(
            select(ThreatAlert)
            .where(ThreatAlert.space_id == asset.space_id)
            .order_by(ThreatAlert.score.desc(), ThreatAlert.last_seen.desc())
            .limit(alert_limit)
        )
    ).scalars().all()
    matched_alerts = [row for row in alerts if _alert_matches_asset(row, asset)]
    signal_ids = {row.signal_id for row in matched_alerts if row.signal_id}
    signals = []
    if signal_ids:
        signals = list(
            (
                await session.execute(
                    select(ThreatSignal).where(ThreatSignal.id.in_(signal_ids))
                )
            ).scalars().all()
        )
        signals = [row for row in signals if row.id in signal_ids]

    scans = list(
        (
            await session.execute(
                select(ThreatAssetScan)
                .where(ThreatAssetScan.asset_id == asset.id)
                .order_by(ThreatAssetScan.created_at.desc())
                .limit(25)
            )
        ).scalars().all()
    )

    cve_evidence: dict[str, list[dict[str, Any]]] = defaultdict(list)
    ttp_evidence: dict[str, list[dict[str, Any]]] = defaultdict(list)
    ioc_candidates: list[dict[str, Any]] = []

    for signal in signals:
        evidence = {
            "kind": "matched-signal",
            "label": signal.title,
            "source": signal.source_name or "Threat Radar signal",
            "source_url": signal.source_url,
            "signal_id": str(signal.id),
            "confidence": signal.confidence,
        }
        for cve_id in signal.cve_ids or []:
            normalized = str(cve_id).upper()
            if _CVE_RE.fullmatch(normalized):
                _append_unique(cve_evidence[normalized], evidence)
        for attack_id in signal.technique_ids or []:
            normalized = str(attack_id).upper()
            if _TTP_RE.fullmatch(normalized):
                _append_unique(ttp_evidence[normalized], evidence)
        for raw_ioc in signal.iocs or []:
            if not isinstance(raw_ioc, dict):
                continue
            value = str(
                raw_ioc.get("value")
                or raw_ioc.get("indicator")
                or raw_ioc.get("observable")
                or raw_ioc.get("ioc")
                or ""
            ).strip()
            if value:
                ioc_candidates.append({
                    "id": "",
                    "value": value,
                    "indicator_type": str(
                        raw_ioc.get("type")
                        or raw_ioc.get("ioc_type")
                        or _guess_ioc_type(value)
                    ),
                    "source_id": signal.source_name or "threat-radar-signal",
                    "source_url": signal.source_url,
                    "confidence": int(raw_ioc.get("confidence") or signal.confidence),
                    "last_seen": "",
                    "malware_family": "",
                    "campaign": "",
                    "technique_ids": [],
                    "status": "correlated",
                    "evidence_level": "matched-signal",
                    "matched_on": [signal.title],
                    "verification_required": True,
                    "note": (
                        "This IOC appears in a signal correlated to the asset inventory. "
                        "It is not proof that the IOC was observed on the asset."
                    ),
                })

    for scan in scans:
        scan_label = f"Assessment {scan.created_at.isoformat() if scan.created_at else scan.id}"
        for candidate in (scan.ai_analysis or {}).get("cve_candidates", []):
            if not isinstance(candidate, dict):
                continue
            cve_id = str(candidate.get("cve_id") or "").upper()
            if _CVE_RE.fullmatch(cve_id):
                _append_unique(cve_evidence[cve_id], {
                    "kind": "scan-cpe-candidate",
                    "label": scan_label,
                    "source": "Nmap CPE to local CVE candidate",
                    "scan_id": str(scan.id),
                    "matched_cpe": str(candidate.get("matched_cpe") or ""),
                    "confidence": 45,
                })
        for finding in scan.findings or []:
            if not isinstance(finding, dict):
                continue
            match = _CVE_RE.search(str(finding.get("title") or ""))
            if match:
                cve_id = match.group(0).upper()
                _append_unique(cve_evidence[cve_id], {
                    "kind": str(finding.get("category") or "scan-candidate"),
                    "label": scan_label,
                    "source": str(finding.get("source") or "asset assessment"),
                    "scan_id": str(scan.id),
                    "confidence": 45,
                })

    inventory_identities = _asset_identities(asset)
    direct_iocs = await _direct_inventory_iocs(session, inventory_identities, item_limit)
    ioc_candidates.extend(direct_iocs)

    explicit_cpes = _metadata_values(asset.metadata_json or {}, {"cpe", "cpes", "component_cpe"})
    product_terms = _meaningful_product_terms(asset)
    inventory_cve_rows = await _inventory_cve_candidates(
        session,
        explicit_cpes,
        product_terms,
        item_limit,
    )
    for row, matched_on, exact_cpe in inventory_cve_rows:
        _append_unique(cve_evidence[row.cve_id.upper()], {
            "kind": "inventory-cpe" if exact_cpe else "inventory-name-candidate",
            "label": ", ".join(matched_on[:5]),
            "source": "Asset inventory to local CVE library",
            "confidence": 70 if exact_cpe else 35,
        })

    cve_ids = set(cve_evidence)
    cve_records = await _cve_records(session, cve_ids, item_limit)

    if cve_ids:
        cve_technique_links = list(
            (
                await session.execute(
                    select(CVETechniqueLink)
                    .where(CVETechniqueLink.cve_id.in_(cve_ids))
                    .limit(item_limit * 2)
                )
            ).scalars().all()
        )
        for link in cve_technique_links:
            if link.cve_id.upper() not in cve_ids:
                continue
            attack_id = link.attack_id.upper()
            if _TTP_RE.fullmatch(attack_id):
                _append_unique(ttp_evidence[attack_id], {
                    "kind": "cve-technique-link",
                    "label": link.cve_id.upper(),
                    "source": link.source_id,
                    "confidence": link.confidence,
                    "evidence": link.evidence[:500],
                })

        cve_ioc_links = list(
            (
                await session.execute(
                    select(CVEIOCLink)
                    .where(CVEIOCLink.cve_id.in_(cve_ids))
                    .limit(item_limit)
                )
            ).scalars().all()
        )
        linked_indicator_ids = {row.indicator_id for row in cve_ioc_links}
        linked_indicators: dict[int, IOCIndicator] = {}
        if linked_indicator_ids:
            rows = (
                await session.execute(
                    select(IOCIndicator).where(IOCIndicator.id.in_(linked_indicator_ids))
                )
            ).scalars().all()
            linked_indicators = {row.id: row for row in rows if row.id in linked_indicator_ids}
        for link in cve_ioc_links:
            indicator = linked_indicators.get(link.indicator_id)
            if not indicator or link.cve_id.upper() not in cve_ids:
                continue
            ioc_candidates.append(_ioc_obj(
                indicator,
                status="correlated",
                evidence_level="cve-linked",
                matched_on=[link.cve_id.upper()],
                note=(
                    "This IOC has a source-backed relationship to a relevant CVE. "
                    "It is not proof that the IOC was observed on the asset."
                ),
            ))

    for ioc in ioc_candidates:
        for attack_id in ioc.get("technique_ids", []):
            normalized = str(attack_id).upper()
            if _TTP_RE.fullmatch(normalized):
                _append_unique(ttp_evidence[normalized], {
                    "kind": "ioc-technique-link",
                    "label": str(ioc.get("value") or ""),
                    "source": str(ioc.get("source_id") or "IOC library"),
                    "confidence": int(ioc.get("confidence") or 50),
                })

    for attack_id in _asset_metadata_ttps(asset):
        _append_unique(ttp_evidence[attack_id], {
            "kind": "inventory-analysis-candidate",
            "label": "Imported asset analysis",
            "source": "Asset inventory metadata",
            "confidence": 40,
        })

    techniques = await _technique_rows(session, set(ttp_evidence), item_limit)
    cves = _serialize_cves(cve_evidence, cve_records, item_limit)
    iocs = _dedupe_iocs(ioc_candidates)[:item_limit]
    ttps = _serialize_ttps(ttp_evidence, techniques, item_limit)
    serialized_alerts = [_alert_obj(row) for row in matched_alerts[:item_limit]]
    serialized_scans = [_scan_summary(row) for row in scans]
    open_services = sum(
        int((row.nmap_result or {}).get("open_port_count") or 0)
        for row in scans[:1]
    )
    risk_score = _risk_score(asset, cves, iocs, serialized_alerts, open_services)

    return {
        "summary": {
            "risk_score": risk_score,
            "risk_level": _risk_level(risk_score),
            "alerts": len(serialized_alerts),
            "cves": len(cves),
            "known_exploited_cves": sum(1 for row in cves if row["known_exploited"]),
            "ttps": len(ttps),
            "iocs": len(iocs),
            "direct_ioc_matches": sum(
                1 for row in iocs if row["evidence_level"] == "exact-inventory-identity"
            ),
            "assessments": len(serialized_scans),
            "latest_open_services": open_services,
            "last_assessed_at": (
                scans[0].completed_at or scans[0].created_at
            ) if scans else None,
        },
        "cves": cves,
        "ttps": ttps,
        "iocs": iocs,
        "alerts": serialized_alerts,
        "recent_scans": serialized_scans,
        "evidence_boundary": (
            "Exact IOC identity matches show that an inventory endpoint is present in the "
            "local IOC library, not that the asset is compromised. Signal, CVE, and TTP "
            "correlations are investigation leads. Product-name and scan-CPE CVE matches "
            "remain candidates until the affected version and configuration are verified."
        ),
    }


def _alert_matches_asset(alert: ThreatAlert, asset: ThreatSpaceAsset) -> bool:
    asset_uuid = str(asset.id).casefold()
    asset_id = asset.asset_id.casefold()
    asset_name = asset.name.casefold()
    keys = {
        asset_uuid,
        asset_id,
        asset_name,
        *[str(item).casefold() for item in asset.ip_addresses or []],
        *[str(item).casefold() for item in asset.domains or []],
    }
    for match in alert.matches or []:
        if not isinstance(match, dict):
            continue
        if str(match.get("asset_uuid") or "").casefold() == asset_uuid:
            return True
        if str(match.get("asset_id") or "").casefold() == asset_id:
            return True
        if str(match.get("inventory_entity") or "").casefold() in keys:
            return True
    return False


def _asset_identities(asset: ThreatSpaceAsset) -> set[str]:
    identities = {
        str(item).strip().casefold()
        for item in asset.ip_addresses or []
        if str(item).strip()
    }
    for raw in asset.domains or []:
        text = str(raw).strip()
        if not text:
            continue
        parsed = urlsplit(text if "://" in text else f"//{text}")
        host = (parsed.hostname or "").casefold().rstrip(".")
        if host:
            identities.add(host)
        if "://" in text:
            identities.add(text.casefold())
    return identities


async def _direct_inventory_iocs(
    session: AsyncSession,
    identities: set[str],
    limit: int,
) -> list[dict[str, Any]]:
    if not identities:
        return []
    rows = list(
        (
            await session.execute(
                select(IOCIndicator)
                .where(func.lower(IOCIndicator.value).in_(identities))
                .order_by(IOCIndicator.confidence.desc(), IOCIndicator.updated_at.desc())
                .limit(limit)
            )
        ).scalars().all()
    )
    return [
        _ioc_obj(
            row,
            status="exact-match",
            evidence_level="exact-inventory-identity",
            matched_on=[row.value],
            note=(
                "The saved inventory identity exactly matches an IOC library value. "
                "Validate freshness, ownership, and source context before escalation."
            ),
        )
        for row in rows
        if row.value.strip().casefold() in identities
    ]


async def _inventory_cve_candidates(
    session: AsyncSession,
    cpes: list[str],
    product_terms: list[str],
    limit: int,
) -> list[tuple[CVERecord, list[str], bool]]:
    predicates = []
    for value in [*cpes, *product_terms][:16]:
        escaped = _escape_like(value.casefold())
        predicates.append(func.lower(cast(CVERecord.cpe_matches, Text)).like(
            f"%{escaped}%",
            escape="\\",
        ))
    if not predicates:
        return []
    rows = list(
        (
            await session.execute(
                select(CVERecord)
                .where(or_(*predicates))
                .order_by(
                    CVERecord.known_exploited.desc(),
                    CVERecord.cvss_score.desc().nulls_last(),
                    CVERecord.last_modified.desc().nulls_last(),
                )
                .limit(limit)
            )
        ).scalars().all()
    )
    results: list[tuple[CVERecord, list[str], bool]] = []
    for row in rows:
        haystack = str(row.cpe_matches or "").casefold()
        matched_cpes = [item for item in cpes if item.casefold() in haystack]
        matched_terms = [
            item for item in product_terms
            if _term_in_cpe_text(item.casefold(), haystack)
        ]
        matched = [*matched_cpes, *matched_terms]
        if matched:
            results.append((row, matched, bool(matched_cpes)))
    return results


async def _cve_records(
    session: AsyncSession,
    cve_ids: set[str],
    limit: int,
) -> dict[str, CVERecord]:
    if not cve_ids:
        return {}
    rows = (
        await session.execute(
            select(CVERecord)
            .where(CVERecord.cve_id.in_(cve_ids))
            .limit(limit)
        )
    ).scalars().all()
    return {
        row.cve_id.upper(): row
        for row in rows
        if row.cve_id.upper() in cve_ids
    }


async def _technique_rows(
    session: AsyncSession,
    attack_ids: set[str],
    limit: int,
) -> dict[str, Technique]:
    if not attack_ids:
        return {}
    rows = (
        await session.execute(
            select(Technique)
            .where(Technique.attack_id.in_(attack_ids))
            .order_by(Technique.version_id.desc())
            .limit(limit * 3)
        )
    ).scalars().all()
    output: dict[str, Technique] = {}
    for row in rows:
        attack_id = row.attack_id.upper()
        if attack_id in attack_ids and attack_id not in output:
            output[attack_id] = row
    return output


def _serialize_cves(
    evidence: dict[str, list[dict[str, Any]]],
    records: dict[str, CVERecord],
    limit: int,
) -> list[dict[str, Any]]:
    rows = []
    for cve_id, evidence_rows in evidence.items():
        record = records.get(cve_id)
        evidence_kinds = {row["kind"] for row in evidence_rows}
        correlated = bool(evidence_kinds & {"matched-signal", "inventory-cpe"})
        rows.append({
            "cve_id": cve_id,
            "description": record.description[:1000] if record else "",
            "severity": record.cvss_severity if record else "",
            "score": record.cvss_score if record else "",
            "known_exploited": bool(record.known_exploited) if record else False,
            "published": record.published if record else None,
            "last_modified": record.last_modified if record else None,
            "references": (record.references or [])[:8] if record else [],
            "status": "correlated" if correlated else "candidate",
            "evidence_level": (
                "source-backed-correlation" if "matched-signal" in evidence_kinds
                else "inventory-cpe-candidate" if "inventory-cpe" in evidence_kinds
                else "review-required-candidate"
            ),
            "evidence": evidence_rows,
            "verification_required": True,
        })
    severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2}
    return sorted(
        rows,
        key=lambda row: (
            row["known_exploited"],
            severity_rank.get(str(row["severity"]).casefold(), 0),
            _float_score(row["score"]),
            row["cve_id"],
        ),
        reverse=True,
    )[:limit]


def _serialize_ttps(
    evidence: dict[str, list[dict[str, Any]]],
    techniques: dict[str, Technique],
    limit: int,
) -> list[dict[str, Any]]:
    rows = []
    for attack_id, evidence_rows in evidence.items():
        technique = techniques.get(attack_id)
        rows.append({
            "attack_id": attack_id,
            "name": technique.name if technique else "",
            "description": technique.description[:1000] if technique else "",
            "url": technique.url if technique else "",
            "platforms": technique.platforms or [] if technique else [],
            "data_sources": technique.data_sources or [] if technique else [],
            "evidence_level": (
                "source-backed-correlation"
                if any(row["kind"] in {"matched-signal", "cve-technique-link"} for row in evidence_rows)
                else "review-required-candidate"
            ),
            "evidence": evidence_rows,
            "verification_required": True,
        })
    return sorted(rows, key=lambda row: row["attack_id"])[:limit]


def _ioc_obj(
    row: IOCIndicator,
    *,
    status: str,
    evidence_level: str,
    matched_on: list[str],
    note: str,
) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "value": row.value,
        "indicator_type": row.indicator_type,
        "source_id": row.source_id,
        "source_url": row.source_url,
        "confidence": row.confidence,
        "last_seen": row.last_seen or "",
        "malware_family": row.malware_family,
        "campaign": row.campaign,
        "technique_ids": row.technique_ids or [],
        "status": status,
        "evidence_level": evidence_level,
        "matched_on": matched_on,
        "verification_required": True,
        "note": note,
    }


def _dedupe_iocs(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: dict[tuple[str, str], dict[str, Any]] = {}
    rank = {
        "exact-inventory-identity": 3,
        "matched-signal": 2,
        "cve-linked": 1,
    }
    for row in rows:
        key = (
            str(row.get("indicator_type") or "ioc").casefold(),
            str(row.get("value") or "").casefold(),
        )
        if not key[1]:
            continue
        current = output.get(key)
        if not current or rank.get(str(row.get("evidence_level")), 0) > rank.get(
            str(current.get("evidence_level")),
            0,
        ):
            output[key] = row
    return sorted(
        output.values(),
        key=lambda row: (
            rank.get(str(row.get("evidence_level")), 0),
            int(row.get("confidence") or 0),
            str(row.get("value") or ""),
        ),
        reverse=True,
    )


def _alert_obj(alert: ThreatAlert) -> dict[str, Any]:
    return {
        "id": str(alert.id),
        "signal_id": str(alert.signal_id) if alert.signal_id else None,
        "case_id": str(alert.case_id) if alert.case_id else None,
        "title": alert.title,
        "description": alert.description,
        "status": alert.status,
        "priority": alert.priority,
        "severity": alert.severity,
        "score": alert.score,
        "match_type": alert.match_type,
        "matches": alert.matches or [],
        "first_seen": alert.first_seen,
        "last_seen": alert.last_seen,
        "route": (
            f"/threat-radar?tab=detail&signal_id={alert.signal_id}"
            if alert.signal_id else "/threat-radar"
        ),
    }


def _scan_summary(scan: ThreatAssetScan) -> dict[str, Any]:
    return {
        "id": str(scan.id),
        "target": scan.target,
        "status": scan.status,
        "scan_profile": scan.scan_profile,
        "nmap_requested": scan.nmap_requested,
        "open_port_count": int((scan.nmap_result or {}).get("open_port_count") or 0),
        "finding_count": len(scan.findings or []),
        "ai_requested": scan.ai_requested,
        "ai_provider": scan.ai_provider,
        "risk_level": str((scan.ai_analysis or {}).get("risk_level") or "unknown"),
        "requested_by": scan.requested_by,
        "completed_at": scan.completed_at,
        "created_at": scan.created_at,
    }


def _meaningful_product_terms(asset: ThreatSpaceAsset) -> list[str]:
    values = [*(asset.products or []), *(asset.components or []), *(asset.technologies or [])]
    output = []
    for value in values:
        normalized = str(value).strip().casefold()
        if (
            len(normalized) >= 4
            and normalized not in _GENERIC_PRODUCT_TERMS
            and normalized not in output
        ):
            output.append(normalized)
    return output[:12]


def _metadata_values(value: Any, keys: set[str]) -> list[str]:
    output: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).casefold() in keys:
                if isinstance(item, list):
                    output.extend(str(entry).strip() for entry in item if str(entry).strip())
                elif str(item).strip():
                    output.append(str(item).strip())
            output.extend(_metadata_values(item, keys))
    elif isinstance(value, list):
        for item in value:
            output.extend(_metadata_values(item, keys))
    return list(dict.fromkeys(output))


def _asset_metadata_ttps(asset: ThreatSpaceAsset) -> list[str]:
    values = [
        *_metadata_values(
            asset.metadata_json or {},
            {"ttp", "ttps", "technique", "techniques", "technique_ids", "ttp_candidates"},
        ),
        *(asset.tags or []),
    ]
    found = {
        match.group(0).upper()
        for value in values
        for match in _TTP_RE.finditer(str(value))
    }
    return sorted(found)


def _term_in_cpe_text(term: str, haystack: str) -> bool:
    tokens = [re.escape(item) for item in re.split(r"[^a-z0-9]+", term) if item]
    if not tokens:
        return False
    token = r"[^a-z0-9]+".join(tokens)
    return bool(re.search(rf"(?:^|[^a-z0-9]){token}(?:$|[^a-z0-9])", haystack))


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _append_unique(rows: list[dict[str, Any]], value: dict[str, Any]) -> None:
    marker = (
        str(value.get("kind") or ""),
        str(value.get("signal_id") or value.get("scan_id") or value.get("label") or ""),
        str(value.get("source") or ""),
    )
    if not any(
        (
            str(row.get("kind") or ""),
            str(row.get("signal_id") or row.get("scan_id") or row.get("label") or ""),
            str(row.get("source") or ""),
        ) == marker
        for row in rows
    ):
        rows.append(value)


def _guess_ioc_type(value: str) -> str:
    text = value.strip()
    try:
        ipaddress.ip_address(text)
        return "ip"
    except ValueError:
        pass
    if text.startswith(("http://", "https://")):
        return "url"
    if "." in text and "/" not in text and "@" not in text:
        return "domain"
    if len(text) in {32, 40, 64} and all(char in "0123456789abcdefABCDEF" for char in text):
        return "hash"
    return "ioc"


def _risk_score(
    asset: ThreatSpaceAsset,
    cves: list[dict[str, Any]],
    iocs: list[dict[str, Any]],
    alerts: list[dict[str, Any]],
    open_services: int,
) -> int:
    score = {
        "critical": 20,
        "high": 14,
        "medium": 8,
        "low": 3,
    }.get(asset.criticality.casefold(), 5)
    score += {
        "internet": 18,
        "external": 14,
        "third-party": 12,
        "customer": 8,
        "internal": 3,
    }.get(asset.exposure.casefold(), 5)
    score += min(
        sum(
            20 if row["known_exploited"]
            else 7 if row["evidence_level"] == "source-backed-correlation"
            else 4 if row["evidence_level"] == "inventory-cpe-candidate"
            else 1
            for row in cves
        ),
        35,
    )
    score += min(
        sum(15 for row in iocs if row["evidence_level"] == "exact-inventory-identity"),
        25,
    )
    score += min(sum(max(int(row.get("score") or 0), 0) // 20 for row in alerts), 15)
    score += min(open_services * 2, 10)
    return min(score, 100)


def _risk_level(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def _float_score(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0
