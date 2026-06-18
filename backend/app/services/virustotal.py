from __future__ import annotations

import base64
import ipaddress
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.models.attack import AptGroup, AptGroupTechnique, AttackVersion, Technique

VT_BASE_URL = "https://www.virustotal.com/api/v3"
ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
NOISY_ACTOR_TERMS = {
    "apt",
    "rat",
    "trojan",
    "malware",
    "ransomware",
    "backdoor",
    "loader",
    "stealer",
    "phishing",
    "windows",
    "linux",
    "macos",
}


@dataclass(frozen=True)
class IndicatorTarget:
    value: str
    type: str
    endpoint: str
    vt_url: str


def classify_indicator(value: str) -> IndicatorTarget:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("Indicator is empty")
    normalized_ip = _strip_ip_port(cleaned)

    if HASH_RE.match(cleaned):
        return IndicatorTarget(
            value=cleaned.lower(),
            type="hash",
            endpoint=f"/files/{cleaned.lower()}",
            vt_url=f"https://www.virustotal.com/gui/file/{cleaned.lower()}",
        )

    try:
        ipaddress.ip_address(normalized_ip)
        return IndicatorTarget(
            value=normalized_ip,
            type="ip",
            endpoint=f"/ip_addresses/{normalized_ip}",
            vt_url=f"https://www.virustotal.com/gui/ip-address/{normalized_ip}",
        )
    except ValueError:
        pass

    parsed = urlparse(cleaned)
    if parsed.scheme and parsed.netloc:
        url_id = base64.urlsafe_b64encode(cleaned.encode()).decode().rstrip("=")
        return IndicatorTarget(
            value=cleaned,
            type="url",
            endpoint=f"/urls/{url_id}",
            vt_url=f"https://www.virustotal.com/gui/url/{url_id}",
        )

    domain = _strip_domain_port(cleaned).lower().strip("/")
    if "." in domain and "/" not in domain and " " not in domain:
        if not _valid_domain(domain):
            return IndicatorTarget(
                value=cleaned,
                type="search",
                endpoint="/search",
                vt_url=f"https://www.virustotal.com/gui/search/{cleaned}",
            )
        return IndicatorTarget(
            value=domain,
            type="domain",
            endpoint=f"/domains/{domain}",
            vt_url=f"https://www.virustotal.com/gui/domain/{domain}",
        )

    return IndicatorTarget(
        value=cleaned,
        type="search",
        endpoint="/search",
        vt_url=f"https://www.virustotal.com/gui/search/{cleaned}",
    )


def _valid_domain(value: str) -> bool:
    if len(value) > 253:
        return False
    labels = value.rstrip(".").split(".")
    if len(labels) < 2:
        return False
    label_re = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
    return all(label_re.fullmatch(label) for label in labels)


def _strip_ip_port(value: str) -> str:
    """Normalize host:port IOCs before choosing the VirusTotal endpoint."""
    if value.startswith("[") and "]" in value:
        host, _, suffix = value[1:].partition("]")
        if suffix.startswith(":"):
            try:
                ipaddress.ip_address(host)
                return host
            except ValueError:
                return value
    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        if port.isdigit():
            try:
                ipaddress.ip_address(host)
                return host
            except ValueError:
                return value
    return value


def _strip_domain_port(value: str) -> str:
    if value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        if port.isdigit() and "." in host and "/" not in host and " " not in host:
            return host
    return value


async def lookup_virustotal_ioc(
    session: AsyncSession,
    indicator: str,
    domain: str = "enterprise-attack",
) -> dict[str, Any]:
    if not settings.virustotal_api_key:
        raise RuntimeError("VIRUSTOTAL_API_KEY is not configured")

    target = classify_indicator(indicator)
    headers = {"x-apikey": settings.virustotal_api_key}

    async with httpx.AsyncClient(base_url=VT_BASE_URL, headers=headers, timeout=25) as client:
        if target.type == "search":
            search_response = await _vt_search(client, target.value)
            return await _search_lookup_result(session, target, search_response, domain)
        try:
            object_response = await _vt_get(client, target.endpoint)
        except httpx.HTTPStatusError as exc:
            if target.type == "domain" and exc.response.status_code == 400:
                search_target = IndicatorTarget(
                    value=indicator.strip(),
                    type="search",
                    endpoint="/search",
                    vt_url=f"https://www.virustotal.com/gui/search/{indicator.strip()}",
                )
                search_response = await _vt_search(client, search_target.value)
                return await _search_lookup_result(session, search_target, search_response, domain)
            raise
        mitre_response: dict[str, Any] | None = None
        if target.type == "hash":
            try:
                mitre_response = await _vt_get(client, f"/files/{target.value}/behaviour_mitre_trees")
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code not in {400, 404}:
                    raise

    attributes = object_response.get("data", {}).get("attributes", {})
    ttp_evidence = _extract_ttp_evidence(attributes, "object attributes")
    ttp_evidence.extend(_extract_ttp_evidence(mitre_response or {}, "behavior MITRE tree"))
    technique_ids = sorted({item["attack_id"] for item in ttp_evidence})
    techniques = await _resolve_techniques(session, technique_ids, domain)
    actors = await _match_local_actors(session, attributes, mitre_response or {}, domain)
    context_text = _flatten_text([attributes, mitre_response or {}])

    return {
        "indicator": target.value,
        "type": target.type,
        "virustotal_url": target.vt_url,
        "permalink": attributes.get("permalink") or target.vt_url,
        "summary": _summary(attributes),
        "reputation": attributes.get("reputation", 0),
        "total_votes": attributes.get("total_votes") or {},
        "last_analysis_stats": attributes.get("last_analysis_stats", {}),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "first_submission_date": attributes.get("first_submission_date"),
        "last_submission_date": attributes.get("last_submission_date"),
        "last_modification_date": attributes.get("last_modification_date"),
        "names": _names(attributes),
        "tags": _dedupe_str_list(attributes.get("tags", [])),
        "threat_names": _threat_names(attributes),
        "detections": _detections(attributes),
        "ttps": techniques,
        "ttp_evidence": ttp_evidence[:80],
        "actors": actors,
        "rules": _crowdsourced_rules(attributes),
        "sandbox_verdicts": _sandbox_verdicts(attributes),
        "dns_records": _dns_records(attributes),
        "resolutions": _resolutions(attributes),
        "whois": _short_text(attributes.get("whois", ""), 1200),
        "network": _network_metadata(attributes),
        "context": _context(attributes, mitre_response, context_text),
    }


async def _vt_get(client: httpx.AsyncClient, endpoint: str) -> dict[str, Any]:
    response = await client.get(endpoint)
    if response.status_code == 404:
        raise ValueError("Indicator was not found in VirusTotal.")
    if response.status_code == 401:
        raise RuntimeError("VirusTotal API key was rejected.")
    if response.status_code == 429:
        raise RuntimeError("VirusTotal API rate limit exceeded.")
    response.raise_for_status()
    return response.json()


async def _vt_search(client: httpx.AsyncClient, query: str) -> dict[str, Any]:
    response = await client.get("/search", params={"query": query})
    if response.status_code == 401:
        raise RuntimeError("VirusTotal API key was rejected.")
    if response.status_code == 429:
        raise RuntimeError("VirusTotal API rate limit exceeded.")
    if response.status_code in {400, 403}:
        raise ValueError(
            "This value is not a direct IOC and VirusTotal search rejected it. "
            "Use an IP, domain, URL, MD5, SHA1, SHA256, or a VT account that supports search."
        )
    response.raise_for_status()
    return response.json()


async def _search_lookup_result(
    session: AsyncSession,
    target: IndicatorTarget,
    search_response: dict[str, Any],
    domain: str,
) -> dict[str, Any]:
    rows = search_response.get("data") or []
    flattened = _flatten_text(rows)
    pseudo_attributes = {
        "meaningful_name": target.value,
        "names": _search_names(rows),
        "tags": _search_tags(rows),
        "popular_threat_classification": {"suggested_threat_label": target.value},
        "last_analysis_stats": _aggregate_search_stats(rows),
        "last_analysis_results": {},
    }
    ttp_evidence = _extract_ttp_evidence(rows, "VirusTotal search results")
    technique_ids = sorted({item["attack_id"] for item in ttp_evidence})
    techniques = await _resolve_techniques(session, technique_ids, domain)
    actors = await _match_local_actors(session, pseudo_attributes, search_response, domain)
    return {
        "indicator": target.value,
        "type": "search",
        "virustotal_url": target.vt_url,
        "permalink": target.vt_url,
        "summary": f"VirusTotal search returned {len(rows)} related object(s). Use this view for malware names, family names, and non-IOC labels.",
        "reputation": 0,
        "total_votes": {},
        "last_analysis_stats": pseudo_attributes["last_analysis_stats"],
        "last_analysis_date": None,
        "first_submission_date": None,
        "last_submission_date": None,
        "last_modification_date": None,
        "names": pseudo_attributes["names"],
        "tags": pseudo_attributes["tags"],
        "threat_names": _dedupe_str_list([target.value, *_search_threat_names(rows)]),
        "detections": [],
        "ttps": techniques,
        "ttp_evidence": ttp_evidence[:80],
        "actors": actors,
        "rules": _search_rules(rows),
        "sandbox_verdicts": [],
        "dns_records": [],
        "resolutions": [],
        "whois": "",
        "network": {},
        "context": {
            "search_result_count": len(rows),
            "has_mitre_behavior": False,
            "crowdsourced_yara_count": len([rule for rule in _search_rules(rows) if rule["type"] == "YARA"]),
            "crowdsourced_ids_count": len([rule for rule in _search_rules(rows) if rule["type"] == "IDS"]),
            "sigma_result_count": len([rule for rule in _search_rules(rows) if rule["type"] == "Sigma"]),
            "sandbox_verdict_count": 0,
            "has_network_metadata": False,
            "context_terms": _dedupe_str_list(flattened.split())[:40],
        },
    }


def _search_attributes(rows: list[Any]) -> list[dict[str, Any]]:
    attrs: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        data = row.get("attributes") if isinstance(row.get("attributes"), dict) else row
        if isinstance(data, dict):
            attrs.append(data)
    return attrs


def _search_names(rows: list[Any]) -> list[str]:
    names: list[Any] = []
    for attributes in _search_attributes(rows):
        names.extend(_names(attributes))
    return _dedupe_str_list(names)[:40]


def _search_tags(rows: list[Any]) -> list[str]:
    tags: list[Any] = []
    for attributes in _search_attributes(rows):
        tags.extend(attributes.get("tags") or [])
    return _dedupe_str_list(tags)[:60]


def _search_threat_names(rows: list[Any]) -> list[str]:
    names: list[str] = []
    for attributes in _search_attributes(rows):
        names.extend(_threat_names(attributes))
    return _dedupe_str_list(names)[:40]


def _aggregate_search_stats(rows: list[Any]) -> dict[str, int]:
    totals = {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
    for attributes in _search_attributes(rows):
        stats = attributes.get("last_analysis_stats") or {}
        for key in totals:
            totals[key] += int(stats.get(key) or 0)
    return totals


def _search_rules(rows: list[Any]) -> list[dict[str, str]]:
    rules: list[dict[str, str]] = []
    for attributes in _search_attributes(rows):
        rules.extend(_crowdsourced_rules(attributes))
    return rules[:30]


def _summary(attributes: dict[str, Any]) -> str:
    stats = attributes.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    harmless = int(stats.get("harmless") or 0)
    undetected = int(stats.get("undetected") or 0)
    if malicious or suspicious:
        return f"{malicious} engines marked malicious and {suspicious} suspicious; {harmless} harmless, {undetected} undetected."
    return f"No malicious detections in last analysis; {harmless} harmless, {undetected} undetected."


def _threat_names(attributes: dict[str, Any]) -> list[str]:
    names: list[str] = []
    classification = attributes.get("popular_threat_classification") or {}
    for key in ("suggested_threat_label",):
        if classification.get(key):
            names.append(str(classification[key]))
    for bucket in ("popular_threat_name", "popular_threat_category"):
        for item in classification.get(bucket) or []:
            value = item.get("value") if isinstance(item, dict) else item
            if value:
                names.append(str(value))
    for key in ("meaningful_name", "popular_threat_name"):
        if attributes.get(key):
            names.append(str(attributes[key]))
    return _dedupe_str_list(names)


def _names(attributes: dict[str, Any]) -> list[str]:
    names: list[Any] = []
    for key in ("meaningful_name", "display_name", "title"):
        if attributes.get(key):
            names.append(attributes[key])
    names.extend(attributes.get("names") or [])
    return _dedupe_str_list(names)[:40]


def _detections(attributes: dict[str, Any], limit: int = 18) -> list[dict[str, str]]:
    results = attributes.get("last_analysis_results") or {}
    rows = []
    for engine, data in results.items():
        if not isinstance(data, dict):
            continue
        category = str(data.get("category") or "")
        result = str(data.get("result") or "")
        if category in {"malicious", "suspicious"} or result:
            rows.append({"engine": str(engine), "category": category, "result": result})
    rows.sort(key=lambda row: (row["category"] != "malicious", row["engine"].lower()))
    return rows[:limit]


def _extract_ttp_evidence(value: Any, source: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []

    def walk(item: Any, path: str, parent: dict[str, Any] | None = None) -> None:
        if isinstance(item, dict):
            candidate_id = item.get("technique_id") or item.get("attack_id") or item.get("external_id")
            candidate_name = item.get("technique") or item.get("technique_name") or item.get("name")
            tactic = item.get("tactic") or item.get("tactic_name")
            if candidate_id and ATTACK_ID_RE.fullmatch(str(candidate_id).strip(),):
                rows.append({
                    "attack_id": str(candidate_id).strip().upper(),
                    "name": str(candidate_name or ""),
                    "tactic": str(tactic or ""),
                    "source": source,
                    "evidence": _short_text(_flatten_text(item), 260),
                })
            for key, child in item.items():
                walk(child, f"{path}.{key}" if path else str(key), item)
            return
        if isinstance(item, list):
            for index, child in enumerate(item):
                walk(child, f"{path}[{index}]", parent)
            return
        text = str(item) if item is not None else ""
        for match in ATTACK_ID_RE.findall(text):
            rows.append({
                "attack_id": match.upper(),
                "name": _related_name(parent),
                "tactic": _related_tactic(parent),
                "source": source,
                "evidence": _short_text(text if len(text) > 12 else path, 260),
            })

    walk(value, "")
    seen = set()
    output = []
    for row in rows:
        key = (row["attack_id"], row["source"], row["evidence"].lower())
        if key not in seen:
            seen.add(key)
            output.append(row)
    return output


def _related_name(parent: dict[str, Any] | None) -> str:
    if not parent:
        return ""
    for key in ("technique_name", "technique", "name", "rule_name", "signature_name"):
        if parent.get(key):
            return str(parent[key])
    return ""


def _related_tactic(parent: dict[str, Any] | None) -> str:
    if not parent:
        return ""
    for key in ("tactic", "tactic_name", "kill_chain_phase"):
        if parent.get(key):
            return str(parent[key])
    return ""


async def _resolve_techniques(session: AsyncSession, attack_ids: list[str], domain: str) -> list[dict[str, Any]]:
    if not attack_ids:
        return []
    try:
        version_id = await _latest_version_id(session, domain)
        if not version_id:
            return [{"attack_id": attack_id, "name": "", "tactics": [], "url": ""} for attack_id in attack_ids]
        rows = await session.execute(
            select(Technique)
            .options(selectinload(Technique.tactics))
            .where(Technique.version_id == version_id, Technique.attack_id.in_(attack_ids))
        )
        by_id = {tech.attack_id: tech for tech in rows.scalars().all()}
        resolved = []
        for attack_id in attack_ids:
            tech = by_id.get(attack_id)
            resolved.append({
                "attack_id": attack_id,
                "name": tech.name if tech else "",
                "tactics": [t.shortname for t in tech.tactics] if tech else [],
                "url": tech.url if tech else "",
            })
        return resolved
    except Exception:
        return [{"attack_id": attack_id, "name": "", "tactics": [], "url": ""} for attack_id in attack_ids]


async def _match_local_actors(
    session: AsyncSession,
    attributes: dict[str, Any],
    mitre_response: dict[str, Any],
    domain: str,
) -> list[dict[str, Any]]:
    actor_context = _actor_context(attributes, mitre_response)
    if not actor_context["text"]:
        return []
    try:
        version_id = await _latest_version_id(session, domain)
        if not version_id:
            return []
        rows = await session.execute(
            select(AptGroup)
            .options(selectinload(AptGroup.technique_usages).selectinload(AptGroupTechnique.technique))
            .where(AptGroup.version_id == version_id)
        )
        matches = []
        for group in rows.scalars().all():
            aliases = [str(alias) for alias in (group.aliases or [])]
            actor_terms = [group.name, *aliases]
            matched, evidence = _match_actor_terms(actor_terms, actor_context)
            if matched:
                technique_ids = sorted({usage.technique.attack_id for usage in group.technique_usages if usage.technique})
                matches.append({
                    "attack_id": group.attack_id,
                    "name": group.name,
                    "aliases": aliases,
                    "matched_terms": matched,
                    "evidence": evidence,
                    "technique_ids": technique_ids,
                    "url": group.url,
                })
        return sorted(matches, key=lambda item: (-len(item["matched_terms"]), item["name"].lower()))[:12]
    except Exception:
        return []


async def _latest_version_id(session: AsyncSession, domain: str) -> int | None:
    row = await session.execute(select(AttackVersion.id).where(AttackVersion.domain == domain, AttackVersion.is_latest.is_(True)))
    return row.scalar_one_or_none()


def _actor_context(attributes: dict[str, Any], mitre_response: dict[str, Any]) -> dict[str, Any]:
    fields: list[dict[str, str]] = []

    def add(source: str, value: Any) -> None:
        text = _short_text(_flatten_text(value), 700)
        if text:
            fields.append({"source": source, "text": text})

    add("threat labels", _threat_names(attributes))
    add("tags", attributes.get("tags"))
    add("names", _names(attributes))
    add("popular threat classification", attributes.get("popular_threat_classification"))
    add("crowdsourced YARA", attributes.get("crowdsourced_yara_results"))
    add("crowdsourced IDS", attributes.get("crowdsourced_ids_results"))
    add("Sigma analysis", attributes.get("sigma_analysis_results"))
    add("sandbox verdicts", attributes.get("sandbox_verdicts"))
    add("malware config", attributes.get("malware_config"))
    add("behavior MITRE tree", mitre_response)
    text = "\n".join(item["text"] for item in fields).lower()
    return {"fields": fields, "text": text}


def _match_actor_terms(actor_terms: list[str], context: dict[str, Any]) -> tuple[list[str], list[dict[str, str]]]:
    matched: list[str] = []
    evidence: list[dict[str, str]] = []
    full_text = context["text"]
    normalized_full_text = _compact_actor_text(full_text)
    for term in actor_terms:
        clean = term.strip()
        if not _actor_term_is_useful(clean):
            continue
        pattern = _term_pattern(clean)
        normalized_term = _compact_actor_text(clean)
        if not pattern.search(full_text) and normalized_term not in normalized_full_text:
            continue
        matched.append(clean)
        for field in context["fields"]:
            field_text = field["text"].lower()
            if pattern.search(field_text) or normalized_term in _compact_actor_text(field_text):
                evidence.append({
                    "term": clean,
                    "source": field["source"],
                    "evidence": _snippet(field["text"], clean),
                })
                break
    return _dedupe_str_list(matched), evidence[:8]


def _actor_term_is_useful(term: str) -> bool:
    lowered = term.lower()
    if len(lowered) < 4 or lowered in NOISY_ACTOR_TERMS:
        return False
    return bool(re.search(r"[a-z0-9]", lowered))


def _term_pattern(term: str) -> re.Pattern[str]:
    escaped = re.escape(term.lower())
    escaped = escaped.replace(r"\ ", r"[\s_.:/-]+")
    return re.compile(rf"(?<![a-z0-9]){escaped}(?![a-z0-9])")


def _compact_actor_text(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _snippet(text: str, term: str, size: int = 180) -> str:
    lowered = text.lower()
    index = lowered.find(term.lower())
    if index < 0:
        return _short_text(text, size)
    start = max(0, index - size // 3)
    end = min(len(text), index + len(term) + size)
    return _short_text(text[start:end], size)


def _crowdsourced_rules(attributes: dict[str, Any]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    mappings = [
        ("YARA", "crowdsourced_yara_results"),
        ("IDS", "crowdsourced_ids_results"),
        ("Sigma", "sigma_analysis_results"),
    ]
    for rule_type, key in mappings:
        for item in attributes.get(key) or []:
            if not isinstance(item, dict):
                continue
            rows.append({
                "type": rule_type,
                "name": str(item.get("rule_name") or item.get("rule_title") or item.get("name") or item.get("alert_context") or ""),
                "source": str(item.get("source") or item.get("author") or item.get("ruleset_name") or ""),
                "severity": str(item.get("rule_severity") or item.get("severity") or item.get("rule_category") or ""),
                "description": _short_text(item.get("description") or item.get("rule_description") or item.get("match_context") or "", 260),
            })
    return [row for row in rows if row["name"] or row["description"]][:30]


def _sandbox_verdicts(attributes: dict[str, Any]) -> list[dict[str, str]]:
    verdicts = attributes.get("sandbox_verdicts") or {}
    rows = []
    if isinstance(verdicts, dict):
        for sandbox, item in verdicts.items():
            if not isinstance(item, dict):
                continue
            rows.append({
                "sandbox": str(sandbox),
                "category": str(item.get("category") or ""),
                "malware_classification": str(item.get("malware_classification") or ""),
                "malware_names": ", ".join(_dedupe_str_list(_as_list(item.get("malware_names")))[:8]),
                "confidence": str(item.get("confidence") or ""),
            })
    return rows[:20]


def _dns_records(attributes: dict[str, Any]) -> list[dict[str, str]]:
    rows = []
    for item in attributes.get("last_dns_records") or []:
        if not isinstance(item, dict):
            continue
        rows.append({
            "type": str(item.get("type") or ""),
            "value": str(item.get("value") or ""),
            "ttl": str(item.get("ttl") or ""),
        })
    return rows[:30]


def _resolutions(attributes: dict[str, Any]) -> list[dict[str, str]]:
    rows = []
    for item in attributes.get("resolutions") or []:
        if not isinstance(item, dict):
            continue
        rows.append({
            "host_name": str(item.get("host_name") or ""),
            "ip_address": str(item.get("ip_address") or ""),
            "date": str(item.get("date") or ""),
        })
    return rows[:30]


def _network_metadata(attributes: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "as_owner",
        "asn",
        "continent",
        "country",
        "jarm",
        "network",
        "registrar",
        "whois_date",
        "creation_date",
        "last_update_date",
    )
    return {key: attributes[key] for key in keys if attributes.get(key) is not None}


def _context(attributes: dict[str, Any], mitre_response: dict[str, Any] | None, context_text: str) -> dict[str, Any]:
    return {
        "has_mitre_behavior": bool(mitre_response),
        "crowdsourced_yara_count": len(attributes.get("crowdsourced_yara_results") or []),
        "crowdsourced_ids_count": len(attributes.get("crowdsourced_ids_results") or []),
        "sigma_result_count": len(attributes.get("sigma_analysis_results") or []),
        "sandbox_verdict_count": len(attributes.get("sandbox_verdicts") or {}),
        "has_network_metadata": bool(_network_metadata(attributes)),
        "context_terms": _dedupe_str_list(context_text.split())[:40],
    }


def _flatten_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    if isinstance(value, dict):
        return " ".join(_flatten_text(item) for pair in value.items() for item in pair)
    if isinstance(value, list):
        return " ".join(_flatten_text(item) for item in value)
    return str(value)


def _dedupe_str_list(values: list[Any]) -> list[str]:
    seen = set()
    output = []
    for value in values:
        text = str(value).strip()
        key = text.lower()
        if text and key not in seen:
            seen.add(key)
            output.append(text)
    return output


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _short_text(value: Any, limit: int) -> str:
    text = " ".join(str(value).split())
    if len(text) <= limit:
        return text
    return f"{text[:limit - 1].rstrip()}..."
