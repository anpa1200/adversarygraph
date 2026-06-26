from __future__ import annotations

import base64
import ipaddress
import json
import re
from collections import Counter
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlparse

import httpx
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.version import APP_USER_AGENT
from app.models.attack import AptGroup, Technique
from app.models.ioc import IOCActorLink, IOCIndicator
from app.services.ai.factory import get_adapter
from app.services.virustotal import classify_indicator, lookup_virustotal_ioc

ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
GRAPH_OBJECT_TYPES = {"ioc", "ip", "ipv4", "ipv6", "domain", "url", "hash", "md5", "sha1", "sha256", "file", "report", "collection"}
GRAPH_TYPE_ALIASES = {
    "a": "ip",
    "aaaa": "ip",
    "cname": "domain",
    "dns": "domain",
    "host": "domain",
    "hostname": "domain",
    "mx": "domain",
    "ns": "domain",
    "ip_address": "ip",
    "sha256_hash": "hash",
    "sha1_hash": "hash",
    "md5_hash": "hash",
    "file-name": "file",
    "filename": "file",
}


@dataclass
class InvestigationOptions:
    domain: str = "enterprise-attack"
    depth: int = 2
    max_tier_nodes: int = 25
    ai_summarize: bool = False
    ai_provider: str = "local"


async def investigate_ioc(
    session: AsyncSession,
    artifact: str,
    *,
    options: InvestigationOptions | None = None,
) -> dict[str, Any]:
    options = options or InvestigationOptions()
    value = artifact.strip()
    if not value:
        raise ValueError("Artifact is empty")

    target = classify_indicator(value)
    normalized = target.value
    graph_nodes: dict[str, dict[str, Any]] = {}
    graph_edges: list[dict[str, Any]] = []
    source_results: list[dict[str, Any]] = []

    _add_node(graph_nodes, "artifact", normalized, target.type, tier=0, source="input", suspicious=0)

    local = await _local_enrichment(session, normalized, target.type, options.domain)
    source_results.append(local)
    _merge_graph(graph_nodes, graph_edges, local, normalized)

    vt = await _safe_source("virustotal", lambda: _virustotal_enrichment(session, normalized, options.domain))
    source_results.append(vt)
    _merge_graph(graph_nodes, graph_edges, vt, normalized)

    threatfox = await _safe_source("threatfox", lambda: _threatfox_enrichment(normalized, target.type))
    source_results.append(threatfox)
    _merge_graph(graph_nodes, graph_edges, threatfox, normalized)

    malwarebazaar = await _safe_source("malwarebazaar", lambda: _malwarebazaar_enrichment(normalized))
    source_results.append(malwarebazaar)
    _merge_graph(graph_nodes, graph_edges, malwarebazaar, normalized)

    otx = await _safe_source("otx", lambda: _otx_enrichment(normalized, target.type))
    source_results.append(otx)
    _merge_graph(graph_nodes, graph_edges, otx, normalized)

    urlscan = await _safe_source("urlscan", lambda: _urlscan_enrichment(normalized, target.type, options))
    source_results.append(urlscan)
    _merge_graph(graph_nodes, graph_edges, urlscan, normalized)

    greynoise = await _safe_source("greynoise", lambda: _greynoise_enrichment(normalized, target.type))
    source_results.append(greynoise)
    _merge_graph(graph_nodes, graph_edges, greynoise, normalized)

    abuseipdb = await _safe_source("abuseipdb", lambda: _abuseipdb_enrichment(normalized, target.type))
    source_results.append(abuseipdb)
    _merge_graph(graph_nodes, graph_edges, abuseipdb, normalized)

    shodan = await _safe_source("shodan", lambda: _shodan_enrichment(normalized, target.type))
    source_results.append(shodan)
    _merge_graph(graph_nodes, graph_edges, shodan, normalized)

    censys = await _safe_source("censys", lambda: _censys_enrichment(normalized, target.type))
    source_results.append(censys)
    _merge_graph(graph_nodes, graph_edges, censys, normalized)

    tier2_results: list[dict[str, Any]] = []
    tier3_results: list[dict[str, Any]] = []
    if options.depth >= 2:
        tier2_results = await _expand_local_tier(session, graph_nodes, graph_edges, options, source_tier=1, target_tier=2)
    if options.depth >= 3:
        tier3_results = await _expand_local_tier(session, graph_nodes, graph_edges, options, source_tier=2, target_tier=3)

    pivot_results = [*tier2_results, *tier3_results]
    techniques = await _resolve_techniques(session, _collect_attack_ids(source_results, pivot_results), options.domain)
    actors = await _resolve_actors(session, source_results, pivot_results, options.domain)
    score = _suspicion_score(source_results, graph_nodes)
    for node in graph_nodes.values():
        if node.get("tier") == 0:
            node["suspicious"] = max(int(node.get("suspicious") or 0), score)
    report_input = _report_input(
        normalized=normalized,
        artifact_type=target.type,
        source_results=source_results,
        tier2_results=tier2_results,
        tier3_results=tier3_results,
        graph_nodes=list(graph_nodes.values()),
        graph_edges=graph_edges,
        techniques=techniques,
        actors=actors,
        score=score,
    )
    ai_summary = ""
    ai_error = ""
    if options.ai_summarize:
        try:
            ai_summary = await _ai_summary(report_input, options)
        except Exception as exc:
            ai_error = f"{type(exc).__name__}: {exc}"

    return {
        "artifact": normalized,
        "artifact_type": target.type,
        "depth": options.depth,
        "suspicion_score": score,
        "verdict": _verdict(score),
        "summary": ai_summary or _deterministic_summary(normalized, target.type, score, techniques, actors, source_results),
        "kill_chain": _kill_chain(techniques),
        "techniques": techniques,
        "actors": actors,
        "sources": source_results,
        "tier2_sources": tier2_results,
        "tier3_sources": tier3_results,
        "relationships": {
            "nodes": sorted(graph_nodes.values(), key=lambda item: (item["tier"], item["type"], item["value"]))[:300],
            "edges": graph_edges[:500],
        },
        "ai_input": report_input,
        "ai_error": ai_error,
    }


async def _expand_local_tier(
    session: AsyncSession,
    graph_nodes: dict[str, dict[str, Any]],
    graph_edges: list[dict[str, Any]],
    options: InvestigationOptions,
    *,
    source_tier: int,
    target_tier: int,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for related in _tier_values(graph_nodes, source_tier, options.max_tier_nodes):
        result = await _safe_source(
            f"local-tier{target_tier}",
            lambda value=related: _local_enrichment(session, value, "", options.domain, tier=target_tier),
        )
        if result["status"] == "ok" and result.get("relationships"):
            results.append(result)
            _merge_graph(graph_nodes, graph_edges, result, related, default_tier=target_tier)
    return results


async def _safe_source(name: str, fn) -> dict[str, Any]:
    try:
        return await fn()
    except Exception as exc:
        msg = str(exc) or f"{type(exc).__name__}"
        return {
            "source": name,
            "status": "error",
            "error": msg,
            "summary": f"{name} enrichment failed: {msg}",
            "relationships": [],
            "technique_ids": [],
            "actors": [],
            "raw": {},
        }


async def _local_enrichment(session: AsyncSession, value: str, artifact_type: str, domain: str, tier: int = 1) -> dict[str, Any]:
    term = value.strip()
    pattern = f"%{term}%"
    rows = await session.execute(
        select(IOCIndicator)
        .options(selectinload(IOCIndicator.actor_links))
        .where(
            or_(
                IOCIndicator.value == term,
                IOCIndicator.value.ilike(pattern),
                IOCIndicator.description.ilike(pattern),
                IOCIndicator.malware_family.ilike(pattern),
                IOCIndicator.campaign.ilike(pattern),
            )
        )
        .order_by(IOCIndicator.updated_at.desc())
        .limit(30)
    )
    indicators = list(rows.scalars().all())
    relationships: list[dict[str, Any]] = []
    technique_ids: list[str] = []
    actors: list[dict[str, Any]] = []
    for indicator in indicators:
        related_type = indicator.indicator_type or "ioc"
        relationships.append(_relationship(term, indicator.value, related_type, "local-db", tier, indicator.description or indicator.source_id))
        technique_ids.extend([str(item).upper() for item in indicator.technique_ids or [] if ATTACK_ID_RE.fullmatch(str(item))])
        technique_ids.extend([match.upper() for match in ATTACK_ID_RE.findall(json.dumps(indicator.raw or {}, default=str))])
        for link in indicator.actor_links:
            actors.append({
                "attack_id": link.actor_attack_id,
                "name": link.actor_name,
                "source": link.source_id,
                "confidence": link.confidence,
                "evidence": link.evidence,
            })
            relationships.append(_relationship(indicator.value, link.actor_name, "actor", link.source_id, tier, link.evidence))
    return {
        "source": "local-db",
        "status": "ok",
        "summary": f"Found {len(indicators)} local IOC record(s).",
        "relationships": relationships,
        "technique_ids": _dedupe(technique_ids),
        "actors": _dedupe_actors(actors),
        "raw": {"matched_records": len(indicators), "artifact_type": artifact_type, "domain": domain},
    }


async def _virustotal_enrichment(session: AsyncSession, value: str, domain: str) -> dict[str, Any]:
    data = await lookup_virustotal_ioc(session, value, domain=domain)
    relationships: list[dict[str, Any]] = []
    for name in data.get("names") or []:
        relationships.append(_relationship(value, name, "name", "virustotal", 1, "VirusTotal known name"))
    for name in data.get("threat_names") or []:
        relationships.append(_relationship(value, name, "malware", "virustotal", 1, "VirusTotal threat classification"))
    for record in data.get("dns_records") or []:
        relationships.append(_relationship(value, str(record.get("value") or ""), str(record.get("type") or "dns"), "virustotal", 1, "DNS record"))
    for resolution in data.get("resolutions") or []:
        relationships.append(_relationship(value, str(resolution.get("ip_address") or ""), "ip", "virustotal", 1, "Passive DNS resolution"))
        relationships.append(_relationship(value, str(resolution.get("host_name") or ""), "domain", "virustotal", 1, "Passive DNS resolution"))
    return {
        "source": "virustotal",
        "status": "ok",
        "summary": data.get("summary") or "",
        "relationships": [item for item in relationships if item["target"]],
        "technique_ids": [item["attack_id"] for item in data.get("ttps") or []],
        "actors": data.get("actors") or [],
        "raw": _compact_raw(data, exclude={"raw"}),
    }


async def _threatfox_enrichment(value: str, artifact_type: str) -> dict[str, Any]:
    if not settings.threatfox_auth_key:
        return _not_configured("threatfox", "THREATFOX_AUTH_KEY")
    query = "search_ioc" if artifact_type != "hash" else "search_hash"
    key = "search_term" if query == "search_ioc" else "hash"
    payload = await _post_json(
        "https://threatfox-api.abuse.ch/api/v1/",
        json_body={"query": query, key: value},
        headers={"Auth-Key": settings.threatfox_auth_key, "Accept": "application/json", "User-Agent": APP_USER_AGENT},
    )
    rows = payload.get("data") or []
    relationships: list[dict[str, Any]] = []
    technique_ids: list[str] = []
    for row in rows if isinstance(rows, list) else []:
        relationships.extend(_row_relationships(value, row, "threatfox"))
        technique_ids.extend(ATTACK_ID_RE.findall(json.dumps(row, default=str)))
    return {
        "source": "threatfox",
        "status": "ok",
        "summary": f"ThreatFox returned {len(rows) if isinstance(rows, list) else 0} record(s).",
        "relationships": relationships,
        "technique_ids": _dedupe([item.upper() for item in technique_ids]),
        "actors": [],
        "raw": _compact_raw(payload),
    }


async def _malwarebazaar_enrichment(value: str) -> dict[str, Any]:
    if not HASH_RE.fullmatch(value):
        return {"source": "malwarebazaar", "status": "skipped", "summary": "MalwareBazaar is hash-focused; input is not a hash.", "relationships": [], "technique_ids": [], "actors": [], "raw": {}}
    mb_headers: dict[str, str] = {"Accept": "application/json", "User-Agent": APP_USER_AGENT}
    if settings.threatfox_auth_key:
        mb_headers["Auth-Key"] = settings.threatfox_auth_key
    payload = await _post_json("https://mb-api.abuse.ch/api/v1/", json_body={"query": "get_info", "hash": value}, headers=mb_headers)
    rows = payload.get("data") or []
    relationships: list[dict[str, Any]] = []
    for row in rows if isinstance(rows, list) else []:
        relationships.extend(_row_relationships(value, row, "malwarebazaar"))
    return {
        "source": "malwarebazaar",
        "status": "ok",
        "summary": f"MalwareBazaar returned {len(rows) if isinstance(rows, list) else 0} sample record(s).",
        "relationships": relationships,
        "technique_ids": _dedupe([match.upper() for match in ATTACK_ID_RE.findall(json.dumps(payload, default=str))]),
        "actors": [],
        "raw": _compact_raw(payload),
    }


async def _otx_enrichment(value: str, artifact_type: str) -> dict[str, Any]:
    if not settings.otx_api_key:
        return _not_configured("otx", "OTX_API_KEY")
    section = {
        "ip": "IPv4",
        "domain": "domain",
        "url": "url",
        "hash": "file",
    }.get(artifact_type, "general")
    if section == "general":
        endpoint = f"https://otx.alienvault.com/api/v1/search/pulses?q={quote(value)}"
    else:
        endpoint = f"https://otx.alienvault.com/api/v1/indicators/{section}/{quote(value, safe='')}/general"
    payload = await _get_json(endpoint, headers={"X-OTX-API-KEY": settings.otx_api_key}, timeout=45)
    pulses = ((payload.get("pulse_info") or {}).get("pulses") or payload.get("results") or [])
    relationships: list[dict[str, Any]] = []
    for pulse in pulses[:20] if isinstance(pulses, list) else []:
        name = str(pulse.get("name") or pulse.get("title") or "")
        if name:
            relationships.append(_relationship(value, name, "collection", "otx", 1, "OTX pulse"))
    return {
        "source": "otx",
        "status": "ok",
        "summary": f"OTX returned {len(pulses) if isinstance(pulses, list) else 0} pulse(s).",
        "relationships": relationships,
        "technique_ids": _dedupe([match.upper() for match in ATTACK_ID_RE.findall(json.dumps(payload, default=str))]),
        "actors": [],
        "raw": _compact_raw(payload),
    }


async def _urlscan_enrichment(value: str, artifact_type: str, options: InvestigationOptions) -> dict[str, Any]:
    query = value
    if artifact_type == "domain":
        query = f"domain:{value}"
    elif artifact_type == "ip":
        query = f"ip:{value}"
    elif artifact_type == "url":
        host = urlparse(value).hostname
        query = f"domain:{host}" if host else value
    headers = {"API-Key": settings.urlscan_api_key} if settings.urlscan_api_key else {}
    payload = await _get_json("https://urlscan.io/api/v1/search/", params={"q": query, "size": "10"}, headers=headers)
    rows = payload.get("results") or []
    relationships: list[dict[str, Any]] = []
    for row in rows[:10]:
        page = row.get("page") or {}
        task = row.get("task") or {}
        for candidate, kind, evidence in [
            (page.get("domain"), "domain", "urlscan page domain"),
            (page.get("ip"), "ip", "urlscan page IP"),
            (page.get("url"), "url", "urlscan page URL"),
            (task.get("url"), "url", "urlscan submitted URL"),
        ]:
            if candidate:
                relationships.append(_relationship(value, str(candidate), kind, "urlscan", 1, evidence))
    activity = await _urlscan_activity_analysis(value, rows[:10], payload, options)
    technique_ids = [str(item) for item in activity.get("technique_ids", [])]
    for finding in activity.get("findings", []):
        label = str(finding.get("pattern") or finding.get("severity") or "").strip()
        if label:
            relationships.append(_relationship(value, label, "suspicious-pattern", "urlscan-analysis", 1, str(finding.get("evidence") or "urlscan activity analysis")))
    return {
        "source": "urlscan",
        "status": "ok",
        "summary": f"urlscan returned {len(rows)} scan result(s). {activity.get('summary', '')}".strip(),
        "relationships": relationships,
        "technique_ids": technique_ids,
        "actors": [],
        "raw": {**_compact_raw(payload), "activity_analysis": activity},
    }


async def _urlscan_activity_analysis(
    value: str,
    rows: list[dict[str, Any]],
    payload: dict[str, Any],
    options: InvestigationOptions,
) -> dict[str, Any]:
    heuristic = _urlscan_heuristic_analysis(value, rows, payload)
    if not options.ai_summarize:
        return heuristic
    try:
        adapter = get_adapter(options.ai_provider)
        text = json.dumps({"indicator": value, "urlscan_results": rows}, ensure_ascii=True, default=str)[:18000]
        system = "You are a CTI analyst reviewing urlscan activity. Return only valid JSON."
        user = (
            "Analyze these urlscan search results for suspicious or malicious web activity patterns. "
            "Return JSON with keys summary, findings, technique_ids. findings must be a list of objects "
            "with severity, pattern, evidence, rationale. technique_ids must contain only ATT&CK IDs when "
            "there is defensible behavior evidence. Do not overclaim attribution.\n\n"
            f"{text}"
        )
        raw = await adapter._raw_complete(system, user)
        data = _extract_json_object(raw)
        findings = data.get("findings") if isinstance(data.get("findings"), list) else []
        technique_ids = _dedupe([*heuristic.get("technique_ids", []), *[str(item) for item in data.get("technique_ids", [])]])
        return {
            "mode": f"ai:{options.ai_provider}",
            "summary": str(data.get("summary") or heuristic.get("summary") or ""),
            "findings": [item for item in findings if isinstance(item, dict)][:12] or heuristic.get("findings", []),
            "technique_ids": technique_ids,
            "heuristic_findings": heuristic.get("findings", []),
        }
    except Exception as exc:
        return {**heuristic, "mode": "heuristic", "ai_error": str(exc)}


def _urlscan_heuristic_analysis(value: str, rows: list[dict[str, Any]], payload: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    technique_ids: list[str] = []
    raw_text = json.dumps({"value": value, "rows": rows, "payload": payload}, default=str).lower()
    verdict_hits = 0
    redirect_hosts: set[str] = set()
    submitted_hosts: set[str] = set()
    ips: set[str] = set()

    for row in rows:
        page = row.get("page") or {}
        task = row.get("task") or {}
        verdicts = row.get("verdicts") or {}
        stats = row.get("stats") or {}
        if any(str(verdicts.get(key, {})).lower().find("malicious") >= 0 for key in ("overall", "urlscan", "engines", "community")):
            verdict_hits += 1
        page_url = str(page.get("url") or "")
        task_url = str(task.get("url") or "")
        for url_value in (page_url, task_url):
            host = urlparse(url_value).hostname
            if host:
                if url_value == task_url:
                    submitted_hosts.add(host.lower())
                else:
                    redirect_hosts.add(host.lower())
        if page.get("ip"):
            ips.add(str(page["ip"]))
        if int(stats.get("uniqIPs") or stats.get("uniq_ips") or 0) >= 5:
            findings.append({
                "severity": "medium",
                "pattern": "multiple network destinations",
                "evidence": f"urlscan reported {stats.get('uniqIPs') or stats.get('uniq_ips')} unique IPs",
                "rationale": "Multiple distinct network destinations can indicate redirect, loader, or injected third-party activity.",
            })

    if verdict_hits:
        findings.append({
            "severity": "high",
            "pattern": "malicious urlscan verdict",
            "evidence": f"{verdict_hits} urlscan result(s) contain malicious verdict context",
            "rationale": "A malicious verdict is a source-backed signal requiring analyst review.",
        })
        technique_ids.append("T1204")
    if redirect_hosts - submitted_hosts:
        findings.append({
            "severity": "medium",
            "pattern": "redirect or hosted-content pivot",
            "evidence": f"observed page hosts differ from submitted hosts: {', '.join(sorted((redirect_hosts - submitted_hosts))[:5])}",
            "rationale": "Domain changes after submission may indicate redirect chains, compromised content, or external payload hosting.",
        })
        technique_ids.append("T1189")
    for term, pattern, technique in [
        ("phish", "phishing-themed content", "T1566"),
        ("credential", "credential collection language", "T1056"),
        ("login", "login page or credential prompt", "T1056"),
        ("c2", "command-and-control keyword", "T1071"),
        ("payload", "payload delivery keyword", "T1105"),
        ("malware", "malware keyword", "T1105"),
    ]:
        if term in raw_text:
            findings.append({
                "severity": "medium",
                "pattern": pattern,
                "evidence": f"urlscan metadata contains '{term}'",
                "rationale": "Keyword evidence is weak alone, but useful for triage when combined with verdicts and pivots.",
            })
            technique_ids.append(technique)

    findings = _dedupe_findings(findings)
    summary = f"urlscan activity analysis found {len(findings)} suspicious pattern(s)." if findings else "urlscan activity analysis found no obvious suspicious pattern."
    return {
        "mode": "heuristic",
        "summary": summary,
        "findings": findings[:12],
        "technique_ids": _dedupe(technique_ids),
        "observed_ips": sorted(ips)[:20],
        "observed_hosts": sorted(redirect_hosts | submitted_hosts)[:20],
    }


async def _greynoise_enrichment(value: str, artifact_type: str) -> dict[str, Any]:
    if artifact_type != "ip":
        return {"source": "greynoise", "status": "skipped", "summary": "GreyNoise is IP-focused; input is not an IP.", "relationships": [], "technique_ids": [], "actors": [], "raw": {}}
    # Use GreyNoise Community by default. It does not require an API key and is
    # safer for local deployments because a stale optional key cannot break
    # baseline IP reputation context.
    headers: dict[str, str] = {}
    endpoint = f"https://api.greynoise.io/v3/community/{quote(value)}"
    payload = await _get_json(endpoint, headers=headers)
    relationships = []
    for key in ("classification", "name", "riot", "noise"):
        if payload.get(key) not in {None, ""}:
            relationships.append(_relationship(value, str(payload[key]), "classification", "greynoise", 1, f"GreyNoise {key}"))
    return {
        "source": "greynoise",
        "status": "ok",
        "summary": f"GreyNoise classification: {payload.get('classification') or 'unknown'}.",
        "relationships": relationships,
        "technique_ids": [],
        "actors": [],
        "raw": _compact_raw({"mode": "community", **payload}),
    }


async def _abuseipdb_enrichment(value: str, artifact_type: str) -> dict[str, Any]:
    if artifact_type != "ip":
        return {"source": "abuseipdb", "status": "skipped", "summary": "AbuseIPDB is IP-focused; input is not an IP.", "relationships": [], "technique_ids": [], "actors": [], "raw": {}}
    if not settings.abuseipdb_api_key:
        return _not_configured("abuseipdb", "ABUSEIPDB_API_KEY")
    payload = await _get_json(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": value, "maxAgeInDays": 90, "verbose": "true"},
        headers={"Key": settings.abuseipdb_api_key, "Accept": "application/json"},
    )
    data = payload.get("data") or {}
    relationships: list[dict[str, Any]] = []
    for candidate, kind, evidence in [
        (data.get("domain"), "domain", "AbuseIPDB domain"),
        (data.get("countryCode"), "country", "AbuseIPDB country"),
        (data.get("usageType"), "usage-type", "AbuseIPDB usage type"),
        (data.get("isp"), "provider", "AbuseIPDB ISP"),
    ]:
        if candidate:
            relationships.append(_relationship(value, str(candidate), kind, "abuseipdb", 1, evidence))
    for hostname in data.get("hostnames") or []:
        relationships.append(_relationship(value, str(hostname), "domain", "abuseipdb", 1, "AbuseIPDB hostname"))
    confidence = int(data.get("abuseConfidenceScore") or 0)
    if confidence:
        relationships.append(_relationship(value, f"abuse-confidence:{confidence}", "reputation", "abuseipdb", 1, "AbuseIPDB abuse confidence score"))
    return {
        "source": "abuseipdb",
        "status": "ok",
        "summary": f"AbuseIPDB confidence score: {confidence}/100.",
        "relationships": relationships,
        "technique_ids": [],
        "actors": [],
        "raw": _compact_raw(payload),
    }


async def _shodan_enrichment(value: str, artifact_type: str) -> dict[str, Any]:
    if artifact_type != "ip":
        return {"source": "shodan", "status": "skipped", "summary": "Shodan host lookup is IP-focused; input is not an IP.", "relationships": [], "technique_ids": [], "actors": [], "raw": {}}
    if not settings.shodan_api_key:
        return _not_configured("shodan", "SHODAN_API_KEY")
    payload = await _get_json(f"https://api.shodan.io/shodan/host/{quote(value)}", params={"key": settings.shodan_api_key})
    relationships: list[dict[str, Any]] = []
    for hostname in payload.get("hostnames") or []:
        relationships.append(_relationship(value, str(hostname), "domain", "shodan", 1, "Shodan hostname"))
    for port in payload.get("ports") or []:
        relationships.append(_relationship(value, str(port), "service-port", "shodan", 1, "Open service port"))
    for vuln in (payload.get("vulns") or {}).keys() if isinstance(payload.get("vulns"), dict) else []:
        relationships.append(_relationship(value, str(vuln), "vulnerability", "shodan", 1, "Shodan vulnerability"))
    return {
        "source": "shodan",
        "status": "ok",
        "summary": f"Shodan returned {len(payload.get('ports') or [])} open port(s).",
        "relationships": relationships,
        "technique_ids": [],
        "actors": [],
        "raw": _compact_raw(payload),
    }


async def _censys_enrichment(value: str, artifact_type: str) -> dict[str, Any]:
    if artifact_type not in {"ip", "domain", "url"}:
        return {"source": "censys", "status": "skipped", "summary": "Censys host and search pivots support IP, domain, and URL inputs.", "relationships": [], "technique_ids": [], "actors": [], "raw": {}}
    if not settings.censys_api_key:
        return _not_configured("censys", "CENSYS_API_KEY")

    base_headers = {
        "Authorization": f"Bearer {settings.censys_api_key}",
    }
    if settings.censys_org_id:
        base_headers["X-Organization-ID"] = settings.censys_org_id

    if artifact_type == "ip":
        headers = {**base_headers, "Accept": "application/vnd.censys.api.v3.host.v1+json"}
        payload = await _get_json(f"https://api.platform.censys.io/v3/global/asset/host/{quote(value)}", headers=headers)
        resource = ((payload.get("result") or {}).get("resource") or payload.get("resource") or {})
        relationships = _censys_host_relationships(value, resource)
        return {
            "source": "censys",
            "status": "ok",
            "summary": f"Censys host lookup returned {len(resource.get('services') or [])} service(s).",
            "relationships": relationships,
            "technique_ids": _dedupe([match.upper() for match in ATTACK_ID_RE.findall(json.dumps(payload, default=str))]),
            "actors": [],
            "raw": _compact_raw(payload),
        }

    host = urlparse(value).hostname if artifact_type == "url" else value
    if not host:
        return {"source": "censys", "status": "skipped", "summary": "Censys could not extract a domain host from this URL.", "relationships": [], "technique_ids": [], "actors": [], "raw": {}}

    web_payload = await _post_json(
        "https://api.platform.censys.io/v3/global/asset/webproperty",
        json_body={"webproperty_ids": [f"{host}:80", f"{host}:443"]},
        headers={**base_headers, "Accept": "application/vnd.censys.api.v3.webproperty.v1+json"},
    )
    web_resources = _censys_webproperty_resources(web_payload)
    relationships = _censys_webproperty_relationships(host, web_resources)
    technique_ids = _dedupe([match.upper() for match in ATTACK_ID_RE.findall(json.dumps(web_payload, default=str))])

    if not settings.censys_org_id:
        return {
            "source": "censys",
            "status": "ok",
            "summary": (
                f"Censys web property lookup returned {len(web_resources)} record(s) for {host}. "
                "Broader Censys search requires an organization-enabled account and API role."
            ),
            "relationships": relationships,
            "technique_ids": technique_ids,
            "actors": [],
            "raw": _compact_raw(web_payload),
        }

    query = f'host.dns.names: "{host}" or host.services.tls.certificates.leaf_data.names: "{host}"'
    try:
        payload = await _post_json(
            "https://api.platform.censys.io/v3/global/search/query",
            json_body={
                "query": query,
                "page_size": 10,
                "fields": [
                    "host.ip",
                    "host.location.country",
                    "host.autonomous_system.name",
                    "host.services.port",
                    "host.services.service_name",
                    "host.dns.names",
                ],
            },
            headers={**base_headers, "Accept": "application/json"},
        )
    except RuntimeError as exc:
        return {
            "source": "censys",
            "status": "ok",
            "summary": f"Censys web property lookup returned {len(web_resources)} record(s) for {host}; broader search was unavailable: {exc}",
            "relationships": relationships,
            "technique_ids": technique_ids,
            "actors": [],
            "raw": _compact_raw({"webproperty": web_payload, "search_error": str(exc)}),
        }
    hits = _censys_hits(payload)
    for hit in hits[:10]:
        relationships.extend(_censys_search_relationships(host, hit))
    return {
        "source": "censys",
        "status": "ok",
        "summary": f"Censys web property lookup returned {len(web_resources)} record(s), and search returned {len(hits)} host result(s) for {host}.",
        "relationships": relationships,
        "technique_ids": _dedupe([*technique_ids, *[match.upper() for match in ATTACK_ID_RE.findall(json.dumps(payload, default=str))]]),
        "actors": [],
        "raw": _compact_raw({"webproperty": web_payload, "search": payload}),
    }


async def _get_json(url: str, *, params: dict[str, Any] | None = None, headers: dict[str, str] | None = None, timeout: int = 25) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        response = await client.get(url, params=params, headers=headers or {})
        if response.status_code in {401, 403}:
            raise RuntimeError(_credential_error_detail(url, response))
        if response.status_code == 404:
            return {"query_status": "not_found"}
        response.raise_for_status()
        return response.json()


async def _post_json(url: str, *, json_body: dict[str, Any], headers: dict[str, str] | None = None) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        response = await client.post(url, json=json_body, headers=headers or {})
        if response.status_code in {401, 403}:
            raise RuntimeError(_credential_error_detail(url, response))
        response.raise_for_status()
        return response.json()


def _credential_error_detail(url: str, response: httpx.Response) -> str:
    host = urlparse(url).netloc
    try:
        payload = response.json()
    except ValueError:
        payload = {}
    query_status = str(payload.get("query_status") or "").strip() if isinstance(payload, dict) else ""
    if host in {"threatfox-api.abuse.ch", "mb-api.abuse.ch"} and query_status in {"unknown_auth_key", "auth_key_required"}:
        return (
            f"abuse.ch rejected THREATFOX_AUTH_KEY for {host}: {query_status}. "
            "Generate a new Auth-Key in the abuse.ch authentication portal, update THREATFOX_AUTH_KEY in .env, and restart the API container."
        )
    if query_status:
        return f"API rejected credentials for {host}: {query_status}"
    return f"API rejected credentials for {host}"


async def _resolve_techniques(session: AsyncSession, attack_ids: list[str], domain: str) -> list[dict[str, Any]]:
    ids = _dedupe([item.upper() for item in attack_ids if ATTACK_ID_RE.fullmatch(str(item))])
    if not ids:
        return []
    rows = await session.execute(
        select(Technique)
        .options(selectinload(Technique.tactics))
        .where(Technique.attack_id.in_(ids))
    )
    by_id = {tech.attack_id: tech for tech in rows.scalars().all()}
    output = []
    for attack_id in ids:
        tech = by_id.get(attack_id)
        output.append({
            "attack_id": attack_id,
            "name": tech.name if tech else "",
            "tactics": [tactic.shortname for tactic in tech.tactics] if tech else [],
            "url": tech.url if tech else f"https://attack.mitre.org/techniques/{attack_id.replace('.', '/')}/",
            "evidence_sources": [],
        })
    return output


async def _resolve_actors(session: AsyncSession, source_results: list[dict[str, Any]], tier2_results: list[dict[str, Any]], domain: str) -> list[dict[str, Any]]:
    actors: list[dict[str, Any]] = []
    for result in [*source_results, *tier2_results]:
        for actor in result.get("actors") or []:
            actors.append({
                "attack_id": str(actor.get("attack_id") or actor.get("actor_attack_id") or ""),
                "name": str(actor.get("name") or actor.get("actor_name") or ""),
                "source": str(actor.get("source") or result.get("source") or ""),
                "confidence": int(actor.get("confidence") or 50),
                "evidence": str(actor.get("evidence") or ""),
            })
    actor_text = " ".join(
        str(rel.get("target") or "")
        for result in source_results
        for rel in result.get("relationships") or []
        if rel.get("target_type") in {"tag", "report", "malware", "name"}
    ).lower()
    if actor_text:
        rows = await session.execute(select(AptGroup).where(AptGroup.domain == domain).limit(300))
        for group in rows.scalars().all():
            terms = [group.name, *[str(alias) for alias in group.aliases or []]]
            matched = [term for term in terms if len(term) >= 4 and term.lower() in actor_text]
            if matched:
                actors.append({
                    "attack_id": group.attack_id,
                    "name": group.name,
                    "source": "local-actor-alias-match",
                    "confidence": 55,
                    "evidence": ", ".join(matched[:5]),
                })
    return _dedupe_actors(actors)


def _relationship(source: str, target: str, target_type: str, evidence_source: str, tier: int, evidence: str) -> dict[str, Any]:
    return {
        "source": str(source or ""),
        "target": str(target or ""),
        "target_type": str(target_type or "unknown"),
        "evidence_source": evidence_source,
        "tier": tier,
        "evidence": _short(str(evidence or ""), 220),
    }


def _row_relationships(root: str, row: dict[str, Any], source: str) -> list[dict[str, Any]]:
    relationships: list[dict[str, Any]] = []
    keys = {
        "ioc": "ioc",
        "ioc_value": "ioc",
        "url": "url",
        "domain": "domain",
        "host": "domain",
        "ip": "ip",
        "ip_address": "ip",
        "sha256_hash": "hash",
        "sha1_hash": "hash",
        "md5_hash": "hash",
        "file_name": "file",
    }
    for key, kind in keys.items():
        raw = row.get(key)
        values = raw if isinstance(raw, list) else [raw]
        for value in values:
            if value:
                relationships.append(_relationship(root, str(value), kind, source, 1, f"{source} field {key}"))
    return relationships


def _censys_host_relationships(root: str, resource: dict[str, Any]) -> list[dict[str, Any]]:
    relationships: list[dict[str, Any]] = []
    location = resource.get("location") or {}
    autonomous_system = resource.get("autonomous_system") or {}
    whois = resource.get("whois") or {}
    dns = resource.get("dns") or {}

    for candidate, kind, evidence in [
        (location.get("country") or location.get("country_code"), "country", "Censys host location"),
        (location.get("city"), "city", "Censys host location"),
        (autonomous_system.get("name") or autonomous_system.get("description"), "asn", "Censys autonomous system"),
        (autonomous_system.get("asn"), "asn", "Censys ASN"),
        (((whois.get("organization") or {}).get("name")), "organization", "Censys WHOIS organization"),
        (((whois.get("network") or {}).get("name")), "network", "Censys WHOIS network"),
    ]:
        if candidate:
            relationships.append(_relationship(root, str(candidate), kind, "censys", 1, evidence))

    for name in _dedupe([*(dns.get("names") or []), *((dns.get("reverse_dns") or {}).get("names") or [])]):
        relationships.append(_relationship(root, str(name), "domain", "censys", 1, "Censys DNS name"))

    for service in resource.get("services") or []:
        if not isinstance(service, dict):
            continue
        port = service.get("port")
        service_name = service.get("service_name") or service.get("protocol") or service.get("transport_protocol")
        if port:
            label = f"{service_name or 'service'}:{port}"
            relationships.append(_relationship(root, label, "service-port", "censys", 1, "Censys exposed service"))
        for software in service.get("software") or []:
            if isinstance(software, dict):
                name = software.get("name") or software.get("product") or software.get("vendor")
                if name:
                    relationships.append(_relationship(root, str(name), "software", "censys", 1, "Censys service software"))
        tls = service.get("tls") or {}
        certs = tls.get("certificates") or {}
        leaf = certs.get("leaf_data") or certs.get("leaf") or {}
        for name in leaf.get("names") or []:
            relationships.append(_relationship(root, str(name), "domain", "censys", 1, "Censys TLS certificate name"))
        for hash_key in ("fingerprint_sha256", "fingerprint_sha1"):
            if leaf.get(hash_key):
                relationships.append(_relationship(root, str(leaf[hash_key]), "hash", "censys", 1, f"Censys TLS {hash_key}"))
    return relationships


def _censys_hits(payload: dict[str, Any]) -> list[dict[str, Any]]:
    result = payload.get("result") or {}
    for key in ("hits", "resources", "results"):
        value = result.get(key) or payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def _censys_webproperty_resources(payload: dict[str, Any]) -> list[dict[str, Any]]:
    result = payload.get("result") or []
    if isinstance(result, dict):
        result = result.get("resources") or result.get("webproperties") or []
    resources: list[dict[str, Any]] = []
    for item in result if isinstance(result, list) else []:
        if not isinstance(item, dict):
            continue
        resource = item.get("resource") if isinstance(item.get("resource"), dict) else item
        resources.append(resource)
    return resources


def _censys_webproperty_relationships(root: str, resources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    relationships: list[dict[str, Any]] = []
    for resource in resources:
        hostname = resource.get("hostname") or resource.get("name")
        port = resource.get("port")
        if hostname:
            relationships.append(_relationship(root, str(hostname), "domain", "censys", 1, "Censys web property hostname"))
        if port:
            relationships.append(_relationship(root, f"http:{port}", "service-port", "censys", 1, "Censys web property port"))
        for ip in _extract_values(resource, {"ip", "ipv4", "ipv6", "ip_address"}):
            relationships.append(_relationship(root, str(ip), "ip", "censys", 1, "Censys web property IP"))
        for cert_hash in _extract_values(resource, {"fingerprint_sha256", "fingerprint_sha1", "sha256", "sha1"}):
            relationships.append(_relationship(root, str(cert_hash), "hash", "censys", 1, "Censys web property certificate hash"))
        for software in _extract_values(resource, {"software", "product", "vendor", "service_name"}):
            if isinstance(software, str):
                relationships.append(_relationship(root, software, "software", "censys", 1, "Censys web property software"))
        for vuln in _extract_values(resource, {"cve", "cves", "vulns", "vulnerability"}):
            if isinstance(vuln, str) and vuln.upper().startswith("CVE-"):
                relationships.append(_relationship(root, vuln.upper(), "vulnerability", "censys", 1, "Censys web property vulnerability"))
    return relationships


def _extract_values(value: Any, keys: set[str]) -> list[Any]:
    found: list[Any] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key in keys:
                if isinstance(item, list):
                    found.extend(item)
                else:
                    found.append(item)
            found.extend(_extract_values(item, keys))
    elif isinstance(value, list):
        for item in value:
            found.extend(_extract_values(item, keys))
    return found[:100]


def _censys_search_relationships(root: str, hit: dict[str, Any]) -> list[dict[str, Any]]:
    relationships: list[dict[str, Any]] = []
    host = hit.get("host") if isinstance(hit.get("host"), dict) else hit
    ip = host.get("ip") or hit.get("ip")
    if ip:
        relationships.append(_relationship(root, str(ip), "ip", "censys", 1, "Censys host search result"))
    location = host.get("location") or {}
    autonomous_system = host.get("autonomous_system") or {}
    for candidate, kind, evidence in [
        (location.get("country") or location.get("country_code"), "country", "Censys search host location"),
        (autonomous_system.get("name") or autonomous_system.get("description"), "asn", "Censys search autonomous system"),
    ]:
        if candidate:
            relationships.append(_relationship(root, str(candidate), kind, "censys", 1, evidence))
    dns = host.get("dns") or {}
    for name in dns.get("names") or []:
        relationships.append(_relationship(root, str(name), "domain", "censys", 1, "Censys search DNS name"))
    for service in host.get("services") or []:
        if isinstance(service, dict) and service.get("port"):
            relationships.append(_relationship(root, f"{service.get('service_name') or 'service'}:{service['port']}", "service-port", "censys", 1, "Censys search exposed service"))
    return relationships


def _merge_graph(nodes: dict[str, dict[str, Any]], edges: list[dict[str, Any]], result: dict[str, Any], root: str, default_tier: int = 1) -> None:
    for rel in result.get("relationships") or []:
        source = str(rel.get("source") or root)
        target = str(rel.get("target") or "")
        target_type = _graph_object_type(str(rel.get("target_type") or "unknown"), target)
        if not target or not target_type:
            continue
        tier = int(rel.get("tier") or default_tier)
        source_type = _infer_graph_source_type(source)
        suspicious = _relationship_suspicious_score(result, rel)
        _add_node(nodes, "artifact", source, source_type, tier=max(0, tier - 1), source=result.get("source", "unknown"), suspicious=suspicious)
        _add_node(nodes, "relationship", target, target_type, tier=tier, source=str(rel.get("evidence_source") or result.get("source") or "unknown"), suspicious=suspicious)
        edge = {
            "source": source,
            "target": target,
            "type": target_type,
            "tier": tier,
            "evidence_source": rel.get("evidence_source") or result.get("source"),
            "evidence": rel.get("evidence") or "",
        }
        if edge not in edges:
            edges.append(edge)


def _add_node(nodes: dict[str, dict[str, Any]], kind: str, value: str, node_type: str, *, tier: int, source: str, suspicious: int = -1) -> None:
    if not value:
        return
    key = f"{node_type}:{value}".lower()
    existing = nodes.get(key)
    if existing:
        existing["tier"] = min(existing["tier"], tier)
        existing["sources"] = _dedupe([*existing["sources"], source])
        existing["suspicious"] = max(existing.get("suspicious", 0), suspicious)
        return
    nodes[key] = {
        "id": key,
        "kind": kind,
        "type": node_type,
        "value": value,
        "tier": tier,
        "sources": [source],
        "suspicious": suspicious,
    }


def _tier_values(nodes: dict[str, dict[str, Any]], tier: int, limit: int) -> list[str]:
    return [node["value"] for node in nodes.values() if node["tier"] == tier and _graph_object_type(node["type"], node["value"]) in {"ioc", "ip", "domain", "url", "hash", "file"}][:limit]


def _relationship_suspicious_score(result: dict[str, Any], rel: dict[str, Any]) -> int:
    if result.get("status") not in {"ok", "warning"}:
        return -1
    score = 0
    raw = result.get("raw") or {}
    raw_text = json.dumps(raw, default=str).lower()
    evidence_text = f"{rel.get('evidence') or ''} {rel.get('target') or ''} {rel.get('target_type') or ''}".lower()
    stats = _nested_dict(raw, "last_analysis_stats") if isinstance(raw, dict) else {}
    if stats:
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        score = max(score, min(100, malicious * 8 + suspicious * 5))
        if malicious == 0 and suspicious == 0 and harmless > 0:
            score = max(score, 8)
    if result.get("technique_ids"):
        score = max(score, 45)
    if result.get("actors"):
        score = max(score, 35)
    for finding in ((raw.get("activity_analysis") or {}).get("findings") or []) if isinstance(raw, dict) else []:
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity") or "").lower()
        if severity == "high":
            score = max(score, 80)
        elif severity == "medium":
            score = max(score, 55)
        elif severity:
            score = max(score, 25)
    if re.search(r"malicious|ransom|phish|c2|command.?and.?control|botnet|trojan|stealer|backdoor|abuse|suspicious", f"{raw_text} {evidence_text}"):
        score = max(score, 60)
    if re.search(r"benign|harmless|clean|known good", f"{raw_text} {evidence_text}") and score < 45:
        score = max(score, 10)
    return score if score > 0 else -1


def _graph_object_type(raw_type: str, value: str) -> str | None:
    node_type = GRAPH_TYPE_ALIASES.get(raw_type.lower(), raw_type.lower())
    value = str(value or "").strip()
    if node_type not in GRAPH_OBJECT_TYPES or not value:
        return None
    if node_type in {"ip", "ipv4", "ipv6"}:
        return "ip" if _looks_like_ip(value) else None
    if node_type == "domain":
        return "domain" if _looks_like_domain(value) else None
    if node_type == "url":
        return "url" if _looks_like_url(value) else None
    if node_type in {"hash", "md5", "sha1", "sha256"}:
        return "hash" if HASH_RE.fullmatch(value) else None
    if node_type == "file":
        return "file" if _looks_like_file(value) else None
    if node_type in {"report", "collection"}:
        return node_type
    return node_type


def _infer_graph_source_type(value: str) -> str:
    detected = classify_indicator(value).type
    return _graph_object_type(detected, value) or "ioc"


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _looks_like_domain(value: str) -> bool:
    if _looks_like_url(value) or " " in value or "/" in value or ":" in value:
        return False
    return "." in value and bool(re.fullmatch(r"[A-Za-z0-9*_.-]+", value))


def _looks_like_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https", "ftp"} and bool(parsed.netloc)


def _looks_like_file(value: str) -> bool:
    if " " in value or len(value) > 180:
        return False
    return bool(HASH_RE.fullmatch(value) or re.search(r"\.[A-Za-z0-9]{1,8}$", value))


def _collect_attack_ids(source_results: list[dict[str, Any]], tier2_results: list[dict[str, Any]]) -> list[str]:
    ids: list[str] = []
    for result in [*source_results, *tier2_results]:
        ids.extend([str(item) for item in result.get("technique_ids") or []])
        ids.extend([match.upper() for match in ATTACK_ID_RE.findall(json.dumps(result.get("raw") or {}, default=str))])
    return _dedupe([item.upper() for item in ids])


def _suspicion_score(source_results: list[dict[str, Any]], nodes: dict[str, dict[str, Any]]) -> int:
    score = 0
    for result in source_results:
        if result.get("status") != "ok":
            continue
        raw_text = json.dumps(result.get("raw") or {}, default=str).lower()
        stats = _nested_dict(result.get("raw") or {}, "last_analysis_stats")
        malicious = int(stats.get("malicious") or 0) if stats else 0
        suspicious = int(stats.get("suspicious") or 0) if stats else 0
        score += min(35, malicious * 6 + suspicious * 4)
        if result.get("technique_ids"):
            score += 20
        if result.get("actors"):
            score += 20
        activity = (result.get("raw") or {}).get("activity_analysis") if isinstance(result.get("raw"), dict) else {}
        if isinstance(activity, dict):
            for finding in activity.get("findings") or []:
                if not isinstance(finding, dict):
                    continue
                severity = str(finding.get("severity") or "").lower()
                if severity == "high":
                    score += 14
                elif severity == "medium":
                    score += 8
                elif severity:
                    score += 3
        for term in ("c2", "botnet", "ransomware", "trojan", "stealer", "backdoor"):
            if term in raw_text:
                score += 8
        if "greynoise" == result.get("source") and "benign" in raw_text:
            score -= 15
    score += min(25, len(nodes) // 3)
    return max(0, min(score, 100))


def _nested_dict(value: dict[str, Any], key: str) -> dict[str, Any]:
    found = value.get(key)
    if isinstance(found, dict):
        return found
    for child in value.values():
        if isinstance(child, dict):
            nested = _nested_dict(child, key)
            if nested:
                return nested
    return {}


def _verdict(score: int) -> str:
    if score >= 75:
        return "highly suspicious"
    if score >= 45:
        return "suspicious"
    if score >= 20:
        return "needs review"
    return "low signal"


def _kill_chain(techniques: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts = Counter(tactic for tech in techniques for tactic in tech.get("tactics", []))
    return [{"phase": phase, "techniques": count} for phase, count in counts.most_common()]


def _deterministic_summary(value: str, artifact_type: str, score: int, techniques: list[dict[str, Any]], actors: list[dict[str, Any]], source_results: list[dict[str, Any]]) -> str:
    ok_sources = [item["source"] for item in source_results if item.get("status") == "ok"]
    return (
        f"{value} was classified as {artifact_type}. Investigation verdict is {_verdict(score)} "
        f"with score {score}/100. Sources checked successfully: {', '.join(ok_sources) or 'none'}. "
        f"Found {len(techniques)} ATT&CK technique lead(s) and {len(actors)} actor lead(s)."
    )


def _report_input(**kwargs: Any) -> dict[str, Any]:
    return kwargs


async def _ai_summary(report_input: dict[str, Any], options: InvestigationOptions) -> str:
    adapter = get_adapter(options.ai_provider)
    text = json.dumps(report_input, ensure_ascii=True, default=str)[:30000]
    system = "You are a senior CTI analyst. Return concise prose, no markdown table."
    user = (
        "Summarize this IOC investigation for a CTI analyst. Explain IOC type, relationship graph, "
        "Tier 1/Tier 2 pivots, suspicious evidence, ATT&CK TTPs, kill-chain phases, actor/APT leads, "
        "confidence, caveats, and next steps. Do not overclaim attribution.\n\n"
        f"{text}"
    )
    return (await adapter._raw_complete(system, user))[:5000]


def _not_configured(source: str, env_var: str) -> dict[str, Any]:
    return {
        "source": source,
        "status": "not_configured",
        "error": f"{env_var} is not configured.",
        "summary": f"{source} skipped because {env_var} is not configured.",
        "relationships": [],
        "technique_ids": [],
        "actors": [],
        "raw": {},
    }


def _compact_raw(value: Any, exclude: set[str] | None = None) -> dict[str, Any]:
    exclude = exclude or set()
    if not isinstance(value, dict):
        return {"value": _short(json.dumps(value, default=str), 8000)}
    output: dict[str, Any] = {}
    for key, item in value.items():
        if key in exclude:
            continue
        try:
            text = json.dumps(item, default=str)
        except Exception:
            text = str(item)
        output[key] = item if len(text) < 4000 else text[:4000]
    return output


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        clean = str(value or "").strip()
        key = clean.lower()
        if clean and key not in seen:
            seen.add(key)
            output.append(clean)
    return output[:200]


def _dedupe_actors(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    output: list[dict[str, Any]] = []
    for value in values:
        key = f"{value.get('attack_id') or ''}:{value.get('name') or ''}".lower()
        if key.strip(":") and key not in seen:
            seen.add(key)
            output.append(value)
    return output[:50]


def _dedupe_findings(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    output: list[dict[str, Any]] = []
    for value in values:
        key = f"{value.get('severity') or ''}:{value.get('pattern') or ''}:{value.get('evidence') or ''}".lower()
        if key.strip(":") and key not in seen:
            seen.add(key)
            output.append(value)
    return output


def _extract_json_object(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        value = json.loads(cleaned)
        return value if isinstance(value, dict) else {}
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start >= 0 and end > start:
            try:
                value = json.loads(cleaned[start:end + 1])
                return value if isinstance(value, dict) else {}
            except json.JSONDecodeError:
                return {}
    return {}


def _short(value: str, limit: int) -> str:
    value = " ".join(str(value or "").split())
    return value[:limit]
