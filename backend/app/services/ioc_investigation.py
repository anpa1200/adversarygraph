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
from app.models.attack import AptGroup, Technique
from app.models.ioc import IOCActorLink, IOCIndicator
from app.services.ai.factory import get_adapter
from app.services.virustotal import classify_indicator, lookup_virustotal_ioc

ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")


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

    urlscan = await _safe_source("urlscan", lambda: _urlscan_enrichment(normalized, target.type))
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

    tier1_values = _tier_values(graph_nodes, 1, options.max_tier_nodes)
    tier2_results: list[dict[str, Any]] = []
    if options.depth >= 2:
        for related in tier1_values:
            result = await _safe_source("local-tier2", lambda value=related: _local_enrichment(session, value, "", options.domain, tier=2))
            if result["status"] == "ok" and result.get("relationships"):
                tier2_results.append(result)
                _merge_graph(graph_nodes, graph_edges, result, related, default_tier=2)

    techniques = await _resolve_techniques(session, _collect_attack_ids(source_results, tier2_results), options.domain)
    actors = await _resolve_actors(session, source_results, tier2_results, options.domain)
    score = _suspicion_score(source_results, graph_nodes)
    report_input = _report_input(
        normalized=normalized,
        artifact_type=target.type,
        source_results=source_results,
        tier2_results=tier2_results,
        graph_nodes=list(graph_nodes.values()),
        graph_edges=graph_edges,
        techniques=techniques,
        actors=actors,
        score=score,
    )
    ai_summary = await _ai_summary(report_input, options) if options.ai_summarize else ""

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
        "relationships": {
            "nodes": sorted(graph_nodes.values(), key=lambda item: (item["tier"], item["type"], item["value"]))[:300],
            "edges": graph_edges[:500],
        },
        "ai_input": report_input,
    }


async def _safe_source(name: str, fn) -> dict[str, Any]:
    try:
        return await fn()
    except Exception as exc:
        return {
            "source": name,
            "status": "error",
            "error": str(exc),
            "summary": f"{name} enrichment failed: {exc}",
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
        headers={"Auth-Key": settings.threatfox_auth_key},
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
    payload = await _post_json("https://mb-api.abuse.ch/api/v1/", json_body={"query": "get_info", "hash": value})
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
    payload = await _get_json(endpoint, headers={"X-OTX-API-KEY": settings.otx_api_key})
    pulses = ((payload.get("pulse_info") or {}).get("pulses") or payload.get("results") or [])
    relationships: list[dict[str, Any]] = []
    for pulse in pulses[:20] if isinstance(pulses, list) else []:
        name = str(pulse.get("name") or pulse.get("title") or "")
        if name:
            relationships.append(_relationship(value, name, "report", "otx", 1, "OTX pulse"))
        for tag in pulse.get("tags") or []:
            relationships.append(_relationship(value, str(tag), "tag", "otx", 1, "OTX pulse tag"))
    return {
        "source": "otx",
        "status": "ok",
        "summary": f"OTX returned {len(pulses) if isinstance(pulses, list) else 0} pulse(s).",
        "relationships": relationships,
        "technique_ids": _dedupe([match.upper() for match in ATTACK_ID_RE.findall(json.dumps(payload, default=str))]),
        "actors": [],
        "raw": _compact_raw(payload),
    }


async def _urlscan_enrichment(value: str, artifact_type: str) -> dict[str, Any]:
    query = value
    if artifact_type == "domain":
        query = f"domain:{value}"
    elif artifact_type == "ip":
        query = f"ip:{value}"
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
    return {
        "source": "urlscan",
        "status": "ok",
        "summary": f"urlscan returned {len(rows)} scan result(s).",
        "relationships": relationships,
        "technique_ids": [],
        "actors": [],
        "raw": _compact_raw(payload),
    }


async def _greynoise_enrichment(value: str, artifact_type: str) -> dict[str, Any]:
    if artifact_type != "ip":
        return {"source": "greynoise", "status": "skipped", "summary": "GreyNoise is IP-focused; input is not an IP.", "relationships": [], "technique_ids": [], "actors": [], "raw": {}}
    headers = {"key": settings.greynoise_api_key} if settings.greynoise_api_key else {}
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
        "raw": _compact_raw(payload),
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


async def _get_json(url: str, *, params: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=25, follow_redirects=True) as client:
        response = await client.get(url, params=params, headers=headers or {})
        if response.status_code in {401, 403}:
            raise RuntimeError(f"API rejected credentials for {urlparse(url).netloc}")
        if response.status_code == 404:
            return {"query_status": "not_found"}
        response.raise_for_status()
        return response.json()


async def _post_json(url: str, *, json_body: dict[str, Any], headers: dict[str, str] | None = None) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        response = await client.post(url, json=json_body, headers=headers or {})
        if response.status_code in {401, 403}:
            raise RuntimeError(f"API rejected credentials for {urlparse(url).netloc}")
        response.raise_for_status()
        return response.json()


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
        "malware": "malware",
        "malware_printable": "malware",
        "signature": "malware",
        "file_name": "file-name",
        "tags": "tag",
    }
    for key, kind in keys.items():
        raw = row.get(key)
        values = raw if isinstance(raw, list) else [raw]
        for value in values:
            if value:
                relationships.append(_relationship(root, str(value), kind, source, 1, f"{source} field {key}"))
    return relationships


def _merge_graph(nodes: dict[str, dict[str, Any]], edges: list[dict[str, Any]], result: dict[str, Any], root: str, default_tier: int = 1) -> None:
    for rel in result.get("relationships") or []:
        source = str(rel.get("source") or root)
        target = str(rel.get("target") or "")
        if not target:
            continue
        tier = int(rel.get("tier") or default_tier)
        _add_node(nodes, "artifact", source, "ioc", tier=max(0, tier - 1), source=result.get("source", "unknown"))
        _add_node(nodes, "relationship", target, str(rel.get("target_type") or "unknown"), tier=tier, source=str(rel.get("evidence_source") or result.get("source") or "unknown"))
        edge = {
            "source": source,
            "target": target,
            "type": rel.get("target_type") or "related",
            "tier": tier,
            "evidence_source": rel.get("evidence_source") or result.get("source"),
            "evidence": rel.get("evidence") or "",
        }
        if edge not in edges:
            edges.append(edge)


def _add_node(nodes: dict[str, dict[str, Any]], kind: str, value: str, node_type: str, *, tier: int, source: str, suspicious: int = 0) -> None:
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
    return [node["value"] for node in nodes.values() if node["tier"] == tier and node["type"] in {"ioc", "ip", "domain", "url", "hash"}][:limit]


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
        key = (str(value.get("attack_id") or ""), str(value.get("name") or "")).lower()
        if key.strip(":") and key not in seen:
            seen.add(key)
            output.append(value)
    return output[:50]


def _short(value: str, limit: int) -> str:
    value = " ".join(str(value or "").split())
    return value[:limit]
