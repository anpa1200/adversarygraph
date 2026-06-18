from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any

import requests
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.pipeline import CollectionRun, CollectionSource, EnrichmentResult, Observable

ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
HASH_RE = re.compile(r"\b([A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b")
IP_RE = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}\b")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


async def sync_sandbox_feed(session: AsyncSession, source: CollectionSource) -> CollectionRun:
    """Import malware behavior reports from a sandbox JSON feed."""
    if source.kind != "sandbox":
        raise ValueError(f"{source.kind.upper()} is not a sandbox behavior feed")
    limit = int((source.config or {}).get("limit") or 100)
    limit = max(1, min(limit, 1000))
    run = CollectionRun(source_id=source.id)
    session.add(run)
    await session.flush()
    try:
        reports = fetch_sandbox_reports(source.url, limit=limit)
        created_enrichments = 0
        touched_observables = 0
        for report in reports:
            parsed = parse_sandbox_report(report, source.url)
            if not parsed["hashes"]:
                continue
            primary_hash = _primary_hash(parsed["hashes"])
            observable, created = await _upsert_observable(
                session,
                _hash_type(primary_hash),
                primary_hash,
                source.url,
                parsed["tags"],
            )
            touched_observables += int(created)
            if await _insert_enrichment_once(session, observable, source, parsed):
                created_enrichments += 1
        run.status = "complete"
        run.items_seen = len(reports)
        run.items_created = created_enrichments
        run.observables_created = touched_observables
        source.last_run_at = datetime.now(timezone.utc)
    except Exception as exc:
        run.status = "failed"
        run.error = str(exc)[:2000]
    run.completed_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(run)
    return run


async def list_sandbox_behaviors(session: AsyncSession, limit: int = 100) -> list[dict[str, Any]]:
    rows = await session.execute(
        select(EnrichmentResult, Observable)
        .join(Observable, Observable.id == EnrichmentResult.observable_id)
        .where(EnrichmentResult.provider.ilike("sandbox:%"))
        .order_by(EnrichmentResult.created_at.desc())
        .limit(max(1, min(limit, 500)))
    )
    output: list[dict[str, Any]] = []
    for enrichment, observable in rows.all():
        raw = enrichment.raw_data or {}
        output.append({
            "id": str(enrichment.id),
            "observable_id": str(observable.id),
            "observable_type": observable.type,
            "observable": observable.value,
            "provider": enrichment.provider,
            "verdict": enrichment.verdict,
            "confidence": enrichment.confidence,
            "created_at": enrichment.created_at.isoformat() if enrichment.created_at else "",
            "report_id": raw.get("report_id", ""),
            "source_url": raw.get("source_url", ""),
            "sandbox": raw.get("sandbox", ""),
            "malware_family": raw.get("malware_family", ""),
            "score": raw.get("score"),
            "ttps": raw.get("ttps", []),
            "signatures": raw.get("signatures", []),
            "processes": raw.get("processes", []),
            "network": raw.get("network", {}),
            "tags": raw.get("tags", []),
        })
    return output


def fetch_sandbox_reports(url: str, limit: int = 100) -> list[dict[str, Any]]:
    response = requests.get(url, timeout=90)
    response.raise_for_status()
    payload = response.json()
    if isinstance(payload, list):
        reports = payload
    elif isinstance(payload, dict):
        for key in ("reports", "data", "results", "items", "analyses", "tasks"):
            if isinstance(payload.get(key), list):
                reports = payload[key]
                break
        else:
            reports = [payload]
    else:
        reports = []
    return [item for item in reports[:limit] if isinstance(item, dict)]


def parse_sandbox_report(report: dict[str, Any], source_url: str = "") -> dict[str, Any]:
    text = _flatten_text(report)
    hashes = _dedupe(_extract_hashes(report, text))
    ttps = sorted({item.upper() for item in ATTACK_ID_RE.findall(text)})
    signatures = _extract_named_rows(report, ("signatures", "signatures_triggered", "behavior", "mitre_attacks"))
    processes = _extract_processes(report)
    network = _extract_network(report, text)
    tags = _dedupe([*_as_str_list(report.get("tags")), *_as_str_list(report.get("labels"))])[:40]
    score = _first_value(report, ("score", "threat_score", "malscore", "malicious_score"))
    verdict = _verdict(report, score, text)
    report_id = str(_first_value(report, ("id", "task_id", "analysis_id", "sha256", "md5")) or _stable_id(text))
    return {
        "report_id": report_id,
        "source_url": str(_first_value(report, ("url", "permalink", "report_url")) or source_url),
        "sandbox": str(_first_value(report, ("sandbox", "provider", "environment")) or "sandbox-feed"),
        "malware_family": str(_first_value(report, ("malware_family", "family", "signature", "threat_name")) or ""),
        "score": score,
        "verdict": verdict,
        "confidence": _confidence(verdict, score),
        "hashes": hashes,
        "ttps": ttps,
        "signatures": signatures[:30],
        "processes": processes[:40],
        "network": network,
        "tags": tags,
        "summary": _summary(verdict, score, ttps, signatures, network),
        "raw_excerpt": _short_text(text, 5000),
    }


async def _upsert_observable(
    session: AsyncSession,
    kind: str,
    value: str,
    source_ref: str,
    tags: list[str],
) -> tuple[Observable, bool]:
    normalized = value.lower().strip()
    existing = await session.execute(select(Observable).where(Observable.type == kind, Observable.normalized_value == normalized))
    row = existing.scalar_one_or_none()
    if row:
        row.last_seen_at = datetime.now(timezone.utc)
        refs = row.source_refs or []
        row.source_refs = refs if source_ref in refs else [*refs, source_ref]
        row.tags = _dedupe([*(row.tags or []), *tags])
        return row, False
    row = Observable(type=kind, value=value, normalized_value=normalized, source_refs=[source_ref] if source_ref else [], tags=tags)
    session.add(row)
    await session.flush()
    return row, True


async def _insert_enrichment_once(
    session: AsyncSession,
    observable: Observable,
    source: CollectionSource,
    parsed: dict[str, Any],
) -> bool:
    provider = f"sandbox:{source.name}"
    rows = await session.execute(
        select(EnrichmentResult).where(EnrichmentResult.observable_id == observable.id, EnrichmentResult.provider == provider)
    )
    for existing in rows.scalars().all():
        raw = existing.raw_data or {}
        if raw.get("report_id") == parsed["report_id"] or (
            raw.get("source_url") and raw.get("source_url") == parsed.get("source_url")
        ):
            existing.status = "complete"
            existing.verdict = parsed["verdict"]
            existing.confidence = parsed["confidence"]
            existing.raw_data = parsed
            return False
    session.add(
        EnrichmentResult(
            observable_id=observable.id,
            provider=provider,
            status="complete",
            verdict=parsed["verdict"],
            confidence=parsed["confidence"],
            raw_data=parsed,
        )
    )
    return True


def _extract_hashes(report: dict[str, Any], text: str) -> list[str]:
    values: list[str] = []
    for key in ("sha256", "sha1", "md5", "hash", "sample_hash"):
        value = report.get(key)
        if isinstance(value, str):
            values.append(value)
    values.extend(HASH_RE.findall(text))
    return values


def _primary_hash(hashes: list[str]) -> str:
    return sorted(hashes, key=lambda item: len(item), reverse=True)[0].lower()


def _hash_type(value: str) -> str:
    if len(value) == 64:
        return "sha256"
    if len(value) == 40:
        return "sha1"
    return "md5"


def _extract_named_rows(report: dict[str, Any], keys: tuple[str, ...]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for key in keys:
        value = report.get(key)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    name = _first_value(item, ("name", "description", "signature", "ttp", "technique", "id"))
                    severity = _first_value(item, ("severity", "level", "score"))
                    if name:
                        rows.append({"name": _short_text(str(name), 180), "severity": str(severity or ""), "source": key})
                elif item:
                    rows.append({"name": _short_text(str(item), 180), "severity": "", "source": key})
        elif isinstance(value, dict):
            for item_key, item_value in value.items():
                rows.append({"name": _short_text(f"{item_key}: {_flatten_text(item_value)}", 180), "severity": "", "source": key})
    return _dedupe_named(rows)


def _extract_processes(report: dict[str, Any]) -> list[str]:
    rows: list[str] = []
    for key in ("processes", "process_tree", "process_list", "behavior_processes"):
        value = report.get(key)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    rows.append(str(_first_value(item, ("process_name", "name", "image", "command_line", "cmdline")) or ""))
                elif item:
                    rows.append(str(item))
    return _dedupe([_short_text(item, 220) for item in rows if item])[:40]


def _extract_network(report: dict[str, Any], text: str) -> dict[str, list[str]]:
    network = report.get("network") if isinstance(report.get("network"), dict) else {}
    ips = _as_str_list(network.get("ips") if isinstance(network, dict) else None)
    domains = _as_str_list(network.get("domains") if isinstance(network, dict) else None)
    urls = _as_str_list(network.get("urls") if isinstance(network, dict) else None)
    ips.extend(IP_RE.findall(text))
    domains.extend(DOMAIN_RE.findall(text))
    urls.extend(URL_RE.findall(text))
    return {
        "ips": _dedupe(ips)[:40],
        "domains": _dedupe(domains)[:40],
        "urls": _dedupe(urls)[:30],
    }


def _verdict(report: dict[str, Any], score: Any, text: str) -> str:
    explicit = str(_first_value(report, ("verdict", "classification", "category", "status")) or "").lower()
    if any(item in explicit for item in ("malicious", "malware", "trojan", "ransom")):
        return "malicious"
    if any(item in explicit for item in ("suspicious", "grayware", "unknown")):
        return "suspicious"
    try:
        numeric = float(score)
        if numeric >= 70:
            return "malicious"
        if numeric >= 30:
            return "suspicious"
    except (TypeError, ValueError):
        pass
    lowered = text.lower()
    if any(item in lowered for item in ("malicious", "ransomware", "trojan", "backdoor")):
        return "malicious"
    if "suspicious" in lowered:
        return "suspicious"
    return "unknown"


def _confidence(verdict: str, score: Any) -> int:
    try:
        numeric = float(score)
        if numeric <= 10:
            numeric *= 10
        return max(0, min(100, int(numeric)))
    except (TypeError, ValueError):
        return 80 if verdict == "malicious" else 55 if verdict == "suspicious" else 30


def _summary(verdict: str, score: Any, ttps: list[str], signatures: list[dict[str, str]], network: dict[str, list[str]]) -> str:
    parts = [f"Verdict: {verdict}"]
    if score not in (None, ""):
        parts.append(f"score {score}")
    if ttps:
        parts.append(f"{len(ttps)} ATT&CK technique(s)")
    if signatures:
        parts.append(f"{len(signatures)} behavior signature(s)")
    network_count = sum(len(values) for values in network.values())
    if network_count:
        parts.append(f"{network_count} network artifact(s)")
    return "; ".join(parts)


def _first_value(value: Any, keys: tuple[str, ...]) -> Any:
    if not isinstance(value, dict):
        return None
    for key in keys:
        if value.get(key) not in (None, ""):
            return value[key]
    for child in value.values():
        if isinstance(child, dict):
            found = _first_value(child, keys)
            if found not in (None, ""):
                return found
    return None


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


def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item not in (None, "")]
    if isinstance(value, dict):
        return [str(key) for key in value.keys()]
    return [str(value)]


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        text = str(value).strip()
        key = text.lower()
        if text and key not in seen:
            seen.add(key)
            output.append(text)
    return output


def _dedupe_named(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[str] = set()
    output: list[dict[str, str]] = []
    for row in rows:
        key = row["name"].lower()
        if key and key not in seen:
            seen.add(key)
            output.append(row)
    return output


def _stable_id(text: str) -> str:
    return hashlib.sha256(text.encode(errors="ignore")).hexdigest()[:24]


def _short_text(value: Any, limit: int) -> str:
    text = " ".join(str(value).split())
    if len(text) <= limit:
        return text
    return f"{text[:limit - 1].rstrip()}..."
