"""Explicit, bounded passive queries through the platform's existing providers."""
from __future__ import annotations

import asyncio
import hashlib
import time
from datetime import datetime, timezone

from app.services.ioc_investigation import enrich_ioc_sources, InvestigationOptions
from app.services.pcap_analyzer import canonical_json
from app.services.pcap_assessment import disclosure_allowed, provider_signal

PROVIDERS = {"virustotal", "threatfox", "malwarebazaar", "otx", "urlscan", "greynoise", "abuseipdb", "shodan", "censys"}
MAX_TARGETS = 10
MAX_PROVIDERS = 3
BATCH_TIMEOUT_SECONDS = 90
PROVIDER_TIMEOUT_SECONDS = 25


def select_targets(result: dict, observable_ids: list[str]) -> list[dict]:
    ids = list(dict.fromkeys(observable_ids))
    if not 1 <= len(ids) <= MAX_TARGETS:
        raise ValueError(f"Choose 1–{MAX_TARGETS} observed targets")
    by_id = {o["observable_id"]: o for o in result.get("observables", [])}
    targets = []
    for identity in ids:
        item = by_id.get(identity)
        if not item:
            raise ValueError("A selected target is not in this capture")
        if not disclosure_allowed(item["type"], item["value"]):
            raise ValueError("Private/reserved targets, full URLs, identities and special-use domains cannot be sent to providers")
        targets.append(item)
    return targets


async def enrich_capture(db, result: dict, *, observable_ids: list[str], providers: list[str], previous: dict | None = None) -> dict:
    targets = select_targets(result, observable_ids)
    selected = list(dict.fromkeys(providers))
    if not selected or len(selected) > MAX_PROVIDERS or set(selected) - PROVIDERS:
        raise ValueError("Choose 1–3 supported passive providers")
    started = time.monotonic()
    lookup_count = 0
    rate_limited = set()
    # A bounded rolling snapshot retains previous target/provider observations.
    old = previous or {}
    entries = {e["observable_id"]: e for e in old.get("items", [])}
    batch = []
    for target in targets:
        queried_at = datetime.now(timezone.utc).isoformat()
        existing = entries.get(target["observable_id"], {})
        signals = {s["source"]: s for s in existing.get("signals", [])}
        for provider in selected:
            remaining = BATCH_TIMEOUT_SECONDS - (time.monotonic() - started)
            if provider in rate_limited:
                response = {"source": provider, "status": "deferred-rate-limit"}
            elif provider in {"abuseipdb", "greynoise", "shodan", "censys"} and target["type"] not in {"ipv4", "ipv6"}:
                response = {"source": provider, "status": "not-applicable"}
            elif provider == "malwarebazaar" and target["type"] not in {"md5", "sha1", "sha256"}:
                response = {"source": provider, "status": "not-applicable"}
            elif remaining <= 0:
                response = {"source": provider, "status": "not-attempted-budget"}
            else:
                lookup_count += 1
                try:
                    async with asyncio.timeout(min(remaining, PROVIDER_TIMEOUT_SECONDS)):
                        rows = await enrich_ioc_sources(db, target["value"], sources=[provider], options=InvestigationOptions(depth=1, ai_summarize=False))
                    response = rows[0]
                except TimeoutError:
                    response = {"source": provider, "status": "error", "error_category": "timeout"}
            if response.get("error_category") == "rate_limited":
                rate_limited.add(provider)
            signal = provider_signal(target["type"], target["value"], response)
            signal["queried_at"] = datetime.now(timezone.utc).isoformat()
            # Threat context stays separate from packet-observed TTPs.
            signal["technique_ids"] = response.get("technique_ids", [])[:40]
            signal["actors"] = response.get("actors", [])[:20]
            signal["relationship_context"] = response.get("relationships", [])[:40]
            signal["context_status"] = "provider-assertion-not-capture-behavior-or-attribution"
            signals[provider] = signal
            batch.append({"observable_id": target["observable_id"], "provider": provider, "status": signal["status"]})
        entries[target["observable_id"]] = {
            "observable_id": target["observable_id"], "type": target["type"], "value": target["value"],
            "queried_at": queried_at, "signals": sorted(signals.values(), key=lambda s: s["source"]),
        }
    snapshot = {
        "schema_version": "pcap-reputation-v1", "source_semantic_sha256": result["semantic_sha256"],
        "updated_at": datetime.now(timezone.utc).isoformat(), "previous_snapshot_sha256": old.get("snapshot_sha256"),
        "items": sorted(entries.values(), key=lambda e: e["queried_at"], reverse=True)[:200],
        "coverage": {"batch_targets": len(targets), "provider_lookups_started": lookup_count, "batch_results": batch,
                     "retained_targets": min(len(entries), 200), "targets_omitted": max(0, len(entries) - 200),
                     "payload_uploads": 0, "active_scans": 0, "full_urls_disclosed": 0},
    }
    snapshot["snapshot_sha256"] = hashlib.sha256(canonical_json(snapshot).encode()).hexdigest()
    return snapshot
