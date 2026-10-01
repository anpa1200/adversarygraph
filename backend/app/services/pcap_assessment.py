"""Evidence-bound triage. Observed != IOC; provider reputation != capture-time intent.

This layer never changes the deterministic result, promotes canonical IOCs,
infers actor attribution, or propagates a file verdict to its hosting address.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import Counter, defaultdict
from typing import Any

from app.services.pcap_context import observable_key
from app.services.pcap_analyzer import canonical_json

POLICY_VERSION = "pcap-assessment-v1"
NETWORK_TYPES = {"ipv4", "ipv6", "domain", "url"}
HASH_TYPES = {"md5", "sha1", "sha256"}
# These rules support investigation, not an unconditional malicious verdict.
# Simple downloads, directory activity and failed DNS alone are not IOC evidence.
TRIAGE_RULES = {
    "http-on-tls-port", "remote-access-user-agent", "powershell-http-client",
    "cleartext-tokenized-api", "browser-fingerprint-upload", "high-volume-http-posts",
    "distributed-periodic-http-posts", "large-http-post", "repeated-http-posts",
    "periodic-http-callbacks", "multi-host-tls-cadence", "cleartext-tool-self-identification",
    "unclassified-external-tcp",
}


def disclosure_allowed(kind: str, value: str) -> bool:
    """No private/reserved IPs, full URLs, identities or special-use names leave automatically."""
    if kind in HASH_TYPES:
        return bool(re.fullmatch(r"[a-fA-F0-9]{%d}" % {"md5": 32, "sha1": 40, "sha256": 64}[kind], value))
    if kind in {"ipv4", "ipv6"}:
        try:
            address = ipaddress.ip_address(value)
            return address.is_global and not address.is_multicast
        except ValueError:
            return False
    if kind == "domain":
        name = value.lower().rstrip(".")
        if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", name):
            return False
        return not any(name == suffix or name.endswith("." + suffix) for suffix in (
            "localhost", "local", "internal", "intranet", "lan", "corp", "home", "test", "invalid", "example",
            "example.com", "example.net", "example.org", "arpa", "onion",
        ))
    return False


def _integer(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def provider_signal(kind: str, value: str, result: dict) -> dict:
    """Interpret only typed DIRECT fields for the queried artifact, never arbitrary text."""
    source = result.get("source", "unknown")
    status = result.get("status", "unknown")
    signal = {"source": source, "status": status, "verdict": "unknown", "basis": "No direct maliciousness evidence", "evidence": {}}
    if status != "ok":
        signal["basis"] = "No verdict: " + str(status)
        if result.get("error_category"):
            signal["error_category"] = result["error_category"]
        return signal
    raw = result.get("raw") or {}
    if not isinstance(raw, dict):
        return signal
    if source == "virustotal":
        # Require provider identity, preventing a related object's detections
        # or an aggregate search result from becoming this target's verdict.
        provider_value = str(raw.get("indicator") or "")
        if observable_key(kind, provider_value) != observable_key(kind, value):
            signal["basis"] = "Provider target missing or mismatched"
            return signal
        stats = raw.get("last_analysis_stats") or {}
        if not isinstance(stats, dict):
            return signal
        malicious, suspicious = _integer(stats.get("malicious")), _integer(stats.get("suspicious"))
        signal.update(
            verdict="provider-reported-malicious" if malicious else "suspicious" if suspicious else "no-detections",
            basis=f"VirusTotal direct object: {malicious} malicious, {suspicious} suspicious engine reports; not independent confirmations",
            evidence={"last_analysis_stats": stats, "last_analysis_date": raw.get("last_analysis_date"), "url": raw.get("virustotal_url")},
        )
        if not stats:
            signal.update(verdict="unknown", basis="Provider returned no analysis statistics")
    elif source in {"malwarebazaar", "threatfox"}:
        rows = raw.get("data") or []
        matches = []
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            direct = row.get(kind + "_hash") if kind in HASH_TYPES else row.get("ioc")
            if source == "threatfox" and kind not in HASH_TYPES:
                expected_type = {"domain": "domain", "url": "url", "ipv4": "ip", "ipv6": "ip"}.get(kind)
                if row.get("ioc_type") != expected_type:
                    continue
            if direct and observable_key(kind, str(direct)) == observable_key(kind, value):
                matches.append({k: row[k] for k in ("id", "ioc", "ioc_type", "sha256_hash", "sha1_hash", "md5_hash", "malware", "signature", "confidence_level", "first_seen", "last_seen", "reference") if k in row})
        if matches:
            signal.update(verdict="provider-reported-malicious", basis="Exact typed artifact match in " + source, evidence={"records": matches[:20]})
    elif source == "greynoise" and raw.get("ip") == value:
        classification = raw.get("classification")
        if classification in {"malicious", "benign"}:
            signal.update(verdict="provider-reported-malicious" if classification == "malicious" else "provider-reported-benign",
                          basis="GreyNoise direct IP classification", evidence={"classification": classification, "last_seen": raw.get("last_seen")})
    elif source == "abuseipdb":
        data = raw.get("data") or {}
        if isinstance(data, dict) and data.get("ipAddress") == value:
            score = _integer(data.get("abuseConfidenceScore"))
            signal.update(verdict="suspicious" if score >= 75 else "context-only", basis="AbuseIPDB report confidence is not malware proof",
                          evidence={"abuseConfidenceScore": score, "totalReports": data.get("totalReports"), "lastReportedAt": data.get("lastReportedAt")})
    else:
        signal.update(verdict="context-only", basis="Provider context only; relationships and threat names do not establish target maliciousness")
    return signal


def assess(result: dict, context: dict | None = None, enrichment: dict | None = None) -> dict:
    context, enrichment = context or {}, enrichment or {}
    local = defaultdict(list)
    for match in context.get("matches", []):
        local[observable_key(match.get("type", ""), match.get("value", ""))].append(match)
    providers = {observable_key(item["type"], item["value"]): item for item in enrichment.get("items", [])}
    artifacts = {a["sha256"]: a for a in result.get("artifacts", [])}
    related = defaultdict(list)
    # Resolve the remote peer from request direction, not all participants in a
    # finding frame. In particular, a DNS resolver is not the queried domain.
    by_frame = defaultdict(list)
    for kind in ("http_request", "tls_client_hello", "unclassified_tcp"):
        for event in result.get("events", {}).get(kind, []):
            by_frame[event.get("frame_number")].append(event)
    for finding in result.get("findings", []):
        if finding.get("rule_id") not in TRIAGE_RULES:
            continue
        for evidence in finding.get("evidence", []):
            for event in by_frame.get(evidence.get("frame_number"), []):
                fields = event.get("fields", {})
                targets = [("ipv4", event.get("dst_ip", ""))]
                host = str(fields.get("http.host", ""))
                # IPv6 literals are handled as addresses, not domain labels.
                if host and not host.startswith("["):
                    targets.append(("domain", host.split(":", 1)[0]))
                targets.append(("url", fields.get("http.request.full_uri", "")))
                targets.extend(("domain", s.strip()) for s in str(fields.get("tls.handshake.extensions_server_name", "")).split(","))
                for kind, value in targets:
                    if value:
                        related[observable_key(kind, value)].append({"kind": "behavior", "finding_id": finding.get("finding_id"), "rule_id": finding["rule_id"], "frame_number": evidence["frame_number"]})
    rows = []
    for observable in result.get("observables", []):
        kind, value = observable_key(observable.get("type", ""), observable.get("value", ""))
        if kind not in NETWORK_TYPES | HASH_TYPES:
            continue
        reasons = related[(kind, value)][:20]
        artifact = artifacts.get(value) if kind == "sha256" else None
        if artifact:
            features = {f.get("feature") for f in artifact.get("static_features", {}).get("features", [])}
            if "encoded-command" in features or {"powershell-download", "dynamic-evaluation"} <= features:
                reasons.append({"kind": "static-review", "artifact_id": artifact["artifact_id"], "features": sorted(features), "interpretation": "Suspicious static features, not execution or malware proof"})
        for match in local[(kind, value)][:10]:
            reasons.append({"kind": "local-intelligence", "indicator_id": match.get("indicator_id"), "source_id": match.get("source_id"), "source_url": match.get("source_url"), "interpretation": "Exact local match; review source quality and dates"})
        entry = providers.get((kind, value), {})
        signals = entry.get("signals", [])
        malicious = any(s.get("verdict") == "provider-reported-malicious" for s in signals)
        suspicious = any(s.get("verdict") == "suspicious" for s in signals)
        conflicting = malicious and any(s.get("verdict") == "provider-reported-benign" for s in signals)
        classification = "provider-reported-malicious" if malicious else "suspicious" if suspicious or any(r["kind"] in {"behavior", "static-review"} for r in reasons) else "intelligence-match" if reasons else "observed"
        candidate = classification != "observed" and (kind not in {"ipv4", "ipv6"} or disclosure_allowed(kind, value))
        rows.append({
            "observable_id": observable["observable_id"], "type": kind, "value": value,
            "classification": classification, "ioc_candidate": candidate, "reasons": reasons,
            "signals": signals, "provider_conflict": conflicting,
            "evidence": observable.get("evidence", [])[:20], "roles": observable.get("roles", []),
            "enrichment_eligible": disclosure_allowed(kind, value),
            "enrichment_status": "checked" if signals else "not-requested",
            "queried_at": entry.get("queried_at"),
        })
    counts = dict(Counter(r["classification"] for r in rows))
    output = {
        "policy_version": POLICY_VERSION, "source_semantic_sha256": result.get("semantic_sha256"),
        "items": rows, "counts": counts, "ioc_candidate_count": sum(r["ioc_candidate"] for r in rows),
        "summary": f"{len(rows)} typed observations; {sum(r['ioc_candidate'] for r in rows)} evidence-backed IOC candidates for review, including {counts.get('provider-reported-malicious', 0)} with direct malicious provider reports. No automatic confirmation or attribution.",
        "limitations": ["No detections, no record, missing credentials and provider errors do not mean benign.",
                       "Current reputation may postdate the capture. Shared hosting, DNS resolution and graph overlap do not transfer maliciousness.",
                       "A recovered file is not proof of execution; hashes identify exported bytes, including partial objects.",
                       "Public-looking enterprise domains may still be sensitive: review selected targets before external disclosure."],
    }
    output["assessment_sha256"] = hashlib.sha256(canonical_json(output).encode()).hexdigest()
    return output


def review_candidates(assessment: dict) -> list[dict]:
    ranked = sorted((r for r in assessment["items"] if r["ioc_candidate"]), key=lambda r: (r["classification"] != "provider-reported-malicious", r["type"], r["value"]))
    return [{**r, "indicator_type": r["type"], "confidence": 50, "source": "pcap-evidence-assessment", "status": "requires-review"} for r in ranked[:200]]


def assessment_report(assessment: dict, enrichment: dict | None = None) -> str:
    lines = ["## Evidence-backed IOC assessment", "", assessment["summary"], "", f"Policy: `{assessment['policy_version']}`; assessment SHA-256: `{assessment['assessment_sha256']}`.", ""]
    for item in review_candidates(assessment):
        lines.append(f"- {item['type']} `{item['value']}` — {item['classification']}; evidence: `{canonical_json(item['reasons'])}`; provider signals: `{canonical_json(item['signals'])}`")
    lines.extend(["", "Ordinary observations remain in the capture inventory; they are not declared malicious IOCs.", ""])
    if enrichment:
        lines.append(f"Reputation snapshot: `{enrichment.get('snapshot_sha256')}`; updated {enrichment.get('updated_at')}. Each target retains its query time. Coverage: `{canonical_json(enrichment.get('coverage', {}))}`.")
    lines.extend("- " + limit for limit in assessment["limitations"])
    return "\n".join(lines) + "\n"
