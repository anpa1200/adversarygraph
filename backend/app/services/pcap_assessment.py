"""Evidence-bound triage. Observed != IOC; provider reputation != capture-time intent.

This layer never changes the deterministic result, promotes canonical IOCs,
infers actor attribution, or propagates a file verdict to its hosting address.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from app.services.pcap_context import observable_key
from app.services.pcap_analyzer import canonical_json

POLICY_VERSION = "pcap-assessment-v2"
NETWORK_TYPES = {"ipv4", "ipv6", "domain", "url"}
HASH_TYPES = {"md5", "sha1", "sha256"}
# These rules support investigation, not an unconditional malicious verdict.
# Simple downloads, directory activity and failed DNS alone are not IOC evidence.
TRIAGE_RULES = {
    "http-on-tls-port", "remote-access-user-agent", "powershell-http-client",
    "cleartext-tokenized-api", "browser-fingerprint-upload", "high-volume-http-posts",
    "distributed-periodic-http-posts", "large-http-post", "repeated-http-posts",
    "periodic-http-callbacks", "cleartext-tool-self-identification", "sensitive-data-in-cleartext",
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


def enrichment_state(signals: list[dict]) -> str:
    applicable = [s for s in signals if s.get("status") not in {"not-applicable", "skipped"}]
    usable = sum(s.get("status") in {"ok", "not_found"} for s in applicable)
    if not signals:
        return "not-requested"
    if usable and usable == len(applicable):
        return "checked"
    return "partial" if usable else "unavailable"


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
        if kind in HASH_TYPES:
            # These are labels on this exact file, not names of related hosts
            # or a transitive malware-family assertion about the whole capture.
            signal["evidence"]["threat_names"] = [v[:160] for v in raw.get("threat_names", []) if isinstance(v, str)][:20]
            signal["evidence"]["known_filenames"] = [v[:160] for v in raw.get("names", []) if isinstance(v, str)][:10]
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
    providers = {observable_key(item["type"], item["value"]): item for item in enrichment.get("items", []) if item.get("type") and item.get("value")}
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
                targets = []
                for address in (event.get("src_ip", ""), event.get("dst_ip", "")):
                    ip_type = "ipv6" if ":" in address else "ipv4"
                    if disclosure_allowed(ip_type, address):
                        targets.append((ip_type, address))
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
        # A single engine's warning on a shared service must remain visible,
        # but is not enough to put that service into a capture's IOC shortlist.
        # Three is an explicit triage threshold, not independent corroboration
        # or proof; behavior/local evidence can separately justify review.
        weak_network_reputation_only = kind in NETWORK_TYPES and not reasons and not any(
            (s.get("source") == "virustotal" and _integer(s.get("evidence", {}).get("last_analysis_stats", {}).get("malicious")) >= 3)
            or (s.get("source") != "virustotal" and s.get("verdict") == "provider-reported-malicious")
            for s in signals
        )
        if weak_network_reputation_only:
            candidate = False
        rows.append({
            "observable_id": observable["observable_id"], "type": kind, "value": value,
            "classification": classification, "ioc_candidate": candidate, "reasons": reasons,
            "signals": signals, "provider_conflict": conflicting,
            "ioc_selection_note": "Weak reputation only: retained as provider context, not a declared IOC candidate" if weak_network_reputation_only and classification != "observed" else "Candidate requires analyst validation" if candidate else "Observation only",
            "evidence": observable.get("evidence", [])[:20], "roles": observable.get("roles", []),
            "enrichment_eligible": disclosure_allowed(kind, value),
            "enrichment_status": enrichment_state(signals),
            "queried_at": entry.get("queried_at"),
        })
    counts = dict(Counter(r["classification"] for r in rows))
    output = {
        "policy_version": POLICY_VERSION, "source_semantic_sha256": result.get("semantic_sha256"),
        "items": rows, "counts": counts, "ioc_candidate_count": sum(r["ioc_candidate"] for r in rows),
        "summary": f"{len(rows)} typed observations; {sum(r['ioc_candidate'] for r in rows)} evidence-backed IOC candidates for review, including {sum(r['ioc_candidate'] and r['classification'] == 'provider-reported-malicious' for r in rows)} with direct malicious provider reports. No automatic confirmation or attribution.",
        "limitations": ["No detections, no record, missing credentials and provider errors do not mean benign.",
                       "Current reputation may postdate the capture. Shared hosting, DNS resolution and graph overlap do not transfer maliciousness.",
                       "A recovered file is not proof of execution; hashes identify exported bytes, including partial objects.",
                       "Public-looking enterprise domains may still be sensitive: review selected targets before external disclosure."],
    }
    output["enrichment_plan"] = enrichment_plan(result, rows)
    output["assessment_sha256"] = hashlib.sha256(canonical_json(output).encode()).hexdigest()
    return output


def enrichment_plan(result: dict, rows: list[dict]) -> dict:
    """Rank bounded next queries, independently of IOC declaration.

    TLS names, DNS and opaque conversations must remain discoverable even when
    they do not establish maliciousness. No popularity allowlist or test IOCs.
    """
    priority: dict[tuple, tuple[int, set[str]]] = {}

    def offer(kind, value, score, reason):
        if not value:
            return
        key = observable_key(kind, value)
        old_score, reasons = priority.get(key, (0, set()))
        priority[key] = (max(score, old_score), reasons | {reason})

    for artifact in result.get("artifacts", []):
        kind = artifact.get("static_features", {}).get("content_kind")
        score = 95 if kind in {"pe", "ole-document", "script-like-text"} else 70 if kind == "zip" else 25
        offer("sha256", artifact.get("sha256"), score, "recovered-" + str(kind or "unclassified") + "-bytes")
        for transfer in artifact.get("transfers", []):
            if score >= 70:
                value = transfer.get("server_ip", "")
                offer("ipv6" if ":" in value else "ipv4", value, 80, "served-inspectable-file-not-transitive-verdict")
    for kind in ("http_request", "tls_client_hello", "unclassified_tcp", "smtp"):
        for event in result.get("events", {}).get(kind, []):
            fields = event.get("fields", {})
            score = 60 if kind == "http_request" and fields.get("http.request.method") == "POST" else 45
            # Either direction may contain a public peer, including a victim's
            # HTTP server responding to an external client.
            for endpoint in (event.get("src_ip", ""), event.get("dst_ip", "")):
                offer("ipv6" if ":" in endpoint else "ipv4", endpoint, score, kind + "-peer")
            host = str(fields.get("http.host", ""))
            if host and not host.startswith("["):
                offer("domain", host.split(":", 1)[0], score + 1, "observed-http-host")
            for name in str(fields.get("tls.handshake.extensions_server_name", "")).split(","):
                offer("domain", name.strip(), 46, "observed-tls-sni-content-unknown")
    for event in result.get("events", {}).get("dns", []):
        fields = event.get("fields", {})
        addresses = str(fields.get("dns.a", "")).split(",") + str(fields.get("dns.aaaa", "")).split(",")
        connected = [priority.get(observable_key("ipv6" if ":" in v else "ipv4", v), (0, set()))[0] for v in addresses]
        for name in str(fields.get("dns.qry.name", "")).split(","):
            offer("domain", name.strip(), max([20, *connected]), "dns-name-not-resolver-verdict")
    items = []
    for row in rows:
        if not row["enrichment_eligible"]:
            continue
        score, reasons = priority.get(observable_key(row["type"], row["value"]), (10, {"observed-in-capture"}))
        if row["ioc_candidate"]:
            score = max(score, 100)
            reasons = reasons | {"existing-evidence-candidate"}
        # A completed ThreatFox query cannot hide a failed VirusTotal query.
        # Never retry an active cooldown or repeatedly queue missing credentials.
        direct = [s for s in row["signals"] if s.get("source") in {"virustotal", "malwarebazaar", "threatfox"}
                  and s.get("status") not in {"not-applicable", "skipped"}]
        checked = [s["source"] for s in direct if s.get("status") in {"ok", "not_found"}]
        pending = [s for s in direct if s.get("status") not in {"ok", "not_found"}]
        retryable = []
        for signal in pending:
            if signal.get("status") not in {"error", "deferred-rate-limit", "not-attempted-budget"}:
                continue
            if signal.get("error_category") in {"authentication", "forbidden", "not_configured", "configuration"}:
                continue
            if signal.get("retry_at"):
                try:
                    retry_at = datetime.fromisoformat(signal["retry_at"].replace("Z", "+00:00"))
                    if retry_at.tzinfo is None or retry_at > datetime.now(timezone.utc):
                        continue
                except (ValueError, TypeError, AttributeError):
                    continue
            retryable.append(signal["source"])
        direct_checked = bool(checked) and not pending
        queue_ready = not direct or bool(retryable)
        items.append({"observable_id": row["observable_id"], "type": row["type"], "value": row["value"],
                      "priority": score, "reasons": sorted(reasons), "direct_checked": direct_checked,
                      "checked_providers": sorted(checked), "pending_providers": sorted(s["source"] for s in pending),
                      "retryable_providers": sorted(retryable), "queue_ready": queue_ready,
                      "ioc_candidate": row["ioc_candidate"]})
    items.sort(key=lambda r: (not r["queue_ready"], bool(r["retryable_providers"]), -r["priority"], r["type"], r["value"]))
    return {"policy": "evidence-priority-v2", "items": items, "eligible_count": len(items),
            "next_batch": [r["observable_id"] for r in items if r["queue_ready"]][:10],
            "scope": "Query recommendations, not IOC verdicts. Partial provider coverage stays pending; cooldowns/credential failures are not completed checks. Checked means completed attempted direct providers, not all available providers. Review before external disclosure."}


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
