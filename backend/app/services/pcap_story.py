"""A concise, cited interpretation after decoding and enrichment.

Packet evidence stays authoritative. This module makes a declared, bounded
projection; it never labels a long inventory as a completed investigation.
"""
from __future__ import annotations

from datetime import datetime, timezone
from collections import Counter
import json
from urllib.parse import urlsplit, urlunsplit

from app.services import investigation_story as story
from app.services.pcap_assessment import assess
from app.services.pcap_context import observable_key
from app.services.rag import normalize_tlp

PROMPT_VERSION = "pcap-investigation-summary-v5"
MAX_WORDS = 320
MAX_NARRATIVE_WORDS = 130
MAX_EVIDENCE_CHARS = 18_000
SYSTEM = story.SYSTEM + """

PCAP FINAL REPORT CONTRACT (takes precedence over generic length guidance):
Write for a SOC analyst who needs to understand this capture in one minute.
Target 180-260 words TOTAL; hard limit 320 words across all text fields.
what_happened: 2-3 short sentences, at most 130 words. Start with the affected
device/account when bound by evidence, then the actual sequence and its security
meaning. Link a transferred file to its client and direct provider label only
when those exact relationships are supplied. Distinguish capture-time activity
from today's reputation. If there is insufficient evidence for an infection,
say that directly; do not fill the gap with a generic attack story.
Use one short sentence per what_happened claim so each sentence can cite the
specific records supporting its identifiers; do not put the whole story in one
claim when its evidence would require more than three citations.
Describe salient transfer-bound PE/document/archive downloads before weak generic
POST heuristics. A PNG-named URL returning PE bytes is an important discrepancy;
do not misread the extension as the actual file format. Account for all high-value
download clients instead of calling the noisiest POST sender the infected host.
Do not claim that no payload was downloaded when recovered executable transfers
are supplied. A benign purpose is also unproven without affirmative evidence.

Do NOT lead with packet counts, schema names, source hashes, raw protocol lists,
file inventories, or how the platform works. Do NOT write a mini-report for every
observation. Select only the most useful evidence. Keep packet facts, provider
assertions and your interpretation distinguishable without repeating the same
disclaimer in every sentence. Never say downloaded malware executed unless the
capture explicitly establishes execution, and do not call every device infected.

identities: at most 3 relevant bound host/account/IP items; no domain-controller
inventory unless it matters to the incident. ttps: at most 2 evidence-supported
technique candidates. iocs: at most 5 actionable evidence-qualified indicators;
give each one's role and reason in one short sentence. Prefer a relevant payload
SHA-256 over redundant MD5/SHA-1. Do not repeat full hashes in what_happened.
uncertainties: 1-2 material gaps, not boilerplate. next_steps: at most 1 practical
next check. Every statement must retain the supplied source citations.
Weak repeated POST traffic alone is not a useful malicious IOC declaration; omit
it from the action list if no additional evidence supports its security meaning.
T1105 means transfer of tools into an environment, not outbound data exfiltration.
Do not map a technique to unrelated traffic just because its ID is present.
If required_narrative_evidence_ids is nonempty, the narrative must cite at least
one passage from those high-value file-transfer records. A T1105 entry must cite
both a source-present technique ID and a supplied packet file-transfer record.

Families are provider-reported labels on a file or indicator, not proof that all
traffic belongs to that family. Similarity to actor profiles is NOT attribution.
A bounded summary cannot cover every packet: consult coverage for omitted rows.
"""


def fingerprint(row, session) -> str:
    provenance = session.source_provenance or {}
    return story.checksum({"analysis_id": str(row.id), "semantic_sha256": row.semantic_sha256,
        "context": provenance.get("pcap_context", {}).get("snapshot_sha256"),
        "enrichment": provenance.get("pcap_enrichment", {}).get("snapshot_sha256"),
        "tlp": normalize_tlp(session.tlp), "prompt_version": PROMPT_VERSION})


def snapshot(row, session) -> dict | None:
    saved = (session.source_provenance or {}).get("pcap_investigation_summary")
    if not isinstance(saved, dict):
        return None
    return {**saved, "stale": saved.get("source_sha256") != fingerprint(row, session)}


def build_pack(row, session, *, compact=False) -> dict:
    result = row.result or {}
    provenance = session.source_provenance or {}
    context, enrichment = provenance.get("pcap_context", {}), provenance.get("pcap_enrichment", {})
    assessment = assess(result, context, enrichment)
    candidates = [r for r in assessment["items"] if r["ioc_candidate"]]
    candidates.sort(key=lambda r: (r["classification"] != "provider-reported-malicious",
                                  r["type"] != "sha256", r["value"]))
    selected = candidates[:5 if compact else 12]
    selected_keys = {observable_key(r["type"], r["value"]) for r in selected}
    all_keys = {observable_key(r["type"], r["value"]) for r in candidates}
    evidence = story.EvidencePack()
    counts = {}
    omitted = {}
    required_narrative = []

    def add(group, kind, value, reference):
        text = story.canonical(value)
        if evidence.characters + len(text) > (10_000 if compact else MAX_EVIDENCE_CHARS):
            omitted[group] = omitted.get(group, 0) + 1
            return
        evidence.add(reference, kind, text)
        counts[group] = counts.get(group, 0) + 1

    base = f"/api/pcap/analyses/{row.id}"
    capture = result.get("capture", {})
    capture_facts = {k: capture[k] for k in ("packet_count", "first_packet_epoch", "last_packet_epoch", "duration_seconds") if k in capture}
    for key in ("first_packet_epoch", "last_packet_epoch"):
        try:
            capture_facts[key.replace("epoch", "utc")] = datetime.fromtimestamp(float(capture[key]), timezone.utc).isoformat()
        except (KeyError, ValueError, TypeError, OverflowError):
            pass
    add("capture", "packet_fact", {"filename": row.filename, **capture_facts}, base + "#capture")
    # Reserve a material limitation record before selecting the evidence.
    warnings = result.get("coverage", {}).get("warnings", [])
    provider_counts = Counter((signal.get("source", "unknown"), signal.get("status", "unknown"))
        for item in enrichment.get("items", []) for signal in item.get("signals", []))
    add("limits", "packet_fact", {"warnings": warnings,
        "visibility": "Encrypted application payloads are not decrypted. No endpoint execution, persistence or actor attribution is established by a download or connection alone.",
        "internal_lookup": context.get("coverage", {})}, base + "#coverage")
    add("reputation_coverage", "intelligence_lead", {"provider_status_counts": [
        {"provider": provider, "status": status, "targets": count} for (provider, status), count in sorted(provider_counts.items())],
        "scope": "Current enrichment coverage only. Rate limited, unavailable and not-found results do not mean clean."}, base + "#enrichment-coverage")

    # Direct exact-target provider assertions come before lower-value inventory.
    for item in selected:
        signals = item.get("signals", [])
        add("candidates", "rule_candidate", {"type": item["type"], "value": item["value"],
            "classification": item["classification"], "role": "investigation candidate, not an unconditional malicious verdict",
            "reasons": item["reasons"][:3], "reputation_status": {s.get("source"): s.get("status") for s in signals}}, base + "#assessment/" + item["observable_id"])
        for signal in signals:
            if signal.get("status") != "ok" or signal.get("verdict") == "context-only":
                continue  # Per-target status above and aggregate coverage retain the gap.
            direct = signal.get("evidence", {})
            add("reputation", "intelligence_lead", {"type": item["type"], "value": item["value"],
                "provider": signal.get("source"), "queried_at": signal.get("queried_at"),
                "status": signal.get("status"), "verdict": signal.get("verdict"),
                "basis": signal.get("basis"),
                "evidence": {k: direct[k] for k in ("last_analysis_stats", "last_analysis_date", "threat_names", "records") if k in direct}},
                base + "#reputation/" + item["observable_id"])

    artifacts = list(result.get("artifacts", []))
    format_rank = {"pe": 0, "ole-document": 1, "zip": 2, "script-like-text": 3}
    artifacts.sort(key=lambda a: (("sha256", a.get("sha256", "")) not in selected_keys,
        format_rank.get(a.get("static_features", {}).get("content_kind"), 4), a.get("sha256", "")))
    interesting = [a for a in artifacts if ("sha256", a.get("sha256", "")) in all_keys or a.get("static_features", {}).get("content_kind") in {"pe", "ole-document", "script-like-text", "zip"}]
    artifact_limit = 6 if compact else 12
    omitted["artifacts"] = max(0, len(artifacts) - min(len(interesting), artifact_limit))
    relevant_clients = set()
    for artifact in interesting[:artifact_limit]:
        transfers = artifact.get("transfers", [])
        for transfer in transfers[:2]:
            if transfer.get("client_ip"):
                relevant_clients.add(transfer["client_ip"])
            before = len(evidence.sources)
            try:
                parsed_url = urlsplit(transfer.get("url", ""))
                display_url = urlunsplit((parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", ""))
            except ValueError:
                display_url = "unparseable URL omitted; inspect original transfer"
            add("transfers", "packet_fact", {"sha256": artifact["sha256"],
                "content_kind": artifact.get("static_features", {}).get("content_kind"),
                "client_ip": transfer.get("client_ip"), "server_ip": transfer.get("server_ip"),
                "url_without_query_or_fragment": display_url, "request_frame": transfer.get("request_frame"),
                "response_frame": transfer.get("response_frame"), "match_basis": transfer.get("match_basis"),
                "completeness": transfer.get("completeness")}, base + "#artifact/" + artifact["artifact_id"])
            if ("sha256", artifact["sha256"]) in selected_keys:
                required_narrative.extend(s["source_id"] for s in evidence.sources[before:])
        if not transfers:
            add("artifacts", "packet_fact", {"filename": artifact["filename"], "sha256": artifact["sha256"],
                "content_kind": artifact.get("static_features", {}).get("content_kind"),
                "size_bytes": artifact.get("size_bytes"), "completeness": artifact.get("completeness"),
                "frames": [r.get("frame_number") for r in artifact.get("evidence", [])[:3]],
                "scope": "Recovered bytes only; client or transfer not bound"}, base + "#artifact/" + artifact["artifact_id"])

    # Retain representative packet events for qualified network candidates.
    selected_events = []
    for kind in ("http_request", "tls_client_hello", "smtp", "unclassified_tcp"):
        for event in result.get("events", {}).get(kind, []):
            fields = event.get("fields", {})
            values = [event.get("src_ip"), event.get("dst_ip"), fields.get("http.host"), fields.get("http.request.full_uri"), fields.get("tls.handshake.extensions_server_name")]
            if any(value and any(value == r["value"] for r in selected) for value in values):
                selected_events.append(event)
    selected_events.sort(key=lambda e: e.get("frame_number", 0))
    omitted["selected_network_events"] = max(0, len(selected_events) - 24)
    # Stratify by remote tuple so a noisy first host cannot fill the whole pack.
    per_peer = {}
    kept_events = []
    for event in selected_events:
        peer = (event.get("src_ip"), event.get("dst_ip"), event.get("kind"))
        if per_peer.get(peer, 0) >= 2:
            continue
        per_peer[peer] = per_peer.get(peer, 0) + 1
        kept_events.append(event)
        if len(kept_events) == (4 if compact else 12):
            break
    omitted["selected_network_events"] = len(selected_events) - len(kept_events)
    for event in kept_events:
        relevant_clients.add(event.get("src_ip"))
        fields = event.get("fields", {})
        allowed_fields = {k: fields[k] for k in ("http.request.method", "http.host", "http.request.full_uri", "http.user_agent", "tls.handshake.extensions_server_name") if k in fields}
        add("network", "packet_fact", {"kind": event["kind"], "frame": event["frame_number"],
            "timestamp_epoch": event.get("timestamp_epoch"), "src_ip": event.get("src_ip"), "dst_ip": event.get("dst_ip"),
            "dst_port": event.get("dst_port"), "fields": allowed_fields}, base + "#frame/" + str(event["frame_number"]))

    identities = [i for i in result.get("identities", []) if i.get("type") in {"hostname", "account", "full-name"}]
    identities.sort(key=lambda i: (not bool(set(i.get("ip_addresses", [])) & relevant_clients), i.get("type") != "account", i.get("value", "")))
    identity_limit = 6 if compact else 10
    omitted["identities"] = max(0, len(identities) - identity_limit)
    for identity in identities[:identity_limit]:
        add("identities", "packet_fact", {"type": identity["type"], "value": identity["value"],
            "ip_addresses": identity.get("ip_addresses", []), "mac_addresses": identity.get("mac_addresses", []),
            "bindings": [{k: b[k] for k in ("owner_ip", "relationship", "frame_number", "account") if k in b} for b in identity.get("bindings", [])[:2]]},
            base + "#identity/" + identity["identity_id"])

    findings = sorted(result.get("findings", []), key=lambda f: (f.get("severity") != "high", f.get("rule_id") in {"script-or-executable-transfer", "directory-service-activity"}, f.get("finding_id", "")))
    finding_limit = 4 if compact else 10
    omitted["findings"] = max(0, len(findings) - finding_limit)
    for finding in findings[:finding_limit]:
        add("findings", "rule_candidate", {"title": finding["title"], "rule_id": finding["rule_id"],
            "explanation": finding.get("explanation"), "metrics": finding.get("metrics"),
            "frames": [r.get("frame_number") for r in finding.get("evidence", [])[:3]]}, base + "#finding/" + finding["finding_id"])
    techniques = result.get("attack_candidates", [])
    omitted["techniques"] = max(0, len(techniques) - 6)
    for technique in techniques[:6]:
        add("techniques", "rule_candidate", {**{k: technique[k] for k in ("attack_id", "name", "tactic", "interpretation") if k in technique},
            "frames": [ref.get("frame_number") for ref in technique.get("evidence", [])[:3]],
            "status": "Heuristic technique candidate, not established adversary activity"}, base + "#technique/" + technique.get("attack_id", ""))
    for match in context.get("matches", [])[:8]:
        add("local_intelligence", "intelligence_lead", {k: match[k] for k in ("type", "value", "source_id", "source_url", "confidence", "first_seen", "last_seen") if k in match}, base + "#local-intelligence")
    omitted["candidates"] = len(candidates) - len(selected)
    identity_values = {v for v in relevant_clients if isinstance(v, str) and v}
    for identity in identities[:identity_limit]:
        identity_values.add(identity["value"])
        identity_values.update(identity.get("ip_addresses", []))
    # Large, heavily escaped packet strings caused observed zero-output length
    # responses. Use a disclosed, deterministic smaller selection before asking
    # for another paid draft, keeping the same evidence qualification rules.
    if not compact and evidence.characters > 14_000:
        return build_pack(row, session, compact=True)
    coverage = {"projection": "pcap-brief-evidence-v2-compact" if compact else "pcap-brief-evidence-v1", "source_characters": evidence.characters,
        "compact_evidence": compact,
        "included_records": counts, "omitted_records": omitted, "candidate_total": len(candidates),
        "enrichment_retained_targets": len(enrichment.get("items", [])), "warnings": warnings,
        "source_digest": row.semantic_sha256,
        "supplement_scope": "Bounded selected packet metadata, direct reputation, identities and transfer relationships; no payload bodies, prior-case content or exhaustive inventory. Full data remains in source analysis."}
    return {"sources": evidence.sources, "report_id": f"pcap:{row.id}", "source_sha256": fingerprint(row, session),
        "coverage": coverage, "effective_tlp": normalize_tlp(session.tlp), "schema_version": PROMPT_VERSION,
        "pcap_ioc_allowlist": sorted(selected_keys), "required_narrative_evidence_ids": required_narrative,
        "pcap_identity_allowlist": sorted(v for v in identity_values if len(v) <= 200),
        "pcap_technique_allowlist": sorted({t["attack_id"] for t in techniques[:6]})}


def validate(raw, pack):
    value = story.validate_story(raw, pack)
    required = set(pack.get("required_narrative_evidence_ids", []))
    if required and not any(c["source_id"] in required for claim in value["what_happened"] for c in claim["evidence"]):
        raise ValueError("Narrative omits required high-value transfer evidence")
    for technique in value["ttps"]:
        if technique["attack_id"] == "T1105" and not any("#artifact/" in ref["reference"] for ref in technique["evidence"]):
            raise ValueError("T1105 lacks a cited packet file-transfer record")
    if sum(len(c["text"].split()) for claims in value.values() for c in claims) > MAX_WORDS:
        raise ValueError("PCAP summary exceeds 320 words")
    if sum(len(c["text"].split()) for c in value["what_happened"]) > MAX_NARRATIVE_WORDS:
        raise ValueError("PCAP narrative exceeds 130 words")
    for key, limit in {"identities": 3, "ttps": 2, "iocs": 5, "uncertainties": 2, "next_steps": 1}.items():
        if len(value[key]) > limit:
            raise ValueError("PCAP concise section limit exceeded")
    return value


def render(value):
    lines = ["# PCAP investigation summary", "", "## What happened", ""]
    for claim in value["what_happened"]:
        lines.extend([story._safe(claim["text"]), ""])
    for key, title in (("identities", "Who was involved"), ("iocs", "Key indicators"), ("ttps", "Supported technique candidates"),
                       ("uncertainties", "What remains uncertain"), ("next_steps", "Next check")):
        if not value[key]:
            continue
        lines.extend([f"## {title}", ""])
        for claim in value[key]:
            label = claim.get("value") or claim.get("attack_id")
            lines.append("- " + (f"{story._safe(label)} — " if label and label not in claim["text"] else "") + story._safe(claim["text"]))
        lines.append("")
    lines.append("Analyst-review draft. Exact evidence references and provider provenance are retained in the structured record.")
    return "\n".join(lines)


def validate_model_draft(raw, pack, adjustments):
    """Keep the narrative strict; conservatively omit unsupported extras.

    Evidence level is server-governed: it may be downgraded, never upgraded.
    No claim text or source quotation is rewritten. Every retained claim still
    passes the unchanged validators. Omitted optional claims are disclosed.
    """
    adjustments.clear()
    payload = json.loads(raw)
    if not isinstance(payload, dict) or set(payload) - set(story.Story.model_fields):
        raise ValueError("Invalid summary structure")
    optional = {"identities": story.Identity, "iocs": story.Indicator,
                "ttps": story.Technique, "next_steps": story.Claim}
    original_indices = {key: [] for key in optional}
    # Missing optional sections mean no optional claims, not a fabricated
    # narrative. Malformed optional entries are withheld just like uncited ones.
    draft = story.Story.model_validate({**payload, **{key: [] for key in optional}}).model_dump()
    for section, model in optional.items():
        claims = payload.get(section, [])
        if not isinstance(claims, list):
            adjustments.append({"section": section, "index": -1, "action": "optional-claim-omitted", "reason": "schema_list_type"})
            continue
        for index, claim in enumerate(claims):
            try:
                draft[section].append(model.model_validate(claim).model_dump())
                original_indices[section].append(index)
            except ValueError as exc:
                adjustments.append({"section": section, "index": index, "action": "optional-claim-omitted", "reason": story.validation_error_code(exc)})
    source_kinds = {s["source_id"]: s["kind"] for s in pack["sources"]}
    for section, claims in draft.items():
        for index, claim in enumerate(claims):
            source_index = original_indices[section][index] if section in original_indices else index
            kinds = {source_kinds.get(c["source_id"]) for c in claim["evidence"]}
            if claim["basis"] == "observed" and kinds != {"packet_fact"}:
                claim["basis"] = "assessment" if "rule_candidate" in kinds else "reported"
                adjustments.append({"section": section, "index": source_index, "action": "evidence-level-downgrade", "basis": claim["basis"]})
    accepted = {key: (claims if key in {"what_happened", "uncertainties"} else []) for key, claims in draft.items()}
    # A bad core narrative or missing material transfer still fails the whole
    # draft and takes the bounded repair path. It is never silently salvaged.
    validate(story.canonical(accepted), pack)
    for section in ("identities", "iocs", "ttps", "next_steps"):
        for index, claim in enumerate(draft[section]):
            trial = {**accepted, section: accepted[section] + [claim]}
            try:
                validate(story.canonical(trial), pack)
            except ValueError as exc:
                adjustments.append({"section": section, "index": original_indices[section][index], "action": "optional-claim-omitted", "reason": story.validation_error_code(exc)})
            else:
                accepted = trial
    return validate(story.canonical(accepted), pack)


async def generate(row, session, adapter):
    pack = build_pack(row, session)
    adapter.story_section_limits = {"identities": 3, "ttps": 2, "iocs": 5, "uncertainties": 2, "next_steps": 1}
    adjustments = []
    output = await story.generate_story(pack, adapter, system=SYSTEM, prompt_version=PROMPT_VERSION,
        validator=lambda raw, evidence: validate_model_draft(raw, evidence, adjustments), renderer=render,
        omit_invalid_optional_citations=True)
    # Keep the human report short; provenance is separately visible/exportable.
    output.update(content=render(output["structured"]), type="pcap-investigation-summary",
        label="PCAP investigation summary", analysis_id=str(row.id), filename=row.filename,
        capture_sha256=row.source_sha256, stale=False,
        validation_adjustments=[*output.pop("binding_adjustments", []),
            *({**item, "stage": "claim_validation"} for item in adjustments)],
        word_count=sum(len(c["text"].split()) for claims in output["structured"].values() for c in claims))
    return output
