from __future__ import annotations

import copy
import json
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.services import investigation_story as story


TEXT = "Host DESKTOP-TEST at 10.0.0.7 sent repeated POST requests. Initial access is not established. T1071.001 is a candidate."


def pack(kind="report_claim"):
    evidence = story.EvidencePack()
    evidence.add("fixture/report", kind, TEXT)
    return {"sources": evidence.sources}


def valid():
    def claim(text, quote):
        return {"text": text, "basis": "reported", "evidence": [{"source_id": "S0001", "quote": quote}]}
    return {
        "what_happened": [claim("The report describes repeated POST requests from the workstation.", "Host DESKTOP-TEST at 10.0.0.7 sent repeated POST requests.")],
        "identities": [{**claim("Workstation identified in the supplied report.", "Host DESKTOP-TEST at 10.0.0.7"), "value": "DESKTOP-TEST", "kind": "host"}],
        "ttps": [{**claim("Web protocol behavior is a candidate, not confirmed C2.", "T1071.001 is a candidate."), "attack_id": "T1071.001", "status": "report_claim"}],
        "iocs": [],
        "uncertainties": [claim("Initial access remains unestablished.", "Initial access is not established.")],
        "next_steps": [],
    }


def test_valid_story_binds_quotes_and_renders_readable_sections():
    result = story.validate_story(json.dumps(valid()), pack())
    citation = result["what_happened"][0]["evidence"][0]
    assert TEXT[citation["start"]:citation["end"]] == citation["quote"]
    rendered = story.render_story(result)
    for title in ("What happened", "Identities", "TTPs", "Priority IOCs", "Unknowns", "Evidence references"):
        assert title in rendered
    assert "analyst" in rendered.lower()


@pytest.mark.parametrize("mutation", [
    lambda d: d["what_happened"][0]["evidence"][0].update(source_id="S9999"),
    lambda d: d["what_happened"][0]["evidence"][0].update(quote="The attacker executed ransomware."),
    lambda d: d["what_happened"][0].update(basis="observed"),
    lambda d: d["what_happened"][0].update(text="The host contacted 198.51.100.99."),
    lambda d: d["identities"][0].update(value="INVENTED-HOST"),
    lambda d: d["ttps"][0].update(attack_id="T1059.001"),
    lambda d: d["ttps"][0].update(status="behavior_candidate"),
    lambda d: d.update(confidence_of_compromise=100),
    lambda d: d.update(uncertainties=[]),
    lambda d: d["what_happened"][0].update(evidence=[]),
])
def test_unsafe_or_unbound_outputs_are_rejected(mutation):
    data = valid()
    mutation(data)
    with pytest.raises(ValueError):
        story.validate_story(json.dumps(data), pack())


def test_provider_tags_never_become_behavior_candidates():
    data = valid()
    data["ttps"][0]["status"] = "behavior_candidate"
    with pytest.raises(ValueError, match="cannot become"):
        story.validate_story(json.dumps(data), pack("intelligence_lead"))
    data["ttps"][0]["status"] = "intelligence_lead"
    assert story.validate_story(json.dumps(data), pack("intelligence_lead"))["ttps"][0]["status"] == "intelligence_lead"


def test_exact_quote_binding_is_not_semantic_proof():
    # Deliberately documents the boundary; never advertise schema/quote binding
    # as hallucination-free verification or benchmark accuracy.
    data = valid()
    data["what_happened"][0]["text"] = "The host was compromised by an unknown adversary."
    assert story.validate_story(json.dumps(data), pack())


def test_ambiguous_quotes_and_oversized_narrative_fail():
    evidence = pack()
    evidence["sources"][0]["text"] += TEXT
    with pytest.raises(ValueError, match="ambiguous"):
        story.validate_story(json.dumps(valid()), evidence)
    data = valid()
    data["what_happened"] = [copy.deepcopy(data["what_happened"][0]) for _ in range(4)]
    for c in data["what_happened"]:
        c["text"] = "word " * 70
    with pytest.raises(ValueError, match="240"):
        story.validate_story(json.dumps(data), pack())


def test_evidence_budget_never_silently_truncates():
    evidence = story.EvidencePack()
    text = "x" * 10000
    evidence.add("report", "report_claim", text)
    assert "".join(s["text"] for s in evidence.sources) == text
    with pytest.raises(HTTPException) as exc:
        evidence.add("report", "report_claim", "x" * story.MAX_SOURCE_CHARS)
    assert exc.value.status_code == 413


def test_untrusted_markdown_does_not_create_images_or_html():
    escaped = story._safe("![tracking](https://untrusted.invalid/pixel) <script>bad</script>")
    assert "![tracking](" not in escaped
    assert "<script>" not in escaped


@pytest.mark.asyncio
async def test_full_report_required_and_previous_summaries_excluded():
    row = SimpleNamespace(id=uuid4(), name="Fixture", description="", domain="enterprise-attack", evidence_edges=[], evidence_nodes=[
        {"id": "report-1", "type": "investigation-report", "content": TEXT},
        {"id": "summary-1", "type": "investigation-summary", "content": "DO NOT USE OLD MODEL CLAIMS"},
    ])
    result = await story.build_pack(None, row, "report-1")
    assert "DO NOT USE" not in json.dumps(result)
    assert result["effective_tlp"] == "TLP:AMBER+STRICT"
    with pytest.raises(HTTPException) as exc:
        await story.build_pack(None, row, "summary-1")
    assert exc.value.status_code == 409
    original_hash = result["source_sha256"]
    row.evidence_nodes[1]["content"] = "Different old summary"
    assert (await story.build_pack(None, row, "report-1"))["source_sha256"] == original_hash
    row.evidence_nodes[0]["content"] += " A changed report."
    assert (await story.build_pack(None, row, "report-1"))["source_sha256"] != original_hash


@pytest.mark.asyncio
async def test_authoritative_pcap_bindings_preserve_different_hosts_and_missing_sources_fail():
    from app.models.pcap import PcapAnalysis
    from app.models.analysis import AnalysisSession
    uid, sid = uuid4(), uuid4()
    identities = [
        {"identity_id": "i1", "type": "account", "value": "alice", "ip_addresses": ["10.0.0.1"], "evidence": [{"frame_number": i} for i in range(1, 9)]},
        {"identity_id": "i2", "type": "account", "value": "bob", "ip_addresses": ["10.0.0.2"], "evidence": [{"frame_number": 10}]},
    ]
    pcap = SimpleNamespace(status="completed", semantic_sha256="a"*64, report_text=TEXT, session_id=sid,
                           result={"capture": {}, "identities": identities, "findings": [], "attack_candidates": [],
                                   "artifacts": [{"artifact_id": "file1", "sha256": "b"*64, "completeness": "unknown"}]})
    records = {(PcapAnalysis, uid): pcap, (AnalysisSession, sid): SimpleNamespace(tlp="TLP:RED", source_provenance={
        "pcap_enrichment": {"snapshot_sha256": "c"*64, "items": [{"value": "b"*64, "signals": [{"verdict": "provider-reported-malicious"}]}]}
    })}
    class DB:
        async def get(self, model, identifier, **kwargs):
            return records.get((model, identifier))
    row = SimpleNamespace(id=uuid4(), name="Fixture", description="", domain="enterprise-attack", evidence_edges=[], evidence_nodes=[
        {"id": "r", "type": "investigation-report", "content": TEXT},
        {"type": "log-pcap-analysis", "source_analysis_ref": f"/api/pcap/analyses/{uid}"},
    ])
    result = await story.build_pack(DB(), row, "r")
    facts = [json.loads(s["text"]) for s in result["sources"] if "/identities/" in s["reference"]]
    assert facts[0]["value"] == "alice" and facts[0]["ip_addresses"] == ["10.0.0.1"]
    assert facts[1]["value"] == "bob" and facts[1]["ip_addresses"] == ["10.0.0.2"]
    assert facts[0]["evidence_total"] == 8 and len(facts[0]["evidence"]) == 3
    assert result["effective_tlp"] == "TLP:RED"
    reputation = [s for s in result["sources"] if s["reference"].endswith('/reputation')]
    assert reputation and all(s["kind"] == "intelligence_lead" for s in reputation)
    assert 'not proof of execution' in reputation[0]["text"]
    assert any('/artifacts/file1' in s['reference'] and s['kind'] == 'packet_fact' for s in result['sources'])
    records.clear()
    with pytest.raises(HTTPException) as exc:
        await story.build_pack(DB(), row, "r")
    assert exc.value.status_code == 409
