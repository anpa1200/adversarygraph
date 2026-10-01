import copy
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from app.services import investigation_story as story, pcap_story
from tests.unit.test_investigation_story import pack, valid


@pytest.mark.asyncio
async def test_claude_returned_model_and_usage_include_cache_tokens():
    from app.services.ai.claude import ClaudeAdapter
    adapter = ClaudeAdapter.__new__(ClaudeAdapter)
    adapter._model = "configured-alias"
    response = SimpleNamespace(model="actual-snapshot", id="message-1", stop_reason="end_turn",
        usage=SimpleNamespace(input_tokens=100, output_tokens=20, cache_read_input_tokens=50, cache_creation_input_tokens=10),
        content=[SimpleNamespace(text='{"ok":true}')])
    adapter._api_client = SimpleNamespace(messages=SimpleNamespace(create=AsyncMock(return_value=response)))
    assert await adapter._raw_complete("system", "user") == '{"ok":true}'
    assert adapter.story_response_model == "actual-snapshot"
    assert adapter.story_usage["prompt_tokens"] == 160
    assert adapter.story_usage["total_tokens"] == 180


def source():
    row = SimpleNamespace(id=uuid4(), filename="test.pcap", semantic_sha256="a"*64,
        source_sha256="b"*64, result={"capture": {"first_packet_epoch": "1587683743"}, "artifacts": [], "observables": []})
    session = SimpleNamespace(tlp="TLP:CLEAR", source_provenance={"pcap_context": {"snapshot_sha256": "c"*64},
        "pcap_enrichment": {"snapshot_sha256": "d"*64, "items": [{"signals": [{"source": "virustotal", "status": "deferred-rate-limit"}]}]}})
    return row, session


def test_projection_preserves_coverage_without_promoting_observations():
    row, session = source()
    row.result["observables"] = [{"observable_id": "victim", "type": "ipv4", "value": "10.0.0.7", "roles": ["source-ip"], "evidence": []}]
    value = pcap_story.build_pack(row, session)
    text = story.canonical(value)
    assert value["pcap_ioc_allowlist"] == []
    assert value["coverage"]["source_characters"] <= pcap_story.MAX_EVIDENCE_CHARS
    assert "deferred-rate-limit" in text and "do not mean clean" in text
    assert "2020-04-23T23:15:43+00:00" in text


def test_staleness_changes_with_evidence_and_tlp_not_with_saved_summary():
    row, session = source()
    fingerprint = pcap_story.fingerprint(row, session)
    assert pcap_story.snapshot(row, session) is None
    session.source_provenance["pcap_investigation_summary"] = {"source_sha256": fingerprint}
    assert not pcap_story.snapshot(row, session)["stale"]
    session.source_provenance["pcap_enrichment"]["snapshot_sha256"] = "e"*64
    assert pcap_story.snapshot(row, session)["stale"]
    session.source_provenance["pcap_enrichment"]["snapshot_sha256"] = "d"*64
    session.tlp = "TLP:RED"
    assert pcap_story.snapshot(row, session)["stale"]


def test_compact_projection_has_explicit_budget_and_keeps_material_transfer():
    row, session = source()
    row.result["artifacts"] = [{"artifact_id": "payload", "sha256": "f"*64, "filename": "payload.png",
        "static_features": {"content_kind": "pe"}, "transfers": [{"client_ip": "10.0.0.7",
        "url": "https://example.invalid/payload.png", "match_basis": "exact-sha256-of-decoded-http-response-body"}]}]
    row.result["observables"] = [{"observable_id": "file", "type": "sha256", "value": "f"*64, "roles": ["exported-object"]}]
    value = pcap_story.build_pack(row, session, compact=True)
    assert value["coverage"]["compact_evidence"] is True
    assert value["coverage"]["source_characters"] <= 10_000
    assert value["required_narrative_evidence_ids"]


def test_executable_cannot_be_crowded_out_by_routine_scripts():
    row, session = source()
    row.result["artifacts"] = [{"artifact_id": str(i), "sha256": str(i).zfill(64), "filename": "routine.js", "static_features": {"content_kind": "script-like-text"}} for i in range(20)]
    row.result["artifacts"].append({"artifact_id": "payload", "sha256": "f"*64, "filename": "payload.png", "static_features": {"content_kind": "pe"},
        "transfers": [{"client_ip": "10.0.0.7", "url": "https://example.invalid/payload.png", "match_basis": "exact-sha256-of-decoded-http-response-body"}]})
    row.result["observables"] = [{"observable_id": "file", "type": "sha256", "value": "f"*64, "roles": ["exported-object"]}]
    value = pcap_story.build_pack(row, session)
    assert ("sha256", "f"*64) in value["pcap_ioc_allowlist"]
    assert value["required_narrative_evidence_ids"]
    transfer = next(s for s in value["sources"] if "#artifact/payload" in s["reference"])
    assert json.loads(transfer["text"])["content_kind"] == "pe"
    evidence = {**pack(), "required_narrative_evidence_ids": ["S0002"]}
    with pytest.raises(ValueError, match="required high-value"):
        pcap_story.validate(json.dumps(valid()), evidence)


def test_concise_limits_apply_in_addition_to_identifier_and_quote_checks():
    value = valid()
    assert pcap_story.validate(json.dumps(value), pack())
    value["what_happened"][0]["text"] = "word "*131
    with pytest.raises(ValueError, match="130"):
        pcap_story.validate(json.dumps(value), pack())
    value = valid()
    value["identities"] *= 4
    with pytest.raises(ValueError, match="section limit"):
        pcap_story.validate(json.dumps(value), pack())
    value = valid()
    value["what_happened"][0]["text"] = "word "*100
    value["uncertainties"] *= 2
    for c in value["uncertainties"]:
        c["text"] = "word "*120
    with pytest.raises(ValueError, match="320"):
        pcap_story.validate(json.dumps(value), pack())


def test_missing_optional_sections_do_not_invent_claims_or_relax_core():
    value = valid()
    for section in ("identities", "iocs", "ttps", "next_steps"):
        value.pop(section)
    adjustments = []
    result = pcap_story.validate_model_draft(json.dumps(value), pack(), adjustments)
    assert result["iocs"] == [] and result["ttps"] == []
    value["iocs"] = [{"text": "Incomplete optional item", "evidence": []}]
    result = pcap_story.validate_model_draft(json.dumps(value), pack(), adjustments)
    assert result["iocs"] == [] and adjustments[0]["action"] == "optional-claim-omitted"
    value.pop("what_happened")
    with pytest.raises(ValueError):
        pcap_story.validate_model_draft(json.dumps(value), pack(), [])


def test_source_id_alias_only_binds_an_entire_single_passage():
    evidence = pack()
    _, bindings = story.cited_passages(evidence)
    assert bindings['S0001'] == bindings['S0001.1']
    long_source = {**evidence['sources'][0], 'text': 'a' * 700}
    _, bindings = story.cited_passages({**evidence, 'sources': [long_source]})
    assert 'S0001' not in bindings


def test_unknown_optional_citation_is_withheld_but_core_never_is():
    _, bindings = story.cited_passages(pack())
    value = valid()
    for claims in value.values():
        for claim in claims:
            claim['evidence'] = [{'source_id': 'S0001.1'}]
    value['identities'][0]['evidence'] = [{'source_id': 'invented'}]
    omitted = []
    bound = json.loads(story.bind_passages(json.dumps(value), bindings, optional_omissions=omitted))
    assert bound['identities'] == []
    assert omitted[0]['reason'] == 'unknown_source'
    with pytest.raises(ValueError, match='Unknown'):
        story.bind_passages(json.dumps(value), bindings)
    value['what_happened'][0]['evidence'] = [{'source_id': 'invented'}]
    with pytest.raises(ValueError, match='Unknown'):
        story.bind_passages(json.dumps(value), bindings, optional_omissions=[])


@pytest.mark.asyncio
async def test_returned_model_is_recorded_separately_and_short_renderer_used(monkeypatch):
    row, session = source()
    evidence = {**pack(), "report_id": "pcap-fixture", "source_sha256": pcap_story.fingerprint(row, session),
        "coverage": {}, "effective_tlp": "TLP:CLEAR"}
    monkeypatch.setattr(pcap_story, "build_pack", lambda *args: evidence)
    wire = copy.deepcopy(valid())
    for claims in wire.values():
        for claim in claims:
            claim["evidence"] = [{"source_id": "S0001.1"}]
    adapter = SimpleNamespace(provider="fixture", model="requested-alias", story_response_model="returned-snapshot",
        story_usage={"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}, _raw_complete=AsyncMock(return_value=json.dumps(wire)))
    result = await pcap_story.generate(row, session, adapter)
    assert result["requested_model"] == "requested-alias"
    assert result["model"] == result["provider_returned_model"] == "returned-snapshot"
    assert result["word_count"] <= 320 and result["token_usage"]["total_tokens"] == 150
    assert result["prompt_version"] == pcap_story.PROMPT_VERSION
    assert "Evidence references" not in result["content"] and "Generation record" not in result["content"]
    assert result["structured"]["what_happened"][0]["evidence"][0]["quote"]
    assert adapter.story_citation_ids == ["S0001", "S0001.1"]


@pytest.mark.asyncio
async def test_openai_wire_citations_use_server_bindings_not_source_schema():
    from app.services.ai.openai import OpenAIAdapter
    adapter = object.__new__(OpenAIAdapter)
    adapter.story_citation_ids = ["S0001.1", "S0002.1"]
    adapter.story_ioc_allowlist = []
    adapter.story_identity_allowlist = ["DESKTOP-TEST", "10.0.0.7"]
    adapter.story_technique_allowlist = []
    await adapter.prepare_investigation_story("system", '{"output_schema":{"fake":true}}')
    schema = adapter._story_response_format["json_schema"]["schema"]
    assert schema["$defs"]["Citation"]["properties"]["source_id"]["enum"] == adapter.story_citation_ids
    assert "fake" not in schema
    assert schema["properties"]["iocs"]["maxItems"] == 0
    assert schema["$defs"]["Identity"]["properties"]["value"]["enum"] == ["10.0.0.7", "DESKTOP-TEST"]
    assert schema["properties"]["ttps"]["maxItems"] == 0
    adapter.story_ioc_allowlist = [("sha256", "a"*64)]
    await adapter.prepare_investigation_story("system", "untrusted")
    assert adapter._story_response_format["json_schema"]["schema"]["$defs"]["Indicator"]["properties"]["value"]["enum"] == ["a"*64]


def test_repair_diagnostics_are_bounded_server_derived_hints():
    projected, bindings = story.cited_passages(pack())
    value = valid()
    value["what_happened"][0].update(text="Host 10.0.0.7 contacted an invented peer 198.51.100.9.", evidence=[])
    value["identities"][0]["evidence"] = None
    hints = story.repair_diagnostics(json.dumps(value), bindings, pack())
    assert any(set(i.get("matching_citation_ids", [])) == {"S0001.1", "S0001"} for i in hints["issues"])
    assert "198.51.100.9" not in json.dumps(hints)
    assert "unsupported identifier; remove it" in json.dumps(hints)


def test_optional_unsupported_claims_are_omitted_with_audit_not_promoted():
    value = valid(); value["identities"][0]["value"] = "INVENTED-HOST"
    value["what_happened"][0]["basis"] = "observed"
    adjustments = []
    checked = pcap_story.validate_model_draft(json.dumps(value), pack(), adjustments)
    assert checked["identities"] == []
    assert checked["what_happened"][0]["basis"] == "reported"
    assert checked["what_happened"][0]["text"] == value["what_happened"][0]["text"]
    assert {a["action"] for a in adjustments} == {"evidence-level-downgrade", "optional-claim-omitted"}
    value["what_happened"][0]["text"] = "The host contacted an invented address 198.51.100.9."
    with pytest.raises(ValueError, match="uncited"):
        pcap_story.validate_model_draft(json.dumps(value), pack(), adjustments)
