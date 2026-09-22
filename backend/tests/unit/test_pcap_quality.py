from unittest.mock import AsyncMock

import httpx
import pytest

from app.services.pcap_assessment import assess
from app.services.pcap_reputation import enrich_capture
from app.services.ioc_investigation import _safe_source


def capture():
    return {"semantic_sha256": "a"*64, "observables": [
        {"observable_id": "ip", "type": "ipv4", "value": "8.8.8.8", "roles": []},
        {"observable_id": "sni", "type": "domain", "value": "investigate.net", "roles": []}],
        "events": {"tls_client_hello": [{"frame_number": 4, "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "fields": {"tls.handshake.extensions_server_name": "investigate.net"}}]},
        "findings": [{"rule_id": "multi-host-tls-cadence", "evidence": [{"frame_number": 4}]}]}


def test_tls_cadence_is_enrichment_lead_not_ioc_verdict():
    assessment = assess(capture())
    assert assessment["ioc_candidate_count"] == 0
    assert assessment["enrichment_plan"]["next_batch"] == ["sni", "ip"]
    assert assessment["enrichment_plan"]["items"][0]["priority"] == 46


def test_reverse_http_and_ipv6_use_remote_peer_not_victim():
    data = capture()
    data["observables"].append({"observable_id": "v6", "type": "ipv6", "value": "2606:4700:4700::1111", "roles": []})
    data["events"] = {"http_request": [{"frame_number": 4, "src_ip": "2606:4700:4700::1111", "dst_ip": "10.0.0.1", "fields": {}}]}
    data["findings"][0]["rule_id"] = "http-on-tls-port"
    rows = {r["observable_id"]: r for r in assess(data)["items"]}
    assert rows["v6"]["ioc_candidate"] and not rows["ip"]["ioc_candidate"]


def test_single_engine_network_warning_is_context_not_capture_ioc():
    data = capture()
    enrichment = {"items": [{"type": "domain", "value": "investigate.net", "signals": [
        {"source": "virustotal", "verdict": "provider-reported-malicious", "status": "ok",
         "evidence": {"last_analysis_stats": {"malicious": 1, "harmless": 80}}}]}]}
    row = next(r for r in assess(data, enrichment=enrichment)["items"] if r["type"] == "domain")
    assert row["classification"] == "provider-reported-malicious" and not row["ioc_candidate"]
    assert "Weak reputation" in row["ioc_selection_note"]
    assert "including 0 with direct malicious provider reports" in assess(data, enrichment=enrichment)["summary"]


def test_one_provider_not_found_does_not_hide_another_provider_rate_limit():
    enrichment = {"items": [{"type": "domain", "value": "investigate.net", "signals": [
        {"source": "threatfox", "status": "not_found", "verdict": "unknown"},
        {"source": "virustotal", "status": "deferred-rate-limit", "verdict": "unknown", "retry_at": "2999-01-01T00:00:00+00:00"},
    ]}]}
    assessment = assess(capture(), enrichment=enrichment)
    row = next(r for r in assessment["items"] if r["type"] == "domain")
    plan = next(r for r in assessment["enrichment_plan"]["items"] if r["type"] == "domain")
    assert row["enrichment_status"] == "partial" and not plan["direct_checked"]
    assert plan["pending_providers"] == ["virustotal"] and not plan["queue_ready"]
    assert "sni" not in assessment["enrichment_plan"]["next_batch"]
    enrichment["items"][0]["signals"][1]["retry_at"] = "2000-01-01T00:00:00Z"
    assessment = assess(capture(), enrichment=enrichment)
    plan = next(r for r in assessment["enrichment_plan"]["items"] if r["type"] == "domain")
    assert plan["retryable_providers"] == ["virustotal"] and plan["queue_ready"]
    assert "sni" in assessment["enrichment_plan"]["next_batch"]
    # A retry without configured credentials is not an automatic queue loop.
    enrichment["items"][0]["signals"][1].update(status="error", error_category="authentication")
    plan = next(r for r in assess(capture(), enrichment=enrichment)["enrichment_plan"]["items"] if r["type"] == "domain")
    assert not plan["queue_ready"] and not plan["direct_checked"]


@pytest.mark.asyncio
async def test_429_is_typed_and_retry_header_preserved_without_request_secrets():
    async def fail():
        response = httpx.Response(429, headers={"Retry-After": "90"}, request=httpx.Request("GET", "https://provider.invalid/?api_key=DO-NOT-PERSIST"))
        response.raise_for_status()
    result = await _safe_source("virustotal", fail)
    assert result["error_category"] == "rate_limited" and result["retry_after_seconds"] == 90
    assert "DO-NOT-PERSIST" not in str(result)


@pytest.mark.asyncio
async def test_optional_vt_429_preserves_successful_direct_verdict(monkeypatch):
    from app.services import virustotal as vt
    async def get(client, endpoint):
        if endpoint.endswith("behaviour_mitre_trees"):
            httpx.Response(429, headers={"Retry-After": "60"}, request=httpx.Request("GET", "https://fixture.invalid")).raise_for_status()
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 8}}}}
    monkeypatch.setattr(vt.settings, "virustotal_api_key", "test-only")
    monkeypatch.setattr(vt, "_vt_get", get)
    monkeypatch.setattr(vt, "_resolve_techniques", AsyncMock(return_value=[]))
    monkeypatch.setattr(vt, "_match_local_actors", AsyncMock(return_value=[]))
    result = await vt.lookup_virustotal_ioc(None, "a"*64)
    assert result["last_analysis_stats"]["malicious"] == 8
    assert result["behavior_coverage"]["http_status"] == 429


@pytest.mark.asyncio
async def test_exact_target_cache_keeps_original_query_time_and_no_new_lookup(monkeypatch):
    calls = []
    async def query(db, value, **kwargs):
        calls.append(value)
        return [{"source": "virustotal", "status": "ok", "raw": {"indicator": value, "last_analysis_stats": {"malicious": 1}}}]
    monkeypatch.setattr("app.services.pcap_reputation.enrich_ioc_sources", query)
    first = await enrich_capture(None, capture(), observable_ids=["ip"], providers=["virustotal"])
    second = await enrich_capture(None, capture(), observable_ids=["ip"], providers=["virustotal"])
    assert len(calls) == 1 and second["coverage"]["cache_hits"] == 1
    assert second["items"][0]["signals"][0]["queried_at"] == first["items"][0]["signals"][0]["queried_at"]


@pytest.mark.asyncio
async def test_cooldown_survives_next_batch_and_preserves_prior_answer(monkeypatch):
    calls = []
    async def query(db, value, **kwargs):
        calls.append(value)
        return [{"source": "virustotal", "status": "error", "error_category": "rate_limited", "retry_after_seconds": 90}]
    monkeypatch.setattr("app.services.pcap_reputation.enrich_ioc_sources", query)
    await enrich_capture(None, capture(), observable_ids=["ip"], providers=["virustotal"])
    previous = {"items": [{"observable_id": "sni", "type": "domain", "value": "investigate.net", "signals": [
        {"source": "virustotal", "status": "ok", "verdict": "provider-reported-malicious", "queried_at": "old-date"}]}]}
    second = await enrich_capture(None, capture(), observable_ids=["sni"], providers=["virustotal"], previous=previous)
    signal = second["items"][0]["signals"][0]
    assert len(calls) == 1 and signal["queried_at"] == "old-date"
    assert signal["latest_attempt"]["status"] == "deferred-rate-limit"


@pytest.mark.asyncio
async def test_story_rate_limit_keeps_only_numeric_quota_metadata():
    from types import SimpleNamespace
    from app.services.threat_hunting_ai import AIProviderCallError, complete
    class ProviderError(Exception):
        status_code = 429
        body = {"message": "Secret organization ID; Limit 30000, Requested 50000, Used 42", "code": "rate_limit_exceeded"}
    adapter = SimpleNamespace(provider="openai", _raw_complete=AsyncMock(side_effect=ProviderError()))
    with pytest.raises(AIProviderCallError) as exc:
        await complete(adapter, "system", "user")
    assert exc.value.rate_details == {"limit": 30000, "requested": 50000, "used": 42}
    assert "Secret" not in str(exc.value)


@pytest.mark.asyncio
async def test_openai_story_uses_native_strict_schema_and_scoped_output_budget():
    import json
    from types import SimpleNamespace
    from app.services.ai.openai import OpenAIAdapter
    adapter = object.__new__(OpenAIAdapter)
    await adapter.prepare_investigation_story("system", "untrusted content must not define schema")
    assert adapter._story_max_tokens == 4096
    wire = adapter._story_response_format
    assert wire["type"] == "json_schema" and wire["json_schema"]["strict"]
    assert wire["json_schema"]["schema"]["additionalProperties"] is False
    assert "what_happened" in wire["json_schema"]["schema"]["required"]
    assert set(wire["json_schema"]["schema"]["$defs"]["Citation"]["properties"]) == {"source_id"}
    assert wire["json_schema"]["schema"]["$defs"]["Claim"]["properties"]["text"]["pattern"] == "^[\\s\\S]{8,800}$"
    create = AsyncMock(return_value=SimpleNamespace(usage=None, choices=[SimpleNamespace(message=SimpleNamespace(content="{}"), finish_reason="stop")]))
    adapter._model = "gpt-4.1"
    adapter._api_client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    evidence = {"sources": [{"text": "Untrusted packet data: keep exactly."}]}
    await adapter._raw_complete("system", json.dumps({"output_schema": {"fixture": True}, "untrusted_evidence": evidence}))
    request = create.call_args.kwargs
    assert request["response_format"]["type"] == "json_schema" and request["max_tokens"] == 4096
    assert json.loads(request["messages"][1]["content"]) == {"untrusted_evidence": evidence}
