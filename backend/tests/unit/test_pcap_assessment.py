import copy

import pytest

from app.services.pcap_assessment import assess, disclosure_allowed, provider_signal, review_candidates
from app.services.pcap_reputation import enrich_capture, select_targets


def observation(kind, value, identity="o1", **extra):
    return {"observable_id": identity, "type": kind, "value": value, "roles": [], "evidence": [], **extra}


@pytest.mark.parametrize("kind,value", [
    ("ipv4", "10.0.0.1"), ("ipv4", "127.0.0.1"), ("ipv4", "169.254.169.254"), ("ipv4", "100.64.0.1"),
    ("ipv4", "192.0.2.1"), ("ipv4", "224.0.0.1"), ("ipv6", "::1"), ("ipv6", "ff02::1"),
    ("domain", "secret.local"), ("domain", "foo.example.com"), ("domain", "x.onion"), ("domain", "foo.invalid"),
    ("domain", "user@public.com"), ("domain", "localhost"), ("url", "https://public.com/?token=secret"), ("sha256", "z"*64),
])
def test_private_and_sensitive_targets_blocked(kind, value):
    assert not disclosure_allowed(kind, value)
    with pytest.raises(ValueError):
        select_targets({"observables": [observation(kind, value)]}, ["o1"])


def test_unusual_file_extension_and_public_ip_are_not_iocs():
    result = {"observables": [observation("ipv4", "8.8.8.8"), observation("sha256", "a"*64, "file")],
              "artifacts": [{"artifact_id": "a1", "sha256": "a"*64, "filename": "setup.exe", "static_features": {"content_kind": "pe"}}]}
    original = copy.deepcopy(result)
    assessment = assess(result)
    assert assessment["ioc_candidate_count"] == 0
    assert review_candidates(assessment) == []
    assert result == original


def test_remote_http_peer_is_candidate_but_resolver_and_victim_are_not():
    result = {
        "observables": [observation("ipv4", "8.8.8.8"), observation("ipv4", "9.9.9.9", "remote"), observation("ipv4", "10.0.0.5", "victim"), observation("domain", "callback.net", "host")],
        "events": {"http_request": [{"frame_number": 3, "src_ip": "10.0.0.5", "dst_ip": "9.9.9.9", "fields": {"http.host": "callback.net"}}]},
        "findings": [{"finding_id": "f1", "rule_id": "periodic-http-callbacks", "evidence": [{"frame_number": 3}]}],
    }
    rows = {r["observable_id"]: r for r in assess(result)["items"]}
    assert rows["remote"]["ioc_candidate"] and rows["host"]["ioc_candidate"]
    assert rows["remote"]["reasons"][0]["frame_number"] == 3
    assert not rows["o1"]["ioc_candidate"] and not rows["victim"]["ioc_candidate"]
    result["findings"][0]["rule_id"] = "script-or-executable-transfer"
    assert assess(result)["ioc_candidate_count"] == 0


@pytest.mark.parametrize("status", ["not_found", "not_configured", "error", "skipped", "not-attempted-budget"])
def test_missing_or_failed_provider_never_means_benign(status):
    signal = provider_signal("sha256", "a"*64, {"source": "virustotal", "status": status})
    assert signal["verdict"] == "unknown"


def test_direct_vt_stats_not_related_text_or_search_totals():
    raw = {"indicator": "9.9.9.9", "last_analysis_stats": {"malicious": 2, "harmless": 50}, "last_analysis_date": 123}
    response = {"source": "virustotal", "status": "ok", "raw": raw}
    assert provider_signal("ipv4", "9.9.9.9", response)["verdict"] == "provider-reported-malicious"
    assert provider_signal("ipv4", "8.8.8.8", response)["verdict"] == "unknown"
    raw["last_analysis_stats"] = {"malicious": 0, "undetected": 50}
    raw["related"] = {"last_analysis_stats": {"malicious": 80}, "name": "ransomware C2"}
    assert provider_signal("ipv4", "9.9.9.9", response)["verdict"] == "no-detections"


def test_exact_bazaar_hash_only_and_no_transitive_verdict():
    response = {"source": "malwarebazaar", "status": "ok", "raw": {"data": [{"sha256_hash": "a"*64, "signature": "Example"}]}}
    signal = provider_signal("sha256", "a"*64, response)
    assert signal["verdict"] == "provider-reported-malicious"
    assert provider_signal("sha256", "b"*64, response)["verdict"] == "unknown"
    result = {"observables": [observation("sha256", "a"*64), observation("ipv4", "9.9.9.9", "host")]}
    enriched = {"items": [{"type": "sha256", "value": "a"*64, "signals": [signal]}]}
    rows = assess(result, enrichment=enriched)["items"]
    assert rows[0]["classification"] == "provider-reported-malicious"
    assert rows[1]["classification"] == "observed"


def test_threatfox_substring_and_ip_port_do_not_become_exact_ip_match():
    response = {"source": "threatfox", "status": "ok", "raw": {"data": [{"ioc": "9.9.9.9:443", "ioc_type": "ip:port"}]}}
    assert provider_signal("ipv4", "9.9.9.9", response)["verdict"] == "unknown"


def test_url_case_preserved_and_local_intel_not_confirmed():
    result = {"observables": [observation("url", "https://site.net/A"), observation("url", "https://site.net/a", "other")]}
    context = {"matches": [{"type": "url", "value": "https://site.net/A", "indicator_id": 1}]}
    rows = assess(result, context)["items"]
    assert rows[0]["classification"] == "intelligence-match"
    assert rows[1]["classification"] == "observed"


def test_unknown_target_and_oversized_batch_fail_before_queries():
    with pytest.raises(ValueError):
        select_targets({"observables": []}, ["missing"])
    with pytest.raises(ValueError):
        select_targets({"observables": []}, [str(i) for i in range(11)])


@pytest.mark.asyncio
async def test_reputation_reuses_passive_adapter_retains_timestamps_and_bounds_types(monkeypatch):
    calls = []
    async def fake(db, artifact, *, sources, options):
        calls.append((artifact, sources))
        assert options.depth == 1 and not options.ai_summarize
        return [{"source": sources[0], "status": "not_found", "raw": {}}]
    monkeypatch.setattr("app.services.pcap_reputation.enrich_ioc_sources", fake)
    result = {"semantic_sha256": "b"*64, "observables": [observation("sha256", "a"*64)]}
    snapshot = await enrich_capture(None, result, observable_ids=["o1"], providers=["virustotal", "abuseipdb"])
    assert calls == [("a"*64, ["virustotal"])]
    assert snapshot["coverage"]["payload_uploads"] == 0
    assert all(s["queried_at"] for s in snapshot["items"][0]["signals"])
    assert assess(result, enrichment=snapshot)["ioc_candidate_count"] == 0
    again = await enrich_capture(None, result, observable_ids=["o1"], providers=["threatfox"], previous=snapshot)
    assert len(again["items"][0]["signals"]) == 3
    assert again["previous_snapshot_sha256"] == snapshot["snapshot_sha256"]


@pytest.mark.asyncio
async def test_timeout_is_unknown_and_budget_exhaustion_explicit(monkeypatch):
    async def timeout(*args, **kwargs):
        raise TimeoutError()
    monkeypatch.setattr("app.services.pcap_reputation.enrich_ioc_sources", timeout)
    result = {"semantic_sha256": "b"*64, "observables": [observation("sha256", "a"*64)]}
    snapshot = await enrich_capture(None, result, observable_ids=["o1"], providers=["virustotal"])
    signal = snapshot["items"][0]["signals"][0]
    assert signal["verdict"] == "unknown" and signal["error_category"] == "timeout"
    monkeypatch.setattr("app.services.pcap_reputation.BATCH_TIMEOUT_SECONDS", 0)
    snapshot = await enrich_capture(None, result, observable_ids=["o1"], providers=["virustotal"])
    assert snapshot["items"][0]["signals"][0]["status"] == "not-attempted-budget"
    assert snapshot["coverage"]["provider_lookups_started"] == 0


@pytest.mark.asyncio
async def test_rate_limit_stops_further_lookups_for_that_provider(monkeypatch):
    calls = []
    async def limited(db, value, **kwargs):
        calls.append(value)
        return [{"source": "virustotal", "status": "error", "error_category": "rate_limited"}]
    monkeypatch.setattr("app.services.pcap_reputation.enrich_ioc_sources", limited)
    result = {"semantic_sha256": "a"*64, "observables": [observation("sha256", "a"*64), observation("sha256", "b"*64, "o2")]}
    snapshot = await enrich_capture(None, result, observable_ids=["o1", "o2"], providers=["virustotal"])
    assert len(calls) == 1
    assert snapshot["items"][0]["signals"][0]["status"] == "deferred-rate-limit"
    assert assess(result, enrichment=snapshot)["ioc_candidate_count"] == 0


def test_verbose_registry_result_retains_typed_hash_evidence():
    from app.services.ioc_investigation import _registry_evidence
    payload = {"query_status": "ok", "data": [{"sha256_hash": "a"*64, "signature": "Example", "verbose": "x"*5000}]}
    compact = _registry_evidence(payload)
    assert isinstance(compact["data"], list) and compact["data"][0]["sha256_hash"] == "a"*64
    assert "verbose" not in compact["data"][0]
    assert provider_signal("sha256", "a"*64, {"source": "malwarebazaar", "status": "ok", "raw": compact})["verdict"] == "provider-reported-malicious"
