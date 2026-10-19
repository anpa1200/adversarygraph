from __future__ import annotations

import hashlib

from pcap_analyzer.app import _build_findings, _sha256_json


def _request(frame: int, timestamp: float, *, user_agent: str = "NetSupport Manager/1.3") -> dict:
    return {
        "id": f"request-{frame}",
        "frame_number": frame,
        "timestamp_epoch": str(timestamp),
        "src_ip": "10.0.0.5",
        "dst_ip": "198.51.100.9",
        "dst_port": 443,
        "tcp_stream": frame,
        "fields": {
            "http.request.method": "POST",
            "http.host": "198.51.100.9",
            "http.request.uri": "/status",
            "http.user_agent": user_agent,
            "http.content_length": "1200000",
        },
    }


def test_findings_aggregate_packet_evidence_by_behavior() -> None:
    requests = [_request(index, float(index * 60)) for index in range(1, 7)]
    findings = _build_findings("f" * 64, {
        "http_request": requests,
        "dns": [],
        "http_response": [],
        "tls_client_hello": [],
        "dhcp": [],
        "identity": [],
    })
    rule_ids = [item["rule_id"] for item in findings]
    assert len(rule_ids) == len(set(rule_ids))
    assert {
        "http-on-tls-port",
        "periodic-http-callbacks",
        "remote-access-user-agent",
        "repeated-http-posts",
        "large-http-post",
    }.issubset(rule_ids)
    assert all(len(item["evidence"]) <= 20 for item in findings)


def test_distributed_periodic_posts_aggregate_rotating_targets() -> None:
    requests = [_request(index, float(index * 30), user_agent="") for index in range(1, 13)]
    for index, event in enumerate(requests):
        event["dst_port"] = 80
        event["dst_ip"] = f"198.51.100.{10 + index % 3}"
        event["fields"]["http.host"] = f"fallback-{index % 3}.example"
        event["fields"]["http.request.uri"] = f"/{index:02d}/rotating"
        event["fields"]["http.content_length"] = "100000"
    findings = _build_findings("d" * 64, {"http_request": requests, "http_response": []})
    distributed = next(item for item in findings if item["rule_id"] == "distributed-periodic-http-posts")
    high_volume = next(item for item in findings if item["rule_id"] == "high-volume-http-posts")
    assert distributed["metrics"]["request_count"] == 12
    assert distributed["metrics"]["destination_count"] == 3
    assert distributed["metrics"]["median_interval_seconds"] == 30.0
    assert high_volume["metrics"]["declared_body_bytes"] == 1_200_000


def test_cleartext_fingerprint_and_powershell_rules_are_evidence_bound() -> None:
    fingerprint = _request(20, 1200, user_agent="Mozilla/5.0")
    fingerprint["dst_port"] = 80
    fingerprint["fields"].update({
        "http.request.uri": "/api/set_agent?id=abc&token=0123456789abcdef&act=log",
        "http.host": "fingerprint.example",
        "http.content_length": "8023",
    })
    powershell = _request(21, 1230, user_agent="WindowsPowerShell/5.1")
    powershell["dst_port"] = 80
    powershell["fields"]["http.request.method"] = "GET"
    findings = _build_findings("e" * 64, {
        "http_request": [fingerprint, powershell],
        "http_response": [],
    })
    by_rule = {item["rule_id"]: item for item in findings}
    assert by_rule["cleartext-tokenized-api"]["evidence"][0]["frame_number"] == 20
    assert by_rule["browser-fingerprint-upload"]["metrics"]["declared_body_bytes"] == 8023
    assert by_rule["powershell-http-client"]["confidence"] == 0.94


def test_semantic_hash_is_key_order_independent() -> None:
    assert _sha256_json({"a": 1, "b": 2}) == _sha256_json({"b": 2, "a": 1})
    assert _sha256_json({"a": 1}) == hashlib.sha256(b'{"a":1}').hexdigest()
