from __future__ import annotations

import hashlib

import pytest
from httpx import AsyncClient


PCAP = bytes.fromhex("d4c3b2a1") + b"\x00" * 20


def _analyzer_result() -> dict:
    source_sha256 = hashlib.sha256(PCAP).hexdigest()
    return {
        "schema_version": "pcap-analysis-v1",
        "semantic_sha256": "c" * 64,
        "analysis_key_material": {
            "source_sha256": source_sha256,
            "analyzer_manifest_sha256": "a" * 64,
            "rulepack_version": "test-rules-v1",
        },
        "analyzer_manifest": {"manifest_sha256": "a" * 64, "profile_id": "test-profile"},
        "capture": {
            "format": "pcap-le-microsecond",
            "source_sha256": source_sha256,
            "source_size_bytes": len(PCAP),
            "packet_count": 1,
            "duration_seconds": 0,
            "captured_bytes": 24,
            "first_packet_epoch": "1.0",
            "last_packet_epoch": "1.0",
            "interface_ids": [0],
            "encapsulation_types": [1],
            "protocol_counts": {"eth": 1},
        },
        "endpoints": [],
        "flows": [],
        "events": {},
        "identities": [],
        "artifacts": [],
        "observables": [{
            "observable_id": "observable-1",
            "type": "ipv4",
            "value": "8.8.8.8",
            "roles": ["remote"],
            "is_private": False,
            "first_seen_epoch": "1.0",
            "last_seen_epoch": "1.0",
            "evidence": [{"frame_number": 1, "timestamp_epoch": "1.0", "display_filter": "frame.number == 1"}],
            "enrichment_state": "not_requested",
        }],
        "findings": [{
            "rule_id": "periodic-http-callbacks",
            "rule_version": "1",
            "severity": "high",
            "title": "Periodic callbacks",
            "explanation": "Repeated callbacks have a stable interval.",
            "confidence": 0.9,
            "metrics": {"median_interval_seconds": 60},
            "evidence": [{"frame_number": 1, "tcp_stream": 0}],
        }],
        "attack_candidates": [{
            "attack_id": "T1071.001",
            "name": "Web Protocols",
            "tactic": "command-and-control",
            "confidence": 0.9,
            "status": "suggested",
            "mapping_basis": "periodic-http-callbacks",
            "finding_ids": ["finding-1"],
            "evidence": [{"frame_number": 1, "tcp_stream": 0}],
        }],
        "actor_leads": [],
        "coverage": {"warnings": []},
        "summary": "Periodic callback behavior was found.",
    }


@pytest.mark.asyncio
async def test_pcap_analysis_is_durable_and_retrievable(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    analyzer_calls = 0

    async def fake_manifest():
        return {"manifest_sha256": "a" * 64, "profile_id": "test-profile"}

    async def fake_analyze(_handle, _filename):
        nonlocal analyzer_calls
        analyzer_calls += 1
        return _analyzer_result()

    async def fake_validate(*_args, **_kwargs):
        return None

    async def fake_rank(*_args, **_kwargs):
        return []

    async def fake_review(*_args, **_kwargs):
        return None

    monkeypatch.setattr("app.api.routes.pcap.get_manifest", fake_manifest)
    monkeypatch.setattr("app.api.routes.pcap.analyze_capture", fake_analyze)
    monkeypatch.setattr("app.api.routes.pcap._validate_technique_ids", fake_validate)
    monkeypatch.setattr("app.api.routes.pcap._rank_apt_groups", fake_rank)
    monkeypatch.setattr("app.api.routes.pcap._start_review_with_preflight", fake_review)
    monkeypatch.setattr("app.api.routes.pcap.settings.pcap_retain_uploads", False)

    created = await client.post(
        "/api/pcap/analyze",
        files={"file": ("sample.pcap", PCAP, "application/vnd.tcpdump.pcap")},
    )
    assert created.status_code == 200, created.text
    payload = created.json()
    assert payload["status"] == "completed"
    assert payload["source_sha256"] == hashlib.sha256(PCAP).hexdigest()
    assert payload["result"]["findings"][0]["evidence"][0]["frame_number"] == 1
    assert payload["techniques"][0]["attack_id"] == "T1071.001"
    assert "not attribution" not in payload["report"]

    repeated = await client.post(
        "/api/pcap/analyze",
        files={"file": ("renamed-same-content.pcap", PCAP, "application/vnd.tcpdump.pcap")},
    )
    assert repeated.status_code == 200
    assert repeated.json()["analysis_id"] == payload["analysis_id"]
    assert analyzer_calls == 1

    intake = await client.get("/api/operations/intake")
    assert intake.status_code == 200
    pcap_intake = next(item for item in intake.json() if item["analysis_session_id"] == payload["session_id"])
    assert pcap_intake["actor_ids"] == []
    assert pcap_intake["technique_ids"] == ["T1071.001"]
    assert pcap_intake["indicators"][0]["value"] == "8.8.8.8"
    assert pcap_intake["provenance"]["source_sha256"] == hashlib.sha256(PCAP).hexdigest()

    fetched = await client.get(f"/api/pcap/analyses/{payload['analysis_id']}")
    assert fetched.status_code == 200
    assert fetched.json()["semantic_sha256"] == payload["semantic_sha256"]

    collection = await client.get("/api/pcap/analyses")
    assert collection.status_code == 200
    assert collection.json()["items"][0]["analysis_id"] == payload["analysis_id"]


@pytest.mark.asyncio
async def test_pcap_analysis_rejects_non_capture(client: AsyncClient) -> None:
    response = await client.post(
        "/api/pcap/analyze",
        files={"file": ("fake.pcap", b"not really a packet capture", "application/octet-stream")},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "File is not a recognized PCAP or PCAPNG capture"


@pytest.mark.asyncio
async def test_pcap_analysis_fails_explicitly_when_disabled(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("app.api.routes.pcap.settings.pcap_analyzer_enabled", False)
    response = await client.post(
        "/api/pcap/analyze",
        files={"file": ("sample.pcap", PCAP, "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 503
    assert response.json()["detail"] == "Deterministic PCAP analysis is disabled"
