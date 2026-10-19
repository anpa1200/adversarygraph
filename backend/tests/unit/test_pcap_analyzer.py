from __future__ import annotations

import hashlib
import io

import pytest

from app.services.pcap_analyzer import (
    PcapAnalyzerError,
    analysis_key,
    canonical_json,
    render_report,
    retain_capture,
    validate_capture_magic,
    validate_result,
)


def _result() -> dict:
    manifest = {
        "schema_version": "pcap-analyzer-manifest-v1",
        "profile_id": "test-profile",
        "rulepack_version": "test-rules-v1",
    }
    manifest["manifest_sha256"] = hashlib.sha256(canonical_json(manifest).encode()).hexdigest()
    payload = {
        "schema_version": "pcap-analysis-v1",
        "analyzer_manifest": manifest,
        "capture": {
            "source_sha256": "b" * 64,
            "packet_count": 7,
            "duration_seconds": 2.5,
            "captured_bytes": 900,
        },
        "endpoints": [],
        "flows": [],
        "identities": [],
        "artifacts": [],
        "observables": [{"type": "ipv4", "value": "198.51.100.7", "roles": ["remote"]}],
        "findings": [{
            "rule_id": "test-rule",
            "rule_version": "1",
            "severity": "high",
            "title": "Test behavior",
            "explanation": "A deterministic test finding.",
            "confidence": 0.9,
            "metrics": {"count": 1},
            "evidence": [{"frame_number": 7, "tcp_stream": 2}],
        }],
        "attack_candidates": [{
            "attack_id": "T1071.001",
            "name": "Web Protocols",
            "tactic": "command-and-control",
            "confidence": 0.8,
            "status": "suggested",
            "mapping_basis": "test-rule",
        }],
        "coverage": {"warnings": []},
        "summary": "One deterministic behavior was found.",
    }
    payload["semantic_sha256"] = hashlib.sha256(canonical_json(payload).encode()).hexdigest()
    return payload


def test_analysis_key_binds_capture_and_manifest() -> None:
    first = analysis_key("1" * 64, "2" * 64)
    assert first == analysis_key("1" * 64, "2" * 64)
    assert first != analysis_key("3" * 64, "2" * 64)
    assert first != analysis_key("1" * 64, "4" * 64)


@pytest.mark.parametrize("magic", [
    bytes.fromhex("d4c3b2a1"),
    bytes.fromhex("a1b2c3d4"),
    bytes.fromhex("4d3cb2a1"),
    bytes.fromhex("a1b23c4d"),
    bytes.fromhex("0a0d0d0a"),
])
def test_validate_capture_magic_accepts_pcap_variants(magic: bytes) -> None:
    handle = io.BytesIO(magic + b"\x00" * 20)
    handle.seek(8)
    validate_capture_magic(handle)
    assert handle.tell() == 8


def test_validate_capture_magic_rejects_non_capture() -> None:
    with pytest.raises(PcapAnalyzerError, match="recognized PCAP"):
        validate_capture_magic(io.BytesIO(b"not-a-capture"))


def test_retain_capture_atomically_replaces_same_digest(tmp_path) -> None:
    destination = tmp_path / "capture.pcap"
    retain_capture(io.BytesIO(b"first"), destination)
    retain_capture(io.BytesIO(b"second"), destination)

    assert destination.read_bytes() == b"second"
    assert list(tmp_path.glob("*.partial")) == []


def test_validate_result_detects_semantic_tampering() -> None:
    payload = _result()
    validate_result(payload)
    payload["summary"] = "changed after signing"
    with pytest.raises(PcapAnalyzerError, match="checksum mismatch"):
        validate_result(payload)


def test_report_preserves_evidence_and_attribution_boundary() -> None:
    report = render_report("sample.pcap", _result(), [{
        "group_name": "Example Group",
        "group_attack_id": "G0001",
        "similarity": 0.5,
    }])
    assert "frame 7 / TCP stream 2" in report
    assert "T1071.001 Web Protocols" in report
    assert "investigation lead, not attribution" in report
    assert "Packet and protocol facts are deterministic" in report
