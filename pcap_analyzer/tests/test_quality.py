import base64
import hashlib
from pathlib import Path

import pytest

from pcap_analyzer import app as a


def event(frame=1, **extra):
    return {"frame_number": frame, "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "tcp_stream": 0,
            "timestamp_epoch": str(frame), "fields": {}, **extra}


def test_body_projection_redacts_secrets_and_separates_directory_subjects():
    body = b"Host Name . . . : WORKSTATION\r\nUser name              alice\r\nUsername: bob Username: guest \r\nPassword: TOP-SECRET\r\n"
    features = a._body_features(body)
    assert features["credential_record_present"]
    assert "TOP-SECRET" not in str(features)
    e = event(body_features=features)
    identities = {i["value"]: i for i in a._build_identities("a"*64, {"http_request": [e]})}
    assert identities["alice"]["ip_addresses"] == ["10.0.0.1"]
    assert identities["bob"]["ip_addresses"] == []
    assert identities["WORKSTATION"]["bindings"][0]["relationship"] == "body-asserted-not-authenticated"


def test_body_password_marker_without_value_is_not_credential_record():
    assert not a._body_features(b'Content-Disposition: name="source"\r\n\r\nOutlook passwords')["credential_record_present"]


def test_http_body_is_hashed_not_copied_and_flags_have_frame_evidence():
    body = b"password=private-fixture"
    e = a._normalize_event("a"*64, "http_request", 0, {"frame.number": "5", "http.file_data": body.hex(), "ip.src": "10.0.0.1", "ip.dst": "8.8.8.8"})
    assert e["body_sha256"] == hashlib.sha256(body).hexdigest()
    assert "http.file_data" not in e["fields"] and "private-fixture" not in str(e)
    f = a._additional_findings("a"*64, {"http_request": [e]}, [])
    assert f[0]["rule_id"] == "sensitive-data-in-cleartext" and f[0]["evidence"][0]["frame_number"] == 5


def test_contiguous_reassembly_handles_reorder_duplicates_and_gaps():
    segments = [(4, b"def", event(2)), (1, b"abc", event(1)), (2, b"bcde", event(3)), (10, b"tail", event(4))]
    runs = a._contiguous_runs(segments)
    assert [(r[0], r[1]) for r in runs] == [(1, b"abcdef"), (10, b"tail")]
    with pytest.raises(a.AnalyzerLimitError, match="Conflicting"):
        a._contiguous_runs([(1, b"abcd", event()), (3, b"XX", event(2))])


def test_embedded_file_is_inert_exact_hash_and_parent_bound(tmp_path, monkeypatch):
    monkeypatch.setattr(a, "_run_fields", lambda *args: ([], False))
    directory = tmp_path / "http-objects"; directory.mkdir()
    payload = bytes.fromhex("d0cf11e0a1b11ae1") + b"fixture" * 100
    parent = b"<script>var x='" + base64.b64encode(payload) + b"';</script>"
    (directory / "page.html").write_bytes(parent)
    source = {"sha256": hashlib.sha256(parent).hexdigest(), "evidence": [{"frame_number": 10}], "transfers": []}
    objects, warnings = a._supplemental_objects(tmp_path, Path("unused"), "a"*64, {}, [source])
    assert not warnings and len(objects) == 1
    assert objects[0]["sha256"] == hashlib.sha256(payload).hexdigest()
    assert objects[0]["parent_sha256"] == source["sha256"]
    assert objects[0]["static_features"]["content_kind"] == "ole-document"
    assert objects[0]["evidence"] == source["evidence"]


def test_combined_pass_preserves_per_kind_budget_and_excludes_smtp_from_unknown(tmp_path, monkeypatch):
    rows = [{"frame.number": str(n), "frame.protocols": "eth:ip:tcp:smtp:data", "tcp.len": "100", "smtp.req.command": "DATA"} for n in range(3)]
    monkeypatch.setattr(a, "_run_fields", lambda *args: (rows, False))
    monkeypatch.setattr(a, "MAX_EVENTS_PER_KIND", 2)
    result = a._run_event_fields(tmp_path, Path("unused"))
    assert len(result["smtp"][0]) == 2 and result["smtp"][1]
    assert result["unclassified_tcp"] == ([], False)


def test_port_fanout_is_not_successful_lateral_movement_or_mail_delivery():
    flows = [{"transport": "tcp", "initiator_ip": "10.0.0.1", "responder_ip": f"10.0.1.{i}", "responder_port": 445,
              "first_frame": i, "stream": i, "first_seen_epoch": str(i)} for i in range(1, 25)]
    finding = a._additional_findings("a"*64, {}, flows)[0]
    assert finding["metrics"]["peer_count"] == 24
    assert "do not establish successful" in finding["explanation"]


def test_cleartext_http_rule_preserves_reverse_direction_on_source_port_443():
    request = event(src_ip="8.8.8.8", dst_ip="10.0.0.1", src_port=443, dst_port=51000,
                    fields={"http.request.method": "GET", "http.request.uri": "/"})
    findings = a._build_findings("a" * 64, {"http_request": [request]})
    finding = next(f for f in findings if f["rule_id"] == "http-on-tls-port")
    assert finding["metrics"]["source"] == "8.8.8.8"
    assert finding["metrics"]["destination"] == "10.0.0.1"


def test_raw_fallback_rejects_truncation_and_recovers_complete_bytes(tmp_path, monkeypatch):
    def rows(data):
        return [{"frame.number": "2", "ip.src": "8.8.8.8", "ip.dst": "10.0.0.1", "tcp.srcport": "80", "tcp.dstport": "50000", "tcp.stream": "0", "tcp.seq": "1", "tcp.payload": data.hex()}]
    requests = {"http_request": [event(fields={"http.request.method": "GET", "http.request.full_uri": "http://fixture.invalid/a"})]}
    monkeypatch.setattr(a, "_run_fields", lambda *args: (rows(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabc"), False))
    assert a._supplemental_objects(tmp_path, Path("unused"), "a"*64, requests, [])[0] == []
    monkeypatch.setattr(a, "_run_fields", lambda *args: (rows(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcd"), False))
    item = a._supplemental_objects(tmp_path, Path("unused"), "a"*64, requests, [])[0][0]
    assert item["sha256"] == hashlib.sha256(b"abcd").hexdigest()
    assert item["transfers"][0]["request_frame"] == 1
