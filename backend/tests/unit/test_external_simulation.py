from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading

from app.services.external_simulation import (
    WEB_SIMULATION_IDS,
    _redact_siem_destination,
    _validate_siem_destination,
    build_plan,
    forward_telemetry_logs,
    list_simulations,
    list_targets,
    run_controlled_record,
    tail_telemetry_logs,
)


def test_catalog_contains_safe_external_ttp_simulations():
    catalog = list_simulations()
    ids = {item["id"] for item in catalog}
    assert WEB_SIMULATION_IDS.issubset(ids)
    assert {
        "sim-t1190-traversal-canary",
        "sim-t1190-sqli-xss-canary",
        "sim-t1190-ssrf-canary",
        "sim-t1059-web-command-canary",
        "sim-t1505-webshell-canary",
        "sim-t1105-web-upload-download",
        "sim-t1110-web-login-failures",
        "sim-t1110-web-bruteforce",
        "sim-t1110-web-password-spray",
        "sim-t1589-web-user-enumeration",
        "sim-t1071-web-beacon",
        "sim-t1041-web-exfil-canary",
    }.issubset(ids)
    assert all(item["destructive"] is False for item in catalog)


def test_plan_allows_only_allowlisted_target_simulation_pair():
    plan = build_plan("sim-t1595-http-fingerprint", "lab-web-01")
    assert plan["allowed"] is True
    assert plan["target"]["environment"] == "lab"
    assert "target allowlist" in " ".join(plan["approval_checklist"]).lower()


def test_plan_blocks_mismatched_target_type():
    plan = build_plan("sim-t1110-lab-login-sequence", "lab-web-01")
    assert plan["allowed"] is False
    assert plan["block_reasons"]


def test_web_run_emits_only_local_lab_traffic_and_logs_telemetry():
    result = run_controlled_record("sim-t1595-http-fingerprint", "lab-web-01", "test")
    assert result["status"] == "completed_with_local_lab_telemetry"
    assert result["traffic_emitted"] is True
    assert result["validation_status"] == "not_proven"
    assert result["telemetry"]["server"]["url"] == "http://127.0.0.1:8765"
    assert result["telemetry"]["request_count"] == 2
    assert result["telemetry"]["success_count"] == 2
    assert Path(result["telemetry"]["log_file"]).exists()
    assert Path(result["telemetry"]["web_access_log_file"]).exists()
    web_logs = tail_telemetry_logs("web", run_id=result["run_id"], limit=10)
    run_logs = tail_telemetry_logs("run", run_id=result["run_id"], limit=10)
    assert web_logs["events"]
    assert run_logs["events"]
    assert all(item["run_id"] == result["run_id"] for item in web_logs["events"])


def test_all_web_attack_scenarios_are_allowlisted_for_lab_web_target():
    for simulation_id in WEB_SIMULATION_IDS:
        plan = build_plan(simulation_id, "lab-web-01")
        assert plan["allowed"] is True, simulation_id


def test_all_web_attack_scenarios_run_against_local_lab_fixture():
    for simulation_id in sorted(WEB_SIMULATION_IDS):
        result = run_controlled_record(simulation_id, "lab-web-01", "catalog smoke")
        assert result["status"] == "completed_with_local_lab_telemetry", simulation_id
        assert result["traffic_emitted"] is True
        assert result["telemetry"]["server"]["url"] == "http://127.0.0.1:8765"
        assert result["telemetry"]["request_count"] >= 1
        assert result["telemetry"]["success_count"] == result["telemetry"]["request_count"]
        assert all(event["url"].startswith("http://127.0.0.1:8765") for event in result["telemetry"]["events"])


def test_web_canary_run_records_body_metadata_and_canary_classification():
    result = run_controlled_record("sim-t1059-web-command-canary", "lab-web-01", "body telemetry")
    web_logs = tail_telemetry_logs("web", run_id=result["run_id"], limit=10)
    post_events = [event for event in web_logs["events"] if event["method"] == "POST"]

    assert post_events
    assert post_events[0]["clean_path"] == "/api/run"
    assert post_events[0]["body_length"] > 0
    assert post_events[0]["body_sha256"]
    assert "whoami" in post_events[0]["body_preview"]
    assert "command_injection" in post_events[0]["matched_canaries"]


def test_web_attack_generates_real_access_security_and_error_logs():
    result = run_controlled_record("sim-t1190-sqli-xss-canary", "lab-web-01", "real log test")
    access_logs = tail_telemetry_logs("access", run_id=result["run_id"], limit=10)
    security_logs = tail_telemetry_logs("security", run_id=result["run_id"], limit=10)

    assert access_logs["log_file"].endswith("lab-web-access.log")
    assert access_logs["events"]
    assert '"GET /search?' in access_logs["events"][0]["raw_line"]
    assert access_logs["events"][0]["run_id"] == result["run_id"]
    assert security_logs["log_file"].endswith("lab-web-security.log")
    assert {item["matched_canaries"][0] for item in security_logs["events"]} >= {"sqli", "xss"}

    discovery = run_controlled_record("sim-t1595-web-content-discovery", "lab-web-01", "error log test")
    error_logs = tail_telemetry_logs("error", run_id=discovery["run_id"], limit=10)
    assert error_logs["log_file"].endswith("lab-web-error.log")
    assert error_logs["events"]
    assert any(int(item["status"]) == 404 for item in error_logs["events"])


def test_web_bruteforce_attack_generates_auth_and_security_telemetry_without_password_leakage():
    result = run_controlled_record("sim-t1110-web-bruteforce", "lab-web-01", "auth telemetry")
    auth_logs = tail_telemetry_logs("auth", run_id=result["run_id"], limit=10)
    security_logs = tail_telemetry_logs("security", run_id=result["run_id"], limit=10)
    web_logs = tail_telemetry_logs("web", run_id=result["run_id"], limit=10)

    assert result["telemetry"]["request_count"] == 4
    assert result["telemetry"]["success_count"] == 4
    assert auth_logs["log_file"].endswith("lab-web-auth.log")
    assert len(auth_logs["events"]) == 4
    assert {item["auth_outcome"] for item in auth_logs["events"]} == {"failure", "success"}
    assert {item["credential_attack_type"] for item in auth_logs["events"]} == {"brute_force"}
    assert all(item["auth_user_exists"] is True for item in auth_logs["events"])
    assert all("CorrectHorseBattery1!" not in item["raw_line"] for item in auth_logs["events"])
    assert all("Password123!" not in item["raw_line"] for item in auth_logs["events"])
    assert any("brute_force" in item.get("matched_canaries", []) for item in security_logs["events"])
    assert any(item["auth_outcome"] == "success" and item["status"] == 200 for item in web_logs["events"])


def test_new_web_attack_clears_previous_shared_target_logs():
    first = run_controlled_record("sim-t1110-web-bruteforce", "lab-web-01", "first run")
    first_auth = tail_telemetry_logs("auth", run_id=first["run_id"], limit=10)
    assert len(first_auth["events"]) == 4

    second = run_controlled_record("sim-t1190-sqli-xss-canary", "lab-web-01", "second run")
    assert second["telemetry"]["cleared_shared_logs"]
    all_auth_after_second = tail_telemetry_logs("auth", limit=10)
    all_access_after_second = tail_telemetry_logs("access", limit=10)

    assert all_auth_after_second["events"] == []
    assert all(item["run_id"] == second["run_id"] for item in all_access_after_second["events"])
    assert all(item["run_id"] != first["run_id"] for item in all_access_after_second["events"])


def test_web_password_spray_and_user_enumeration_have_correct_auth_telemetry():
    spray = run_controlled_record("sim-t1110-web-password-spray", "lab-web-01", "spray telemetry")
    spray_auth = tail_telemetry_logs("auth", run_id=spray["run_id"], limit=10)
    assert len(spray_auth["events"]) == 4
    assert {item["credential_attack_type"] for item in spray_auth["events"]} == {"password_spray"}
    assert {item["auth_username"] for item in spray_auth["events"]} == {"admin", "alice", "bob", "service"}
    assert {item["auth_outcome"] for item in spray_auth["events"]} == {"failure"}
    assert all(item["auth_failure_reason"] == "bad_password" for item in spray_auth["events"])

    enumeration = run_controlled_record("sim-t1589-web-user-enumeration", "lab-web-01", "enum telemetry")
    enum_auth = tail_telemetry_logs("auth", run_id=enumeration["run_id"], limit=10)
    enum_security = tail_telemetry_logs("security", run_id=enumeration["run_id"], limit=10)
    assert len(enum_auth["events"]) == 4
    assert {item["credential_attack_type"] for item in enum_auth["events"]} == {"user_enumeration"}
    assert any(item["auth_username"] == "backupadmin" and item["auth_user_exists"] is False for item in enum_auth["events"])
    assert any(item["auth_username"] == "admin" and item["auth_user_exists"] is True for item in enum_auth["events"])
    assert any("user_enumeration" in item.get("matched_canaries", []) for item in enum_security["events"])


def test_targets_are_lab_fixtures():
    targets = list_targets()
    assert targets
    assert all(item["environment"] == "lab" for item in targets)


def test_forward_telemetry_logs_to_http_collector():
    received: list[dict] = []
    received_headers: list[dict] = []

    class Collector(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            received_headers.append({key: value for key, value in self.headers.items()})
            received.append(json.loads(self.rfile.read(length)))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Collector)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = run_controlled_record("sim-t1190-web-exposure", "lab-web-01", "forward test")
        forward = forward_telemetry_logs(
            source="web",
            run_id=result["run_id"],
            destination_url=f"http://127.0.0.1:{server.server_port}/collector",
            limit=10,
            auth_type="basic",
            username="analyst",
            password="secret",
            payload_format="envelope",
        )
    finally:
        server.shutdown()
        server.server_close()

    assert forward["ok"] is True
    assert forward["status"] == 204
    assert forward["event_count"] == 3
    assert received
    assert received_headers[0]["Authorization"].startswith("Basic ")
    assert received[0]["run_id"] == result["run_id"]
    assert len(received[0]["events"]) == 3


def test_forward_telemetry_logeye_per_event_payloads():
    received: list[dict] = []

    class Collector(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            received.append(json.loads(self.rfile.read(length)))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Collector)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = run_controlled_record("sim-t1595-http-fingerprint", "lab-web-01", "per event test")
        forward = forward_telemetry_logs(
            source="run",
            run_id=result["run_id"],
            destination_url=f"http://127.0.0.1:{server.server_port}/collector",
            limit=10,
            payload_format="per_event",
        )
    finally:
        server.shutdown()
        server.server_close()

    assert forward["ok"] is True
    assert forward["event_count"] == 4
    assert forward["sent_event_count"] == 4
    assert len(received) == 4
    assert received[0]["product"] == "AdversaryGraph"
    assert received[0]["run_id"] == result["run_id"]
    assert "message" in received[0]


def test_forward_real_access_log_payloads():
    received: list[dict] = []

    class Collector(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            received.append(json.loads(self.rfile.read(length)))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Collector)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = run_controlled_record("sim-t1190-sqli-xss-canary", "lab-web-01", "real access forward")
        forward = forward_telemetry_logs(
            source="access",
            run_id=result["run_id"],
            destination_url=f"http://127.0.0.1:{server.server_port}/collector",
            limit=10,
            payload_format="per_event",
        )
    finally:
        server.shutdown()
        server.server_close()

    assert forward["ok"] is True
    assert forward["event_count"] == 2
    assert received
    assert received[0]["source"] == "access"
    assert "raw_line" in received[0]


def test_forward_telemetry_supports_bearer_and_custom_header_auth():
    received_headers: list[dict] = []

    class Collector(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            received_headers.append({key: value for key, value in self.headers.items()})
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Collector)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = run_controlled_record("sim-t1595-http-fingerprint", "lab-web-01", "auth test")
        forward_telemetry_logs(
            source="web",
            run_id=result["run_id"],
            destination_url=f"http://127.0.0.1:{server.server_port}/collector",
            limit=10,
            auth_type="bearer",
            token="bearer-secret",
            payload_format="envelope",
        )
        forward_telemetry_logs(
            source="web",
            run_id=result["run_id"],
            destination_url=f"http://127.0.0.1:{server.server_port}/collector",
            limit=10,
            auth_type="custom_header",
            header_name="X-SIEM-Token",
            token="custom-secret",
            payload_format="envelope",
        )
    finally:
        server.shutdown()
        server.server_close()

    assert received_headers[0]["Authorization"] == "Bearer bearer-secret"
    custom_headers = {key.lower(): value for key, value in received_headers[1].items()}
    assert custom_headers["x-siem-token"] == "custom-secret"


def test_forward_telemetry_accepts_raw_host_destination():
    received: list[dict] = []

    class Collector(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            received.append(json.loads(self.rfile.read(length)))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Collector)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = run_controlled_record("sim-t1595-http-fingerprint", "lab-web-01", "raw host test")
        forward = forward_telemetry_logs(
            source="web",
            run_id=result["run_id"],
            destination_url=f"127.0.0.1:{server.server_port}/collector",
            limit=10,
        )
    finally:
        server.shutdown()
        server.server_close()

    assert forward["ok"] is True
    assert forward["destination_url"].startswith("http://127.0.0.1:")
    assert received[0]["run_id"] == result["run_id"]


def test_forward_telemetry_can_fallback_from_https_to_http_collector():
    received: list[dict] = []

    class Collector(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            received.append(json.loads(self.rfile.read(length)))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Collector)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = run_controlled_record("sim-t1595-http-fingerprint", "lab-web-01", "https fallback test")
        forward = forward_telemetry_logs(
            source="web",
            run_id=result["run_id"],
            destination_url=f"https://127.0.0.1:{server.server_port}/collector",
            limit=10,
            allow_http_fallback=True,
        )
    finally:
        server.shutdown()
        server.server_close()

    assert forward["ok"] is True
    assert forward["status"] == 200
    assert forward["http_fallback_used"] is True
    assert forward["destination_url"].startswith("http://127.0.0.1:")
    assert received[0]["run_id"] == result["run_id"]


def test_validate_siem_destination_translates_localhost_for_docker(monkeypatch):
    def fake_getaddrinfo(host, port, type=None):
        assert host == "host.docker.internal"
        assert port == 30303
        return [(None, None, None, None, ("172.17.0.1", port))]

    monkeypatch.setattr("app.services.external_simulation._running_in_container", lambda: True)
    monkeypatch.setattr("app.services.external_simulation.socket.getaddrinfo", fake_getaddrinfo)

    destination = _validate_siem_destination("https://127.0.0.1:30303/logeye/api/logger.jsp?token=secret")

    assert destination == "https://host.docker.internal:30303/logeye/api/logger.jsp?token=secret"


def test_validate_siem_destination_direct_mode_preserves_loopback_in_docker(monkeypatch):
    def fake_getaddrinfo(host, port, type=None):
        assert host == "127.0.0.1"
        assert port == 30303
        return [(None, None, None, None, ("127.0.0.1", port))]

    monkeypatch.setattr("app.services.external_simulation._running_in_container", lambda: True)
    monkeypatch.setattr("app.services.external_simulation.socket.getaddrinfo", fake_getaddrinfo)

    destination = _validate_siem_destination("127.0.0.1:30303/logeye/api/logger.jsp", connection_mode="direct")

    assert destination == "http://127.0.0.1:30303/logeye/api/logger.jsp"


def test_validate_siem_destination_maps_wildcard_address_for_docker(monkeypatch):
    def fake_getaddrinfo(host, port, type=None):
        assert host == "host.docker.internal"
        assert port == 30304
        return [(None, None, None, None, ("172.17.0.1", port))]

    monkeypatch.setattr("app.services.external_simulation._running_in_container", lambda: True)
    monkeypatch.setattr("app.services.external_simulation.socket.getaddrinfo", fake_getaddrinfo)

    destination = _validate_siem_destination("https://0.0.0.0:30304/logeye/api/logger.jsp?token=secret")

    assert destination == "https://host.docker.internal:30304/logeye/api/logger.jsp?token=secret"


def test_validate_siem_destination_maps_wildcard_address_for_direct_mode(monkeypatch):
    def fake_getaddrinfo(host, port, type=None):
        assert host == "127.0.0.1"
        assert port == 30304
        return [(None, None, None, None, ("127.0.0.1", port))]

    monkeypatch.setattr("app.services.external_simulation._running_in_container", lambda: True)
    monkeypatch.setattr("app.services.external_simulation.socket.getaddrinfo", fake_getaddrinfo)

    destination = _validate_siem_destination("0.0.0.0:30304/logeye/api/logger.jsp", connection_mode="direct")

    assert destination == "http://127.0.0.1:30304/logeye/api/logger.jsp"


def test_redact_siem_destination_hides_sensitive_query_values():
    destination = _redact_siem_destination("https://siem.example/api?token=secret&source=web&api_key=k")

    assert destination == "https://siem.example/api?token=secret&source=web&api_key=REDACTED"


def test_forward_telemetry_blocks_unsafe_destination_scheme():
    try:
        forward_telemetry_logs("web", "", "file:///tmp/collector", limit=1)
    except ValueError as exc:
        assert "http or https" in str(exc)
    else:
        raise AssertionError("unsafe SIEM destination was not blocked")
