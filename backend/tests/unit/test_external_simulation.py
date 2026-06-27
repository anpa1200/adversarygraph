from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading

from app.services.external_simulation import (
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
    assert "sim-t1595-http-fingerprint" in ids
    assert "sim-t1190-web-exposure" in ids
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


def test_targets_are_lab_fixtures():
    targets = list_targets()
    assert targets
    assert all(item["environment"] == "lab" for item in targets)


def test_forward_telemetry_logs_to_http_collector():
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
        result = run_controlled_record("sim-t1190-web-exposure", "lab-web-01", "forward test")
        forward = forward_telemetry_logs(
            source="web",
            run_id=result["run_id"],
            destination_url=f"http://127.0.0.1:{server.server_port}/collector",
            limit=10,
        )
    finally:
        server.shutdown()
        server.server_close()

    assert forward["ok"] is True
    assert forward["status"] == 204
    assert forward["event_count"] == 3
    assert received
    assert received[0]["run_id"] == result["run_id"]
    assert len(received[0]["events"]) == 3


def test_forward_telemetry_blocks_unsafe_destination_scheme():
    try:
        forward_telemetry_logs("web", "", "file:///tmp/collector", limit=1)
    except ValueError as exc:
        assert "http or https" in str(exc)
    else:
        raise AssertionError("unsafe SIEM destination was not blocked")
