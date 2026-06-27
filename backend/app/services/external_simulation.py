from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import logging
from pathlib import Path
import re
import socket
import threading
import time
from typing import Any
from urllib import parse, request
from urllib.error import HTTPError, URLError
from uuid import uuid4

from app.core.config import settings


logger = logging.getLogger(__name__)
_LAB_WEB_SERVER: ThreadingHTTPServer | None = None
_LAB_WEB_SERVER_LOCK = threading.Lock()
_LAB_WEB_HOST = "127.0.0.1"
_LAB_WEB_PORT = 8765
_LAB_WEB_BASE_URL = f"http://{_LAB_WEB_HOST}:{_LAB_WEB_PORT}"
_RUN_ID_RE = re.compile(r"^run-[a-f0-9-]{36}$")


@dataclass(frozen=True)
class Simulation:
    id: str
    technique_id: str
    name: str
    category: str
    risk_level: int
    target_types: list[str]
    description: str
    expected_telemetry: list[str]
    safety_controls: list[str]
    steps: list[str]
    destructive: bool = False
    emits_network_traffic: bool = False


@dataclass(frozen=True)
class Target:
    id: str
    name: str
    address: str
    target_type: str
    environment: str
    owner: str
    authorization: str
    allowed_categories: list[str]
    allowed_simulations: list[str] = field(default_factory=list)
    rate_limit: str = "dry-run only"
    allowed_hours: str = "lab approval required"


SIMULATIONS: list[Simulation] = [
    Simulation(
        id="sim-t1595-http-fingerprint",
        technique_id="T1595",
        name="HTTP/TLS service fingerprint plan",
        category="reconnaissance",
        risk_level=0,
        target_types=["http", "https", "web"],
        description="Prepare a safe external-service fingerprint validation for approved web targets.",
        expected_telemetry=["lab web access log", "request headers", "response status", "source IP", "run correlation ID"],
        safety_controls=["target allowlist", "local telemetry server only", "no payloads", "rate limit", "analyst review"],
        steps=[
            "Confirm target authorization and maintenance window.",
            "Start the local telemetry web server on 127.0.0.1.",
            "Send one HTTP HEAD request and one HTTP GET request to the local lab server.",
            "Record request/response telemetry to JSONL log files.",
            "Record whether the detection fired or the telemetry was only observed.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1190-web-exposure",
        technique_id="T1190",
        name="Public web exposure validation plan",
        category="initial-access-surface",
        risk_level=1,
        target_types=["http", "https", "web"],
        description="Validate visibility for benign public-facing web exposure checks without exploit payloads.",
        expected_telemetry=["lab web access log", "application access log", "request headers", "path and status"],
        safety_controls=["no exploit payload", "no fuzzing", "local telemetry server only", "single request set"],
        steps=[
            "Review target technology and allowed URL paths.",
            "Start the local telemetry web server on 127.0.0.1.",
            "Send benign requests for /, /robots.txt, /.well-known/security.txt.",
            "Do not submit forms or payloads.",
            "Capture expected log fields: path, status, user-agent, source IP.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1133-remote-service-reachability",
        technique_id="T1133",
        name="External remote service reachability plan",
        category="remote-access",
        risk_level=1,
        target_types=["vpn", "ssh", "rdp", "remote-service"],
        description="Validate telemetry for approved remote-service reachability checks.",
        expected_telemetry=["firewall deny/allow", "VPN gateway log", "remote access service log"],
        safety_controls=["no authentication attempts", "no brute force", "target allowlist", "single connection intent"],
        steps=[
            "Confirm service and port are approved for reachability validation.",
            "Prepare one low-rate connection attempt without credentials.",
            "Validate firewall and remote-access telemetry.",
            "Record whether alerting exists for unexpected external reachability.",
        ],
    ),
    Simulation(
        id="sim-t1071-controlled-beacon",
        technique_id="T1071",
        name="Controlled HTTP/DNS beacon validation plan",
        category="c2-emulation",
        risk_level=2,
        target_types=["lab-agent", "egress"],
        description="Plan a controlled beacon from a lab agent to a controlled endpoint.",
        expected_telemetry=["DNS resolver log", "proxy log", "NDR metadata", "EDR network event"],
        safety_controls=["lab agent only", "controlled endpoint only", "no malware", "fixed interval cap"],
        steps=[
            "Confirm the target is a lab agent, not a production host.",
            "Prepare a fixed benign HTTP or DNS callback to a controlled domain.",
            "Validate proxy/DNS/NDR/EDR telemetry.",
            "Document periodicity, source process, and destination context.",
        ],
    ),
    Simulation(
        id="sim-t1110-lab-login-sequence",
        technique_id="T1110",
        name="Lab-only failed-login sequence plan",
        category="credential-access",
        risk_level=2,
        target_types=["identity-lab", "sso-lab"],
        description="Plan low-rate failed logins against a lab-only identity target and test account.",
        expected_telemetry=["IdP sign-in log", "MFA log", "VPN/SSO log", "SIEM identity alert"],
        safety_controls=["lab-only target", "test account only", "low rate", "no real users", "explicit approval"],
        steps=[
            "Confirm the identity target is lab-only and uses a test account.",
            "Prepare a low-rate failed-login sequence.",
            "Do not target real users or production identity providers.",
            "Validate failed-login sequence telemetry and alerting.",
        ],
    ),
]

TARGETS: list[Target] = [
    Target(
        id="lab-web-01",
        name="Local telemetry web target",
        address=_LAB_WEB_BASE_URL,
        target_type="web",
        environment="lab",
        owner="security-team",
        authorization="local-telemetry-fixture",
        allowed_categories=["reconnaissance", "initial-access-surface"],
        allowed_simulations=["sim-t1595-http-fingerprint", "sim-t1190-web-exposure"],
        rate_limit="predefined request set only",
        allowed_hours="local lab only",
    ),
    Target(
        id="lab-idp-01",
        name="Approved lab identity target",
        address="https://idp-lab.example.test",
        target_type="identity-lab",
        environment="lab",
        owner="identity-security",
        authorization="approved-lab-fixture",
        allowed_categories=["credential-access"],
        allowed_simulations=["sim-t1110-lab-login-sequence"],
    ),
    Target(
        id="lab-egress-agent",
        name="Approved lab egress agent",
        address="agent://lab-egress-agent",
        target_type="lab-agent",
        environment="lab",
        owner="detection-engineering",
        authorization="approved-lab-fixture",
        allowed_categories=["c2-emulation"],
        allowed_simulations=["sim-t1071-controlled-beacon"],
    ),
]


def list_simulations() -> list[dict]:
    return [_simulation_dict(item) for item in SIMULATIONS]


def list_targets() -> list[dict]:
    return [_target_dict(item) for item in TARGETS]


def get_simulation(simulation_id: str) -> Simulation | None:
    return next((item for item in SIMULATIONS if item.id == simulation_id), None)


def get_target(target_id: str) -> Target | None:
    return next((item for item in TARGETS if item.id == target_id), None)


def build_plan(simulation_id: str, target_id: str) -> dict:
    simulation = get_simulation(simulation_id)
    target = get_target(target_id)
    if not simulation or not target:
        raise ValueError("Unknown simulation or target")
    allowed, reasons = is_allowed(simulation, target)
    return {
        "plan_id": f"plan-{uuid4()}",
        "simulation": _simulation_dict(simulation),
        "target": _target_dict(target),
        "allowed": allowed,
        "block_reasons": reasons,
        "execution_mode": "dry_run_required",
        "safety_notice": (
            "Attack Simulation runs only predefined benign actions against approved lab fixtures. "
            "It does not run exploit payloads, does not accept arbitrary commands, and does not target user-supplied hosts."
        ),
        "expected_telemetry": simulation.expected_telemetry,
        "steps": simulation.steps,
        "approval_checklist": [
            "Target allowlist entry is registered and approved.",
            "Simulation category is allowed for target.",
            "Analyst reviewed dry-run plan.",
            "Expected telemetry owner is known.",
            "Cleanup and stop criteria are documented.",
        ],
    }


def run_controlled_record(simulation_id: str, target_id: str, analyst_note: str = "") -> dict:
    plan = build_plan(simulation_id, target_id)
    now = datetime.now(timezone.utc).isoformat()
    if not plan["allowed"]:
        return {
            "run_id": f"run-{uuid4()}",
            "status": "blocked",
            "started_at": now,
            "ended_at": now,
            "plan": plan,
            "transcript": ["Simulation blocked by safety policy before execution."],
            "traffic_emitted": False,
            "result": "not_run",
            "validation_status": "not_proven",
            "gaps": plan["block_reasons"],
            "telemetry": {},
        }

    simulation = plan["simulation"]
    target = plan["target"]
    run_id = f"run-{uuid4()}"
    telemetry: dict[str, Any] = {}
    traffic_emitted = False
    result = "telemetry_validation_record_prepared"
    gaps = [
        "Attach SIEM, WAF, firewall, DNS, proxy, EDR, or IdP evidence if validating against enterprise telemetry.",
        "Mark as passed only after telemetry and detection firing are verified.",
    ]
    next_steps = [
        "Review the generated JSONL telemetry log.",
        "Compare the request sequence with expected detection logic.",
        "Record detection result as passed, failed, partial, or not proven.",
    ]

    if target["id"] == "lab-web-01" and simulation["id"] in {"sim-t1595-http-fingerprint", "sim-t1190-web-exposure"}:
        telemetry = run_lab_web_attack(run_id, simulation["id"], analyst_note)
        traffic_emitted = True
        result = "local_lab_web_telemetry_collected"
        gaps = telemetry.get("validation_gaps", gaps)
        next_steps = telemetry.get("next_steps", next_steps)

    transcript = [
        f"Prepared {simulation['id']} for target {target['id']}.",
        "Verified target allowlist and simulation-category policy.",
        "Generated expected telemetry checklist.",
        (
            f"Executed predefined local lab web request set against {target['address']}."
            if traffic_emitted
            else "No network traffic emitted by this simulation runner."
        ),
        "Analyst must validate detection coverage before marking the result as passed.",
    ]
    if telemetry.get("log_file"):
        transcript.append(f"Telemetry log saved: {telemetry['log_file']}")
    if analyst_note:
        transcript.append(f"Analyst note: {analyst_note}")
    return {
        "run_id": run_id,
        "status": "completed_with_local_lab_telemetry" if traffic_emitted else "completed_record_only",
        "started_at": now,
        "ended_at": datetime.now(timezone.utc).isoformat(),
        "plan": plan,
        "transcript": transcript,
        "traffic_emitted": traffic_emitted,
        "result": result,
        "validation_status": "not_proven",
        "gaps": gaps,
        "next_steps": next_steps,
        "telemetry": telemetry,
    }


def is_allowed(simulation: Simulation, target: Target) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if simulation.destructive:
        reasons.append("Destructive simulations are disabled.")
    if target.environment != "lab":
        reasons.append("Only lab targets are allowed in the MVP.")
    if simulation.id not in target.allowed_simulations:
        reasons.append("Simulation is not allowlisted for this target.")
    if simulation.category not in target.allowed_categories:
        reasons.append("Simulation category is not allowed for this target.")
    if target.target_type not in simulation.target_types:
        reasons.append("Target type does not match simulation target types.")
    if simulation.risk_level > 2:
        reasons.append("Risk level above 2 is disabled.")
    return not reasons, reasons


def _simulation_dict(item: Simulation) -> dict:
    return {
        "id": item.id,
        "technique_id": item.technique_id,
        "name": item.name,
        "category": item.category,
        "risk_level": item.risk_level,
        "target_types": item.target_types,
        "description": item.description,
        "expected_telemetry": item.expected_telemetry,
        "safety_controls": item.safety_controls,
        "steps": item.steps,
        "destructive": item.destructive,
        "emits_network_traffic": item.emits_network_traffic,
    }


def _target_dict(item: Target) -> dict:
    return {
        "id": item.id,
        "name": item.name,
        "address": item.address,
        "target_type": item.target_type,
        "environment": item.environment,
        "owner": item.owner,
        "authorization": item.authorization,
        "allowed_categories": item.allowed_categories,
        "allowed_simulations": item.allowed_simulations,
        "rate_limit": item.rate_limit,
        "allowed_hours": item.allowed_hours,
    }


def run_lab_web_attack(run_id: str, simulation_id: str, analyst_note: str = "") -> dict[str, Any]:
    server_url = ensure_lab_web_server()
    attack_log_file = _attack_log_path(run_id)
    requests_to_send = _web_request_sequence(simulation_id)
    results: list[dict[str, Any]] = []
    started = datetime.now(timezone.utc)
    _append_jsonl(
        attack_log_file,
        {
            "timestamp": started.isoformat(),
            "event_type": "attack_run_started",
            "run_id": run_id,
            "simulation_id": simulation_id,
            "target": server_url,
            "analyst_note": analyst_note,
        },
    )

    for index, item in enumerate(requests_to_send, start=1):
        event = _send_lab_web_request(run_id, simulation_id, index, server_url, item["method"], item["path"])
        results.append(event)
        _append_jsonl(attack_log_file, event)
        time.sleep(0.15)

    ended = datetime.now(timezone.utc)
    summary = {
        "timestamp": ended.isoformat(),
        "event_type": "attack_run_completed",
        "run_id": run_id,
        "simulation_id": simulation_id,
        "target": server_url,
        "request_count": len(results),
        "success_count": sum(1 for item in results if item.get("ok")),
        "duration_ms": round((ended - started).total_seconds() * 1000, 3),
    }
    _append_jsonl(attack_log_file, summary)

    return {
        "server": {
            "url": server_url,
            "host": _LAB_WEB_HOST,
            "port": _LAB_WEB_PORT,
            "status": "running",
        },
        "log_file": str(attack_log_file),
        "web_access_log_file": str(_web_access_log_path()),
        "request_count": len(results),
        "success_count": summary["success_count"],
        "events": results,
        "summary": summary,
        "validation_gaps": [
            "Telemetry was collected from the built-in local lab web server, not from production WAF or SIEM.",
            "Confirm detection coverage by forwarding these logs or reproducing the same safe request set in an authorized detection lab.",
        ],
        "next_steps": [
            "Open the JSONL log file and verify run_id correlation across attack and web access events.",
            "Map observed paths, methods, status codes, and user-agent values into detection logic.",
            "Forward the log file to SIEM/WAF test ingestion if enterprise detection validation is required.",
        ],
    }


def ensure_lab_web_server() -> str:
    global _LAB_WEB_SERVER
    with _LAB_WEB_SERVER_LOCK:
        if _LAB_WEB_SERVER is not None:
            return _LAB_WEB_BASE_URL

        _ensure_log_dir()
        _LAB_WEB_SERVER = ThreadingHTTPServer((_LAB_WEB_HOST, _LAB_WEB_PORT), _TelemetryWebHandler)
        thread = threading.Thread(target=_LAB_WEB_SERVER.serve_forever, name="attack-simulation-lab-web", daemon=True)
        thread.start()
        logger.info("Started Attack Simulation telemetry web server on %s", _LAB_WEB_BASE_URL)
    return _LAB_WEB_BASE_URL


def _web_request_sequence(simulation_id: str) -> list[dict[str, str]]:
    if simulation_id == "sim-t1190-web-exposure":
        return [
            {"method": "GET", "path": "/"},
            {"method": "GET", "path": "/robots.txt"},
            {"method": "GET", "path": "/.well-known/security.txt"},
        ]
    return [
        {"method": "HEAD", "path": "/"},
        {"method": "GET", "path": "/"},
    ]


def _send_lab_web_request(run_id: str, simulation_id: str, index: int, base_url: str, method: str, path: str) -> dict[str, Any]:
    url = f"{base_url}{path}"
    started = time.perf_counter()
    headers = {
        "User-Agent": f"AdversaryGraph-AttackSimulation/{simulation_id}",
        "X-AdversaryGraph-Run-Id": run_id,
        "X-AdversaryGraph-Simulation-Id": simulation_id,
        "X-AdversaryGraph-Request-Index": str(index),
    }
    req = request.Request(url, method=method, headers=headers)
    try:
        with request.urlopen(req, timeout=5) as response:
            body = response.read(4096)
            status = response.status
            response_headers = dict(response.headers.items())
            ok = 200 <= status < 500
            error = ""
    except HTTPError as exc:
        body = exc.read(4096)
        status = exc.code
        response_headers = dict(exc.headers.items())
        ok = False
        error = str(exc)
    except URLError as exc:
        body = b""
        status = 0
        response_headers = {}
        ok = False
        error = str(exc.reason)
    duration_ms = round((time.perf_counter() - started) * 1000, 3)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "attack_request",
        "run_id": run_id,
        "simulation_id": simulation_id,
        "request_index": index,
        "method": method,
        "url": url,
        "path": path,
        "request_headers": headers,
        "status": status,
        "ok": ok,
        "duration_ms": duration_ms,
        "response_bytes": len(body),
        "response_headers": response_headers,
        "error": error,
    }


class _TelemetryWebHandler(BaseHTTPRequestHandler):
    server_version = "AdversaryGraphTelemetryWeb/1.0"

    def do_HEAD(self) -> None:
        self._handle_request(include_body=False)

    def do_GET(self) -> None:
        self._handle_request(include_body=True)

    def do_POST(self) -> None:
        self.send_error(405, "Only safe GET/HEAD lab requests are supported")
        self._log_access_event(405, 0)

    def log_message(self, format: str, *args: Any) -> None:
        logger.debug("Telemetry web server: " + format, *args)

    def _handle_request(self, include_body: bool) -> None:
        body = _response_body_for_path(self.path)
        status = 200 if body is not None else 404
        payload = body if body is not None else b"not found\n"
        content_type = "text/plain; charset=utf-8"
        if self.path == "/":
            content_type = "text/html; charset=utf-8"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-AdversaryGraph-Lab", "attack-simulation")
        self.end_headers()
        if include_body:
            self.wfile.write(payload)
        self._log_access_event(status, len(payload) if include_body else 0)

    def _log_access_event(self, status: int, response_bytes: int) -> None:
        headers = {key: value for key, value in self.headers.items()}
        header_lookup = {key.lower(): value for key, value in headers.items()}
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "lab_web_access",
            "run_id": header_lookup.get("x-adversarygraph-run-id", ""),
            "simulation_id": header_lookup.get("x-adversarygraph-simulation-id", ""),
            "request_index": header_lookup.get("x-adversarygraph-request-index", ""),
            "client_ip": self.client_address[0],
            "client_port": self.client_address[1],
            "method": self.command,
            "path": self.path,
            "protocol": self.request_version,
            "headers": headers,
            "status": status,
            "response_bytes": response_bytes,
        }
        _append_jsonl(_web_access_log_path(), event)


def _response_body_for_path(path: str) -> bytes | None:
    clean_path = path.split("?", 1)[0]
    if clean_path == "/":
        return (
            b"<html><head><title>AdversaryGraph Lab Web</title></head>"
            b"<body><h1>AdversaryGraph Attack Simulation Lab</h1></body></html>\n"
        )
    if clean_path == "/robots.txt":
        return b"User-agent: *\nDisallow: /admin\n"
    if clean_path == "/.well-known/security.txt":
        return b"Contact: mailto:security@example.test\nPolicy: https://example.test/security-policy\n"
    return None


def _ensure_log_dir() -> Path:
    path = Path(settings.log_dir) / "attack-simulation"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _attack_log_path(run_id: str) -> Path:
    return _ensure_log_dir() / f"{run_id}.jsonl"


def _web_access_log_path() -> Path:
    return _ensure_log_dir() / "lab-web-access.jsonl"


def _append_jsonl(path: Path, event: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")


def tail_telemetry_logs(source: str = "web", run_id: str = "", limit: int = 100) -> dict[str, Any]:
    limit = max(1, min(limit, 500))
    if source not in {"web", "run"}:
        raise ValueError("Unknown telemetry log source")
    if source == "run":
        if not _RUN_ID_RE.match(run_id):
            raise ValueError("A valid run_id is required for run telemetry logs")
        path = _attack_log_path(run_id)
    else:
        path = _web_access_log_path()

    events = _tail_jsonl(path, limit=limit, run_id=run_id if source == "web" else "")
    return {
        "source": source,
        "run_id": run_id,
        "log_file": str(path),
        "exists": path.exists(),
        "line_count": len(events),
        "events": events,
        "returned_at": datetime.now(timezone.utc).isoformat(),
    }


def forward_telemetry_logs(
    source: str,
    run_id: str,
    destination_url: str,
    limit: int = 100,
    bearer_token: str = "",
) -> dict[str, Any]:
    destination = _validate_siem_destination(destination_url)
    logs = tail_telemetry_logs(source=source, run_id=run_id, limit=limit)
    payload = {
        "product": "AdversaryGraph",
        "module": "Attack Simulation",
        "sent_at": datetime.now(timezone.utc).isoformat(),
        "source": logs["source"],
        "run_id": logs["run_id"],
        "log_file": logs["log_file"],
        "event_count": logs["line_count"],
        "events": logs["events"],
    }
    body = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "AdversaryGraph-AttackSimulation-Forwarder/1.0",
        "X-AdversaryGraph-Module": "attack-simulation",
        "X-AdversaryGraph-Run-Id": run_id,
    }
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    req = request.Request(destination, data=body, method="POST", headers=headers)
    started = time.perf_counter()
    try:
        with request.urlopen(req, timeout=10) as response:
            response_body = response.read(2048).decode("utf-8", errors="replace")
            status = response.status
            ok = 200 <= status < 300
            response_headers = dict(response.headers.items())
    except HTTPError as exc:
        response_body = exc.read(2048).decode("utf-8", errors="replace")
        status = exc.code
        ok = False
        response_headers = dict(exc.headers.items())
    except URLError as exc:
        return {
            "ok": False,
            "status": 0,
            "destination_url": destination,
            "source": source,
            "run_id": run_id,
            "event_count": logs["line_count"],
            "duration_ms": round((time.perf_counter() - started) * 1000, 3),
            "error": str(exc.reason),
            "response_preview": "",
            "response_headers": {},
        }

    return {
        "ok": ok,
        "status": status,
        "destination_url": destination,
        "source": source,
        "run_id": run_id,
        "event_count": logs["line_count"],
        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
        "error": "" if ok else response_body[:500],
        "response_preview": response_body[:500],
        "response_headers": response_headers,
    }


def _tail_jsonl(path: Path, limit: int, run_id: str = "") -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                event = {"event_type": "parse_error", "raw": line}
            if run_id and event.get("run_id") != run_id:
                continue
            events.append(event)
            if len(events) > limit:
                events = events[-limit:]
    return events


def _validate_siem_destination(destination_url: str) -> str:
    parsed = parse.urlparse(destination_url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("SIEM destination must use http or https")
    if not parsed.hostname:
        raise ValueError("SIEM destination host is required")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in SIEM URL are not allowed; use bearer token instead")

    hostname = parsed.hostname.lower()
    if hostname in {"169.254.169.254", "metadata.google.internal"}:
        raise ValueError("Metadata service destinations are blocked")

    try:
        infos = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve SIEM destination host: {hostname}") from exc
    for info in infos:
        address = info[4][0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            raise ValueError("Unsafe SIEM destination address is blocked")
        if str(ip) == "169.254.169.254":
            raise ValueError("Metadata service destinations are blocked")

    return parse.urlunparse(parsed)
