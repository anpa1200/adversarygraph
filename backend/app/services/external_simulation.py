from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import select
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
_DEFAULT_ATTACK_LAB_WEB_URL = _LAB_WEB_BASE_URL
_ATTACK_LAB_WEB_URL = os.environ.get("ATTACK_LAB_WEB_URL", _DEFAULT_ATTACK_LAB_WEB_URL).rstrip("/")
_RUN_ID_RE = re.compile(r"^run-[a-f0-9-]{36}$")
_LOOPBACK_BRIDGES: set[int] = set()
_LOOPBACK_BRIDGES_LOCK = threading.Lock()
LAB_AUTH_USERS = {
    "admin": "CorrectHorseBattery1!",
    "alice": "Wonderland-2026!",
    "bob": "Builder-2026!",
    "service": "Service-Token-2026!",
}


WEB_SIMULATION_REQUESTS: dict[str, list[dict[str, Any]]] = {
    "sim-t1595-http-fingerprint": [
        {"method": "HEAD", "path": "/", "purpose": "service header fingerprint"},
        {"method": "GET", "path": "/", "purpose": "landing page fingerprint"},
    ],
    "sim-t1190-web-exposure": [
        {"method": "GET", "path": "/", "purpose": "public root exposure"},
        {"method": "GET", "path": "/robots.txt", "purpose": "robots disclosure"},
        {"method": "GET", "path": "/.well-known/security.txt", "purpose": "security metadata discovery"},
    ],
    "sim-t1595-web-content-discovery": [
        {"method": "GET", "path": "/admin", "purpose": "admin path discovery"},
        {"method": "GET", "path": "/login", "purpose": "login path discovery"},
        {"method": "GET", "path": "/api/v1/status", "purpose": "API status discovery"},
        {"method": "GET", "path": "/backup.zip", "purpose": "backup artifact discovery"},
        {"method": "GET", "path": "/.git/config", "purpose": "repository metadata discovery"},
    ],
    "sim-t1190-traversal-canary": [
        {"method": "GET", "path": "/download?file=../../../../etc/passwd&ag_canary=path_traversal", "purpose": "path traversal canary"},
        {"method": "GET", "path": "/static/%2e%2e/%2e%2e/windows/win.ini?ag_canary=encoded_traversal", "purpose": "encoded traversal canary"},
    ],
    "sim-t1190-sqli-xss-canary": [
        {"method": "GET", "path": "/search?q=%27%20OR%20%271%27%3D%271&ag_canary=sqli", "purpose": "SQL injection canary"},
        {"method": "GET", "path": "/comment?text=%3Cscript%3Eag_xss_canary%3C%2Fscript%3E&ag_canary=xss", "purpose": "XSS canary"},
    ],
    "sim-t1190-ssrf-canary": [
        {"method": "GET", "path": "/fetch?url=http://169.254.169.254/latest/meta-data/&ag_canary=ssrf_metadata", "purpose": "SSRF metadata canary"},
        {"method": "GET", "path": "/proxy?target=http://127.0.0.1:22&ag_canary=ssrf_loopback", "purpose": "SSRF loopback canary"},
    ],
    "sim-t1059-web-command-canary": [
        {"method": "GET", "path": "/cgi-bin/status?cmd=id&ag_canary=command_injection", "purpose": "command injection canary"},
        {"method": "POST", "path": "/api/run", "body": '{"command":"whoami","ag_canary":"command_injection"}', "purpose": "JSON command injection canary"},
    ],
    "sim-t1505-webshell-canary": [
        {"method": "GET", "path": "/shell.php?cmd=whoami&ag_canary=webshell", "purpose": "web shell URI canary"},
        {"method": "POST", "path": "/uploads/cmd.aspx", "body": "cmd=whoami&ag_canary=webshell", "purpose": "web shell POST canary"},
    ],
    "sim-t1105-web-upload-download": [
        {"method": "GET", "path": "/downloads/agent.ps1?ag_canary=tool_download", "purpose": "tool download canary"},
        {"method": "POST", "path": "/upload", "body": "AG_BENIGN_UPLOAD_CANARY", "purpose": "small upload canary"},
    ],
    "sim-t1552-web-secret-exposure-canary": [
        {"method": "GET", "path": "/.env?ag_canary=secret_exposure", "purpose": "environment secret exposure canary"},
        {"method": "GET", "path": "/config.php.bak?ag_canary=secret_exposure", "purpose": "backup config exposure canary"},
        {"method": "GET", "path": "/id_rsa?ag_canary=secret_exposure", "purpose": "private key exposure canary"},
    ],
    "sim-t1110-web-login-failures": [
        {"method": "POST", "path": "/login", "body": "username=admin&password=wrong-one&ag_canary=failed_login", "purpose": "failed login canary"},
        {"method": "POST", "path": "/login", "body": "username=admin&password=wrong-two&ag_canary=failed_login", "purpose": "second failed login canary"},
        {"method": "POST", "path": "/login", "body": "username=service&password=wrong-three&ag_canary=failed_login", "purpose": "low-rate credential canary"},
    ],
    "sim-t1110-web-bruteforce": [
        {"method": "POST", "path": "/login", "body": "username=admin&password=Summer2024!&ag_canary=brute_force", "purpose": "brute force attempt 1"},
        {"method": "POST", "path": "/login", "body": "username=admin&password=Password123!&ag_canary=brute_force", "purpose": "brute force attempt 2"},
        {"method": "POST", "path": "/login", "body": "username=admin&password=Admin12345!&ag_canary=brute_force", "purpose": "brute force attempt 3"},
        {"method": "POST", "path": "/login", "body": "username=admin&password=CorrectHorseBattery1!&ag_canary=brute_force", "purpose": "brute force final success canary"},
    ],
    "sim-t1110-web-password-spray": [
        {"method": "POST", "path": "/login", "body": "username=admin&password=Spring2026!&ag_canary=password_spray", "purpose": "password spray admin"},
        {"method": "POST", "path": "/login", "body": "username=alice&password=Spring2026!&ag_canary=password_spray", "purpose": "password spray alice"},
        {"method": "POST", "path": "/login", "body": "username=bob&password=Spring2026!&ag_canary=password_spray", "purpose": "password spray bob"},
        {"method": "POST", "path": "/login", "body": "username=service&password=Spring2026!&ag_canary=password_spray", "purpose": "password spray service"},
    ],
    "sim-t1589-web-user-enumeration": [
        {"method": "GET", "path": "/login/user-check?username=admin&ag_canary=user_enumeration", "purpose": "known user enumeration canary"},
        {"method": "GET", "path": "/login/user-check?username=alice&ag_canary=user_enumeration", "purpose": "second known user enumeration canary"},
        {"method": "GET", "path": "/login/user-check?username=backupadmin&ag_canary=user_enumeration", "purpose": "unknown user enumeration canary"},
        {"method": "POST", "path": "/login", "body": "username=backupadmin&password=anything&ag_canary=user_enumeration", "purpose": "unknown login user enumeration canary"},
    ],
    "sim-t1071-web-beacon": [
        {"method": "GET", "path": "/api/ping?client=lab-agent&seq=1&ag_canary=beacon", "purpose": "HTTP beacon canary"},
        {"method": "GET", "path": "/api/ping?client=lab-agent&seq=2&ag_canary=beacon", "purpose": "second HTTP beacon canary"},
        {"method": "POST", "path": "/api/telemetry", "body": '{"client":"lab-agent","seq":3,"ag_canary":"beacon"}', "purpose": "HTTP beacon POST canary"},
    ],
    "sim-t1041-web-exfil-canary": [
        {"method": "POST", "path": "/api/export", "body": '{"records":25,"classification":"benign_lab","ag_canary":"exfil"}', "purpose": "small exfil-like upload canary"},
        {"method": "POST", "path": "/collect", "body": "AG_EXFIL_CANARY_BLOCK_001\nAG_EXFIL_CANARY_BLOCK_002\n", "purpose": "multi-line exfil-like body canary"},
    ],
}

WEB_SIMULATION_IDS = set(WEB_SIMULATION_REQUESTS)
LOG_SOURCES = {"web", "run", "access", "security", "error", "auth"}


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
        id="sim-t1595-web-content-discovery",
        technique_id="T1595",
        name="Web content discovery and path enumeration",
        category="web-reconnaissance",
        risk_level=1,
        target_types=["http", "https", "web"],
        description="Generate benign admin/API/backup/repository path probes against the lab web server.",
        expected_telemetry=["access log path distribution", "404 status spikes", "admin path probes", "backup path probes"],
        safety_controls=["local telemetry server only", "fixed path list", "no directory brute force", "no payload execution"],
        steps=[
            "Start the local telemetry web server.",
            "Request a fixed set of common administrative, API, backup, and repository paths.",
            "Record status, path, user-agent, and run correlation fields.",
            "Validate web discovery detections without scanning arbitrary paths.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1190-traversal-canary",
        technique_id="T1190",
        name="Path traversal canary validation",
        category="web-exploit-canary",
        risk_level=1,
        target_types=["http", "https", "web"],
        description="Send harmless path-traversal-shaped canary requests to validate parser and WAF telemetry.",
        expected_telemetry=["query string", "encoded traversal sequence", "canary tag", "HTTP 404/200 status"],
        safety_controls=["canary strings only", "local telemetry server only", "no filesystem access", "no exploit execution"],
        steps=[
            "Send fixed traversal-looking requests containing explicit ag_canary markers.",
            "Do not read files or resolve paths on the server.",
            "Record decoded query keys and matched canary indicators.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1190-sqli-xss-canary",
        technique_id="T1190",
        name="SQL injection and XSS canary validation",
        category="web-exploit-canary",
        risk_level=1,
        target_types=["http", "https", "web"],
        description="Generate SQLi/XSS-shaped canary requests without database, browser, or script execution.",
        expected_telemetry=["sqli-shaped query", "xss-shaped query", "URL encoding", "canary classification"],
        safety_controls=["local telemetry server only", "no database", "no script execution", "fixed canaries"],
        steps=[
            "Send one SQLi-shaped query and one XSS-shaped query to benign lab endpoints.",
            "Classify canary indicators in web telemetry.",
            "Validate WAF/SIEM parsing and alert coverage.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1190-ssrf-canary",
        technique_id="T1190",
        name="SSRF metadata and loopback canary validation",
        category="web-exploit-canary",
        risk_level=1,
        target_types=["http", "https", "web"],
        description="Generate SSRF-shaped URL parameters without making server-side outbound requests.",
        expected_telemetry=["metadata URL parameter", "loopback URL parameter", "query keys", "canary classification"],
        safety_controls=["no server-side fetch", "local telemetry server only", "fixed URL parameters", "metadata not contacted"],
        steps=[
            "Send fixed SSRF-looking URL parameters to local lab endpoints.",
            "The server records the parameter but never fetches it.",
            "Validate SSRF detector logic on request telemetry.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1059-web-command-canary",
        technique_id="T1059",
        name="Web command execution canary validation",
        category="execution-canary",
        risk_level=1,
        target_types=["http", "https", "web"],
        description="Generate command-injection-shaped canary requests without command execution.",
        expected_telemetry=["cmd parameter", "JSON command field", "body hash", "canary classification"],
        safety_controls=["commands are never executed", "local telemetry server only", "fixed canary values"],
        steps=[
            "Send command-shaped parameters and JSON fields to lab endpoints.",
            "Record request body length, hash, and preview.",
            "Validate command-injection detection logic without execution.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1505-webshell-canary",
        technique_id="T1505.003",
        name="Web shell URI and POST canary validation",
        category="persistence-canary",
        risk_level=1,
        target_types=["http", "https", "web"],
        description="Generate web-shell-shaped requests to validate telemetry without uploading or running shells.",
        expected_telemetry=["shell-like extension", "cmd parameter", "POST body hash", "canary classification"],
        safety_controls=["no file creation", "no command execution", "local telemetry server only", "fixed canaries"],
        steps=[
            "Send URI and POST canaries that resemble web-shell access patterns.",
            "The lab server returns benign responses and records indicators.",
            "Validate web-shell detection logic and triage fields.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1105-web-upload-download",
        technique_id="T1105",
        name="Ingress tool transfer upload/download canary",
        category="transfer-canary",
        risk_level=1,
        target_types=["http", "https", "web"],
        description="Generate benign upload/download telemetry for tool-transfer detection validation.",
        expected_telemetry=["download path", "upload endpoint", "body length", "user-agent", "canary classification"],
        safety_controls=["no executable content", "small benign body", "local telemetry server only"],
        steps=[
            "Request a fixed benign download path.",
            "POST a small benign canary body to an upload endpoint.",
            "Record transfer-like telemetry without storing files.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1552-web-secret-exposure-canary",
        technique_id="T1552.001",
        name="Web-exposed secret and backup file canary",
        category="credential-exposure-canary",
        risk_level=1,
        target_types=["http", "https", "web"],
        description="Generate requests for exposed .env, backup config, and private-key paths without returning secrets.",
        expected_telemetry=["secret-like path", "backup config path", "private-key path", "canary classification"],
        safety_controls=["no real secrets", "local telemetry server only", "fixed path list", "404/benign responses only"],
        steps=[
            "Request fixed secret/config/key-looking paths against the local lab server.",
            "The server records access attempts but never serves secret material.",
            "Validate detections for exposed credential/config discovery attempts.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1110-web-login-failures",
        technique_id="T1110",
        name="Web failed-login sequence canary",
        category="credential-access",
        risk_level=2,
        target_types=["http", "https", "web"],
        description="Generate low-rate failed-login-shaped telemetry against the lab web server only.",
        expected_telemetry=["login endpoint", "username field", "failed status", "low-rate sequence", "canary classification"],
        safety_controls=["lab server only", "no real accounts", "fixed low rate", "no brute force"],
        steps=[
            "Send three fixed failed-login canaries to the local lab login endpoint.",
            "Record body hash and username-like fields without authenticating.",
            "Validate failed-login sequence detections.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1110-web-bruteforce",
        technique_id="T1110.001",
        name="Web login brute-force sequence",
        category="credential-attack",
        risk_level=2,
        target_types=["http", "https", "web"],
        description="Generate a fixed lab-only brute-force sequence against the built-in auth endpoint.",
        expected_telemetry=["auth log failures", "auth log final success", "same username repeated", "WAF/security brute_force alerts"],
        safety_controls=["lab server only", "fixed test account", "four requests only", "no real credentials", "no external target"],
        steps=[
            "Send a fixed sequence of failed passwords for the admin lab account.",
            "Send one final known-good lab password to prove successful-auth telemetry.",
            "Record access, auth, security, and structured JSONL events with run correlation.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1110-web-password-spray",
        technique_id="T1110.003",
        name="Web password spraying sequence",
        category="credential-attack",
        risk_level=2,
        target_types=["http", "https", "web"],
        description="Generate a fixed password-spray pattern across lab-only users using one incorrect password.",
        expected_telemetry=["auth log failures", "one password across many users", "password_spray security alerts", "source IP correlation"],
        safety_controls=["lab server only", "fixed test users", "one benign password", "four requests only", "no lockout logic"],
        steps=[
            "POST the same incorrect password across a fixed list of lab users.",
            "Record user existence, outcome, failure reason, and source IP without logging the cleartext password.",
            "Validate SIEM detection for one password across multiple accounts.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1589-web-user-enumeration",
        technique_id="T1589.002",
        name="Web user enumeration sequence",
        category="reconnaissance",
        risk_level=1,
        target_types=["http", "https", "web"],
        description="Generate user-enumeration-shaped requests against the built-in auth fixture.",
        expected_telemetry=["username probe", "user exists flag", "unknown user failure", "user_enumeration security alerts"],
        safety_controls=["lab server only", "fixed user list", "no password attack volume", "no external identity provider"],
        steps=[
            "Probe fixed known and unknown lab usernames.",
            "Record whether the auth fixture treated each username as existing.",
            "Validate enumeration detections based on mixed known/unknown user probes.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1071-web-beacon",
        technique_id="T1071.001",
        name="HTTP web beacon canary",
        category="c2-emulation",
        risk_level=2,
        target_types=["http", "https", "web"],
        description="Generate benign periodic HTTP beacon-shaped telemetry to the local lab server.",
        expected_telemetry=["periodic paths", "sequence parameter", "POST telemetry body", "canary classification"],
        safety_controls=["local telemetry server only", "fixed small sequence", "no external C2", "no malware"],
        steps=[
            "Send a short fixed sequence of beacon-shaped GET and POST requests.",
            "Record sequence values and timing.",
            "Validate web-protocol C2 detections on benign lab telemetry.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1041-web-exfil-canary",
        technique_id="T1041",
        name="Web exfiltration-shaped upload canary",
        category="exfiltration-canary",
        risk_level=2,
        target_types=["http", "https", "web"],
        description="Generate small benign exfiltration-shaped uploads to validate outbound/body telemetry parsing.",
        expected_telemetry=["POST body length", "multi-line body", "export endpoint", "canary classification"],
        safety_controls=["small benign payload", "no sensitive data", "local telemetry server only", "no external destination"],
        steps=[
            "POST small benign JSON and text bodies to lab collection endpoints.",
            "Record body metadata without storing sensitive content.",
            "Validate exfiltration-shaped web telemetry detections.",
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
        name="Docker attack lab web target",
        address=_ATTACK_LAB_WEB_URL,
        target_type="web",
        environment="lab",
        owner="security-team",
        authorization="local-telemetry-fixture",
        allowed_categories=[
            "reconnaissance",
            "initial-access-surface",
            "web-reconnaissance",
            "web-exploit-canary",
            "execution-canary",
            "persistence-canary",
            "transfer-canary",
            "credential-exposure-canary",
            "credential-access",
            "credential-attack",
            "c2-emulation",
            "exfiltration-canary",
        ],
        allowed_simulations=sorted(WEB_SIMULATION_IDS),
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

    if target["id"] == "lab-web-01" and simulation["id"] in WEB_SIMULATION_IDS:
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
    server_url = ensure_lab_web_target()
    attack_log_file = _attack_log_path(run_id)
    requests_to_send = _web_request_sequence(simulation_id)
    results: list[dict[str, Any]] = []
    started = datetime.now(timezone.utc)
    cleared_logs = clear_shared_lab_web_logs()
    _append_jsonl(
        attack_log_file,
        {
            "timestamp": started.isoformat(),
            "event_type": "attack_run_started",
            "run_id": run_id,
            "simulation_id": simulation_id,
            "target": server_url,
            "analyst_note": analyst_note,
            "cleared_shared_logs": cleared_logs,
        },
    )

    for index, item in enumerate(requests_to_send, start=1):
        event = _send_lab_web_request(
            run_id,
            simulation_id,
            index,
            server_url,
            item["method"],
            item["path"],
            body=item.get("body", ""),
            purpose=item.get("purpose", ""),
        )
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
        "server": _lab_web_target_info(server_url),
        "log_file": str(attack_log_file),
        "web_access_log_file": str(_web_access_log_path()),
        "web_server_access_log_file": str(_web_server_access_log_path()),
        "web_security_log_file": str(_web_security_log_path()),
        "web_error_log_file": str(_web_error_log_path()),
        "web_auth_log_file": str(_web_auth_log_path()),
        "cleared_shared_logs": cleared_logs,
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


def ensure_lab_web_target() -> str:
    target_url = os.environ.get("ATTACK_LAB_WEB_URL", _DEFAULT_ATTACK_LAB_WEB_URL).rstrip("/")
    if target_url != _DEFAULT_ATTACK_LAB_WEB_URL:
        return target_url
    return ensure_lab_web_server()


def _lab_web_target_info(server_url: str) -> dict[str, Any]:
    parsed = parse.urlparse(server_url)
    return {
        "url": server_url,
        "host": parsed.hostname or _LAB_WEB_HOST,
        "port": parsed.port or (443 if parsed.scheme == "https" else 80),
        "status": "running",
        "deployment": "docker_target" if server_url != _DEFAULT_ATTACK_LAB_WEB_URL else "in_process_test_fallback",
    }


def _web_request_sequence(simulation_id: str) -> list[dict[str, Any]]:
    return WEB_SIMULATION_REQUESTS.get(simulation_id, WEB_SIMULATION_REQUESTS["sim-t1595-http-fingerprint"])


def _send_lab_web_request(run_id: str, simulation_id: str, index: int, base_url: str, method: str, path: str, body: str = "", purpose: str = "") -> dict[str, Any]:
    url = f"{base_url}{path}"
    started = time.perf_counter()
    headers = {
        "User-Agent": f"AdversaryGraph-AttackSimulation/{simulation_id}",
        "X-AdversaryGraph-Run-Id": run_id,
        "X-AdversaryGraph-Simulation-Id": simulation_id,
        "X-AdversaryGraph-Request-Index": str(index),
        "X-AdversaryGraph-Request-Purpose": purpose,
    }
    data = body.encode("utf-8") if body else None
    if data is not None:
        headers["Content-Type"] = "application/json" if body.strip().startswith(("{", "[")) else "application/x-www-form-urlencoded"
    req = request.Request(url, data=data, method=method, headers=headers)
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
        ok = 200 <= status < 500
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
        "purpose": purpose,
        "request_headers": headers,
        "request_body_length": len(data or b""),
        "request_body_sha256": hashlib.sha256(data).hexdigest() if data else "",
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
        self._handle_request(include_body=True)

    def log_message(self, format: str, *args: Any) -> None:
        logger.debug("Telemetry web server: " + format, *args)

    def _handle_request(self, include_body: bool) -> None:
        request_body = self._read_request_body()
        auth_event = _auth_event_for_request(self.command, self.path, request_body)
        body = _response_body_for_path(self.path)
        status = 200 if body is not None else 404
        payload = body if body is not None else b"not found\n"
        if auth_event:
            status = int(auth_event["status"])
            payload = json.dumps(
                {
                    "status": auth_event["auth_outcome"],
                    "user_exists": auth_event["auth_user_exists"],
                    "reason": auth_event["auth_failure_reason"],
                }
            ).encode("utf-8") + b"\n"
        elif self.command == "POST":
            status = 200
            payload = b'{"status":"recorded","lab":"attack-simulation"}\n'
        content_type = "text/plain; charset=utf-8"
        if self.path == "/":
            content_type = "text/html; charset=utf-8"
        if self.command == "POST" or auth_event:
            content_type = "application/json"
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-AdversaryGraph-Lab", "attack-simulation")
        self.end_headers()
        if include_body:
            self.wfile.write(payload)
        self._log_access_event(status, len(payload) if include_body else 0, request_body, auth_event=auth_event)

    def _read_request_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            length = 0
        if length <= 0:
            return b""
        return self.rfile.read(min(length, 8192))

    def _log_access_event(self, status: int, response_bytes: int, request_body: bytes = b"", auth_event: dict[str, Any] | None = None) -> None:
        headers = {key: value for key, value in self.headers.items()}
        header_lookup = {key.lower(): value for key, value in headers.items()}
        parsed = parse.urlparse(self.path)
        query = parse.parse_qs(parsed.query, keep_blank_values=True)
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
            "clean_path": parsed.path,
            "query_keys": sorted(query.keys()),
            "protocol": self.request_version,
            "headers": headers,
            "body_length": len(request_body),
            "body_sha256": hashlib.sha256(request_body).hexdigest() if request_body else "",
            "body_preview": request_body[:160].decode("utf-8", errors="replace") if request_body else "",
            "matched_canaries": _classify_web_canaries(self.command, self.path, headers, request_body),
            "status": status,
            "response_bytes": response_bytes,
        }
        if auth_event:
            event.update(auth_event)
        _append_jsonl(_web_access_log_path(), event)
        _append_operational_web_logs(event)


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
    if clean_path == "/login":
        return b"login failed\n"
    if clean_path == "/login/user-check":
        return b'{"status":"recorded","lab":"attack-simulation"}\n'
    if clean_path.startswith("/api/"):
        return b'{"status":"ok","lab":"attack-simulation"}\n'
    if clean_path in {"/admin", "/download", "/fetch", "/proxy", "/cgi-bin/status", "/shell.php"}:
        return b"lab canary recorded\n"
    if clean_path.startswith("/downloads/"):
        return b"AG_BENIGN_DOWNLOAD_CANARY\n"
    return None


def _auth_event_for_request(method: str, path: str, body: bytes) -> dict[str, Any] | None:
    parsed = parse.urlparse(path)
    clean_path = parsed.path
    query = parse.parse_qs(parsed.query, keep_blank_values=True)
    body_fields = _parse_request_fields(body)
    fields = {**{key: values[-1] if values else "" for key, values in query.items()}, **body_fields}
    canary = str(fields.get("ag_canary") or "").lower()

    if method == "GET" and clean_path == "/login/user-check":
        username = str(fields.get("username") or "").strip()
        exists = username in LAB_AUTH_USERS
        return {
            "event_type": "lab_web_auth_enumeration",
            "auth_username": username,
            "auth_user_hash": _stable_hash(username),
            "auth_user_exists": exists,
            "auth_outcome": "user_exists" if exists else "user_unknown",
            "auth_failure_reason": "" if exists else "unknown_user",
            "credential_attack_type": "user_enumeration",
            "password_length": 0,
            "password_sha256": "",
            "status": 200 if exists else 404,
        }

    if method == "POST" and clean_path == "/login":
        username = str(fields.get("username") or "").strip()
        password = str(fields.get("password") or "")
        exists = username in LAB_AUTH_USERS
        success = exists and LAB_AUTH_USERS[username] == password
        attack_type = _credential_attack_type(canary, username=username, exists=exists)
        return {
            "event_type": "lab_web_auth",
            "auth_username": username,
            "auth_user_hash": _stable_hash(username),
            "auth_user_exists": exists,
            "auth_outcome": "success" if success else "failure",
            "auth_failure_reason": "" if success else ("bad_password" if exists else "unknown_user"),
            "credential_attack_type": attack_type,
            "password_length": len(password),
            "password_sha256": _stable_hash(password) if password else "",
            "status": 200 if success else (404 if not exists else 401),
        }

    return None


def _parse_request_fields(body: bytes) -> dict[str, str]:
    if not body:
        return {}
    text = body.decode("utf-8", errors="replace")
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            loaded = json.loads(stripped)
        except json.JSONDecodeError:
            return {}
        if isinstance(loaded, dict):
            return {str(key): str(value) for key, value in loaded.items()}
        return {}
    parsed = parse.parse_qs(text, keep_blank_values=True)
    return {key: values[-1] if values else "" for key, values in parsed.items()}


def _credential_attack_type(canary: str, username: str, exists: bool) -> str:
    if "brute_force" in canary:
        return "brute_force"
    if "password_spray" in canary:
        return "password_spray"
    if "user_enumeration" in canary or not exists:
        return "user_enumeration"
    if "failed_login" in canary:
        return "failed_login"
    return "login"


def _stable_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _classify_web_canaries(method: str, path: str, headers: dict[str, str], body: bytes) -> list[str]:
    haystack = " ".join(
        [
            method,
            parse.unquote_plus(path),
            " ".join(f"{key}:{value}" for key, value in headers.items()),
            body.decode("utf-8", errors="replace"),
        ]
    ).lower()
    indicators = {
        "path_traversal": ["../", "%2e%2e", "etc/passwd", "win.ini"],
        "sqli": ["' or '1'='1", "ag_canary=sqli"],
        "xss": ["<script>", "ag_xss_canary", "ag_canary=xss"],
        "ssrf": ["169.254.169.254", "127.0.0.1:22", "ag_canary=ssrf"],
        "command_injection": ["cmd=id", '"command":"whoami"', "ag_canary=command_injection"],
        "webshell": ["shell.php", "cmd.aspx", "ag_canary=webshell"],
        "tool_transfer": ["agent.ps1", "ag_benign_upload_canary", "ag_canary=tool_download"],
        "secret_exposure": ["/.env", "config.php.bak", "/id_rsa", "ag_canary=secret_exposure"],
        "failed_login": ["ag_canary=failed_login", "password=wrong"],
        "brute_force": ["ag_canary=brute_force"],
        "password_spray": ["ag_canary=password_spray"],
        "user_enumeration": ["ag_canary=user_enumeration", "/login/user-check"],
        "beacon": ["ag_canary=beacon", "/api/ping", "/api/telemetry"],
        "exfil": ["ag_canary=exfil", "ag_exfil_canary", "/api/export", "/collect"],
        "admin_discovery": ["/admin", "/.git/config", "/backup.zip"],
    }
    matches: list[str] = []
    for name, needles in indicators.items():
        if any(needle in haystack for needle in needles):
            matches.append(name)
    return matches


def _ensure_log_dir() -> Path:
    path = Path(settings.log_dir) / "attack-simulation"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _attack_log_path(run_id: str) -> Path:
    return _ensure_log_dir() / f"{run_id}.jsonl"


def _web_access_log_path() -> Path:
    return _ensure_log_dir() / "lab-web-access.jsonl"


def _web_server_access_log_path() -> Path:
    return _ensure_log_dir() / "lab-web-access.log"


def _web_security_log_path() -> Path:
    return _ensure_log_dir() / "lab-web-security.log"


def _web_error_log_path() -> Path:
    return _ensure_log_dir() / "lab-web-error.log"


def _web_auth_log_path() -> Path:
    return _ensure_log_dir() / "lab-web-auth.log"


def _shared_lab_web_log_paths() -> list[Path]:
    return [
        _web_access_log_path(),
        _web_server_access_log_path(),
        _web_security_log_path(),
        _web_error_log_path(),
        _web_auth_log_path(),
    ]


def clear_shared_lab_web_logs() -> list[str]:
    cleared: list[str] = []
    for path in _shared_lab_web_log_paths():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
        cleared.append(str(path))
    return cleared


def _append_jsonl(path: Path, event: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")


def _append_text_line(path: Path, line: str) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line.rstrip("\n") + "\n")


def _append_operational_web_logs(event: dict[str, Any]) -> None:
    _append_text_line(_web_server_access_log_path(), _format_web_access_line(event))
    matches = event.get("matched_canaries") or []
    if matches:
        for category in matches:
            _append_text_line(_web_security_log_path(), _format_web_security_line(event, str(category)))
    if event.get("credential_attack_type") or str(event.get("event_type") or "").startswith("lab_web_auth"):
        _append_text_line(_web_auth_log_path(), _format_web_auth_line(event))
    status = int(event.get("status") or 0)
    if status >= 400:
        _append_text_line(_web_error_log_path(), _format_web_error_line(event))


def _format_web_access_line(event: dict[str, Any]) -> str:
    timestamp = _apache_log_time(str(event.get("timestamp") or ""))
    client_ip = str(event.get("client_ip") or "-")
    method = str(event.get("method") or "-")
    path = str(event.get("path") or "-").replace('"', r'\"')
    protocol = str(event.get("protocol") or "HTTP/1.1")
    status = int(event.get("status") or 0)
    response_bytes = int(event.get("response_bytes") or 0)
    headers = event.get("headers") if isinstance(event.get("headers"), dict) else {}
    referer = str(headers.get("Referer") or "-").replace('"', r'\"')
    user_agent = str(headers.get("User-Agent") or "-").replace('"', r'\"')
    run_id = str(event.get("run_id") or "-")
    simulation_id = str(event.get("simulation_id") or "-")
    body_length = int(event.get("body_length") or 0)
    matches = ",".join(str(item) for item in event.get("matched_canaries") or []) or "-"
    auth_user = str(event.get("auth_username") or "-").replace('"', r'\"')
    auth_outcome = str(event.get("auth_outcome") or "-").replace('"', r'\"')
    return (
        f'{client_ip} - - [{timestamp}] "{method} {path} {protocol}" {status} {response_bytes} '
        f'"{referer}" "{user_agent}" rt=0.001 run_id="{run_id}" simulation_id="{simulation_id}" '
        f'body_bytes={body_length} canaries="{matches}" auth_user="{auth_user}" auth_outcome="{auth_outcome}"'
    )


def _format_web_security_line(event: dict[str, Any], category: str) -> str:
    timestamp = str(event.get("timestamp") or datetime.now(timezone.utc).isoformat())
    client_ip = str(event.get("client_ip") or "-")
    method = str(event.get("method") or "-")
    path = str(event.get("path") or "-").replace('"', r'\"')
    clean_path = str(event.get("clean_path") or "-").replace('"', r'\"')
    run_id = str(event.get("run_id") or "-")
    simulation_id = str(event.get("simulation_id") or "-")
    status = int(event.get("status") or 0)
    body_sha = str(event.get("body_sha256") or "-")
    severity = _security_severity(category)
    rule_id = _security_rule_id(category)
    return (
        f'{timestamp} attack-simulation-waf alert_id="{rule_id}" severity="{severity}" '
        f'category="{category}" client="{client_ip}" method="{method}" uri="{path}" clean_uri="{clean_path}" '
        f'status={status} run_id="{run_id}" simulation_id="{simulation_id}" body_sha256="{body_sha}" '
        f'msg="Matched AdversaryGraph {category} canary in lab web telemetry"'
    )


def _format_web_error_line(event: dict[str, Any]) -> str:
    timestamp = str(event.get("timestamp") or datetime.now(timezone.utc).isoformat())
    client_ip = str(event.get("client_ip") or "-")
    method = str(event.get("method") or "-")
    path = str(event.get("path") or "-").replace('"', r'\"')
    status = int(event.get("status") or 0)
    run_id = str(event.get("run_id") or "-")
    simulation_id = str(event.get("simulation_id") or "-")
    return (
        f'[{timestamp}] [error] [client {client_ip}] lab web server returned HTTP {status}, '
        f'request="{method} {path}" run_id="{run_id}" simulation_id="{simulation_id}"'
    )


def _format_web_auth_line(event: dict[str, Any]) -> str:
    timestamp = str(event.get("timestamp") or datetime.now(timezone.utc).isoformat())
    client_ip = str(event.get("client_ip") or "-")
    username = str(event.get("auth_username") or "-").replace('"', r'\"')
    user_hash = str(event.get("auth_user_hash") or "-")
    exists = str(bool(event.get("auth_user_exists"))).lower()
    outcome = str(event.get("auth_outcome") or "-")
    reason = str(event.get("auth_failure_reason") or "-")
    attack_type = str(event.get("credential_attack_type") or "-")
    method = str(event.get("method") or "-")
    path = str(event.get("path") or "-").replace('"', r'\"')
    run_id = str(event.get("run_id") or "-")
    simulation_id = str(event.get("simulation_id") or "-")
    status = int(event.get("status") or 0)
    password_length = int(event.get("password_length") or 0)
    password_sha = str(event.get("password_sha256") or "-")
    return (
        f'{timestamp} adversarygraph-lab-auth event="{outcome}" attack_type="{attack_type}" '
        f'user="{username}" user_hash="{user_hash}" user_exists={exists} src="{client_ip}" '
        f'method="{method}" uri="{path}" status={status} failure_reason="{reason}" '
        f'password_len={password_length} password_sha256="{password_sha}" run_id="{run_id}" '
        f'simulation_id="{simulation_id}"'
    )


def _security_rule_id(category: str) -> str:
    digest = hashlib.sha1(category.encode("utf-8")).hexdigest()[:6].upper()
    return f"AG-WEB-{digest}"


def _security_severity(category: str) -> str:
    if category in {"webshell", "command_injection", "exfil", "secret_exposure", "brute_force", "password_spray"}:
        return "high"
    if category in {"sqli", "xss", "ssrf", "path_traversal", "failed_login", "user_enumeration"}:
        return "medium"
    return "low"


def _apache_log_time(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        parsed = datetime.now(timezone.utc)
    return parsed.strftime("%d/%b/%Y:%H:%M:%S %z")


def tail_telemetry_logs(source: str = "web", run_id: str = "", limit: int = 100) -> dict[str, Any]:
    limit = max(1, min(limit, 500))
    if source not in LOG_SOURCES:
        raise ValueError("Unknown telemetry log source")
    if source == "run":
        if not _RUN_ID_RE.match(run_id):
            raise ValueError("A valid run_id is required for run telemetry logs")
        path = _attack_log_path(run_id)
        events = _tail_jsonl(path, limit=limit, run_id="")
    elif source == "web":
        path = _web_access_log_path()
        events = _tail_jsonl(path, limit=limit, run_id=run_id)
    else:
        paths = {
            "access": _web_server_access_log_path(),
            "security": _web_security_log_path(),
            "error": _web_error_log_path(),
            "auth": _web_auth_log_path(),
        }
        path = paths[source]
        events = _tail_text_log(path, source=source, limit=limit, run_id=run_id)

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
    auth_type: str = "none",
    username: str = "",
    password: str = "",
    token: str = "",
    header_name: str = "",
    connection_mode: str = "auto",
    allow_http_fallback: bool = True,
    payload_format: str = "per_event",
) -> dict[str, Any]:
    destination = _validate_siem_destination(destination_url, connection_mode=connection_mode)
    logs = tail_telemetry_logs(source=source, run_id=run_id, limit=limit)
    if payload_format not in {"per_event", "json_lines", "envelope"}:
        raise ValueError("Unsupported SIEM payload format")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "AdversaryGraph-AttackSimulation-Forwarder/1.0",
        "X-AdversaryGraph-Module": "attack-simulation",
        "X-AdversaryGraph-Run-Id": run_id,
        "X-Xpolog-Sender": "adversarygraph-attack-simulation",
    }
    headers.update(_siem_auth_headers(auth_type, username=username, password=password, token=token, header_name=header_name))
    started = time.perf_counter()
    if payload_format == "per_event":
        return _forward_siem_events_individually(
            destination=destination,
            logs=logs,
            headers=headers,
            started=started,
            original_destination=destination_url,
            connection_mode=connection_mode,
            allow_http_fallback=allow_http_fallback,
        )
    body = _siem_payload_body(logs, payload_format)
    result, fallback_note = _post_siem_payload(
        destination=destination,
        body=body,
        headers=headers,
        started=started,
        original_destination=destination_url,
        connection_mode=connection_mode,
        allow_http_fallback=allow_http_fallback,
    )
    result.update(
        {
            "source": source,
            "run_id": run_id,
            "event_count": logs["line_count"],
            "duration_ms": round((time.perf_counter() - started) * 1000, 3),
            "http_fallback_used": bool(fallback_note),
            "fallback_note": fallback_note,
            "payload_format": payload_format,
            "sent_event_count": logs["line_count"],
        }
    )
    return result


def _siem_payload_body(logs: dict[str, Any], payload_format: str) -> bytes:
    if payload_format == "json_lines":
        lines = [_siem_event_payload(event, logs) for event in logs["events"]]
        return ("\n".join(json.dumps(item, sort_keys=True) for item in lines) + "\n").encode("utf-8")
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
    return json.dumps(payload).encode("utf-8")


def _siem_event_payload(event: dict[str, Any], logs: dict[str, Any]) -> dict[str, Any]:
    payload = {
        "product": "AdversaryGraph",
        "module": "Attack Simulation",
        "source": logs["source"],
        "run_id": event.get("run_id") or logs["run_id"],
        "event_type": event.get("event_type", "attack_simulation_event"),
        "time": event.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "message": _siem_event_message(event),
    }
    payload.update(event)
    return payload


def _siem_event_message(event: dict[str, Any]) -> str:
    parts = [
        str(event.get("event_type") or "attack_simulation_event"),
        str(event.get("simulation_id") or ""),
        str(event.get("method") or ""),
        str(event.get("path") or event.get("url") or ""),
        str(event.get("run_id") or ""),
        str(event.get("analyst_note") or ""),
    ]
    return " ".join(item for item in parts if item)


def _forward_siem_events_individually(
    destination: str,
    logs: dict[str, Any],
    headers: dict[str, str],
    started: float,
    original_destination: str,
    connection_mode: str,
    allow_http_fallback: bool,
) -> dict[str, Any]:
    events = logs["events"] or [
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "attack_simulation_no_events",
            "run_id": logs["run_id"],
            "message": "No Attack Simulation telemetry events matched the selected source/run filter.",
        }
    ]
    sent = 0
    last_result: dict[str, Any] | None = None
    fallback_used = False
    fallback_note = ""
    errors: list[str] = []
    for event in events:
        body = json.dumps(_siem_event_payload(event, logs), sort_keys=True).encode("utf-8")
        result, note = _post_siem_payload(
            destination=destination,
            body=body,
            headers=headers,
            started=started,
            original_destination=original_destination,
            connection_mode=connection_mode,
            allow_http_fallback=allow_http_fallback,
        )
        last_result = result
        fallback_used = fallback_used or bool(note)
        fallback_note = fallback_note or note
        if result["ok"]:
            sent += 1
        else:
            errors.append(result.get("error") or f"HTTP {result.get('status')}")
            break
    ok = sent == len(events) and not errors
    return {
        "ok": ok,
        "status": int(last_result.get("status", 0)) if last_result else 0,
        "destination_url": last_result.get("destination_url", _redact_siem_destination(destination)) if last_result else _redact_siem_destination(destination),
        "connection_mode": connection_mode,
        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
        "error": "" if ok else "; ".join(errors),
        "response_preview": last_result.get("response_preview", "") if last_result else "",
        "response_headers": last_result.get("response_headers", {}) if last_result else {},
        "source": logs["source"],
        "run_id": logs["run_id"],
        "event_count": logs["line_count"],
        "http_fallback_used": fallback_used,
        "fallback_note": fallback_note,
        "payload_format": "per_event",
        "sent_event_count": sent,
    }


def _post_siem_payload(
    destination: str,
    body: bytes,
    headers: dict[str, str],
    started: float,
    original_destination: str,
    connection_mode: str,
    allow_http_fallback: bool,
) -> tuple[dict[str, Any], str]:
    _ensure_strict_loopback_bridge(destination, connection_mode)
    try:
        return _post_siem_payload_once(destination, body, headers, started, original_destination, connection_mode), ""
    except URLError as exc:
        error = str(exc.reason)
        fallback_destination = _http_fallback_destination(destination)
        if allow_http_fallback and fallback_destination and _is_tls_protocol_error(error):
            fallback_result = _post_siem_payload_once(fallback_destination, body, headers, started, original_destination, connection_mode)
            return fallback_result, "HTTPS failed with a TLS protocol error; retried the same destination with http://."
        return {
            "ok": False,
            "status": 0,
            "destination_url": _redact_siem_destination(destination),
            "connection_mode": connection_mode,
            "error": _siem_connection_error(str(exc.reason), original_destination, destination, connection_mode),
            "response_preview": "",
            "response_headers": {},
        }, ""


def _post_siem_payload_once(
    destination: str,
    body: bytes,
    headers: dict[str, str],
    started: float,
    original_destination: str,
    connection_mode: str,
) -> dict[str, Any]:
    req = request.Request(destination, data=body, method="POST", headers=headers)
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
    return {
        "ok": ok,
        "status": status,
        "destination_url": _redact_siem_destination(destination),
        "connection_mode": connection_mode,
        "duration_ms": round((time.perf_counter() - started) * 1000, 3),
        "error": "" if ok else response_body[:500],
        "response_preview": response_body[:500],
        "response_headers": response_headers,
    }


def _http_fallback_destination(destination: str) -> str:
    parsed = parse.urlparse(destination)
    if parsed.scheme != "https":
        return ""
    return parse.urlunparse(parsed._replace(scheme="http"))


def _is_tls_protocol_error(error: str) -> bool:
    lowered = error.lower()
    return "wrong version number" in lowered or "record layer failure" in lowered or "unknown protocol" in lowered


def _ensure_strict_loopback_bridge(destination: str, connection_mode: str) -> None:
    if connection_mode != "direct" or not _running_in_container():
        return
    parsed = parse.urlparse(destination)
    if parsed.hostname not in {"127.0.0.1", "localhost"} or not parsed.port:
        return
    port = parsed.port
    if port == _LAB_WEB_PORT:
        return
    with _LOOPBACK_BRIDGES_LOCK:
        if port in _LOOPBACK_BRIDGES:
            return
        ready = threading.Event()
        failed: list[str] = []
        thread = threading.Thread(
            target=_run_loopback_host_bridge,
            args=(port, ready, failed),
            name=f"siem-loopback-bridge-{port}",
            daemon=True,
        )
        thread.start()
        ready.wait(timeout=1.5)
        if failed:
            logger.info("Strict loopback bridge not started for port %s: %s", port, failed[0])
            return
        _LOOPBACK_BRIDGES.add(port)
        logger.info("Started strict loopback SIEM bridge 127.0.0.1:%s -> host.docker.internal:%s", port, port)


def _run_loopback_host_bridge(port: int, ready: threading.Event, failed: list[str]) -> None:
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", port))
        server.listen(20)
    except OSError as exc:
        failed.append(str(exc))
        ready.set()
        return
    ready.set()
    while True:
        try:
            client, _ = server.accept()
        except OSError:
            return
        threading.Thread(target=_handle_loopback_bridge_client, args=(client, port), daemon=True).start()


def _handle_loopback_bridge_client(client: socket.socket, port: int) -> None:
    upstream: socket.socket | None = None
    try:
        upstream = socket.create_connection(("host.docker.internal", port), timeout=5)
        client.setblocking(False)
        upstream.setblocking(False)
        sockets = [client, upstream]
        while True:
            readable, _, errored = select.select(sockets, [], sockets, 15)
            if errored:
                return
            if not readable:
                return
            for source in readable:
                try:
                    data = source.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                target = upstream if source is client else client
                target.sendall(data)
    except OSError as exc:
        logger.warning("Strict loopback SIEM bridge failed for port %s: %s", port, exc)
    finally:
        try:
            client.close()
        except OSError:
            pass
        if upstream is not None:
            try:
                upstream.close()
            except OSError:
                pass


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


def _tail_text_log(path: Path, source: str, limit: int, run_id: str = "") -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            raw = line.rstrip("\n")
            if not raw:
                continue
            if run_id and run_id not in raw:
                continue
            event = _text_log_event(source, raw, line_number)
            events.append(event)
            if len(events) > limit:
                events = events[-limit:]
    return events


def _text_log_event(source: str, raw: str, line_number: int) -> dict[str, Any]:
    event: dict[str, Any] = {
        "timestamp": _timestamp_from_log_line(raw) or datetime.now(timezone.utc).isoformat(),
        "event_type": f"lab_web_{source}_log",
        "source": source,
        "line_number": line_number,
        "raw_line": raw,
        "message": raw,
    }
    run_match = re.search(r'run_id="?([^"\s]+)"?', raw)
    sim_match = re.search(r'simulation_id="?([^"\s]+)"?', raw)
    method_path_match = re.search(r'"(GET|POST|HEAD|PUT|DELETE|PATCH|OPTIONS)\s+([^"\s]+)', raw)
    status_match = re.search(r'"\s+(\d{3})\s+', raw) or re.search(r"\bHTTP\s+(\d{3})\b", raw) or re.search(r"\bstatus=(\d{3})\b", raw)
    client_match = re.search(r"^(\S+)\s", raw) or re.search(r'client="?([^"\s]+)"?', raw) or re.search(r"\[client ([^\]]+)\]", raw)
    if run_match:
        event["run_id"] = run_match.group(1)
    if sim_match:
        event["simulation_id"] = sim_match.group(1)
    if method_path_match:
        event["method"] = method_path_match.group(1)
        event["path"] = method_path_match.group(2)
    if status_match:
        event["status"] = int(status_match.group(1))
    if client_match:
        event["client_ip"] = client_match.group(1)
    if source == "security":
        category_match = re.search(r'category="([^"]+)"', raw)
        severity_match = re.search(r'severity="([^"]+)"', raw)
        if category_match:
            event["matched_canaries"] = [category_match.group(1)]
        if severity_match:
            event["severity"] = severity_match.group(1)
    if source == "auth":
        for key, field in {
            "auth_outcome": "event",
            "credential_attack_type": "attack_type",
            "auth_username": "user",
            "auth_user_hash": "user_hash",
            "auth_failure_reason": "failure_reason",
            "password_sha256": "password_sha256",
        }.items():
            match = re.search(rf'{field}="([^"]*)"', raw)
            if match:
                event[key] = match.group(1)
        exists_match = re.search(r"\buser_exists=(true|false)\b", raw)
        password_len_match = re.search(r"\bpassword_len=(\d+)\b", raw)
        if exists_match:
            event["auth_user_exists"] = exists_match.group(1) == "true"
        if password_len_match:
            event["password_length"] = int(password_len_match.group(1))
    return event


def _timestamp_from_log_line(raw: str) -> str:
    iso_match = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\+00:00|Z)?)", raw)
    if iso_match:
        return iso_match.group(1)
    apache_match = re.search(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]", raw)
    if apache_match:
        try:
            return datetime.strptime(apache_match.group(1), "%d/%b/%Y:%H:%M:%S %z").isoformat()
        except ValueError:
            return ""
    return ""


def _validate_siem_destination(destination_url: str, connection_mode: str = "auto") -> str:
    destination = destination_url.strip()
    if not destination:
        raise ValueError("SIEM destination URL is required")
    if connection_mode not in {"auto", "direct", "docker_host"}:
        raise ValueError("Unsupported SIEM connection mode")
    if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", destination):
        destination = f"http://{destination}"
    parsed = parse.urlparse(destination)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("SIEM destination must use http or https")
    if not parsed.hostname:
        raise ValueError("SIEM destination host is required")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in SIEM URL are not allowed; use the SIEM authentication fields instead")

    hostname = parsed.hostname.lower()
    use_docker_host = connection_mode == "docker_host" or (connection_mode == "auto" and _running_in_container())
    if hostname in {"0.0.0.0", "::"}:
        replacement_host = "host.docker.internal" if use_docker_host else "127.0.0.1"
        netloc = replacement_host
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
        parsed = parsed._replace(netloc=netloc)
        hostname = replacement_host
    elif hostname in {"localhost", "127.0.0.1"} and use_docker_host:
        netloc = "host.docker.internal"
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
        parsed = parsed._replace(netloc=netloc)
        hostname = "host.docker.internal"
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


def _redact_siem_destination(destination: str) -> str:
    parsed = parse.urlparse(destination)
    if not parsed.query:
        return destination
    sensitive = {"api_key", "apikey", "key", "secret", "password", "pass", "auth", "access_token", "bearer"}
    pairs = parse.parse_qsl(parsed.query, keep_blank_values=True)
    redacted_pairs = [(key, "REDACTED" if key.lower() in sensitive else value) for key, value in pairs]
    return parse.urlunparse(parsed._replace(query=parse.urlencode(redacted_pairs)))


def _running_in_container() -> bool:
    if Path("/.dockerenv").exists():
        return True
    cgroup = Path("/proc/1/cgroup")
    if not cgroup.exists():
        return False
    try:
        content = cgroup.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False
    return "docker" in content or "kubepods" in content or "containerd" in content


def _siem_connection_error(error: str, original_destination: str, connection_destination: str, connection_mode: str) -> str:
    original_host = parse.urlparse(original_destination.strip() if "://" in original_destination else f"http://{original_destination.strip()}").hostname
    connection_host = parse.urlparse(connection_destination).hostname
    if "wrong version number" in error or "record layer failure" in error or "unknown protocol" in error:
        return (
            f"{error}. TLS handshake failed. The collector is probably HTTP, not HTTPS. "
            "Change the destination scheme to http:// or enable TLS on the collector."
        )
    if (
        connection_mode == "direct"
        and original_host in {"localhost", "127.0.0.1"}
        and _running_in_container()
        and "Connection refused" in error
    ):
        return (
            f"{error}. Direct mode preserves localhost/127.0.0.1 inside the API container. "
            "For a collector running on the Docker host, choose Docker host gateway or Auto connection route."
        )
    if original_host in {"localhost", "127.0.0.1"} and connection_host == "host.docker.internal":
        return (
            f"{error}. Docker translated localhost/127.0.0.1 to host.docker.internal. "
            "If the SIEM collector runs on the host, make sure it is listening on the host network interface "
            "or 0.0.0.0, not only on loopback, and use the correct http/https scheme."
        )
    return error


def _siem_auth_headers(
    auth_type: str,
    username: str = "",
    password: str = "",
    token: str = "",
    header_name: str = "",
) -> dict[str, str]:
    if auth_type == "none":
        return {}
    if auth_type == "bearer":
        if not token:
            raise ValueError("Bearer authentication requires a token")
        return {"Authorization": f"Bearer {token}"}
    if auth_type == "token":
        if not token:
            raise ValueError("Token authentication requires a token")
        return {"Authorization": f"Token {token}"}
    if auth_type == "basic":
        if not username or not password:
            raise ValueError("Basic authentication requires username and password")
        encoded = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        return {"Authorization": f"Basic {encoded}"}
    if auth_type == "custom_header":
        if not header_name or not token:
            raise ValueError("Custom header authentication requires header name and token")
        if not re.match(r"^[A-Za-z0-9-]{1,80}$", header_name):
            raise ValueError("Custom auth header name contains invalid characters")
        if header_name.lower() in {"host", "content-length", "content-type", "user-agent"}:
            raise ValueError("This custom auth header name is reserved")
        return {header_name: token}
    raise ValueError("Unsupported SIEM authentication type")
