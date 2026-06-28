from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
from urllib import parse


HOST = os.environ.get("ATTACK_LAB_WEB_HOST", "127.0.0.1")
PORT = int(os.environ.get("ATTACK_LAB_WEB_PORT", "8081"))
LOG_DIR = Path(os.environ.get("ATTACK_LAB_WEB_LOG_DIR", "/app/logs")) / "attack-simulation"
LOG_DIR.mkdir(parents=True, exist_ok=True)

LAB_AUTH_USERS = {
    "admin": "CorrectHorseBattery1!",
    "alice": "Wonderland-2026!",
    "bob": "Builder-2026!",
    "service": "Service-Token-2026!",
}


class AttackLabWebHandler(BaseHTTPRequestHandler):
    server_version = "AdversaryGraphAttackLabWeb/1.0"

    def do_HEAD(self) -> None:
        self._handle_request(include_body=False)

    def do_GET(self) -> None:
        self._handle_request(include_body=True)

    def do_POST(self) -> None:
        self._handle_request(include_body=True)

    def log_message(self, *_args) -> None:
        return

    def _handle_request(self, include_body: bool) -> None:
        request_body = self._read_request_body()
        if self.path.split("?", 1)[0] == "/health":
            payload = b"ok\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if include_body:
                self.wfile.write(payload)
            return
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
        self._log_access_event(status, len(payload) if include_body else 0, request_body, auth_event)

    def _read_request_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            length = 0
        if length <= 0:
            return b""
        return self.rfile.read(min(length, 8192))

    def _log_access_event(
        self,
        status: int,
        response_bytes: int,
        request_body: bytes,
        auth_event: dict[str, object] | None,
    ) -> None:
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
            "client_ip": _client_ip_from_headers(header_lookup, self.client_address[0]),
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
            b"<html><head><title>AdversaryGraph Attack Lab Web</title></head>"
            b"<body><h1>AdversaryGraph Docker Attack Lab Target</h1></body></html>\n"
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


def _auth_event_for_request(method: str, path: str, body: bytes) -> dict[str, object] | None:
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
        attack_type = _credential_attack_type(canary, exists=exists)
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


def _credential_attack_type(canary: str, exists: bool) -> str:
    if "brute_force" in canary:
        return "brute_force"
    if "password_spray" in canary:
        return "password_spray"
    if "user_enumeration" in canary or not exists:
        return "user_enumeration"
    if "failed_login" in canary:
        return "failed_login"
    return "login"


def _client_ip_from_headers(headers: dict[str, str], fallback: str) -> str:
    forwarded_for = str(headers.get("x-forwarded-for") or "").split(",", 1)[0].strip()
    if forwarded_for:
        return forwarded_for
    real_ip = str(headers.get("x-real-ip") or "").strip()
    return real_ip or fallback


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
    return [name for name, needles in indicators.items() if any(needle in haystack for needle in needles)]


def _append_operational_web_logs(event: dict[str, object]) -> None:
    for category in event.get("matched_canaries") or []:
        _append_text_line(_web_security_log_path(), _format_web_security_line(event, str(category)))
    if event.get("credential_attack_type") or str(event.get("event_type") or "").startswith("lab_web_auth"):
        _append_text_line(_web_auth_log_path(), _format_web_auth_line(event))


def _format_web_security_line(event: dict[str, object], category: str) -> str:
    return (
        f'{event.get("timestamp") or datetime.now(timezone.utc).isoformat()} attack-simulation-waf '
        f'alert_id="{_security_rule_id(category)}" severity="{_security_severity(category)}" '
        f'category="{category}" client="{event.get("client_ip") or "-"}" method="{event.get("method") or "-"}" '
        f'uri="{str(event.get("path") or "-").replace(chr(34), r"\"")}" '
        f'clean_uri="{str(event.get("clean_path") or "-").replace(chr(34), r"\"")}" '
        f'status={int(event.get("status") or 0)} run_id="{event.get("run_id") or "-"}" '
        f'simulation_id="{event.get("simulation_id") or "-"}" body_sha256="{event.get("body_sha256") or "-"}" '
        f'msg="Matched AdversaryGraph {category} canary in Docker lab web telemetry"'
    )


def _format_web_auth_line(event: dict[str, object]) -> str:
    return (
        f'{event.get("timestamp") or datetime.now(timezone.utc).isoformat()} adversarygraph-lab-auth '
        f'event="{event.get("auth_outcome") or "-"}" attack_type="{event.get("credential_attack_type") or "-"}" '
        f'user="{str(event.get("auth_username") or "-").replace(chr(34), r"\"")}" '
        f'user_hash="{event.get("auth_user_hash") or "-"}" user_exists={str(bool(event.get("auth_user_exists"))).lower()} '
        f'src="{event.get("client_ip") or "-"}" method="{event.get("method") or "-"}" '
        f'uri="{str(event.get("path") or "-").replace(chr(34), r"\"")}" status={int(event.get("status") or 0)} '
        f'failure_reason="{event.get("auth_failure_reason") or "-"}" '
        f'password_len={int(event.get("password_length") or 0)} password_sha256="{event.get("password_sha256") or "-"}" '
        f'run_id="{event.get("run_id") or "-"}" simulation_id="{event.get("simulation_id") or "-"}"'
    )


def _security_rule_id(category: str) -> str:
    return f"AG-WEB-{hashlib.sha1(category.encode('utf-8')).hexdigest()[:6].upper()}"


def _security_severity(category: str) -> str:
    if category in {"webshell", "command_injection", "exfil", "secret_exposure", "brute_force", "password_spray"}:
        return "high"
    if category in {"sqli", "xss", "ssrf", "path_traversal", "failed_login", "user_enumeration"}:
        return "medium"
    return "low"


def _stable_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _web_access_log_path() -> Path:
    return LOG_DIR / "lab-web-access.jsonl"


def _web_security_log_path() -> Path:
    return LOG_DIR / "lab-web-security.log"


def _web_auth_log_path() -> Path:
    return LOG_DIR / "lab-web-auth.log"


def _append_jsonl(path: Path, event: dict[str, object]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")


def _append_text_line(path: Path, line: str) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line.rstrip("\n") + "\n")


if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), AttackLabWebHandler)
    print(f"AdversaryGraph Docker attack lab web target listening on {HOST}:{PORT}", flush=True)
    server.serve_forever()
