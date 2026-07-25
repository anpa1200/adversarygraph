"""Bounded network tools exposed by the scanner MCP service.

No function accepts arbitrary command-line arguments, template paths, shell
fragments, request bodies, credentials, or redirect targets. The caller selects
only fixed profiles and supplies one normalized inventory target.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import socket
import ssl
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Any, Awaitable, Callable
from urllib.parse import urlsplit

from defusedxml import ElementTree as ET
import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from .config import settings
from .models import ScanTarget, normalize_ip, normalize_target


SCANNER_IDS = ("nmap", "web", "tls", "dns", "nuclei")
ADDITIONAL_SCANNERS = ("tls", "dns", "nuclei")
_SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content-Security-Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
}


def scanner_catalog() -> dict[str, Any]:
    nuclei_ready = _executable_ready(Path(settings.nuclei_binary)) and _directory_ready(
        Path(settings.nuclei_templates)
    )
    return {
        "service": "adversarygraph-scanner-mcp",
        "version": "1.0.0",
        "transport": "streamable-http",
        "execution_boundary": "isolated-container",
        "tools": [
            {
                "id": "resolve",
                "enabled": True,
                "profile": "bounded-address-resolution",
                "mode": "passive-network",
            },
            {
                "id": "nmap",
                "label": "Nmap safe service discovery",
                "enabled": settings.nmap_enabled
                and _executable_ready(Path(settings.nmap_binary)),
                "configured": settings.nmap_enabled,
                "profile": "safe-service-discovery",
                "mode": "active-authorized",
                "timeout_seconds": settings.nmap_timeout_seconds,
                "top_ports": settings.nmap_top_ports,
                "boundary": (
                    "Unprivileged TCP connect and light service detection only. "
                    "No NSE scripts, UDP scan, OS fingerprinting, evasion, or exploitation."
                ),
            },
            {
                "id": "web",
                "label": "Root HTTP security posture",
                "enabled": settings.web_probe_enabled,
                "configured": settings.web_probe_enabled,
                "profile": "safe-root-http-posture",
                "mode": "active-bounded",
                "timeout_seconds": settings.web_probe_timeout_seconds,
                "boundary": (
                    "At most two root HTTP(S) GET requests. No redirect following, "
                    "crawling, form submission, injection payload, brute force, or exploitation."
                ),
            },
            {
                "id": "tls",
                "label": "TLS certificate and protocol",
                "enabled": settings.tls_enabled,
                "configured": settings.tls_enabled,
                "profile": "verified-tls-handshake",
                "mode": "active-bounded",
                "timeout_seconds": settings.tls_timeout_seconds,
                "boundary": (
                    "One verified TLS handshake to the exact inventory target. "
                    "No downgrade, renegotiation flood, or cipher-exhaustion testing."
                ),
            },
            {
                "id": "dns",
                "label": "DNS security posture",
                "enabled": settings.dns_enabled,
                "configured": settings.dns_enabled,
                "profile": "read-only-dns-posture",
                "mode": "passive-network",
                "timeout_seconds": settings.dns_timeout_seconds,
                "boundary": (
                    "Read-only A, AAAA, CAA, TXT, DNSKEY, and DMARC queries. "
                    "No zone transfer, brute force, wildcard enumeration, or mutation."
                ),
            },
            {
                "id": "nuclei",
                "label": "Nuclei vulnerability detection",
                "enabled": settings.nuclei_enabled and nuclei_ready,
                "configured": settings.nuclei_enabled,
                "profile": "signed-bounded-network-templates",
                "mode": "active-authorized",
                "timeout_seconds": settings.nuclei_timeout_seconds,
                "rate_limit_per_second": settings.nuclei_rate_limit,
                "template_concurrency": settings.nuclei_concurrency,
                "engine": "Nuclei v3.11.0 source snapshot 6ecdb947 (dependency-hardened)",
                "templates": "Nuclei Templates v10.4.6",
                "boundary": (
                    "Pinned signed HTTP, TLS, and DNS templates with operator-capped rate "
                    "and concurrency. Fuzzing, headless, code, file, JavaScript, "
                    "brute-force, intrusive, denial-of-service, and out-of-band templates "
                    "are excluded."
                ),
            },
        ],
    }


async def resolve_target(target: ScanTarget) -> list[str]:
    normalized_ip = normalize_ip(target.host)
    if normalized_ip:
        return [normalized_ip]
    try:
        async with asyncio.timeout(5):
            rows = await asyncio.get_running_loop().run_in_executor(
                None,
                lambda: socket.getaddrinfo(target.host, None, type=socket.SOCK_STREAM),
            )
    except (TimeoutError, OSError, socket.gaierror):
        return []
    addresses: list[str] = []
    for row in rows:
        address = normalize_ip(str(row[4][0]))
        if address and address not in addresses:
            addresses.append(address)
    return addresses[: settings.max_resolved_ips]


async def run_nmap(target: ScanTarget) -> dict[str, Any]:
    if not settings.nmap_enabled:
        return _disabled("nmap", "Nmap discovery is disabled by the operator.")
    resolved_ips = await resolve_target(target)
    if target.target_type != "ip" and not resolved_ips:
        return {
            "status": "unresolved",
            "scanner": "nmap",
            "summary": "The inventory hostname could not be resolved; Nmap was not started.",
            "hosts": [],
            "services": [],
            "open_port_count": 0,
        }
    scan_targets = resolved_ips or [target.host]
    command = [
        settings.nmap_binary,
        "-Pn",
        "-sT",
        "-sV",
        "--version-light",
        "--open",
        "-T3",
        "--max-retries",
        "2",
        "--host-timeout",
        f"{settings.nmap_timeout_seconds}s",
        "--top-ports",
        str(settings.nmap_top_ports),
        "-oX",
        "-",
        *scan_targets,
    ]
    started = datetime.now(UTC)
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return {
            "status": "unavailable",
            "scanner": "nmap",
            "summary": "The fixed Nmap executable is unavailable.",
            "hosts": [],
            "services": [],
            "open_port_count": 0,
        }
    try:
        async with asyncio.timeout(settings.nmap_timeout_seconds + 10):
            stdout, stderr = await process.communicate()
    except TimeoutError:
        process.kill()
        await process.communicate()
        return {
            "status": "timeout",
            "scanner": "nmap",
            "summary": "The bounded Nmap discovery profile timed out.",
            "hosts": [],
            "services": [],
            "open_port_count": 0,
        }
    if len(stdout) > settings.max_output_bytes:
        return {
            "status": "error",
            "scanner": "nmap",
            "summary": "Nmap exceeded the scanner output safety limit.",
            "hosts": [],
            "services": [],
            "open_port_count": 0,
        }
    if process.returncode not in {0, 1}:
        return {
            "status": "error",
            "scanner": "nmap",
            "summary": "Nmap discovery did not complete.",
            "warning": _safe_stderr(stderr),
            "hosts": [],
            "services": [],
            "open_port_count": 0,
        }
    try:
        parsed = parse_nmap_xml(stdout)
    except (ET.ParseError, ValueError):
        return {
            "status": "error",
            "scanner": "nmap",
            "summary": "Nmap returned invalid or incomplete XML.",
            "hosts": [],
            "services": [],
            "open_port_count": 0,
        }
    parsed.update(
        {
            "status": "ok",
            "scanner": "nmap",
            "profile": "safe-service-discovery",
            "command_policy": (
                "Unprivileged TCP connect; top ports; light version detection; "
                "no NSE, OS fingerprinting, UDP, evasion, or exploitation."
            ),
            "started_at": started.isoformat(),
            "completed_at": datetime.now(UTC).isoformat(),
        }
    )
    return parsed


async def run_web(target: ScanTarget) -> dict[str, Any]:
    if not settings.web_probe_enabled:
        return _disabled("web", "Safe web posture checks are disabled by the operator.")
    probes: list[dict[str, Any]] = []
    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(settings.web_probe_timeout_seconds),
        trust_env=False,
        headers={"User-Agent": "AdversaryGraph-Scanner-MCP/1"},
    ) as client:
        for url in _web_probe_urls(target):
            try:
                async with client.stream("GET", url) as response:
                    headers = {
                        key.lower(): value[:2_000]
                        for key, value in response.headers.items()
                        if key.lower()
                        in {
                            *_SECURITY_HEADERS,
                            "access-control-allow-origin",
                            "location",
                            "server",
                            "set-cookie",
                            "x-frame-options",
                            "x-powered-by",
                        }
                    }
                    probes.append(
                        {
                            "url": str(response.request.url),
                            "status": "observed",
                            "status_code": response.status_code,
                            "headers": headers,
                            "tls_verified": response.request.url.scheme == "https",
                        }
                    )
            except (httpx.HTTPError, TimeoutError) as exc:
                probes.append(
                    {
                        "url": url,
                        "status": "unavailable",
                        "error_type": type(exc).__name__,
                        "summary": "The endpoint did not return an inspectable response.",
                        "headers": {},
                    }
                )
    findings = analyze_web_posture(probes)
    observed = sum(item.get("status") == "observed" for item in probes)
    return {
        "status": "ok"
        if observed == len(probes)
        else "partial"
        if observed
        else "unavailable",
        "scanner": "web",
        "summary": (
            f"Safe web posture inspected {observed} of {len(probes)} endpoint(s); "
            f"{len(findings)} configuration observation(s) require review."
        ),
        "profile": "safe-root-http-posture",
        "command_policy": (
            "Root GET only; no redirects, crawling, forms, authentication, injection, "
            "brute force, or exploitation."
        ),
        "probes": probes,
        "findings": findings,
        "completed_at": datetime.now(UTC).isoformat(),
    }


async def run_tls(target: ScanTarget) -> dict[str, Any]:
    if not settings.tls_enabled:
        return _disabled("tls", "TLS assessment is disabled.")
    parsed = urlsplit(target.value if target.target_type == "url" else "")
    port = parsed.port or 443
    started = datetime.now(UTC)
    context = ssl.create_default_context()
    try:
        async with asyncio.timeout(settings.tls_timeout_seconds):
            _, writer = await asyncio.open_connection(
                target.host,
                port,
                ssl=context,
                server_hostname=target.host,
            )
            ssl_object = writer.get_extra_info("ssl_object")
            certificate = ssl_object.getpeercert() if ssl_object else {}
            negotiated_protocol = ssl_object.version() if ssl_object else ""
            cipher = ssl_object.cipher() if ssl_object else None
            alpn = ssl_object.selected_alpn_protocol() if ssl_object else None
            writer.close()
            await writer.wait_closed()
    except ssl.SSLCertVerificationError as exc:
        return {
            "status": "observed",
            "scanner": "tls",
            "profile": "verified-tls-handshake",
            "summary": "TLS responded, but certificate verification failed.",
            "endpoint": f"{target.host}:{port}",
            "findings": [
                _finding(
                    "tls-certificate",
                    "high",
                    "TLS certificate verification failed",
                    _safe_error(exc),
                    "tls",
                    verification_required=False,
                )
            ],
            "started_at": started.isoformat(),
            "completed_at": datetime.now(UTC).isoformat(),
        }
    except (OSError, TimeoutError, ssl.SSLError) as exc:
        return {
            "status": "unavailable",
            "scanner": "tls",
            "profile": "verified-tls-handshake",
            "summary": "A verified TLS handshake could not be completed.",
            "endpoint": f"{target.host}:{port}",
            "findings": [],
            "error_type": type(exc).__name__,
            "started_at": started.isoformat(),
            "completed_at": datetime.now(UTC).isoformat(),
        }
    findings: list[dict[str, Any]] = []
    not_after = str(certificate.get("notAfter") or "")
    expires_at = _certificate_expiry(not_after)
    days_remaining: int | None = None
    if expires_at is not None:
        days_remaining = int((expires_at - datetime.now(UTC)).total_seconds() // 86_400)
        if days_remaining < 0:
            findings.append(
                _finding(
                    "tls-certificate",
                    "critical",
                    "TLS certificate is expired",
                    f"The verified certificate expired at {expires_at.isoformat()}.",
                    "tls",
                    verification_required=False,
                )
            )
        elif days_remaining < 30:
            findings.append(
                _finding(
                    "tls-certificate",
                    "medium",
                    "TLS certificate expires within 30 days",
                    f"The verified certificate expires at {expires_at.isoformat()}.",
                    "tls",
                    verification_required=False,
                )
            )
    return {
        "status": "ok",
        "scanner": "tls",
        "profile": "verified-tls-handshake",
        "summary": (
            f"Verified TLS negotiated {negotiated_protocol or 'an unknown protocol'}"
            f"{f' with {cipher[0]}' if cipher else ''}; {len(findings)} finding(s)."
        ),
        "endpoint": f"{target.host}:{port}",
        "protocol": negotiated_protocol,
        "cipher": cipher[0] if cipher else "",
        "cipher_bits": cipher[2] if cipher else None,
        "alpn": alpn or "",
        "issuer": _certificate_name(certificate.get("issuer")),
        "subject": _certificate_name(certificate.get("subject")),
        "subject_alt_names": [
            str(value)
            for kind, value in certificate.get("subjectAltName") or []
            if kind in {"DNS", "IP Address"} and str(value)
        ][:100],
        "not_before": certificate.get("notBefore"),
        "not_after": not_after,
        "days_remaining": days_remaining,
        "findings": findings,
        "started_at": started.isoformat(),
        "completed_at": datetime.now(UTC).isoformat(),
    }


async def run_dns(target: ScanTarget) -> dict[str, Any]:
    if not settings.dns_enabled:
        return _disabled("dns", "DNS posture assessment is disabled.")
    if target.target_type == "ip":
        return {
            "status": "not_applicable",
            "scanner": "dns",
            "profile": "read-only-dns-posture",
            "summary": "DNS posture checks require an inventory hostname.",
            "records": {},
            "findings": [],
        }
    started = datetime.now(UTC)
    resolver = dns.asyncresolver.Resolver(configure=True)
    resolver.timeout = min(5.0, float(settings.dns_timeout_seconds))
    resolver.lifetime = float(settings.dns_timeout_seconds)
    records: dict[str, list[str]] = {}
    errors: dict[str, str] = {}
    queries = {
        "A": (target.host, "A"),
        "AAAA": (target.host, "AAAA"),
        "CAA": (target.host, "CAA"),
        "TXT": (target.host, "TXT"),
        "DNSKEY": (target.host, "DNSKEY"),
        "DMARC": (f"_dmarc.{target.host}", "TXT"),
    }

    async def lookup(label: str, name: str, record_type: str) -> None:
        try:
            answer = await resolver.resolve(
                name,
                record_type,
                raise_on_no_answer=False,
                lifetime=settings.dns_timeout_seconds,
            )
            records[label] = [item.to_text().strip() for item in answer][:100]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            records[label] = []
        except (
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
            dns.exception.DNSException,
        ) as exc:
            records[label] = []
            errors[label] = type(exc).__name__

    await asyncio.gather(
        *(
            lookup(label, name, record_type)
            for label, (name, record_type) in queries.items()
        )
    )
    findings: list[dict[str, Any]] = []
    if not records.get("CAA"):
        findings.append(
            _finding(
                "dns-posture",
                "informational",
                "CAA record not observed at the assessed hostname",
                f"No direct CAA answer was returned for {target.host}; parent inheritance needs review.",
                "dns",
            )
        )
    if not any("v=spf1" in row.casefold() for row in records.get("TXT", [])):
        findings.append(
            _finding(
                "dns-posture",
                "informational",
                "SPF policy not observed at the assessed hostname",
                f"No direct v=spf1 TXT answer was returned for {target.host}.",
                "dns",
            )
        )
    if not any("v=dmarc1" in row.casefold() for row in records.get("DMARC", [])):
        findings.append(
            _finding(
                "dns-posture",
                "informational",
                "DMARC policy not observed at the assessed hostname",
                f"No direct v=DMARC1 TXT answer was returned for _dmarc.{target.host}.",
                "dns",
            )
        )
    return {
        "status": "partial" if errors else "ok",
        "scanner": "dns",
        "profile": "read-only-dns-posture",
        "summary": (
            f"Read-only DNS posture collected {sum(len(rows) for rows in records.values())} "
            f"record value(s); {len(findings)} review item(s)."
        ),
        "records": records,
        "errors": errors,
        "dnssec_records_observed": bool(records.get("DNSKEY")),
        "findings": findings,
        "started_at": started.isoformat(),
        "completed_at": datetime.now(UTC).isoformat(),
    }


async def run_nuclei(target: ScanTarget) -> dict[str, Any]:
    if not settings.nuclei_enabled:
        return _disabled("nuclei", "Nuclei assessment is disabled.")
    binary = Path(settings.nuclei_binary)
    templates = Path(settings.nuclei_templates)
    if not _executable_ready(binary) or not _directory_ready(templates):
        return {
            "status": "unavailable",
            "scanner": "nuclei",
            "summary": "The pinned Nuclei runtime or template bundle is unavailable.",
            "findings": [],
        }
    target_value = (
        target.value
        if target.target_type == "url"
        else f"https://{target.host}/"
        if target.target_type == "domain"
        else target.host
    )
    command = [
        str(binary),
        "-u",
        target_value,
        "-t",
        str(templates),
        "-as",
        "-pt",
        "http,ssl,dns",
        "-severity",
        "info,low,medium,high,critical",
        "-etags",
        (
            "dos,fuzz,intrusive,bruteforce,default-login,token-spray,"
            "credential-stuffing,headless,code,file,javascript,oast"
        ),
        "-ept",
        "headless,code,file,javascript,workflow,websocket",
        "-dut",
        "-ni",
        "-duc",
        "-rl",
        str(settings.nuclei_rate_limit),
        "-bs",
        "1",
        "-c",
        str(settings.nuclei_concurrency),
        "-timeout",
        "5",
        "-retries",
        "1",
        "-mhe",
        "5",
        "-rsr",
        "1048576",
        "-rss",
        "1048576",
        "-jsonl",
        "-silent",
        "-no-color",
        "-no-stdin",
    ]
    started = datetime.now(UTC)
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            # The container mounts /tmp as a private, size-capped noexec tmpfs
            # for its non-root UID; Nuclei cannot write to the read-only image.
            env={**os.environ, "HOME": "/tmp"},  # nosec B108
        )
    except FileNotFoundError:
        return {
            "status": "unavailable",
            "scanner": "nuclei",
            "summary": "The fixed Nuclei executable is unavailable.",
            "findings": [],
        }
    try:
        async with asyncio.timeout(settings.nuclei_timeout_seconds):
            stdout, stderr = await process.communicate()
    except TimeoutError:
        process.kill()
        await process.communicate()
        return {
            "status": "timeout",
            "scanner": "nuclei",
            "profile": "signed-bounded-network-templates",
            "summary": "The bounded Nuclei assessment reached its operator timeout.",
            "findings": [],
            "started_at": started.isoformat(),
            "completed_at": datetime.now(UTC).isoformat(),
        }
    if len(stdout) > settings.max_output_bytes:
        return {
            "status": "error",
            "scanner": "nuclei",
            "summary": "Nuclei exceeded the scanner output safety limit.",
            "findings": [],
        }
    if process.returncode not in {0, 1}:
        return {
            "status": "error",
            "scanner": "nuclei",
            "summary": "Nuclei did not complete the bounded assessment.",
            "findings": [],
            "warning": _safe_stderr(stderr),
            "started_at": started.isoformat(),
            "completed_at": datetime.now(UTC).isoformat(),
        }
    findings, rejected_lines = parse_nuclei_jsonl(stdout)
    return {
        "status": "ok",
        "scanner": "nuclei",
        "profile": "signed-bounded-network-templates",
        "engine": "Nuclei v3.11.0 source snapshot 6ecdb947 (dependency-hardened)",
        "templates": "Nuclei Templates v10.4.6",
        "summary": (
            f"Nuclei reported {len(findings)} signed-template match(es)"
            f"{f'; {rejected_lines} malformed line(s) were rejected' if rejected_lines else ''}."
        ),
        "finding_count": len(findings),
        "findings": findings,
        "rate_limit_per_second": settings.nuclei_rate_limit,
        "template_concurrency": settings.nuclei_concurrency,
        "command_policy": (
            "Pinned signed HTTP/TLS/DNS templates; fixed rate/concurrency; no fuzzing, "
            "headless, code, file, JavaScript, brute force, intrusive, DoS, or OAST."
        ),
        "started_at": started.isoformat(),
        "completed_at": datetime.now(UTC).isoformat(),
    }


async def run_assessment_plan(
    raw_target: str,
    *,
    run_nmap_requested: bool,
    run_web_requested: bool,
    additional_scanners: list[str],
) -> dict[str, Any]:
    target = normalize_target(raw_target)
    selected = list(dict.fromkeys(additional_scanners))
    unknown = sorted(set(selected) - set(ADDITIONAL_SCANNERS))
    if unknown:
        raise ValueError(f"Unsupported scanner(s): {', '.join(unknown)}")

    started = datetime.now(UTC)
    resolved_ips = await resolve_target(target)
    jobs: list[tuple[str, Callable[[ScanTarget], Awaitable[dict[str, Any]]]]] = []
    if run_nmap_requested:
        jobs.append(("nmap", run_nmap))
    if run_web_requested:
        jobs.append(("web", run_web))
    runners = {"tls": run_tls, "dns": run_dns, "nuclei": run_nuclei}
    jobs.extend((name, runners[name]) for name in selected)

    async def execute(
        name: str, runner: Callable[[ScanTarget], Awaitable[dict[str, Any]]]
    ):
        call_started = perf_counter()
        try:
            result = await runner(target)
        except Exception as exc:
            result = {
                "status": "error",
                "scanner": name,
                "summary": f"{name.upper()} failed safely; no result was accepted as evidence.",
                "findings": [],
                "error_type": type(exc).__name__,
            }
        return name, result, int((perf_counter() - call_started) * 1_000)

    completed = await asyncio.gather(*(execute(name, runner) for name, runner in jobs))
    results = {name: result for name, result, _ in completed}
    trace = [
        {
            "tool": f"scanner.{name}",
            "status": str(result.get("status") or "unknown"),
            "duration_ms": duration,
            "profile": str(result.get("profile") or ""),
        }
        for name, result, duration in completed
    ]
    return {
        "service": "adversarygraph-scanner-mcp",
        "service_version": "1.0.0",
        "transport": "mcp-streamable-http",
        "target": {
            "value": target.value,
            "host": target.host,
            "target_type": target.target_type,
        },
        "resolved_ips": resolved_ips,
        "nmap_result": results.get(
            "nmap",
            {
                "status": "not_requested",
                "scanner": "nmap",
                "summary": "Active service discovery was not requested.",
                "hosts": [],
                "services": [],
                "open_port_count": 0,
            },
        ),
        "web_probe_result": results.get(
            "web",
            {
                "status": "not_requested",
                "scanner": "web",
                "summary": "Safe web posture checks were not requested.",
                "probes": [],
                "findings": [],
            },
        ),
        "scanner_results": {name: results[name] for name in selected},
        "tool_trace": trace,
        "authorization_enforced_by": "AdversaryGraph API permission and inventory-membership gate",
        "started_at": started.isoformat(),
        "completed_at": datetime.now(UTC).isoformat(),
    }


def parse_nmap_xml(raw: bytes) -> dict[str, Any]:
    if not raw.strip():
        raise ValueError("Nmap XML is empty")
    root = ET.fromstring(raw)
    if root.tag != "nmaprun":
        raise ValueError("Nmap output is not an nmaprun document")
    hosts: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []
    for host in root.findall("host"):
        status_node = host.find("status")
        addresses = [
            {
                "address": node.attrib.get("addr", ""),
                "type": node.attrib.get("addrtype", ""),
            }
            for node in host.findall("address")
        ]
        hostnames = [
            node.attrib.get("name", "")
            for node in host.findall("./hostnames/hostname")
            if node.attrib.get("name")
        ]
        ports: list[dict[str, Any]] = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue
            service = port.find("service")
            row = {
                "protocol": port.attrib.get("protocol", ""),
                "port": int(port.attrib.get("portid", "0") or 0),
                "state": "open",
                "service": service.attrib.get("name", "")
                if service is not None
                else "",
                "product": service.attrib.get("product", "")
                if service is not None
                else "",
                "version": service.attrib.get("version", "")
                if service is not None
                else "",
                "extra_info": service.attrib.get("extrainfo", "")
                if service is not None
                else "",
                "cpes": [
                    str(node.text or "")[:500]
                    for node in service.findall("cpe")
                    if service is not None and str(node.text or "").startswith("cpe:")
                ]
                if service is not None
                else [],
            }
            ports.append(row)
            services.append(row)
        hosts.append(
            {
                "status": status_node.attrib.get("state", "")
                if status_node is not None
                else "",
                "addresses": addresses,
                "hostnames": hostnames,
                "ports": ports,
            }
        )
    return {
        "summary": f"Nmap observed {len(services)} open service(s) across {len(hosts)} host(s).",
        "hosts": hosts,
        "services": services,
        "open_port_count": len(services),
    }


def parse_nuclei_jsonl(raw: bytes) -> tuple[list[dict[str, Any]], int]:
    findings: list[dict[str, Any]] = []
    rejected = 0
    for line in raw.decode("utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            rejected += 1
            continue
        if not isinstance(row, dict):
            rejected += 1
            continue
        info = row.get("info") if isinstance(row.get("info"), dict) else {}
        template_id = str(row.get("template-id") or row.get("template_id") or "")[:200]
        title = str(info.get("name") or template_id or "Nuclei template match")[:500]
        severity = _risk_level(info.get("severity"))
        if severity == "unknown":
            severity = "informational"
        matched_at = str(
            row.get("matched-at")
            or row.get("matched")
            or row.get("host")
            or row.get("ip")
            or ""
        )[:2_000]
        description = " ".join(str(info.get("description") or "").split())[:1_000]
        references = info.get("reference")
        reference_values = (
            references
            if isinstance(references, list)
            else [references]
            if isinstance(references, str)
            else []
        )
        findings.append(
            {
                "category": "nuclei-template-match",
                "severity": severity,
                "title": title,
                "evidence": (
                    f"Template {template_id or 'unknown'} matched {matched_at or 'the target'}."
                    f"{f' {description}' if description else ''}"
                )[:2_000],
                "source": "nuclei",
                "status": "observed",
                "verification_required": True,
                "recommendation": (
                    "Reproduce through an approved validation workflow and confirm "
                    "product/version before remediation."
                ),
                "template_id": template_id,
                "matched_at": matched_at,
                "references": [
                    str(value)[:1_000]
                    for value in reference_values
                    if str(value).startswith(("https://", "http://"))
                ][:10],
                "matcher_name": str(row.get("matcher-name") or "")[:200],
                "protocol": str(row.get("type") or "")[:80],
            }
        )
        if len(findings) >= 500:
            break
    return _deduplicate_findings(findings), rejected


def analyze_web_posture(probes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for probe in probes:
        if probe.get("status") != "observed":
            continue
        url = str(probe.get("url") or "")
        headers = {
            str(key).casefold(): str(value)
            for key, value in (probe.get("headers") or {}).items()
        }
        scheme = urlsplit(url).scheme.casefold()
        for header, label in _SECURITY_HEADERS.items():
            if header == "strict-transport-security" and scheme != "https":
                continue
            if header not in headers:
                findings.append(
                    _web_finding(
                        f"{label} header not observed",
                        f"{url} did not include {header} in the root response.",
                        "low" if header != "strict-transport-security" else "medium",
                    )
                )
        if (
            "x-frame-options" not in headers
            and "frame-ancestors"
            not in headers.get("content-security-policy", "").casefold()
        ):
            findings.append(
                _web_finding(
                    "Frame embedding protection not observed",
                    f"{url} exposed neither X-Frame-Options nor CSP frame-ancestors.",
                    "low",
                )
            )
        if headers.get("access-control-allow-origin", "").strip() == "*":
            findings.append(
                _web_finding(
                    "Wildcard CORS policy observed",
                    f"{url} returned Access-Control-Allow-Origin: *.",
                    "low",
                )
            )
    return findings[:100]


def _web_probe_urls(target: ScanTarget) -> list[str]:
    if target.target_type == "url":
        return [target.value]
    host = f"[{target.host}]" if ":" in target.host else target.host
    return [f"https://{host}/", f"http://{host}/"]


def _web_finding(title: str, evidence: str, severity: str) -> dict[str, Any]:
    return {
        "category": "web-posture",
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "source": "safe-web-posture",
        "status": "observed",
        "verification_required": True,
        "recommendation": "Confirm against the approved web-security baseline.",
    }


def _finding(
    category: str,
    severity: str,
    title: str,
    evidence: str,
    source: str,
    *,
    verification_required: bool = True,
) -> dict[str, Any]:
    return {
        "category": category,
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "source": source,
        "status": "observed",
        "verification_required": verification_required,
        "recommendation": "Validate against authoritative configuration before production changes.",
    }


def _disabled(scanner: str, summary: str) -> dict[str, Any]:
    return {
        "status": "disabled",
        "scanner": scanner,
        "summary": summary,
        "findings": [],
    }


def _executable_ready(path: Path) -> bool:
    try:
        return path.is_file() and os.access(path, os.X_OK)
    except OSError:
        return False


def _directory_ready(path: Path) -> bool:
    try:
        return path.is_dir() and any(path.iterdir())
    except OSError:
        return False


def _certificate_expiry(value: str) -> datetime | None:
    try:
        return (
            datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=UTC)
            if value
            else None
        )
    except (OverflowError, TypeError, ValueError):
        return None


def _certificate_name(value: Any) -> str:
    parts: list[str] = []
    for group in value or []:
        for item in group if isinstance(group, (list, tuple)) else []:
            if (
                isinstance(item, (list, tuple))
                and len(item) == 2
                and str(item[1]).strip()
            ):
                parts.append(f"{item[0]}={item[1]}")
    return ", ".join(parts)[:1_000]


def _safe_error(exc: Exception) -> str:
    return re.sub(r"[\r\n\t]+", " ", str(exc)).strip()[:1_000]


def _safe_stderr(raw: bytes) -> str:
    return re.sub(r"[\r\n\t]+", " ", raw.decode("utf-8", errors="replace")).strip()[
        :1_000
    ]


def _risk_level(value: Any) -> str:
    normalized = str(value or "").casefold().strip()
    return (
        normalized
        if normalized in {"informational", "info", "low", "medium", "high", "critical"}
        else "unknown"
    )


def _deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for finding in findings:
        fingerprint = tuple(
            " ".join(str(finding.get(field) or "").casefold().split())
            for field in ("category", "title", "source", "evidence")
        )
        if fingerprint not in seen:
            seen.add(fingerprint)
            output.append(finding)
    return output
