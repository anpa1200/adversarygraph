from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ScanTarget:
    value: str
    host: str
    target_type: str


def normalize_target(raw_target: str) -> ScanTarget:
    value = str(raw_target or "").strip()
    if not value or len(value) > 2_048 or any(ord(char) < 32 for char in value):
        raise ValueError("Target must be a non-empty IP, domain, or HTTP(S) URL")

    if "://" in value:
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as exc:
            raise ValueError("Target URL is invalid") from exc
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS asset URLs are supported")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Target URLs must not contain credentials")
        host = normalize_host(parsed.hostname or "")
        if not host:
            raise ValueError("Target URL must include a valid host")
        if port is not None and not 1 <= port <= 65_535:
            raise ValueError("Target URL port is invalid")
        netloc = f"[{host}]" if ":" in host else host
        if port is not None:
            netloc = f"{netloc}:{port}"
        return ScanTarget(
            urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", "", "")),
            host,
            "url",
        )

    normalized_ip = normalize_ip(value)
    if normalized_ip:
        return ScanTarget(normalized_ip, normalized_ip, "ip")
    host = normalize_host(value)
    if not host:
        raise ValueError("Target must be a valid IP, domain, or HTTP(S) URL")
    return ScanTarget(host, host, "domain")


def normalize_ip(value: str) -> str:
    try:
        return ipaddress.ip_address(str(value).strip().strip("[]")).compressed
    except ValueError:
        return ""


def normalize_host(value: str) -> str:
    candidate = str(value or "").strip().casefold().rstrip(".")
    if not candidate or len(candidate) > 253:
        return ""
    normalized_ip = normalize_ip(candidate)
    if normalized_ip:
        return normalized_ip
    try:
        ascii_host = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    return ascii_host if _DOMAIN_RE.fullmatch(ascii_host) else ""
