"""
SSRF-safe HTTP helpers.

safe_get  — synchronous (requests)
async_safe_get — asynchronous (httpx)

Both functions validate the target URL before making the request:
  1. Scheme must be http or https.
  2. The resolved IP must not be loopback, link-local, private, multicast,
     or the cloud metadata endpoint (169.254.169.254).
  3. Redirects are disabled so a redirect cannot bypass the IP check.
"""
from __future__ import annotations

import ipaddress
import socket
import urllib.parse
from typing import Any

import httpx
import requests


def _check_url(url: str) -> None:
    """Raise ValueError if url uses a disallowed scheme or resolves to a
    private/reserved address.  Called by both safe_get and async_safe_get."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("blocked: scheme must be http or https")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("blocked: no hostname in URL")

    try:
        results = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise ValueError(f"blocked: could not resolve hostname: {exc}") from exc

    for _family, _type, _proto, _canonname, sockaddr in results:
        raw_ip = sockaddr[0]
        try:
            addr = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue

        # Explicit block for AWS/GCP/Azure metadata endpoint
        if str(addr) == "169.254.169.254":
            raise ValueError("blocked: private/reserved address")

        if (
            addr.is_loopback
            or addr.is_link_local
            or addr.is_private
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
        ):
            raise ValueError("blocked: private/reserved address")


def safe_get(url: str, *, timeout: int = 30, **kwargs: Any) -> requests.Response:
    """Make a GET request only if the target URL is safe.

    Raises ValueError for disallowed schemes or private/reserved addresses.
    Redirects are disabled to prevent bypass via redirect chains.
    """
    _check_url(url)
    return requests.get(url, timeout=timeout, allow_redirects=False, **kwargs)


def require_body_size(max_bytes: int = 10 * 1024 * 1024):
    """FastAPI dependency: reject requests whose Content-Length exceeds max_bytes."""
    from fastapi import HTTPException, Request

    async def _check(request: Request) -> None:
        cl = request.headers.get("content-length")
        if cl and int(cl) > max_bytes:
            raise HTTPException(
                413,
                f"Request body too large (max {max_bytes // (1024 * 1024)} MB)",
            )

    return _check


async def async_safe_get(url: str, *, timeout: int = 30, **kwargs: Any) -> httpx.Response:
    """Async version of safe_get using httpx.AsyncClient.

    Raises ValueError for disallowed schemes or private/reserved addresses.
    Redirects are disabled to prevent bypass via redirect chains.
    """
    _check_url(url)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        return await client.get(url, **kwargs)
