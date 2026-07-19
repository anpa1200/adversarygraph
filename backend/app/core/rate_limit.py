"""
In-memory sliding-window rate limiter middleware for expensive API routes.

Keyed by (client_ip, route_prefix).  Single-instance deployment only — for
multi-worker setups, replace the in-memory deque with a Redis sorted set.
"""
from __future__ import annotations

import hmac
import ipaddress
import time
from collections import defaultdict, deque
from typing import Deque

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings

# (max_requests, window_seconds) per exact path prefix (POST/non-GET only)
_LIMITS: dict[str, tuple[int, int]] = {
    "/api/auth/login":        (10, 60),
    "/api/analyze":           (10, 60),
    "/api/threat-hunting/ai":  (6, 60),
    "/api/rag/assist":         (6, 60),
    "/api/rag/search":         (30, 60),
    "/api/rag/reindex":        (2, 60),
    "/api/malwaregraph/llm":   (6, 60),
    "/api/malwaregraph/analyses": (20, 60),
    "/api/retrohunt/collect":  (5, 60),
    "/api/knowledge/seed":     (5, 60),
    "/api/sector/sync":        (5, 60),
    "/api/sync/trigger":       (5, 60),
    "/api/sync/ioc":           (5, 60),
    "/api/sync/dynamic-db":    (5, 60),
    "/api/ioc/virustotal":     (15, 60),
    "/api/export/analysis":    (10, 60),
    "/api/export/layer":       (10, 60),
}

# {(ip, prefix): deque of timestamps}
_windows: dict[tuple[str, str], Deque[float]] = defaultdict(deque)
_CLEANUP_INTERVAL_SECONDS = 60
_MAX_WINDOW_KEYS = 50_000
_last_cleanup = 0.0


def _cleanup_windows(now: float) -> None:
    """Discard expired client keys so transient callers cannot leak memory."""
    global _last_cleanup
    if now - _last_cleanup < _CLEANUP_INTERVAL_SECONDS:
        return
    _last_cleanup = now
    for key, bucket in list(_windows.items()):
        window = _LIMITS.get(key[1], (0, 60))[1]
        while bucket and bucket[0] < now - window:
            bucket.popleft()
        if not bucket:
            _windows.pop(key, None)


def _bucket_for(key: tuple[str, str], now: float) -> Deque[float]:
    _cleanup_windows(now)
    if key not in _windows and len(_windows) >= _MAX_WINDOW_KEYS:
        oldest_key = min(
            _windows,
            key=lambda item: _windows[item][-1] if _windows[item] else float("-inf"),
        )
        _windows.pop(oldest_key, None)
    return _windows[key]


def _client_ip(request: Request) -> str:
    """Return a non-spoofable client key for rate limiting.

    Forwarded headers are trusted only when the dedicated rate-limit proxy
    secret is configured and present. Direct deployments therefore key on the
    actual TCP peer instead of attacker-controlled XFF. The authentication
    proxy secret is deliberately not accepted for this separate trust boundary.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    proxy_secret = request.headers.get("X-RateLimit-Proxy-Secret") or ""
    if (
        forwarded
        and settings.rate_limit_proxy_secret
        and hmac.compare_digest(proxy_secret, settings.rate_limit_proxy_secret)
    ):
        candidate = forwarded.split(",", 1)[0].strip()
        # 45 characters covers the longest standard textual IPv6 address,
        # including an embedded IPv4 address. Reject longer/malformed tokens
        # so a trusted but misconfigured proxy cannot create unbounded keys.
        if 0 < len(candidate) <= 45:
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError:
                pass
    if request.client:
        return request.client.host
    return "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Block requests that exceed the configured per-route rate limits."""

    async def dispatch(self, request: Request, call_next):
        if request.method in {"GET", "HEAD", "OPTIONS"}:
            return await call_next(request)

        path = request.url.path
        matched: tuple[int, int] | None = None
        matched_prefix = ""
        for prefix, limit in _LIMITS.items():
            if path.startswith(prefix):
                if len(prefix) > len(matched_prefix):
                    matched = limit
                    matched_prefix = prefix

        if matched is None:
            return await call_next(request)

        max_req, window = matched
        ip = _client_ip(request)
        key = (ip, matched_prefix)
        now = time.monotonic()
        bucket = _bucket_for(key, now)

        # Drop timestamps outside the current window
        while bucket and bucket[0] < now - window:
            bucket.popleft()

        if len(bucket) >= max_req:
            retry_after = int(window - (now - bucket[0])) + 1
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Please slow down."},
                headers={"Retry-After": str(retry_after)},
            )

        bucket.append(now)
        return await call_next(request)
