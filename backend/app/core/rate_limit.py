"""
In-memory sliding-window rate limiter middleware for expensive API routes.

Keyed by (client_ip, route_prefix).  Single-instance deployment only — for
multi-worker setups, replace the in-memory deque with a Redis sorted set.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Deque

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

# (max_requests, window_seconds) per exact path prefix (POST/non-GET only)
_LIMITS: dict[str, tuple[int, int]] = {
    "/api/analyze":           (10, 60),
    "/api/sync/trigger":       (5, 60),
    "/api/sync/ioc":           (5, 60),
    "/api/sync/dynamic-db":    (5, 60),
    "/api/ioc/virustotal":     (15, 60),
    "/api/export/analysis":    (10, 60),
    "/api/export/layer":       (10, 60),
}

# {(ip, prefix): deque of timestamps}
_windows: dict[tuple[str, str], Deque[float]] = defaultdict(deque)


def _client_ip(request: Request) -> str:
    """Return client IP, honoring X-Forwarded-For when behind a proxy."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
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
        bucket = _windows[key]

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
