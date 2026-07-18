from __future__ import annotations

from collections import deque

import pytest
from fastapi import Request
from fastapi.responses import JSONResponse

from app.core import rate_limit
from app.core.config import settings


def _request(
    path: str = "/api/auth/login",
    *,
    client_ip: str = "198.51.100.20",
    headers: list[tuple[bytes, bytes]] | None = None,
) -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": headers or [],
            "client": (client_ip, 43123),
            "server": ("api.example.test", 443),
        }
    )


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    rate_limit._windows.clear()
    rate_limit._last_cleanup = 0.0
    yield
    rate_limit._windows.clear()
    rate_limit._last_cleanup = 0.0


def test_client_ip_ignores_spoofed_xff_without_trusted_proxy(monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_proxy_secret", "")
    request = _request(headers=[(b"x-forwarded-for", b"203.0.113.99")])

    assert rate_limit._client_ip(request) == "198.51.100.20"


def test_client_ip_uses_xff_only_with_matching_proxy_secret(monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_proxy_secret", "rate-limit-secret")
    untrusted = _request(headers=[(b"x-forwarded-for", b"203.0.113.99")])
    trusted = _request(
        headers=[
            (b"x-forwarded-for", b"203.0.113.99, 10.0.0.2"),
            (b"x-ratelimit-proxy-secret", b"rate-limit-secret"),
        ]
    )

    assert rate_limit._client_ip(untrusted) == "198.51.100.20"
    assert rate_limit._client_ip(trusted) == "203.0.113.99"


@pytest.mark.parametrize(
    ("forwarded", "expected"),
    [
        ("203.0.113.99", "203.0.113.99"),
        ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
        ("not-an-ip", "198.51.100.20"),
        ("1" * 46, "198.51.100.20"),
    ],
)
def test_trusted_forwarded_ip_is_validated_and_normalized(
    monkeypatch,
    forwarded,
    expected,
):
    monkeypatch.setattr(settings, "rate_limit_proxy_secret", "rate-limit-secret")
    request = _request(
        headers=[
            (b"x-forwarded-for", forwarded.encode()),
            (b"x-ratelimit-proxy-secret", b"rate-limit-secret"),
        ]
    )

    assert rate_limit._client_ip(request) == expected


def test_auth_proxy_secret_does_not_trust_forwarded_client_ip(monkeypatch):
    monkeypatch.setattr(settings, "proxy_secret", "auth-proxy-secret")
    monkeypatch.setattr(settings, "rate_limit_proxy_secret", "rate-limit-secret")
    request = _request(
        headers=[
            (b"x-forwarded-for", b"203.0.113.99"),
            (b"x-internal-proxy-secret", b"auth-proxy-secret"),
        ]
    )

    assert rate_limit._client_ip(request) == "198.51.100.20"


@pytest.mark.asyncio
async def test_login_limit_cannot_be_bypassed_by_rotating_xff(monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_proxy_secret", "")
    middleware = rate_limit.RateLimitMiddleware(lambda *_args: None)

    async def call_next(_request):
        return JSONResponse({"ok": False}, status_code=401)

    responses = []
    for index in range(11):
        request = _request(headers=[(b"x-forwarded-for", f"203.0.113.{index}".encode())])
        responses.append(await middleware.dispatch(request, call_next))

    assert [response.status_code for response in responses[:10]] == [401] * 10
    assert responses[10].status_code == 429
    assert responses[10].headers["retry-after"]


def test_cleanup_removes_expired_client_keys():
    rate_limit._windows[("198.51.100.20", "/api/auth/login")] = deque([1.0])
    rate_limit._windows[("198.51.100.21", "/api/auth/login")] = deque([199.0])

    rate_limit._cleanup_windows(200.0)

    assert ("198.51.100.20", "/api/auth/login") not in rate_limit._windows
    assert ("198.51.100.21", "/api/auth/login") in rate_limit._windows
