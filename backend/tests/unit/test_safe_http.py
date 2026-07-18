import asyncio
import socket
import ssl
from types import SimpleNamespace

import httpcore
import httpx
import pytest
from fastapi import HTTPException, Request

from app.core import safe_http


def _addr(ip: str):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))]


def test_safe_http_blocks_metadata_endpoint(monkeypatch):
    monkeypatch.setattr(safe_http.socket, "getaddrinfo", lambda *_args, **_kwargs: _addr("169.254.169.254"))

    with pytest.raises(ValueError, match="private/reserved"):
        safe_http.safe_get("http://metadata.google.internal/latest")


def test_safe_http_blocks_localhost(monkeypatch):
    monkeypatch.setattr(safe_http.socket, "getaddrinfo", lambda *_args, **_kwargs: _addr("127.0.0.1"))

    with pytest.raises(ValueError, match="private/reserved"):
        safe_http.safe_get("http://localhost:6379/")


def test_safe_http_rejects_non_http_scheme():
    with pytest.raises(ValueError, match="scheme"):
        safe_http.safe_get("file:///etc/passwd")


def test_safe_http_allows_public_https_and_disables_redirects(monkeypatch):
    calls = {}
    monkeypatch.setattr(safe_http.socket, "getaddrinfo", lambda *_args, **_kwargs: _addr("93.184.216.34"))

    class FakeResponse:
        headers = {"content-length": "2"}

        @property
        def content(self):
            return self._content

        def iter_content(self, chunk_size):
            assert chunk_size == 64 * 1024
            yield b"ok"

        def close(self):
            calls["closed"] = True

    class FakeSession:
        trust_env = True

        def mount(self, prefix, adapter):
            calls.setdefault("mounts", {})[prefix] = adapter

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def get(self, url, **kwargs):
            calls["trust_env"] = self.trust_env
            calls["url"] = url
            calls["kwargs"] = kwargs
            return FakeResponse()

    monkeypatch.setattr(safe_http.requests, "Session", FakeSession)

    response = safe_http.safe_get("https://example.com/feed.json", timeout=12)

    assert response is not None
    assert calls["url"] == "https://example.com/feed.json"
    assert calls["kwargs"]["timeout"] == 12
    assert calls["kwargs"]["allow_redirects"] is False
    assert calls["kwargs"]["stream"] is True
    assert calls["trust_env"] is False
    assert set(calls["mounts"]) == {"http://", "https://"}
    assert response.content == b"ok"
    assert calls["closed"] is True


def test_safe_http_stops_decoded_response_over_limit(monkeypatch):
    monkeypatch.setattr(safe_http.socket, "getaddrinfo", lambda *_args, **_kwargs: _addr("93.184.216.34"))

    class FakeResponse:
        headers = {}
        closed = False

        def iter_content(self, chunk_size):
            yield b"1234"
            yield b"5678"

        def close(self):
            self.closed = True

    response = FakeResponse()

    class FakeSession:
        def mount(self, *_args):
            return None

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def get(self, *_args, **_kwargs):
            return response

    monkeypatch.setattr(safe_http.requests, "Session", FakeSession)

    with pytest.raises(safe_http.ResponseTooLargeError):
        safe_http.safe_get("https://example.com/large", max_bytes=5)

    assert response.closed is True


@pytest.mark.asyncio
async def test_async_safe_http_stops_decoded_response_over_limit(monkeypatch):
    monkeypatch.setattr(safe_http.socket, "getaddrinfo", lambda *_args, **_kwargs: _addr("93.184.216.34"))
    real_client = httpx.AsyncClient

    class Chunks(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"1234"
            yield b"5678"

    transport = httpx.MockTransport(lambda _request: httpx.Response(200, stream=Chunks()))
    monkeypatch.setattr(safe_http, "_PinnedAsyncHTTPTransport", lambda: transport)

    client_kwargs = {}

    def client_factory(**kwargs):
        client_kwargs.update(kwargs)
        return real_client(**kwargs)

    monkeypatch.setattr(safe_http.httpx, "AsyncClient", client_factory)

    with pytest.raises(safe_http.ResponseTooLargeError):
        await safe_http.async_safe_get("https://example.com/large", max_bytes=5)

    assert client_kwargs["trust_env"] is False


def test_resolver_rejects_mixed_public_and_private_answers(monkeypatch):
    answers = _addr("93.184.216.34") + _addr("127.0.0.1")
    monkeypatch.setattr(safe_http.socket, "getaddrinfo", lambda *_args, **_kwargs: answers)

    with pytest.raises(ValueError, match="private/reserved"):
        safe_http._check_url("https://mixed-answer.example/feed")


@pytest.mark.asyncio
async def test_async_resolver_validates_all_answers_without_blocking_loop(monkeypatch):
    loop = asyncio.get_running_loop()
    calls = []

    async def getaddrinfo(host, port, **kwargs):
        calls.append((host, port, kwargs))
        return _addr("93.184.216.34") + _addr("169.254.169.254")

    monkeypatch.setattr(loop, "getaddrinfo", getaddrinfo)

    with pytest.raises(ValueError, match="private/reserved"):
        await safe_http._async_resolve_public_ip("mixed-answer.example", 443)

    assert calls == [("mixed-answer.example", 443, {"type": socket.SOCK_STREAM})]


def test_safe_http_rejects_url_credentials():
    with pytest.raises(ValueError, match="credentials"):
        safe_http.safe_get("https://user:password@example.com/feed")


def test_safe_http_rejects_invalid_port():
    with pytest.raises(ValueError, match="port"):
        safe_http.safe_get("https://example.com:0/feed")


@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"verify": False}, "verification"),
        ({"proxies": {"https": "http://proxy.example"}}, "proxies"),
        ({"headers": {"Host": "metadata.internal"}}, "Host header"),
    ],
)
def test_safe_http_rejects_connection_policy_overrides(kwargs, message):
    with pytest.raises(ValueError, match=message):
        safe_http.safe_get("https://example.com/feed", **kwargs)


def test_sync_connection_rechecks_dns_and_blocks_rebinding(monkeypatch):
    answers = iter([_addr("93.184.216.34"), _addr("127.0.0.1")])
    calls = []

    def changing_dns(host, port, **kwargs):
        calls.append((host, port, kwargs))
        return next(answers)

    monkeypatch.setattr(safe_http.socket, "getaddrinfo", changing_dns)

    with pytest.raises(ValueError, match="private/reserved"):
        safe_http.safe_get("https://rebind.example/feed")

    assert [call[:2] for call in calls] == [
        ("rebind.example", 443),
        ("rebind.example", 443),
    ]


def test_sync_connection_pins_numeric_ip_and_keeps_hostname(monkeypatch):
    monkeypatch.setattr(safe_http.socket, "getaddrinfo", lambda *_args, **_kwargs: _addr("93.184.216.34"))
    connected = {}
    fake_socket = object()

    def create_connection(address, timeout, **kwargs):
        connected.update(address=address, timeout=timeout, kwargs=kwargs)
        return fake_socket

    monkeypatch.setattr(safe_http.urllib3_util_connection, "create_connection", create_connection)
    connection = safe_http._PinnedHTTPSConnection("example.com", port=443, timeout=4)

    assert connection._new_conn() is fake_socket
    assert connected["address"] == ("93.184.216.34", 443)
    assert connection.host == "example.com"


def test_sync_connection_resolves_exact_absolute_dns_name(monkeypatch):
    resolved = []

    def resolve(host, *_args, **_kwargs):
        resolved.append(host)
        return _addr("93.184.216.34")

    monkeypatch.setattr(safe_http.socket, "getaddrinfo", resolve)
    monkeypatch.setattr(safe_http.urllib3_util_connection, "create_connection", lambda *_args, **_kwargs: object())
    connection = safe_http._PinnedHTTPSConnection("example.com.", port=443)

    connection._new_conn()

    assert resolved == ["example.com."]
    assert connection.host == "example.com"


def test_sync_https_retains_original_hostname_for_tls(monkeypatch):
    connection = safe_http._PinnedHTTPSConnection("example.com", port=443, cert_reqs=ssl.CERT_REQUIRED)
    monkeypatch.setattr(connection, "_new_conn", lambda: object())
    monkeypatch.setattr(safe_http.urllib3_connection.ssl_, "ALPN_PROTOCOLS", [])
    wrapped = {}

    def wrap_socket(**kwargs):
        wrapped.update(kwargs)
        return SimpleNamespace(socket=object(), is_verified=True)

    monkeypatch.setattr(safe_http.urllib3_connection, "_ssl_wrap_socket_and_match_hostname", wrap_socket)

    connection.connect()

    assert wrapped["server_hostname"] == "example.com"
    assert wrapped["cert_reqs"] == ssl.CERT_REQUIRED


class _ScriptedAsyncStream(httpcore.AsyncNetworkStream):
    def __init__(self, response: bytes):
        self._response = response
        self.writes = bytearray()
        self.server_hostname = None
        self.ssl_context = None

    async def read(self, max_bytes, timeout=None):  # noqa: ASYNC109 - httpcore interface
        del timeout
        if not self._response:
            return b""
        chunk, self._response = self._response[:max_bytes], self._response[max_bytes:]
        return chunk

    async def write(self, buffer, timeout=None):  # noqa: ASYNC109 - httpcore interface
        del timeout
        self.writes.extend(buffer)

    async def aclose(self):
        return None

    async def start_tls(  # noqa: ASYNC109 - httpcore interface
        self,
        ssl_context,
        server_hostname=None,
        timeout=None,  # noqa: ASYNC109 - httpcore interface
    ):
        del timeout
        self.ssl_context = ssl_context
        self.server_hostname = server_hostname
        return self

    def get_extra_info(self, _info):
        return None


class _RecordingAsyncBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, responses):
        self.responses = list(responses)
        self.connects = []
        self.streams = []

    async def connect_tcp(  # noqa: ASYNC109 - httpcore interface
        self,
        host,
        port,
        timeout=None,  # noqa: ASYNC109 - httpcore interface
        local_address=None,
        socket_options=None,
    ):
        self.connects.append((host, port, timeout, local_address, socket_options))
        stream = _ScriptedAsyncStream(self.responses.pop(0))
        self.streams.append(stream)
        return stream

    async def connect_unix_socket(  # noqa: ASYNC109 - httpcore interface
        self,
        path,
        timeout=None,  # noqa: ASYNC109 - httpcore interface
        socket_options=None,
    ):
        raise AssertionError(f"unexpected Unix socket connection to {path}")

    async def sleep(self, _seconds):
        return None


@pytest.mark.asyncio
async def test_async_connection_pins_ip_and_preserves_host_and_tls_sni(monkeypatch):
    async def resolve(*_args, **_kwargs):
        return "93.184.216.34"

    monkeypatch.setattr(safe_http, "_async_resolve_public_ip", resolve)
    backend = _RecordingAsyncBackend(
        [b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"]
    )
    transport = safe_http._PinnedAsyncHTTPTransport(network_backend=backend)

    async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
        response = await client.get("https://example.com/feed")

    assert response.content == b"ok"
    assert backend.connects[0][0:2] == ("93.184.216.34", 443)
    assert backend.streams[0].server_hostname == "example.com"
    assert backend.streams[0].ssl_context.verify_mode == ssl.CERT_REQUIRED
    assert backend.streams[0].ssl_context.check_hostname is True
    assert b"Host: example.com\r\n" in backend.streams[0].writes


@pytest.mark.asyncio
async def test_async_connection_rechecks_dns_and_blocks_rebinding(monkeypatch):
    answers = iter([_addr("93.184.216.34"), _addr("169.254.169.254")])

    async def changing_dns(*_args, **_kwargs):
        return safe_http._select_public_ip(next(answers))

    monkeypatch.setattr(safe_http, "_async_resolve_public_ip", changing_dns)
    backend = _RecordingAsyncBackend([])
    pinned_transport = safe_http._PinnedAsyncHTTPTransport
    monkeypatch.setattr(
        safe_http,
        "_PinnedAsyncHTTPTransport",
        lambda: pinned_transport(network_backend=backend),
    )

    with pytest.raises(ValueError, match="private/reserved"):
        await safe_http.async_safe_get("https://rebind.example/feed")

    assert backend.connects == []


@pytest.mark.asyncio
async def test_async_redirect_target_is_revalidated(monkeypatch):
    async def resolve(host, _port, **_kwargs):
        answers = _addr("93.184.216.34") if host == "public.example" else _addr("127.0.0.1")
        return safe_http._select_public_ip(answers)

    monkeypatch.setattr(safe_http, "_async_resolve_public_ip", resolve)
    backend = _RecordingAsyncBackend(
        [
            b"HTTP/1.1 302 Found\r\nLocation: https://internal.example/secret\r\n"
            b"Content-Length: 0\r\nConnection: close\r\n\r\n"
        ]
    )
    pinned_transport = safe_http._PinnedAsyncHTTPTransport
    monkeypatch.setattr(
        safe_http,
        "_PinnedAsyncHTTPTransport",
        lambda: pinned_transport(network_backend=backend),
    )

    with pytest.raises(ValueError, match="private/reserved"):
        await safe_http.async_safe_get("https://public.example/feed", follow_redirects=True)

    assert [connection[:2] for connection in backend.connects] == [("93.184.216.34", 443)]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kwargs, message",
    [
        ({"headers": {"Host": "metadata.internal"}}, "Host header"),
        ({"extensions": {"sni_hostname": "metadata.internal"}}, "SNI"),
    ],
)
async def test_async_safe_http_rejects_hostname_overrides(kwargs, message):
    with pytest.raises(ValueError, match=message):
        await safe_http.async_safe_get("https://example.com/feed", **kwargs)


@pytest.mark.asyncio
async def test_body_size_dependency_rejects_invalid_content_length():
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/upload",
            "headers": [(b"content-length", b"not-a-number")],
        }
    )

    with pytest.raises(HTTPException) as exc:
        await safe_http.require_body_size(10)(request)

    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_upload_reader_enforces_actual_bytes_when_size_is_missing():
    class Upload:
        size = None

        def __init__(self):
            self.chunks = [b"1234", b"5678", b""]

        async def read(self, _size):
            return self.chunks.pop(0)

    with pytest.raises(HTTPException) as exc:
        await safe_http.read_upload_limited(Upload(), 5, chunk_size=4)

    assert exc.value.status_code == 413
