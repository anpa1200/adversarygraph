"""SSRF-hardened synchronous and asynchronous HTTP helpers.

Each outgoing request is checked immediately before dispatch, including every
request in a redirect chain. The connection then performs a second DNS lookup,
rejects the hostname if *any* answer is not globally routable, and connects to
one of the validated numeric addresses. This closes the DNS-rebinding window
between validation and connect while retaining the original hostname for the
HTTP Host header, TLS SNI, and certificate verification.

Environment and explicit proxies are disabled because a proxy would resolve
the destination independently. Deployment DNS and egress policy remain useful
defense-in-depth boundaries.
"""
import asyncio
import ipaddress
import socket
import sys
import urllib.parse
from collections.abc import Iterable, Mapping
from typing import Any

import httpcore
import httpx
import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3 import connection as urllib3_connection
from urllib3 import connectionpool as urllib3_connectionpool
from urllib3 import poolmanager as urllib3_poolmanager
from urllib3.exceptions import ConnectTimeoutError, NewConnectionError
from urllib3.util import connection as urllib3_util_connection

DEFAULT_MAX_RESPONSE_BYTES = 50 * 1024 * 1024


class ResponseTooLargeError(Exception):
    """Raised when a remote response crosses the decoded body limit."""


def _validated_url_target(url: str) -> tuple[str, int]:
    """Return the hostname and effective port after structural validation."""
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise ValueError(f"blocked: invalid URL: {exc}") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("blocked: scheme must be http or https")
    if not parsed.hostname:
        raise ValueError("blocked: no hostname in URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("blocked: URL credentials are not allowed")

    if port is not None and port < 1:
        raise ValueError("blocked: invalid URL port")
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    return parsed.hostname, port if port is not None else default_port


def _select_public_ip(results: Iterable[tuple[Any, Any, Any, Any, tuple[Any, ...]]]) -> str:
    """Reject mixed/unsafe resolver answers and select one public address."""
    addresses: list[str] = []
    for _family, _type, _proto, _canonname, sockaddr in results:
        raw_ip = sockaddr[0]
        try:
            address = ipaddress.ip_address(raw_ip)
        except ValueError as exc:
            raise ValueError("blocked: resolver returned an invalid address") from exc
        if not address.is_global:
            raise ValueError("blocked: private/reserved address")
        normalized = str(address)
        if normalized not in addresses:
            addresses.append(normalized)

    if not addresses:
        raise ValueError("blocked: hostname did not resolve to a usable address")
    return addresses[0]


def _resolve_public_ip(hostname: str, port: int) -> str:
    """Synchronously resolve *hostname* and return a validated public IP."""
    try:
        results = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"blocked: could not resolve hostname: {exc}") from exc
    return _select_public_ip(results)


async def _async_resolve_public_ip(hostname: str, port: int) -> str:
    """Resolve without blocking the event loop and return a validated IP."""
    try:
        results = await asyncio.get_running_loop().getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ValueError(f"blocked: could not resolve hostname: {exc}") from exc
    return _select_public_ip(results)


def _check_url(url: str) -> None:
    """Reject malformed URLs and hosts with any non-public DNS answer."""
    hostname, port = _validated_url_target(url)
    _resolve_public_ip(hostname, port)


async def _async_check_url(url: str) -> None:
    """Async counterpart to :func:`_check_url` for HTTPX request dispatch."""
    hostname, port = _validated_url_target(url)
    await _async_resolve_public_ip(hostname, port)


def _header_names(headers: Any) -> Iterable[str]:
    if headers is None:
        return ()
    items: Iterable[Any]
    if isinstance(headers, Mapping) or hasattr(headers, "keys"):
        items = headers.keys()
    else:
        items = (item[0] for item in headers)
    return (
        item.decode("latin-1").lower() if isinstance(item, bytes) else str(item).lower()
        for item in items
    )


def _reject_caller_host_header(headers: Any) -> None:
    if "host" in _header_names(headers):
        raise ValueError("blocked: overriding the Host header is not allowed")


def _validate_sync_options(kwargs: Mapping[str, Any]) -> None:
    _reject_caller_host_header(kwargs.get("headers"))
    if "verify" in kwargs and not kwargs["verify"]:
        raise ValueError("blocked: TLS certificate verification cannot be disabled")
    if kwargs.get("proxies"):
        raise ValueError("blocked: explicit proxies are not allowed")


class _PinnedConnectionMixin:
    """Resolve at connect time and open the socket to the validated IP."""

    host: str
    _dns_host: str
    port: int
    timeout: float | None
    source_address: tuple[str, int] | None
    socket_options: list[tuple[int, int, int]] | None

    def _new_conn(self) -> socket.socket:
        # urllib3 keeps the exact DNS target separately from the normalized
        # hostname used by HTTP and TLS (for example, an absolute name ending
        # in a dot). Resolve that exact target, but leave ``host`` unchanged so
        # certificate verification and SNI retain urllib3's normal behavior.
        pinned_ip = _resolve_public_ip(self._dns_host, self.port)
        try:
            sock = urllib3_util_connection.create_connection(
                (pinned_ip, self.port),
                self.timeout,
                source_address=self.source_address,
                socket_options=self.socket_options,
            )
        except TimeoutError as exc:
            raise ConnectTimeoutError(
                self,
                f"Connection to {self.host} timed out. (connect timeout={self.timeout})",
            ) from exc
        except OSError as exc:
            raise NewConnectionError(self, f"Failed to establish a new connection: {exc}") from exc

        sys.audit("http.client.connect", self, self.host, self.port)
        return sock


class _PinnedHTTPConnection(_PinnedConnectionMixin, urllib3_connection.HTTPConnection):
    pass


class _PinnedHTTPSConnection(_PinnedConnectionMixin, urllib3_connection.HTTPSConnection):
    pass


class _PinnedHTTPConnectionPool(urllib3_connectionpool.HTTPConnectionPool):
    ConnectionCls = _PinnedHTTPConnection


class _PinnedHTTPSConnectionPool(urllib3_connectionpool.HTTPSConnectionPool):
    ConnectionCls = _PinnedHTTPSConnection


class _PinnedPoolManager(urllib3_poolmanager.PoolManager):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.pool_classes_by_scheme = {
            "http": _PinnedHTTPConnectionPool,
            "https": _PinnedHTTPSConnectionPool,
        }


class _PinnedHTTPAdapter(HTTPAdapter):
    """Requests adapter that validates every prepared request and pins DNS."""

    def init_poolmanager(
        self,
        connections: int,
        maxsize: int,
        block: bool = False,
        **pool_kwargs: Any,
    ) -> None:
        self._pool_connections = connections
        self._pool_maxsize = maxsize
        self._pool_block = block
        self.poolmanager = _PinnedPoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            **pool_kwargs,
        )

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> urllib3.ProxyManager:
        del proxy, proxy_kwargs
        raise ValueError("blocked: proxies are not allowed")

    def send(
        self,
        request: requests.PreparedRequest,
        stream: bool = False,
        timeout: Any = None,
        verify: bool | str = True,
        cert: Any = None,
        proxies: Mapping[str, str] | None = None,
    ) -> requests.Response:
        if not request.url:
            raise ValueError("blocked: request has no URL")
        _check_url(request.url)
        _reject_caller_host_header(request.headers)
        if not verify:
            raise ValueError("blocked: TLS certificate verification cannot be disabled")
        if proxies:
            raise ValueError("blocked: proxies are not allowed")
        return super().send(
            request,
            stream=stream,
            timeout=timeout,
            verify=verify,
            cert=cert,
            proxies=proxies,
        )


class _PinnedAsyncNetworkBackend(httpcore.AsyncNetworkBackend):
    """httpcore network backend that connects only to a validated numeric IP."""

    def __init__(self, backend: httpcore.AsyncNetworkBackend | None = None) -> None:
        self._backend = backend or httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109 - httpcore interface
        local_address: str | None = None,
        socket_options: Iterable[tuple[int, int, int | bytes]] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        # DNS resolution is deliberately repeated here, at the final connect
        # boundary. The validated numeric address is the only value delegated
        # to the socket backend.
        pinned_ip = await _async_resolve_public_ip(host, port)
        return await self._backend.connect_tcp(
            pinned_ip,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,  # noqa: ASYNC109 - httpcore interface
        socket_options: Iterable[tuple[int, int, int | bytes]] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        del path, timeout, socket_options
        raise ValueError("blocked: Unix-socket HTTP transports are not allowed")

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


class _PinnedAsyncHTTPTransport(httpx.AsyncHTTPTransport):
    """HTTPX transport with per-request checks and connect-time DNS pinning."""

    def __init__(self, network_backend: httpcore.AsyncNetworkBackend | None = None) -> None:
        super().__init__(verify=True, trust_env=False)
        # HTTPX does not expose network_backend in its public constructor. Its
        # pinned httpcore pool does, so replace only that backend while leaving
        # HTTPX's native exception mapping and streaming implementation intact.
        self._pool._network_backend = _PinnedAsyncNetworkBackend(network_backend)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await _async_check_url(str(request.url))
        expected_host = request.url.netloc.decode("ascii").lower()
        actual_host = request.headers.get("host", "").lower()
        if actual_host != expected_host:
            raise ValueError("blocked: overriding the Host header is not allowed")
        if request.extensions.get("sni_hostname") is not None:
            raise ValueError("blocked: overriding the TLS SNI hostname is not allowed")
        return await super().handle_async_request(request)


def _validate_response_limit(max_bytes: int) -> None:
    if max_bytes <= 0:
        raise ValueError("Response limit must be positive")


def _content_length_exceeds(headers: Any, max_bytes: int) -> bool:
    raw = headers.get("content-length") if headers is not None else None
    if not raw:
        return False
    try:
        return int(raw) > max_bytes
    except (TypeError, ValueError):
        return False


def _read_sync_response_limited(response: requests.Response, max_bytes: int) -> requests.Response:
    if _content_length_exceeds(response.headers, max_bytes):
        response.close()
        raise ResponseTooLargeError(f"Remote response exceeds the {max_bytes}-byte limit")
    content = bytearray()
    try:
        for chunk in response.iter_content(chunk_size=64 * 1024):
            if not chunk:
                continue
            content.extend(chunk)
            if len(content) > max_bytes:
                raise ResponseTooLargeError(f"Remote response exceeds the {max_bytes}-byte limit")
    finally:
        response.close()
    response._content = bytes(content)
    response._content_consumed = True
    return response


def safe_get(
    url: str,
    *,
    timeout: int = 30,
    max_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    **kwargs: Any,
) -> requests.Response:
    """Make a GET request only if the target URL is safe.

    Raises ValueError for disallowed schemes or private/reserved addresses.
    Redirects are disabled to prevent bypass via redirect chains.
    """
    _validated_url_target(url)
    _validate_response_limit(max_bytes)
    if "stream" in kwargs:
        raise TypeError("safe_get manages response streaming internally")
    if "allow_redirects" in kwargs:
        raise TypeError("safe_get controls redirect handling internally")
    _validate_sync_options(kwargs)
    with requests.Session() as session:
        # Environment proxy variables resolve/connect independently of this
        # process and can bypass the hostname/IP policy.
        session.trust_env = False
        session.mount("http://", _PinnedHTTPAdapter())
        session.mount("https://", _PinnedHTTPAdapter())
        response = session.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            stream=True,
            **kwargs,
        )
        return _read_sync_response_limited(response, max_bytes)


def safe_post(
    url: str,
    *,
    timeout: int = 30,
    max_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    **kwargs: Any,
) -> requests.Response:
    """Make a POST request only if the target URL is safe."""
    _validated_url_target(url)
    _validate_response_limit(max_bytes)
    if "stream" in kwargs:
        raise TypeError("safe_post manages response streaming internally")
    if "allow_redirects" in kwargs:
        raise TypeError("safe_post controls redirect handling internally")
    _validate_sync_options(kwargs)
    with requests.Session() as session:
        session.trust_env = False
        session.mount("http://", _PinnedHTTPAdapter())
        session.mount("https://", _PinnedHTTPAdapter())
        response = session.post(
            url,
            timeout=timeout,
            allow_redirects=False,
            stream=True,
            **kwargs,
        )
        return _read_sync_response_limited(response, max_bytes)


def require_body_size(max_bytes: int = 10 * 1024 * 1024):
    """FastAPI dependency: reject requests whose Content-Length exceeds max_bytes."""
    from fastapi import HTTPException, Request

    async def _check(request: Request) -> None:
        cl = request.headers.get("content-length")
        if not cl:
            return
        try:
            content_length = int(cl)
        except ValueError as exc:
            raise HTTPException(400, "Invalid Content-Length header") from exc
        if content_length < 0:
            raise HTTPException(400, "Invalid Content-Length header")
        if content_length > max_bytes:
            raise HTTPException(
                413,
                f"Request body too large (max {max_bytes // (1024 * 1024)} MB)",
            )

    return _check


async def read_upload_limited(file: Any, max_bytes: int, *, chunk_size: int = 64 * 1024) -> bytes:
    """Read an UploadFile with a hard cap, including chunked requests.

    ``Content-Length`` and ``UploadFile.size`` are useful early checks but are
    not security boundaries. This helper stops reading as soon as the decoded
    multipart file crosses the configured limit.
    """
    from fastapi import HTTPException

    if max_bytes <= 0 or chunk_size <= 0:
        raise ValueError("Upload limits must be positive")
    declared_size = getattr(file, "size", None)
    if declared_size is not None and declared_size > max_bytes:
        raise HTTPException(413, f"Uploaded file exceeds {max_bytes // (1024 * 1024)} MB limit")

    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(413, f"Uploaded file exceeds {max_bytes // (1024 * 1024)} MB limit")
        chunks.append(chunk)
    return b"".join(chunks)


async def async_safe_get(
    url: str,
    *,
    timeout: int = 30,  # noqa: ASYNC109 - mirrors requests/httpx public APIs
    max_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    follow_redirects: bool = False,
    **kwargs: Any,
) -> httpx.Response:
    """Async version of safe_get using httpx.AsyncClient.

    Raises ValueError for disallowed schemes or private/reserved addresses.
    Redirects default to disabled. If explicitly enabled, the transport
    revalidates and pins every request in the redirect chain.
    """
    _validated_url_target(url)
    _validate_response_limit(max_bytes)
    _reject_caller_host_header(kwargs.get("headers"))
    extensions = kwargs.get("extensions")
    if extensions and extensions.get("sni_hostname") is not None:
        raise ValueError("blocked: overriding the TLS SNI hostname is not allowed")
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=follow_redirects,
        trust_env=False,
        transport=_PinnedAsyncHTTPTransport(),
    ) as client:
        async with client.stream("GET", url, **kwargs) as response:
            if _content_length_exceeds(response.headers, max_bytes):
                raise ResponseTooLargeError(f"Remote response exceeds the {max_bytes}-byte limit")
            chunks: list[bytes] = []
            total = 0
            async for chunk in response.aiter_bytes():
                total += len(chunk)
                if total > max_bytes:
                    raise ResponseTooLargeError(f"Remote response exceeds the {max_bytes}-byte limit")
                chunks.append(chunk)
            return httpx.Response(
                status_code=response.status_code,
                headers=response.headers,
                content=b"".join(chunks),
                request=response.request,
                extensions=response.extensions,
            )
