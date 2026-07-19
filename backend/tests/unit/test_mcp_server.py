from __future__ import annotations

from types import SimpleNamespace
from urllib.parse import urlsplit

import httpx
import pytest

from app import mcp_server


class _FakeClient:
    def __init__(self, response: httpx.Response, calls: dict):
        self.response = response
        self.calls = calls

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    def stream(self, method, url, **kwargs):
        self.calls.update({"method": method, "url": url, "kwargs": kwargs})
        return _FakeResponseContext(self.response)


class _FakeResponseContext:
    def __init__(self, response: httpx.Response):
        self.response = response

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, *_args):
        return None


def _response(status: int, payload: object) -> httpx.Response:
    request = httpx.Request("GET", "http://adversarygraph.invalid/fixed")
    return httpx.Response(status, json=payload, request=request)


def test_mcp_settings_do_not_require_platform_database_credentials(monkeypatch):
    monkeypatch.delenv("DB_PASS", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)

    isolated = mcp_server.MCPSettings(_env_file=None)

    assert isolated.mcp_transport == "stdio"
    assert isolated.mcp_api_base_url == "http://127.0.0.1:3000"
    assert set(type(isolated).model_fields) == {
        "mcp_transport",
        "mcp_api_base_url",
        "mcp_api_token",
        "auth_enabled",
    }


@pytest.fixture
def local_api(monkeypatch):
    monkeypatch.setattr(mcp_server.settings, "mcp_api_base_url", "http://127.0.0.1:8000")
    monkeypatch.setattr(mcp_server.settings, "mcp_api_token", "")
    monkeypatch.setattr(mcp_server.settings, "auth_enabled", False)


@pytest.mark.parametrize(
    "value",
    [
        "",
        "file:///tmp/api",
        "https://user:password@example.com",
        "https://example.com/api",
        "https://example.com?next=https://attacker.invalid",
        "https://example.com/#fragment",
        "https://example.com:99999",
        "https://example.com\n.invalid",
    ],
)
def test_api_base_url_rejects_unsafe_shapes(value):
    with pytest.raises(mcp_server.MCPConfigurationError):
        mcp_server._validated_base_url(value)


def test_api_base_url_rejects_public_plain_http_and_allows_https_or_private_http():
    with pytest.raises(mcp_server.MCPConfigurationError, match="Plain HTTP"):
        mcp_server._validated_base_url("http://api.example.com")

    assert mcp_server._validated_base_url("https://api.example.com") == "https://api.example.com"
    assert mcp_server._validated_base_url("http://api:8000") == "http://api:8000"


def test_api_urls_are_fixed_and_entity_segments_are_encoded(local_api):
    assert mcp_server._build_url(mcp_server._Endpoint.SEARCH) == "http://127.0.0.1:8000/api/rag/search"

    url = mcp_server._build_url(
        mcp_server._Endpoint.ENTITY,
        source_type="cve",
        source_id="CVE/../../proposals/abc/confirm?mode=replace",
    )
    parsed = urlsplit(url)
    assert parsed.query == ""
    assert parsed.fragment == ""
    assert parsed.path.startswith("/api/rag/entity/cve/CVE%2F..%2F..%2Fproposals%2Fabc%2Fconfirm%3F")
    assert parsed.path.count("/") == 5

    with pytest.raises(mcp_server.MCPConfigurationError, match="allowlisted"):
        mcp_server._build_url("/api/rag/reindex")  # type: ignore[arg-type]


def test_endpoint_policy_contains_no_confirmation_or_mutation_route():
    assert {endpoint for endpoint in mcp_server._Endpoint} == {
        mcp_server._Endpoint.SEARCH,
        mcp_server._Endpoint.ASSIST,
        mcp_server._Endpoint.ENTITY,
    }
    for endpoint in mcp_server._Endpoint:
        assert endpoint.path in {"/api/rag/search", "/api/rag/assist", "/api/rag/entity"}
        assert "/confirm" not in endpoint.path
        assert "/reindex" not in endpoint.path
        assert "/layers" not in endpoint.path


@pytest.mark.asyncio
async def test_stable_sdk_registers_four_tools_with_security_annotations():
    if mcp_server.mcp is None:
        pytest.skip("MCP SDK dependencies are not installed in this diagnostic environment")

    tools = {tool.name: tool for tool in await mcp_server.mcp.list_tools()}

    assert set(tools) == {
        "search_intelligence",
        "ask_intelligence",
        "get_indexed_entity",
        "propose_navigator_layer",
    }
    assert tools["search_intelligence"].annotations.readOnlyHint is True
    assert tools["get_indexed_entity"].annotations.readOnlyHint is True
    assert tools["ask_intelligence"].annotations.destructiveHint is False
    assert tools["propose_navigator_layer"].annotations.destructiveHint is False
    assert all(tool.annotations.openWorldHint is False for tool in tools.values())
    assert tools["search_intelligence"].inputSchema["properties"]["query"]["maxLength"] == 2_000
    assert tools["search_intelligence"].inputSchema["properties"]["limit"]["maximum"] == 25


@pytest.mark.asyncio
async def test_search_validates_hard_input_bounds_before_api_call(monkeypatch, local_api):
    async def should_not_run(*_args, **_kwargs):
        pytest.fail("API request should not run for invalid MCP input")

    monkeypatch.setattr(mcp_server, "_request_json", should_not_run)

    with pytest.raises(mcp_server.MCPInputError, match="2000"):
        await mcp_server.search_intelligence("x" * 2_001)
    with pytest.raises(mcp_server.MCPInputError, match="between 1 and 25"):
        await mcp_server.search_intelligence("ioc", limit=26)
    with pytest.raises(mcp_server.MCPInputError, match="source_type"):
        await mcp_server.search_intelligence("ioc", source_types=["not-a-source"])  # type: ignore[list-item]
    with pytest.raises(mcp_server.MCPInputError, match="domain"):
        await mcp_server.search_intelligence("ioc", domain="unknown")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_search_calls_only_search_and_preserves_provenance(monkeypatch, local_api):
    captured = {}

    async def fake_request(endpoint, **kwargs):
        captured.update({"endpoint": endpoint, **kwargs})
        return {
            "retrieval_mode": "exact+fts+vector",
            "corpus_indexed_at": "2026-07-19T10:00:00Z",
            "warnings": [],
            "items": [
                {
                    "chunk_id": "chunk-1",
                    "document_id": "doc-1",
                    "source_type": "ioc",
                    "source_id": "203.0.113.10",
                    "title": "Observed infrastructure",
                    "excerpt": "Evidence excerpt",
                    "route": "/ioc/203.0.113.10",
                    "tlp": "TLP:AMBER",
                    "score": 0.91,
                    "content_hash": "a" * 64,
                    "metadata": {"feed": "example"},
                }
            ],
        }

    monkeypatch.setattr(mcp_server, "_request_json", fake_request)
    result = await mcp_server.search_intelligence(
        "Israel technology company indicators",
        source_types=["ioc", "attack_group"],
        client_profile_id=4,
    )

    assert captured["endpoint"] is mcp_server._Endpoint.SEARCH
    assert captured["body"]["source_types"] == ["ioc", "attack_group"]
    assert result["provenance_preserved"] is True
    assert result["items"][0]["provenance"] == {
        "source_type": "ioc",
        "source_id": "203.0.113.10",
        "content_hash": "a" * 64,
    }


@pytest.mark.asyncio
async def test_assistant_is_pinned_to_local_provider_without_cloud_ack(monkeypatch, local_api):
    captured = {}

    async def fake_request(endpoint, **kwargs):
        captured.update({"endpoint": endpoint, **kwargs})
        return {
            "answer": "Relevant evidence [S1]",
            "citations": [
                {
                    "source_ref": "S1",
                    "source_type": "cve",
                    "source_id": "CVE-2026-12345",
                    "title": "Example",
                    "excerpt": "Evidence",
                    "tlp": "TLP:GREEN",
                    "legal_sensitive": True,
                    "verified": True,
                }
            ],
            "retrieval_mode": "fts+vector",
            "effective_tlp": "TLP:GREEN",
        }

    monkeypatch.setattr(mcp_server, "_request_json", fake_request)
    result = await mcp_server.ask_intelligence("What matters to this business?")

    assert captured["endpoint"] is mcp_server._Endpoint.ASSIST
    assert captured["body"]["provider"] == "local"
    assert captured["body"]["cloud_processing_acknowledged"] is False
    assert result["citations"][0]["verified"] is True
    assert result["citations"][0]["legal_sensitive"] is True
    assert result["provenance_preserved"] is True


@pytest.mark.asyncio
async def test_navigator_tool_only_requests_proposal_and_never_confirms(monkeypatch, local_api):
    calls = []

    async def fake_request(endpoint, **kwargs):
        calls.append((endpoint, kwargs))
        return {
            "answer": "Suggested mapping [S1]",
            "citations": [{"source_ref": "S1", "verified": True}],
            "navigator_proposal": {
                "id": "8fe5c006-1af1-4b86-93fe-83c74a018cbc",
                "name": "Reviewed mapping",
                "domain": "enterprise-attack",
                "attack_version": "16.1",
                "technique_ids": ["T1059", "T1059.001"],
                "rationale": "Supported by S1",
                "proposal_checksum": "a" * 64,
                "expires_at": "2026-07-19T12:30:00Z",
            },
        }

    monkeypatch.setattr(mcp_server, "_request_json", fake_request)
    result = await mcp_server.propose_navigator_layer("Paste relevant TTPs on Navigator")

    assert len(calls) == 1
    assert calls[0][0] is mcp_server._Endpoint.ASSIST
    assert result["confirmation_performed"] is False
    assert result["navigator_state_changed"] is False
    assert result["saved_layer_created"] is False
    assert result["navigator_proposal"]["requires_confirmation"] is True


@pytest.mark.asyncio
async def test_entity_id_bound_is_enforced_before_request(monkeypatch, local_api):
    async def should_not_run(*_args, **_kwargs):
        pytest.fail("API request should not run for invalid source ID")

    monkeypatch.setattr(mcp_server, "_request_json", should_not_run)
    with pytest.raises(mcp_server.MCPInputError, match="255"):
        await mcp_server.get_indexed_entity("ioc", "x" * 256)


def test_entity_output_preserves_policy_and_partial_chunk_markers():
    result = mcp_server._entity_output({
        "document_id": "doc-1",
        "source_type": "analysis_report",
        "source_id": "report-1",
        "tlp": "TLP:AMBER",
        "legal_sensitive": True,
        "chunk_count": 73,
        "chunks_truncated": True,
        "chunks": [{"id": "chunk-1", "content": "bounded evidence"}],
    })

    assert result["legal_sensitive"] is True
    assert result["chunk_count"] == 73
    assert result["chunks_truncated"] is True
    assert len(result["chunks"]) == 1


def test_non_stdio_transport_fails_closed_before_sdk_run(monkeypatch, local_api):
    fake_mcp = SimpleNamespace(run=lambda **_kwargs: pytest.fail("MCP SDK must not start"))
    monkeypatch.setattr(mcp_server, "mcp", fake_mcp)
    monkeypatch.setattr(mcp_server, "_MCP_IMPORT_ERROR", None)

    with pytest.raises(mcp_server.MCPConfigurationError, match="Only MCP stdio"):
        mcp_server.run_server("streamable-http")
    with pytest.raises(mcp_server.MCPConfigurationError, match="Only MCP stdio"):
        mcp_server.run_server("sse")


def test_auth_enabled_requires_api_token(monkeypatch, local_api):
    monkeypatch.setattr(mcp_server.settings, "auth_enabled", True)
    monkeypatch.setattr(mcp_server.settings, "mcp_api_token", "")
    monkeypatch.setattr(mcp_server, "_MCP_IMPORT_ERROR", None)
    monkeypatch.setattr(mcp_server, "mcp", SimpleNamespace(run=lambda **_kwargs: None))

    with pytest.raises(mcp_server.MCPConfigurationError, match="MCP_API_TOKEN is required"):
        mcp_server.run_server("stdio")


def test_auth_disabled_local_mode_can_start_without_token(monkeypatch, local_api):
    calls = []
    monkeypatch.setattr(mcp_server, "_MCP_IMPORT_ERROR", None)
    monkeypatch.setattr(mcp_server, "mcp", SimpleNamespace(run=lambda **kwargs: calls.append(kwargs)))

    mcp_server.run_server("stdio")

    assert calls == [{"transport": "stdio"}]


@pytest.mark.asyncio
async def test_http_errors_are_sanitized_and_do_not_echo_body_token_or_url(monkeypatch, local_api):
    calls = {}
    secret = "DATABASE_PASSWORD=do-not-disclose"
    token = "session-token-do-not-disclose"
    monkeypatch.setattr(mcp_server.settings, "mcp_api_token", token)
    response = _response(500, {"detail": secret, "traceback": "/internal/path"})
    monkeypatch.setattr(mcp_server, "_new_http_client", lambda _timeout: _FakeClient(response, calls))

    with pytest.raises(mcp_server.MCPAPIError) as exc_info:
        await mcp_server._request_json(mcp_server._Endpoint.SEARCH, body={"query": "safe"})

    message = str(exc_info.value)
    assert message == "AdversaryGraph API is temporarily unavailable"
    assert secret not in message
    assert token not in message
    assert "127.0.0.1" not in message
    assert calls["kwargs"]["headers"]["Authorization"] == f"Bearer {token}"


@pytest.mark.asyncio
async def test_chunked_response_is_stopped_at_decoded_size_limit(monkeypatch, local_api):
    class OversizedResponse:
        status_code = 200
        headers = {}

        async def aiter_bytes(self):
            yield b"{" + b"x" * (1024 * 1024)
            yield b"y" * (1024 * 1024 + 1)

    monkeypatch.setattr(
        mcp_server,
        "_new_http_client",
        lambda _timeout: _FakeClient(OversizedResponse(), {}),  # type: ignore[arg-type]
    )

    with pytest.raises(mcp_server.MCPAPIError, match="safety limit"):
        await mcp_server._request_json(mcp_server._Endpoint.SEARCH, body={"query": "safe"})


@pytest.mark.asyncio
async def test_client_disables_redirects_and_environment_proxy(monkeypatch, local_api):
    captured = {}
    real_client = httpx.AsyncClient
    response = _response(200, {"items": [], "warnings": []})

    def fake_async_client(**kwargs):
        captured.update(kwargs)
        return _FakeClient(response, {})

    monkeypatch.setattr(httpx, "AsyncClient", fake_async_client)
    try:
        await mcp_server._request_json(mcp_server._Endpoint.SEARCH, body={"query": "safe"})
    finally:
        monkeypatch.setattr(httpx, "AsyncClient", real_client)

    assert captured["follow_redirects"] is False
    assert captured["trust_env"] is False
