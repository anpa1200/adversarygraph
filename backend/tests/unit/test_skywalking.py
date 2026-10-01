from __future__ import annotations

import httpx
import pytest

from app.services import skywalking


def _transport(responses: list[dict]) -> httpx.MockTransport:
    remaining = list(responses)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/graphql"
        return httpx.Response(200, json=remaining.pop(0), request=request)

    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_health_is_explicitly_disabled(monkeypatch):
    monkeypatch.setattr(skywalking.settings, "skywalking_enabled", False)
    result = await skywalking.health()
    assert result["status"] == "disabled"
    assert result["connected"] is False


@pytest.mark.asyncio
async def test_health_reports_connected_without_leaking_token(monkeypatch):
    monkeypatch.setattr(skywalking.settings, "skywalking_enabled", True)
    monkeypatch.setattr(skywalking.settings, "skywalking_graphql_url", "http://oap.test/graphql")
    monkeypatch.setattr(skywalking.settings, "skywalking_auth_token", "secret-token")
    result = await skywalking.health(
        transport=_transport([{"data": {"version": "10.2.0", "checkHealth": {"score": 0, "details": "healthy"}}}])
    )
    assert result["connected"] is True
    assert result["version"] == "10.2.0"
    assert "secret-token" not in str(result)


@pytest.mark.asyncio
async def test_topology_normalizes_runtime_provenance(monkeypatch):
    monkeypatch.setattr(skywalking.settings, "skywalking_enabled", True)
    monkeypatch.setattr(skywalking.settings, "skywalking_graphql_url", "http://oap.test/graphql")
    payload = {"data": {"topology": {
        "nodes": [
            {"id": "svc-a", "name": "frontend", "type": "HTTP", "isReal": True, "layers": ["GENERAL"]},
            {"id": "svc-b", "name": "postgres", "type": "PostgreSQL", "isReal": False, "layers": ["VIRTUAL_DATABASE"]},
        ],
        "calls": [{"id": "call-1", "source": "svc-a", "target": "svc-b",
                   "sourceComponents": ["HTTP"], "targetComponents": ["PostgreSQL"],
                   "detectPoints": ["CLIENT"]}],
    }}}
    result = await skywalking.topology(minutes=60, transport=_transport([payload]))
    assert result["counts"] == {"nodes": 2, "edges": 1}
    assert result["nodes"][0]["evidence_kind"] == "runtime_observation"
    assert result["edges"][0]["edge_type"] == "runtime_call"
    assert "not proof" in result["provenance"]["statement"]


@pytest.mark.asyncio
async def test_investigation_keeps_match_and_one_hop_neighbors(monkeypatch):
    monkeypatch.setattr(skywalking.settings, "skywalking_enabled", True)
    monkeypatch.setattr(skywalking.settings, "skywalking_graphql_url", "http://oap.test/graphql")
    payload = {"data": {"topology": {
        "nodes": [
            {"id": "a", "name": "checkout", "type": "HTTP", "isReal": True, "layers": []},
            {"id": "b", "name": "payments", "type": "gRPC", "isReal": True, "layers": []},
            {"id": "c", "name": "unrelated", "type": "HTTP", "isReal": True, "layers": []},
        ],
        "calls": [{"id": "ab", "source": "a", "target": "b",
                   "sourceComponents": [], "targetComponents": [], "detectPoints": []}],
    }}}
    result = await skywalking.topology(query="checkout", transport=_transport([payload]))
    assert {node["id"] for node in result["nodes"]} == {"a", "b"}
    assert [edge["id"] for edge in result["edges"]] == ["ab"]


@pytest.mark.asyncio
async def test_graphql_errors_are_safely_reported(monkeypatch):
    monkeypatch.setattr(skywalking.settings, "skywalking_enabled", True)
    monkeypatch.setattr(skywalking.settings, "skywalking_graphql_url", "http://oap.test/graphql")
    with pytest.raises(skywalking.SkyWalkingError, match="GraphQL error"):
        await skywalking.topology(
            transport=_transport([{"errors": [{"message": "unknown field getGlobalTopology"}]}])
        )


def test_endpoint_rejects_embedded_credentials(monkeypatch):
    monkeypatch.setattr(skywalking.settings, "skywalking_graphql_url", "http://user:password@oap.test/graphql")
    with pytest.raises(skywalking.SkyWalkingError, match="must not contain credentials"):
        skywalking._validated_endpoint()
