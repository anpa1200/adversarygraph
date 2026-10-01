from __future__ import annotations

from unittest.mock import AsyncMock, patch
from types import SimpleNamespace

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_skywalking_status_route(client: AsyncClient):
    payload = {"enabled": True, "connected": True, "status": "ok", "message": "Connected."}
    with patch("app.api.routes.observability.skywalking.health", AsyncMock(return_value=payload)):
        response = await client.get("/api/observability/skywalking/status")
    assert response.status_code == 200
    assert response.json()["connected"] is True


@pytest.mark.asyncio
async def test_platform_architecture_route_returns_provenance(client: AsyncClient):
    payload = {
        "generated_at": "2026-07-29T00:00:00+00:00",
        "window_minutes": 60,
        "nodes": [{"id": "api", "label": "AdversaryGraph API"}],
        "edges": [],
        "counts": {},
        "correlations": [],
        "streams": {},
        "api": {},
        "logs": {},
        "skywalking": {"health": {"status": "ok"}},
        "provenance": {"boundary": "Telemetry is not proof of compromise."},
    }
    with patch(
        "app.api.routes.observability.platform_architecture.snapshot",
        AsyncMock(return_value=payload),
    ) as architecture:
        response = await client.get(
            "/api/observability/architecture", params={"minutes": 360}
        )
    assert response.status_code == 200
    assert response.json()["nodes"][0]["id"] == "api"
    assert "not proof" in response.json()["provenance"]["boundary"]
    architecture.assert_awaited_once()
    assert architecture.await_args.kwargs["minutes"] == 360


@pytest.mark.asyncio
async def test_skywalking_investigation_validates_query(client: AsyncClient):
    response = await client.get("/api/observability/skywalking/investigate", params={"query": "x"})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_skywalking_investigation_returns_graph(client: AsyncClient):
    payload = {
        "source": "apache_skywalking", "scope": "global", "query": "checkout",
        "window_minutes": 60, "nodes": [], "edges": [],
        "counts": {"nodes": 0, "edges": 0}, "truncated": False,
        "provenance": {"classification": "runtime_observation",
                       "retrieved_at": "2026-07-29T00:00:00+00:00",
                       "statement": "Runtime observation."},
    }
    with patch("app.api.routes.observability.skywalking.topology", AsyncMock(return_value=payload)) as topology:
        response = await client.get(
            "/api/observability/skywalking/investigate",
            params={"query": "checkout", "minutes": 60},
        )
    assert response.status_code == 200
    assert response.json()["source"] == "apache_skywalking"
    topology.assert_awaited_once()


@pytest.mark.asyncio
async def test_skywalking_sync_persists_and_reindexes_runtime_evidence(client: AsyncClient):
    topology_payload = {
        "source": "apache_skywalking", "scope": "global", "query": "",
        "window_minutes": 60, "nodes": [], "edges": [],
        "counts": {"nodes": 0, "edges": 0}, "truncated": False,
        "provenance": {"classification": "runtime_observation"},
    }
    persisted = {
        "snapshot_id": "11111111-1111-1111-1111-111111111111",
        "services_created": 0, "services_updated": 0,
        "calls_created": 0, "calls_updated": 0, "asset_links_created": 0,
    }
    rag_result = SimpleNamespace(
        status="completed",
        to_dict=lambda: {"status": "completed", "documents_seen": 0},
    )
    with (
        patch("app.api.routes.observability.skywalking.topology", AsyncMock(return_value=topology_payload)),
        patch("app.api.routes.observability.runtime_intelligence.persist_topology", AsyncMock(return_value=persisted)),
        patch("app.api.routes.observability.runtime_intelligence.enforce_retention", AsyncMock(return_value={})),
        patch("app.api.routes.observability.rag_service.reconcile_corpus", AsyncMock(return_value=rag_result)) as reconcile,
        patch("app.api.routes.observability.audit", AsyncMock()),
    ):
        response = await client.post(
            "/api/observability/skywalking/sync",
            json={"minutes": 60, "tlp": "TLP:AMBER+STRICT"},
        )
    assert response.status_code == 200
    assert response.json()["rag"]["status"] == "completed"
    assert reconcile.await_args.kwargs["source_types"] == ["runtime_service"]


@pytest.mark.asyncio
async def test_stored_runtime_graph_route(client: AsyncClient):
    payload = {
        "source": "adversarygraph_runtime_store",
        "nodes": [], "edges": [], "asset_links": [],
        "counts": {"nodes": 0, "edges": 0},
    }
    with patch(
        "app.api.routes.observability.runtime_intelligence.list_runtime_graph",
        AsyncMock(return_value=payload),
    ):
        response = await client.get("/api/observability/runtime-graph")
    assert response.status_code == 200
    assert response.json()["source"] == "adversarygraph_runtime_store"


@pytest.mark.asyncio
async def test_runtime_promotion_requires_valid_uuid(client: AsyncClient):
    response = await client.post(
        "/api/observability/runtime-graph/promote",
        json={"service_ids": ["not-a-uuid"]},
    )
    assert response.status_code == 422
