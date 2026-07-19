"""Integration tests for /api/layers routes."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_layers_list_returns_empty_list(client: AsyncClient):
    response = await client.get("/api/layers")
    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.asyncio
async def test_layers_get_invalid_id_returns_400(client: AsyncClient):
    response = await client.get("/api/layers/not-a-uuid")
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_layers_get_unknown_returns_404(client: AsyncClient):
    response = await client.get("/api/layers/00000000-0000-0000-0000-000000000020")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_layers_delete_invalid_id_returns_400(client: AsyncClient):
    response = await client.delete("/api/layers/not-a-uuid")
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_layers_delete_unknown_returns_404(client: AsyncClient):
    response = await client.delete("/api/layers/00000000-0000-0000-0000-000000000021")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_layers_create_missing_name_returns_422(client: AsyncClient):
    response = await client.post("/api/layers", json={"domain": "enterprise-attack", "technique_ids": ["T1059"]})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_layers_create_empty_techniques_returns_422(client: AsyncClient):
    response = await client.post(
        "/api/layers",
        json={"name": "Test Layer", "domain": "enterprise-attack", "technique_ids": []},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_layers_create_rejects_malformed_technique_before_catalog_lookup(client: AsyncClient):
    response = await client.post(
        "/api/layers",
        json={"name": "Unsafe Layer", "domain": "enterprise-attack", "technique_ids": ["not-an-id"]},
    )
    assert response.status_code == 422
    assert "Malformed" in response.json()["detail"]


@pytest.mark.asyncio
async def test_layers_create_rejects_unknown_domain(client: AsyncClient):
    response = await client.post(
        "/api/layers",
        json={"name": "Wrong domain", "domain": "unknown-attack", "technique_ids": ["T1059"]},
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "Unsupported ATT&CK domain"
