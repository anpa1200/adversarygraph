import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_taxonomy_status_route(client: AsyncClient):
    response = await client.get("/api/system/taxonomy/status")

    assert response.status_code == 200
    payload = response.json()
    assert payload["convention"] == "namespace:value"
    assert "normalized" in payload


@pytest.mark.asyncio
async def test_taxonomy_normalize_route(client: AsyncClient):
    response = await client.post("/api/system/taxonomy/normalize")

    assert response.status_code == 200
    payload = response.json()
    assert "rows_changed" in payload
    assert "tables" in payload
