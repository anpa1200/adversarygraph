import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_asset_surface_analyze_saves_registry_and_runs_retrohunt(client: AsyncClient):
    response = await client.post(
        "/api/asset-surface/analyze",
        data={
            "provider": "local",
            "use_ai": "false",
            "inventory_name": "unit asset inventory",
            "text": (
                "asset_id,name,asset_type,environment,owner,ip_addresses,domains,ports,technologies,products,suppliers,dependencies,exposure,criticality,tags\n"
                "asset-0001,customer-portal,web-app,prod,Digital,203.0.113.10,portal.example.com,\"80;443\",nginx,portal,internal,npm,internet,critical,customer-data\n"
            ),
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["case_id"]
    assert payload["registry_summary"]["created"] == 1
    assert payload["retrohunt_summary"]["assets_checked"] == 1
    assert payload["assets"][0]["technologies"] == ["nginx"]
    assert payload["assets"][0]["products"] == ["portal"]


@pytest.mark.asyncio
async def test_asset_surface_csv_schema_endpoint_returns_strict_header(client: AsyncClient):
    response = await client.get("/api/asset-surface/csv-schema")

    assert response.status_code == 200
    payload = response.json()
    assert payload["template_header"].startswith("asset_id,name,asset_type")
    assert "products" not in payload["columns"]
    assert "suppliers" not in payload["columns"]
    assert "dependencies" not in payload["columns"]
    assert "technologies" in payload["columns"]


@pytest.mark.asyncio
async def test_asset_surface_retrohunt_endpoint_accepts_saved_assets(client: AsyncClient):
    create_response = await client.post(
        "/api/asset-surface/analyze",
        data={
            "provider": "local",
            "use_ai": "false",
            "inventory_name": "unit asset inventory",
            "text": "vpn.example.com 198.51.100.20 ports 443 public vpn",
        },
    )
    assert create_response.status_code == 200

    response = await client.post("/api/asset-surface/retrohunt", json={"asset_ids": []})

    assert response.status_code == 200
    assert response.json()["assets_checked"] >= 1
