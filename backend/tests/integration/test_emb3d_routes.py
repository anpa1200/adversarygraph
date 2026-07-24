from __future__ import annotations

import pytest

from app.api.routes import emb3d
from app.services.emb3d import Emb3dDataUnavailable, parse_emb3d_bundle


@pytest.fixture(autouse=True)
def _emb3d_reference_data(monkeypatch):
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "x-mitre-emb3d-property",
                "id": "x-mitre-emb3d-property--network",
                "name": "Device exposes remote network services",
                "category": "Networking",
                "x_mitre_emb3d_property_id": "PID-41",
            },
            {
                "type": "vulnerability",
                "id": "vulnerability--network",
                "name": "Exploitable network service",
                "x_mitre_emb3d_threat_id": "TID-210",
            },
            {
                "type": "relationship",
                "relationship_type": "relates-to",
                "source_ref": "x-mitre-emb3d-property--network",
                "target_ref": "vulnerability--network",
            },
        ],
    }
    monkeypatch.setattr(
        emb3d,
        "load_emb3d_knowledge_base",
        lambda: parse_emb3d_bundle(bundle),
    )


@pytest.mark.asyncio
async def test_emb3d_catalog_is_available(client):
    response = await client.get("/api/emb3d/catalog")
    assert response.status_code == 200
    payload = response.json()
    assert payload["properties"]


@pytest.mark.asyncio
async def test_emb3d_preview_returns_an_assessment(client):
    response = await client.post(
        "/api/emb3d/preview",
        json={
            "asset_id": "demo-plc-01",
            "name": "Demo PLC",
            "asset_type": "plc",
            "environment": "production",
            "exposure": "internet",
            "criticality": "high",
            "ports": [502],
            "technologies": ["modbus"],
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["asset_count"] == 1
    assert payload["assets"][0]["inventory_asset_id"] == "demo-plc-01"


@pytest.mark.asyncio
async def test_emb3d_asset_report_handles_an_empty_registry(client):
    response = await client.get("/api/emb3d/assets/report?limit=10")
    assert response.status_code == 200
    assert response.json()["asset_count"] == 0


@pytest.mark.asyncio
async def test_emb3d_assessment_rejects_invalid_asset_ids(client):
    response = await client.post(
        "/api/emb3d/assets/assess",
        json={"asset_ids": ["not-a-uuid"]},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Invalid asset ID"


@pytest.mark.asyncio
async def test_emb3d_returns_controlled_dependency_error_without_reference_data(client, monkeypatch):
    def unavailable():
        raise Emb3dDataUnavailable("EMB3D reference data is unavailable.")

    monkeypatch.setattr(emb3d, "load_emb3d_knowledge_base", unavailable)

    response = await client.get("/api/emb3d/catalog")

    assert response.status_code == 503
    assert response.json()["detail"] == "EMB3D reference data is unavailable."
