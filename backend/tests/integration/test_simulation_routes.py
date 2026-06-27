import pytest


@pytest.mark.asyncio
async def test_simulation_catalog_route(client):
    response = await client.get("/api/simulation/catalog")
    assert response.status_code == 200
    assert any(item["technique_id"] == "T1595" for item in response.json())


@pytest.mark.asyncio
async def test_simulation_plan_route(client):
    response = await client.post(
        "/api/simulation/plan",
        json={"simulation_id": "sim-t1595-http-fingerprint", "target_id": "lab-web-01"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["allowed"] is True
    assert payload["execution_mode"] == "dry_run_required"


@pytest.mark.asyncio
async def test_simulation_run_record_route_does_not_emit_traffic(client):
    response = await client.post(
        "/api/simulation/run",
        json={"simulation_id": "sim-t1595-http-fingerprint", "target_id": "lab-web-01", "analyst_note": "route test"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["traffic_emitted"] is False
    assert payload["status"] == "completed_record_only"
