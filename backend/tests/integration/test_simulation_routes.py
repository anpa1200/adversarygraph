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
async def test_simulation_run_record_route_collects_local_web_telemetry(client):
    response = await client.post(
        "/api/simulation/run",
        json={"simulation_id": "sim-t1595-http-fingerprint", "target_id": "lab-web-01", "analyst_note": "route test"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["traffic_emitted"] is True
    assert payload["status"] == "completed_with_local_lab_telemetry"
    assert payload["telemetry"]["server"]["url"] == "http://127.0.0.1:8765"
    assert payload["telemetry"]["request_count"] == 2
    logs = await client.get("/api/simulation/logs", params={"source": "web", "run_id": payload["run_id"], "limit": 10})
    assert logs.status_code == 200
    log_payload = logs.json()
    assert log_payload["exists"] is True
    assert log_payload["events"]
    assert all(item["run_id"] == payload["run_id"] for item in log_payload["events"])


@pytest.mark.asyncio
async def test_simulation_forward_logs_rejects_unsafe_scheme(client):
    response = await client.post(
        "/api/simulation/forward-logs",
        json={"source": "web", "destination_url": "file:///tmp/collector", "limit": 10},
    )
    assert response.status_code == 400
