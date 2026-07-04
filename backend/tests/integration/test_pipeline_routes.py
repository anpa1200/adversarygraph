import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_pipeline_lists_and_identity(client: AsyncClient):
    for path in ("sources", "runs", "observables", "detections/versions", "audit"):
        response = await client.get(f"/api/pipeline/{path}")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
    me = await client.get("/api/pipeline/me")
    assert me.json()["name"] == "local"


@pytest.mark.asyncio
async def test_detection_validation_endpoint(client: AsyncClient):
    response = await client.post("/api/pipeline/detections/validate", json={"format": "sigma", "content": ""})
    assert response.status_code == 200
    assert response.json()["valid"] is False


@pytest.mark.asyncio
async def test_sandbox_behaviors_route_shape(client: AsyncClient):
    response = await client.get("/api/pipeline/sandbox/behaviors")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_sandbox_source_kind_is_accepted(client: AsyncClient):
    response = await client.post(
        "/api/pipeline/sources",
        json={
            "name": "Private Sandbox",
            "kind": "sandbox",
            "url": "https://sandbox.local/reports.json",
            "enabled": True,
            "interval_minutes": 1440,
            "config": {"limit": 50},
        },
    )
    assert response.status_code == 201


# ── Source CRUD ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_source_create_and_update(client: AsyncClient):
    payload = {
        "name": "Test RSS feed",
        "kind": "rss",
        "url": "https://example.com/feed.rss",
        "enabled": True,
        "interval_minutes": 60,
        "config": {},
    }
    create = await client.post("/api/pipeline/sources", json=payload)
    assert create.status_code == 201
    source_id = create.json()["id"]
    assert create.json()["name"] == "Test RSS feed"

    update = await client.put(
        f"/api/pipeline/sources/{source_id}",
        json={**payload, "name": "Updated RSS feed", "enabled": False},
    )
    assert update.status_code == 200
    assert update.json()["name"] == "Updated RSS feed"
    assert update.json()["enabled"] is False


@pytest.mark.asyncio
async def test_source_invalid_kind_rejected(client: AsyncClient):
    response = await client.post(
        "/api/pipeline/sources",
        json={"name": "Bad kind", "kind": "ftp", "url": "https://example.com"},
    )
    assert response.status_code == 422


# ── Observable create ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_observable_create(client: AsyncClient):
    response = await client.post(
        "/api/pipeline/observables",
        json={
            "type": "domain",
            "value": "test.example.com",
            "status": "new",
            "confidence": 75,
            "tags": ["phishing"],
        },
    )
    assert response.status_code == 201
    assert response.json()["type"] == "domain"
    assert response.json()["value"] == "test.example.com"
    assert response.json()["tags"] == ["tag:phishing"]


@pytest.mark.asyncio
async def test_observable_idempotent_upsert(client: AsyncClient):
    payload = {"type": "ip", "value": "192.0.2.1", "status": "new"}
    r1 = await client.post("/api/pipeline/observables", json=payload)
    r2 = await client.post("/api/pipeline/observables", json=payload)
    assert r1.status_code == 201
    assert r2.status_code == 201
    assert r1.json()["id"] == r2.json()["id"]


# ── Detection skeleton generation ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detection_generate_skeleton(client: AsyncClient):
    response = await client.post(
        "/api/pipeline/detections/generate",
        json={
            "title": "Suspicious PowerShell",
            "technique_id": "T1059.001",
            "format": "sigma",
            "telemetry": ["windows_process"],
            "use_ai": False,
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["technique_id"] == "T1059.001"
    assert data["format"] == "sigma"
    assert data["content"]
