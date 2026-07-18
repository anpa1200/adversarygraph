from urllib.parse import parse_qsl, urlsplit

import pytest
from httpx import AsyncClient

from app.models.pipeline import CollectionSource
from tests import conftest


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

    assert (
        await client.get("/api/pipeline/sandbox/behaviors", params={"limit": 0})
    ).status_code == 422


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


@pytest.mark.asyncio
async def test_source_listing_redacts_nested_secret_config(client: AsyncClient):
    source = CollectionSource(
        name="Credentialed feed",
        kind="rss",
        url=(
            "https://feed-user:feed-password@example.test/feed"
            "?topic=apt&api_key=query-secret&cursor=123"
            "#access_token=fragment-secret"
        ),
        enabled=True,
        interval_minutes=60,
        config={
            "limit": 25,
            "api_key": "top-secret",
            "nested": {"access_token": "nested-secret", "region": "eu"},
        },
    )
    conftest._mock_session.add(source)

    response = await client.get("/api/pipeline/sources")

    assert response.status_code == 200
    config = response.json()[0]["config"]
    assert config["limit"] == 25
    assert config["api_key"] == "[REDACTED]"
    assert config["nested"] == {"access_token": "[REDACTED]", "region": "eu"}
    safe_url = urlsplit(response.json()[0]["url"])
    assert safe_url.username is None
    assert safe_url.password is None
    assert safe_url.netloc == "example.test"
    assert safe_url.fragment == ""
    assert dict(parse_qsl(safe_url.query)) == {
        "topic": "apt",
        "api_key": "[REDACTED]",
        "cursor": "123",
    }


@pytest.mark.asyncio
async def test_pipeline_rejects_unbounded_payload_and_provider_values(client: AsyncClient):
    oversized = await client.post(
        "/api/pipeline/detections/validate",
        json={"format": "sigma", "content": "x" * 250_001},
    )
    invalid_provider = await client.post(
        "/api/pipeline/observables/11111111-1111-4111-8111-111111111111/enrich",
        params={"provider": "attacker-selected"},
    )

    assert oversized.status_code == 422
    assert invalid_provider.status_code == 422


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
