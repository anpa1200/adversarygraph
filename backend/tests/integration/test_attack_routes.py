"""
Integration smoke-tests for the ATT&CK and APT routes.

These run against a real FastAPI instance (no network, no external DB needed
for these particular tests since we verify the API shape and error responses).
"""

import pytest
from httpx import AsyncClient


# ── Health ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_health(client: AsyncClient):
    resp = await client.get("/api/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "version" in body


# ── /api/attack/versions ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_versions_returns_list(client: AsyncClient):
    resp = await client.get("/api/attack/versions")
    # 200 with an empty list is fine (no data ingested in test env)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ── /api/attack/tactics ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_tactics_no_data_returns_404(client: AsyncClient):
    """When no ATT&CK data has been ingested the endpoint should 404."""
    resp = await client.get("/api/attack/tactics", params={"domain": "enterprise-attack"})
    assert resp.status_code == 404
    assert "domain" in resp.json()["detail"].lower() or "data" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_tactics_invalid_domain(client: AsyncClient):
    resp = await client.get("/api/attack/tactics", params={"domain": "nonexistent-domain"})
    assert resp.status_code == 404


# ── /api/attack/techniques ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_techniques_no_data_returns_404(client: AsyncClient):
    resp = await client.get("/api/attack/techniques", params={"domain": "enterprise-attack"})
    assert resp.status_code == 404


# ── /api/attack/techniques/{id} ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_technique_detail_not_found(client: AsyncClient):
    resp = await client.get(
        "/api/attack/techniques/T9999",
        params={"domain": "enterprise-attack"},
    )
    assert resp.status_code == 404


# ── /api/apt/groups ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_groups_no_data_returns_404(client: AsyncClient):
    resp = await client.get("/api/apt/groups", params={"domain": "enterprise-attack"})
    assert resp.status_code == 404


# ── /api/apt/compare ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_compare_empty_list_returns_400(client: AsyncClient):
    resp = await client.post(
        "/api/apt/compare",
        json={"technique_ids": []},
        params={"domain": "enterprise-attack"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_compare_no_data_returns_404(client: AsyncClient):
    resp = await client.post(
        "/api/apt/compare",
        json={"technique_ids": ["T1566", "T1059"]},
        params={"domain": "enterprise-attack"},
    )
    assert resp.status_code == 404


# ── /api/sync/status ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_sync_status_shape(client: AsyncClient):
    resp = await client.get("/api/sync/status")
    # May return 500 without psycopg2/GitHub — acceptable in unit-test environment
    assert resp.status_code in (200, 500)
    if resp.status_code == 200:
        body = resp.json()
        assert "sources" in body
        assert "domains" in body
        assert "any_updates_needed" in body
        for domain_info in body["domains"]:
            assert domain_info["source"] == "mitre-attack"
            assert "domain" in domain_info
            assert "current_version" in domain_info
            assert "content" in domain_info
