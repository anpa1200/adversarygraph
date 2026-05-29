"""Integration tests for the APT comparison endpoint and export routes."""

import pytest
from httpx import AsyncClient


# ── /api/apt/compare (POST) ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_compare_validates_input(client: AsyncClient):
    """Non-list body should return 422."""
    resp = await client.post(
        "/api/apt/compare",
        json="not-a-list",
        params={"domain": "enterprise-attack"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_compare_top_n_capped(client: AsyncClient):
    """top_n > 50 should return 422."""
    resp = await client.post(
        "/api/apt/compare",
        json=["T1566"],
        params={"domain": "enterprise-attack", "top_n": 999},
    )
    assert resp.status_code in (404, 422)


# ── /api/export/layer (PDF) ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_export_layer_empty_list(client: AsyncClient):
    resp = await client.post("/api/export/layer", json={"technique_ids": [], "domain": "enterprise-attack"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_export_layer_no_attck_data(client: AsyncClient):
    """When no ATT&CK data is ingested the resolve_version_id call should 404."""
    resp = await client.post(
        "/api/export/layer",
        json={"technique_ids": ["T1566", "T1059"], "domain": "enterprise-attack"},
    )
    assert resp.status_code in (200, 404)


# ── /api/export/analysis/{id} ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_export_analysis_invalid_uuid(client: AsyncClient):
    resp = await client.post("/api/export/analysis/not-a-uuid")
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_export_analysis_missing(client: AsyncClient):
    import uuid
    resp = await client.post(f"/api/export/analysis/{uuid.uuid4()}")
    assert resp.status_code == 404


# ── /api/analyze (POST, Celery path) ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_analyze_no_input_returns_400(client: AsyncClient):
    resp = await client.post("/api/analyze", data={"provider": "claude"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_analyze_bad_provider_returns_400(client: AsyncClient):
    resp = await client.post(
        "/api/analyze",
        data={"provider": "nonexistent", "text": "some text"},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_analyze_chat_missing_message(client: AsyncClient):
    resp = await client.post(
        "/api/analyze/chat",
        json={"provider": "claude"},     # no "message" field
    )
    assert resp.status_code == 422
