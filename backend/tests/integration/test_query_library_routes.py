from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from app.api.routes import query_library


@pytest.fixture(autouse=True)
def _query_library_services(monkeypatch):
    monkeypatch.setattr(
        query_library.library,
        "ensure_curated_library",
        AsyncMock(return_value=None),
    )


@pytest.mark.asyncio
async def test_query_library_search_facets_and_autocomplete(client, monkeypatch):
    monkeypatch.setattr(
        query_library.library,
        "search_library",
        AsyncMock(return_value=([], 0)),
    )
    monkeypatch.setattr(
        query_library.library,
        "facets",
        AsyncMock(return_value={"languages": ["sigma", "yaral"]}),
    )
    monkeypatch.setattr(
        query_library.library,
        "autocomplete",
        AsyncMock(return_value=[{"value": "T1059.003", "type": "technique"}]),
    )

    search = await client.get("/api/query-library?q=powershell")
    facets = await client.get("/api/query-library/facets")
    autocomplete = await client.get("/api/query-library/autocomplete?q=T1059")

    assert search.status_code == 200
    assert search.json() == {"items": [], "total": 0, "limit": 50, "offset": 0}
    assert facets.status_code == 200
    assert facets.json()["languages"] == ["sigma", "yaral"]
    assert autocomplete.status_code == 200
    assert autocomplete.json()["items"][0]["value"] == "T1059.003"


@pytest.mark.asyncio
async def test_query_library_builds_multiple_query_formats(client, monkeypatch):
    monkeypatch.setattr(
        query_library.library,
        "resolve_iocs",
        AsyncMock(
            return_value=(
                [{"value": "198.51.100.4", "type": "ipv4"}],
                ["T1071.001"],
            )
        ),
    )

    sigma = await client.post(
        "/api/query-library/build-from-ioc",
        json={"observables": [{"value": "198.51.100.4", "type": "ipv4"}], "language": "sigma"},
    )
    yaral = await client.post(
        "/api/query-library/build-from-ioc",
        json={"observables": [{"value": "198.51.100.4", "type": "ipv4"}], "language": "yaral"},
    )

    assert sigma.status_code == 200
    assert sigma.json()["query_language"] == "sigma"
    assert "198.51.100.4" in sigma.json()["query_text"]
    assert yaral.status_code == 200
    assert yaral.json()["query_language"] == "yaral"
    assert "198.51.100.4" in yaral.json()["query_text"]


@pytest.mark.asyncio
async def test_query_library_sync_and_missing_item(client, monkeypatch):
    monkeypatch.setattr(
        query_library.library,
        "import_detection_versions",
        AsyncMock(return_value={"status": "ok", "imported": 12}),
    )

    sync = await client.post("/api/query-library/sync")
    missing = await client.get("/api/query-library/00000000-0000-0000-0000-000000000000")

    assert sync.status_code == 200
    assert sync.json() == {"status": "ok", "imported": 12}
    assert missing.status_code == 404
