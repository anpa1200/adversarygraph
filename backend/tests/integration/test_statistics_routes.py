import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_statistics_overview_returns_widget_shape(client: AsyncClient):
    response = await client.get(
        "/api/statistics/overview",
        params=[
            ("domain", "enterprise-attack"),
            ("include", "actors"),
            ("include", "ttps"),
            ("include", "cves"),
            ("limit", "10"),
        ],
    )
    assert response.status_code == 200
    body = response.json()
    assert body["domain"] == "enterprise-attack"
    assert body["included"] == ["actors", "ttps", "cves"]
    assert isinstance(body["totals"], list)
    assert isinstance(body["widgets"], list)
    assert all({"id", "title", "dataset", "kind", "points"} <= set(widget) for widget in body["widgets"])


@pytest.mark.asyncio
async def test_statistics_invalid_include_falls_back(client: AsyncClient):
    response = await client.get("/api/statistics/overview", params={"include": "not-a-dataset"})
    assert response.status_code == 200
    body = response.json()
    assert sorted(body["included"]) == ["actors", "cves", "iocs", "reports", "sectors", "ttps"]
