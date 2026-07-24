import pytest
from unittest.mock import AsyncMock
from httpx import AsyncClient

from app.api.routes import statistics
from app.core.config import settings
from app.services.auth import TeamUser, current_user


@pytest.fixture(autouse=True)
def _auth_disabled_by_default(monkeypatch, app):
    monkeypatch.setattr(settings, "auth_enabled", False)

    async def test_user():
        return TeamUser(
            name="test-analyst",
            roles=["admin", "analyst", "viewer"],
            permissions=["read", "run_analysis", "export_data", "manage_auth"],
        )

    app.dependency_overrides[current_user] = test_user
    yield
    app.dependency_overrides.pop(current_user, None)


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
    widget_ids = {widget["id"] for widget in body["widgets"]}
    assert {
        "ttp-platform-tags",
        "ttp-telemetry-source-tags",
        "cve-risk-tags",
        "cve-attack-vector-tags",
        "global-entity-tag-cloud",
    } <= widget_ids
    assert "ttp-type-tags" not in widget_ids


@pytest.mark.asyncio
async def test_statistics_invalid_include_falls_back(client: AsyncClient):
    response = await client.get("/api/statistics/overview", params={"include": "not-a-dataset"})
    assert response.status_code == 200
    body = response.json()
    assert sorted(body["included"]) == ["actors", "cves", "iocs", "reports", "sectors", "ttps"]


@pytest.mark.asyncio
async def test_cross_dataset_pressure_preaggregates_each_large_relationship_table(
    client: AsyncClient,
    monkeypatch,
):
    rows = AsyncMock(return_value=[])
    monkeypatch.setattr(statistics, "_rows", rows)

    response = await client.get(
        "/api/statistics/overview",
        params=[("include", "ttps"), ("limit", "5")],
    )

    assert response.status_code == 200
    sql_statements = [str(call.args[1]) for call in rows.await_args_list]
    cross_query = next(sql for sql in sql_statements if "actor_counts AS" in sql)
    assert "campaign_counts AS" in cross_query
    assert "cve_counts AS" in cross_query
    assert "ioc_counts AS" in cross_query
    assert "LEFT JOIN LATERAL" not in cross_query
