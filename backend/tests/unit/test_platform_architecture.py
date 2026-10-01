from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.services import platform_architecture


@pytest.mark.asyncio
async def test_architecture_snapshot_labels_measured_and_configured_edges(monkeypatch):
    table_counts = {
        "ioc_indicators": 1200,
        "cve_records": 300,
        "cve_technique_links": 14,
        "cve_ioc_links": 8,
        "cve_actor_links": 3,
        "ioc_actor_links": 11,
        "rag_documents": 1500,
        "rag_chunks": 4200,
    }

    async def fake_count(_db, table, _where=""):
        return table_counts.get(table, 5), "measured"

    async def fake_source_health(_db, _table):
        return {
            "configured": 6,
            "enabled": 5,
            "degraded": 0,
            "latest_sync": "2026-07-29T12:00:00+00:00",
        }

    monkeypatch.setattr(platform_architecture, "_safe_count", fake_count)
    monkeypatch.setattr(platform_architecture, "_source_health", fake_source_health)
    async def fake_rag_logic(_db):
        return {
            "source_types": [{"source_type": "ioc", "documents": 1200}],
            "latest_run": {"status": "completed", "documents_seen": 1500},
        }

    monkeypatch.setattr(platform_architecture, "_rag_logic", fake_rag_logic)
    monkeypatch.setattr(platform_architecture, "_log_activity", lambda: {
        "exists": True, "sampled_lines": 10, "levels": {"info": 9, "error": 1}
    })
    monkeypatch.setattr(
        platform_architecture,
        "observability_state",
        SimpleNamespace(
            snapshot=lambda: {
                "uptime_seconds": 120,
                "requests_total": 40,
                "requests_by_status": {"2xx": 39, "5xx": 1},
                "latency": {"avg_ms": 12.0, "max_ms": 55.0},
                "top_routes": [{"route": "/api/ioc/search", "count": 7}],
                "recent_traces": [],
            }
        ),
    )

    async def fake_health():
        return {"enabled": True, "connected": False, "status": "unavailable"}

    monkeypatch.setattr(platform_architecture.skywalking, "health", fake_health)

    result = await platform_architecture.snapshot(object(), minutes=60)

    assert result["streams"]["ioc"]["records"] == 1200
    assert result["streams"]["cve"]["records"] == 300
    assert result["streams"]["rag"]["chunks"] == 4200
    assert result["data_logic"]["coverage"]["ioc_tagged"] == 1200
    assert result["data_logic"]["rag"]["latest_run"]["status"] == "completed"
    assert result["data_logic"]["mcp"]["tool_count"] == 5
    assert result["data_logic"]["ai"]["human_review_required"] is True
    assert any(
        edge["source"] == "api"
        and edge["target"] == "ioc"
        and edge["kind"] == "api_traffic"
        and edge["count"] == 7
        and edge["observed"] is True
        for edge in result["edges"]
    )
    assert any(
        edge["source"] == "cve"
        and edge["target"] == "ioc"
        and edge["kind"] == "correlation"
        and edge["count"] == 8
        for edge in result["edges"]
    )
    assert any(
        edge["kind"] == "configured_dependency"
        and edge["observed"] is False
        for edge in result["edges"]
    )
    assert "not proof" in result["provenance"]["boundary"]
