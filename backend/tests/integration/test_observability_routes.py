from __future__ import annotations

import pytest

from app.api.routes import observability
from app.core.config import settings
from app.core.observability import observability_state


@pytest.mark.asyncio
async def test_observability_summary_traces_and_metrics(client):
    observability_state.record_request(
        request_id="contract-test",
        method="GET",
        path="/api/test",
        status_code=200,
        duration_ms=2.5,
        client="test",
    )

    summary = await client.get("/api/observability/summary")
    traces = await client.get("/api/observability/traces?limit=1")
    metrics = await client.get("/api/observability/metrics")

    assert summary.status_code == 200
    assert summary.json()["requests_total"] >= 1
    assert traces.status_code == 200
    assert traces.json()["limit"] == 1
    assert len(traces.json()["items"]) == 1
    assert metrics.status_code == 200
    assert "text/plain" in metrics.headers["content-type"]
    assert "adversarygraph_requests_total" in metrics.text


@pytest.mark.asyncio
async def test_observability_logs_are_redacted(client, monkeypatch, tmp_path):
    log_file = tmp_path / "adversarygraph-api.log"
    log_file.write_text(
        "Authorization: Bearer definitely-secret-token\n"
        "OPENAI_API_KEY=also-secret\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "log_dir", str(tmp_path))

    response = await client.get("/api/observability/logs?limit=10")

    assert response.status_code == 200
    text = "\n".join(response.json()["lines"])
    assert "definitely-secret-token" not in text
    assert "also-secret" not in text
    assert "[REDACTED]" in text
    assert observability._tail_lines(log_file, 1) == ["OPENAI_API_KEY=also-secret"]
