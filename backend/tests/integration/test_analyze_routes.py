"""Integration tests for /api/analyze routes."""

import pytest
import httpx
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_analyze_sessions_returns_list(client: AsyncClient):
    response = await client.get("/api/analyze/sessions")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


@pytest.mark.asyncio
async def test_analyze_get_unknown_session_returns_404(client: AsyncClient):
    response = await client.get("/api/analyze/00000000-0000-0000-0000-000000000001")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_analyze_delete_unknown_session_returns_404(client: AsyncClient):
    response = await client.delete("/api/analyze/sessions/00000000-0000-0000-0000-000000000002")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_analyze_review_unknown_session_returns_404(client: AsyncClient):
    response = await client.patch(
        "/api/analyze/sessions/00000000-0000-0000-0000-000000000003/techniques/T1059/review",
        json={"review_status": "accepted"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_analyze_invalid_provider_returns_400(client: AsyncClient):
    response = await client.post(
        "/api/analyze",
        data={"provider": "notarealthing", "text": "Sample threat report text."},
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_analyze_no_input_returns_400(client: AsyncClient):
    """Sending no text and no file should return 400 before reaching the AI adapter."""
    from unittest.mock import MagicMock, patch

    mock_adapter = MagicMock()
    mock_adapter.model = "test-model"
    mock_adapter.provider = "claude"

    with patch("app.api.routes.analyze._get_adapter", return_value=mock_adapter):
        response = await client.post("/api/analyze", data={"provider": "claude"})
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_analyze_chat_missing_message_returns_422(client: AsyncClient):
    response = await client.post("/api/analyze/chat", json={"provider": "claude"})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_analyze_chat_invalid_provider_returns_400(client: AsyncClient):
    response = await client.post(
        "/api/analyze/chat",
        json={"message": "What is T1059?", "provider": "bad_provider"},
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_ingest_research_url_stores_text_and_images(client: AsyncClient, monkeypatch: pytest.MonkeyPatch):
    async def fake_safe_get(url: str, **_kwargs):
        return httpx.Response(
            200,
            headers={"content-type": "text/html; charset=utf-8"},
            content=b"""
            <html><head><title>URL Report</title></head><body>
            <h1>URL Report</h1><p>Observed CVE-2024-1111 and T1190 exploitation.</p>
            <img src="/img/graph.png" alt="Kill chain graph">
            </body></html>
            """,
            request=httpx.Request("GET", url),
        )

    monkeypatch.setattr("app.api.routes.analyze.async_safe_get", fake_safe_get)

    response = await client.post(
        "/api/analyze/sessions/research-url",
        data={"url": "https://example.com/report.html", "parse_with_ai": "false", "domain": "enterprise-attack"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["title"] == "URL Report"
    assert payload["source_url"] == "https://example.com/report.html"

    assert payload["source_text_available"] is True
