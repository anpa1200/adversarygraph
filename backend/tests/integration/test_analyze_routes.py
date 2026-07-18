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
async def test_analyze_chat_rejects_oversized_message(client: AsyncClient):
    from app.api.routes.analyze import MAX_CHAT_MESSAGE_CHARS

    response = await client.post(
        "/api/analyze/chat",
        json={"message": "x" * (MAX_CHAT_MESSAGE_CHARS + 1), "provider": "local"},
    )

    assert response.status_code == 422
    assert any(
        error["loc"][-1] == "message" and error["type"] == "string_too_long"
        for error in response.json()["detail"]
    )


@pytest.mark.asyncio
async def test_analyze_chat_invalid_provider_returns_400(client: AsyncClient):
    response = await client.post(
        "/api/analyze/chat",
        json={"message": "What is T1059?", "provider": "bad_provider"},
    )
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_analysis_session_lists_reject_unbounded_pagination(client: AsyncClient):
    too_large = await client.get("/api/analyze/sessions", params={"limit": 251})
    negative_offset = await client.get(
        "/api/analyze/sessions/collection",
        params={"offset": -1},
    )

    assert too_large.status_code == 422
    assert negative_offset.status_code == 422


@pytest.mark.asyncio
async def test_ingest_research_url_stores_text_and_images(client: AsyncClient, monkeypatch: pytest.MonkeyPatch):
    async def fake_safe_get(url: str, **_kwargs):
        return httpx.Response(
            200,
            headers={"content-type": "text/html; charset=utf-8"},
            content=b"""
            <html><head><title>URL Report</title></head><body>
            <h1>URL Report</h1><p>Observed CVE-2024-1111 and T1190 exploitation from 8.8.8.8.</p>
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


@pytest.mark.asyncio
async def test_ingest_research_url_rejects_oversized_response(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    from app.core.safe_http import ResponseTooLargeError

    async def fake_safe_get(_url: str, **_kwargs):
        raise ResponseTooLargeError("remote response is too large")

    monkeypatch.setattr("app.api.routes.analyze.async_safe_get", fake_safe_get)

    response = await client.post(
        "/api/analyze/sessions/research-url",
        data={"url": "https://example.com/report.html", "parse_with_ai": "false"},
    )

    assert response.status_code == 413
    assert response.json()["detail"] == "Fetched report exceeds 50 MB limit"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "expected_status", "expected_detail"),
    [
        (
            ValueError("blocked URL contained token=do-not-return"),
            400,
            "Report URL is not allowed by the outbound network policy",
        ),
        (
            RuntimeError("upstream failed with password=do-not-return"),
            502,
            "Report URL could not be fetched. See server logs.",
        ),
    ],
)
async def test_ingest_research_url_does_not_return_fetch_exception_details(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
    expected_status: int,
    expected_detail: str,
):
    async def fake_safe_get(_url: str, **_kwargs):
        raise failure

    monkeypatch.setattr("app.api.routes.analyze.async_safe_get", fake_safe_get)

    response = await client.post(
        "/api/analyze/sessions/research-url",
        data={"url": "https://example.com/report.html", "parse_with_ai": "false"},
    )

    assert response.status_code == expected_status
    assert response.json()["detail"] == expected_detail
    assert "do-not-return" not in response.text


@pytest.mark.asyncio
async def test_analyze_persists_only_stable_failure_message(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    app,
):
    from app.core.database import get_session
    from app.models.analysis import AnalysisSession

    mock_session = app.dependency_overrides[get_session].__globals__["_mock_session"]

    class FailingAdapter:
        provider = "local"
        model = "test-model"

        async def extract(self, _body: str, _domain: str):
            raise RuntimeError(
                "provider failed at https://collector.example/api?token=exception-secret password=also-secret"
            )

    monkeypatch.setattr("app.api.routes.analyze._get_adapter", lambda *_args: FailingAdapter())

    response = await client.post(
        "/api/analyze",
        data={"provider": "local", "text": "Sample threat report."},
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "Operation failed. See server logs."
    assert "exception-secret" not in response.text
    sessions = [
        item
        for item in mock_session._objects.values()
        if isinstance(item, AnalysisSession)
    ]
    assert len(sessions) == 1
    assert sessions[0].status == "failed"
    assert sessions[0].error == "Analysis processing failed. See server logs."
    assert "exception-secret" not in sessions[0].error


@pytest.mark.asyncio
async def test_ingest_research_url_redacts_query_secrets_before_response_and_storage(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
    app,
):
    from app.core.database import get_session
    from app.models.analysis import AnalysisSession
    from app.models.operations import ReportIntake

    mock_session = app.dependency_overrides[get_session].__globals__["_mock_session"]

    requested_urls: list[str] = []

    async def fake_safe_get(url: str, **_kwargs):
        requested_urls.append(url)
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            content=b"""
            <html><head><title>Credentialized source</title></head><body>
            <article><p>Observed T1190 exploitation.</p>
            <img src="/graph.png?api_key=image-secret" alt="Graph">
            </article></body></html>
            """,
            request=httpx.Request("GET", url),
        )

    monkeypatch.setattr("app.api.routes.analyze.async_safe_get", fake_safe_get)
    source_url = (
        "https://example.com/report?source=feed&token=source-secret#access_token=fragment-secret"
    )

    response = await client.post(
        "/api/analyze/sessions/research-url",
        data={"url": source_url, "parse_with_ai": "false"},
    )

    assert response.status_code == 200
    assert requested_urls == [source_url]
    payload = response.json()
    assert payload["source_url"] == (
        "https://example.com/report?source=feed&token=REDACTED"
    )
    assert "source-secret" not in response.text
    assert "fragment-secret" not in response.text

    sessions = [
        item
        for item in mock_session._objects.values()
        if isinstance(item, AnalysisSession)
    ]
    intakes = [
        item
        for item in mock_session._objects.values()
        if isinstance(item, ReportIntake)
    ]
    assert len(sessions) == 1
    assert len(intakes) == 1
    assert "source-secret" not in (sessions[0].filename or "")
    assert "source-secret" not in intakes[0].url
    assert "source-secret" not in intakes[0].analyst_notes
    assert "image-secret" not in intakes[0].analyst_notes
    assert "REDACTED" in intakes[0].analyst_notes


@pytest.mark.asyncio
async def test_ingest_research_url_rejects_embedded_credentials(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
):
    async def unexpected_fetch(*_args, **_kwargs):
        raise AssertionError("credentialized URL must be rejected before fetch")

    monkeypatch.setattr("app.api.routes.analyze.async_safe_get", unexpected_fetch)

    response = await client.post(
        "/api/analyze/sessions/research-url",
        data={
            "url": "https://analyst:do-not-return@example.com/report",
            "parse_with_ai": "false",
        },
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "Report URL must use http or https and include a host"
    )
    assert "do-not-return" not in response.text
