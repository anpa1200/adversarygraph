from __future__ import annotations

from types import SimpleNamespace
from uuid import UUID

import pytest
from fastapi import Request
from fastapi.responses import JSONResponse

import main as main_module
from app.core.observability import ObservabilityState


def _request(path: str, request_id: str = "request-1") -> Request:
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "https",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": [(b"x-request-id", request_id.encode())],
            "client": ("198.51.100.20", 43123),
            "server": ("api.example.test", 443),
        }
    )


@pytest.mark.asyncio
async def test_dynamic_ids_share_route_metric_and_trace_template(monkeypatch):
    state = ObservabilityState()
    monkeypatch.setattr(main_module, "observability_state", state)

    async def call_next(request: Request):
        request.scope["route"] = SimpleNamespace(path="/api/items/{item_id}")
        return JSONResponse({"ok": True})

    await main_module.request_logging_middleware(_request("/api/items/one"), call_next)
    await main_module.request_logging_middleware(_request("/api/items/two"), call_next)

    snapshot = state.snapshot()
    assert snapshot["top_routes"] == [
        {"route": "GET /api/items/{item_id}", "count": 2}
    ]
    assert {trace["path"] for trace in snapshot["recent_traces"]} == {
        "/api/items/{item_id}"
    }


@pytest.mark.asyncio
async def test_arbitrary_404_paths_collapse_to_unmatched_bucket(monkeypatch):
    state = ObservabilityState()
    monkeypatch.setattr(main_module, "observability_state", state)

    async def call_next(_request: Request):
        return JSONResponse({"detail": "Not Found"}, status_code=404)

    for index in range(25):
        await main_module.request_logging_middleware(
            _request(f"/attacker-controlled/{index}"),
            call_next,
        )

    snapshot = state.snapshot()
    assert snapshot["top_routes"] == [{"route": "GET <unmatched>", "count": 25}]
    assert len(state._requests_by_route) == 1


def test_request_id_accepts_safe_token_and_replaces_untrusted_values():
    assert main_module._safe_request_id("safe.request-id:123") == "safe.request-id:123"

    for value in ("x" * 129, "line\nbreak", " spaces ", ""):
        generated = main_module._safe_request_id(value)
        UUID(generated)
        assert generated != value
