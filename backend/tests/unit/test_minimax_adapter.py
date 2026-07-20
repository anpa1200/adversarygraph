"""MiniMax OpenAI-compatible transport tests without calling external APIs."""

from __future__ import annotations

import sys
import types

import pytest


class _Stream:
    def __init__(self, content: list[str | None]) -> None:
        self._content = iter(content)

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            content = next(self._content)
        except StopIteration as exc:
            raise StopAsyncIteration from exc
        return types.SimpleNamespace(
            choices=[types.SimpleNamespace(delta=types.SimpleNamespace(content=content))]
        )


@pytest.mark.asyncio
async def test_minimax_adapter_uses_reasoning_split_and_bounded_transport(monkeypatch):
    created: dict[str, object] = {}

    class _Completions:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        async def create(self, **kwargs):
            self.calls.append(kwargs)
            if kwargs.get("stream"):
                return _Stream([None, '{"status":', '"ok"}'])
            return types.SimpleNamespace(
                choices=[types.SimpleNamespace(message=types.SimpleNamespace(
                    content='{"status":"ok"}',
                    reasoning_details="PRIVATE_REASONING_MUST_NOT_REACH_JSON",
                ))]
            )

    class _AsyncOpenAI:
        def __init__(self, **kwargs) -> None:
            created["client_kwargs"] = kwargs
            self.completions = _Completions()
            self.chat = types.SimpleNamespace(completions=self.completions)
            created["client"] = self

    openai_module = types.ModuleType("openai")
    openai_module.AsyncOpenAI = _AsyncOpenAI
    monkeypatch.setitem(sys.modules, "openai", openai_module)
    monkeypatch.setattr("app.core.config.settings.minimax_api_key", "demo-key")
    monkeypatch.setattr("app.core.config.settings.minimax_base_url", "https://api.minimax.io/v1/")

    from app.services.ai.minimax import MiniMaxAdapter

    adapter = MiniMaxAdapter()
    assert adapter.provider == "minimax"
    assert adapter.model == "MiniMax-M2.7"
    assert created["client_kwargs"] == {
        "api_key": "demo-key",
        "base_url": "https://api.minimax.io/v1",
        "timeout": 120.0,
        "max_retries": 1,
    }

    completed = await adapter._raw_complete("system", "user")
    assert completed == '{"status":"ok"}'
    assert "PRIVATE_REASONING" not in completed
    assert [part async for part in adapter._stream_complete("system", "user")] == [
        '{"status":',
        '"ok"}',
    ]

    client = created["client"]
    calls = client.completions.calls
    assert len(calls) == 2
    expected = {
        "model": "MiniMax-M2.7",
        "max_completion_tokens": 2048,
        "temperature": 0.1,
        "extra_body": {"reasoning_split": True},
        "messages": [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "user"},
        ],
    }
    assert calls[0] == expected
    assert calls[1] == {**expected, "stream": True}
