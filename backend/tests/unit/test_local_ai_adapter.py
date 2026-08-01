from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.services.ai.local import LocalLLMAdapter


class _Completions:
    def __init__(self) -> None:
        self.kwargs = {}

    async def create(self, **kwargs):
        self.kwargs = kwargs
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content='{"ok":true}'))]
        )


@pytest.mark.asyncio
async def test_openai_compatible_local_model_uses_original_prompt():
    adapter = LocalLLMAdapter(
        model="qwen3:8b",
        base_url="http://127.0.0.1:1234/v1",
    )
    completions = _Completions()
    adapter._api_client = SimpleNamespace(
        chat=SimpleNamespace(completions=completions)
    )

    result = await adapter._raw_complete("Return strict JSON.", "Question")

    assert result == '{"ok":true}'
    assert completions.kwargs["messages"][0]["content"] == "Return strict JSON."


@pytest.mark.asyncio
async def test_non_qwen_local_model_keeps_original_system_prompt():
    adapter = LocalLLMAdapter(
        model="llama3.1:8b",
        base_url="http://127.0.0.1:1234/v1",
    )
    completions = _Completions()
    adapter._api_client = SimpleNamespace(
        chat=SimpleNamespace(completions=completions)
    )

    await adapter._raw_complete("Return strict JSON.", "Question")

    assert completions.kwargs["messages"][0]["content"] == "Return strict JSON."


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("user", "token_limit", "proposal_type"),
    [
        ("Question", 88, "null"),
        (
            "Map and preview a reviewed ATT&CK Navigator layer from the evidence.",
            88,
            "null",
        ),
    ],
)
async def test_ollama_native_call_disables_thinking(
    monkeypatch,
    user,
    token_limit,
    proposal_type,
):
    captured = {}

    class _Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"message": {"content": '{"ok":true}', "thinking": ""}}

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def post(self, url, *, json):
            captured.update({"url": url, "json": json})
            return _Response()

    monkeypatch.setattr(
        "app.services.ai.local.httpx.AsyncClient",
        lambda **_kwargs: _Client(),
    )
    adapter = LocalLLMAdapter(
        model="qwen3:8b",
        base_url="http://127.0.0.1:11434/v1",
    )

    result = await adapter._raw_complete(
        "You are the AdversaryGraph intelligence retrieval assistant.",
        user,
    )

    assert result == '{"ok":true}'
    assert captured["url"] == "http://127.0.0.1:11434/api/chat"
    assert captured["json"]["think"] is False
    assert captured["json"]["format"]["additionalProperties"] is False
    assert captured["json"]["format"]["required"] == [
        "answer",
        "cited_source_ids",
        "relevant_source_ids",
        "cautions",
        "navigator_proposal",
    ]
    assert (
        captured["json"]["format"]["properties"]["navigator_proposal"]["type"]
        == proposal_type
    )
    assert captured["json"]["options"]["num_predict"] == token_limit
