"""OpenAI-compatible local LLM adapter."""

from __future__ import annotations

from typing import AsyncIterator
from urllib.parse import urlsplit

import httpx
from fastapi import HTTPException

from app.core.config import settings
from app.services.ai.base import LLMAdapter

DEFAULT_MODEL = "llama3.1:8b"
MAX_TOKENS = 8192
TIMEOUT_SECONDS = 180.0
_RAG_SYSTEM_MARKER = "AdversaryGraph intelligence retrieval assistant"
_RAG_BASE_PROPERTIES = {
    "answer": {"type": "string", "maxLength": 240},
    "cited_source_ids": {
        "type": "array",
        "items": {"type": "string"},
        "maxItems": 3,
    },
    "relevant_source_ids": {
        "type": "array",
        "items": {"type": "string"},
        "maxItems": 3,
    },
    "cautions": {
        "type": "array",
        "items": {"type": "string", "maxLength": 160},
        "maxItems": 1,
    },
}
_RAG_REQUIRED = [
    "answer",
    "cited_source_ids",
    "relevant_source_ids",
    "cautions",
    "navigator_proposal",
]
_RAG_ANSWER_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        **_RAG_BASE_PROPERTIES,
        "navigator_proposal": {"type": "null"},
    },
    "required": _RAG_REQUIRED,
    "additionalProperties": False,
}
_RAG_NAVIGATOR_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "answer": {"type": "string", "maxLength": 32},
        "cited_source_ids": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 2,
        },
        "relevant_source_ids": {
            "type": "array",
            "items": {"type": "string"},
            "maxItems": 2,
        },
        "cautions": {"type": "array", "items": {"type": "string"}, "maxItems": 0},
        "navigator_proposal": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "maxLength": 32},
                "technique_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "maxItems": 10,
                },
                "rationale": {"type": "string", "maxLength": 48},
            },
            "required": ["name", "technique_ids", "rationale"],
            "additionalProperties": False,
        },
    },
    "required": _RAG_REQUIRED,
    "additionalProperties": False,
}


class LocalLLMAdapter(LLMAdapter):
    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        base_url: str | None = None,
        api_key: str | None = None,
    ) -> None:
        self._model = model
        self._story_context_tokens = 0
        self.story_usage = None
        self._base_url = (base_url or settings.local_llm_base_url).rstrip("/")
        parsed = urlsplit(self._base_url)
        self._ollama_native_url = (
            f"{parsed.scheme}://{parsed.netloc}/api/chat"
            if parsed.scheme in {"http", "https"} and parsed.port == 11434
            else ""
        )
        from openai import AsyncOpenAI
        self._api_client = AsyncOpenAI(
            api_key=api_key or settings.local_llm_api_key or "local",
            base_url=self._base_url,
            # Stage-specific callers enforce their own shorter deadline. Keep
            # the transport ceiling high enough for CPU-hosted local models so
            # it does not pre-empt THREAT_HUNTING_AI_TIMEOUT_SECONDS.
            timeout=TIMEOUT_SECONDS,
            max_retries=1,
        )

    @property
    def provider(self) -> str:
        return "local"

    @property
    def model(self) -> str:
        return self._model

    async def prepare_investigation_story(self, system: str, user: str) -> None:
        """Reserve context explicitly; never rely on a server's short default.

        UTF-8 bytes are a deliberately conservative subword-token bound, plus
        template and completion reserves. This is not a billable-token estimate.
        Models/servers with an unknown capacity cannot silently accept a report.
        """
        required = len(system.encode()) + len(user.encode()) + MAX_TOKENS + 1024
        capacity = settings.local_llm_context_tokens
        if self._ollama_native_url:
            try:
                async with httpx.AsyncClient(timeout=5.0, follow_redirects=False, trust_env=False) as client:
                    response = await client.post(self._ollama_native_url.removesuffix("/chat") + "/show", json={"model": self.model})
                    response.raise_for_status()
                    model_info = response.json().get("model_info", {})
                    advertised = [v for k, v in model_info.items() if k.endswith(".context_length") and type(v) is int and v > 0]
                    if advertised:
                        capacity = min(min(advertised), capacity) if capacity > 0 else min(advertised)
                    else:
                        capacity = 0
            except (httpx.HTTPError, ValueError, AttributeError):
                raise HTTPException(503, "Could not verify local model context capacity. No report was sent for generation.")
        if capacity <= 0:
            raise HTTPException(503, "Local model context capacity is unknown. Configure LOCAL_LLM_CONTEXT_TOKENS after verifying the inference server's non-truncating capacity.")
        if required > capacity:
            raise HTTPException(413, f"Full summary input needs a conservative {required}-token capacity reservation; configured model capacity is {capacity}. Use a larger-context private model or split the full report. No report was sent for generation.")
        self._story_context_tokens = required

    async def _raw_complete(self, system: str, user: str) -> str:
        # Ollama's OpenAI-compatibility route does not reliably honor Qwen3's
        # thinking control. Its native API does, avoiding minutes of hidden
        # reasoning before a bounded JSON response.
        if self._ollama_native_url:
            is_rag = _RAG_SYSTEM_MARKER in system
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(TIMEOUT_SECONDS, connect=10.0),
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = await client.post(
                    self._ollama_native_url,
                    json={
                        "model": self._model,
                        "stream": False,
                        "think": False,
                        # The story schema is validated in the application.
                        # Older Ollama schema-to-grammar parsers crash on its
                        # nested definitions; keep their established JSON mode.
                        "format": _RAG_ANSWER_JSON_SCHEMA if is_rag else "json",
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": user},
                        ],
                        "options": {
                            "temperature": 0.1,
                            "num_predict": (
                                88 if is_rag else MAX_TOKENS
                            ),
                            **({"num_ctx": self._story_context_tokens} if self._story_context_tokens else {}),
                        },
                    },
                )
                response.raise_for_status()
                payload = response.json()
                if self._story_context_tokens:
                    if payload.get("done_reason") == "length":
                        raise ValueError("Summary completion was truncated")
                    if type(payload.get("prompt_eval_count")) is int and type(payload.get("eval_count")) is int:
                        self.story_usage = {"input_tokens": payload["prompt_eval_count"], "output_tokens": payload["eval_count"], "source": "ollama-response"}
                message = payload.get("message") if isinstance(payload, dict) else None
                if not isinstance(message, dict):
                    return ""
                return str(message.get("content") or "")
        resp = await self._api_client.chat.completions.create(
            model=self._model,
            max_tokens=MAX_TOKENS,
            temperature=0.1,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        if self._story_context_tokens:
            if resp.choices[0].finish_reason == "length":
                raise ValueError("Summary completion was truncated")
            if resp.usage is not None:
                self.story_usage = {"input_tokens": resp.usage.prompt_tokens, "output_tokens": resp.usage.completion_tokens, "source": "provider-response"}
        return resp.choices[0].message.content or ""

    async def _stream_complete(self, system: str, user: str) -> AsyncIterator[str]:
        stream = await self._api_client.chat.completions.create(
            model=self._model,
            max_tokens=MAX_TOKENS,
            temperature=0.1,
            stream=True,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        async for chunk in stream:
            delta = chunk.choices[0].delta.content
            if delta:
                yield delta
