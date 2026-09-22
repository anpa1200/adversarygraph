"""OpenAI adapter with JSON response format enforcement."""

from __future__ import annotations

import json

from typing import AsyncIterator

from app.core.config import settings
from app.services.ai.base import LLMAdapter

DEFAULT_MODEL = "gpt-4.1"
MAX_TOKENS = 8192


TIMEOUT_SECONDS = 120.0


class OpenAIAdapter(LLMAdapter):
    def __init__(self, model: str = DEFAULT_MODEL) -> None:
        self._model = model
        from openai import AsyncOpenAI
        self._api_client = AsyncOpenAI(
            api_key=settings.openai_api_key,
            timeout=TIMEOUT_SECONDS,
            max_retries=1,
        )

    @property
    def provider(self) -> str:
        return "openai"

    @property
    def model(self) -> str:
        return self._model

    async def prepare_investigation_story(self, system: str, user: str) -> None:
        # The cited <=600-word narrative needs a smaller output reservation
        # than a full threat report. Keep this scoped to the fresh story adapter;
        # unrelated platform report generation retains its existing budget.
        self._story_max_tokens = 4096
        from app.services.investigation_story import story_response_schema

        def wire_schema(value):
            # Keep the full validation constraints locally. The wire schema
            # uses the documented structural subset; no model-supplied schema.
            if isinstance(value, dict):
                result = {k: wire_schema(v) for k, v in value.items() if k not in {"minLength", "maxLength"}}
                if value.get("type") == "string" and "pattern" not in value and ("minLength" in value or "maxLength" in value):
                    low, high = value.get("minLength", 0), value.get("maxLength", "")
                    result["pattern"] = "^[\\s\\S]{" + str(low) + "," + str(high) + "}$"
                return result
            if isinstance(value, list):
                return [wire_schema(v) for v in value]
            return value

        self._story_response_format = {"type": "json_schema", "json_schema": {
            "name": "investigation_story", "strict": True, "schema": wire_schema(story_response_schema())}}

    async def _raw_complete(self, system: str, user: str) -> str:
        if hasattr(self, "_story_response_format"):
            # Schema is authoritative in response_format; avoid paying for its
            # second copy in the prompt. Evidence is kept byte-for-byte as data.
            payload = json.loads(user)
            payload.pop("output_schema", None)
            if isinstance(payload.get("original_request"), dict):
                payload["original_request"].pop("output_schema", None)
            user = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        resp = await self._api_client.chat.completions.create(
            model=self._model,
            max_tokens=getattr(self, "_story_max_tokens", MAX_TOKENS),
            response_format=getattr(self, "_story_response_format", {"type": "json_object"}),
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        )
        self.story_usage = resp.usage.model_dump() if resp.usage is not None else None
        self.story_finish_reason = resp.choices[0].finish_reason
        return resp.choices[0].message.content or ""

    async def _stream_complete(self, system: str, user: str) -> AsyncIterator[str]:
        stream = await self._api_client.chat.completions.create(
            model=self._model,
            max_tokens=MAX_TOKENS,
            stream=True,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        )
        async for chunk in stream:
            delta = chunk.choices[0].delta.content
            if delta:
                yield delta
