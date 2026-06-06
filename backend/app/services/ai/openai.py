"""OpenAI adapter — GPT-4o with JSON response format enforcement."""

from __future__ import annotations

from typing import AsyncIterator

from app.core.config import settings
from app.services.ai.base import LLMAdapter

DEFAULT_MODEL = "gpt-4o"
MAX_TOKENS = 4096


class OpenAIAdapter(LLMAdapter):
    def __init__(self, model: str = DEFAULT_MODEL) -> None:
        self._model = model
        from openai import AsyncOpenAI
        self._api_client = AsyncOpenAI(api_key=settings.openai_api_key)

    @property
    def provider(self) -> str:
        return "openai"

    @property
    def model(self) -> str:
        return self._model

    async def _raw_complete(self, system: str, user: str) -> str:
        resp = await self._api_client.chat.completions.create(
            model=self._model,
            max_tokens=MAX_TOKENS,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        )
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
