"""MiniMax OpenAI-compatible adapter."""

from __future__ import annotations

from typing import AsyncIterator

from app.core.config import settings
from app.services.ai.base import LLMAdapter

DEFAULT_MODEL = "MiniMax-M2.7"
MAX_COMPLETION_TOKENS = 2048
TIMEOUT_SECONDS = 120.0


class MiniMaxAdapter(LLMAdapter):
    def __init__(self, model: str = DEFAULT_MODEL) -> None:
        self._model = model
        from openai import AsyncOpenAI

        self._api_client = AsyncOpenAI(
            api_key=settings.minimax_api_key,
            base_url=settings.minimax_base_url.rstrip("/"),
            timeout=TIMEOUT_SECONDS,
            max_retries=1,
        )

    @property
    def provider(self) -> str:
        return "minimax"

    @property
    def model(self) -> str:
        return self._model

    async def _raw_complete(self, system: str, user: str) -> str:
        resp = await self._api_client.chat.completions.create(
            model=self._model,
            max_completion_tokens=MAX_COMPLETION_TOKENS,
            temperature=0.1,
            extra_body={"reasoning_split": True},
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return resp.choices[0].message.content or ""

    async def _stream_complete(self, system: str, user: str) -> AsyncIterator[str]:
        stream = await self._api_client.chat.completions.create(
            model=self._model,
            max_completion_tokens=MAX_COMPLETION_TOKENS,
            temperature=0.1,
            extra_body={"reasoning_split": True},
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
