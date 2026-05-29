"""Anthropic Claude adapter."""

from __future__ import annotations

from typing import AsyncIterator

from app.core.config import settings
from app.services.ai.base import LLMAdapter

DEFAULT_MODEL = "claude-opus-4-8"
MAX_TOKENS = 4096


class ClaudeAdapter(LLMAdapter):
    def __init__(self, model: str = DEFAULT_MODEL) -> None:
        self._model = model

    @property
    def provider(self) -> str:
        return "claude"

    @property
    def model(self) -> str:
        return self._model

    def _client(self):
        import anthropic
        return anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)

    async def _raw_complete(self, system: str, user: str) -> str:
        msg = await self._client().messages.create(
            model=self._model,
            max_tokens=MAX_TOKENS,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return msg.content[0].text  # type: ignore[index]

    async def _stream_complete(self, system: str, user: str) -> AsyncIterator[str]:
        async with self._client().messages.stream(
            model=self._model,
            max_tokens=MAX_TOKENS,
            system=system,
            messages=[{"role": "user", "content": user}],
        ) as stream:
            async for text in stream.text_stream:
                yield text
