"""Google Gemini adapter using the google-genai SDK."""

from __future__ import annotations

from typing import AsyncIterator

from app.core.config import settings
from app.services.ai.base import LLMAdapter

class GeminiAdapter(LLMAdapter):
    def __init__(self, model: str | None = None) -> None:
        self._model_name = model or settings.gemini_model
        import google.genai as genai
        import google.genai.types as genai_types
        self._client = genai.Client(api_key=settings.gemini_api_key)
        self._genai_types = genai_types

    @property
    def provider(self) -> str:
        return "gemini"

    @property
    def model(self) -> str:
        return self._model_name

    def _config(self, system: str):
        return self._genai_types.GenerateContentConfig(
            system_instruction=system,
            response_mime_type="application/json",
            max_output_tokens=8192,
            temperature=0.2,
        )

    async def _raw_complete(self, system: str, user: str) -> str:
        response = await self._client.aio.models.generate_content(
            model=self._model_name,
            contents=user,
            config=self._config(system),
        )
        return response.text

    async def _stream_complete(self, system: str, user: str) -> AsyncIterator[str]:
        async for chunk in await self._client.aio.models.generate_content_stream(
            model=self._model_name,
            contents=user,
            config=self._config(system),
        ):
            if chunk.text:
                yield chunk.text
