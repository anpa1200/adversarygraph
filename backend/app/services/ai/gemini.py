"""Google Gemini adapter."""

from __future__ import annotations

from typing import AsyncIterator

from app.core.config import settings
from app.services.ai.base import LLMAdapter

DEFAULT_MODEL = "gemini-2.0-flash"


class GeminiAdapter(LLMAdapter):
    def __init__(self, model: str = DEFAULT_MODEL) -> None:
        self._model_name = model
        import google.generativeai as genai
        genai.configure(api_key=settings.gemini_api_key)
        self._genai = genai

    @property
    def provider(self) -> str:
        return "gemini"

    @property
    def model(self) -> str:
        return self._model_name

    def _build_model(self, system: str):
        from google.generativeai.types import GenerationConfig
        return self._genai.GenerativeModel(
            model_name=self._model_name,
            system_instruction=system,
            generation_config=GenerationConfig(
                response_mime_type="application/json",
                max_output_tokens=8192,
                temperature=0.2,
            ),
        )

    _TIMEOUT = {"timeout": 120}

    async def _raw_complete(self, system: str, user: str) -> str:
        model = self._build_model(system)
        response = await model.generate_content_async(user, request_options=self._TIMEOUT)
        return response.text

    async def _stream_complete(self, system: str, user: str) -> AsyncIterator[str]:
        model = self._build_model(system)
        async for chunk in await model.generate_content_async(user, stream=True, request_options=self._TIMEOUT):
            if chunk.text:
                yield chunk.text
