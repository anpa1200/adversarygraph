"""Returns the correct adapter instance for a given provider string."""

from __future__ import annotations

from app.core.config import settings
from app.services.ai.base import LLMAdapter

_DEFAULTS: dict[str, str] = {
    "claude": "claude-opus-4-8",
    "openai": settings.openai_model,
    "gemini": "gemini-2.0-flash",
    "minimax": settings.minimax_model,
    "local": settings.local_llm_model,
}


def get_adapter(provider: str, model: str | None = None) -> LLMAdapter:
    """
    provider: "claude" | "openai" | "gemini" | "minimax" | "local"
    model:    optional override; falls back to the provider default.

    Adapter classes are imported lazily so missing SDK packages don't
    raise ImportError at startup — only when the adapter is actually used.
    """
    provider = provider.lower().strip()

    if provider == "claude":
        from app.services.ai.claude import ClaudeAdapter
        return ClaudeAdapter(model=model or _DEFAULTS["claude"])
    if provider == "openai":
        from app.services.ai.openai import OpenAIAdapter
        return OpenAIAdapter(model=model or _DEFAULTS["openai"])
    if provider == "gemini":
        from app.services.ai.gemini import GeminiAdapter
        return GeminiAdapter(model=model or _DEFAULTS["gemini"])
    if provider == "minimax":
        from app.services.ai.minimax import MiniMaxAdapter
        return MiniMaxAdapter(model=model or _DEFAULTS["minimax"])
    if provider == "local":
        from app.services.ai.local import LocalLLMAdapter
        return LocalLLMAdapter(model=model or _DEFAULTS["local"])

    raise ValueError(
        f"Unknown LLM provider: {provider!r}. Choose from: {list(_DEFAULTS)}"
    )
