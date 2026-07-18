"""Gemini adapter smoke tests without calling Google APIs."""

from __future__ import annotations

import sys
import types


def test_gemini_adapter_uses_google_genai_sdk(monkeypatch):
    created = {}

    class _Client:
        def __init__(self, api_key: str):
            created["api_key"] = api_key
            self.aio = types.SimpleNamespace(models=types.SimpleNamespace())

    class _GenerateContentConfig:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    google_module = types.ModuleType("google")
    genai_module = types.ModuleType("google.genai")
    types_module = types.ModuleType("google.genai.types")
    genai_module.Client = _Client
    types_module.GenerateContentConfig = _GenerateContentConfig
    google_module.genai = genai_module
    genai_module.types = types_module

    monkeypatch.setitem(sys.modules, "google", google_module)
    monkeypatch.setitem(sys.modules, "google.genai", genai_module)
    monkeypatch.setitem(sys.modules, "google.genai.types", types_module)
    monkeypatch.setattr("app.core.config.settings.gemini_api_key", "demo-key")

    from app.services.ai.gemini import GeminiAdapter

    adapter = GeminiAdapter(model="gemini-test")

    assert adapter.provider == "gemini"
    assert adapter.model == "gemini-test"
    assert created["api_key"] == "demo-key"
    config = adapter._config("system text")
    assert config.kwargs["system_instruction"] == "system text"
    assert config.kwargs["response_mime_type"] == "application/json"


def test_gemini_adapter_uses_configured_default_model(monkeypatch):
    class _Client:
        def __init__(self, api_key: str):
            self.aio = types.SimpleNamespace(models=types.SimpleNamespace())

    google_module = types.ModuleType("google")
    genai_module = types.ModuleType("google.genai")
    types_module = types.ModuleType("google.genai.types")
    genai_module.Client = _Client
    types_module.GenerateContentConfig = object
    google_module.genai = genai_module
    genai_module.types = types_module
    monkeypatch.setitem(sys.modules, "google", google_module)
    monkeypatch.setitem(sys.modules, "google.genai", genai_module)
    monkeypatch.setitem(sys.modules, "google.genai.types", types_module)
    monkeypatch.setattr("app.core.config.settings.gemini_api_key", "demo-key")
    monkeypatch.setattr("app.core.config.settings.gemini_model", "gemini-configured")

    from app.services.ai.gemini import GeminiAdapter

    assert GeminiAdapter().model == "gemini-configured"
