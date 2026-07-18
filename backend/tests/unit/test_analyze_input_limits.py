from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.api.routes import analyze


@pytest.mark.asyncio
@pytest.mark.parametrize("reader", [analyze._read_input, analyze._read_log_input])
async def test_pasted_text_uses_utf8_byte_limit(monkeypatch, reader):
    monkeypatch.setattr(analyze, "MAX_UPLOAD_BYTES", 5)

    with pytest.raises(HTTPException) as exc:
        await reader("ééé", None)

    assert exc.value.status_code == 413


@pytest.mark.asyncio
@pytest.mark.parametrize("reader", [analyze._read_input, analyze._read_log_input])
async def test_pasted_text_at_utf8_byte_limit_is_allowed(monkeypatch, reader):
    monkeypatch.setattr(analyze, "MAX_UPLOAD_BYTES", 6)

    content, filename = await reader("ééé", None)

    assert content == "ééé"
    assert filename is None


def test_adapter_configuration_error_does_not_expose_factory_details(monkeypatch):
    def fail_adapter(*_args, **_kwargs):
        raise ValueError("invalid api_key=adapter-secret at https://llm.example?token=url-secret")

    monkeypatch.setattr(analyze, "get_adapter", fail_adapter)

    with pytest.raises(HTTPException) as exc:
        analyze._get_adapter("local", None)

    assert exc.value.status_code == 400
    assert exc.value.detail == "AI provider configuration is invalid"
    assert "adapter-secret" not in str(exc.value.detail)
    assert "url-secret" not in str(exc.value.detail)
