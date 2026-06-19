"""Unit tests for LLM provider factory registration."""

from app.services.ai.factory import get_adapter


def test_minimax_provider_is_registered():
    adapter = get_adapter("minimax")

    assert adapter.provider == "minimax"
    assert adapter.model == "MiniMax-M3"
