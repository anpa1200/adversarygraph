from types import SimpleNamespace

import pytest

from app.services.ai.claude import ClaudeAdapter


class _Messages:
    def __init__(self, content):
        self.content = content

    async def create(self, **_kwargs):
        return SimpleNamespace(content=self.content)


def _adapter(content) -> ClaudeAdapter:
    adapter = ClaudeAdapter.__new__(ClaudeAdapter)
    adapter._model = "claude-test"
    adapter._api_client = SimpleNamespace(messages=_Messages(content))
    return adapter


@pytest.mark.asyncio
async def test_claude_completion_concatenates_only_text_blocks():
    adapter = _adapter(
        [
            SimpleNamespace(type="thinking", thinking="internal"),
            SimpleNamespace(type="text", text="first "),
            SimpleNamespace(type="tool_use", name="lookup"),
            SimpleNamespace(type="text", text="second"),
        ]
    )

    assert await adapter._raw_complete("system", "user") == "first second"


@pytest.mark.asyncio
async def test_claude_completion_fails_clearly_without_text_blocks():
    adapter = _adapter([SimpleNamespace(type="tool_use", name="lookup")])

    with pytest.raises(RuntimeError, match="no text content"):
        await adapter._raw_complete("system", "user")
