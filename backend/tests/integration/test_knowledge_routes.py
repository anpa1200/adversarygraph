from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from app.api.routes import knowledge


@pytest.mark.asyncio
async def test_knowledge_articles_and_missing_detail(client):
    listing = await client.get("/api/knowledge/articles")
    missing = await client.get("/api/knowledge/articles/999999")

    assert listing.status_code == 200
    assert listing.json() == []
    assert missing.status_code == 404
    assert missing.json()["detail"] == "Article not found"


@pytest.mark.asyncio
async def test_knowledge_seed_uses_the_managed_feed_service(client, monkeypatch):
    seed = AsyncMock(return_value={"status": "ok", "created": 4, "updated": 2})
    monkeypatch.setattr(knowledge, "seed_knowledge", seed)

    response = await client.post("/api/knowledge/seed")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "created": 4, "updated": 2}
    seed.assert_awaited_once()
