from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select, func, or_, cast
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.models.knowledge import KnowledgeArticle
from app.services.auth import TeamUser, require_permission
from app.services.knowledge_seeder import seed_knowledge

router = APIRouter(prefix="/knowledge", tags=["Knowledge"])


class ArticleOut(BaseModel):
    id: int
    category: str
    external_id: str
    title: str
    summary: str
    tags: list[str]
    meta: dict[str, Any]
    source_file: str
    published_at: datetime | None

    model_config = {"from_attributes": True}


class ArticleDetailOut(ArticleOut):
    body: str


class StatsOut(BaseModel):
    total: int
    by_category: dict[str, int]


@router.get("/articles", response_model=list[ArticleOut])
async def list_articles(
    q: str | None = Query(None, description="Full-text search in title + body"),
    category: str | None = Query(None),
    tag: str | None = Query(None, description="Filter by tag"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_session),
) -> list[KnowledgeArticle]:
    stmt = select(KnowledgeArticle)

    if category:
        stmt = stmt.where(KnowledgeArticle.category == category)
    if q:
        pattern = f"%{q}%"
        stmt = stmt.where(
            or_(
                KnowledgeArticle.title.ilike(pattern),
                KnowledgeArticle.body.ilike(pattern),
            )
        )
    if tag:
        stmt = stmt.where(
            KnowledgeArticle.tags.contains(cast([tag], JSONB))
        )

    stmt = stmt.order_by(
        KnowledgeArticle.published_at.desc().nullslast(),
        KnowledgeArticle.id.desc(),
    )
    stmt = stmt.limit(limit).offset(offset)

    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.get("/articles/{article_id}", response_model=ArticleDetailOut)
async def get_article(
    article_id: int,
    db: AsyncSession = Depends(get_session),
) -> KnowledgeArticle:
    result = await db.execute(
        select(KnowledgeArticle).where(KnowledgeArticle.id == article_id)
    )
    article = result.scalar_one_or_none()
    if article is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Article not found")
    return article


@router.get("/stats", response_model=StatsOut)
async def stats(db: AsyncSession = Depends(get_session)) -> StatsOut:
    total_r = await db.execute(select(func.count()).select_from(KnowledgeArticle))
    total = total_r.scalar_one()

    cat_r = await db.execute(
        select(KnowledgeArticle.category, func.count()).group_by(KnowledgeArticle.category)
    )
    by_category = {row[0]: row[1] for row in cat_r}

    return StatsOut(total=total, by_category=by_category)


@router.post("/seed")
async def trigger_seed(
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(require_permission("manage_feeds")),
) -> dict[str, Any]:
    return await seed_knowledge(db)
