from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.models.query_library import HuntQueryLibraryItem
from app.services import query_library as library
from app.services.auth import TeamUser, require_permission

router = APIRouter(prefix="/query-library", tags=["Threat Hunting Query Library"])
read_library = require_permission("run_analysis")
manage_library = require_permission("manage_feeds")


class ItemOut(BaseModel):
    id: UUID
    stable_key: str
    title: str
    description: str
    language: str
    query_text: str
    technique_ids: list[str]
    tactics: list[str]
    tags: list[str]
    data_sources: list[str]
    platforms: list[str]
    ioc_types: list[str]
    source_name: str
    source_url: str
    source_license: str
    source_rule_id: str
    quality_score: int
    validation: dict[str, Any]
    community: bool
    updated_at: datetime
    last_synced_at: datetime | None

    model_config = {"from_attributes": True}


class SearchOut(BaseModel):
    items: list[ItemOut]
    total: int
    limit: int
    offset: int


class RawIOC(BaseModel):
    value: str = Field(..., min_length=1, max_length=2000)
    type: str = Field("", max_length=40)


class IOCBuildBody(BaseModel):
    ioc_ids: list[int] = Field(default_factory=list, max_length=200)
    observables: list[RawIOC] = Field(default_factory=list, max_length=200)
    language: str = Field("sigma", pattern=r"^(sigma|yaral|yara|kql|spl|eql|lucene|sql|osquery|generic)$")
    title: str = Field("IOC match hunt", min_length=3, max_length=200)
    technique_ids: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("technique_ids")
    @classmethod
    def techniques(cls, values: list[str]) -> list[str]:
        cleaned = sorted(set(value.strip().upper() for value in values if value.strip()))
        invalid = [value for value in cleaned if not library.ATTACK_ID_RE.fullmatch(value)]
        if invalid:
            raise ValueError(f"Invalid ATT&CK technique IDs: {', '.join(invalid)}")
        return cleaned


@router.get("", response_model=SearchOut)
async def search(
    q: str = Query("", max_length=500), language: str = Query("", max_length=40),
    technique: str = Query("", max_length=30), tag: str = Query("", max_length=100),
    source: str = Query("", max_length=255), platform: str = Query("", max_length=100),
    ioc_type: str = Query("", max_length=40), limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0, le=100_000), session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(read_library),
):
    await library.ensure_curated_library(session)
    rows, total = await library.search_library(session, q=q, language=language, technique=technique, tag=tag, source=source, platform=platform, ioc_type=ioc_type, limit=limit, offset=offset)
    return SearchOut(items=[ItemOut.model_validate(row) for row in rows], total=total, limit=limit, offset=offset)


@router.get("/facets")
async def get_facets(session: AsyncSession = Depends(get_session), _: TeamUser = Depends(read_library)):
    await library.ensure_curated_library(session)
    return await library.facets(session)


@router.get("/autocomplete")
async def get_autocomplete(q: str = Query("", max_length=120), limit: int = Query(12, ge=1, le=30), session: AsyncSession = Depends(get_session), _: TeamUser = Depends(read_library)):
    await library.ensure_curated_library(session)
    return {"items": await library.autocomplete(session, q, limit)}


@router.post("/build-from-ioc")
async def build_from_ioc(body: IOCBuildBody, session: AsyncSession = Depends(get_session), _: TeamUser = Depends(read_library)):
    try:
        observables, stored_techniques = await library.resolve_iocs(session, body.ioc_ids, [item.model_dump() for item in body.observables])
        return library.build_ioc_query(observables, body.language, title=body.title, technique_ids=sorted(set(stored_techniques + body.technique_ids)))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/sync")
async def sync_from_detection_feeds(session: AsyncSession = Depends(get_session), _: TeamUser = Depends(manage_library)):
    await library.ensure_curated_library(session)
    return await library.import_detection_versions(session)


@router.get("/{item_id}", response_model=ItemOut)
async def get_item(item_id: UUID, session: AsyncSession = Depends(get_session), _: TeamUser = Depends(read_library)):
    await library.ensure_curated_library(session)
    row = (await session.execute(select(HuntQueryLibraryItem).where(HuntQueryLibraryItem.id == item_id, HuntQueryLibraryItem.enabled.is_(True)))).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="Query library item not found")
    return ItemOut.model_validate(row)
