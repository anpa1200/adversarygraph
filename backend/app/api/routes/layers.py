"""
GET    /api/layers              — list saved layers
POST   /api/layers              — save current TTP selection as a named layer
GET    /api/layers/{layer_id}   — load a specific layer (returns technique_ids)
DELETE /api/layers/{layer_id}   — delete a saved layer
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.models.analysis import UserLayer

router = APIRouter(prefix="/layers", tags=["Saved Layers"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class LayerCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    domain: str = "enterprise-attack"
    technique_ids: list[str] = Field(..., min_length=1, max_length=500)


class LayerListItem(BaseModel):
    id: str
    name: str
    domain: str
    technique_count: int
    created_at: str
    updated_at: str


class LayerDetail(LayerListItem):
    technique_ids: list[str]


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("", response_model=list[LayerListItem])
async def list_layers(
    domain: str | None = None,
    db: AsyncSession = Depends(get_session),
):
    stmt = select(UserLayer).order_by(UserLayer.updated_at.desc())
    if domain:
        stmt = stmt.where(UserLayer.domain == domain)
    rows = await db.execute(stmt)
    layers = rows.scalars().all()
    return [
        LayerListItem(
            id=str(layer.id),
            name=layer.name,
            domain=layer.domain,
            technique_count=len(layer.layer_data.get("technique_ids", [])),
            created_at=layer.created_at.isoformat(),
            updated_at=layer.updated_at.isoformat(),
        )
        for layer in layers
    ]


@router.post("", response_model=LayerDetail, status_code=201)
async def save_layer(
    body: LayerCreate,
    db: AsyncSession = Depends(get_session),
):
    layer = UserLayer(
        name=body.name,
        domain=body.domain,
        layer_data={"technique_ids": sorted(set(body.technique_ids))},
    )
    db.add(layer)
    await db.commit()
    await db.refresh(layer)
    ids = layer.layer_data.get("technique_ids", [])
    return LayerDetail(
        id=str(layer.id),
        name=layer.name,
        domain=layer.domain,
        technique_count=len(ids),
        technique_ids=ids,
        created_at=layer.created_at.isoformat(),
        updated_at=layer.updated_at.isoformat(),
    )


@router.get("/{layer_id}", response_model=LayerDetail)
async def get_layer(
    layer_id: str,
    db: AsyncSession = Depends(get_session),
):
    try:
        lid = uuid.UUID(layer_id)
    except ValueError:
        raise HTTPException(400, "Invalid layer ID")
    row = await db.execute(select(UserLayer).where(UserLayer.id == lid))
    layer = row.scalar_one_or_none()
    if not layer:
        raise HTTPException(404, "Layer not found")
    ids = layer.layer_data.get("technique_ids", [])
    return LayerDetail(
        id=str(layer.id),
        name=layer.name,
        domain=layer.domain,
        technique_count=len(ids),
        technique_ids=ids,
        created_at=layer.created_at.isoformat(),
        updated_at=layer.updated_at.isoformat(),
    )


@router.delete("/{layer_id}", status_code=204)
async def delete_layer(
    layer_id: str,
    db: AsyncSession = Depends(get_session),
):
    try:
        lid = uuid.UUID(layer_id)
    except ValueError:
        raise HTTPException(400, "Invalid layer ID")
    row = await db.execute(select(UserLayer).where(UserLayer.id == lid))
    layer = row.scalar_one_or_none()
    if not layer:
        raise HTTPException(404, "Layer not found")
    await db.delete(layer)
    await db.commit()
