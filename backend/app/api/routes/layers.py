"""
GET    /api/layers              — list saved layers
POST   /api/layers              — save current TTP selection as a named layer
GET    /api/layers/{layer_id}   — load a specific layer (returns technique_ids)
DELETE /api/layers/{layer_id}   — delete a saved layer
"""

from __future__ import annotations

import uuid
import re

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.models.analysis import UserLayer
from app.models.attack import AttackVersion, Technique
from app.core.config import settings
from app.services.auth import TeamUser, audit, current_user, require_permission

router = APIRouter(prefix="/layers", tags=["Saved Layers"])
manage_layers = require_permission("manage_intel")


# ── Schemas ───────────────────────────────────────────────────────────────────

class LayerCreate(BaseModel):
    model_config = {"extra": "forbid"}

    name: str = Field(..., min_length=1, max_length=255)
    domain: str = Field(default="enterprise-attack", min_length=1, max_length=50)
    technique_ids: list[str] = Field(..., min_length=1, max_length=500)


class LayerListItem(BaseModel):
    id: str
    name: str
    domain: str
    attack_version: str = ""
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
    _: TeamUser = Depends(current_user),
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
            attack_version=str(layer.layer_data.get("attack_version", "")),
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
    user: TeamUser = Depends(manage_layers),
):
    technique_ids, attack_version = await _validate_layer_techniques(
        db, body.domain, body.technique_ids
    )
    layer = UserLayer(
        name=body.name,
        domain=body.domain,
        layer_data={
            "technique_ids": technique_ids,
            "attack_version": attack_version,
        },
    )
    db.add(layer)
    await db.flush()
    await audit(db, user, "layers.create", "user_layer", str(layer.id), {"name": layer.name, "domain": layer.domain, "technique_count": len(layer.layer_data.get("technique_ids", []))})
    await db.commit()
    await db.refresh(layer)
    ids = layer.layer_data.get("technique_ids", [])
    return LayerDetail(
        id=str(layer.id),
        name=layer.name,
        domain=layer.domain,
        attack_version=attack_version,
        technique_count=len(ids),
        technique_ids=ids,
        created_at=layer.created_at.isoformat(),
        updated_at=layer.updated_at.isoformat(),
    )


@router.get("/{layer_id}", response_model=LayerDetail)
async def get_layer(
    layer_id: str,
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(current_user),
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
        attack_version=str(layer.layer_data.get("attack_version", "")),
        technique_count=len(ids),
        technique_ids=ids,
        created_at=layer.created_at.isoformat(),
        updated_at=layer.updated_at.isoformat(),
    )


@router.delete("/{layer_id}", status_code=204)
async def delete_layer(
    layer_id: str,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(manage_layers),
):
    try:
        lid = uuid.UUID(layer_id)
    except ValueError:
        raise HTTPException(400, "Invalid layer ID")
    row = await db.execute(select(UserLayer).where(UserLayer.id == lid))
    layer = row.scalar_one_or_none()
    if not layer:
        raise HTTPException(404, "Layer not found")
    await audit(db, user, "layers.delete", "user_layer", layer_id)
    await db.delete(layer)
    await db.commit()


_TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_ATLAS_TECHNIQUE_ID = re.compile(r"^AML\.T\d{4}(?:\.\d{3})?$")


async def _validate_layer_techniques(
    db: AsyncSession,
    domain: str,
    technique_ids: list[str],
) -> tuple[list[str], str]:
    """Fail closed on cross-domain, malformed, stale, or invented IDs."""
    normalized_domain = domain.strip().lower()
    if normalized_domain not in set(settings.attck_domain_list):
        raise HTTPException(422, "Unsupported ATT&CK domain")

    normalized = sorted({value.strip().upper() for value in technique_ids})
    identifier_pattern = (
        _ATLAS_TECHNIQUE_ID if normalized_domain == "atlas" else _TECHNIQUE_ID
    )
    malformed = [value for value in normalized if not identifier_pattern.fullmatch(value)]
    if malformed:
        raise HTTPException(
            422,
            f"Malformed ATT&CK/ATLAS technique IDs: {', '.join(malformed[:10])}",
        )

    version = (
        await db.execute(
            select(AttackVersion).where(
                AttackVersion.domain == normalized_domain,
                AttackVersion.is_latest.is_(True),
            )
        )
    ).scalar_one_or_none()
    if version is None:
        raise HTTPException(409, f"No current ATT&CK catalog is loaded for {normalized_domain}")

    rows = await db.execute(
        select(Technique.attack_id).where(
            Technique.version_id == version.id,
            Technique.attack_id.in_(normalized),
            Technique.is_deprecated.is_(False),
        )
    )
    known = {str(value).upper() for value in rows.scalars().all()}
    unknown = [value for value in normalized if value not in known]
    if unknown:
        raise HTTPException(
            422,
            f"Technique IDs are not present in the current {normalized_domain} catalog: {', '.join(unknown[:20])}",
        )
    return normalized, str(version.version)
