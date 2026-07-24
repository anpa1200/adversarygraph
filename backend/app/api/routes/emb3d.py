from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.models.asset_surface import AssetRegistryItem
from app.services.auth import TeamUser, audit, require_permission
from app.services.emb3d import (
    Emb3dDataUnavailable,
    assess_assets_with_emb3d,
    catalog_summary,
    load_emb3d_knowledge_base,
)

router = APIRouter(prefix="/emb3d", tags=["EMB3D"])
run_emb3d_assessment = require_permission("run_analysis")


class Emb3dAssessIn(BaseModel):
    asset_ids: list[str] = Field(default_factory=list)
    limit: int = Field(default=200, ge=1, le=500)


def _knowledge_base():
    try:
        return load_emb3d_knowledge_base()
    except Emb3dDataUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.get("/catalog")
async def emb3d_catalog(_: TeamUser = Depends(run_emb3d_assessment)):
    kb = _knowledge_base()
    return {
        **catalog_summary(kb),
        "properties": sorted(kb.properties.values(), key=lambda item: item["id"]),
    }


@router.get("/assets/report")
async def emb3d_asset_report(
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(run_emb3d_assessment),
):
    kb = _knowledge_base()
    rows = (
        await session.execute(
            select(AssetRegistryItem)
            .order_by(AssetRegistryItem.last_seen_at.desc())
            .limit(limit)
            .offset(offset)
        )
    ).scalars().all()
    report = assess_assets_with_emb3d(list(rows), kb)
    await audit(
        session,
        user,
        "emb3d.asset_report",
        "asset_registry",
        details={"asset_count": report["asset_count"], "threat_count": report["threat_count"]},
    )
    await session.commit()
    return report


@router.post("/assets/assess")
async def emb3d_assess_assets(
    payload: Emb3dAssessIn,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(run_emb3d_assessment),
):
    kb = _knowledge_base()
    stmt = select(AssetRegistryItem).order_by(AssetRegistryItem.last_seen_at.desc()).limit(payload.limit)
    if payload.asset_ids:
        try:
            ids = [uuid.UUID(item) for item in payload.asset_ids]
        except ValueError as exc:
            raise HTTPException(400, "Invalid asset ID") from exc
        stmt = select(AssetRegistryItem).where(AssetRegistryItem.id.in_(ids)).limit(payload.limit)
    rows = (await session.execute(stmt)).scalars().all()
    report = assess_assets_with_emb3d(list(rows), kb)
    await audit(
        session,
        user,
        "emb3d.assess_assets",
        "asset_registry",
        details={"requested_asset_ids": payload.asset_ids, "asset_count": report["asset_count"]},
    )
    await session.commit()
    return report


@router.post("/preview")
async def emb3d_preview_asset(asset: dict[str, Any], _: TeamUser = Depends(run_emb3d_assessment)):
    kb = _knowledge_base()
    registry_asset = AssetRegistryItem(
        inventory_asset_id=str(asset.get("inventory_asset_id") or asset.get("asset_id") or asset.get("name") or "preview"),
        fingerprint=f"preview:{asset.get('asset_id') or asset.get('name') or 'asset'}",
        name=str(asset.get("name") or asset.get("asset") or "Preview asset"),
        asset_type=str(asset.get("asset_type") or "unknown"),
        environment=str(asset.get("environment") or "unknown"),
        exposure=str(asset.get("exposure") or "unknown"),
        criticality=str(asset.get("criticality") or "medium"),
        ip_addresses=_list(asset.get("ip_addresses")),
        domains=_list(asset.get("domains")),
        ports=[int(item) for item in _list(asset.get("ports")) if str(item).isdigit()],
        technologies=_list(asset.get("technologies")),
        products=_list(asset.get("products")),
        suppliers=_list(asset.get("suppliers")),
        dependencies=_list(asset.get("dependencies")),
        tags=_list(asset.get("tags")),
        labels=asset.get("labels") if isinstance(asset.get("labels"), dict) else {},
        raw=asset,
        risk_score=int(asset.get("risk_score") or 0),
        risk_level=str(asset.get("risk_level") or "low"),
    )
    return assess_assets_with_emb3d([registry_asset], kb)


def _list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [part.strip() for part in str(value).replace(",", ";").split(";") if part.strip()]
