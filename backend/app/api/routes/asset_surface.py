from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.core.config import settings
from app.core.safe_http import read_upload_limited
from app.models.asset_surface import AssetSurfaceCase
from app.models.threat_radar import ThreatCompanySpace, ThreatSpaceAsset
from app.services.asset_intel import (
    list_asset_matches,
    list_assets,
    retrohunt_assets,
    upsert_assets_from_surface_case,
)
from app.services.ai.factory import get_adapter
from app.services.asset_surface import (
    STRICT_ASSET_CSV_ALLOWED_VALUES,
    STRICT_ASSET_CSV_COLUMNS,
    STRICT_ASSET_CSV_REQUIRED_COLUMNS,
    build_ai_prompt,
    build_baseline_matrix,
    merge_ai_matrix,
    parse_ai_json,
    parse_inventory,
)
from app.services.auth import TeamUser, analyst, audit, has_permission, require_permission
from app.services.taxonomy import TAXONOMY_SYSTEM_INSTRUCTIONS

router = APIRouter(prefix="/asset-surface", tags=["Asset Attack Surface"])
manage_asset_surface = require_permission("manage_intel")
run_asset_analysis = require_permission("run_analysis")
logger = logging.getLogger(__name__)

MAX_ASSET_UPLOAD_BYTES = 10 * 1024 * 1024
ALLOWED_PROVIDERS = {"claude", "openai", "gemini", "minimax", "local"}


class AssetSurfaceAnalysisOut(BaseModel):
    case_id: str | None = None
    case_name: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    provider: str | None
    model: str | None
    filename: str | None
    inventory_name: str | None
    asset_count: int
    summary: str
    exposure_counts: dict[str, int]
    risk_counts: dict[str, int]
    assets: list[dict[str, Any]]
    top_risks: list[dict[str, Any]]
    recommended_workflow: list[str]
    cross_asset_findings: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    validation_gaps: list[str] = Field(default_factory=list)
    registry_summary: dict[str, Any] = Field(default_factory=dict)
    retrohunt_summary: dict[str, Any] = Field(default_factory=dict)
    intel_matches: list[dict[str, Any]] = Field(default_factory=list)
    company_space_id: str | None = None
    company_space_assets_synced: int = 0
    raw_ai_response: str = ""


class AssetSurfaceCaseListItem(BaseModel):
    id: str
    name: str
    filename: str | None = None
    provider: str
    model: str
    use_ai: bool
    asset_count: int
    technique_ids: list[str]
    high_or_critical_count: int
    summary: str
    created_at: datetime
    updated_at: datetime


class AssetRetrohuntIn(BaseModel):
    asset_ids: list[str] = Field(default_factory=list)


@router.get("/csv-schema")
async def asset_surface_csv_schema(_: TeamUser = Depends(analyst)):
    return {
        "format": "csv",
        "delimiter": ",",
        "multi_value_separator": ";",
        "columns": STRICT_ASSET_CSV_COLUMNS,
        "required_columns": STRICT_ASSET_CSV_REQUIRED_COLUMNS,
        "allowed_values": STRICT_ASSET_CSV_ALLOWED_VALUES,
        "template_header": ",".join(STRICT_ASSET_CSV_COLUMNS),
        "notes": [
            "Use UTF-8 CSV with a header row.",
            "Use semicolon-separated values inside multi-value cells.",
            "Quote cells that contain semicolons, commas, or spaces.",
            "Keep asset_id stable across uploads.",
            "Do not include secrets, credentials, private keys, or exploit payloads.",
        ],
    }


@router.post("/analyze", response_model=AssetSurfaceAnalysisOut)
async def analyze_asset_surface(
    provider: Annotated[str, Form()] = "local",
    model: Annotated[str | None, Form()] = None,
    inventory_name: Annotated[str | None, Form()] = None,
    company_space_id: Annotated[str | None, Form()] = None,
    use_ai: Annotated[bool, Form()] = True,
    text: Annotated[str | None, Form()] = None,
    file: UploadFile | None = File(default=None),
    files: list[UploadFile] | None = File(default=None),
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(manage_asset_surface),
):
    if (
        (file is not None or bool(files))
        and settings.auth_enabled
        and not has_permission(user, "upload_files")
    ):
        raise HTTPException(403, "Permission required: upload_files")
    company_space = await _get_company_space_or_none(session, company_space_id)
    inventory_inputs = await _read_inventory_inputs(text, file, files)
    filenames = [filename or "pasted inventory" for _, filename in inventory_inputs]
    filename = _combined_filename(filenames)
    records = []
    for content, source_filename in inventory_inputs:
        try:
            parsed_records, _source_text = parse_inventory(content, source_filename)
            records.extend(parsed_records)
        except Exception as exc:
            source_label = source_filename or "pasted inventory"
            logger.warning("Could not parse inventory source=%s", source_label, exc_info=True)
            raise HTTPException(400, f"Could not parse inventory {source_label}") from exc

    if not records:
        raise HTTPException(400, "Inventory did not contain any recognizable assets")

    baseline = build_baseline_matrix(records)
    ai_raw = ""
    matrix = baseline
    adapter_provider: str | None = None
    adapter_model: str | None = None

    if use_ai:
        try:
            adapter = _get_adapter(provider, model)
            adapter_provider = adapter.provider
            adapter_model = adapter.model
            ai_raw = await adapter._raw_complete(
                "You are a senior attack surface management analyst. Return only valid JSON.\n\n"
                + TAXONOMY_SYSTEM_INSTRUCTIONS,
                build_ai_prompt(records, baseline),
            )
            matrix = merge_ai_matrix(baseline, parse_ai_json(ai_raw))
        except Exception as exc:
            logger.warning("Asset-surface AI enrichment failed: %s", exc, exc_info=True)
            matrix = {
                **baseline,
                "validation_gaps": [
                    "AI enrichment failed; deterministic baseline matrix is shown.",
                    "Review server logs for the provider failure detail.",
                ],
            }

    await audit(
        session,
        user,
        "asset_surface.analyze",
        "asset_surface",
        details={
            "provider": adapter_provider or provider,
            "filename": filename,
            "filenames": filenames,
            "asset_count": len(records),
            "use_ai": use_ai,
            "company_space_id": str(company_space.id) if company_space else None,
        },
    )
    case_name = _case_name(inventory_name, filename)
    result = AssetSurfaceAnalysisOut(
        provider=adapter_provider,
        model=adapter_model,
        filename=filename,
        inventory_name=inventory_name,
        asset_count=len(records),
        summary=matrix["summary"],
        exposure_counts=matrix["exposure_counts"],
        risk_counts=matrix["risk_counts"],
        assets=matrix["assets"],
        top_risks=matrix["top_risks"],
        recommended_workflow=matrix["recommended_workflow"],
        cross_asset_findings=matrix.get("cross_asset_findings", []),
        assumptions=matrix.get("assumptions", []),
        validation_gaps=matrix.get("validation_gaps", []),
        company_space_id=str(company_space.id) if company_space else None,
        company_space_assets_synced=0,
        raw_ai_response=ai_raw,
    )
    case = AssetSurfaceCase(
        name=case_name,
        filename=filename or "",
        provider=adapter_provider or ("baseline" if not use_ai else provider),
        model=adapter_model or "",
        use_ai=use_ai,
        asset_count=len(records),
        technique_ids=_technique_ids(matrix["assets"]),
        high_or_critical_count=_high_or_critical_count(matrix["assets"]),
        summary=matrix["summary"],
        result=result.model_dump(mode="json"),
    )
    session.add(case)
    await session.flush()
    registry_summary = await upsert_assets_from_surface_case(
        session,
        case_id=case.id,
        inventory_name=case_name,
        assets=matrix["assets"],
    )
    retrohunt_summary = await retrohunt_assets(session, asset_ids=registry_summary["asset_ids"])
    recent_matches = await list_asset_matches(session, limit=100)
    asset_ids = set(registry_summary["asset_ids"])
    intel_matches = [match for match in recent_matches if match["asset_id"] in asset_ids][:50]
    space_sync_summary = await _sync_company_space_assets(session, company_space, matrix["assets"], case_name, str(case.id))
    result.case_id = str(case.id)
    result.case_name = case.name
    result.created_at = case.created_at
    result.updated_at = case.updated_at
    result.registry_summary = registry_summary
    result.retrohunt_summary = retrohunt_summary
    result.intel_matches = intel_matches
    result.company_space_id = str(company_space.id) if company_space else None
    result.company_space_assets_synced = space_sync_summary["synced"]
    case.result = result.model_dump(mode="json")

    await audit(
        session,
        user,
        "asset_surface.create_case",
        "asset_surface_case",
        str(case.id),
        details={"name": case.name, "asset_count": case.asset_count, "technique_count": len(case.technique_ids)},
    )
    await audit(
        session,
        user,
        "asset_surface.retrohunt",
        "asset_registry",
        details={
            "case_id": str(case.id),
            "assets_checked": retrohunt_summary.get("assets_checked", 0),
            "matches_created": retrohunt_summary.get("matches_created", 0),
        },
    )
    if company_space:
        await audit(
            session,
            user,
            "asset_surface.sync_company_space",
            "threat_company_space",
            str(company_space.id),
            details={
                "case_id": str(case.id),
                "inventory_name": case_name,
                "assets_synced": space_sync_summary["synced"],
                "created": space_sync_summary["created"],
                "updated": space_sync_summary["updated"],
            },
        )
    await session.commit()
    await session.refresh(case)
    result.created_at = case.created_at
    result.updated_at = case.updated_at
    return result


@router.get("/cases", response_model=list[AssetSurfaceCaseListItem])
async def list_asset_surface_cases(
    limit: int = 50,
    offset: int = 0,
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
):
    limit = min(max(limit, 1), 200)
    offset = max(offset, 0)
    rows = await session.execute(
        select(AssetSurfaceCase)
        .order_by(AssetSurfaceCase.updated_at.desc())
        .limit(limit)
        .offset(offset)
    )
    return [_case_list_item(row) for row in rows.scalars().all()]


@router.get("/assets")
async def list_registered_assets(
    search: str = "",
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
):
    return await list_assets(session, search=search, limit=limit, offset=offset)


@router.get("/intel-matches")
async def list_registered_asset_matches(
    asset_id: str | None = None,
    source_type: str = "",
    limit: int = Query(200, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
):
    try:
        return await list_asset_matches(session, asset_id=asset_id, source_type=source_type, limit=limit, offset=offset)
    except ValueError as exc:
        raise HTTPException(400, "Invalid asset ID") from exc


@router.post("/retrohunt")
async def run_asset_retrohunt(
    payload: AssetRetrohuntIn,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(run_asset_analysis),
):
    summary = await retrohunt_assets(session, asset_ids=payload.asset_ids or None)
    await audit(session, user, "asset_surface.retrohunt", "asset_registry", details=summary)
    await session.commit()
    return summary


@router.get("/cases/{case_id}", response_model=AssetSurfaceAnalysisOut)
async def get_asset_surface_case(
    case_id: str,
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
):
    case = await _get_case_or_404(session, case_id)
    payload = dict(case.result or {})
    payload.update({
        "case_id": str(case.id),
        "case_name": case.name,
        "created_at": case.created_at,
        "updated_at": case.updated_at,
    })
    return AssetSurfaceAnalysisOut(**payload)


@router.delete("/cases/{case_id}", status_code=204)
async def delete_asset_surface_case(
    case_id: str,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(manage_asset_surface),
):
    case = await _get_case_or_404(session, case_id)
    await audit(session, user, "asset_surface.delete_case", "asset_surface_case", str(case.id), {"name": case.name})
    await session.delete(case)
    await session.commit()


async def _read_inventory_inputs(
    text: str | None,
    file: UploadFile | None,
    files: list[UploadFile] | None,
) -> list[tuple[bytes, str | None]]:
    inventory_inputs: list[tuple[bytes, str | None]] = []
    total_bytes = 0
    if file:
        content = await read_upload_limited(file, MAX_ASSET_UPLOAD_BYTES)
        total_bytes += len(content)
        inventory_inputs.append((content, file.filename))
    for item in files or []:
        remaining = MAX_ASSET_UPLOAD_BYTES - total_bytes
        if remaining <= 0:
            raise HTTPException(413, "Inventory uploads exceed 10 MB total limit")
        content = await read_upload_limited(item, remaining)
        total_bytes += len(content)
        inventory_inputs.append((content, item.filename))
    if total_bytes > MAX_ASSET_UPLOAD_BYTES:
        raise HTTPException(413, "Inventory uploads exceed 10 MB total limit")
    if text and text.strip():
        content = text.encode("utf-8")
        if total_bytes + len(content) > MAX_ASSET_UPLOAD_BYTES:
            raise HTTPException(413, "Inventory uploads exceed 10 MB total limit")
        inventory_inputs.append((content, None))
    if inventory_inputs:
        return inventory_inputs
    raise HTTPException(400, "Provide pasted inventory text or upload a CSV/JSON/TXT inventory file")


def _combined_filename(filenames: list[str]) -> str | None:
    clean = [item.strip() for item in filenames if item.strip() and item != "pasted inventory"]
    if not clean:
        return None
    if len(clean) == 1:
        return clean[0][:500]
    joined = "; ".join(clean)
    if len(joined) <= 500:
        return joined
    return f"{len(clean)} inventory files: {joined[:470]}..."


async def _get_company_space_or_none(session: AsyncSession, company_space_id: str | None) -> ThreatCompanySpace | None:
    if not company_space_id:
        return None
    try:
        uid = uuid.UUID(company_space_id)
    except ValueError:
        raise HTTPException(400, "Invalid company space ID") from None
    space = await session.get(ThreatCompanySpace, uid)
    if not space:
        raise HTTPException(404, "Company space not found")
    return space


async def _sync_company_space_assets(
    session: AsyncSession,
    space: ThreatCompanySpace | None,
    assets: list[dict[str, Any]],
    inventory_name: str,
    case_id: str,
) -> dict[str, int]:
    if not space:
        return {"synced": 0, "created": 0, "updated": 0}
    created = 0
    updated = 0
    for row in assets:
        asset_id = str(row.get("asset_id") or "").strip() or f"asset-{uuid.uuid4().hex[:8]}"
        existing = (
            await session.execute(
                select(ThreatSpaceAsset).where(
                    ThreatSpaceAsset.space_id == space.id,
                    ThreatSpaceAsset.asset_id == asset_id,
                )
            )
        ).scalar_one_or_none()
        values = {
            "name": str(row.get("asset") or row.get("name") or asset_id)[:255],
            "asset_type": str(row.get("asset_type") or "unknown")[:120],
            "environment": str(row.get("environment") or "unknown")[:120],
            "owner": str(row.get("owner") or "")[:255],
            "criticality": str(row.get("criticality") or "medium")[:80],
            "exposure": str(row.get("exposure") or "unknown")[:80],
            "products": _list(row.get("products")),
            "components": _list(row.get("dependencies")) + _list(row.get("components")),
            "technologies": _list(row.get("technologies")),
            "ip_addresses": _list(row.get("ip_addresses")),
            "domains": _list(row.get("domains")),
            "tags": _space_asset_tags(row),
            "metadata_json": {
                "source": "asset_surface_upload",
                "source_case_id": case_id,
                "source_inventory_name": inventory_name,
                "risk_score": row.get("risk_score"),
                "risk_level": row.get("risk_level"),
                "ttp_candidates": row.get("ttp_candidates", []),
                "validation_steps": row.get("validation_steps", []),
                "control_gaps": row.get("control_gaps", []),
            },
        }
        if existing:
            for key, value in values.items():
                setattr(existing, key, value)
            updated += 1
        else:
            session.add(ThreatSpaceAsset(space_id=space.id, asset_id=asset_id, **values))
            created += 1
    return {"synced": created + updated, "created": created, "updated": updated}


def _space_asset_tags(row: dict[str, Any]) -> list[str]:
    labels = row.get("labels")
    if isinstance(labels, dict):
        return _list(labels.get("tags")) + _list(labels.get("ttps"))
    return _list(row.get("tags"))


def _list(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, dict):
        return [str(item).strip() for item in value.values() if str(item).strip()]
    return [part.strip() for part in str(value).replace(",", ";").split(";") if part.strip()]


def _get_adapter(provider: str, model: str | None):
    provider = provider.lower().strip()
    if provider not in ALLOWED_PROVIDERS:
        raise HTTPException(400, f"Invalid provider. Choose one of: {', '.join(sorted(ALLOWED_PROVIDERS))}")
    if model and len(model) > 100:
        raise HTTPException(400, "Model name is too long")
    return get_adapter(provider, model)


def _case_name(inventory_name: str | None, filename: str | None) -> str:
    name = (inventory_name or "").strip() or (filename or "").strip() or "Asset surface case"
    return name[:255]


def _technique_ids(assets: list[dict[str, Any]]) -> list[str]:
    ids = {
        str(ttp.get("attack_id", "")).upper()
        for asset in assets
        for ttp in asset.get("ttp_candidates", [])
        if ttp.get("attack_id")
    }
    return sorted(ids)


def _high_or_critical_count(assets: list[dict[str, Any]]) -> int:
    return sum(
        1
        for asset in assets
        if asset.get("risk_level") in {"high", "critical"} or asset.get("ai_risk_level") in {"high", "critical"}
    )


def _case_list_item(case: AssetSurfaceCase) -> AssetSurfaceCaseListItem:
    return AssetSurfaceCaseListItem(
        id=str(case.id),
        name=case.name,
        filename=case.filename or None,
        provider=case.provider,
        model=case.model,
        use_ai=case.use_ai,
        asset_count=case.asset_count,
        technique_ids=[str(item) for item in case.technique_ids],
        high_or_critical_count=case.high_or_critical_count,
        summary=case.summary,
        created_at=case.created_at,
        updated_at=case.updated_at,
    )


async def _get_case_or_404(session: AsyncSession, case_id: str) -> AssetSurfaceCase:
    try:
        uid = uuid.UUID(case_id)
    except ValueError:
        raise HTTPException(400, "Invalid asset surface case ID")
    case = await session.get(AssetSurfaceCase, uid)
    if not case:
        raise HTTPException(404, "Asset surface case not found")
    return case
