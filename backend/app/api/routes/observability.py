from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_session
from app.core.observability import observability_state
from app.core.redaction import redact_sensitive_text
from app.services.auth import TeamUser, audit, require_permission
from app.services import rag as rag_service
from app.services import platform_architecture, runtime_intelligence, skywalking
from app.services.rag_retention import RAG_CORPUS_ADVISORY_LOCK_ID

router = APIRouter(
    prefix="/observability",
    tags=["Observability"],
    dependencies=[Depends(require_permission("read"))],
)
manage_runtime = require_permission("manage_intel")
view_platform_diagnostics = require_permission("view_audit")


class RuntimeSyncBody(BaseModel):
    minutes: int = Field(default=60, ge=5, le=10_080)
    service: str = Field(default="", max_length=200)
    layer: str = Field(default="", max_length=80)
    tlp: str = Field(default="TLP:AMBER+STRICT", pattern=r"^TLP:(CLEAR|GREEN|AMBER|AMBER\+STRICT|RED)$")


class RuntimePromotionBody(BaseModel):
    service_ids: list[UUID] = Field(min_length=1, max_length=100)

def _tail_lines(path: Path, limit: int) -> list[str]:
    if not path.exists() or not path.is_file():
        return []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    except OSError:
        return []
    return [line.rstrip("\n") for line in lines[-limit:]]


def _redact_log_line(line: str) -> str:
    return redact_sensitive_text(line)


@router.get("/summary")
async def observability_summary(
    _: TeamUser = Depends(view_platform_diagnostics),
) -> dict[str, Any]:
    log_path = Path(settings.log_dir) / "adversarygraph-api.log"
    snapshot = observability_state.snapshot()
    snapshot["log_file"] = {
        "path": str(log_path),
        "exists": log_path.exists(),
        "size_bytes": log_path.stat().st_size if log_path.exists() else 0,
    }
    return snapshot


@router.get("/traces")
async def recent_traces(
    limit: int = Query(100, ge=1, le=500),
    _: TeamUser = Depends(view_platform_diagnostics),
) -> dict[str, Any]:
    traces = observability_state.snapshot()["recent_traces"][:limit]
    return {"items": traces, "limit": limit}


@router.get("/logs")
async def api_logs(
    limit: int = Query(200, ge=1, le=1000),
    _: TeamUser = Depends(view_platform_diagnostics),
) -> dict[str, Any]:
    log_path = Path(settings.log_dir) / "adversarygraph-api.log"
    lines = [_redact_log_line(line) for line in _tail_lines(log_path, limit)]
    return {
        "path": str(log_path),
        "exists": log_path.exists(),
        "limit": limit,
        "lines": lines,
    }


@router.get("/metrics")
async def prometheus_metrics(
    _: TeamUser = Depends(view_platform_diagnostics),
) -> Response:
    return Response(
        content=observability_state.prometheus_text(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@router.get("/architecture")
async def platform_architecture_snapshot(
    minutes: int = Query(60, ge=5, le=10_080),
    db: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(view_platform_diagnostics),
) -> dict[str, Any]:
    """Return one evidence-labelled platform architecture and flow snapshot."""
    return await platform_architecture.snapshot(db, minutes=minutes)


@router.get("/skywalking/status")
async def skywalking_status() -> dict[str, Any]:
    """Return configuration and live OAP readiness without exposing secrets."""
    return await skywalking.health()


@router.get("/skywalking/topology")
async def skywalking_topology(
    minutes: int = Query(60, ge=5, le=10_080),
    service: str = Query("", max_length=200),
    layer: str = Query("", max_length=80),
) -> dict[str, Any]:
    try:
        return await skywalking.topology(minutes=minutes, service=service, layer=layer)
    except skywalking.SkyWalkingError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.get("/skywalking/investigate")
async def skywalking_investigate(
    query: str = Query(..., min_length=2, max_length=200),
    minutes: int = Query(60, ge=5, le=10_080),
    service: str = Query("", max_length=200),
    layer: str = Query("", max_length=80),
) -> dict[str, Any]:
    """Find matching runtime services and retain their one-hop dependencies."""
    try:
        return await skywalking.topology(
            minutes=minutes,
            service=service,
            layer=layer,
            query=query,
        )
    except skywalking.SkyWalkingError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/skywalking/sync")
async def sync_skywalking_runtime(
    body: RuntimeSyncBody,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(manage_runtime),
) -> dict[str, Any]:
    """Persist a bounded topology snapshot and immediately reconcile its RAG records."""
    try:
        topology = await skywalking.topology(
            minutes=body.minutes,
            service=body.service,
            layer=body.layer,
        )
    except skywalking.SkyWalkingError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    persisted = await runtime_intelligence.persist_topology(
        db, topology, actor=user.name, tlp=body.tlp
    )
    retention = await runtime_intelligence.enforce_retention(
        db, settings.skywalking_runtime_retention_days
    )
    await db.execute(
        text("SELECT pg_advisory_xact_lock(:lock_id)"),
        {"lock_id": RAG_CORPUS_ADVISORY_LOCK_ID},
    )
    rag_result = await rag_service.reconcile_corpus(
        db,
        None,
        source_types=["runtime_service"],
        include_embeddings=False,
    )
    await audit(
        db,
        user,
        "observability.skywalking_sync",
        "runtime_topology_snapshot",
        persisted["snapshot_id"],
        {
            "scope": topology["scope"],
            "counts": topology["counts"],
            "tlp": body.tlp,
            "rag_status": rag_result.status,
        },
    )
    await db.commit()
    return {
        **persisted,
        "retention": retention,
        "rag": rag_result.to_dict(),
        "vector_refresh": "scheduled" if settings.rag_embedding_enabled else "disabled",
        "provenance": topology["provenance"],
    }


@router.get("/runtime-graph")
async def stored_runtime_graph(
    query: str = Query("", max_length=200),
    limit: int = Query(200, ge=1, le=500),
    db: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    return await runtime_intelligence.list_runtime_graph(db, query=query, limit=limit)


@router.post("/runtime-graph/promote")
async def promote_runtime_evidence(
    body: RuntimePromotionBody,
    db: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(manage_runtime),
) -> dict[str, Any]:
    result = await runtime_intelligence.promote_to_evidence_graph(
        db, [str(value) for value in body.service_ids], actor=user.name
    )
    await audit(
        db,
        user,
        "observability.runtime_promote",
        "evidence_graph",
        details={"service_ids": [str(value) for value in body.service_ids], **result},
    )
    await db.commit()
    return {
        **result,
        "review_status": "needs_evidence",
        "route": "/evidence-graph",
        "boundary": "Promotion records observed telemetry; it does not confirm malicious activity.",
    }
