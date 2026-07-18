from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Query, Response

from app.core.config import settings
from app.core.observability import observability_state
from app.core.redaction import redact_sensitive_text
from app.services.auth import require_permission

router = APIRouter(
    prefix="/observability",
    tags=["Observability"],
    dependencies=[Depends(require_permission("view_audit"))],
)

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
async def observability_summary() -> dict[str, Any]:
    log_path = Path(settings.log_dir) / "adversarygraph-api.log"
    snapshot = observability_state.snapshot()
    snapshot["log_file"] = {
        "path": str(log_path),
        "exists": log_path.exists(),
        "size_bytes": log_path.stat().st_size if log_path.exists() else 0,
    }
    return snapshot


@router.get("/traces")
async def recent_traces(limit: int = Query(100, ge=1, le=500)) -> dict[str, Any]:
    traces = observability_state.snapshot()["recent_traces"][:limit]
    return {"items": traces, "limit": limit}


@router.get("/logs")
async def api_logs(limit: int = Query(200, ge=1, le=1000)) -> dict[str, Any]:
    log_path = Path(settings.log_dir) / "adversarygraph-api.log"
    lines = [_redact_log_line(line) for line in _tail_lines(log_path, limit)]
    return {
        "path": str(log_path),
        "exists": log_path.exists(),
        "limit": limit,
        "lines": lines,
    }


@router.get("/metrics")
async def prometheus_metrics() -> Response:
    return Response(
        content=observability_state.prometheus_text(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )
