from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.services import external_simulation
from app.services.auth import TeamUser, analyst, audit

router = APIRouter(prefix="/simulation", tags=["Attack Simulation"])


class SimulationRunRequest(BaseModel):
    simulation_id: str = Field(..., min_length=1)
    target_id: str = Field(..., min_length=1)
    analyst_note: str = Field(default="", max_length=2000)


class ManualResultRequest(BaseModel):
    simulation_id: str
    target_id: str
    detection_result: str = Field(pattern="^(passed|failed|partial|not_proven)$")
    evidence: str = Field(default="", max_length=8000)
    gaps: list[str] = Field(default_factory=list)


class ForwardLogsRequest(BaseModel):
    source: str = Field(default="web", pattern="^(web|run)$")
    run_id: str = Field(default="", max_length=80)
    destination_url: str = Field(..., min_length=8, max_length=1000)
    limit: int = Field(default=100, ge=1, le=500)
    bearer_token: str = Field(default="", max_length=2048)


@router.get("/catalog")
async def catalog(_: TeamUser = Depends(analyst)) -> list[dict[str, Any]]:
    return external_simulation.list_simulations()


@router.get("/targets")
async def targets(_: TeamUser = Depends(analyst)) -> list[dict[str, Any]]:
    return external_simulation.list_targets()


@router.get("/logs")
async def logs(
    source: str = "web",
    run_id: str = "",
    limit: int = 100,
    _: TeamUser = Depends(analyst),
) -> dict[str, Any]:
    try:
        return external_simulation.tail_telemetry_logs(source=source, run_id=run_id, limit=limit)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/forward-logs")
async def forward_logs(
    payload: ForwardLogsRequest,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
) -> dict[str, Any]:
    try:
        result = external_simulation.forward_telemetry_logs(
            source=payload.source,
            run_id=payload.run_id,
            destination_url=payload.destination_url,
            limit=payload.limit,
            bearer_token=payload.bearer_token,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    await audit(
        session,
        user,
        "simulation.forward_logs",
        "external_simulation",
        payload.run_id or payload.source,
        details={
            "source": payload.source,
            "run_id": payload.run_id,
            "destination_url": payload.destination_url,
            "event_count": result["event_count"],
            "ok": result["ok"],
            "status": result["status"],
        },
    )
    await session.commit()
    return result


@router.post("/plan")
async def plan(
    payload: SimulationRunRequest,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
) -> dict[str, Any]:
    try:
        result = external_simulation.build_plan(payload.simulation_id, payload.target_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    await audit(
        session,
        user,
        "simulation.plan",
        "external_simulation",
        payload.simulation_id,
        details={"target_id": payload.target_id, "allowed": result["allowed"]},
    )
    await session.commit()
    return result


@router.post("/run")
async def run(
    payload: SimulationRunRequest,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
) -> dict[str, Any]:
    try:
        result = external_simulation.run_controlled_record(payload.simulation_id, payload.target_id, payload.analyst_note)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    await audit(
        session,
        user,
        "simulation.run_record",
        "external_simulation",
        payload.simulation_id,
        details={
            "target_id": payload.target_id,
            "status": result["status"],
            "traffic_emitted": result["traffic_emitted"],
        },
    )
    await session.commit()
    return result


@router.post("/manual-result")
async def manual_result(
    payload: ManualResultRequest,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
) -> dict[str, Any]:
    try:
        plan = external_simulation.build_plan(payload.simulation_id, payload.target_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    result = {
        "result_id": f"manual-{payload.simulation_id}-{payload.target_id}",
        "created_at": datetime.utcnow().isoformat() + "Z",
        "plan": plan,
        "detection_result": payload.detection_result,
        "validation_status": payload.detection_result,
        "evidence": payload.evidence,
        "gaps": payload.gaps,
        "traffic_emitted_by_platform": False,
        "note": "Manual result records analyst-supplied evidence from an authorized lab run.",
    }
    await audit(
        session,
        user,
        "simulation.manual_result",
        "external_simulation",
        payload.simulation_id,
        details={"target_id": payload.target_id, "detection_result": payload.detection_result},
    )
    await session.commit()
    return result
