from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.models.simulation import SimulationSiemDestination
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
    source: str = Field(default="access", pattern="^(attacked_server|web|run|access|security|error|auth|endpoint)$")
    run_id: str = Field(default="", max_length=80)
    destination_url: str = Field(..., min_length=8, max_length=1000)
    limit: int = Field(default=100, ge=1, le=500)
    auth_type: str = Field(default="none", pattern="^(none|bearer|token|basic|custom_header)$")
    username: str = Field(default="", max_length=256)
    password: str = Field(default="", max_length=2048)
    token: str = Field(default="", max_length=4096)
    header_name: str = Field(default="", max_length=80)
    connection_mode: str = Field(default="auto", pattern="^(auto|direct|docker_host)$")
    allow_http_fallback: bool = Field(default=True)
    payload_format: str = Field(default="raw_lines", pattern="^(raw_lines|per_event|json_lines|envelope)$")


class AiAssistantTelemetryRequest(BaseModel):
    mode: str = Field(default="challenge", pattern="^(ttps|actor|challenge)$")
    ai_provider: str = Field(default="local", pattern="^(local|claude|openai|gemini|minimax)$")
    complicated_attack: bool = Field(default=False)
    scenario_id: str = Field(default="", max_length=120)
    technique_ids: list[str] = Field(default_factory=list, max_length=12)
    actor_profile: str = Field(default="generic-intrusion", max_length=80)
    analyst_goal: str = Field(default="", max_length=2000)
    destination_url: str = Field(..., min_length=8, max_length=1000)
    auth_type: str = Field(default="none", pattern="^(none|bearer|token|basic|custom_header)$")
    username: str = Field(default="", max_length=256)
    password: str = Field(default="", max_length=2048)
    token: str = Field(default="", max_length=4096)
    header_name: str = Field(default="", max_length=80)
    connection_mode: str = Field(default="auto", pattern="^(auto|direct|docker_host)$")
    allow_http_fallback: bool = Field(default=True)
    payload_format: str = Field(default="per_event", pattern="^(raw_lines|per_event|json_lines|envelope)$")


class SiemDestinationSaveRequest(BaseModel):
    destination_url: str = Field(..., min_length=8, max_length=1000)
    auth_type: str = Field(default="none", pattern="^(none|bearer|token|basic|custom_header)$")
    username: str = Field(default="", max_length=256)
    header_name: str = Field(default="", max_length=80)
    connection_mode: str = Field(default="auto", pattern="^(auto|direct|docker_host)$")
    allow_http_fallback: bool = True
    payload_format: str = Field(default="raw_lines", pattern="^(raw_lines|per_event|json_lines|envelope)$")
    source: str = Field(default="access", pattern="^(attacked_server|web|run|access|security|error|auth|endpoint)$")


class SiemDestinationOut(BaseModel):
    id: str
    destination_url: str
    auth_type: str
    username: str
    header_name: str
    connection_mode: str
    allow_http_fallback: bool
    payload_format: str
    source: str
    last_status: int
    last_ok: bool
    last_event_count: int
    last_error: str
    updated_at: datetime


@router.get("/catalog")
async def catalog(_: TeamUser = Depends(analyst)) -> list[dict[str, Any]]:
    return external_simulation.list_simulations()


@router.get("/targets")
async def targets(_: TeamUser = Depends(analyst)) -> list[dict[str, Any]]:
    return external_simulation.list_targets()


@router.get("/ai-assistant/scenarios")
async def ai_assistant_scenarios(_: TeamUser = Depends(analyst)) -> list[dict[str, Any]]:
    return external_simulation.list_ai_assistant_scenarios()


@router.get("/siem-destinations", response_model=list[SiemDestinationOut])
async def siem_destinations(
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(analyst),
) -> list[dict[str, Any]]:
    result = await session.execute(
        select(SimulationSiemDestination)
        .order_by(SimulationSiemDestination.updated_at.desc())
        .limit(10)
    )
    return [_siem_destination_out(row) for row in result.scalars().all()]


@router.post("/siem-destinations", response_model=SiemDestinationOut)
async def save_siem_destination(
    payload: SiemDestinationSaveRequest,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
) -> dict[str, Any]:
    try:
        row = await _upsert_siem_destination(session, user, payload)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    await audit(
        session,
        user,
        "simulation.save_siem_destination",
        "simulation_siem_destination",
        str(row.id),
        details={"destination_url": row.destination_url, "source": row.source, "auth_type": row.auth_type},
    )
    await session.commit()
    await session.refresh(row)
    return _siem_destination_out(row)


@router.delete("/siem-destinations")
async def clear_siem_destinations(
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
) -> dict[str, int]:
    result = await session.execute(delete(SimulationSiemDestination))
    await audit(session, user, "simulation.clear_siem_destinations", "simulation_siem_destination")
    await session.commit()
    return {"deleted": result.rowcount or 0}


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
            auth_type=payload.auth_type,
            username=payload.username,
            password=payload.password,
            token=payload.token,
            header_name=payload.header_name,
            connection_mode=payload.connection_mode,
            allow_http_fallback=payload.allow_http_fallback,
            payload_format=payload.payload_format,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    destination = await _upsert_siem_destination(
        session,
        user,
        SiemDestinationSaveRequest(
            destination_url=result["destination_url"],
            auth_type=payload.auth_type,
            username=payload.username,
            header_name=payload.header_name,
            connection_mode=payload.connection_mode,
            allow_http_fallback=payload.allow_http_fallback,
            payload_format=payload.payload_format,
            source=payload.source,
        ),
        last_status=int(result.get("status") or 0),
        last_ok=bool(result.get("ok")),
        last_event_count=int(result.get("event_count") or 0),
        last_error=str(result.get("error") or "")[:1000],
    )
    await audit(
        session,
        user,
        "simulation.forward_logs",
        "external_simulation",
        payload.run_id or payload.source,
        details={
            "source": payload.source,
            "run_id": payload.run_id,
            "destination_url": result["destination_url"],
            "auth_type": payload.auth_type,
            "auth_header": payload.header_name if payload.auth_type == "custom_header" else "",
            "connection_mode": payload.connection_mode,
            "http_fallback_allowed": payload.allow_http_fallback,
            "payload_format": payload.payload_format,
            "event_count": result["event_count"],
            "ok": result["ok"],
            "status": result["status"],
            "saved_destination_id": str(destination.id),
        },
    )
    await session.commit()
    return result


@router.post("/ai-assistant/telemetry")
async def ai_assistant_telemetry(
    payload: AiAssistantTelemetryRequest,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(analyst),
) -> dict[str, Any]:
    try:
        result = await external_simulation.run_ai_assistant_telemetry_simulation(
            mode=payload.mode,
            ai_provider=payload.ai_provider,
            complicated_attack=payload.complicated_attack,
            scenario_id=payload.scenario_id,
            technique_ids=payload.technique_ids,
            actor_profile=payload.actor_profile,
            analyst_goal=payload.analyst_goal,
            destination_url=payload.destination_url,
            auth_type=payload.auth_type,
            username=payload.username,
            password=payload.password,
            token=payload.token,
            header_name=payload.header_name,
            connection_mode=payload.connection_mode,
            allow_http_fallback=payload.allow_http_fallback,
            payload_format=payload.payload_format,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    delivery = result["delivery"]
    destination = await _upsert_siem_destination(
        session,
        user,
        SiemDestinationSaveRequest(
            destination_url=delivery["destination_url"],
            auth_type=payload.auth_type,
            username=payload.username,
            header_name=payload.header_name,
            connection_mode=payload.connection_mode,
            allow_http_fallback=payload.allow_http_fallback,
            payload_format=payload.payload_format,
            source="endpoint",
        ),
        last_status=int(delivery.get("status") or 0),
        last_ok=bool(delivery.get("ok")),
        last_event_count=int(delivery.get("event_count") or 0),
        last_error=str(delivery.get("error") or "")[:1000],
    )
    await audit(
        session,
        user,
        "simulation.ai_assistant_telemetry",
        "external_simulation",
        result["run_id"],
        details={
            "mode": payload.mode,
            "ai_provider": payload.ai_provider,
            "complicated_attack": payload.complicated_attack,
            "actor_profile": payload.actor_profile,
            "technique_ids": result["technique_ids"],
            "destination_url": delivery["destination_url"],
            "event_count": delivery["event_count"],
            "ok": delivery["ok"],
            "status": delivery["status"],
            "saved_destination_id": str(destination.id),
        },
    )
    await session.commit()
    return result


def _siem_destination_out(row: SimulationSiemDestination) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "destination_url": row.destination_url,
        "auth_type": row.auth_type,
        "username": row.username,
        "header_name": row.header_name,
        "connection_mode": row.connection_mode,
        "allow_http_fallback": row.allow_http_fallback,
        "payload_format": row.payload_format,
        "source": row.source,
        "last_status": row.last_status,
        "last_ok": row.last_ok,
        "last_event_count": row.last_event_count,
        "last_error": row.last_error,
        "updated_at": row.updated_at,
    }


async def _upsert_siem_destination(
    session: AsyncSession,
    user: TeamUser,
    payload: SiemDestinationSaveRequest,
    last_status: int = 0,
    last_ok: bool = False,
    last_event_count: int = 0,
    last_error: str = "",
) -> SimulationSiemDestination:
    destination_url = external_simulation.normalize_siem_destination_for_storage(payload.destination_url)
    result = await session.execute(
        select(SimulationSiemDestination).where(
            SimulationSiemDestination.destination_url == destination_url,
            SimulationSiemDestination.connection_mode == payload.connection_mode,
            SimulationSiemDestination.payload_format == payload.payload_format,
            SimulationSiemDestination.auth_type == payload.auth_type,
            SimulationSiemDestination.source == payload.source,
        )
    )
    row = result.scalar_one_or_none()
    if row is None:
        row = SimulationSiemDestination(
            destination_url=destination_url,
            connection_mode=payload.connection_mode,
            payload_format=payload.payload_format,
            auth_type=payload.auth_type,
            source=payload.source,
            created_by=user.name,
        )
        session.add(row)
    row.username = payload.username.strip() if payload.auth_type == "basic" else ""
    row.header_name = payload.header_name.strip() if payload.auth_type == "custom_header" else (payload.header_name or "Authorization")
    row.allow_http_fallback = payload.allow_http_fallback
    row.last_status = last_status
    row.last_ok = last_ok
    row.last_event_count = last_event_count
    row.last_error = last_error[:1000]
    await session.flush()
    await _trim_siem_destinations(session)
    return row


async def _trim_siem_destinations(session: AsyncSession) -> None:
    result = await session.execute(
        select(SimulationSiemDestination.id)
        .order_by(SimulationSiemDestination.updated_at.desc())
        .offset(10)
    )
    stale_ids = list(result.scalars().all())
    if stale_ids:
        await session.execute(delete(SimulationSiemDestination).where(SimulationSiemDestination.id.in_(stale_ids)))


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
