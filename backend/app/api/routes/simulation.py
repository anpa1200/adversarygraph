from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.models.simulation import SimulationAttackFlow, SimulationSiemDestination
from app.services import external_simulation
from app.services.auth import TeamUser, audit, require_permission

router = APIRouter(prefix="/simulation", tags=["Attack Simulation"])
run_simulation = require_permission("run_attack_simulation")
forward_siem = require_permission("forward_siem")
logger = logging.getLogger(__name__)

_DESTINATION_PERSISTENCE_WARNING = (
    "Delivery completed, but the SIEM destination was not saved because its URL did not pass storage validation."
)


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
    allow_http_fallback: bool = Field(default=False)
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
    allow_http_fallback: bool = Field(default=False)
    payload_format: str = Field(default="per_event", pattern="^(raw_lines|per_event|json_lines|envelope)$")


class SiemDestinationSaveRequest(BaseModel):
    destination_url: str = Field(..., min_length=8, max_length=1000)
    auth_type: str = Field(default="none", pattern="^(none|bearer|token|basic|custom_header)$")
    username: str = Field(default="", max_length=256)
    header_name: str = Field(default="", max_length=80)
    connection_mode: str = Field(default="auto", pattern="^(auto|direct|docker_host)$")
    allow_http_fallback: bool = False
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


class AttackFlowOut(BaseModel):
    id: str
    run_id: str
    mode: str
    ai_provider: str
    ai_model: str
    ai_used: bool
    complicated_attack: bool
    actor_profile: str
    scenario_id: str
    scenario_name: str
    summary: str
    technique_ids: list[str]
    event_count: int
    last_delivery_status: int
    last_delivery_ok: bool
    last_delivery_error: str
    created_at: datetime
    updated_at: datetime
    attack_plan: dict[str, Any]
    events: list[dict[str, Any]]
    delivery: dict[str, Any]


class AttackFlowResendRequest(BaseModel):
    destination_url: str = Field(..., min_length=8, max_length=1000)
    auth_type: str = Field(default="none", pattern="^(none|bearer|token|basic|custom_header)$")
    username: str = Field(default="", max_length=256)
    password: str = Field(default="", max_length=2048)
    token: str = Field(default="", max_length=4096)
    header_name: str = Field(default="", max_length=80)
    connection_mode: str = Field(default="auto", pattern="^(auto|direct|docker_host)$")
    allow_http_fallback: bool = Field(default=False)
    payload_format: str = Field(default="per_event", pattern="^(raw_lines|per_event|json_lines|envelope)$")


@router.get("/catalog")
async def catalog(_: TeamUser = Depends(run_simulation)) -> list[dict[str, Any]]:
    return external_simulation.list_simulations()


@router.get("/targets")
async def targets(_: TeamUser = Depends(run_simulation)) -> list[dict[str, Any]]:
    return external_simulation.list_targets()


@router.get("/ai-assistant/scenarios")
async def ai_assistant_scenarios(_: TeamUser = Depends(run_simulation)) -> list[dict[str, Any]]:
    return external_simulation.list_ai_assistant_scenarios()


@router.get("/attack-flows", response_model=list[AttackFlowOut])
async def attack_flows(
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(run_simulation),
) -> list[dict[str, Any]]:
    result = await session.execute(
        select(SimulationAttackFlow)
        .order_by(SimulationAttackFlow.created_at.desc())
        .limit(20)
    )
    return [_attack_flow_out(row) for row in result.scalars().all()]


@router.post("/attack-flows/{flow_id}/resend")
async def resend_attack_flow(
    flow_id: UUID,
    payload: AttackFlowResendRequest,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(forward_siem),
) -> dict[str, Any]:
    row = await session.get(SimulationAttackFlow, flow_id)
    if row is None:
        raise HTTPException(404, "Attack flow not found")
    try:
        delivery = external_simulation.resend_ai_assistant_telemetry_events(
            stored_result=_attack_flow_result(row),
            destination_url=payload.destination_url,
            auth_type=payload.auth_type,
            username=payload.username,
            password=payload.password,
            token=payload.token,
            header_name=payload.header_name,
            connection_mode=payload.connection_mode,
            allow_http_fallback=payload.allow_http_fallback and payload.auth_type == "none",
            payload_format=payload.payload_format,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    delivery_status = int(delivery.get("status") or 0)
    delivery_ok = bool(delivery.get("ok"))
    delivery_error = str(delivery.get("error") or "")[:1000]
    destination, persistence_warning = await _persist_siem_destination_after_delivery(
        session,
        user,
        SiemDestinationSaveRequest(
            destination_url=delivery["destination_url"],
            auth_type=payload.auth_type,
            username=payload.username,
            header_name=payload.header_name,
            connection_mode=payload.connection_mode,
            allow_http_fallback=payload.allow_http_fallback and payload.auth_type == "none",
            payload_format=payload.payload_format,
            source="endpoint",
        ),
        last_status=delivery_status,
        last_ok=delivery_ok,
        last_event_count=int(delivery.get("event_count") or 0),
        last_error=delivery_error,
    )
    if persistence_warning:
        delivery = {**delivery, "destination_url": ""}
    row.delivery = delivery
    row.last_delivery_status = delivery_status
    row.last_delivery_ok = delivery_ok
    row.last_delivery_error = delivery_error
    await audit(
        session,
        user,
        "simulation.resend_attack_flow",
        "simulation_attack_flow",
        str(row.id),
        details={
            "run_id": row.run_id,
            "destination_url": delivery["destination_url"],
            "event_count": delivery["event_count"],
            "sent_event_count": delivery.get("sent_event_count", 0),
            "ok": delivery["ok"],
            "status": delivery["status"],
            "saved_destination_id": str(destination.id) if destination else "",
            "destination_persistence_warning": persistence_warning,
        },
    )
    await session.commit()
    await session.refresh(row)
    return {
        "flow": _attack_flow_out(row),
        "delivery": delivery,
        "destination_persistence": {
            "saved": destination is not None,
            "warning": persistence_warning,
        },
    }


@router.get("/siem-destinations", response_model=list[SiemDestinationOut])
async def siem_destinations(
    session: AsyncSession = Depends(get_session),
    _: TeamUser = Depends(forward_siem),
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
    user: TeamUser = Depends(forward_siem),
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
    user: TeamUser = Depends(forward_siem),
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
    _: TeamUser = Depends(run_simulation),
) -> dict[str, Any]:
    try:
        return external_simulation.tail_telemetry_logs(source=source, run_id=run_id, limit=limit)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/forward-logs")
async def forward_logs(
    payload: ForwardLogsRequest,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(forward_siem),
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
            allow_http_fallback=payload.allow_http_fallback and payload.auth_type == "none",
            payload_format=payload.payload_format,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    destination, persistence_warning = await _persist_siem_destination_after_delivery(
        session,
        user,
        SiemDestinationSaveRequest(
            destination_url=result["destination_url"],
            auth_type=payload.auth_type,
            username=payload.username,
            header_name=payload.header_name,
            connection_mode=payload.connection_mode,
            allow_http_fallback=payload.allow_http_fallback and payload.auth_type == "none",
            payload_format=payload.payload_format,
            source=payload.source,
        ),
        last_status=int(result.get("status") or 0),
        last_ok=bool(result.get("ok")),
        last_event_count=int(result.get("event_count") or 0),
        last_error=str(result.get("error") or "")[:1000],
    )
    if persistence_warning:
        result = {**result, "destination_url": ""}
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
            "http_fallback_allowed": payload.allow_http_fallback and payload.auth_type == "none",
            "payload_format": payload.payload_format,
            "event_count": result["event_count"],
            "ok": result["ok"],
            "status": result["status"],
            "saved_destination_id": str(destination.id) if destination else "",
            "destination_persistence_warning": persistence_warning,
        },
    )
    await session.commit()
    result["destination_persistence"] = {
        "saved": destination is not None,
        "warning": persistence_warning,
    }
    return result


@router.post("/ai-assistant/telemetry")
async def ai_assistant_telemetry(
    payload: AiAssistantTelemetryRequest,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(run_simulation),
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
            allow_http_fallback=payload.allow_http_fallback and payload.auth_type == "none",
            payload_format=payload.payload_format,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    delivery = result["delivery"]
    destination, persistence_warning = await _persist_siem_destination_after_delivery(
        session,
        user,
        SiemDestinationSaveRequest(
            destination_url=delivery["destination_url"],
            auth_type=payload.auth_type,
            username=payload.username,
            header_name=payload.header_name,
            connection_mode=payload.connection_mode,
            allow_http_fallback=payload.allow_http_fallback and payload.auth_type == "none",
            payload_format=payload.payload_format,
            source="endpoint",
        ),
        last_status=int(delivery.get("status") or 0),
        last_ok=bool(delivery.get("ok")),
        last_event_count=int(delivery.get("event_count") or 0),
        last_error=str(delivery.get("error") or "")[:1000],
    )
    if persistence_warning:
        delivery = {**delivery, "destination_url": ""}
        result = {**result, "delivery": delivery}
    flow = await _save_attack_flow(session, user, result)
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
            "saved_destination_id": str(destination.id) if destination else "",
            "saved_attack_flow_id": str(flow.id),
            "destination_persistence_warning": persistence_warning,
        },
    )
    await _trim_attack_flows(session)
    await session.commit()
    result["destination_persistence"] = {
        "saved": destination is not None,
        "warning": persistence_warning,
    }
    return result


def _attack_flow_out(row: SimulationAttackFlow) -> dict[str, Any]:
    return {
        "id": str(row.id),
        "run_id": row.run_id,
        "mode": row.mode,
        "ai_provider": row.ai_provider,
        "ai_model": row.ai_model,
        "ai_used": row.ai_used,
        "complicated_attack": row.complicated_attack,
        "actor_profile": row.actor_profile,
        "scenario_id": row.scenario_id,
        "scenario_name": row.scenario_name,
        "summary": row.summary,
        "technique_ids": row.technique_ids or [],
        "event_count": row.event_count,
        "last_delivery_status": row.last_delivery_status,
        "last_delivery_ok": row.last_delivery_ok,
        "last_delivery_error": row.last_delivery_error,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "attack_plan": row.attack_plan or {},
        "events": row.events or [],
        "delivery": row.delivery or {},
    }


def _attack_flow_result(row: SimulationAttackFlow) -> dict[str, Any]:
    return {
        "run_id": row.run_id,
        "mode": row.mode,
        "ai_provider": row.ai_provider,
        "ai_model": row.ai_model,
        "ai_used": row.ai_used,
        "complicated_attack": row.complicated_attack,
        "actor_profile": row.actor_profile,
        "technique_ids": row.technique_ids or [],
        "attack_plan": row.attack_plan or {},
        "events": row.events or [],
        "delivery": row.delivery or {},
    }


async def _save_attack_flow(session: AsyncSession, user: TeamUser, result: dict[str, Any]) -> SimulationAttackFlow:
    scenario = result.get("scenario") or {}
    now = datetime.now(timezone.utc)
    flow = SimulationAttackFlow(
        run_id=str(result.get("run_id") or ""),
        mode=str(result.get("mode") or "challenge"),
        ai_provider=str(result.get("ai_provider") or "local"),
        ai_model=str(result.get("ai_model") or ""),
        ai_used=bool(result.get("ai_used")),
        complicated_attack=bool(result.get("complicated_attack")),
        actor_profile=str(result.get("actor_profile") or ""),
        scenario_id=str(scenario.get("id") or ""),
        scenario_name=str(scenario.get("name") or ""),
        summary=str((result.get("attack_plan") or {}).get("summary") or ""),
        technique_ids=list(result.get("technique_ids") or []),
        attack_plan=dict(result.get("attack_plan") or {}),
        events=list(result.get("events") or []),
        delivery=dict(result.get("delivery") or {}),
        event_count=len(result.get("events") or []),
        last_delivery_status=int((result.get("delivery") or {}).get("status") or 0),
        last_delivery_ok=bool((result.get("delivery") or {}).get("ok")),
        last_delivery_error=str((result.get("delivery") or {}).get("error") or "")[:1000],
        created_by=user.name,
        created_at=now,
        updated_at=now,
    )
    session.add(flow)
    await session.flush()
    return flow


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


async def _persist_siem_destination_after_delivery(
    session: AsyncSession,
    user: TeamUser,
    payload: SiemDestinationSaveRequest,
    *,
    last_status: int = 0,
    last_ok: bool = False,
    last_event_count: int = 0,
    last_error: str = "",
) -> tuple[SimulationSiemDestination | None, str]:
    """Persist delivery metadata without misreporting an already-sent delivery.

    The send helpers validate destinations before performing I/O. This second
    validation protects stored metadata if an upstream response returns a
    different URL. A validation failure at this point must not turn a completed
    delivery into an API error, so callers receive an explicit persistence
    warning and continue to report the real delivery result.
    """
    try:
        destination = await _upsert_siem_destination(
            session,
            user,
            payload,
            last_status=last_status,
            last_ok=last_ok,
            last_event_count=last_event_count,
            last_error=last_error,
        )
    except ValueError as exc:
        logger.warning(
            "SIEM delivery completed but destination metadata failed storage validation: %s",
            exc,
        )
        return None, _DESTINATION_PERSISTENCE_WARNING
    return destination, ""


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
    # Never persist an authenticated HTTPS-to-HTTP downgrade preference. Even if
    # an older client sends `true`, credentials must remain confined to the
    # operator-selected transport.
    row.allow_http_fallback = payload.allow_http_fallback and payload.auth_type == "none"
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


async def _trim_attack_flows(session: AsyncSession) -> None:
    result = await session.execute(
        select(SimulationAttackFlow.id)
        .order_by(SimulationAttackFlow.created_at.desc())
        .offset(20)
    )
    stale_ids = list(result.scalars().all())
    if stale_ids:
        await session.execute(delete(SimulationAttackFlow).where(SimulationAttackFlow.id.in_(stale_ids)))


@router.post("/plan")
async def plan(
    payload: SimulationRunRequest,
    session: AsyncSession = Depends(get_session),
    user: TeamUser = Depends(run_simulation),
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
    user: TeamUser = Depends(run_simulation),
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
    user: TeamUser = Depends(run_simulation),
) -> dict[str, Any]:
    try:
        plan = external_simulation.build_plan(payload.simulation_id, payload.target_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    result = {
        "result_id": f"manual-{payload.simulation_id}-{payload.target_id}",
        "created_at": datetime.now(timezone.utc).isoformat() + "Z",
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
