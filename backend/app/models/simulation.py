from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class SimulationSiemDestination(Base):
    __tablename__ = "simulation_siem_destinations"
    __table_args__ = (
        UniqueConstraint(
            "destination_url",
            "connection_mode",
            "payload_format",
            "auth_type",
            "source",
            name="uq_simulation_siem_destination",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    destination_url: Mapped[str] = mapped_column(String(1000))
    auth_type: Mapped[str] = mapped_column(String(30), default="none")
    username: Mapped[str] = mapped_column(String(256), default="")
    header_name: Mapped[str] = mapped_column(String(80), default="")
    connection_mode: Mapped[str] = mapped_column(String(30), default="auto")
    allow_http_fallback: Mapped[bool] = mapped_column(Boolean, default=False)
    payload_format: Mapped[str] = mapped_column(String(30), default="raw_lines")
    source: Mapped[str] = mapped_column(String(30), default="access")
    last_status: Mapped[int] = mapped_column(Integer, default=0)
    last_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    last_event_count: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str] = mapped_column(String(1000), default="")
    created_by: Mapped[str] = mapped_column(String(255), default="local")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class SimulationAttackFlow(Base):
    __tablename__ = "simulation_attack_flows"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    run_id: Mapped[str] = mapped_column(String(100), index=True)
    mode: Mapped[str] = mapped_column(String(30), default="challenge")
    ai_provider: Mapped[str] = mapped_column(String(30), default="local")
    ai_model: Mapped[str] = mapped_column(String(120), default="")
    ai_used: Mapped[bool] = mapped_column(Boolean, default=False)
    complicated_attack: Mapped[bool] = mapped_column(Boolean, default=False)
    actor_profile: Mapped[str] = mapped_column(String(120), default="")
    scenario_id: Mapped[str] = mapped_column(String(120), default="")
    scenario_name: Mapped[str] = mapped_column(String(255), default="")
    summary: Mapped[str] = mapped_column(String(1000), default="")
    technique_ids: Mapped[list[str]] = mapped_column(JSONB, default=list)
    attack_plan: Mapped[dict] = mapped_column(JSONB, default=dict)
    events: Mapped[list[dict]] = mapped_column(JSONB, default=list)
    delivery: Mapped[dict] = mapped_column(JSONB, default=dict)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    last_delivery_status: Mapped[int] = mapped_column(Integer, default=0)
    last_delivery_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    last_delivery_error: Mapped[str] = mapped_column(String(1000), default="")
    created_by: Mapped[str] = mapped_column(String(255), default="local")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
