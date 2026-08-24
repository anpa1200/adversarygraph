"""Authority records for revisioned CTI research and durable workflows."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


PROJECT_STATUSES = ("active", "archived")
PROJECT_REVISION_STATUSES = ("current", "superseded", "revoked")
PROJECT_TLPS = (
    "TLP:CLEAR",
    "TLP:GREEN",
    "TLP:AMBER",
    "TLP:AMBER+STRICT",
    "TLP:RED",
)
PROJECT_SPEC_SCHEMA_VERSION = "research-project-spec-v1"
WORKFLOW_STATUSES = (
    "queued",
    "running",
    "succeeded",
    "degraded",
    "failed",
    "cancelled",
    "dead_lettered",
)
WORKFLOW_TRIGGER_TYPES = ("manual", "api", "schedule", "replay")
WORKFLOW_SCHEMA_VERSION = "research-workflow-v1"
WORKFLOW_PLAN_SCHEMA_VERSION = "research-workflow-plan-v1"
STAGE_CONFIG_SCHEMA_VERSION = "research-stage-config-v1"
STAGE_CHECKPOINT_SCHEMA_VERSION = "research-stage-checkpoint-v1"
STAGE_STATUSES = (
    "pending",
    "ready",
    "running",
    "retry_wait",
    "succeeded",
    "degraded",
    "skipped",
    "failed",
    "cancelled",
    "dead_lettered",
)
STAGE_ATTEMPT_STATUSES = (
    "running",
    "succeeded",
    "degraded",
    "failed",
    "cancelled",
    "abandoned",
)
OUTBOX_MESSAGE_STATUSES = (
    "pending",
    "dispatching",
    "awaiting_receipt",
    "retry_wait",
    "delivered",
    "dead_lettered",
    "cancelled",
)
OUTBOX_DELIVERY_STATUSES = (
    "dispatching",
    "awaiting_receipt",
    "delivered",
    "failed",
    "abandoned",
    "cancelled",
)
OUTBOX_EMISSION_KINDS = (
    "migration_backfill",
    "root_ready",
    "dependency_ready",
    "retry_scheduled",
    "lease_recovered",
    "manual_redrive",
)
OUTBOX_TOPIC_WORKFLOW_STAGE_READY = "workflow.stage.ready"
OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1 = "workflow-stage-ready-v1"
OUTBOX_V1_MAX_ATTEMPTS = 8
MAX_OUTBOX_DELIVERY_CYCLE = 9_007_199_254_740_991


def _quoted(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{value}'" for value in values)


class ResearchProject(Base):
    """Long-lived research container with optimistic concurrency control."""

    __tablename__ = "research_projects"
    __table_args__ = (
        UniqueConstraint("project_key", name="uq_research_project_key"),
        CheckConstraint(
            "project_key ~ '^[a-z0-9][a-z0-9-]{0,79}$'",
            name="ck_research_project_key",
        ),
        CheckConstraint(
            f"status IN ({_quoted(PROJECT_STATUSES)})",
            name="ck_research_project_status",
        ),
        CheckConstraint(
            f"tlp IN ({_quoted(PROJECT_TLPS)})",
            name="ck_research_project_tlp",
        ),
        CheckConstraint("version >= 1", name="ck_research_project_version"),
        CheckConstraint(
            "(status = 'archived' AND archived_at IS NOT NULL AND archive_reason <> '') "
            "OR (status = 'active' AND archived_at IS NULL AND archive_reason = '')",
            name="ck_research_project_archive_facts",
        ),
        Index("ix_research_projects_status_updated", "status", "updated_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_key: Mapped[str] = mapped_column(String(80))
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="active")
    domain: Mapped[str] = mapped_column(String(50), default="enterprise-attack")
    tlp: Mapped[str] = mapped_column(String(24), default="TLP:AMBER+STRICT")
    version: Mapped[int] = mapped_column(Integer, default=1)
    created_by: Mapped[str] = mapped_column(String(255))
    created_by_id: Mapped[str] = mapped_column(String(80), default="")
    updated_by: Mapped[str] = mapped_column(String(255), default="")
    updated_by_id: Mapped[str] = mapped_column(String(80), default="")
    archive_reason: Mapped[str] = mapped_column(Text, default="")
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class ProjectRevision(Base):
    """Immutable project specification snapshot with explicit lineage.

    Only lifecycle fields may transition after insertion. ``spec``, its
    checksum, schema version, revision number, and parent are immutable service
    invariants.  A partial unique index also guarantees that a project has at
    most one current revision even when multiple API replicas race.
    """

    __tablename__ = "project_revisions"
    __table_args__ = (
        UniqueConstraint("project_id", "revision", name="uq_project_revision_number"),
        CheckConstraint("revision >= 1", name="ck_project_revision_number"),
        CheckConstraint(
            f"status IN ({_quoted(PROJECT_REVISION_STATUSES)})",
            name="ck_project_revision_status",
        ),
        CheckConstraint(
            "spec_checksum ~ '^[0-9a-f]{64}$'",
            name="ck_project_revision_checksum",
        ),
        CheckConstraint(
            "parent_revision_id IS NULL OR parent_revision_id <> id",
            name="ck_project_revision_parent_not_self",
        ),
        CheckConstraint(
            "(status = 'revoked' AND revoked_at IS NOT NULL "
            "AND revoked_by <> '' AND revoked_by_id <> '') OR "
            "(status <> 'revoked' AND revoked_at IS NULL "
            "AND revoked_by = '' AND revoked_by_id = '')",
            name="ck_project_revision_revocation_facts",
        ),
        Index(
            "uq_project_revision_current",
            "project_id",
            unique=True,
            postgresql_where=text("status = 'current'"),
        ),
        Index(
            "ix_project_revisions_project_status_revision",
            "project_id",
            "status",
            "revision",
        ),
        Index("ix_project_revisions_parent", "parent_revision_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "research_projects.id",
            ondelete="RESTRICT",
            name="fk_project_revision_project",
        ),
    )
    revision: Mapped[int] = mapped_column(Integer)
    parent_revision_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "project_revisions.id",
            ondelete="RESTRICT",
            name="fk_project_revision_parent",
        ),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(String(20), default="current")
    schema_version: Mapped[str] = mapped_column(String(80), default=PROJECT_SPEC_SCHEMA_VERSION)
    spec: Mapped[dict] = mapped_column(JSONB)
    spec_checksum: Mapped[str] = mapped_column(String(64), index=True)
    change_summary: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(255))
    created_by_id: Mapped[str] = mapped_column(String(80), default="")
    revoked_by: Mapped[str] = mapped_column(String(255), default="")
    revoked_by_id: Mapped[str] = mapped_column(String(80), default="")
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class WorkflowRun(Base):
    """One idempotent execution bound to an immutable project revision."""

    __tablename__ = "workflow_runs"
    __table_args__ = (
        UniqueConstraint(
            "project_revision_id",
            "workflow_type",
            "idempotency_key",
            name="uq_workflow_run_idempotency",
        ),
        UniqueConstraint(
            "cancel_request_id",
            name="uq_workflow_run_cancel_request",
        ),
        CheckConstraint(
            f"status IN ({_quoted(WORKFLOW_STATUSES)})",
            name="ck_workflow_run_status",
        ),
        CheckConstraint(
            f"trigger_type IN ({_quoted(WORKFLOW_TRIGGER_TYPES)})",
            name="ck_workflow_run_trigger",
        ),
        CheckConstraint(
            "workflow_type ~ '^[a-z][a-z0-9_.-]{0,79}$'",
            name="ck_workflow_run_type",
        ),
        CheckConstraint(
            "workflow_schema_version <> '' AND plan_schema_version <> ''",
            name="ck_workflow_run_schema_versions",
        ),
        CheckConstraint(
            "priority BETWEEN 0 AND 9",
            name="ck_workflow_run_priority",
        ),
        CheckConstraint(
            "state_version >= 1",
            name="ck_workflow_run_state_version",
        ),
        CheckConstraint(
            "input_checksum ~ '^[0-9a-f]{64}$'",
            name="ck_workflow_run_input_checksum",
        ),
        CheckConstraint(
            "plan_checksum ~ '^[0-9a-f]{64}$'",
            name="ck_workflow_run_plan_checksum",
        ),
        CheckConstraint(
            "idempotency_key ~ '^[0-9a-f]{64}$'",
            name="ck_workflow_run_idempotency_key",
        ),
        CheckConstraint(
            "jsonb_typeof(input_manifest) = 'object' AND jsonb_typeof(stage_plan) = 'array'",
            name="ck_workflow_run_json_shapes",
        ),
        CheckConstraint(
            "replay_of_run_id IS NULL OR replay_of_run_id <> id",
            name="ck_workflow_run_replay_not_self",
        ),
        CheckConstraint(
            "(trigger_type = 'replay' AND replay_of_run_id IS NOT NULL) OR (trigger_type <> 'replay' AND replay_of_run_id IS NULL)",
            name="ck_workflow_run_replay_facts",
        ),
        CheckConstraint(
            "(status IN ('succeeded', 'degraded', 'failed', 'cancelled', 'dead_lettered') "
            "AND completed_at IS NOT NULL) OR "
            "(status IN ('queued', 'running') AND completed_at IS NULL)",
            name="ck_workflow_run_completion_facts",
        ),
        CheckConstraint(
            "(status = 'queued' AND started_at IS NULL) OR "
            "status = 'cancelled' OR "
            "(status IN ('running', 'succeeded', 'degraded', 'failed', 'dead_lettered') "
            "AND started_at IS NOT NULL)",
            name="ck_workflow_run_start_facts",
        ),
        CheckConstraint(
            "(status = 'cancelled' AND cancel_requested_at IS NOT NULL "
            "AND cancel_reason <> '' AND cancel_requested_by <> '' "
            "AND cancel_requested_by_id <> '') "
            "OR (status <> 'cancelled' AND cancel_requested_at IS NULL "
            "AND cancel_reason = '' AND cancel_requested_by = '' "
            "AND cancel_requested_by_id = '' AND cancel_request_id IS NULL)",
            name="ck_workflow_run_cancellation_facts",
        ),
        CheckConstraint(
            "(status IN ('degraded', 'failed', 'dead_lettered') "
            "AND status_reason_code <> '') OR "
            "(status NOT IN ('degraded', 'failed', 'dead_lettered') "
            "AND status_reason_code = '' AND status_summary = '')",
            name="ck_workflow_run_reason_facts",
        ),
        CheckConstraint(
            "(completed_at IS NULL OR started_at IS NULL OR completed_at >= started_at) "
            "AND (cancel_requested_at IS NULL OR completed_at >= cancel_requested_at)",
            name="ck_workflow_run_timestamp_order",
        ),
        Index(
            "ix_workflow_runs_project_status_created",
            "project_revision_id",
            "status",
            "created_at",
        ),
        Index("ix_workflow_runs_status_created", "status", "created_at"),
        Index("ix_workflow_runs_correlation", "correlation_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    project_revision_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "project_revisions.id",
            ondelete="RESTRICT",
            name="fk_workflow_run_project_revision",
        ),
    )
    replay_of_run_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "workflow_runs.id",
            ondelete="RESTRICT",
            name="fk_workflow_run_replay",
        ),
        nullable=True,
    )
    workflow_type: Mapped[str] = mapped_column(String(80))
    workflow_schema_version: Mapped[str] = mapped_column(String(80), default=WORKFLOW_SCHEMA_VERSION)
    plan_schema_version: Mapped[str] = mapped_column(String(80), default=WORKFLOW_PLAN_SCHEMA_VERSION)
    status: Mapped[str] = mapped_column(String(24), default="queued", index=True)
    trigger_type: Mapped[str] = mapped_column(String(20), default="api")
    idempotency_key: Mapped[str] = mapped_column(String(64))
    correlation_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), default=uuid.uuid4)
    input_manifest: Mapped[dict] = mapped_column(JSONB, default=dict)
    input_checksum: Mapped[str] = mapped_column(String(64))
    stage_plan: Mapped[list] = mapped_column(JSONB, default=list)
    plan_checksum: Mapped[str] = mapped_column(String(64))
    priority: Mapped[int] = mapped_column(Integer, default=5)
    state_version: Mapped[int] = mapped_column(Integer, default=1)
    status_reason_code: Mapped[str] = mapped_column(String(80), default="")
    status_summary: Mapped[str] = mapped_column(String(500), default="")
    created_by: Mapped[str] = mapped_column(String(255))
    created_by_id: Mapped[str] = mapped_column(String(80), default="")
    cancel_requested_by: Mapped[str] = mapped_column(String(255), default="")
    cancel_requested_by_id: Mapped[str] = mapped_column(String(80), default="")
    cancel_reason: Mapped[str] = mapped_column(String(500), default="")
    cancel_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # NULL is retained only for immutable cancelled rows created before the
    # 0004 contract.  The 0004 guard requires every new cancellation to bind a
    # unique request identity, so historical NULL rows are not replay proof.
    cancel_request_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class StageRun(Base):
    """Durable logical stage with a fenced, expiring worker lease."""

    __tablename__ = "stage_runs"
    __table_args__ = (
        UniqueConstraint("workflow_run_id", "id", name="uq_stage_run_workflow_id"),
        UniqueConstraint("workflow_run_id", "stage_key", name="uq_stage_run_key"),
        UniqueConstraint("workflow_run_id", "ordinal", name="uq_stage_run_ordinal"),
        UniqueConstraint("workflow_run_id", "idempotency_key", name="uq_stage_run_idempotency"),
        CheckConstraint(
            f"status IN ({_quoted(STAGE_STATUSES)})",
            name="ck_stage_run_status",
        ),
        CheckConstraint("ordinal >= 1", name="ck_stage_run_ordinal"),
        CheckConstraint(
            "stage_key ~ '^[a-z][a-z0-9_.-]{0,79}$' AND stage_type ~ '^[a-z][a-z0-9_.-]{0,79}$'",
            name="ck_stage_run_identity",
        ),
        CheckConstraint(
            "stage_version <> '' AND config_schema_version <> '' AND checkpoint_schema_version <> ''",
            name="ck_stage_run_schema_versions",
        ),
        CheckConstraint(
            "priority BETWEEN 0 AND 9",
            name="ck_stage_run_priority",
        ),
        CheckConstraint(
            "state_version >= 1",
            name="ck_stage_run_state_version",
        ),
        CheckConstraint(
            "attempt_count >= 0 AND max_attempts BETWEEN 1 AND 20 AND attempt_count <= max_attempts",
            name="ck_stage_run_attempts",
        ),
        CheckConstraint(
            "config_checksum ~ '^[0-9a-f]{64}$'",
            name="ck_stage_run_config_checksum",
        ),
        CheckConstraint(
            "input_checksum ~ '^[0-9a-f]{64}$'",
            name="ck_stage_run_input_checksum",
        ),
        CheckConstraint(
            "idempotency_key ~ '^[0-9a-f]{64}$'",
            name="ck_stage_run_idempotency_key",
        ),
        CheckConstraint(
            "output_checksum = '' OR output_checksum ~ '^[0-9a-f]{64}$'",
            name="ck_stage_run_output_checksum",
        ),
        CheckConstraint(
            "checkpoint_checksum ~ '^[0-9a-f]{64}$'",
            name="ck_stage_run_checkpoint_checksum",
        ),
        CheckConstraint(
            "checkpoint_version >= 0",
            name="ck_stage_run_checkpoint_version",
        ),
        CheckConstraint(
            "jsonb_typeof(depends_on) = 'array' "
            "AND jsonb_typeof(config) = 'object' "
            "AND jsonb_typeof(input_manifest) = 'object' "
            "AND jsonb_typeof(output_manifest) = 'object' "
            "AND jsonb_typeof(checkpoint) = 'object'",
            name="ck_stage_run_json_shapes",
        ),
        CheckConstraint(
            "(status = 'running' AND lease_owner <> '' AND lease_token IS NOT NULL "
            "AND leased_at IS NOT NULL AND lease_expires_at IS NOT NULL "
            "AND heartbeat_at IS NOT NULL) OR "
            "(status <> 'running' AND lease_owner = '' AND lease_token IS NULL "
            "AND leased_at IS NULL AND lease_expires_at IS NULL "
            "AND heartbeat_at IS NULL)",
            name="ck_stage_run_lease_facts",
        ),
        CheckConstraint(
            "(status IN ('ready', 'retry_wait') AND next_attempt_at IS NOT NULL) OR "
            "(status NOT IN ('ready', 'retry_wait') AND next_attempt_at IS NULL)",
            name="ck_stage_run_schedule_facts",
        ),
        CheckConstraint(
            "(status IN ('succeeded', 'degraded', 'skipped', 'failed', 'cancelled', 'dead_lettered') "
            "AND completed_at IS NOT NULL) OR "
            "(status IN ('pending', 'ready', 'running', 'retry_wait') AND completed_at IS NULL)",
            name="ck_stage_run_completion_facts",
        ),
        CheckConstraint(
            "(status IN ('pending', 'ready', 'skipped') "
            "AND attempt_count = 0 AND first_started_at IS NULL) OR "
            "(status IN ('running', 'retry_wait', 'succeeded', 'degraded', "
            "'failed', 'dead_lettered') AND attempt_count > 0 "
            "AND first_started_at IS NOT NULL) OR "
            "(status = 'cancelled' AND ((attempt_count = 0 AND first_started_at IS NULL) "
            "OR (attempt_count > 0 AND first_started_at IS NOT NULL)))",
            name="ck_stage_run_start_facts",
        ),
        CheckConstraint(
            "(status IN ('succeeded', 'degraded') "
            "AND output_checksum ~ '^[0-9a-f]{64}$') OR "
            "(status NOT IN ('succeeded', 'degraded') AND output_checksum = '')",
            name="ck_stage_run_output_facts",
        ),
        CheckConstraint(
            "(status = 'retry_wait' AND last_error_code <> '' "
            "AND last_error_retryable) OR "
            "(status = 'failed' AND last_error_code <> '' "
            "AND NOT last_error_retryable) OR "
            "(status = 'dead_lettered' AND last_error_code <> '' "
            "AND last_error_retryable) OR "
            "(status NOT IN ('retry_wait', 'failed', 'dead_lettered') "
            "AND last_error_code = '' AND last_error_summary = '' "
            "AND NOT last_error_retryable)",
            name="ck_stage_run_error_facts",
        ),
        CheckConstraint(
            "status <> 'running' OR (lease_expires_at > leased_at AND heartbeat_at >= leased_at AND heartbeat_at <= lease_expires_at)",
            name="ck_stage_run_lease_order",
        ),
        CheckConstraint(
            "completed_at IS NULL OR first_started_at IS NULL OR completed_at >= first_started_at",
            name="ck_stage_run_timestamp_order",
        ),
        Index(
            "ix_stage_runs_workflow_status_ordinal",
            "workflow_run_id",
            "status",
            "ordinal",
        ),
        Index(
            "ix_stage_runs_claim_ready",
            "next_attempt_at",
            "priority",
            "created_at",
            "id",
            postgresql_where=text("status IN ('ready', 'retry_wait')"),
        ),
        Index(
            "ix_stage_runs_expired_lease",
            "lease_expires_at",
            postgresql_where=text("status = 'running'"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workflow_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "workflow_runs.id",
            ondelete="RESTRICT",
            name="fk_stage_run_workflow",
        ),
    )
    stage_key: Mapped[str] = mapped_column(String(80))
    stage_type: Mapped[str] = mapped_column(String(80))
    stage_version: Mapped[str] = mapped_column(String(80))
    ordinal: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(24), default="pending", index=True)
    priority: Mapped[int] = mapped_column(Integer, default=5)
    state_version: Mapped[int] = mapped_column(Integer, default=1)
    idempotency_key: Mapped[str] = mapped_column(String(64))
    depends_on: Mapped[list] = mapped_column(JSONB, default=list)
    required: Mapped[bool] = mapped_column(Boolean, default=True)
    config_schema_version: Mapped[str] = mapped_column(String(80), default=STAGE_CONFIG_SCHEMA_VERSION)
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    config_checksum: Mapped[str] = mapped_column(String(64))
    input_manifest: Mapped[dict] = mapped_column(JSONB, default=dict)
    input_checksum: Mapped[str] = mapped_column(String(64))
    output_manifest: Mapped[dict] = mapped_column(JSONB, default=dict)
    output_checksum: Mapped[str] = mapped_column(String(64), default="")
    checkpoint: Mapped[dict] = mapped_column(JSONB, default=dict)
    checkpoint_schema_version: Mapped[str] = mapped_column(String(80), default=STAGE_CHECKPOINT_SCHEMA_VERSION)
    checkpoint_version: Mapped[int] = mapped_column(Integer, default=0)
    checkpoint_checksum: Mapped[str] = mapped_column(String(64))
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lease_owner: Mapped[str] = mapped_column(String(255), default="")
    lease_token: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    leased_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error_code: Mapped[str] = mapped_column(String(80), default="")
    last_error_summary: Mapped[str] = mapped_column(String(500), default="")
    last_error_retryable: Mapped[bool] = mapped_column(Boolean, default=False)
    first_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class StageAttempt(Base):
    """Attempt history and lease-token evidence for a logical stage."""

    __tablename__ = "stage_attempts"
    __table_args__ = (
        UniqueConstraint("stage_run_id", "attempt_number", name="uq_stage_attempt_number"),
        UniqueConstraint("lease_token", name="uq_stage_attempt_lease_token"),
        UniqueConstraint(
            "outbox_delivery_attempt_id",
            name="uq_stage_attempt_outbox_delivery",
        ),
        CheckConstraint(
            f"status IN ({_quoted(STAGE_ATTEMPT_STATUSES)})",
            name="ck_stage_attempt_status",
        ),
        CheckConstraint("attempt_number >= 1", name="ck_stage_attempt_number"),
        CheckConstraint("state_version >= 1", name="ck_stage_attempt_state_version"),
        CheckConstraint(
            "input_checksum ~ '^[0-9a-f]{64}$'",
            name="ck_stage_attempt_input_checksum",
        ),
        CheckConstraint(
            "output_checksum = '' OR output_checksum ~ '^[0-9a-f]{64}$'",
            name="ck_stage_attempt_output_checksum",
        ),
        CheckConstraint(
            "checkpoint_start_version >= 0 AND checkpoint_end_version >= checkpoint_start_version",
            name="ck_stage_attempt_checkpoint_versions",
        ),
        CheckConstraint(
            "(status = 'running' AND completed_at IS NULL) OR (status <> 'running' AND completed_at IS NOT NULL)",
            name="ck_stage_attempt_completion_facts",
        ),
        CheckConstraint(
            "lease_owner <> '' AND lease_expires_at > started_at "
            "AND heartbeat_at >= started_at "
            "AND (completed_at IS NULL OR completed_at >= heartbeat_at)",
            name="ck_stage_attempt_lease_facts",
        ),
        CheckConstraint(
            "(status IN ('succeeded', 'degraded') "
            "AND output_checksum ~ '^[0-9a-f]{64}$' "
            "AND error_code = '' AND error_class = '' AND error_summary = '' "
            "AND NOT retryable) OR "
            "(status = 'failed' AND error_code <> '' AND error_class <> '' "
            "AND error_summary <> '' AND output_checksum = '') OR "
            "(status = 'abandoned' AND error_code <> '' "
            "AND error_class <> '' AND error_summary <> '' "
            "AND output_checksum = '' AND retryable) OR "
            "(status = 'running' AND output_checksum = '' "
            "AND error_code = '' AND error_class = '' AND error_summary = '' "
            "AND NOT retryable) OR "
            "(status = 'cancelled' AND error_code <> '' AND error_class <> '' "
            "AND error_summary <> '' AND output_checksum = '' AND NOT retryable)",
            name="ck_stage_attempt_outcome_facts",
        ),
        CheckConstraint(
            "NOT retryable OR status IN ('failed', 'abandoned')",
            name="ck_stage_attempt_retryable_facts",
        ),
        CheckConstraint(
            "status <> 'running' OR outbox_delivery_attempt_id IS NOT NULL",
            name="ck_stage_attempt_receipt_required",
        ),
        Index("ix_stage_attempts_stage_status", "stage_run_id", "status"),
        Index(
            "uq_stage_attempt_running",
            "stage_run_id",
            unique=True,
            postgresql_where=text("status = 'running'"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    stage_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "stage_runs.id",
            ondelete="RESTRICT",
            name="fk_stage_attempt_stage",
        ),
    )
    outbox_delivery_attempt_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "outbox_delivery_attempts.id",
            ondelete="RESTRICT",
            name="fk_stage_attempt_outbox_delivery",
        ),
        nullable=True,
    )
    attempt_number: Mapped[int] = mapped_column(Integer)
    lease_token: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    lease_owner: Mapped[str] = mapped_column(String(255))
    delivery_id: Mapped[str] = mapped_column(String(100), default="")
    status: Mapped[str] = mapped_column(String(20), default="running")
    state_version: Mapped[int] = mapped_column(Integer, default=1)
    input_checksum: Mapped[str] = mapped_column(String(64))
    checkpoint_start_version: Mapped[int] = mapped_column(Integer)
    checkpoint_end_version: Mapped[int] = mapped_column(Integer)
    output_checksum: Mapped[str] = mapped_column(String(64), default="")
    error_code: Mapped[str] = mapped_column(String(80), default="")
    error_class: Mapped[str] = mapped_column(String(120), default="")
    error_summary: Mapped[str] = mapped_column(String(500), default="")
    retryable: Mapped[bool] = mapped_column(Boolean, default=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    lease_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class OutboxMessage(Base):
    """Immutable stage-ready envelope plus fenced delivery lifecycle."""

    __tablename__ = "outbox_messages"
    __table_args__ = (
        UniqueConstraint(
            "logical_key",
            "redrive_ordinal",
            name="uq_outbox_message_logical_redrive",
        ),
        UniqueConstraint(
            "redrive_of_message_id",
            name="uq_outbox_message_redrive_parent",
        ),
        CheckConstraint(
            f"status IN ({_quoted(OUTBOX_MESSAGE_STATUSES)})",
            name="ck_outbox_message_status",
        ),
        CheckConstraint(
            "aggregate_type = 'workflow_stage' AND aggregate_id = stage_run_id "
            f"AND topic = '{OUTBOX_TOPIC_WORKFLOW_STAGE_READY}' "
            f"AND schema_version = '{OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1}' "
            "AND stage_key ~ '^[a-z][a-z0-9_.-]{0,79}$'",
            name="ck_outbox_message_registry_identity",
        ),
        CheckConstraint(
            f"emission_kind IN ({_quoted(OUTBOX_EMISSION_KINDS)})",
            name="ck_outbox_message_emission_kind",
        ),
        CheckConstraint(
            "aggregate_version >= 1 AND state_version >= 1",
            name="ck_outbox_message_versions",
        ),
        CheckConstraint(
            "target_attempt_number BETWEEN 1 AND 20",
            name="ck_outbox_message_target_attempt",
        ),
        CheckConstraint(
            "input_checksum ~ '^[0-9a-f]{64}$' "
            "AND plan_checksum ~ '^[0-9a-f]{64}$' "
            "AND envelope_checksum ~ '^[0-9a-f]{64}$' "
            "AND logical_key ~ '^[0-9a-f]{64}$'",
            name="ck_outbox_message_checksums",
        ),
        CheckConstraint(
            "envelope_bytes BETWEEN 1 AND 49152 "
            "AND envelope_bytes = octet_length(convert_to(envelope_canonical, 'UTF8')) "
            "AND envelope_checksum = encode(sha256(convert_to(envelope_canonical, 'UTF8')), 'hex') "
            "AND envelope_canonical = ag_outbox_stage_ready_envelope("
            "workflow_run_id, stage_run_id, stage_key, target_attempt_number, "
            "input_checksum, plan_checksum)",
            name="ck_outbox_message_envelope_authority",
        ),
        CheckConstraint(
            "logical_key = ag_outbox_stage_ready_logical_key(workflow_run_id, stage_run_id, stage_key, target_attempt_number)",
            name="ck_outbox_message_logical_authority",
        ),
        CheckConstraint(
            f"attempt_count BETWEEN 0 AND max_attempts "
            f"AND max_attempts = {OUTBOX_V1_MAX_ATTEMPTS} "
            f"AND delivery_cycle BETWEEN 0 AND {MAX_OUTBOX_DELIVERY_CYCLE} "
            "AND delivery_cycle >= attempt_count",
            name="ck_outbox_message_delivery_counts",
        ),
        CheckConstraint(
            "(delivery_cycle = 0 AND cycle_key IS NULL) OR "
            "(delivery_cycle > 0 AND cycle_key ~ '^[0-9a-f]{64}$' "
            "AND cycle_key = ag_outbox_delivery_cycle_key(logical_key, delivery_cycle))",
            name="ck_outbox_message_cycle_authority",
        ),
        CheckConstraint(
            "(status IN ('pending', 'retry_wait') AND available_at IS NOT NULL) OR "
            "(status NOT IN ('pending', 'retry_wait') AND available_at IS NULL)",
            name="ck_outbox_message_schedule_facts",
        ),
        CheckConstraint(
            "(status IN ('dispatching', 'awaiting_receipt') "
            "AND active_delivery_attempt_id IS NOT NULL) OR "
            "(status NOT IN ('dispatching', 'awaiting_receipt') "
            "AND active_delivery_attempt_id IS NULL)",
            name="ck_outbox_message_active_facts",
        ),
        CheckConstraint(
            "(status = 'dispatching' AND lease_owner <> '' AND lease_token IS NOT NULL "
            "AND leased_at IS NOT NULL AND lease_expires_at IS NOT NULL "
            "AND heartbeat_at IS NOT NULL) OR "
            "(status <> 'dispatching' AND lease_owner = '' AND lease_token IS NULL "
            "AND leased_at IS NULL AND lease_expires_at IS NULL AND heartbeat_at IS NULL)",
            name="ck_outbox_message_lease_facts",
        ),
        CheckConstraint(
            "status <> 'dispatching' OR (lease_expires_at > leased_at AND heartbeat_at >= leased_at AND heartbeat_at <= lease_expires_at)",
            name="ck_outbox_message_lease_order",
        ),
        CheckConstraint(
            "(status = 'awaiting_receipt' AND receipt_deadline_at IS NOT NULL) OR "
            "(status <> 'awaiting_receipt' AND receipt_deadline_at IS NULL)",
            name="ck_outbox_message_receipt_facts",
        ),
        CheckConstraint(
            "(last_error_code = '' AND last_error_class = '' "
            "AND last_error_summary = '' AND NOT last_error_retryable) OR "
            "(last_error_code ~ '^[a-z][a-z0-9_.-]{0,79}$' "
            "AND last_error_class ~ '^[A-Za-z][A-Za-z0-9_.-]{0,119}$' "
            "AND last_error_summary <> '')",
            name="ck_outbox_message_error_facts",
        ),
        CheckConstraint(
            "status NOT IN ('retry_wait', 'dead_lettered') OR last_error_code <> ''",
            name="ck_outbox_message_error_required",
        ),
        CheckConstraint(
            "(status = 'delivered' AND delivered_at IS NOT NULL "
            "AND dead_lettered_at IS NULL AND cancelled_at IS NULL) OR "
            "(status = 'dead_lettered' AND delivered_at IS NULL "
            "AND dead_lettered_at IS NOT NULL AND cancelled_at IS NULL) OR "
            "(status = 'cancelled' AND delivered_at IS NULL "
            "AND dead_lettered_at IS NULL AND cancelled_at IS NOT NULL) OR "
            "(status NOT IN ('delivered', 'dead_lettered', 'cancelled') "
            "AND delivered_at IS NULL AND dead_lettered_at IS NULL AND cancelled_at IS NULL)",
            name="ck_outbox_message_terminal_facts",
        ),
        CheckConstraint(
            "(status = 'cancelled' AND cancelled_by <> '' "
            "AND cancelled_by_id <> '' AND cancel_reason <> '') OR "
            "(status <> 'cancelled' AND cancelled_by = '' "
            "AND cancelled_by_id = '' AND cancel_reason = '')",
            name="ck_outbox_message_cancellation_facts",
        ),
        CheckConstraint(
            "(redrive_ordinal = 0 AND redrive_of_message_id IS NULL "
            "AND emission_kind <> 'manual_redrive' "
            "AND redrive_requested_by = '' AND redrive_requested_by_id = '' "
            "AND redrive_reason = '' AND redrive_requested_at IS NULL) OR "
            "(redrive_ordinal >= 1 AND redrive_of_message_id IS NOT NULL "
            "AND emission_kind = 'manual_redrive' "
            "AND redrive_requested_by <> '' AND redrive_requested_by_id <> '' "
            "AND redrive_reason <> '' AND redrive_requested_at IS NOT NULL)",
            name="ck_outbox_message_redrive_facts",
        ),
        CheckConstraint(
            "redrive_of_message_id IS NULL OR redrive_of_message_id <> id",
            name="ck_outbox_message_parent_not_self",
        ),
        CheckConstraint(
            "updated_at >= created_at "
            "AND (redrive_requested_at IS NULL OR redrive_requested_at >= created_at) "
            "AND (delivered_at IS NULL OR delivered_at >= created_at) "
            "AND (dead_lettered_at IS NULL OR dead_lettered_at >= created_at) "
            "AND (cancelled_at IS NULL OR cancelled_at >= created_at)",
            name="ck_outbox_message_timestamp_order",
        ),
        ForeignKeyConstraint(
            ["workflow_run_id", "stage_run_id"],
            ["stage_runs.workflow_run_id", "stage_runs.id"],
            name="fk_outbox_message_stage_workflow",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["id", "active_delivery_attempt_id"],
            ["outbox_delivery_attempts.message_id", "outbox_delivery_attempts.id"],
            name="fk_outbox_message_active_delivery",
            ondelete="RESTRICT",
            deferrable=True,
            initially="DEFERRED",
            use_alter=True,
        ),
        Index(
            "uq_outbox_message_active_logical",
            "logical_key",
            unique=True,
            postgresql_where=text("status IN ('pending', 'dispatching', 'awaiting_receipt', 'retry_wait')"),
        ),
        Index(
            "ix_outbox_messages_claim",
            "available_at",
            "created_at",
            "id",
            postgresql_where=text("status IN ('pending', 'retry_wait')"),
        ),
        Index(
            "ix_outbox_messages_dispatch_lease",
            "lease_expires_at",
            "id",
            postgresql_where=text("status = 'dispatching'"),
        ),
        Index(
            "ix_outbox_messages_receipt_deadline",
            "receipt_deadline_at",
            "id",
            postgresql_where=text("status = 'awaiting_receipt'"),
        ),
        Index(
            "ix_outbox_messages_stage_target",
            "stage_run_id",
            "target_attempt_number",
            "redrive_ordinal",
        ),
        Index(
            "ix_outbox_messages_stage_active",
            "stage_run_id",
            "target_attempt_number",
            "id",
            postgresql_where=text("status IN ('pending', 'dispatching', 'awaiting_receipt', 'retry_wait')"),
        ),
        Index(
            "ix_outbox_messages_workflow_status_created",
            "workflow_run_id",
            "status",
            "created_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    workflow_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("workflow_runs.id", ondelete="RESTRICT", name="fk_outbox_message_workflow"),
    )
    stage_run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    aggregate_type: Mapped[str] = mapped_column(String(40))
    aggregate_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    aggregate_version: Mapped[int] = mapped_column(Integer)
    emission_kind: Mapped[str] = mapped_column(String(32))
    topic: Mapped[str] = mapped_column(String(80))
    schema_version: Mapped[str] = mapped_column(String(80))
    correlation_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    causation_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    stage_key: Mapped[str] = mapped_column(String(80))
    target_attempt_number: Mapped[int] = mapped_column(Integer)
    input_checksum: Mapped[str] = mapped_column(String(64))
    plan_checksum: Mapped[str] = mapped_column(String(64))
    envelope_canonical: Mapped[str] = mapped_column(Text)
    envelope_checksum: Mapped[str] = mapped_column(String(64))
    envelope_bytes: Mapped[int] = mapped_column(Integer)
    logical_key: Mapped[str] = mapped_column(String(64))
    redrive_of_message_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "outbox_messages.id",
            ondelete="RESTRICT",
            name="fk_outbox_message_redrive_parent",
        ),
        nullable=True,
    )
    redrive_ordinal: Mapped[int] = mapped_column(Integer, default=0)
    redrive_requested_by: Mapped[str] = mapped_column(String(255), default="")
    redrive_requested_by_id: Mapped[str] = mapped_column(String(80), default="")
    redrive_reason: Mapped[str] = mapped_column(String(500), default="")
    redrive_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="pending")
    state_version: Mapped[int] = mapped_column(Integer, default=1)
    attempt_count: Mapped[int] = mapped_column(Integer, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer)
    delivery_cycle: Mapped[int] = mapped_column(BigInteger, default=0)
    cycle_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    available_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    active_delivery_attempt_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    lease_owner: Mapped[str] = mapped_column(String(255), default="")
    lease_token: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    leased_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    receipt_deadline_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error_code: Mapped[str] = mapped_column(String(80), default="")
    last_error_class: Mapped[str] = mapped_column(String(120), default="")
    last_error_summary: Mapped[str] = mapped_column(String(500), default="")
    last_error_retryable: Mapped[bool] = mapped_column(Boolean, default=False)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    dead_lettered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cancelled_by: Mapped[str] = mapped_column(String(255), default="")
    cancelled_by_id: Mapped[str] = mapped_column(String(80), default="")
    cancel_reason: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class OutboxDeliveryAttempt(Base):
    """One publisher-fenced network-delivery cycle for an outbox message."""

    __tablename__ = "outbox_delivery_attempts"
    __table_args__ = (
        UniqueConstraint("message_id", "id", name="uq_outbox_delivery_message_id"),
        UniqueConstraint("message_id", "delivery_cycle", name="uq_outbox_delivery_message_cycle"),
        UniqueConstraint("message_id", "attempt_number", name="uq_outbox_delivery_message_attempt"),
        UniqueConstraint("delivery_token", name="uq_outbox_delivery_token"),
        UniqueConstraint("cycle_key", name="uq_outbox_delivery_cycle_key"),
        CheckConstraint(
            f"status IN ({_quoted(OUTBOX_DELIVERY_STATUSES)})",
            name="ck_outbox_delivery_status",
        ),
        CheckConstraint(
            f"attempt_number BETWEEN 1 AND 32 AND delivery_cycle BETWEEN 1 AND {MAX_OUTBOX_DELIVERY_CYCLE}",
            name="ck_outbox_delivery_numbers",
        ),
        CheckConstraint("state_version >= 1", name="ck_outbox_delivery_state_version"),
        CheckConstraint(
            "cycle_key ~ '^[0-9a-f]{64}$'",
            name="ck_outbox_delivery_cycle_key",
        ),
        CheckConstraint(
            "publisher_id <> '' AND lease_expires_at > leased_at AND heartbeat_at >= leased_at",
            name="ck_outbox_delivery_lease_facts",
        ),
        CheckConstraint(
            "(status = 'dispatching' AND broker_name = '' "
            "AND broker_message_id = '' AND broker_receipt_id = '') OR "
            "(status = 'awaiting_receipt' "
            "AND broker_name ~ '^[a-z][a-z0-9_.-]{0,79}$' "
            "AND broker_message_id <> '' AND broker_message_id !~ '[[:cntrl:]]' "
            "AND broker_receipt_id = '') OR "
            "(status = 'delivered' "
            "AND broker_name ~ '^[a-z][a-z0-9_.-]{0,79}$' "
            "AND broker_message_id <> '' AND broker_message_id !~ '[[:cntrl:]]' "
            "AND broker_receipt_id !~ '[[:cntrl:]]') OR "
            "(status IN ('failed', 'abandoned', 'cancelled') AND ("
            "(broker_name = '' AND broker_message_id = '' AND broker_receipt_id = '') OR "
            "(broker_name ~ '^[a-z][a-z0-9_.-]{0,79}$' "
            "AND broker_message_id <> '' AND broker_message_id !~ '[[:cntrl:]]' "
            "AND broker_receipt_id !~ '[[:cntrl:]]')))",
            name="ck_outbox_delivery_broker_facts",
        ),
        CheckConstraint(
            "(status = 'dispatching' AND dispatched_at IS NULL "
            "AND receipt_deadline_at IS NULL AND receipt_received_at IS NULL "
            "AND completed_at IS NULL) OR "
            "(status = 'awaiting_receipt' AND dispatched_at IS NOT NULL "
            "AND receipt_deadline_at IS NOT NULL AND receipt_received_at IS NULL "
            "AND completed_at IS NULL) OR "
            "(status = 'delivered' AND dispatched_at IS NOT NULL "
            "AND receipt_deadline_at IS NULL AND receipt_received_at IS NOT NULL "
            "AND completed_at IS NOT NULL) OR "
            "(status IN ('failed', 'abandoned', 'cancelled') "
            "AND receipt_deadline_at IS NULL AND receipt_received_at IS NULL "
            "AND completed_at IS NOT NULL)",
            name="ck_outbox_delivery_completion_facts",
        ),
        CheckConstraint(
            "(status IN ('dispatching', 'awaiting_receipt', 'delivered') "
            "AND error_code = '' AND error_class = '' AND error_summary = '' "
            "AND NOT retryable) OR "
            "(status IN ('failed', 'abandoned', 'cancelled') "
            "AND error_code ~ '^[a-z][a-z0-9_.-]{0,79}$' "
            "AND error_class ~ '^[A-Za-z][A-Za-z0-9_.-]{0,119}$' "
            "AND error_summary <> '')",
            name="ck_outbox_delivery_error_facts",
        ),
        CheckConstraint(
            "(status = 'abandoned' AND retryable) OR (status = 'cancelled' AND NOT retryable) OR status NOT IN ('abandoned', 'cancelled')",
            name="ck_outbox_delivery_retryable_facts",
        ),
        CheckConstraint(
            "(status = 'delivered' AND broker_receipt_id ~ '^[0-9a-f]{64}$') OR (status <> 'delivered' AND broker_receipt_id = '')",
            name="ck_outbox_delivery_receipt_fingerprint",
        ),
        CheckConstraint(
            "heartbeat_at <= lease_expires_at "
            "AND (dispatched_at IS NULL OR dispatched_at >= leased_at) "
            "AND (receipt_deadline_at IS NULL OR receipt_deadline_at > dispatched_at) "
            "AND (receipt_received_at IS NULL OR receipt_received_at >= dispatched_at) "
            "AND (completed_at IS NULL OR completed_at >= leased_at) "
            "AND updated_at >= created_at",
            name="ck_outbox_delivery_timestamp_order",
        ),
        Index(
            "uq_outbox_delivery_active_message",
            "message_id",
            unique=True,
            postgresql_where=text("status IN ('dispatching', 'awaiting_receipt')"),
        ),
        Index(
            "ix_outbox_delivery_message_status_attempt",
            "message_id",
            "status",
            "attempt_number",
        ),
        Index(
            "ix_outbox_delivery_dispatch_lease",
            "lease_expires_at",
            "id",
            postgresql_where=text("status = 'dispatching'"),
        ),
        Index(
            "ix_outbox_delivery_receipt_deadline",
            "receipt_deadline_at",
            "id",
            postgresql_where=text("status = 'awaiting_receipt'"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    message_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey(
            "outbox_messages.id",
            ondelete="RESTRICT",
            name="fk_outbox_delivery_message",
        ),
    )
    delivery_cycle: Mapped[int] = mapped_column(BigInteger)
    attempt_number: Mapped[int] = mapped_column(Integer)
    cycle_key: Mapped[str] = mapped_column(String(64))
    delivery_token: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    publisher_id: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(24), default="dispatching")
    state_version: Mapped[int] = mapped_column(Integer, default=1)
    leased_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    lease_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    broker_name: Mapped[str] = mapped_column(String(80), default="")
    broker_message_id: Mapped[str] = mapped_column(String(255), default="")
    broker_receipt_id: Mapped[str] = mapped_column(String(255), default="")
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    receipt_deadline_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    receipt_received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_code: Mapped[str] = mapped_column(String(80), default="")
    error_class: Mapped[str] = mapped_column(String(120), default="")
    error_summary: Mapped[str] = mapped_column(String(500), default="")
    retryable: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
