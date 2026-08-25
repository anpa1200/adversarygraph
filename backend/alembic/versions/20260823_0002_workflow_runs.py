"""Create durable workflow, stage, and attempt records.

Revision ID: 20260823_0002
Revises: 20260823_0001
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "20260823_0002"
down_revision: str | None = "20260823_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "workflow_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("project_revision_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("replay_of_run_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("workflow_type", sa.String(length=80), nullable=False),
        sa.Column("workflow_schema_version", sa.String(length=80), nullable=False),
        sa.Column("plan_schema_version", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("trigger_type", sa.String(length=20), nullable=False),
        sa.Column("idempotency_key", sa.String(length=64), nullable=False),
        sa.Column("correlation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("input_manifest", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("input_checksum", sa.String(length=64), nullable=False),
        sa.Column("stage_plan", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("plan_checksum", sa.String(length=64), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("state_version", sa.Integer(), nullable=False),
        sa.Column("status_reason_code", sa.String(length=80), nullable=False),
        sa.Column("status_summary", sa.String(length=500), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("created_by_id", sa.String(length=80), nullable=False),
        sa.Column("cancel_requested_by", sa.String(length=255), nullable=False),
        sa.Column("cancel_requested_by_id", sa.String(length=80), nullable=False),
        sa.Column("cancel_reason", sa.String(length=500), nullable=False),
        sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', 'degraded', 'failed', 'cancelled', 'dead_lettered')",
            name="ck_workflow_run_status",
        ),
        sa.CheckConstraint(
            "trigger_type IN ('manual', 'api', 'schedule', 'replay')",
            name="ck_workflow_run_trigger",
        ),
        sa.CheckConstraint(
            "workflow_type ~ '^[a-z][a-z0-9_.-]{0,79}$'",
            name="ck_workflow_run_type",
        ),
        sa.CheckConstraint(
            "workflow_schema_version <> '' AND plan_schema_version <> ''",
            name="ck_workflow_run_schema_versions",
        ),
        sa.CheckConstraint("priority BETWEEN 0 AND 9", name="ck_workflow_run_priority"),
        sa.CheckConstraint("state_version >= 1", name="ck_workflow_run_state_version"),
        sa.CheckConstraint(
            "input_checksum ~ '^[0-9a-f]{64}$'",
            name="ck_workflow_run_input_checksum",
        ),
        sa.CheckConstraint(
            "plan_checksum ~ '^[0-9a-f]{64}$'",
            name="ck_workflow_run_plan_checksum",
        ),
        sa.CheckConstraint(
            "idempotency_key ~ '^[0-9a-f]{64}$'",
            name="ck_workflow_run_idempotency_key",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(input_manifest) = 'object' AND jsonb_typeof(stage_plan) = 'array'",
            name="ck_workflow_run_json_shapes",
        ),
        sa.CheckConstraint(
            "replay_of_run_id IS NULL OR replay_of_run_id <> id",
            name="ck_workflow_run_replay_not_self",
        ),
        sa.CheckConstraint(
            "(trigger_type = 'replay' AND replay_of_run_id IS NOT NULL) OR "
            "(trigger_type <> 'replay' AND replay_of_run_id IS NULL)",
            name="ck_workflow_run_replay_facts",
        ),
        sa.CheckConstraint(
            "(status IN ('succeeded', 'degraded', 'failed', 'cancelled', 'dead_lettered') "
            "AND completed_at IS NOT NULL) OR "
            "(status IN ('queued', 'running') AND completed_at IS NULL)",
            name="ck_workflow_run_completion_facts",
        ),
        sa.CheckConstraint(
            "(status = 'queued' AND started_at IS NULL) OR "
            "status = 'cancelled' OR "
            "(status IN ('running', 'succeeded', 'degraded', 'failed', 'dead_lettered') "
            "AND started_at IS NOT NULL)",
            name="ck_workflow_run_start_facts",
        ),
        sa.CheckConstraint(
            "(status = 'cancelled' AND cancel_requested_at IS NOT NULL "
            "AND cancel_reason <> '' AND cancel_requested_by <> '' "
            "AND cancel_requested_by_id <> '') "
            "OR (status <> 'cancelled' AND cancel_requested_at IS NULL "
            "AND cancel_reason = '' AND cancel_requested_by = '' "
            "AND cancel_requested_by_id = '')",
            name="ck_workflow_run_cancellation_facts",
        ),
        sa.CheckConstraint(
            "(status IN ('degraded', 'failed', 'dead_lettered') "
            "AND status_reason_code <> '') OR "
            "(status NOT IN ('degraded', 'failed', 'dead_lettered') "
            "AND status_reason_code = '' AND status_summary = '')",
            name="ck_workflow_run_reason_facts",
        ),
        sa.CheckConstraint(
            "(completed_at IS NULL OR started_at IS NULL OR completed_at >= started_at) "
            "AND (cancel_requested_at IS NULL OR completed_at >= cancel_requested_at)",
            name="ck_workflow_run_timestamp_order",
        ),
        sa.ForeignKeyConstraint(
            ["project_revision_id"],
            ["project_revisions.id"],
            name="fk_workflow_run_project_revision",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["replay_of_run_id"],
            ["workflow_runs.id"],
            name="fk_workflow_run_replay",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "project_revision_id",
            "workflow_type",
            "idempotency_key",
            name="uq_workflow_run_idempotency",
        ),
    )
    op.create_index("ix_workflow_runs_status", "workflow_runs", ["status"])
    op.create_index(
        "ix_workflow_runs_project_status_created",
        "workflow_runs",
        ["project_revision_id", "status", "created_at"],
    )
    op.create_index(
        "ix_workflow_runs_status_created",
        "workflow_runs",
        ["status", "created_at"],
    )
    op.create_index("ix_workflow_runs_correlation", "workflow_runs", ["correlation_id"])

    op.create_table(
        "stage_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workflow_run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("stage_key", sa.String(length=80), nullable=False),
        sa.Column("stage_type", sa.String(length=80), nullable=False),
        sa.Column("stage_version", sa.String(length=80), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("state_version", sa.Integer(), nullable=False),
        sa.Column("idempotency_key", sa.String(length=64), nullable=False),
        sa.Column("depends_on", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("required", sa.Boolean(), nullable=False),
        sa.Column("config_schema_version", sa.String(length=80), nullable=False),
        sa.Column("config", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("config_checksum", sa.String(length=64), nullable=False),
        sa.Column("input_manifest", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("input_checksum", sa.String(length=64), nullable=False),
        sa.Column("output_manifest", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("output_checksum", sa.String(length=64), nullable=False),
        sa.Column("checkpoint", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("checkpoint_schema_version", sa.String(length=80), nullable=False),
        sa.Column("checkpoint_version", sa.Integer(), nullable=False),
        sa.Column("checkpoint_checksum", sa.String(length=64), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_owner", sa.String(length=255), nullable=False),
        sa.Column("lease_token", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("leased_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(length=80), nullable=False),
        sa.Column("last_error_summary", sa.String(length=500), nullable=False),
        sa.Column("last_error_retryable", sa.Boolean(), nullable=False),
        sa.Column("first_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'ready', 'running', 'retry_wait', 'succeeded', "
            "'degraded', 'skipped', 'failed', 'cancelled', 'dead_lettered')",
            name="ck_stage_run_status",
        ),
        sa.CheckConstraint("ordinal >= 1", name="ck_stage_run_ordinal"),
        sa.CheckConstraint(
            "stage_key ~ '^[a-z][a-z0-9_.-]{0,79}$' AND stage_type ~ '^[a-z][a-z0-9_.-]{0,79}$'",
            name="ck_stage_run_identity",
        ),
        sa.CheckConstraint(
            "stage_version <> '' AND config_schema_version <> '' AND checkpoint_schema_version <> ''",
            name="ck_stage_run_schema_versions",
        ),
        sa.CheckConstraint("priority BETWEEN 0 AND 9", name="ck_stage_run_priority"),
        sa.CheckConstraint("state_version >= 1", name="ck_stage_run_state_version"),
        sa.CheckConstraint(
            "attempt_count >= 0 AND max_attempts BETWEEN 1 AND 20 AND attempt_count <= max_attempts",
            name="ck_stage_run_attempts",
        ),
        sa.CheckConstraint(
            "config_checksum ~ '^[0-9a-f]{64}$'",
            name="ck_stage_run_config_checksum",
        ),
        sa.CheckConstraint(
            "input_checksum ~ '^[0-9a-f]{64}$'",
            name="ck_stage_run_input_checksum",
        ),
        sa.CheckConstraint(
            "idempotency_key ~ '^[0-9a-f]{64}$'",
            name="ck_stage_run_idempotency_key",
        ),
        sa.CheckConstraint(
            "output_checksum = '' OR output_checksum ~ '^[0-9a-f]{64}$'",
            name="ck_stage_run_output_checksum",
        ),
        sa.CheckConstraint(
            "checkpoint_checksum ~ '^[0-9a-f]{64}$'",
            name="ck_stage_run_checkpoint_checksum",
        ),
        sa.CheckConstraint(
            "checkpoint_version >= 0",
            name="ck_stage_run_checkpoint_version",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(depends_on) = 'array' "
            "AND jsonb_typeof(config) = 'object' "
            "AND jsonb_typeof(input_manifest) = 'object' "
            "AND jsonb_typeof(output_manifest) = 'object' "
            "AND jsonb_typeof(checkpoint) = 'object'",
            name="ck_stage_run_json_shapes",
        ),
        sa.CheckConstraint(
            "(status = 'running' AND lease_owner <> '' AND lease_token IS NOT NULL "
            "AND leased_at IS NOT NULL AND lease_expires_at IS NOT NULL "
            "AND heartbeat_at IS NOT NULL) OR "
            "(status <> 'running' AND lease_owner = '' AND lease_token IS NULL "
            "AND leased_at IS NULL AND lease_expires_at IS NULL "
            "AND heartbeat_at IS NULL)",
            name="ck_stage_run_lease_facts",
        ),
        sa.CheckConstraint(
            "(status IN ('ready', 'retry_wait') AND next_attempt_at IS NOT NULL) OR "
            "(status NOT IN ('ready', 'retry_wait') AND next_attempt_at IS NULL)",
            name="ck_stage_run_schedule_facts",
        ),
        sa.CheckConstraint(
            "(status IN ('succeeded', 'degraded', 'skipped', 'failed', 'cancelled', 'dead_lettered') "
            "AND completed_at IS NOT NULL) OR "
            "(status IN ('pending', 'ready', 'running', 'retry_wait') AND completed_at IS NULL)",
            name="ck_stage_run_completion_facts",
        ),
        sa.CheckConstraint(
            "(status IN ('pending', 'ready', 'skipped') "
            "AND attempt_count = 0 AND first_started_at IS NULL) OR "
            "(status IN ('running', 'retry_wait', 'succeeded', 'degraded', "
            "'failed', 'dead_lettered') AND attempt_count > 0 "
            "AND first_started_at IS NOT NULL) OR "
            "(status = 'cancelled' AND ((attempt_count = 0 AND first_started_at IS NULL) "
            "OR (attempt_count > 0 AND first_started_at IS NOT NULL)))",
            name="ck_stage_run_start_facts",
        ),
        sa.CheckConstraint(
            "(status IN ('succeeded', 'degraded') "
            "AND output_checksum ~ '^[0-9a-f]{64}$') OR "
            "(status NOT IN ('succeeded', 'degraded') AND output_checksum = '')",
            name="ck_stage_run_output_facts",
        ),
        sa.CheckConstraint(
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
        sa.CheckConstraint(
            "status <> 'running' OR (lease_expires_at > leased_at "
            "AND heartbeat_at >= leased_at AND heartbeat_at <= lease_expires_at)",
            name="ck_stage_run_lease_order",
        ),
        sa.CheckConstraint(
            "completed_at IS NULL OR first_started_at IS NULL "
            "OR completed_at >= first_started_at",
            name="ck_stage_run_timestamp_order",
        ),
        sa.ForeignKeyConstraint(
            ["workflow_run_id"],
            ["workflow_runs.id"],
            name="fk_stage_run_workflow",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("workflow_run_id", "idempotency_key", name="uq_stage_run_idempotency"),
        sa.UniqueConstraint("workflow_run_id", "stage_key", name="uq_stage_run_key"),
        sa.UniqueConstraint("workflow_run_id", "ordinal", name="uq_stage_run_ordinal"),
    )
    op.create_index("ix_stage_runs_status", "stage_runs", ["status"])
    op.create_index(
        "ix_stage_runs_workflow_status_ordinal",
        "stage_runs",
        ["workflow_run_id", "status", "ordinal"],
    )
    op.create_index(
        "ix_stage_runs_claim_ready",
        "stage_runs",
        ["next_attempt_at", "priority", "created_at", "id"],
        postgresql_where=sa.text("status IN ('ready', 'retry_wait')"),
    )
    op.create_index(
        "ix_stage_runs_expired_lease",
        "stage_runs",
        ["lease_expires_at"],
        postgresql_where=sa.text("status = 'running'"),
    )

    op.create_table(
        "stage_attempts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("stage_run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("lease_token", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("lease_owner", sa.String(length=255), nullable=False),
        sa.Column("delivery_id", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("state_version", sa.Integer(), nullable=False),
        sa.Column("input_checksum", sa.String(length=64), nullable=False),
        sa.Column("checkpoint_start_version", sa.Integer(), nullable=False),
        sa.Column("checkpoint_end_version", sa.Integer(), nullable=False),
        sa.Column("output_checksum", sa.String(length=64), nullable=False),
        sa.Column("error_code", sa.String(length=80), nullable=False),
        sa.Column("error_class", sa.String(length=120), nullable=False),
        sa.Column("error_summary", sa.String(length=500), nullable=False),
        sa.Column("retryable", sa.Boolean(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('running', 'succeeded', 'degraded', 'failed', 'cancelled', 'abandoned')",
            name="ck_stage_attempt_status",
        ),
        sa.CheckConstraint("attempt_number >= 1", name="ck_stage_attempt_number"),
        sa.CheckConstraint("state_version >= 1", name="ck_stage_attempt_state_version"),
        sa.CheckConstraint(
            "input_checksum ~ '^[0-9a-f]{64}$'",
            name="ck_stage_attempt_input_checksum",
        ),
        sa.CheckConstraint(
            "output_checksum = '' OR output_checksum ~ '^[0-9a-f]{64}$'",
            name="ck_stage_attempt_output_checksum",
        ),
        sa.CheckConstraint(
            "checkpoint_start_version >= 0 AND checkpoint_end_version >= checkpoint_start_version",
            name="ck_stage_attempt_checkpoint_versions",
        ),
        sa.CheckConstraint(
            "(status = 'running' AND completed_at IS NULL) OR (status <> 'running' AND completed_at IS NOT NULL)",
            name="ck_stage_attempt_completion_facts",
        ),
        sa.CheckConstraint(
            "lease_owner <> '' AND lease_expires_at > started_at "
            "AND heartbeat_at >= started_at "
            "AND (completed_at IS NULL OR completed_at >= heartbeat_at)",
            name="ck_stage_attempt_lease_facts",
        ),
        sa.CheckConstraint(
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
        sa.CheckConstraint(
            "NOT retryable OR status IN ('failed', 'abandoned')",
            name="ck_stage_attempt_retryable_facts",
        ),
        sa.ForeignKeyConstraint(
            ["stage_run_id"],
            ["stage_runs.id"],
            name="fk_stage_attempt_stage",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("lease_token", name="uq_stage_attempt_lease_token"),
        sa.UniqueConstraint("stage_run_id", "attempt_number", name="uq_stage_attempt_number"),
    )
    op.create_index(
        "ix_stage_attempts_stage_status",
        "stage_attempts",
        ["stage_run_id", "status"],
    )
    op.create_index(
        "uq_stage_attempt_running",
        "stage_attempts",
        ["stage_run_id"],
        unique=True,
        postgresql_where=sa.text("status = 'running'"),
    )
    op.execute("""
        CREATE FUNCTION ag_guard_research_project_authority()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'research project authority records cannot be deleted'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_research_project_no_delete';
            END IF;

            IF TG_OP = 'INSERT' THEN
                IF NEW.status <> 'active' OR NEW.version <> 1 THEN
                    RAISE EXCEPTION 'research projects must start active at version one'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_research_project_initial_state';
                END IF;
                IF NEW.created_by = '' OR NEW.created_by_id = ''
                   OR NEW.updated_by = '' OR NEW.updated_by_id = '' THEN
                    RAISE EXCEPTION 'research project authority requires stable actor identities'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_research_project_actor';
                END IF;
                RETURN NEW;
            END IF;

            IF OLD.id IS DISTINCT FROM NEW.id
               OR OLD.project_key IS DISTINCT FROM NEW.project_key
               OR OLD.created_by IS DISTINCT FROM NEW.created_by
               OR OLD.created_by_id IS DISTINCT FROM NEW.created_by_id
               OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
                RAISE EXCEPTION 'immutable research project authority fields cannot be changed'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_research_project_immutable';
            END IF;
            IF OLD.status = 'archived' THEN
                RAISE EXCEPTION 'archived research projects are terminal'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_research_project_transition';
            END IF;
            IF OLD.status <> 'active' OR NEW.status NOT IN ('active', 'archived')
               OR NEW.version <> OLD.version + 1 THEN
                RAISE EXCEPTION 'illegal research project lifecycle transition'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_research_project_transition';
            END IF;
            IF NEW.updated_by = '' OR NEW.updated_by_id = '' THEN
                RAISE EXCEPTION 'research project updates require a stable actor identity'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_research_project_actor';
            END IF;
            IF NEW.status = 'archived' AND (
                OLD.name IS DISTINCT FROM NEW.name
                OR OLD.description IS DISTINCT FROM NEW.description
                OR OLD.domain IS DISTINCT FROM NEW.domain
                OR OLD.tlp IS DISTINCT FROM NEW.tlp
            ) THEN
                RAISE EXCEPTION 'archival cannot rewrite research project metadata'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_research_project_archive_transition';
            END IF;
            RETURN NEW;
        END;
        $$
    """)
    op.execute("""
        CREATE TRIGGER trg_research_project_authority_guard
        BEFORE INSERT OR UPDATE OR DELETE ON research_projects
        FOR EACH ROW EXECUTE FUNCTION ag_guard_research_project_authority()
    """)

    op.execute("""
        CREATE FUNCTION ag_guard_project_revision_authority()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        DECLARE
            parent_project_id uuid;
            parent_revision_number integer;
            parent_status text;
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'project revision authority records cannot be deleted'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_project_revision_no_delete';
            END IF;

            IF TG_OP = 'UPDATE' AND (
                OLD.id IS DISTINCT FROM NEW.id
                OR OLD.project_id IS DISTINCT FROM NEW.project_id
                OR OLD.revision IS DISTINCT FROM NEW.revision
                OR OLD.parent_revision_id IS DISTINCT FROM NEW.parent_revision_id
                OR OLD.schema_version IS DISTINCT FROM NEW.schema_version
                OR OLD.spec IS DISTINCT FROM NEW.spec
                OR OLD.spec_checksum IS DISTINCT FROM NEW.spec_checksum
                OR OLD.change_summary IS DISTINCT FROM NEW.change_summary
                OR OLD.created_by IS DISTINCT FROM NEW.created_by
                OR OLD.created_by_id IS DISTINCT FROM NEW.created_by_id
                OR OLD.created_at IS DISTINCT FROM NEW.created_at
            ) THEN
                RAISE EXCEPTION 'immutable project revision authority fields cannot be changed'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_project_revision_immutable';
            END IF;

            IF TG_OP = 'INSERT' THEN
                IF NEW.status <> 'current' THEN
                    RAISE EXCEPTION 'project revisions must start current'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_project_revision_initial_state';
                END IF;
                IF NEW.created_by = '' OR NEW.created_by_id = '' THEN
                    RAISE EXCEPTION 'project revision authority requires a stable actor identity'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_project_revision_actor';
                END IF;
            ELSE
                IF OLD.status = 'revoked'
                   OR NOT (
                       (OLD.status = 'current' AND NEW.status IN ('superseded', 'revoked'))
                       OR (OLD.status = 'superseded' AND NEW.status = 'revoked')
                   ) THEN
                    RAISE EXCEPTION 'illegal project revision lifecycle transition'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_project_revision_transition';
                END IF;
                IF NEW.status = 'revoked' AND (
                    NEW.revoked_by = '' OR NEW.revoked_by_id = '' OR NEW.revoked_at IS NULL
                ) THEN
                    RAISE EXCEPTION 'revision revocation requires immutable actor and time evidence'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_project_revision_revocation_facts';
                END IF;
            END IF;

            IF NEW.revision = 1 AND NEW.parent_revision_id IS NOT NULL THEN
                RAISE EXCEPTION 'revision one cannot have a parent'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_project_revision_lineage';
            ELSIF NEW.revision > 1 AND NEW.parent_revision_id IS NULL THEN
                RAISE EXCEPTION 'non-initial revisions require a parent'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_project_revision_lineage';
            END IF;

            IF NEW.parent_revision_id IS NOT NULL THEN
                SELECT parent.project_id, parent.revision, parent.status
                INTO parent_project_id, parent_revision_number, parent_status
                FROM project_revisions AS parent
                WHERE parent.id = NEW.parent_revision_id;
                IF parent_project_id IS NULL
                   OR parent_project_id IS DISTINCT FROM NEW.project_id
                   OR parent_revision_number <> NEW.revision - 1
                   OR parent_status NOT IN ('superseded', 'revoked') THEN
                    RAISE EXCEPTION 'project revision parent must be the preceding non-current revision in the same project'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_project_revision_lineage';
                END IF;
            END IF;
            RETURN NEW;
        END;
        $$
    """)
    op.execute("""
        CREATE TRIGGER trg_project_revision_authority_guard
        BEFORE INSERT OR UPDATE OR DELETE ON project_revisions
        FOR EACH ROW EXECUTE FUNCTION ag_guard_project_revision_authority()
    """)

    op.execute("""
        CREATE FUNCTION ag_guard_workflow_run_authority()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        DECLARE
            origin_workflow_type text;
            origin_status text;
            origin_created_at timestamptz;
            origin_project_id uuid;
            target_project_id uuid;
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'workflow authority records cannot be deleted'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_workflow_run_no_delete';
            END IF;

            IF TG_OP = 'INSERT' THEN
                IF NEW.status <> 'queued' OR NEW.state_version <> 1 THEN
                    RAISE EXCEPTION 'workflows must start queued at state version one'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_workflow_run_initial_state';
                END IF;
                IF NEW.created_by = '' OR NEW.created_by_id = '' THEN
                    RAISE EXCEPTION 'workflow authority requires a stable actor identity'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_workflow_run_actor';
                END IF;
            ELSE
                IF OLD.id IS DISTINCT FROM NEW.id
                   OR OLD.project_revision_id IS DISTINCT FROM NEW.project_revision_id
                   OR OLD.replay_of_run_id IS DISTINCT FROM NEW.replay_of_run_id
                   OR OLD.workflow_type IS DISTINCT FROM NEW.workflow_type
                   OR OLD.workflow_schema_version IS DISTINCT FROM NEW.workflow_schema_version
                   OR OLD.plan_schema_version IS DISTINCT FROM NEW.plan_schema_version
                   OR OLD.trigger_type IS DISTINCT FROM NEW.trigger_type
                   OR OLD.idempotency_key IS DISTINCT FROM NEW.idempotency_key
                   OR OLD.correlation_id IS DISTINCT FROM NEW.correlation_id
                   OR OLD.input_manifest IS DISTINCT FROM NEW.input_manifest
                   OR OLD.input_checksum IS DISTINCT FROM NEW.input_checksum
                   OR OLD.stage_plan IS DISTINCT FROM NEW.stage_plan
                   OR OLD.plan_checksum IS DISTINCT FROM NEW.plan_checksum
                   OR OLD.priority IS DISTINCT FROM NEW.priority
                   OR OLD.created_by IS DISTINCT FROM NEW.created_by
                   OR OLD.created_by_id IS DISTINCT FROM NEW.created_by_id
                   OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
                    RAISE EXCEPTION 'immutable workflow definition fields cannot be changed'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_workflow_run_immutable';
                END IF;
                IF OLD.status IN ('succeeded', 'degraded', 'failed', 'cancelled', 'dead_lettered')
                   OR NEW.state_version <> OLD.state_version + 1
                   OR NOT (
                       (OLD.status = 'queued' AND NEW.status IN ('running', 'cancelled'))
                       OR (OLD.status = 'running' AND NEW.status IN (
                           'succeeded', 'degraded', 'failed', 'cancelled', 'dead_lettered'
                       ))
                   ) THEN
                    RAISE EXCEPTION 'illegal workflow state transition'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_workflow_run_transition';
                END IF;
                IF OLD.status = 'queued' AND NEW.status = 'cancelled'
                   AND NEW.started_at IS NOT NULL THEN
                    RAISE EXCEPTION 'a queued cancellation cannot claim execution started'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_workflow_run_transition';
                END IF;
                IF OLD.started_at IS NOT NULL
                   AND OLD.started_at IS DISTINCT FROM NEW.started_at THEN
                    RAISE EXCEPTION 'workflow start evidence is immutable once set'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_workflow_run_immutable';
                END IF;
            END IF;

            IF NEW.replay_of_run_id IS NOT NULL THEN
                SELECT origin.workflow_type,
                       origin.status,
                       origin.created_at,
                       origin_revision.project_id,
                       target_revision.project_id
                INTO origin_workflow_type,
                     origin_status,
                     origin_created_at,
                     origin_project_id,
                     target_project_id
                FROM workflow_runs AS origin
                JOIN project_revisions AS origin_revision
                  ON origin_revision.id = origin.project_revision_id
                JOIN project_revisions AS target_revision
                  ON target_revision.id = NEW.project_revision_id
                WHERE origin.id = NEW.replay_of_run_id;
                IF NOT FOUND
                   OR origin_workflow_type IS DISTINCT FROM NEW.workflow_type
                   OR origin_project_id IS DISTINCT FROM target_project_id
                   OR origin_created_at >= NEW.created_at
                   OR origin_status NOT IN (
                       'succeeded', 'degraded', 'failed', 'cancelled', 'dead_lettered'
                   ) THEN
                    RAISE EXCEPTION 'replay origin must be an older terminal run of the same workflow and project'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_workflow_run_replay_lineage';
                END IF;
            END IF;
            RETURN NEW;
        END;
        $$
    """)
    op.execute("""
        CREATE TRIGGER trg_workflow_run_authority_guard
        BEFORE INSERT OR UPDATE OR DELETE ON workflow_runs
        FOR EACH ROW EXECUTE FUNCTION ag_guard_workflow_run_authority()
    """)

    op.execute("""
        CREATE FUNCTION ag_guard_stage_run_authority()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        DECLARE
            attempt_status text;
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'stage authority records cannot be deleted'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_run_no_delete';
            END IF;

            IF TG_OP = 'INSERT' THEN
                IF NEW.status NOT IN ('pending', 'ready') OR NEW.state_version <> 1 THEN
                    RAISE EXCEPTION 'stages must start pending or ready at state version one'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_run_initial_state';
                END IF;
                RETURN NEW;
            END IF;

            IF OLD.id IS DISTINCT FROM NEW.id
               OR OLD.workflow_run_id IS DISTINCT FROM NEW.workflow_run_id
               OR OLD.stage_key IS DISTINCT FROM NEW.stage_key
               OR OLD.stage_type IS DISTINCT FROM NEW.stage_type
               OR OLD.stage_version IS DISTINCT FROM NEW.stage_version
               OR OLD.ordinal IS DISTINCT FROM NEW.ordinal
               OR OLD.priority IS DISTINCT FROM NEW.priority
               OR OLD.idempotency_key IS DISTINCT FROM NEW.idempotency_key
               OR OLD.depends_on IS DISTINCT FROM NEW.depends_on
               OR OLD.required IS DISTINCT FROM NEW.required
               OR OLD.config_schema_version IS DISTINCT FROM NEW.config_schema_version
               OR OLD.config IS DISTINCT FROM NEW.config
               OR OLD.config_checksum IS DISTINCT FROM NEW.config_checksum
               OR OLD.input_manifest IS DISTINCT FROM NEW.input_manifest
               OR OLD.input_checksum IS DISTINCT FROM NEW.input_checksum
               OR OLD.checkpoint_schema_version IS DISTINCT FROM NEW.checkpoint_schema_version
               OR OLD.max_attempts IS DISTINCT FROM NEW.max_attempts
               OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
                RAISE EXCEPTION 'immutable stage definition fields cannot be changed'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_run_immutable';
            END IF;
            IF OLD.status IN (
                'succeeded', 'degraded', 'skipped', 'failed', 'cancelled', 'dead_lettered'
            ) OR NEW.state_version <> OLD.state_version + 1
               OR NOT (
                   (OLD.status = 'pending' AND NEW.status IN ('ready', 'skipped', 'cancelled'))
                   OR (OLD.status = 'ready' AND NEW.status IN ('running', 'skipped', 'cancelled'))
                   OR (OLD.status = 'running' AND NEW.status IN (
                       'running', 'retry_wait', 'succeeded', 'degraded',
                       'failed', 'cancelled', 'dead_lettered'
                   ))
                   OR (OLD.status = 'retry_wait' AND NEW.status IN (
                       'running', 'cancelled', 'dead_lettered'
                   ))
               ) THEN
                RAISE EXCEPTION 'illegal stage state transition'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_run_transition';
            END IF;
            IF NEW.checkpoint_version < OLD.checkpoint_version THEN
                RAISE EXCEPTION 'stage checkpoint versions cannot move backwards'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_run_checkpoint_transition';
            END IF;

            IF NEW.status = 'running' AND OLD.status IN ('ready', 'retry_wait') THEN
                IF NEW.attempt_count <> OLD.attempt_count + 1
                   OR (OLD.status = 'ready' AND NEW.first_started_at IS NULL)
                   OR (OLD.first_started_at IS NOT NULL
                       AND OLD.first_started_at IS DISTINCT FROM NEW.first_started_at)
                   OR OLD.checkpoint_version IS DISTINCT FROM NEW.checkpoint_version
                   OR OLD.checkpoint IS DISTINCT FROM NEW.checkpoint
                   OR OLD.checkpoint_checksum IS DISTINCT FROM NEW.checkpoint_checksum THEN
                    RAISE EXCEPTION 'claiming a stage must advance only its attempt and lease facts'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_run_claim_transition';
                END IF;
            ELSIF OLD.status = 'running' THEN
                IF NEW.attempt_count IS DISTINCT FROM OLD.attempt_count
                   OR NEW.first_started_at IS DISTINCT FROM OLD.first_started_at THEN
                    RAISE EXCEPTION 'running stage attempt identity cannot be rewritten'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_run_attempt_transition';
                END IF;
                SELECT attempt.status
                INTO attempt_status
                FROM stage_attempts AS attempt
                WHERE attempt.stage_run_id = OLD.id
                  AND attempt.lease_token = OLD.lease_token;
                IF NOT FOUND OR (NEW.status = 'running' AND attempt_status <> 'running')
                   OR (NEW.status <> 'running' AND attempt_status = 'running') THEN
                    RAISE EXCEPTION 'stage state must agree with its fenced attempt evidence'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_run_attempt_evidence';
                END IF;
                IF NEW.status = 'running' AND (
                    NEW.lease_token IS DISTINCT FROM OLD.lease_token
                    OR NEW.lease_owner IS DISTINCT FROM OLD.lease_owner
                    OR NEW.leased_at IS DISTINCT FROM OLD.leased_at
                    OR NEW.heartbeat_at < OLD.heartbeat_at
                    OR NEW.lease_expires_at < OLD.lease_expires_at
                ) THEN
                    RAISE EXCEPTION 'running stage lease updates must be monotonic and retain their fence'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_run_lease_transition';
                END IF;
            ELSE
                IF NEW.attempt_count IS DISTINCT FROM OLD.attempt_count
                   OR NEW.first_started_at IS DISTINCT FROM OLD.first_started_at
                   OR NEW.checkpoint_version IS DISTINCT FROM OLD.checkpoint_version
                   OR NEW.checkpoint IS DISTINCT FROM OLD.checkpoint
                   OR NEW.checkpoint_checksum IS DISTINCT FROM OLD.checkpoint_checksum THEN
                    RAISE EXCEPTION 'non-running stage transitions cannot rewrite attempt evidence'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_run_attempt_transition';
                END IF;
            END IF;

            IF NEW.status = 'retry_wait' AND NEW.attempt_count >= NEW.max_attempts THEN
                RAISE EXCEPTION 'an exhausted retryable stage must be dead-lettered'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_run_retry_transition';
            END IF;
            IF NEW.status = 'dead_lettered' AND NEW.attempt_count <> NEW.max_attempts THEN
                RAISE EXCEPTION 'dead-lettered stages must exhaust their attempt budget'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_run_retry_transition';
            END IF;
            RETURN NEW;
        END;
        $$
    """)
    op.execute("""
        CREATE TRIGGER trg_stage_run_authority_guard
        BEFORE INSERT OR UPDATE OR DELETE ON stage_runs
        FOR EACH ROW EXECUTE FUNCTION ag_guard_stage_run_authority()
    """)

    op.execute("""
        CREATE FUNCTION ag_guard_stage_attempt_authority()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        DECLARE
            parent_status text;
            parent_attempt_count integer;
            parent_lease_token uuid;
            parent_lease_owner text;
            parent_input_checksum text;
            parent_checkpoint_version integer;
            parent_leased_at timestamptz;
            parent_heartbeat_at timestamptz;
            parent_lease_expires_at timestamptz;
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'stage attempt evidence cannot be deleted'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_attempt_no_delete';
            END IF;

            SELECT stage.status,
                   stage.attempt_count,
                   stage.lease_token,
                   stage.lease_owner,
                   stage.input_checksum,
                   stage.checkpoint_version,
                   stage.leased_at,
                   stage.heartbeat_at,
                   stage.lease_expires_at
            INTO parent_status,
                 parent_attempt_count,
                 parent_lease_token,
                 parent_lease_owner,
                 parent_input_checksum,
                 parent_checkpoint_version,
                 parent_leased_at,
                 parent_heartbeat_at,
                 parent_lease_expires_at
            FROM stage_runs AS stage
            WHERE stage.id = NEW.stage_run_id
            FOR UPDATE;
            IF NOT FOUND OR parent_status <> 'running' THEN
                RAISE EXCEPTION 'attempt evidence requires a currently running parent stage'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_attempt_parent_fence';
            END IF;

            IF TG_OP = 'INSERT' THEN
                IF NEW.status <> 'running' OR NEW.state_version <> 1
                   OR NEW.attempt_number <> parent_attempt_count
                   OR NEW.lease_token IS DISTINCT FROM parent_lease_token
                   OR NEW.lease_owner IS DISTINCT FROM parent_lease_owner
                   OR NEW.input_checksum IS DISTINCT FROM parent_input_checksum
                   OR NEW.checkpoint_start_version <> parent_checkpoint_version
                   OR NEW.checkpoint_end_version <> parent_checkpoint_version
                   OR NEW.started_at IS DISTINCT FROM parent_leased_at
                   OR NEW.heartbeat_at IS DISTINCT FROM parent_heartbeat_at
                   OR NEW.lease_expires_at IS DISTINCT FROM parent_lease_expires_at THEN
                    RAISE EXCEPTION 'attempt start evidence must exactly match the parent stage fence'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_attempt_parent_fence';
                END IF;
                RETURN NEW;
            END IF;

            IF OLD.id IS DISTINCT FROM NEW.id
               OR OLD.stage_run_id IS DISTINCT FROM NEW.stage_run_id
               OR OLD.attempt_number IS DISTINCT FROM NEW.attempt_number
               OR OLD.lease_token IS DISTINCT FROM NEW.lease_token
               OR OLD.lease_owner IS DISTINCT FROM NEW.lease_owner
               OR OLD.delivery_id IS DISTINCT FROM NEW.delivery_id
               OR OLD.input_checksum IS DISTINCT FROM NEW.input_checksum
               OR OLD.checkpoint_start_version IS DISTINCT FROM NEW.checkpoint_start_version
               OR OLD.started_at IS DISTINCT FROM NEW.started_at
               OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
                RAISE EXCEPTION 'immutable stage attempt evidence cannot be changed'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_attempt_immutable';
            END IF;
            IF OLD.status <> 'running'
               OR NEW.status NOT IN (
                   'running', 'succeeded', 'degraded', 'failed', 'cancelled', 'abandoned'
               )
               OR NEW.state_version <> OLD.state_version + 1 THEN
                RAISE EXCEPTION 'illegal stage attempt transition'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_attempt_transition';
            END IF;
            IF NEW.attempt_number <> parent_attempt_count
               OR NEW.lease_token IS DISTINCT FROM parent_lease_token
               OR NEW.lease_owner IS DISTINCT FROM parent_lease_owner
               OR NEW.input_checksum IS DISTINCT FROM parent_input_checksum THEN
                RAISE EXCEPTION 'stage attempt update failed its parent lease fence'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_attempt_parent_fence';
            END IF;
            IF NEW.heartbeat_at < OLD.heartbeat_at
               OR NEW.lease_expires_at < OLD.lease_expires_at
               OR NEW.checkpoint_end_version < OLD.checkpoint_end_version THEN
                RAISE EXCEPTION 'attempt heartbeat, lease, and checkpoint progress must be monotonic'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_attempt_progress';
            END IF;
            RETURN NEW;
        END;
        $$
    """)
    op.execute("""
        CREATE TRIGGER trg_stage_attempt_authority_guard
        BEFORE INSERT OR UPDATE OR DELETE ON stage_attempts
        FOR EACH ROW EXECUTE FUNCTION ag_guard_stage_attempt_authority()
    """)
    op.execute("""
        CREATE FUNCTION ag_check_stage_authority_consistency()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        DECLARE
            target_stage_id uuid;
            stage_status text;
            stage_attempt_count integer;
            stage_lease_token uuid;
            stage_lease_owner text;
            stage_input_checksum text;
            stage_heartbeat_at timestamptz;
            stage_lease_expires_at timestamptz;
            stage_checkpoint_version integer;
            running_attempt_count integer;
            running_attempt_number integer;
            running_lease_token uuid;
            running_lease_owner text;
            running_input_checksum text;
            running_heartbeat_at timestamptz;
            running_lease_expires_at timestamptz;
            running_checkpoint_end_version integer;
        BEGIN
            IF TG_TABLE_NAME = 'stage_runs' THEN
                target_stage_id := COALESCE(NEW.id, OLD.id);
            ELSE
                target_stage_id := COALESCE(NEW.stage_run_id, OLD.stage_run_id);
            END IF;

            SELECT stage.status,
                   stage.attempt_count,
                   stage.lease_token,
                   stage.lease_owner,
                   stage.input_checksum,
                   stage.heartbeat_at,
                   stage.lease_expires_at,
                   stage.checkpoint_version
            INTO stage_status,
                 stage_attempt_count,
                 stage_lease_token,
                 stage_lease_owner,
                 stage_input_checksum,
                 stage_heartbeat_at,
                 stage_lease_expires_at,
                 stage_checkpoint_version
            FROM stage_runs AS stage
            WHERE stage.id = target_stage_id;
            IF NOT FOUND THEN
                RETURN NULL;
            END IF;

            SELECT count(*)
            INTO running_attempt_count
            FROM stage_attempts AS attempt
            WHERE attempt.stage_run_id = target_stage_id
              AND attempt.status = 'running';

            IF stage_status <> 'running' THEN
                IF running_attempt_count <> 0 THEN
                    RAISE EXCEPTION 'a non-running stage cannot retain running attempt evidence'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_authority_consistency';
                END IF;
                RETURN NULL;
            END IF;

            IF running_attempt_count <> 1 THEN
                RAISE EXCEPTION 'a running stage requires exactly one running attempt'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_authority_consistency';
            END IF;
            SELECT attempt.attempt_number,
                   attempt.lease_token,
                   attempt.lease_owner,
                   attempt.input_checksum,
                   attempt.heartbeat_at,
                   attempt.lease_expires_at,
                   attempt.checkpoint_end_version
            INTO running_attempt_number,
                 running_lease_token,
                 running_lease_owner,
                 running_input_checksum,
                 running_heartbeat_at,
                 running_lease_expires_at,
                 running_checkpoint_end_version
            FROM stage_attempts AS attempt
            WHERE attempt.stage_run_id = target_stage_id
              AND attempt.status = 'running';
            IF running_attempt_number IS DISTINCT FROM stage_attempt_count
               OR running_lease_token IS DISTINCT FROM stage_lease_token
               OR running_lease_owner IS DISTINCT FROM stage_lease_owner
               OR running_input_checksum IS DISTINCT FROM stage_input_checksum
               OR running_heartbeat_at IS DISTINCT FROM stage_heartbeat_at
               OR running_lease_expires_at IS DISTINCT FROM stage_lease_expires_at
               OR running_checkpoint_end_version IS DISTINCT FROM stage_checkpoint_version THEN
                RAISE EXCEPTION 'running stage and attempt fence evidence do not match'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_authority_consistency';
            END IF;
            RETURN NULL;
        END;
        $$
    """)
    op.execute("""
        CREATE CONSTRAINT TRIGGER trg_stage_authority_consistency_from_stage
        AFTER INSERT OR UPDATE OR DELETE ON stage_runs
        DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW EXECUTE FUNCTION ag_check_stage_authority_consistency()
    """)
    op.execute("""
        CREATE CONSTRAINT TRIGGER trg_stage_authority_consistency_from_attempt
        AFTER INSERT OR UPDATE OR DELETE ON stage_attempts
        DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW EXECUTE FUNCTION ag_check_stage_authority_consistency()
    """)


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS trg_stage_authority_consistency_from_attempt ON stage_attempts"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS trg_stage_authority_consistency_from_stage ON stage_runs"
    )
    op.execute("DROP FUNCTION IF EXISTS ag_check_stage_authority_consistency()")
    op.execute("DROP TRIGGER IF EXISTS trg_stage_attempt_authority_guard ON stage_attempts")
    op.execute("DROP FUNCTION IF EXISTS ag_guard_stage_attempt_authority()")
    op.execute("DROP TRIGGER IF EXISTS trg_stage_run_authority_guard ON stage_runs")
    op.execute("DROP FUNCTION IF EXISTS ag_guard_stage_run_authority()")
    op.execute("DROP TRIGGER IF EXISTS trg_workflow_run_authority_guard ON workflow_runs")
    op.execute("DROP FUNCTION IF EXISTS ag_guard_workflow_run_authority()")
    op.execute("DROP TRIGGER IF EXISTS trg_project_revision_authority_guard ON project_revisions")
    op.execute("DROP FUNCTION IF EXISTS ag_guard_project_revision_authority()")
    op.execute("DROP TRIGGER IF EXISTS trg_research_project_authority_guard ON research_projects")
    op.execute("DROP FUNCTION IF EXISTS ag_guard_research_project_authority()")
    op.drop_table("stage_attempts")
    op.drop_table("stage_runs")
    op.drop_table("workflow_runs")
