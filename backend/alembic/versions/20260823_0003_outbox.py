"""Add the durable workflow-stage outbox expansion.

Revision ID: 20260823_0003
Revises: 20260823_0002

This is deliberately the expand/backfill half of an expand-contract rollout.
It makes the outbox itself authoritative, but does not yet require every
StageRun transition to dual-write an outbox message or every StageAttempt to
carry receipt evidence.  Those cross-domain requirements can only be enabled
after the runtime writes both sides atomically.
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "20260823_0003"
down_revision: str | None = "20260823_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_MAX_DELIVERY_CYCLE = 9_007_199_254_740_991


def _create_key_functions() -> None:
    op.execute(r"""
        CREATE FUNCTION ag_outbox_stage_ready_envelope(
            workflow_id uuid,
            stage_id uuid,
            stage_identity text,
            target_attempt integer,
            stage_input_checksum text,
            workflow_plan_checksum text
        )
        RETURNS text
        LANGUAGE sql
        IMMUTABLE
        STRICT
        PARALLEL SAFE
        SET search_path = pg_catalog
        AS $function$
            SELECT '{"payload":{"input_checksum":"'
                   || stage_input_checksum
                   || '","plan_checksum":"'
                   || workflow_plan_checksum
                   || '","stage_key":"'
                   || stage_identity
                   || '","stage_run_id":"'
                   || stage_id::text
                   || '","target_attempt_number":'
                   || target_attempt::text
                   || ',"workflow_run_id":"'
                   || workflow_id::text
                   || '"},"schema_version":"workflow-stage-ready-v1",'
                   || '"topic":"workflow.stage.ready"}'
        $function$
    """)
    op.execute(r"""
        CREATE FUNCTION ag_outbox_stage_ready_logical_key(
            workflow_id uuid,
            stage_id uuid,
            stage_identity text,
            target_attempt integer
        )
        RETURNS text
        LANGUAGE sql
        IMMUTABLE
        STRICT
        PARALLEL SAFE
        SET search_path = pg_catalog
        AS $function$
            SELECT encode(
                sha256(
                    convert_to('AdversaryGraph/outbox/logical-key/v1', 'UTF8')
                    || decode('00', 'hex')
                    || convert_to(
                        '{"schema_version":"workflow-stage-ready-v1",'
                        || '"stage_key":"'
                        || stage_identity
                        || '","stage_run_id":"'
                        || stage_id::text
                        || '","target_attempt_number":'
                        || target_attempt::text
                        || ',"topic":"workflow.stage.ready",'
                        || '"workflow_run_id":"'
                        || workflow_id::text
                        || '"}',
                        'UTF8'
                    )
                ),
                'hex'
            )
        $function$
    """)
    op.execute(r"""
        CREATE FUNCTION ag_outbox_delivery_cycle_key(
            message_logical_key text,
            target_cycle bigint
        )
        RETURNS text
        LANGUAGE sql
        IMMUTABLE
        STRICT
        PARALLEL SAFE
        SET search_path = pg_catalog
        AS $function$
            SELECT encode(
                sha256(
                    convert_to('AdversaryGraph/outbox/delivery-cycle/v1', 'UTF8')
                    || decode('00', 'hex')
                    || convert_to(message_logical_key, 'UTF8')
                    || decode('00', 'hex')
                    || convert_to(target_cycle::text, 'UTF8')
                ),
                'hex'
            )
        $function$
    """)
    op.execute(r"""
        CREATE FUNCTION ag_outbox_retry_delay_seconds(
            message_logical_key text,
            delivery_attempt integer
        )
        RETURNS integer
        LANGUAGE plpgsql
        IMMUTABLE
        STRICT
        PARALLEL SAFE
        SET search_path = pg_catalog
        AS $function$
        DECLARE
            exponential_delay integer;
            jitter_span integer;
            lower_bound integer;
            upper_bound integer;
            digest_bytes bytea;
            selection numeric := 0;
            byte_index integer;
        BEGIN
            IF message_logical_key !~ '^[0-9a-f]{64}$' THEN
                RAISE EXCEPTION 'logical key must be an exact lowercase SHA-256 value'
                    USING ERRCODE = '22023';
            END IF;
            IF delivery_attempt < 1 OR delivery_attempt > 32 THEN
                RAISE EXCEPTION 'delivery attempt must be between 1 and 32'
                    USING ERRCODE = '22023';
            END IF;

            exponential_delay := LEAST(
                900::bigint,
                5::bigint << (delivery_attempt - 1)
            )::integer;
            jitter_span := (exponential_delay * 20) / 100;
            lower_bound := GREATEST(1, exponential_delay - jitter_span);
            upper_bound := LEAST(900, exponential_delay + jitter_span);
            IF upper_bound <= lower_bound THEN
                RETURN lower_bound;
            END IF;

            digest_bytes := sha256(
                convert_to(
                    'AdversaryGraph/outbox/delivery-retry-jitter/v1',
                    'UTF8'
                )
                || decode('00', 'hex')
                || convert_to(delivery_attempt::text, 'UTF8')
                || decode('00', 'hex')
                || convert_to(message_logical_key, 'UTF8')
            );
            FOR byte_index IN 0..7 LOOP
                selection := selection * 256 + get_byte(digest_bytes, byte_index);
            END LOOP;
            RETURN lower_bound + mod(
                selection,
                (upper_bound - lower_bound + 1)::numeric
            )::integer;
        END;
        $function$
    """)


def _create_tables() -> None:
    op.create_unique_constraint(
        "uq_stage_run_workflow_id",
        "stage_runs",
        ["workflow_run_id", "id"],
    )
    op.create_table(
        "outbox_messages",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workflow_run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("stage_run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("aggregate_type", sa.String(length=40), nullable=False),
        sa.Column("aggregate_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("aggregate_version", sa.Integer(), nullable=False),
        sa.Column("emission_kind", sa.String(length=32), nullable=False),
        sa.Column("topic", sa.String(length=80), nullable=False),
        sa.Column("schema_version", sa.String(length=80), nullable=False),
        sa.Column("correlation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("causation_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("stage_key", sa.String(length=80), nullable=False),
        sa.Column("target_attempt_number", sa.Integer(), nullable=False),
        sa.Column("input_checksum", sa.String(length=64), nullable=False),
        sa.Column("plan_checksum", sa.String(length=64), nullable=False),
        sa.Column("envelope_canonical", sa.Text(), nullable=False),
        sa.Column("envelope_checksum", sa.String(length=64), nullable=False),
        sa.Column("envelope_bytes", sa.Integer(), nullable=False),
        sa.Column("logical_key", sa.String(length=64), nullable=False),
        sa.Column("redrive_of_message_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("redrive_ordinal", sa.Integer(), nullable=False),
        sa.Column("redrive_requested_by", sa.String(length=255), nullable=False),
        sa.Column("redrive_requested_by_id", sa.String(length=80), nullable=False),
        sa.Column("redrive_reason", sa.String(length=500), nullable=False),
        sa.Column("redrive_requested_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("state_version", sa.Integer(), nullable=False),
        sa.Column("attempt_count", sa.Integer(), nullable=False),
        sa.Column("max_attempts", sa.Integer(), nullable=False),
        sa.Column("delivery_cycle", sa.BigInteger(), nullable=False),
        sa.Column("cycle_key", sa.String(length=64), nullable=True),
        sa.Column("available_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("active_delivery_attempt_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("lease_owner", sa.String(length=255), nullable=False),
        sa.Column("lease_token", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("leased_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("receipt_deadline_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_code", sa.String(length=80), nullable=False),
        sa.Column("last_error_class", sa.String(length=120), nullable=False),
        sa.Column("last_error_summary", sa.String(length=500), nullable=False),
        sa.Column("last_error_retryable", sa.Boolean(), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("dead_lettered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancelled_by", sa.String(length=255), nullable=False),
        sa.Column("cancelled_by_id", sa.String(length=80), nullable=False),
        sa.Column("cancel_reason", sa.String(length=500), nullable=False),
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
            "status IN ('pending', 'dispatching', 'awaiting_receipt', 'retry_wait', 'delivered', 'dead_lettered', 'cancelled')",
            name="ck_outbox_message_status",
        ),
        sa.CheckConstraint(
            "aggregate_type = 'workflow_stage' AND aggregate_id = stage_run_id "
            "AND topic = 'workflow.stage.ready' "
            "AND schema_version = 'workflow-stage-ready-v1' "
            "AND stage_key ~ '^[a-z][a-z0-9_.-]{0,79}$'",
            name="ck_outbox_message_registry_identity",
        ),
        sa.CheckConstraint(
            "emission_kind IN ('migration_backfill', 'root_ready', "
            "'dependency_ready', 'retry_scheduled', 'lease_recovered', "
            "'manual_redrive')",
            name="ck_outbox_message_emission_kind",
        ),
        sa.CheckConstraint(
            "aggregate_version >= 1 AND state_version >= 1",
            name="ck_outbox_message_versions",
        ),
        sa.CheckConstraint(
            "target_attempt_number BETWEEN 1 AND 20",
            name="ck_outbox_message_target_attempt",
        ),
        sa.CheckConstraint(
            "input_checksum ~ '^[0-9a-f]{64}$' "
            "AND plan_checksum ~ '^[0-9a-f]{64}$' "
            "AND envelope_checksum ~ '^[0-9a-f]{64}$' "
            "AND logical_key ~ '^[0-9a-f]{64}$'",
            name="ck_outbox_message_checksums",
        ),
        sa.CheckConstraint(
            "envelope_bytes BETWEEN 1 AND 49152 "
            "AND envelope_bytes = octet_length(convert_to(envelope_canonical, 'UTF8')) "
            "AND envelope_checksum = encode(sha256(convert_to(envelope_canonical, 'UTF8')), 'hex') "
            "AND envelope_canonical = ag_outbox_stage_ready_envelope("
            "workflow_run_id, stage_run_id, stage_key, target_attempt_number, "
            "input_checksum, plan_checksum)",
            name="ck_outbox_message_envelope_authority",
        ),
        sa.CheckConstraint(
            "logical_key = ag_outbox_stage_ready_logical_key(workflow_run_id, stage_run_id, stage_key, target_attempt_number)",
            name="ck_outbox_message_logical_authority",
        ),
        sa.CheckConstraint(
            f"attempt_count BETWEEN 0 AND max_attempts "
            f"AND max_attempts = 8 "
            f"AND delivery_cycle BETWEEN 0 AND {_MAX_DELIVERY_CYCLE} "
            "AND delivery_cycle >= attempt_count",
            name="ck_outbox_message_delivery_counts",
        ),
        sa.CheckConstraint(
            "(delivery_cycle = 0 AND cycle_key IS NULL) OR "
            "(delivery_cycle > 0 AND cycle_key ~ '^[0-9a-f]{64}$' "
            "AND cycle_key = ag_outbox_delivery_cycle_key(logical_key, delivery_cycle))",
            name="ck_outbox_message_cycle_authority",
        ),
        sa.CheckConstraint(
            "(status IN ('pending', 'retry_wait') AND available_at IS NOT NULL) OR "
            "(status NOT IN ('pending', 'retry_wait') AND available_at IS NULL)",
            name="ck_outbox_message_schedule_facts",
        ),
        sa.CheckConstraint(
            "(status IN ('dispatching', 'awaiting_receipt') "
            "AND active_delivery_attempt_id IS NOT NULL) OR "
            "(status NOT IN ('dispatching', 'awaiting_receipt') "
            "AND active_delivery_attempt_id IS NULL)",
            name="ck_outbox_message_active_facts",
        ),
        sa.CheckConstraint(
            "(status = 'dispatching' AND lease_owner <> '' AND lease_token IS NOT NULL "
            "AND leased_at IS NOT NULL AND lease_expires_at IS NOT NULL "
            "AND heartbeat_at IS NOT NULL) OR "
            "(status <> 'dispatching' AND lease_owner = '' AND lease_token IS NULL "
            "AND leased_at IS NULL AND lease_expires_at IS NULL AND heartbeat_at IS NULL)",
            name="ck_outbox_message_lease_facts",
        ),
        sa.CheckConstraint(
            "status <> 'dispatching' OR (lease_expires_at > leased_at AND heartbeat_at >= leased_at AND heartbeat_at <= lease_expires_at)",
            name="ck_outbox_message_lease_order",
        ),
        sa.CheckConstraint(
            "(status = 'awaiting_receipt' AND receipt_deadline_at IS NOT NULL) OR "
            "(status <> 'awaiting_receipt' AND receipt_deadline_at IS NULL)",
            name="ck_outbox_message_receipt_facts",
        ),
        sa.CheckConstraint(
            "(last_error_code = '' AND last_error_class = '' "
            "AND last_error_summary = '' AND NOT last_error_retryable) OR "
            "(last_error_code ~ '^[a-z][a-z0-9_.-]{0,79}$' "
            "AND last_error_class ~ '^[A-Za-z][A-Za-z0-9_.-]{0,119}$' "
            "AND last_error_summary <> '')",
            name="ck_outbox_message_error_facts",
        ),
        sa.CheckConstraint(
            "status NOT IN ('retry_wait', 'dead_lettered') OR last_error_code <> ''",
            name="ck_outbox_message_error_required",
        ),
        sa.CheckConstraint(
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
        sa.CheckConstraint(
            "(status = 'cancelled' AND cancelled_by <> '' "
            "AND cancelled_by_id <> '' AND cancel_reason <> '') OR "
            "(status <> 'cancelled' AND cancelled_by = '' "
            "AND cancelled_by_id = '' AND cancel_reason = '')",
            name="ck_outbox_message_cancellation_facts",
        ),
        sa.CheckConstraint(
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
        sa.CheckConstraint(
            "redrive_of_message_id IS NULL OR redrive_of_message_id <> id",
            name="ck_outbox_message_parent_not_self",
        ),
        sa.CheckConstraint(
            "updated_at >= created_at "
            "AND (redrive_requested_at IS NULL OR redrive_requested_at >= created_at) "
            "AND (delivered_at IS NULL OR delivered_at >= created_at) "
            "AND (dead_lettered_at IS NULL OR dead_lettered_at >= created_at) "
            "AND (cancelled_at IS NULL OR cancelled_at >= created_at)",
            name="ck_outbox_message_timestamp_order",
        ),
        sa.ForeignKeyConstraint(
            ["workflow_run_id"],
            ["workflow_runs.id"],
            name="fk_outbox_message_workflow",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["workflow_run_id", "stage_run_id"],
            ["stage_runs.workflow_run_id", "stage_runs.id"],
            name="fk_outbox_message_stage_workflow",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["redrive_of_message_id"],
            ["outbox_messages.id"],
            name="fk_outbox_message_redrive_parent",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "logical_key",
            "redrive_ordinal",
            name="uq_outbox_message_logical_redrive",
        ),
        sa.UniqueConstraint(
            "redrive_of_message_id",
            name="uq_outbox_message_redrive_parent",
        ),
    )
    op.create_table(
        "outbox_delivery_attempts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("message_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("delivery_cycle", sa.BigInteger(), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("cycle_key", sa.String(length=64), nullable=False),
        sa.Column("delivery_token", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("publisher_id", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("state_version", sa.Integer(), nullable=False),
        sa.Column("leased_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("broker_name", sa.String(length=80), nullable=False),
        sa.Column("broker_message_id", sa.String(length=255), nullable=False),
        sa.Column("broker_receipt_id", sa.String(length=255), nullable=False),
        sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("receipt_deadline_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("receipt_received_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_code", sa.String(length=80), nullable=False),
        sa.Column("error_class", sa.String(length=120), nullable=False),
        sa.Column("error_summary", sa.String(length=500), nullable=False),
        sa.Column("retryable", sa.Boolean(), nullable=False),
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
            "status IN ('dispatching', 'awaiting_receipt', 'delivered', 'failed', 'abandoned', 'cancelled')",
            name="ck_outbox_delivery_status",
        ),
        sa.CheckConstraint(
            f"attempt_number BETWEEN 1 AND 32 AND delivery_cycle BETWEEN 1 AND {_MAX_DELIVERY_CYCLE}",
            name="ck_outbox_delivery_numbers",
        ),
        sa.CheckConstraint(
            "state_version >= 1",
            name="ck_outbox_delivery_state_version",
        ),
        sa.CheckConstraint(
            "cycle_key ~ '^[0-9a-f]{64}$'",
            name="ck_outbox_delivery_cycle_key",
        ),
        sa.CheckConstraint(
            "publisher_id <> '' AND lease_expires_at > leased_at AND heartbeat_at >= leased_at",
            name="ck_outbox_delivery_lease_facts",
        ),
        sa.CheckConstraint(
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
        sa.CheckConstraint(
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
        sa.CheckConstraint(
            "(status IN ('dispatching', 'awaiting_receipt', 'delivered') "
            "AND error_code = '' AND error_class = '' AND error_summary = '' "
            "AND NOT retryable) OR "
            "(status IN ('failed', 'abandoned', 'cancelled') "
            "AND error_code ~ '^[a-z][a-z0-9_.-]{0,79}$' "
            "AND error_class ~ '^[A-Za-z][A-Za-z0-9_.-]{0,119}$' "
            "AND error_summary <> '')",
            name="ck_outbox_delivery_error_facts",
        ),
        sa.CheckConstraint(
            "(status = 'abandoned' AND retryable) OR (status = 'cancelled' AND NOT retryable) OR status NOT IN ('abandoned', 'cancelled')",
            name="ck_outbox_delivery_retryable_facts",
        ),
        sa.CheckConstraint(
            "heartbeat_at <= lease_expires_at "
            "AND (dispatched_at IS NULL OR dispatched_at >= leased_at) "
            "AND (receipt_deadline_at IS NULL OR receipt_deadline_at > dispatched_at) "
            "AND (receipt_received_at IS NULL OR receipt_received_at >= dispatched_at) "
            "AND (completed_at IS NULL OR completed_at >= leased_at) "
            "AND updated_at >= created_at",
            name="ck_outbox_delivery_timestamp_order",
        ),
        sa.ForeignKeyConstraint(
            ["message_id"],
            ["outbox_messages.id"],
            name="fk_outbox_delivery_message",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("message_id", "id", name="uq_outbox_delivery_message_id"),
        sa.UniqueConstraint("message_id", "delivery_cycle", name="uq_outbox_delivery_message_cycle"),
        sa.UniqueConstraint("message_id", "attempt_number", name="uq_outbox_delivery_message_attempt"),
        sa.UniqueConstraint("delivery_token", name="uq_outbox_delivery_token"),
        sa.UniqueConstraint("cycle_key", name="uq_outbox_delivery_cycle_key"),
    )
    op.create_foreign_key(
        "fk_outbox_message_active_delivery",
        "outbox_messages",
        "outbox_delivery_attempts",
        ["id", "active_delivery_attempt_id"],
        ["message_id", "id"],
        ondelete="RESTRICT",
        deferrable=True,
        initially="DEFERRED",
    )
    op.add_column(
        "stage_attempts",
        sa.Column(
            "outbox_delivery_attempt_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
    )
    op.create_unique_constraint(
        "uq_stage_attempt_outbox_delivery",
        "stage_attempts",
        ["outbox_delivery_attempt_id"],
    )
    op.create_foreign_key(
        "fk_stage_attempt_outbox_delivery",
        "stage_attempts",
        "outbox_delivery_attempts",
        ["outbox_delivery_attempt_id"],
        ["id"],
        ondelete="RESTRICT",
    )


def _create_indexes() -> None:
    op.create_index(
        "uq_outbox_message_active_logical",
        "outbox_messages",
        ["logical_key"],
        unique=True,
        postgresql_where=sa.text("status IN ('pending', 'dispatching', 'awaiting_receipt', 'retry_wait')"),
    )
    op.create_index(
        "ix_outbox_messages_claim",
        "outbox_messages",
        ["available_at", "created_at", "id"],
        postgresql_where=sa.text("status IN ('pending', 'retry_wait')"),
    )
    op.create_index(
        "ix_outbox_messages_dispatch_lease",
        "outbox_messages",
        ["lease_expires_at", "id"],
        postgresql_where=sa.text("status = 'dispatching'"),
    )
    op.create_index(
        "ix_outbox_messages_receipt_deadline",
        "outbox_messages",
        ["receipt_deadline_at", "id"],
        postgresql_where=sa.text("status = 'awaiting_receipt'"),
    )
    op.create_index(
        "ix_outbox_messages_stage_target",
        "outbox_messages",
        ["stage_run_id", "target_attempt_number", "redrive_ordinal"],
    )
    op.create_index(
        "ix_outbox_messages_stage_active",
        "outbox_messages",
        ["stage_run_id", "target_attempt_number", "id"],
        postgresql_where=sa.text("status IN ('pending', 'dispatching', 'awaiting_receipt', 'retry_wait')"),
    )
    op.create_index(
        "ix_outbox_messages_workflow_status_created",
        "outbox_messages",
        ["workflow_run_id", "status", "created_at"],
    )
    op.create_index(
        "uq_outbox_delivery_active_message",
        "outbox_delivery_attempts",
        ["message_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('dispatching', 'awaiting_receipt')"),
    )
    op.create_index(
        "ix_outbox_delivery_message_status_attempt",
        "outbox_delivery_attempts",
        ["message_id", "status", "attempt_number"],
    )
    op.create_index(
        "ix_outbox_delivery_dispatch_lease",
        "outbox_delivery_attempts",
        ["lease_expires_at", "id"],
        postgresql_where=sa.text("status = 'dispatching'"),
    )
    op.create_index(
        "ix_outbox_delivery_receipt_deadline",
        "outbox_delivery_attempts",
        ["receipt_deadline_at", "id"],
        postgresql_where=sa.text("status = 'awaiting_receipt'"),
    )


def _backfill_ready_stages() -> None:
    op.execute(r"""
        DO $block$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM stage_runs AS stage
                JOIN workflow_runs AS workflow
                  ON workflow.id = stage.workflow_run_id
                WHERE stage.status IN ('ready', 'retry_wait')
                  AND workflow.status NOT IN ('queued', 'running')
            ) THEN
                RAISE EXCEPTION 'cannot backfill runnable stages under inactive workflows'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_backfill_workflow';
            END IF;
        END;
        $block$
    """)
    op.execute(r"""
        WITH candidates AS (
            SELECT stage.id AS stage_run_id,
                   stage.workflow_run_id,
                   stage.stage_key,
                   stage.attempt_count + 1 AS target_attempt_number,
                   stage.input_checksum,
                   stage.state_version AS aggregate_version,
                   stage.next_attempt_at AS available_at,
                   workflow.plan_checksum,
                   workflow.correlation_id
            FROM stage_runs AS stage
            JOIN workflow_runs AS workflow
              ON workflow.id = stage.workflow_run_id
            WHERE stage.status IN ('ready', 'retry_wait')
        ),
        normalized AS (
            SELECT candidates.*,
                   ag_outbox_stage_ready_envelope(
                       workflow_run_id,
                       stage_run_id,
                       stage_key,
                       target_attempt_number,
                       input_checksum,
                       plan_checksum
                   ) AS envelope_canonical,
                   ag_outbox_stage_ready_logical_key(
                       workflow_run_id,
                       stage_run_id,
                       stage_key,
                       target_attempt_number
                   ) AS logical_key
            FROM candidates
        )
        INSERT INTO outbox_messages (
            id, workflow_run_id, stage_run_id, aggregate_type, aggregate_id,
            aggregate_version, emission_kind, topic, schema_version,
            correlation_id, causation_id, stage_key, target_attempt_number,
            input_checksum, plan_checksum, envelope_canonical,
            envelope_checksum, envelope_bytes, logical_key,
            redrive_of_message_id, redrive_ordinal, redrive_requested_by,
            redrive_requested_by_id, redrive_reason, redrive_requested_at,
            status, state_version, attempt_count, max_attempts, delivery_cycle,
            cycle_key, available_at, active_delivery_attempt_id, lease_owner,
            lease_token, leased_at, lease_expires_at, heartbeat_at,
            receipt_deadline_at, last_error_code, last_error_class,
            last_error_summary, last_error_retryable, delivered_at,
            dead_lettered_at, cancelled_at, cancelled_by, cancelled_by_id,
            cancel_reason, created_at, updated_at
        )
        SELECT gen_random_uuid(), workflow_run_id, stage_run_id,
               'workflow_stage', stage_run_id, aggregate_version,
               'migration_backfill', 'workflow.stage.ready',
               'workflow-stage-ready-v1', correlation_id, NULL, stage_key,
               target_attempt_number, input_checksum, plan_checksum,
               envelope_canonical,
               encode(sha256(convert_to(envelope_canonical, 'UTF8')), 'hex'),
               octet_length(convert_to(envelope_canonical, 'UTF8')),
               logical_key, NULL, 0, '', '', '', NULL, 'pending', 1, 0, 8,
               0, NULL, available_at, NULL, '', NULL, NULL, NULL, NULL, NULL,
               '', '', '', FALSE, NULL, NULL, NULL, '', '', '',
               transaction_timestamp(), transaction_timestamp()
        FROM normalized
    """)


def upgrade() -> None:
    # DDL requires a coordinated maintenance window.  This lock also prevents
    # a stage from changing between the backfill snapshot and its insert.
    op.execute("LOCK TABLE workflow_runs, stage_runs, stage_attempts IN ACCESS EXCLUSIVE MODE")
    _create_key_functions()
    _create_tables()
    _create_indexes()
    _backfill_ready_stages()
    _create_authority_guards()


def downgrade() -> None:
    _preflight_downgrade()
    _drop_authority_guards()
    op.execute("DELETE FROM outbox_messages")
    op.drop_constraint("fk_stage_attempt_outbox_delivery", "stage_attempts", type_="foreignkey")
    op.drop_constraint("uq_stage_attempt_outbox_delivery", "stage_attempts", type_="unique")
    op.drop_column("stage_attempts", "outbox_delivery_attempt_id")
    op.drop_constraint("fk_outbox_message_active_delivery", "outbox_messages", type_="foreignkey")
    op.drop_table("outbox_delivery_attempts")
    op.drop_table("outbox_messages")
    op.drop_constraint("uq_stage_run_workflow_id", "stage_runs", type_="unique")
    op.execute("DROP FUNCTION ag_outbox_retry_delay_seconds(text, integer)")
    op.execute("DROP FUNCTION ag_outbox_delivery_cycle_key(text, bigint)")
    op.execute("DROP FUNCTION ag_outbox_stage_ready_logical_key(uuid, uuid, text, integer)")
    op.execute("DROP FUNCTION ag_outbox_stage_ready_envelope(uuid, uuid, text, integer, text, text)")


def _create_authority_guards() -> None:
    """Install immediate outbox authority and deferred pair consistency."""
    op.execute(r"""
        CREATE FUNCTION ag_guard_outbox_message_authority()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $function$
        DECLARE
            db_now timestamptz := transaction_timestamp();
            stage_status text;
            stage_state_version integer;
            stage_attempt_count integer;
            stage_input_checksum text;
            current_stage_key text;
            stage_available_at timestamptz;
            stage_dependency_count integer;
            stage_error_code text;
            workflow_status text;
            workflow_plan_checksum text;
            workflow_correlation_id uuid;
            parent_row outbox_messages%ROWTYPE;
            delivery_status text;
            delivery_retryable boolean;
            delivery_error_code text;
            delivery_error_class text;
            delivery_error_summary text;
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'outbox message authority records cannot be deleted'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_message_no_delete';
            END IF;

            IF TG_OP = 'INSERT' THEN
                IF NEW.emission_kind = 'migration_backfill' THEN
                    RAISE EXCEPTION 'migration backfill provenance cannot be emitted at runtime'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_message_backfill_origin';
                END IF;
                SELECT stage.status,
                       stage.state_version,
                       stage.attempt_count,
                       stage.input_checksum,
                       stage.stage_key,
                       stage.next_attempt_at,
                       jsonb_array_length(stage.depends_on),
                       stage.last_error_code,
                       workflow.status,
                       workflow.plan_checksum,
                       workflow.correlation_id
                INTO stage_status,
                     stage_state_version,
                     stage_attempt_count,
                     stage_input_checksum,
                     current_stage_key,
                     stage_available_at,
                     stage_dependency_count,
                     stage_error_code,
                     workflow_status,
                     workflow_plan_checksum,
                     workflow_correlation_id
                FROM stage_runs AS stage
                JOIN workflow_runs AS workflow
                  ON workflow.id = stage.workflow_run_id
                WHERE stage.id = NEW.stage_run_id
                  AND stage.workflow_run_id = NEW.workflow_run_id;
                IF NOT FOUND OR stage_status NOT IN ('ready', 'retry_wait')
                   OR workflow_status NOT IN ('queued', 'running')
                   OR NEW.aggregate_id IS DISTINCT FROM NEW.stage_run_id
                   OR NEW.aggregate_version IS DISTINCT FROM stage_state_version
                   OR NEW.stage_key IS DISTINCT FROM current_stage_key
                   OR NEW.target_attempt_number IS DISTINCT FROM stage_attempt_count + 1
                   OR NEW.input_checksum IS DISTINCT FROM stage_input_checksum
                   OR NEW.plan_checksum IS DISTINCT FROM workflow_plan_checksum
                   OR NEW.correlation_id IS DISTINCT FROM workflow_correlation_id THEN
                    RAISE EXCEPTION 'outbox message does not match a runnable stage authority snapshot'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_message_stage_authority';
                END IF;
                IF NEW.redrive_of_message_id IS NULL AND (
                   (stage_status = 'ready' AND stage_dependency_count = 0
                    AND NEW.emission_kind <> 'root_ready')
                   OR (stage_status = 'ready' AND stage_dependency_count > 0
                       AND NEW.emission_kind <> 'dependency_ready')
                   OR (stage_status = 'retry_wait'
                       AND stage_error_code = 'workflow.lease_expired'
                       AND NEW.emission_kind <> 'lease_recovered')
                   OR (stage_status = 'retry_wait'
                       AND stage_error_code <> 'workflow.lease_expired'
                       AND NEW.emission_kind <> 'retry_scheduled')) THEN
                    RAISE EXCEPTION 'outbox emission kind does not match its stage transition facts'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_message_emission_authority';
                END IF;
                IF NEW.status <> 'pending' OR NEW.state_version <> 1
                   OR NEW.attempt_count <> 0
                   OR NEW.active_delivery_attempt_id IS NOT NULL
                   OR NEW.lease_token IS NOT NULL
                   OR NEW.last_error_code <> '' OR NEW.last_error_class <> ''
                   OR NEW.last_error_summary <> '' OR NEW.last_error_retryable THEN
                    RAISE EXCEPTION 'outbox messages must start as an unclaimed pending record'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_message_initial_state';
                END IF;

                NEW.created_at := db_now;
                NEW.updated_at := db_now;
                IF NEW.redrive_of_message_id IS NULL THEN
                    IF NEW.redrive_ordinal <> 0
                       OR NEW.emission_kind = 'manual_redrive'
                       OR NEW.delivery_cycle <> 0
                       OR NEW.cycle_key IS NOT NULL THEN
                        RAISE EXCEPTION 'a root outbox message must start the delivery lineage'
                            USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_message_redrive_authority';
                    END IF;
                    NEW.available_at := stage_available_at;
                    NEW.redrive_requested_at := NULL;
                ELSE
                    SELECT *
                    INTO parent_row
                    FROM outbox_messages
                    WHERE id = NEW.redrive_of_message_id
                    FOR UPDATE;
                    IF NOT FOUND OR parent_row.status <> 'dead_lettered'
                       OR NEW.emission_kind <> 'manual_redrive'
                       OR NEW.redrive_ordinal <> parent_row.redrive_ordinal + 1
                       OR NEW.workflow_run_id IS DISTINCT FROM parent_row.workflow_run_id
                       OR NEW.stage_run_id IS DISTINCT FROM parent_row.stage_run_id
                       OR NEW.aggregate_type IS DISTINCT FROM parent_row.aggregate_type
                       OR NEW.aggregate_id IS DISTINCT FROM parent_row.aggregate_id
                       OR NEW.aggregate_version IS DISTINCT FROM parent_row.aggregate_version
                       OR NEW.topic IS DISTINCT FROM parent_row.topic
                       OR NEW.schema_version IS DISTINCT FROM parent_row.schema_version
                       OR NEW.correlation_id IS DISTINCT FROM parent_row.correlation_id
                       OR NEW.stage_key IS DISTINCT FROM parent_row.stage_key
                       OR NEW.target_attempt_number IS DISTINCT FROM parent_row.target_attempt_number
                       OR NEW.input_checksum IS DISTINCT FROM parent_row.input_checksum
                       OR NEW.plan_checksum IS DISTINCT FROM parent_row.plan_checksum
                       OR NEW.envelope_canonical IS DISTINCT FROM parent_row.envelope_canonical
                       OR NEW.envelope_checksum IS DISTINCT FROM parent_row.envelope_checksum
                       OR NEW.envelope_bytes IS DISTINCT FROM parent_row.envelope_bytes
                       OR NEW.logical_key IS DISTINCT FROM parent_row.logical_key
                       OR NEW.max_attempts IS DISTINCT FROM parent_row.max_attempts
                       OR NEW.delivery_cycle IS DISTINCT FROM parent_row.delivery_cycle
                       OR NEW.cycle_key IS DISTINCT FROM parent_row.cycle_key
                       OR NEW.redrive_requested_by = ''
                       OR NEW.redrive_requested_by_id = ''
                       OR NEW.redrive_reason = '' THEN
                        RAISE EXCEPTION 'manual redrive must extend one exact dead-letter lineage'
                            USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_message_redrive_authority';
                    END IF;
                    NEW.available_at := db_now;
                    NEW.redrive_requested_at := db_now;
                END IF;
                RETURN NEW;
            END IF;

            IF OLD.id IS DISTINCT FROM NEW.id
               OR OLD.workflow_run_id IS DISTINCT FROM NEW.workflow_run_id
               OR OLD.stage_run_id IS DISTINCT FROM NEW.stage_run_id
               OR OLD.aggregate_type IS DISTINCT FROM NEW.aggregate_type
               OR OLD.aggregate_id IS DISTINCT FROM NEW.aggregate_id
               OR OLD.aggregate_version IS DISTINCT FROM NEW.aggregate_version
               OR OLD.emission_kind IS DISTINCT FROM NEW.emission_kind
               OR OLD.topic IS DISTINCT FROM NEW.topic
               OR OLD.schema_version IS DISTINCT FROM NEW.schema_version
               OR OLD.correlation_id IS DISTINCT FROM NEW.correlation_id
               OR OLD.causation_id IS DISTINCT FROM NEW.causation_id
               OR OLD.stage_key IS DISTINCT FROM NEW.stage_key
               OR OLD.target_attempt_number IS DISTINCT FROM NEW.target_attempt_number
               OR OLD.input_checksum IS DISTINCT FROM NEW.input_checksum
               OR OLD.plan_checksum IS DISTINCT FROM NEW.plan_checksum
               OR OLD.envelope_canonical IS DISTINCT FROM NEW.envelope_canonical
               OR OLD.envelope_checksum IS DISTINCT FROM NEW.envelope_checksum
               OR OLD.envelope_bytes IS DISTINCT FROM NEW.envelope_bytes
               OR OLD.logical_key IS DISTINCT FROM NEW.logical_key
               OR OLD.redrive_of_message_id IS DISTINCT FROM NEW.redrive_of_message_id
               OR OLD.redrive_ordinal IS DISTINCT FROM NEW.redrive_ordinal
               OR OLD.redrive_requested_by IS DISTINCT FROM NEW.redrive_requested_by
               OR OLD.redrive_requested_by_id IS DISTINCT FROM NEW.redrive_requested_by_id
               OR OLD.redrive_reason IS DISTINCT FROM NEW.redrive_reason
               OR OLD.redrive_requested_at IS DISTINCT FROM NEW.redrive_requested_at
               OR OLD.max_attempts IS DISTINCT FROM NEW.max_attempts
               OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
                RAISE EXCEPTION 'immutable outbox message fields cannot be changed'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_message_immutable';
            END IF;
            IF OLD.status IN ('delivered', 'dead_lettered', 'cancelled')
               OR NEW.state_version <> OLD.state_version + 1 THEN
                RAISE EXCEPTION 'terminal outbox messages are immutable and versions advance exactly once'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_message_transition';
            END IF;
            NEW.updated_at := db_now;

            IF OLD.status IN ('pending', 'retry_wait') AND NEW.status = 'dispatching' THEN
                SELECT stage.status,
                       stage.state_version,
                       stage.attempt_count,
                       stage.input_checksum,
                       stage.stage_key,
                       workflow.status,
                       workflow.plan_checksum,
                       workflow.correlation_id
                INTO stage_status,
                     stage_state_version,
                     stage_attempt_count,
                     stage_input_checksum,
                     current_stage_key,
                     workflow_status,
                     workflow_plan_checksum,
                     workflow_correlation_id
                FROM stage_runs AS stage
                JOIN workflow_runs AS workflow
                  ON workflow.id = stage.workflow_run_id
                WHERE stage.id = OLD.stage_run_id
                  AND stage.workflow_run_id = OLD.workflow_run_id;
                IF NOT FOUND OR stage_status NOT IN ('ready', 'retry_wait')
                   OR workflow_status NOT IN ('queued', 'running')
                   OR stage_state_version IS DISTINCT FROM OLD.aggregate_version
                   OR stage_attempt_count + 1 IS DISTINCT FROM OLD.target_attempt_number
                   OR stage_input_checksum IS DISTINCT FROM OLD.input_checksum
                   OR current_stage_key IS DISTINCT FROM OLD.stage_key
                   OR workflow_plan_checksum IS DISTINCT FROM OLD.plan_checksum
                   OR workflow_correlation_id IS DISTINCT FROM OLD.correlation_id
                   OR OLD.available_at > db_now
                   OR NEW.attempt_count <> OLD.attempt_count + 1
                   OR NEW.delivery_cycle <> OLD.delivery_cycle + 1
                   OR NEW.active_delivery_attempt_id IS NULL
                   OR NEW.lease_owner = '' OR NEW.lease_token IS NULL
                   OR NEW.lease_expires_at IS NULL OR NEW.lease_expires_at <= db_now
                   OR NEW.last_error_code IS DISTINCT FROM OLD.last_error_code
                   OR NEW.last_error_class IS DISTINCT FROM OLD.last_error_class
                   OR NEW.last_error_summary IS DISTINCT FROM OLD.last_error_summary
                   OR NEW.last_error_retryable IS DISTINCT FROM OLD.last_error_retryable THEN
                    RAISE EXCEPTION 'outbox claim must fence one currently runnable message'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_message_claim_transition';
                END IF;
                NEW.available_at := NULL;
                NEW.leased_at := db_now;
                NEW.heartbeat_at := db_now;
                NEW.receipt_deadline_at := NULL;
                RETURN NEW;
            END IF;

            IF OLD.status = 'dispatching' AND NEW.status = 'dispatching' THEN
                IF NEW.attempt_count IS DISTINCT FROM OLD.attempt_count
                   OR NEW.delivery_cycle IS DISTINCT FROM OLD.delivery_cycle
                   OR NEW.cycle_key IS DISTINCT FROM OLD.cycle_key
                   OR NEW.active_delivery_attempt_id IS DISTINCT FROM OLD.active_delivery_attempt_id
                   OR NEW.lease_owner IS DISTINCT FROM OLD.lease_owner
                   OR NEW.lease_token IS DISTINCT FROM OLD.lease_token
                   OR NEW.leased_at IS DISTINCT FROM OLD.leased_at
                   OR NEW.lease_expires_at < OLD.lease_expires_at
                   OR NEW.lease_expires_at <= db_now
                   OR NEW.available_at IS DISTINCT FROM OLD.available_at
                   OR NEW.receipt_deadline_at IS DISTINCT FROM OLD.receipt_deadline_at
                   OR NEW.last_error_code IS DISTINCT FROM OLD.last_error_code
                   OR NEW.last_error_class IS DISTINCT FROM OLD.last_error_class
                   OR NEW.last_error_summary IS DISTINCT FROM OLD.last_error_summary
                   OR NEW.last_error_retryable IS DISTINCT FROM OLD.last_error_retryable THEN
                    RAISE EXCEPTION 'dispatch heartbeat must retain its fence and advance monotonically'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_message_lease_transition';
                END IF;
                NEW.heartbeat_at := db_now;
                RETURN NEW;
            END IF;

            IF OLD.status = 'dispatching' AND NEW.status = 'awaiting_receipt' THEN
                SELECT status
                INTO delivery_status
                FROM outbox_delivery_attempts
                WHERE id = OLD.active_delivery_attempt_id
                  AND message_id = OLD.id;
                IF NOT FOUND OR delivery_status <> 'awaiting_receipt'
                   OR NEW.attempt_count IS DISTINCT FROM OLD.attempt_count
                   OR NEW.delivery_cycle IS DISTINCT FROM OLD.delivery_cycle
                   OR NEW.cycle_key IS DISTINCT FROM OLD.cycle_key
                   OR NEW.active_delivery_attempt_id IS DISTINCT FROM OLD.active_delivery_attempt_id
                   OR NEW.receipt_deadline_at IS NULL
                   OR NEW.receipt_deadline_at <= db_now
                   OR NEW.last_error_code IS DISTINCT FROM OLD.last_error_code
                   OR NEW.last_error_class IS DISTINCT FROM OLD.last_error_class
                   OR NEW.last_error_summary IS DISTINCT FROM OLD.last_error_summary
                   OR NEW.last_error_retryable IS DISTINCT FROM OLD.last_error_retryable THEN
                    RAISE EXCEPTION 'broker acknowledgement must retain the active delivery evidence'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_message_delivery_transition';
                END IF;
                NEW.lease_owner := '';
                NEW.lease_token := NULL;
                NEW.leased_at := NULL;
                NEW.heartbeat_at := NULL;
                NEW.lease_expires_at := NULL;
                NEW.available_at := NULL;
                RETURN NEW;
            END IF;

            IF OLD.status IN ('dispatching', 'awaiting_receipt')
               AND NEW.status IN ('delivered', 'retry_wait', 'dead_lettered', 'cancelled') THEN
                SELECT status, retryable, error_code, error_class, error_summary
                INTO delivery_status, delivery_retryable, delivery_error_code,
                     delivery_error_class, delivery_error_summary
                FROM outbox_delivery_attempts
                WHERE id = OLD.active_delivery_attempt_id
                  AND message_id = OLD.id;
                IF NOT FOUND
                   OR NEW.attempt_count IS DISTINCT FROM OLD.attempt_count
                   OR NEW.delivery_cycle IS DISTINCT FROM OLD.delivery_cycle
                   OR NEW.cycle_key IS DISTINCT FROM OLD.cycle_key THEN
                    RAISE EXCEPTION 'outbox completion must retain its delivery identity'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_message_delivery_transition';
                END IF;
                IF NEW.status = 'delivered' AND delivery_status <> 'delivered' THEN
                    RAISE EXCEPTION 'delivered messages require delivered attempt evidence'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_message_delivery_transition';
                ELSIF NEW.status IN ('retry_wait', 'dead_lettered')
                      AND delivery_status NOT IN ('failed', 'abandoned') THEN
                    RAISE EXCEPTION 'delivery failure requires terminal failed attempt evidence'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_message_delivery_transition';
                ELSIF NEW.status = 'cancelled' AND delivery_status <> 'cancelled' THEN
                    RAISE EXCEPTION 'active delivery cancellation requires cancelled attempt evidence'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_message_delivery_transition';
                END IF;
                IF NEW.status IN ('delivered', 'cancelled') AND (
                    NEW.last_error_code IS DISTINCT FROM OLD.last_error_code
                    OR NEW.last_error_class IS DISTINCT FROM OLD.last_error_class
                    OR NEW.last_error_summary IS DISTINCT FROM OLD.last_error_summary
                    OR NEW.last_error_retryable IS DISTINCT FROM OLD.last_error_retryable
                ) THEN
                    RAISE EXCEPTION 'success and cancellation cannot rewrite prior delivery errors'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_message_delivery_transition';
                ELSIF NEW.status IN ('retry_wait', 'dead_lettered') AND (
                    NEW.last_error_code IS DISTINCT FROM delivery_error_code
                    OR NEW.last_error_class IS DISTINCT FROM delivery_error_class
                    OR NEW.last_error_summary IS DISTINCT FROM delivery_error_summary
                    OR NEW.last_error_retryable IS DISTINCT FROM delivery_retryable
                ) THEN
                    RAISE EXCEPTION 'message failure facts must match latest delivery evidence'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_message_retry_transition';
                END IF;
                IF NEW.status = 'retry_wait' THEN
                    NEW.available_at := db_now + make_interval(
                        secs => ag_outbox_retry_delay_seconds(
                            OLD.logical_key,
                            NEW.attempt_count
                        )
                    );
                END IF;
                IF NEW.status = 'retry_wait' AND (
                    NOT delivery_retryable OR NOT NEW.last_error_retryable
                    OR NEW.attempt_count >= NEW.max_attempts
                    OR NEW.available_at IS NULL OR NEW.available_at <= db_now
                ) THEN
                    RAISE EXCEPTION 'retryable deliveries must retain budget and a future DB-time schedule'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_message_retry_transition';
                ELSIF NEW.status = 'dead_lettered' AND (
                    (delivery_retryable AND NEW.attempt_count < NEW.max_attempts)
                    OR NEW.last_error_retryable IS DISTINCT FROM delivery_retryable
                ) THEN
                    RAISE EXCEPTION 'delivery may dead-letter only when exhausted or non-retryable'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_message_retry_transition';
                END IF;
                NEW.active_delivery_attempt_id := NULL;
                NEW.lease_owner := '';
                NEW.lease_token := NULL;
                NEW.leased_at := NULL;
                NEW.heartbeat_at := NULL;
                NEW.lease_expires_at := NULL;
                NEW.receipt_deadline_at := NULL;
                IF NEW.status = 'delivered' THEN
                    NEW.available_at := NULL;
                    NEW.delivered_at := db_now;
                ELSIF NEW.status = 'dead_lettered' THEN
                    NEW.available_at := NULL;
                    NEW.dead_lettered_at := db_now;
                ELSIF NEW.status = 'cancelled' THEN
                    NEW.available_at := NULL;
                    NEW.cancelled_at := db_now;
                END IF;
                RETURN NEW;
            END IF;

            IF OLD.status IN ('pending', 'retry_wait') AND NEW.status = 'cancelled' THEN
                IF NEW.attempt_count IS DISTINCT FROM OLD.attempt_count
                   OR NEW.delivery_cycle IS DISTINCT FROM OLD.delivery_cycle
                   OR NEW.cycle_key IS DISTINCT FROM OLD.cycle_key
                   OR NEW.last_error_code IS DISTINCT FROM OLD.last_error_code
                   OR NEW.last_error_class IS DISTINCT FROM OLD.last_error_class
                   OR NEW.last_error_summary IS DISTINCT FROM OLD.last_error_summary
                   OR NEW.last_error_retryable IS DISTINCT FROM OLD.last_error_retryable THEN
                    RAISE EXCEPTION 'cancelling an idle message cannot rewrite delivery history'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_message_delivery_transition';
                END IF;
                NEW.available_at := NULL;
                NEW.cancelled_at := db_now;
                RETURN NEW;
            END IF;

            RAISE EXCEPTION 'illegal outbox message state transition'
                USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_message_transition';
        END;
        $function$
    """)
    op.execute(r"""
        CREATE TRIGGER trg_outbox_message_authority_guard
        BEFORE INSERT OR UPDATE OR DELETE ON outbox_messages
        FOR EACH ROW EXECUTE FUNCTION ag_guard_outbox_message_authority()
    """)
    op.execute(r"""
        CREATE FUNCTION ag_align_outbox_message_delivery_time()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $function$
        DECLARE
            delivery_completed_at timestamptz;
        BEGIN
            IF TG_OP <> 'UPDATE'
               OR OLD.status NOT IN ('dispatching', 'awaiting_receipt')
               OR NEW.status NOT IN ('delivered', 'retry_wait', 'dead_lettered', 'cancelled')
               OR OLD.active_delivery_attempt_id IS NULL THEN
                RETURN NEW;
            END IF;

            SELECT completed_at
            INTO delivery_completed_at
            FROM outbox_delivery_attempts
            WHERE id = OLD.active_delivery_attempt_id
              AND message_id = OLD.id;
            IF NOT FOUND OR delivery_completed_at IS NULL THEN
                RAISE EXCEPTION 'outbox completion requires one terminal delivery clock'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_message_delivery_transition';
            END IF;

            NEW.updated_at := delivery_completed_at;
            IF NEW.status = 'delivered' THEN
                NEW.delivered_at := delivery_completed_at;
            ELSIF NEW.status = 'retry_wait' THEN
                NEW.available_at := delivery_completed_at + make_interval(
                    secs => ag_outbox_retry_delay_seconds(
                        OLD.logical_key,
                        NEW.attempt_count
                    )
                );
            ELSIF NEW.status = 'dead_lettered' THEN
                NEW.dead_lettered_at := delivery_completed_at;
            ELSE
                NEW.cancelled_at := delivery_completed_at;
            END IF;
            RETURN NEW;
        END;
        $function$
    """)
    op.execute(r"""
        CREATE TRIGGER trg_outbox_message_delivery_clock_guard
        BEFORE UPDATE ON outbox_messages
        FOR EACH ROW EXECUTE FUNCTION ag_align_outbox_message_delivery_time()
    """)

    op.execute(r"""
        CREATE FUNCTION ag_guard_outbox_delivery_authority()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $function$
        DECLARE
            db_now timestamptz := transaction_timestamp();
            wall_now timestamptz;
            event_at timestamptz;
            parent_row outbox_messages%ROWTYPE;
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'outbox delivery evidence cannot be deleted'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_delivery_no_delete';
            END IF;

            SELECT *
            INTO parent_row
            FROM outbox_messages
            WHERE id = NEW.message_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'outbox delivery requires a parent message'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_delivery_parent_fence';
            END IF;

            IF TG_OP = 'INSERT' THEN
                IF parent_row.status <> 'dispatching'
                   OR parent_row.active_delivery_attempt_id IS DISTINCT FROM NEW.id
                   OR NEW.status <> 'dispatching' OR NEW.state_version <> 1
                   OR NEW.attempt_number IS DISTINCT FROM parent_row.attempt_count
                   OR NEW.delivery_cycle IS DISTINCT FROM parent_row.delivery_cycle
                   OR NEW.cycle_key IS DISTINCT FROM parent_row.cycle_key
                   OR NEW.delivery_token IS DISTINCT FROM parent_row.lease_token
                   OR NEW.publisher_id IS DISTINCT FROM parent_row.lease_owner
                   OR NEW.broker_name <> '' OR NEW.broker_message_id <> ''
                   OR NEW.broker_receipt_id <> ''
                   OR NEW.error_code <> '' OR NEW.error_class <> ''
                   OR NEW.error_summary <> '' OR NEW.retryable THEN
                    RAISE EXCEPTION 'delivery start evidence must match the claimed message fence'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_delivery_parent_fence';
                END IF;
                NEW.leased_at := parent_row.leased_at;
                NEW.heartbeat_at := parent_row.heartbeat_at;
                NEW.lease_expires_at := parent_row.lease_expires_at;
                NEW.created_at := db_now;
                NEW.updated_at := db_now;
                RETURN NEW;
            END IF;

            IF OLD.id IS DISTINCT FROM NEW.id
               OR OLD.message_id IS DISTINCT FROM NEW.message_id
               OR OLD.delivery_cycle IS DISTINCT FROM NEW.delivery_cycle
               OR OLD.attempt_number IS DISTINCT FROM NEW.attempt_number
               OR OLD.cycle_key IS DISTINCT FROM NEW.cycle_key
               OR OLD.delivery_token IS DISTINCT FROM NEW.delivery_token
               OR OLD.publisher_id IS DISTINCT FROM NEW.publisher_id
               OR OLD.leased_at IS DISTINCT FROM NEW.leased_at
               OR OLD.created_at IS DISTINCT FROM NEW.created_at THEN
                RAISE EXCEPTION 'immutable outbox delivery evidence cannot be changed'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_delivery_immutable';
            END IF;
            IF OLD.status IN ('delivered', 'failed', 'abandoned', 'cancelled')
               OR NEW.state_version <> OLD.state_version + 1 THEN
                RAISE EXCEPTION 'terminal delivery evidence is immutable and versions advance exactly once'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_delivery_transition';
            END IF;
            IF parent_row.active_delivery_attempt_id IS DISTINCT FROM OLD.id
               OR parent_row.status NOT IN ('dispatching', 'awaiting_receipt') THEN
                RAISE EXCEPTION 'delivery update lost its active parent fence'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_delivery_parent_fence';
            END IF;
            NEW.updated_at := db_now;

            IF NOT (OLD.status = 'dispatching' AND NEW.status = 'dispatching')
               AND (NEW.heartbeat_at IS DISTINCT FROM OLD.heartbeat_at
                    OR NEW.lease_expires_at IS DISTINCT FROM OLD.lease_expires_at) THEN
                RAISE EXCEPTION 'delivery terminal transitions cannot rewrite lease history'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_delivery_lease_transition';
            END IF;

            IF OLD.status = 'dispatching' AND NEW.status = 'dispatching' THEN
                wall_now := clock_timestamp();
                IF parent_row.status <> 'dispatching'
                   OR parent_row.lease_token IS DISTINCT FROM OLD.delivery_token
                   OR NEW.lease_expires_at < OLD.lease_expires_at
                   OR NEW.lease_expires_at <= wall_now
                   OR NEW.heartbeat_at IS NULL
                   OR NEW.broker_name IS DISTINCT FROM OLD.broker_name
                   OR NEW.broker_message_id IS DISTINCT FROM OLD.broker_message_id
                   OR NEW.broker_receipt_id IS DISTINCT FROM OLD.broker_receipt_id
                   OR NEW.dispatched_at IS DISTINCT FROM OLD.dispatched_at
                   OR NEW.receipt_deadline_at IS DISTINCT FROM OLD.receipt_deadline_at
                   OR NEW.receipt_received_at IS DISTINCT FROM OLD.receipt_received_at
                   OR NEW.completed_at IS DISTINCT FROM OLD.completed_at
                   OR NEW.error_code IS DISTINCT FROM OLD.error_code
                   OR NEW.error_class IS DISTINCT FROM OLD.error_class
                   OR NEW.error_summary IS DISTINCT FROM OLD.error_summary
                   OR NEW.retryable IS DISTINCT FROM OLD.retryable THEN
                    RAISE EXCEPTION 'delivery heartbeat must retain its active fence'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_delivery_lease_transition';
                END IF;
                event_at := GREATEST(
                    NEW.heartbeat_at,
                    OLD.leased_at,
                    OLD.heartbeat_at,
                    OLD.updated_at
                );
                IF event_at > wall_now THEN
                    RAISE EXCEPTION 'delivery heartbeat cannot claim future database time'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_delivery_timestamp_order';
                END IF;
                NEW.heartbeat_at := event_at;
                NEW.updated_at := event_at;
                RETURN NEW;
            END IF;

            IF OLD.status = 'dispatching' AND NEW.status = 'awaiting_receipt' THEN
                wall_now := clock_timestamp();
                IF parent_row.status <> 'dispatching'
                   OR NEW.receipt_deadline_at IS NULL
                   OR NEW.receipt_deadline_at <= wall_now
                   OR NEW.dispatched_at IS NULL
                   OR NEW.broker_name = '' OR NEW.broker_message_id = ''
                   OR NEW.broker_receipt_id <> ''
                   OR NEW.error_code IS DISTINCT FROM OLD.error_code
                   OR NEW.error_class IS DISTINCT FROM OLD.error_class
                   OR NEW.error_summary IS DISTINCT FROM OLD.error_summary
                   OR NEW.retryable IS DISTINCT FROM OLD.retryable THEN
                    RAISE EXCEPTION 'broker acknowledgement requires a bounded receipt deadline'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_delivery_transition';
                END IF;
                event_at := GREATEST(
                    NEW.dispatched_at,
                    OLD.leased_at,
                    OLD.heartbeat_at,
                    OLD.updated_at
                );
                IF event_at > wall_now THEN
                    RAISE EXCEPTION 'broker acknowledgement cannot claim future database time'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_delivery_timestamp_order';
                END IF;
                NEW.dispatched_at := event_at;
                NEW.updated_at := event_at;
                RETURN NEW;
            END IF;

            IF OLD.status IN ('dispatching', 'awaiting_receipt')
               AND NEW.status = 'delivered' THEN
                wall_now := clock_timestamp();
                IF NEW.broker_name = '' OR NEW.broker_message_id = ''
                   OR NEW.completed_at IS NULL
                   OR NEW.receipt_received_at IS NULL
                   OR (OLD.status = 'awaiting_receipt' AND (
                       NEW.broker_name IS DISTINCT FROM OLD.broker_name
                       OR NEW.broker_message_id IS DISTINCT FROM OLD.broker_message_id
                   ))
                   OR NEW.error_code IS DISTINCT FROM OLD.error_code
                   OR NEW.error_class IS DISTINCT FROM OLD.error_class
                   OR NEW.error_summary IS DISTINCT FROM OLD.error_summary
                   OR NEW.retryable IS DISTINCT FROM OLD.retryable THEN
                    RAISE EXCEPTION 'delivered receipt must retain exact broker and lease history'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_delivery_transition';
                END IF;
                event_at := GREATEST(
                    NEW.completed_at,
                    NEW.receipt_received_at,
                    NEW.dispatched_at,
                    OLD.dispatched_at,
                    OLD.leased_at,
                    OLD.heartbeat_at,
                    OLD.updated_at
                );
                IF event_at > wall_now THEN
                    RAISE EXCEPTION 'delivered receipt cannot claim future database time'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_delivery_timestamp_order';
                END IF;
                NEW.dispatched_at := COALESCE(OLD.dispatched_at, event_at);
                NEW.receipt_deadline_at := NULL;
                NEW.receipt_received_at := event_at;
                NEW.completed_at := event_at;
                NEW.updated_at := event_at;
                RETURN NEW;
            END IF;

            IF OLD.status IN ('dispatching', 'awaiting_receipt')
               AND NEW.status IN ('failed', 'abandoned', 'cancelled') THEN
                wall_now := clock_timestamp();
                IF NEW.error_code = '' OR NEW.error_class = '' OR NEW.error_summary = ''
                   OR NEW.completed_at IS NULL
                   OR (NEW.status = 'abandoned' AND NOT NEW.retryable)
                   OR (NEW.status = 'cancelled' AND NEW.retryable)
                   OR NEW.broker_name IS DISTINCT FROM OLD.broker_name
                   OR NEW.broker_message_id IS DISTINCT FROM OLD.broker_message_id
                   OR NEW.broker_receipt_id IS DISTINCT FROM OLD.broker_receipt_id
                   OR NEW.dispatched_at IS DISTINCT FROM OLD.dispatched_at
                   OR NEW.receipt_received_at IS DISTINCT FROM OLD.receipt_received_at THEN
                    RAISE EXCEPTION 'terminal delivery failure requires complete bounded error facts'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_delivery_transition';
                END IF;
                event_at := GREATEST(
                    NEW.completed_at,
                    OLD.dispatched_at,
                    OLD.leased_at,
                    OLD.heartbeat_at,
                    OLD.updated_at
                );
                IF event_at > wall_now THEN
                    RAISE EXCEPTION 'terminal delivery failure cannot claim future database time'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_delivery_timestamp_order';
                END IF;
                NEW.receipt_deadline_at := NULL;
                NEW.completed_at := event_at;
                NEW.updated_at := event_at;
                RETURN NEW;
            END IF;

            RAISE EXCEPTION 'illegal outbox delivery state transition'
                USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_delivery_transition';
        END;
        $function$
    """)
    op.execute(r"""
        CREATE TRIGGER trg_outbox_delivery_authority_guard
        BEFORE INSERT OR UPDATE OR DELETE ON outbox_delivery_attempts
        FOR EACH ROW EXECUTE FUNCTION ag_guard_outbox_delivery_authority()
    """)

    op.execute(r"""
        CREATE FUNCTION ag_guard_stage_attempt_outbox_link()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $function$
        DECLARE
            matching_receipts integer;
        BEGIN
            IF TG_OP = 'UPDATE'
               AND OLD.outbox_delivery_attempt_id IS DISTINCT FROM NEW.outbox_delivery_attempt_id THEN
                RAISE EXCEPTION 'stage attempt outbox receipt evidence is immutable'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_attempt_outbox_immutable';
            END IF;
            IF NEW.outbox_delivery_attempt_id IS NULL THEN
                -- Expand-phase compatibility for pre-outbox runtime writers.
                RETURN NEW;
            END IF;
            SELECT count(*)
            INTO matching_receipts
            FROM outbox_delivery_attempts AS delivery
            JOIN outbox_messages AS message
              ON message.id = delivery.message_id
            WHERE delivery.id = NEW.outbox_delivery_attempt_id
              AND delivery.status = 'delivered'
              AND delivery.attempt_number = message.attempt_count
              AND delivery.delivery_cycle = message.delivery_cycle
              AND delivery.cycle_key = message.cycle_key
              AND message.status = 'delivered'
              AND message.stage_run_id = NEW.stage_run_id
              AND message.target_attempt_number = NEW.attempt_number
              AND message.input_checksum = NEW.input_checksum
              AND NEW.delivery_id = delivery.cycle_key;
            IF matching_receipts <> 1 THEN
                RAISE EXCEPTION 'stage attempt outbox link requires exact delivered receipt evidence'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_attempt_outbox_receipt';
            END IF;
            RETURN NEW;
        END;
        $function$
    """)
    op.execute(r"""
        CREATE TRIGGER trg_stage_attempt_outbox_link_guard
        BEFORE INSERT OR UPDATE ON stage_attempts
        FOR EACH ROW EXECUTE FUNCTION ag_guard_stage_attempt_outbox_link()
    """)

    op.execute(r"""
        CREATE FUNCTION ag_check_outbox_delivery_consistency()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $function$
        DECLARE
            target_message_id uuid;
            message_row outbox_messages%ROWTYPE;
            total_attempts integer;
            maximum_attempt_number integer;
            maximum_delivery_cycle bigint;
            active_attempts integer;
            active_row outbox_delivery_attempts%ROWTYPE;
            latest_row outbox_delivery_attempts%ROWTYPE;
        BEGIN
            IF TG_TABLE_NAME = 'outbox_messages' THEN
                target_message_id := COALESCE(NEW.id, OLD.id);
            ELSE
                target_message_id := COALESCE(NEW.message_id, OLD.message_id);
            END IF;
            SELECT * INTO message_row
            FROM outbox_messages
            WHERE id = target_message_id;
            IF NOT FOUND THEN
                RETURN NULL;
            END IF;

            SELECT count(*), max(attempt_number), max(delivery_cycle),
                   count(*) FILTER (
                       WHERE status IN ('dispatching', 'awaiting_receipt')
                   )
            INTO total_attempts, maximum_attempt_number,
                 maximum_delivery_cycle, active_attempts
            FROM outbox_delivery_attempts
            WHERE message_id = target_message_id;
            IF total_attempts <> message_row.attempt_count
               OR (total_attempts > 0 AND (
                   maximum_attempt_number IS DISTINCT FROM message_row.attempt_count
                   OR maximum_delivery_cycle IS DISTINCT FROM message_row.delivery_cycle
               )) THEN
                RAISE EXCEPTION 'message counters do not match durable delivery evidence'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_delivery_consistency';
            END IF;

            IF message_row.status IN ('dispatching', 'awaiting_receipt') THEN
                IF active_attempts <> 1 THEN
                    RAISE EXCEPTION 'an active message requires exactly one active delivery attempt'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_delivery_consistency';
                END IF;
                SELECT * INTO active_row
                FROM outbox_delivery_attempts
                WHERE message_id = target_message_id
                  AND status IN ('dispatching', 'awaiting_receipt');
                IF active_row.id IS DISTINCT FROM message_row.active_delivery_attempt_id
                   OR active_row.attempt_number IS DISTINCT FROM message_row.attempt_count
                   OR active_row.delivery_cycle IS DISTINCT FROM message_row.delivery_cycle
                   OR active_row.cycle_key IS DISTINCT FROM message_row.cycle_key
                   OR active_row.status IS DISTINCT FROM message_row.status THEN
                    RAISE EXCEPTION 'message and active delivery identity or status drifted'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_delivery_consistency';
                END IF;
                IF message_row.status = 'dispatching' AND (
                    active_row.delivery_token IS DISTINCT FROM message_row.lease_token
                    OR active_row.publisher_id IS DISTINCT FROM message_row.lease_owner
                    OR active_row.leased_at IS DISTINCT FROM message_row.leased_at
                    OR active_row.heartbeat_at IS DISTINCT FROM message_row.heartbeat_at
                    OR active_row.lease_expires_at IS DISTINCT FROM message_row.lease_expires_at
                ) THEN
                    RAISE EXCEPTION 'message and delivery lease fence drifted'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_delivery_consistency';
                ELSIF message_row.status = 'awaiting_receipt'
                      AND active_row.receipt_deadline_at IS DISTINCT FROM message_row.receipt_deadline_at THEN
                    RAISE EXCEPTION 'message and delivery receipt deadline drifted'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_delivery_consistency';
                END IF;
                RETURN NULL;
            END IF;

            IF active_attempts <> 0 THEN
                RAISE EXCEPTION 'an inactive message cannot retain active delivery evidence'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_delivery_consistency';
            END IF;
            IF total_attempts = 0 THEN
                RETURN NULL;
            END IF;
            SELECT * INTO latest_row
            FROM outbox_delivery_attempts
            WHERE message_id = target_message_id
              AND attempt_number = message_row.attempt_count;
            IF (message_row.status = 'delivered' AND latest_row.status <> 'delivered')
               OR (message_row.status IN ('retry_wait', 'dead_lettered')
                   AND latest_row.status NOT IN ('failed', 'abandoned'))
               OR (message_row.status = 'cancelled'
                   AND latest_row.status NOT IN ('failed', 'abandoned', 'cancelled')) THEN
                RAISE EXCEPTION 'message terminal state disagrees with latest delivery evidence'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_delivery_consistency';
            END IF;
            IF message_row.status IN ('retry_wait', 'dead_lettered') AND (
                message_row.last_error_code IS DISTINCT FROM latest_row.error_code
                OR message_row.last_error_class IS DISTINCT FROM latest_row.error_class
                OR message_row.last_error_summary IS DISTINCT FROM latest_row.error_summary
                OR message_row.last_error_retryable IS DISTINCT FROM latest_row.retryable
            ) THEN
                RAISE EXCEPTION 'message error facts disagree with latest delivery evidence'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_delivery_consistency';
            END IF;
            RETURN NULL;
        END;
        $function$
    """)
    op.execute(r"""
        CREATE CONSTRAINT TRIGGER trg_outbox_delivery_consistency_from_message
        AFTER INSERT OR UPDATE OR DELETE ON outbox_messages
        DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW EXECUTE FUNCTION ag_check_outbox_delivery_consistency()
    """)
    op.execute(r"""
        CREATE CONSTRAINT TRIGGER trg_outbox_delivery_consistency_from_attempt
        AFTER INSERT OR UPDATE OR DELETE ON outbox_delivery_attempts
        DEFERRABLE INITIALLY DEFERRED
        FOR EACH ROW EXECUTE FUNCTION ag_check_outbox_delivery_consistency()
    """)


def _drop_authority_guards() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_stage_attempt_outbox_link_guard ON stage_attempts")
    op.execute("DROP FUNCTION IF EXISTS ag_guard_stage_attempt_outbox_link()")
    op.execute("DROP TRIGGER IF EXISTS trg_outbox_delivery_consistency_from_attempt ON outbox_delivery_attempts")
    op.execute("DROP TRIGGER IF EXISTS trg_outbox_delivery_consistency_from_message ON outbox_messages")
    op.execute("DROP FUNCTION IF EXISTS ag_check_outbox_delivery_consistency()")
    op.execute("DROP TRIGGER IF EXISTS trg_outbox_delivery_authority_guard ON outbox_delivery_attempts")
    op.execute("DROP FUNCTION IF EXISTS ag_guard_outbox_delivery_authority()")
    op.execute("DROP TRIGGER IF EXISTS trg_outbox_message_delivery_clock_guard ON outbox_messages")
    op.execute("DROP FUNCTION IF EXISTS ag_align_outbox_message_delivery_time()")
    op.execute("DROP TRIGGER IF EXISTS trg_outbox_message_authority_guard ON outbox_messages")
    op.execute("DROP FUNCTION IF EXISTS ag_guard_outbox_message_authority()")


def _preflight_downgrade() -> None:
    connection = op.get_bind()
    connection.execute(
        sa.text("LOCK TABLE workflow_runs, stage_runs, outbox_messages, outbox_delivery_attempts, stage_attempts IN ACCESS EXCLUSIVE MODE")
    )
    unsafe_attempts = connection.execute(sa.text("SELECT count(*) FROM outbox_delivery_attempts")).scalar_one()
    unsafe_links = connection.execute(
        sa.text("SELECT count(*) FROM stage_attempts WHERE outbox_delivery_attempt_id IS NOT NULL")
    ).scalar_one()
    unsafe_messages = connection.execute(
        sa.text("""
        SELECT count(*)
        FROM outbox_messages
        WHERE emission_kind <> 'migration_backfill'
           OR status <> 'pending'
           OR state_version <> 1
           OR attempt_count <> 0
           OR max_attempts <> 8
           OR delivery_cycle <> 0
           OR cycle_key IS NOT NULL
           OR active_delivery_attempt_id IS NOT NULL
           OR lease_owner <> '' OR lease_token IS NOT NULL
           OR leased_at IS NOT NULL OR lease_expires_at IS NOT NULL
           OR heartbeat_at IS NOT NULL OR receipt_deadline_at IS NOT NULL
           OR last_error_code <> '' OR last_error_class <> ''
           OR last_error_summary <> '' OR last_error_retryable
           OR delivered_at IS NOT NULL OR dead_lettered_at IS NOT NULL
           OR cancelled_at IS NOT NULL
           OR redrive_of_message_id IS NOT NULL OR redrive_ordinal <> 0
           OR redrive_requested_by <> '' OR redrive_requested_by_id <> ''
           OR redrive_reason <> '' OR redrive_requested_at IS NOT NULL
           OR updated_at IS DISTINCT FROM created_at
    """)
    ).scalar_one()
    if unsafe_attempts or unsafe_links or unsafe_messages:
        raise RuntimeError(
            "0003 downgrade would destroy authoritative outbox activity; only untouched migration_backfill messages may be removed"
        )
