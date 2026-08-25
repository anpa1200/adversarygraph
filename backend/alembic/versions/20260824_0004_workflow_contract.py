"""Contract durable workflow execution to receipt-bound outbox authority.

Revision ID: 20260824_0004
Revises: 20260823_0003

This is the contract half of the 0003 expand/contract rollout.  It preserves
historical terminal attempts that predate receipt linkage, but no new attempt
may be created without an exact delivered outbox receipt.  Current-v1 workflow
children are serialized beneath their workflow row and a deferred invariant
checks the complete W/S/A/M/D fixed point at transaction commit.
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "20260824_0004"
down_revision: str | None = "20260823_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_CURRENT_WORKFLOW_SCHEMA = "research-workflow-v1"
_CURRENT_PLAN_SCHEMA = "research-workflow-plan-v1"
_ACTIVE_WORKFLOW_STATUSES = "'queued', 'running'"
_LIVE_MESSAGE_STATUSES = "'pending', 'dispatching', 'awaiting_receipt', 'retry_wait'"


def _require_zero(connection, statement: str, *, message: str) -> None:
    count = int(connection.execute(sa.text(statement)).scalar_one())
    if count:
        raise RuntimeError(f"{message}: {count} row(s)")


def _create_contract_helpers() -> None:
    op.execute(r"""
        CREATE FUNCTION ag_workflow_stage_matches_plan(
            workflow_row workflow_runs,
            stage_row stage_runs
        )
        RETURNS boolean
        LANGUAGE plpgsql
        STABLE
        PARALLEL SAFE
        STRICT
        SET search_path = pg_catalog, public
        AS $function$
        DECLARE
            plan_member jsonb;
            expected_input jsonb;
            expected_idempotency text;
        BEGIN
            IF workflow_row.workflow_schema_version <> 'research-workflow-v1'
               OR workflow_row.plan_schema_version <> 'research-workflow-plan-v1'
               OR jsonb_typeof(workflow_row.stage_plan) <> 'array'
               OR stage_row.ordinal < 1
               OR stage_row.ordinal > jsonb_array_length(workflow_row.stage_plan) THEN
                RETURN FALSE;
            END IF;

            plan_member := workflow_row.stage_plan -> (stage_row.ordinal - 1);
            IF jsonb_typeof(plan_member) <> 'object'
               OR (SELECT count(*) FROM jsonb_object_keys(plan_member)) <> 13
               OR NOT plan_member ?& ARRAY[
                   'stage_key', 'stage_type', 'stage_version', 'ordinal',
                   'depends_on', 'required', 'priority', 'max_attempts',
                   'config_schema_version', 'checkpoint_schema_version',
                   'config', 'input_manifest', 'retry_policy'
               ]
               OR jsonb_typeof(plan_member -> 'stage_key') <> 'string'
               OR jsonb_typeof(plan_member -> 'stage_type') <> 'string'
               OR jsonb_typeof(plan_member -> 'stage_version') <> 'string'
               OR jsonb_typeof(plan_member -> 'ordinal') <> 'number'
               OR jsonb_typeof(plan_member -> 'depends_on') <> 'array'
               OR jsonb_typeof(plan_member -> 'required') <> 'boolean'
               OR jsonb_typeof(plan_member -> 'priority') <> 'number'
               OR jsonb_typeof(plan_member -> 'max_attempts') <> 'number'
               OR jsonb_typeof(plan_member -> 'config_schema_version') <> 'string'
               OR jsonb_typeof(plan_member -> 'checkpoint_schema_version') <> 'string'
               OR jsonb_typeof(plan_member -> 'config') <> 'object'
               OR jsonb_typeof(plan_member -> 'input_manifest') NOT IN ('object', 'null')
               OR jsonb_typeof(plan_member -> 'retry_policy') <> 'object'
               OR (SELECT count(*) FROM jsonb_object_keys(plan_member -> 'retry_policy')) <> 3
               OR NOT (plan_member -> 'retry_policy') ?& ARRAY[
                   'base_delay_seconds', 'max_delay_seconds', 'jitter_percent'
               ]
               OR jsonb_typeof(plan_member #> '{retry_policy,base_delay_seconds}') <> 'number'
               OR jsonb_typeof(plan_member #> '{retry_policy,max_delay_seconds}') <> 'number'
               OR jsonb_typeof(plan_member #> '{retry_policy,jitter_percent}') <> 'number'
               OR (plan_member #>> '{retry_policy,base_delay_seconds}')::integer NOT BETWEEN 1 AND 3600
               OR (plan_member #>> '{retry_policy,max_delay_seconds}')::integer NOT BETWEEN 1 AND 86400
               OR (plan_member #>> '{retry_policy,jitter_percent}')::integer NOT BETWEEN 0 AND 50
               OR (plan_member #>> '{retry_policy,max_delay_seconds}')::integer
                  < (plan_member #>> '{retry_policy,base_delay_seconds}')::integer THEN
                RETURN FALSE;
            END IF;

            expected_input := CASE
                WHEN plan_member -> 'input_manifest' = 'null'::jsonb
                    THEN workflow_row.input_manifest
                ELSE plan_member -> 'input_manifest'
            END;
            expected_idempotency := encode(
                sha256(
                    convert_to(
                        '{"stage_key":"' || stage_row.stage_key
                        || '","workflow_run_id":"' || stage_row.workflow_run_id::text || '"}',
                        'UTF8'
                    )
                ),
                'hex'
            );

            RETURN stage_row.workflow_run_id = workflow_row.id
               AND stage_row.stage_key = plan_member ->> 'stage_key'
               AND stage_row.stage_type = plan_member ->> 'stage_type'
               AND stage_row.stage_version = plan_member ->> 'stage_version'
               AND stage_row.ordinal = (plan_member ->> 'ordinal')::integer
               AND stage_row.depends_on = plan_member -> 'depends_on'
               AND stage_row.required = (plan_member ->> 'required')::boolean
               AND stage_row.priority = (plan_member ->> 'priority')::integer
               AND stage_row.max_attempts = (plan_member ->> 'max_attempts')::integer
               AND stage_row.config_schema_version = plan_member ->> 'config_schema_version'
               AND stage_row.checkpoint_schema_version = plan_member ->> 'checkpoint_schema_version'
               AND stage_row.config = plan_member -> 'config'
               AND stage_row.input_manifest = expected_input
               AND stage_row.idempotency_key = expected_idempotency;
        EXCEPTION
            WHEN OTHERS THEN
                RETURN FALSE;
        END;
        $function$
    """)
    op.execute(r"""
        CREATE FUNCTION ag_workflow_has_exact_stage_plan(workflow_row workflow_runs)
        RETURNS boolean
        LANGUAGE plpgsql
        STABLE
        PARALLEL UNSAFE
        STRICT
        SET search_path = pg_catalog, public
        AS $function$
        DECLARE
            stage_count integer;
            invalid_count integer;
        BEGIN
            IF workflow_row.workflow_schema_version <> 'research-workflow-v1'
               OR workflow_row.plan_schema_version <> 'research-workflow-plan-v1'
               OR jsonb_typeof(workflow_row.stage_plan) <> 'array'
               OR jsonb_array_length(workflow_row.stage_plan) NOT BETWEEN 1 AND 64 THEN
                RETURN FALSE;
            END IF;
            IF EXISTS (
                SELECT 1
                FROM jsonb_array_elements(workflow_row.stage_plan)
                     WITH ORDINALITY AS plan(member, member_ordinal)
                CROSS JOIN LATERAL jsonb_array_elements(member -> 'depends_on')
                     AS dependency(value)
                WHERE jsonb_typeof(dependency.value) <> 'string'
                   OR NOT EXISTS (
                       SELECT 1
                       FROM jsonb_array_elements(workflow_row.stage_plan)
                            WITH ORDINALITY AS predecessor(member, member_ordinal)
                       WHERE predecessor.member_ordinal < plan.member_ordinal
                         AND predecessor.member ->> 'stage_key'
                             = dependency.value #>> '{}'
                   )
                   OR (
                       SELECT count(*)
                       FROM jsonb_array_elements(plan.member -> 'depends_on') AS item(value)
                   ) <> (
                       SELECT count(DISTINCT item.value)
                       FROM jsonb_array_elements(plan.member -> 'depends_on') AS item(value)
                   )
            ) THEN
                RETURN FALSE;
            END IF;
            SELECT count(*),
                   count(*) FILTER (
                       WHERE NOT ag_workflow_stage_matches_plan(workflow_row, stage)
                   )
            INTO stage_count, invalid_count
            FROM stage_runs AS stage
            WHERE stage.workflow_run_id = workflow_row.id;
            RETURN stage_count = jsonb_array_length(workflow_row.stage_plan)
               AND invalid_count = 0;
        EXCEPTION
            WHEN OTHERS THEN
                RETURN FALSE;
        END;
        $function$
    """)
    op.execute(r"""
        CREATE FUNCTION ag_workflow_contract_valid(target_workflow_id uuid)
        RETURNS boolean
        LANGUAGE plpgsql
        STABLE
        PARALLEL UNSAFE
        STRICT
        SET search_path = pg_catalog, public
        AS $function$
        DECLARE
            workflow_row workflow_runs%ROWTYPE;
            stage_row stage_runs%ROWTYPE;
            expected_logical_key text;
            live_count integer;
            leaf_count integer;
            live_leaf_count integer;
            dead_leaf_count integer;
        BEGIN
            SELECT * INTO workflow_row
            FROM workflow_runs
            WHERE id = target_workflow_id;
            IF NOT FOUND THEN
                RETURN FALSE;
            END IF;

            IF workflow_row.workflow_schema_version <> 'research-workflow-v1'
               OR workflow_row.plan_schema_version <> 'research-workflow-plan-v1' THEN
                RETURN workflow_row.status IN (
                    'succeeded', 'degraded', 'failed', 'cancelled', 'dead_lettered'
                );
            END IF;
            IF NOT ag_workflow_has_exact_stage_plan(workflow_row) THEN
                RETURN FALSE;
            END IF;

            -- Every live message is the unique leaf for an exact runnable
            -- stage snapshot beneath an active workflow.
            IF EXISTS (
                SELECT 1
                FROM outbox_messages AS message
                LEFT JOIN stage_runs AS stage
                  ON stage.id = message.stage_run_id
                 AND stage.workflow_run_id = message.workflow_run_id
                WHERE message.workflow_run_id = workflow_row.id
                  AND message.status IN ('pending', 'dispatching', 'awaiting_receipt', 'retry_wait')
                  AND (
                      workflow_row.status NOT IN ('queued', 'running')
                      OR stage.id IS NULL
                      OR stage.status NOT IN ('ready', 'retry_wait')
                      OR message.aggregate_type <> 'workflow_stage'
                      OR message.aggregate_id IS DISTINCT FROM stage.id
                      OR message.aggregate_version IS DISTINCT FROM stage.state_version
                      OR message.stage_key IS DISTINCT FROM stage.stage_key
                      OR message.target_attempt_number IS DISTINCT FROM stage.attempt_count + 1
                      OR message.input_checksum IS DISTINCT FROM stage.input_checksum
                      OR message.plan_checksum IS DISTINCT FROM workflow_row.plan_checksum
                      OR message.correlation_id IS DISTINCT FROM workflow_row.correlation_id
                      OR message.logical_key IS DISTINCT FROM ag_outbox_stage_ready_logical_key(
                          workflow_row.id,
                          stage.id,
                          stage.stage_key,
                          stage.attempt_count + 1
                      )
                      OR EXISTS (
                          SELECT 1
                          FROM outbox_messages AS child
                          WHERE child.redrive_of_message_id = message.id
                      )
                  )
            ) THEN
                RETURN FALSE;
            END IF;

            -- Active delivery authority is only valid beneath the same exact
            -- active message and runnable W/S snapshot.
            IF EXISTS (
                SELECT 1
                FROM outbox_delivery_attempts AS delivery
                JOIN outbox_messages AS message ON message.id = delivery.message_id
                LEFT JOIN stage_runs AS stage
                  ON stage.id = message.stage_run_id
                 AND stage.workflow_run_id = message.workflow_run_id
                WHERE message.workflow_run_id = workflow_row.id
                  AND delivery.status IN ('dispatching', 'awaiting_receipt')
                  AND (
                      workflow_row.status NOT IN ('queued', 'running')
                      OR message.status IS DISTINCT FROM delivery.status
                      OR message.active_delivery_attempt_id IS DISTINCT FROM delivery.id
                      OR stage.id IS NULL
                      OR stage.status NOT IN ('ready', 'retry_wait')
                  )
            ) THEN
                RETURN FALSE;
            END IF;

            -- Runnable stages either own one exact live leaf or are explicitly
            -- paused at one unique dead-letter leaf awaiting manual redrive.
            FOR stage_row IN
                SELECT *
                FROM stage_runs
                WHERE workflow_run_id = workflow_row.id
                  AND status IN ('ready', 'retry_wait')
                ORDER BY ordinal, id
            LOOP
                IF workflow_row.status NOT IN ('queued', 'running') THEN
                    RETURN FALSE;
                END IF;
                expected_logical_key := ag_outbox_stage_ready_logical_key(
                    workflow_row.id,
                    stage_row.id,
                    stage_row.stage_key,
                    stage_row.attempt_count + 1
                );
                SELECT count(*) FILTER (
                           WHERE message.status IN (
                               'pending', 'dispatching', 'awaiting_receipt', 'retry_wait'
                           )
                       ),
                       count(*) FILTER (
                           WHERE NOT EXISTS (
                               SELECT 1 FROM outbox_messages AS child
                               WHERE child.redrive_of_message_id = message.id
                           )
                       ),
                       count(*) FILTER (
                           WHERE message.status IN (
                               'pending', 'dispatching', 'awaiting_receipt', 'retry_wait'
                           )
                             AND NOT EXISTS (
                                 SELECT 1 FROM outbox_messages AS child
                                 WHERE child.redrive_of_message_id = message.id
                             )
                       ),
                       count(*) FILTER (
                           WHERE message.status = 'dead_lettered'
                             AND message.workflow_run_id = workflow_row.id
                             AND message.stage_run_id = stage_row.id
                             AND message.aggregate_id = stage_row.id
                             AND message.aggregate_version = stage_row.state_version
                             AND message.stage_key = stage_row.stage_key
                             AND message.target_attempt_number = stage_row.attempt_count + 1
                             AND message.input_checksum = stage_row.input_checksum
                             AND message.plan_checksum = workflow_row.plan_checksum
                             AND message.correlation_id = workflow_row.correlation_id
                             AND NOT EXISTS (
                                 SELECT 1 FROM outbox_messages AS child
                                 WHERE child.redrive_of_message_id = message.id
                             )
                       )
                INTO live_count, leaf_count, live_leaf_count, dead_leaf_count
                FROM outbox_messages AS message
                WHERE message.logical_key = expected_logical_key;
                IF NOT (
                    (live_count = 1 AND leaf_count = 1 AND live_leaf_count = 1)
                    OR (live_count = 0 AND leaf_count = 1 AND dead_leaf_count = 1)
                ) THEN
                    RETURN FALSE;
                END IF;
            END LOOP;

            -- Every receipt-linked attempt is bound to one exact immutable
            -- delivered D->M lineage and its stage token is domain-separated
            -- from the publisher delivery token.
            IF EXISTS (
                SELECT 1
                FROM stage_attempts AS attempt
                JOIN stage_runs AS stage ON stage.id = attempt.stage_run_id
                LEFT JOIN outbox_delivery_attempts AS delivery
                  ON delivery.id = attempt.outbox_delivery_attempt_id
                LEFT JOIN outbox_messages AS message ON message.id = delivery.message_id
                WHERE stage.workflow_run_id = workflow_row.id
                  AND attempt.outbox_delivery_attempt_id IS NOT NULL
                  AND (
                      delivery.id IS NULL
                      OR message.id IS NULL
                      OR delivery.status <> 'delivered'
                      OR message.status <> 'delivered'
                      OR delivery.message_id IS DISTINCT FROM message.id
                      OR delivery.attempt_number IS DISTINCT FROM message.attempt_count
                      OR delivery.delivery_cycle IS DISTINCT FROM message.delivery_cycle
                      OR delivery.cycle_key IS DISTINCT FROM message.cycle_key
                      OR delivery.completed_at IS DISTINCT FROM message.delivered_at
                      OR delivery.broker_receipt_id !~ '^[0-9a-f]{64}$'
                      OR message.workflow_run_id IS DISTINCT FROM workflow_row.id
                      OR message.stage_run_id IS DISTINCT FROM stage.id
                      OR message.aggregate_id IS DISTINCT FROM stage.id
                      OR message.target_attempt_number IS DISTINCT FROM attempt.attempt_number
                      OR message.input_checksum IS DISTINCT FROM attempt.input_checksum
                      OR message.plan_checksum IS DISTINCT FROM workflow_row.plan_checksum
                      OR message.correlation_id IS DISTINCT FROM workflow_row.correlation_id
                      OR attempt.delivery_id IS DISTINCT FROM delivery.cycle_key
                      OR attempt.lease_token = delivery.delivery_token
                      OR attempt.started_at < delivery.completed_at
                  )
            ) THEN
                RETURN FALSE;
            END IF;

            -- Historical terminal NULL links are retained, but running
            -- authority never exists without a receipt and must exactly match S.
            IF EXISTS (
                SELECT 1
                FROM stage_attempts AS attempt
                JOIN stage_runs AS stage ON stage.id = attempt.stage_run_id
                WHERE stage.workflow_run_id = workflow_row.id
                  AND attempt.status = 'running'
                  AND (
                      workflow_row.status <> 'running'
                      OR stage.status <> 'running'
                      OR attempt.outbox_delivery_attempt_id IS NULL
                      OR attempt.attempt_number IS DISTINCT FROM stage.attempt_count
                      OR attempt.lease_token IS DISTINCT FROM stage.lease_token
                      OR attempt.lease_owner IS DISTINCT FROM stage.lease_owner
                      OR attempt.input_checksum IS DISTINCT FROM stage.input_checksum
                      OR attempt.heartbeat_at IS DISTINCT FROM stage.heartbeat_at
                      OR attempt.lease_expires_at IS DISTINCT FROM stage.lease_expires_at
                      OR attempt.checkpoint_end_version IS DISTINCT FROM stage.checkpoint_version
                      OR attempt.started_at IS DISTINCT FROM stage.leased_at
                  )
            ) THEN
                RETURN FALSE;
            END IF;

            IF workflow_row.status = 'queued' AND (
                EXISTS (
                    SELECT 1
                    FROM stage_runs AS stage
                    WHERE stage.workflow_run_id = workflow_row.id
                      AND (
                          stage.status NOT IN ('pending', 'ready')
                          OR stage.attempt_count <> 0
                          OR stage.first_started_at IS NOT NULL
                      )
                )
                OR EXISTS (
                    SELECT 1
                    FROM stage_attempts AS attempt
                    JOIN stage_runs AS stage ON stage.id = attempt.stage_run_id
                    WHERE stage.workflow_run_id = workflow_row.id
                )
            ) THEN
                RETURN FALSE;
            END IF;

            -- Aggregate settlement is bidirectional: a terminal W cannot
            -- retain unresolved children, and a running W cannot outlive its
            -- last unresolved child.  Authorized writers settle the final S
            -- and W in one deferred transaction.
            IF workflow_row.status = 'running' AND NOT EXISTS (
                SELECT 1
                FROM stage_runs AS stage
                WHERE stage.workflow_run_id = workflow_row.id
                  AND stage.status IN ('pending', 'ready', 'running', 'retry_wait')
            ) THEN
                RETURN FALSE;
            END IF;

            IF workflow_row.status IN (
                'succeeded', 'degraded', 'failed', 'cancelled', 'dead_lettered'
            ) AND (
                EXISTS (
                    SELECT 1 FROM stage_runs AS stage
                    WHERE stage.workflow_run_id = workflow_row.id
                      AND stage.status NOT IN (
                          'succeeded', 'degraded', 'skipped', 'failed',
                          'cancelled', 'dead_lettered'
                      )
                )
                OR EXISTS (
                    SELECT 1
                    FROM stage_attempts AS attempt
                    JOIN stage_runs AS stage ON stage.id = attempt.stage_run_id
                    WHERE stage.workflow_run_id = workflow_row.id
                      AND attempt.status = 'running'
                )
                OR EXISTS (
                    SELECT 1 FROM outbox_messages AS message
                    WHERE message.workflow_run_id = workflow_row.id
                      AND message.status IN (
                          'pending', 'dispatching', 'awaiting_receipt', 'retry_wait'
                      )
                )
                OR EXISTS (
                    SELECT 1
                    FROM outbox_delivery_attempts AS delivery
                    JOIN outbox_messages AS message ON message.id = delivery.message_id
                    WHERE message.workflow_run_id = workflow_row.id
                      AND delivery.status IN ('dispatching', 'awaiting_receipt')
                )
            ) THEN
                RETURN FALSE;
            END IF;
            RETURN TRUE;
        EXCEPTION
            WHEN OTHERS THEN
                RETURN FALSE;
        END;
        $function$
    """)


def _preflight_contract() -> None:
    connection = op.get_bind()
    _require_zero(
        connection,
        f"""
            SELECT count(*)
            FROM workflow_runs
            WHERE status IN ({_ACTIVE_WORKFLOW_STATUSES})
              AND (
                  workflow_schema_version <> '{_CURRENT_WORKFLOW_SCHEMA}'
                  OR plan_schema_version <> '{_CURRENT_PLAN_SCHEMA}'
              )
        """,
        message="0004 cannot contract active workflows with unsupported schema versions",
    )
    _require_zero(
        connection,
        """
            SELECT count(*)
            FROM outbox_delivery_attempts
            WHERE (status = 'delivered' AND broker_receipt_id !~ '^[0-9a-f]{64}$')
               OR (status <> 'delivered' AND broker_receipt_id <> '')
        """,
        message="0004 requires exact SHA-256 delivered receipt fingerprints",
    )
    _require_zero(
        connection,
        """
            SELECT count(*)
            FROM stage_attempts
            WHERE status = 'running' AND outbox_delivery_attempt_id IS NULL
        """,
        message="0004 cannot contract running attempts without receipt evidence",
    )
    _require_zero(
        connection,
        f"""
            SELECT count(*)
            FROM workflow_runs AS workflow
            WHERE workflow.workflow_schema_version = '{_CURRENT_WORKFLOW_SCHEMA}'
              AND workflow.plan_schema_version = '{_CURRENT_PLAN_SCHEMA}'
              AND NOT ag_workflow_contract_valid(workflow.id)
        """,
        message="0004 workflow/outbox authority preflight failed",
    )


def _install_outbox_event_clock_contract() -> None:
    """Preserve one post-lock database clock across D/M terminalization.

    Revision 0003 originally restamped delivery and message terminal facts with
    ``transaction_timestamp()``.  A transaction that started before a
    publisher commit could therefore acquire the delivery lock afterwards and
    write a receipt timestamp older than ``dispatched_at``.  Runtime writers
    already obtain ``clock_timestamp()`` after the complete lock cut and pass
    that one event time through D, M, S, and A.  Keep that proposed database
    time, bound it by the wall clock, and align M to the terminal D fact.
    """

    op.execute(r"""
        CREATE OR REPLACE FUNCTION ag_guard_outbox_delivery_authority()
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
        CREATE OR REPLACE FUNCTION ag_align_outbox_message_delivery_time()
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
    op.execute("DROP TRIGGER IF EXISTS trg_outbox_message_delivery_clock_guard ON outbox_messages")
    op.execute(r"""
        CREATE TRIGGER trg_outbox_message_delivery_clock_guard
        BEFORE UPDATE ON outbox_messages
        FOR EACH ROW EXECUTE FUNCTION ag_align_outbox_message_delivery_time()
    """)


def _create_immediate_guards() -> None:
    op.execute(r"""
        CREATE FUNCTION ag_guard_workflow_contract_plan()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $function$
        DECLARE
            projected_project_id uuid;
            project_row research_projects%ROWTYPE;
            revision_row project_revisions%ROWTYPE;
        BEGIN
            IF TG_OP = 'INSERT' THEN
                -- W only carries the revision identity.  Project revision
                -- writers lock project -> revision, so project the parent
                -- identity without a lock, then acquire the same canonical
                -- order and revalidate the revision after both locks.  This
                -- closes supersession/archive races without inverting locks.
                SELECT project_id INTO projected_project_id
                FROM project_revisions
                WHERE id = NEW.project_revision_id;
                IF NOT FOUND THEN
                    RAISE EXCEPTION 'new workflows require an existing project revision'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_workflow_run_project_authority';
                END IF;
                SELECT * INTO project_row
                FROM research_projects
                WHERE id = projected_project_id
                FOR UPDATE;
                IF NOT FOUND OR project_row.status <> 'active' THEN
                    RAISE EXCEPTION 'new workflows require one locked active project'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_workflow_run_project_authority';
                END IF;
                SELECT * INTO revision_row
                FROM project_revisions
                WHERE id = NEW.project_revision_id
                  AND project_id = project_row.id
                FOR UPDATE;
                IF NOT FOUND OR revision_row.status <> 'current' THEN
                    RAISE EXCEPTION 'new workflows require one locked current project revision'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_workflow_run_project_authority';
                END IF;
                IF NEW.cancel_request_id IS NOT NULL THEN
                    RAISE EXCEPTION 'new workflows cannot start with cancellation request authority'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_workflow_run_cancel_request';
                END IF;
                IF NEW.status IN ('queued', 'running') AND (
                    NEW.workflow_schema_version <> 'research-workflow-v1'
                    OR NEW.plan_schema_version <> 'research-workflow-plan-v1'
                ) THEN
                    RAISE EXCEPTION 'active workflows require the exact current schema pair'
                        USING ERRCODE = '23514', CONSTRAINT = 'ck_workflow_run_contract_schema';
                END IF;
                RETURN NEW;
            END IF;

            IF OLD.cancel_request_id IS DISTINCT FROM NEW.cancel_request_id AND NOT (
                OLD.cancel_request_id IS NULL
                AND NEW.cancel_request_id IS NOT NULL
                AND OLD.status IN ('queued', 'running')
                AND NEW.status = 'cancelled'
            ) THEN
                RAISE EXCEPTION 'workflow cancellation request identity is immutable'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_workflow_run_cancel_request';
            END IF;
            IF OLD.status <> 'cancelled' AND NEW.status = 'cancelled'
               AND NEW.cancel_request_id IS NULL THEN
                RAISE EXCEPTION 'new workflow cancellation requires request identity'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_workflow_run_cancel_request';
            END IF;
            IF NEW.status IN ('queued', 'running') AND (
                NEW.workflow_schema_version <> 'research-workflow-v1'
                OR NEW.plan_schema_version <> 'research-workflow-plan-v1'
            ) THEN
                RAISE EXCEPTION 'active workflows require the exact current schema pair'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_workflow_run_contract_schema';
            END IF;
            IF OLD.status IS DISTINCT FROM NEW.status
               AND NEW.workflow_schema_version = 'research-workflow-v1'
               AND NEW.plan_schema_version = 'research-workflow-plan-v1'
               AND NOT ag_workflow_has_exact_stage_plan(NEW) THEN
                RAISE EXCEPTION 'workflow transition requires its exact persisted stage plan'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_workflow_run_stage_plan_contract';
            END IF;
            RETURN NEW;
        END;
        $function$
    """)
    op.execute(r"""
        CREATE TRIGGER trg_0004_workflow_contract_plan_guard
        BEFORE INSERT OR UPDATE ON workflow_runs
        FOR EACH ROW EXECUTE FUNCTION ag_guard_workflow_contract_plan()
    """)

    op.execute(r"""
        CREATE FUNCTION ag_guard_stage_run_plan_contract()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $function$
        DECLARE
            workflow_row workflow_runs%ROWTYPE;
            dependency_count integer;
        BEGIN
            SELECT * INTO workflow_row
            FROM workflow_runs
            WHERE id = NEW.workflow_run_id
            FOR UPDATE;
            IF NOT FOUND
               OR workflow_row.status <> 'queued'
               OR workflow_row.workflow_schema_version <> 'research-workflow-v1'
               OR workflow_row.plan_schema_version <> 'research-workflow-plan-v1' THEN
                RAISE EXCEPTION 'new stages require one locked queued current-v1 workflow'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_run_plan_parent';
            END IF;
            IF NOT ag_workflow_stage_matches_plan(workflow_row, NEW) THEN
                RAISE EXCEPTION 'new stage does not exactly match its workflow plan member'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_run_plan_member';
            END IF;
            dependency_count := jsonb_array_length(NEW.depends_on);
            IF (dependency_count = 0 AND NEW.status <> 'ready')
               OR (dependency_count > 0 AND NEW.status <> 'pending') THEN
                RAISE EXCEPTION 'new stage status does not match its root/dependency plan role'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_run_plan_member';
            END IF;
            RETURN NEW;
        END;
        $function$
    """)
    op.execute(r"""
        CREATE TRIGGER trg_0004_stage_run_plan_guard
        BEFORE INSERT ON stage_runs
        FOR EACH ROW EXECUTE FUNCTION ag_guard_stage_run_plan_contract()
    """)

    op.execute(r"""
        CREATE FUNCTION ag_guard_outbox_message_parent_contract()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $function$
        DECLARE
            workflow_row workflow_runs%ROWTYPE;
            stage_row stage_runs%ROWTYPE;
        BEGIN
            SELECT * INTO workflow_row
            FROM workflow_runs
            WHERE id = NEW.workflow_run_id
            FOR UPDATE;
            IF NOT FOUND
               OR workflow_row.status NOT IN ('queued', 'running')
               OR workflow_row.workflow_schema_version <> 'research-workflow-v1'
               OR workflow_row.plan_schema_version <> 'research-workflow-plan-v1' THEN
                RAISE EXCEPTION 'new outbox messages require one locked active current-v1 workflow'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_message_workflow_contract';
            END IF;
            SELECT * INTO stage_row
            FROM stage_runs
            WHERE id = NEW.stage_run_id
              AND workflow_run_id = workflow_row.id
            FOR UPDATE;
            IF NOT FOUND OR stage_row.status NOT IN ('ready', 'retry_wait') THEN
                RAISE EXCEPTION 'new outbox messages require one locked runnable stage'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_message_stage_contract';
            END IF;
            IF NEW.aggregate_id IS DISTINCT FROM stage_row.id
               OR NEW.aggregate_version IS DISTINCT FROM stage_row.state_version
               OR NEW.stage_key IS DISTINCT FROM stage_row.stage_key
               OR NEW.target_attempt_number IS DISTINCT FROM stage_row.attempt_count + 1
               OR NEW.input_checksum IS DISTINCT FROM stage_row.input_checksum
               OR NEW.plan_checksum IS DISTINCT FROM workflow_row.plan_checksum
               OR NEW.correlation_id IS DISTINCT FROM workflow_row.correlation_id THEN
                RAISE EXCEPTION 'new outbox message does not match its locked W/S snapshot'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_outbox_message_stage_contract';
            END IF;
            RETURN NEW;
        END;
        $function$
    """)
    op.execute(r"""
        CREATE TRIGGER trg_0004_outbox_message_parent_contract_guard
        BEFORE INSERT ON outbox_messages
        FOR EACH ROW EXECUTE FUNCTION ag_guard_outbox_message_parent_contract()
    """)

    op.execute(r"""
        CREATE FUNCTION ag_guard_stage_attempt_receipt_contract()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $function$
        DECLARE
            projected_workflow_id uuid;
            projected_message_id uuid;
            workflow_row workflow_runs%ROWTYPE;
            stage_row stage_runs%ROWTYPE;
            message_row outbox_messages%ROWTYPE;
            delivery_row outbox_delivery_attempts%ROWTYPE;
        BEGIN
            IF NEW.outbox_delivery_attempt_id IS NULL THEN
                RAISE EXCEPTION 'new stage attempts require delivered receipt evidence'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_attempt_receipt_required';
            END IF;

            SELECT workflow_run_id INTO projected_workflow_id
            FROM stage_runs
            WHERE id = NEW.stage_run_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'new stage attempt has no projected stage parent'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_attempt_receipt_contract';
            END IF;
            SELECT * INTO workflow_row
            FROM workflow_runs
            WHERE id = projected_workflow_id
            FOR UPDATE;
            IF NOT FOUND
               OR workflow_row.status <> 'running'
               OR workflow_row.workflow_schema_version <> 'research-workflow-v1'
               OR workflow_row.plan_schema_version <> 'research-workflow-plan-v1' THEN
                RAISE EXCEPTION 'new stage attempt requires one locked running current-v1 workflow'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_attempt_receipt_contract';
            END IF;
            SELECT * INTO stage_row
            FROM stage_runs
            WHERE id = NEW.stage_run_id
              AND workflow_run_id = workflow_row.id
            FOR UPDATE;
            IF NOT FOUND OR stage_row.status <> 'running' THEN
                RAISE EXCEPTION 'new stage attempt requires one locked running stage'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_attempt_receipt_contract';
            END IF;

            SELECT message_id INTO projected_message_id
            FROM outbox_delivery_attempts
            WHERE id = NEW.outbox_delivery_attempt_id;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'new stage attempt has no projected receipt delivery'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_attempt_receipt_contract';
            END IF;
            SELECT * INTO message_row
            FROM outbox_messages
            WHERE id = projected_message_id
            FOR UPDATE;
            IF NOT FOUND THEN
                RAISE EXCEPTION 'new stage attempt has no locked receipt message'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_attempt_receipt_contract';
            END IF;
            SELECT * INTO delivery_row
            FROM outbox_delivery_attempts
            WHERE id = NEW.outbox_delivery_attempt_id
              AND message_id = message_row.id
            FOR UPDATE;
            IF NOT FOUND
               OR message_row.status <> 'delivered'
               OR delivery_row.status <> 'delivered'
               OR delivery_row.broker_receipt_id !~ '^[0-9a-f]{64}$'
               OR message_row.workflow_run_id IS DISTINCT FROM workflow_row.id
               OR message_row.stage_run_id IS DISTINCT FROM stage_row.id
               OR message_row.aggregate_id IS DISTINCT FROM stage_row.id
               OR message_row.target_attempt_number IS DISTINCT FROM NEW.attempt_number
               OR message_row.input_checksum IS DISTINCT FROM NEW.input_checksum
               OR message_row.plan_checksum IS DISTINCT FROM workflow_row.plan_checksum
               OR message_row.correlation_id IS DISTINCT FROM workflow_row.correlation_id
               OR delivery_row.attempt_number IS DISTINCT FROM message_row.attempt_count
               OR delivery_row.delivery_cycle IS DISTINCT FROM message_row.delivery_cycle
               OR delivery_row.cycle_key IS DISTINCT FROM message_row.cycle_key
               OR delivery_row.completed_at IS DISTINCT FROM message_row.delivered_at
               OR NEW.delivery_id IS DISTINCT FROM delivery_row.cycle_key
               OR NEW.lease_token = delivery_row.delivery_token
               OR NEW.started_at < delivery_row.completed_at THEN
                RAISE EXCEPTION 'new stage attempt receipt lineage is not exact or token-separated'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_stage_attempt_receipt_contract';
            END IF;
            RETURN NEW;
        END;
        $function$
    """)
    op.execute(r"""
        CREATE TRIGGER trg_0004_stage_attempt_receipt_contract_guard
        BEFORE INSERT ON stage_attempts
        FOR EACH ROW EXECUTE FUNCTION ag_guard_stage_attempt_receipt_contract()
    """)


def _create_deferred_contract_triggers() -> None:
    op.execute(r"""
        CREATE FUNCTION ag_check_workflow_contract()
        RETURNS trigger
        LANGUAGE plpgsql
        SET search_path = pg_catalog, public
        AS $function$
        DECLARE
            target_workflow_id uuid;
        BEGIN
            IF TG_TABLE_NAME = 'workflow_runs' THEN
                target_workflow_id := COALESCE(NEW.id, OLD.id);
            ELSIF TG_TABLE_NAME = 'stage_runs' THEN
                target_workflow_id := COALESCE(NEW.workflow_run_id, OLD.workflow_run_id);
            ELSIF TG_TABLE_NAME = 'stage_attempts' THEN
                SELECT workflow_run_id INTO target_workflow_id
                FROM stage_runs
                WHERE id = COALESCE(NEW.stage_run_id, OLD.stage_run_id);
            ELSIF TG_TABLE_NAME = 'outbox_messages' THEN
                target_workflow_id := COALESCE(NEW.workflow_run_id, OLD.workflow_run_id);
            ELSE
                SELECT message.workflow_run_id INTO target_workflow_id
                FROM outbox_messages AS message
                WHERE message.id = COALESCE(NEW.message_id, OLD.message_id);
            END IF;
            IF target_workflow_id IS NULL
               OR NOT ag_workflow_contract_valid(target_workflow_id) THEN
                RAISE EXCEPTION 'workflow W/S/A/M/D contract is inconsistent'
                    USING ERRCODE = '23514', CONSTRAINT = 'ck_workflow_cross_domain_contract';
            END IF;
            RETURN NULL;
        END;
        $function$
    """)
    for table_name, suffix in (
        ("workflow_runs", "workflow"),
        ("stage_runs", "stage"),
        ("stage_attempts", "attempt"),
        ("outbox_messages", "message"),
        ("outbox_delivery_attempts", "delivery"),
    ):
        op.execute(f"""
            CREATE CONSTRAINT TRIGGER trg_workflow_contract_from_{suffix}
            AFTER INSERT OR UPDATE OR DELETE ON {table_name}
            DEFERRABLE INITIALLY DEFERRED
            FOR EACH ROW EXECUTE FUNCTION ag_check_workflow_contract()
        """)


def upgrade() -> None:
    op.execute("LOCK TABLE workflow_runs, stage_runs, outbox_messages, outbox_delivery_attempts, stage_attempts IN ACCESS EXCLUSIVE MODE")
    op.add_column(
        "workflow_runs",
        sa.Column(
            "cancel_request_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
    )
    _create_contract_helpers()
    _preflight_contract()
    _install_outbox_event_clock_contract()

    op.create_unique_constraint(
        "uq_workflow_run_cancel_request",
        "workflow_runs",
        ["cancel_request_id"],
    )
    op.drop_constraint(
        "ck_workflow_run_cancellation_facts",
        "workflow_runs",
        type_="check",
    )
    op.create_check_constraint(
        "ck_workflow_run_cancellation_facts",
        "workflow_runs",
        "(status = 'cancelled' AND cancel_requested_at IS NOT NULL "
        "AND cancel_reason <> '' AND cancel_requested_by <> '' "
        "AND cancel_requested_by_id <> '') OR "
        "(status <> 'cancelled' AND cancel_requested_at IS NULL "
        "AND cancel_reason = '' AND cancel_requested_by = '' "
        "AND cancel_requested_by_id = '' AND cancel_request_id IS NULL)",
    )
    op.create_check_constraint(
        "ck_stage_attempt_receipt_required",
        "stage_attempts",
        "status <> 'running' OR outbox_delivery_attempt_id IS NOT NULL",
    )
    op.create_check_constraint(
        "ck_outbox_delivery_receipt_fingerprint",
        "outbox_delivery_attempts",
        "(status = 'delivered' AND broker_receipt_id ~ '^[0-9a-f]{64}$') OR (status <> 'delivered' AND broker_receipt_id = '')",
    )

    _create_immediate_guards()
    _create_deferred_contract_triggers()


def downgrade() -> None:
    connection = op.get_bind()
    op.execute("LOCK TABLE workflow_runs, stage_runs, outbox_messages, outbox_delivery_attempts, stage_attempts IN ACCESS EXCLUSIVE MODE")
    _require_zero(
        connection,
        "SELECT count(*) FROM workflow_runs WHERE cancel_request_id IS NOT NULL",
        message="Refusing to discard workflow cancellation request authority",
    )
    _require_zero(
        connection,
        f"SELECT count(*) FROM workflow_runs WHERE status IN ({_ACTIVE_WORKFLOW_STATUSES})",
        message="Refusing to weaken the contract while workflows remain active",
    )
    _require_zero(
        connection,
        f"SELECT count(*) FROM outbox_messages WHERE status IN ({_LIVE_MESSAGE_STATUSES})",
        message="Refusing to weaken the contract while outbox messages remain live",
    )
    _require_zero(
        connection,
        "SELECT count(*) FROM stage_attempts WHERE status = 'running'",
        message="Refusing to weaken the contract while stage attempts remain running",
    )

    for table_name, suffix in (
        ("workflow_runs", "workflow"),
        ("stage_runs", "stage"),
        ("stage_attempts", "attempt"),
        ("outbox_messages", "message"),
        ("outbox_delivery_attempts", "delivery"),
    ):
        op.execute(f"DROP TRIGGER IF EXISTS trg_workflow_contract_from_{suffix} ON {table_name}")
    op.execute("DROP FUNCTION IF EXISTS ag_check_workflow_contract()")

    op.execute("DROP TRIGGER IF EXISTS trg_0004_stage_attempt_receipt_contract_guard ON stage_attempts")
    op.execute("DROP FUNCTION IF EXISTS ag_guard_stage_attempt_receipt_contract()")
    op.execute("DROP TRIGGER IF EXISTS trg_0004_outbox_message_parent_contract_guard ON outbox_messages")
    op.execute("DROP FUNCTION IF EXISTS ag_guard_outbox_message_parent_contract()")
    op.execute("DROP TRIGGER IF EXISTS trg_0004_stage_run_plan_guard ON stage_runs")
    op.execute("DROP FUNCTION IF EXISTS ag_guard_stage_run_plan_contract()")
    op.execute("DROP TRIGGER IF EXISTS trg_0004_workflow_contract_plan_guard ON workflow_runs")
    op.execute("DROP FUNCTION IF EXISTS ag_guard_workflow_contract_plan()")

    op.execute("DROP FUNCTION IF EXISTS ag_workflow_contract_valid(uuid)")
    op.execute("DROP FUNCTION IF EXISTS ag_workflow_has_exact_stage_plan(workflow_runs)")
    op.execute("DROP FUNCTION IF EXISTS ag_workflow_stage_matches_plan(workflow_runs, stage_runs)")

    op.drop_constraint(
        "ck_outbox_delivery_receipt_fingerprint",
        "outbox_delivery_attempts",
        type_="check",
    )
    op.drop_constraint(
        "ck_stage_attempt_receipt_required",
        "stage_attempts",
        type_="check",
    )
    op.drop_constraint(
        "ck_workflow_run_cancellation_facts",
        "workflow_runs",
        type_="check",
    )
    op.create_check_constraint(
        "ck_workflow_run_cancellation_facts",
        "workflow_runs",
        "(status = 'cancelled' AND cancel_requested_at IS NOT NULL "
        "AND cancel_reason <> '' AND cancel_requested_by <> '' "
        "AND cancel_requested_by_id <> '') OR "
        "(status <> 'cancelled' AND cancel_requested_at IS NULL "
        "AND cancel_reason = '' AND cancel_requested_by = '' "
        "AND cancel_requested_by_id = '')",
    )
    op.drop_constraint(
        "uq_workflow_run_cancel_request",
        "workflow_runs",
        type_="unique",
    )
    op.drop_column("workflow_runs", "cancel_request_id")
