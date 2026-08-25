"""Ownership and physical-integrity policy for the hybrid migration period."""

from __future__ import annotations

from typing import Any


MIGRATION_OWNED_TABLES = frozenset(
    {
        "research_projects",
        "project_revisions",
        "workflow_runs",
        "stage_runs",
        "stage_attempts",
        "outbox_messages",
        "outbox_delivery_attempts",
    }
)
REQUIRED_SCHEMA_REVISION = "20260824_0004"
# SHA-256 of the canonical PostgreSQL catalog facts for the complete
# migration-owned authority schema.  Startup recomputes this from columns,
# constraints, indexes, triggers, and referenced trigger functions.  Keeping
# it outside the migration prevents a same-name replacement from blessing
# itself by rewriting a database-local marker.
MIGRATION_SCHEMA_AUTHORITY_FINGERPRINT = "05efe0acc78c7a187699eaa2fb4ef24714d9c61342e0731e37575844472d716b"

# Helper functions referenced by CHECK constraints are not trigger entry
# points, so startup must enumerate them explicitly as fingerprint authority.
REQUIRED_MIGRATION_FUNCTIONS = {
    (
        "ag_workflow_stage_matches_plan",
        "workflow_row workflow_runs, stage_row stage_runs",
    ): {
        "language": "plpgsql",
        "result": "boolean",
        "volatility": "s",
        "parallel": "s",
        "security_definer": False,
        "strict": True,
        "config": ("search_path=pg_catalog, public",),
    },
    (
        "ag_workflow_has_exact_stage_plan",
        "workflow_row workflow_runs",
    ): {
        "language": "plpgsql",
        "result": "boolean",
        "volatility": "s",
        "parallel": "u",
        "security_definer": False,
        "strict": True,
        "config": ("search_path=pg_catalog, public",),
    },
    (
        "ag_workflow_contract_valid",
        "target_workflow_id uuid",
    ): {
        "language": "plpgsql",
        "result": "boolean",
        "volatility": "s",
        "parallel": "u",
        "security_definer": False,
        "strict": True,
        "config": ("search_path=pg_catalog, public",),
    },
    (
        "ag_outbox_stage_ready_envelope",
        "workflow_id uuid, stage_id uuid, stage_identity text, target_attempt integer, "
        "stage_input_checksum text, workflow_plan_checksum text",
    ): {
        "language": "sql",
        "result": "text",
        "volatility": "i",
        "parallel": "s",
        "security_definer": False,
        "strict": True,
        "config": ("search_path=pg_catalog",),
    },
    (
        "ag_outbox_stage_ready_logical_key",
        "workflow_id uuid, stage_id uuid, stage_identity text, target_attempt integer",
    ): {
        "language": "sql",
        "result": "text",
        "volatility": "i",
        "parallel": "s",
        "security_definer": False,
        "strict": True,
        "config": ("search_path=pg_catalog",),
    },
    (
        "ag_outbox_delivery_cycle_key",
        "message_logical_key text, target_cycle bigint",
    ): {
        "language": "sql",
        "result": "text",
        "volatility": "i",
        "parallel": "s",
        "security_definer": False,
        "strict": True,
        "config": ("search_path=pg_catalog",),
    },
    (
        "ag_outbox_retry_delay_seconds",
        "message_logical_key text, delivery_attempt integer",
    ): {
        "language": "plpgsql",
        "result": "integer",
        "volatility": "i",
        "parallel": "s",
        "security_definer": False,
        "strict": True,
        "config": ("search_path=pg_catalog",),
    },
}

# Startup checks the physical definition of every critical authority object
# rather than trusting either the Alembic ledger or object names alone.
REQUIRED_MIGRATION_SCHEMA = {
    "research_projects": {
        "primary_key": {"name": "research_projects_pkey", "columns": ("id",)},
        "constraints": {
            "uq_research_project_key": {"type": "u", "validated": True},
            "ck_research_project_key": {"type": "c", "validated": True},
            "ck_research_project_status": {"type": "c", "validated": True},
            "ck_research_project_tlp": {"type": "c", "validated": True},
            "ck_research_project_version": {"type": "c", "validated": True},
            "ck_research_project_archive_facts": {"type": "c", "validated": True},
        },
        "indexes": {
            "ix_research_projects_status_updated": {
                "columns": ("status", "updated_at"),
                "unique": False,
                "predicate": None,
            },
        },
        "triggers": {
            "trg_research_project_authority_guard": {
                "function": "ag_guard_research_project_authority",
                "type_mask": 31,
                "enabled": "O",
            },
        },
    },
    "project_revisions": {
        "primary_key": {"name": "project_revisions_pkey", "columns": ("id",)},
        "constraints": {
            "uq_project_revision_number": {"type": "u", "validated": True},
            "ck_project_revision_number": {"type": "c", "validated": True},
            "ck_project_revision_status": {"type": "c", "validated": True},
            "ck_project_revision_checksum": {"type": "c", "validated": True},
            "ck_project_revision_parent_not_self": {"type": "c", "validated": True},
            "ck_project_revision_revocation_facts": {"type": "c", "validated": True},
            "fk_project_revision_project": {"type": "f", "validated": True},
            "fk_project_revision_parent": {"type": "f", "validated": True},
        },
        "indexes": {
            "uq_project_revision_current": {
                "columns": ("project_id",),
                "unique": True,
                "predicate": {"column": "status", "operator": "eq", "values": ("current",)},
            },
            "ix_project_revisions_parent": {
                "columns": ("parent_revision_id",),
                "unique": False,
                "predicate": None,
            },
            "ix_project_revisions_project_status_revision": {
                "columns": ("project_id", "status", "revision"),
                "unique": False,
                "predicate": None,
            },
            "ix_project_revisions_spec_checksum": {
                "columns": ("spec_checksum",),
                "unique": False,
                "predicate": None,
            },
        },
        "triggers": {
            "trg_project_revision_authority_guard": {
                "function": "ag_guard_project_revision_authority",
                "type_mask": 31,
                "enabled": "O",
            },
        },
    },
    "workflow_runs": {
        "primary_key": {"name": "workflow_runs_pkey", "columns": ("id",)},
        "constraints": {
            "uq_workflow_run_idempotency": {"type": "u", "validated": True},
            "uq_workflow_run_cancel_request": {"type": "u", "validated": True},
            "ck_workflow_run_status": {"type": "c", "validated": True},
            "ck_workflow_run_trigger": {"type": "c", "validated": True},
            "ck_workflow_run_type": {"type": "c", "validated": True},
            "ck_workflow_run_schema_versions": {"type": "c", "validated": True},
            "ck_workflow_run_priority": {"type": "c", "validated": True},
            "ck_workflow_run_state_version": {"type": "c", "validated": True},
            "ck_workflow_run_input_checksum": {"type": "c", "validated": True},
            "ck_workflow_run_plan_checksum": {"type": "c", "validated": True},
            "ck_workflow_run_idempotency_key": {"type": "c", "validated": True},
            "ck_workflow_run_json_shapes": {"type": "c", "validated": True},
            "ck_workflow_run_replay_not_self": {"type": "c", "validated": True},
            "ck_workflow_run_replay_facts": {"type": "c", "validated": True},
            "ck_workflow_run_completion_facts": {"type": "c", "validated": True},
            "ck_workflow_run_start_facts": {"type": "c", "validated": True},
            "ck_workflow_run_cancellation_facts": {"type": "c", "validated": True},
            "ck_workflow_run_reason_facts": {"type": "c", "validated": True},
            "ck_workflow_run_timestamp_order": {"type": "c", "validated": True},
            "fk_workflow_run_project_revision": {"type": "f", "validated": True},
            "fk_workflow_run_replay": {"type": "f", "validated": True},
        },
        "indexes": {
            "ix_workflow_runs_status": {
                "columns": ("status",),
                "unique": False,
                "predicate": None,
            },
            "ix_workflow_runs_project_status_created": {
                "columns": ("project_revision_id", "status", "created_at"),
                "unique": False,
                "predicate": None,
            },
            "ix_workflow_runs_status_created": {
                "columns": ("status", "created_at"),
                "unique": False,
                "predicate": None,
            },
            "ix_workflow_runs_correlation": {
                "columns": ("correlation_id",),
                "unique": False,
                "predicate": None,
            },
        },
        "triggers": {
            "trg_workflow_run_authority_guard": {
                "function": "ag_guard_workflow_run_authority",
                "type_mask": 31,
                "enabled": "O",
            },
            "trg_0004_workflow_contract_plan_guard": {
                "function": "ag_guard_workflow_contract_plan",
                "type_mask": 23,
                "enabled": "O",
            },
            "trg_workflow_contract_from_workflow": {
                "function": "ag_check_workflow_contract",
                "type_mask": 29,
                "enabled": "O",
                "constraint": True,
                "deferrable": True,
                "initially_deferred": True,
            },
        },
    },
    "stage_runs": {
        "primary_key": {"name": "stage_runs_pkey", "columns": ("id",)},
        "constraints": {
            "uq_stage_run_workflow_id": {"type": "u", "validated": True},
            "uq_stage_run_key": {"type": "u", "validated": True},
            "uq_stage_run_ordinal": {"type": "u", "validated": True},
            "uq_stage_run_idempotency": {"type": "u", "validated": True},
            "ck_stage_run_status": {"type": "c", "validated": True},
            "ck_stage_run_ordinal": {"type": "c", "validated": True},
            "ck_stage_run_identity": {"type": "c", "validated": True},
            "ck_stage_run_schema_versions": {"type": "c", "validated": True},
            "ck_stage_run_priority": {"type": "c", "validated": True},
            "ck_stage_run_state_version": {"type": "c", "validated": True},
            "ck_stage_run_attempts": {"type": "c", "validated": True},
            "ck_stage_run_config_checksum": {"type": "c", "validated": True},
            "ck_stage_run_input_checksum": {"type": "c", "validated": True},
            "ck_stage_run_idempotency_key": {"type": "c", "validated": True},
            "ck_stage_run_output_checksum": {"type": "c", "validated": True},
            "ck_stage_run_checkpoint_checksum": {"type": "c", "validated": True},
            "ck_stage_run_checkpoint_version": {"type": "c", "validated": True},
            "ck_stage_run_json_shapes": {"type": "c", "validated": True},
            "ck_stage_run_lease_facts": {"type": "c", "validated": True},
            "ck_stage_run_schedule_facts": {"type": "c", "validated": True},
            "ck_stage_run_completion_facts": {"type": "c", "validated": True},
            "ck_stage_run_start_facts": {"type": "c", "validated": True},
            "ck_stage_run_output_facts": {"type": "c", "validated": True},
            "ck_stage_run_error_facts": {"type": "c", "validated": True},
            "ck_stage_run_lease_order": {"type": "c", "validated": True},
            "ck_stage_run_timestamp_order": {"type": "c", "validated": True},
            "fk_stage_run_workflow": {"type": "f", "validated": True},
        },
        "indexes": {
            "ix_stage_runs_status": {
                "columns": ("status",),
                "unique": False,
                "predicate": None,
            },
            "ix_stage_runs_workflow_status_ordinal": {
                "columns": ("workflow_run_id", "status", "ordinal"),
                "unique": False,
                "predicate": None,
            },
            "ix_stage_runs_claim_ready": {
                "columns": ("next_attempt_at", "priority", "created_at", "id"),
                "unique": False,
                "predicate": {
                    "column": "status",
                    "operator": "in",
                    "values": ("ready", "retry_wait"),
                },
            },
            "ix_stage_runs_expired_lease": {
                "columns": ("lease_expires_at",),
                "unique": False,
                "predicate": {"column": "status", "operator": "eq", "values": ("running",)},
            },
        },
        "triggers": {
            "trg_stage_run_authority_guard": {
                "function": "ag_guard_stage_run_authority",
                "type_mask": 31,
                "enabled": "O",
            },
            "trg_0004_stage_run_plan_guard": {
                "function": "ag_guard_stage_run_plan_contract",
                "type_mask": 7,
                "enabled": "O",
            },
            "trg_stage_authority_consistency_from_stage": {
                "function": "ag_check_stage_authority_consistency",
                "type_mask": 29,
                "enabled": "O",
                "constraint": True,
                "deferrable": True,
                "initially_deferred": True,
            },
            "trg_workflow_contract_from_stage": {
                "function": "ag_check_workflow_contract",
                "type_mask": 29,
                "enabled": "O",
                "constraint": True,
                "deferrable": True,
                "initially_deferred": True,
            },
        },
    },
    "stage_attempts": {
        "primary_key": {"name": "stage_attempts_pkey", "columns": ("id",)},
        "constraints": {
            "uq_stage_attempt_number": {"type": "u", "validated": True},
            "uq_stage_attempt_lease_token": {"type": "u", "validated": True},
            "uq_stage_attempt_outbox_delivery": {"type": "u", "validated": True},
            "ck_stage_attempt_status": {"type": "c", "validated": True},
            "ck_stage_attempt_number": {"type": "c", "validated": True},
            "ck_stage_attempt_state_version": {"type": "c", "validated": True},
            "ck_stage_attempt_input_checksum": {"type": "c", "validated": True},
            "ck_stage_attempt_output_checksum": {"type": "c", "validated": True},
            "ck_stage_attempt_checkpoint_versions": {"type": "c", "validated": True},
            "ck_stage_attempt_completion_facts": {"type": "c", "validated": True},
            "ck_stage_attempt_lease_facts": {"type": "c", "validated": True},
            "ck_stage_attempt_outcome_facts": {"type": "c", "validated": True},
            "ck_stage_attempt_retryable_facts": {"type": "c", "validated": True},
            "ck_stage_attempt_receipt_required": {"type": "c", "validated": True},
            "fk_stage_attempt_stage": {"type": "f", "validated": True},
            "fk_stage_attempt_outbox_delivery": {"type": "f", "validated": True},
        },
        "indexes": {
            "ix_stage_attempts_stage_status": {
                "columns": ("stage_run_id", "status"),
                "unique": False,
                "predicate": None,
            },
            "uq_stage_attempt_running": {
                "columns": ("stage_run_id",),
                "unique": True,
                "predicate": {"column": "status", "operator": "eq", "values": ("running",)},
            },
        },
        "triggers": {
            "trg_stage_attempt_authority_guard": {
                "function": "ag_guard_stage_attempt_authority",
                "type_mask": 31,
                "enabled": "O",
            },
            "trg_stage_attempt_outbox_link_guard": {
                "function": "ag_guard_stage_attempt_outbox_link",
                "type_mask": 23,
                "enabled": "O",
            },
            "trg_0004_stage_attempt_receipt_contract_guard": {
                "function": "ag_guard_stage_attempt_receipt_contract",
                "type_mask": 7,
                "enabled": "O",
            },
            "trg_stage_authority_consistency_from_attempt": {
                "function": "ag_check_stage_authority_consistency",
                "type_mask": 29,
                "enabled": "O",
                "constraint": True,
                "deferrable": True,
                "initially_deferred": True,
            },
            "trg_workflow_contract_from_attempt": {
                "function": "ag_check_workflow_contract",
                "type_mask": 29,
                "enabled": "O",
                "constraint": True,
                "deferrable": True,
                "initially_deferred": True,
            },
        },
    },
    "outbox_messages": {
        "primary_key": {"name": "outbox_messages_pkey", "columns": ("id",)},
        "constraints": {
            "uq_outbox_message_logical_redrive": {"type": "u", "validated": True},
            "uq_outbox_message_redrive_parent": {"type": "u", "validated": True},
            "ck_outbox_message_status": {"type": "c", "validated": True},
            "ck_outbox_message_registry_identity": {"type": "c", "validated": True},
            "ck_outbox_message_emission_kind": {"type": "c", "validated": True},
            "ck_outbox_message_versions": {"type": "c", "validated": True},
            "ck_outbox_message_target_attempt": {"type": "c", "validated": True},
            "ck_outbox_message_checksums": {"type": "c", "validated": True},
            "ck_outbox_message_envelope_authority": {"type": "c", "validated": True},
            "ck_outbox_message_logical_authority": {"type": "c", "validated": True},
            "ck_outbox_message_delivery_counts": {"type": "c", "validated": True},
            "ck_outbox_message_cycle_authority": {"type": "c", "validated": True},
            "ck_outbox_message_schedule_facts": {"type": "c", "validated": True},
            "ck_outbox_message_active_facts": {"type": "c", "validated": True},
            "ck_outbox_message_lease_facts": {"type": "c", "validated": True},
            "ck_outbox_message_lease_order": {"type": "c", "validated": True},
            "ck_outbox_message_receipt_facts": {"type": "c", "validated": True},
            "ck_outbox_message_error_facts": {"type": "c", "validated": True},
            "ck_outbox_message_error_required": {"type": "c", "validated": True},
            "ck_outbox_message_terminal_facts": {"type": "c", "validated": True},
            "ck_outbox_message_cancellation_facts": {"type": "c", "validated": True},
            "ck_outbox_message_redrive_facts": {"type": "c", "validated": True},
            "ck_outbox_message_parent_not_self": {"type": "c", "validated": True},
            "ck_outbox_message_timestamp_order": {"type": "c", "validated": True},
            "fk_outbox_message_workflow": {"type": "f", "validated": True},
            "fk_outbox_message_stage_workflow": {"type": "f", "validated": True},
            "fk_outbox_message_redrive_parent": {"type": "f", "validated": True},
            "fk_outbox_message_active_delivery": {"type": "f", "validated": True},
        },
        "indexes": {
            "uq_outbox_message_active_logical": {
                "columns": ("logical_key",),
                "unique": True,
                "predicate": {
                    "column": "status",
                    "operator": "in",
                    "values": (
                        "pending",
                        "dispatching",
                        "awaiting_receipt",
                        "retry_wait",
                    ),
                },
            },
            "ix_outbox_messages_claim": {
                "columns": ("available_at", "created_at", "id"),
                "unique": False,
                "predicate": {
                    "column": "status",
                    "operator": "in",
                    "values": ("pending", "retry_wait"),
                },
            },
            "ix_outbox_messages_dispatch_lease": {
                "columns": ("lease_expires_at", "id"),
                "unique": False,
                "predicate": {
                    "column": "status",
                    "operator": "eq",
                    "values": ("dispatching",),
                },
            },
            "ix_outbox_messages_receipt_deadline": {
                "columns": ("receipt_deadline_at", "id"),
                "unique": False,
                "predicate": {
                    "column": "status",
                    "operator": "eq",
                    "values": ("awaiting_receipt",),
                },
            },
            "ix_outbox_messages_stage_target": {
                "columns": ("stage_run_id", "target_attempt_number", "redrive_ordinal"),
                "unique": False,
                "predicate": None,
            },
            "ix_outbox_messages_stage_active": {
                "columns": ("stage_run_id", "target_attempt_number", "id"),
                "unique": False,
                "predicate": {
                    "column": "status",
                    "operator": "in",
                    "values": (
                        "pending",
                        "dispatching",
                        "awaiting_receipt",
                        "retry_wait",
                    ),
                },
            },
            "ix_outbox_messages_workflow_status_created": {
                "columns": ("workflow_run_id", "status", "created_at"),
                "unique": False,
                "predicate": None,
            },
        },
        "triggers": {
            "trg_outbox_message_authority_guard": {
                "function": "ag_guard_outbox_message_authority",
                "type_mask": 31,
                "enabled": "O",
            },
            "trg_outbox_message_delivery_clock_guard": {
                "function": "ag_align_outbox_message_delivery_time",
                "type_mask": 19,
                "enabled": "O",
            },
            "trg_0004_outbox_message_parent_contract_guard": {
                "function": "ag_guard_outbox_message_parent_contract",
                "type_mask": 7,
                "enabled": "O",
            },
            "trg_outbox_delivery_consistency_from_message": {
                "function": "ag_check_outbox_delivery_consistency",
                "type_mask": 29,
                "enabled": "O",
                "constraint": True,
                "deferrable": True,
                "initially_deferred": True,
            },
            "trg_workflow_contract_from_message": {
                "function": "ag_check_workflow_contract",
                "type_mask": 29,
                "enabled": "O",
                "constraint": True,
                "deferrable": True,
                "initially_deferred": True,
            },
        },
    },
    "outbox_delivery_attempts": {
        "primary_key": {
            "name": "outbox_delivery_attempts_pkey",
            "columns": ("id",),
        },
        "constraints": {
            "uq_outbox_delivery_message_id": {"type": "u", "validated": True},
            "uq_outbox_delivery_message_cycle": {"type": "u", "validated": True},
            "uq_outbox_delivery_message_attempt": {"type": "u", "validated": True},
            "uq_outbox_delivery_token": {"type": "u", "validated": True},
            "uq_outbox_delivery_cycle_key": {"type": "u", "validated": True},
            "ck_outbox_delivery_status": {"type": "c", "validated": True},
            "ck_outbox_delivery_numbers": {"type": "c", "validated": True},
            "ck_outbox_delivery_state_version": {"type": "c", "validated": True},
            "ck_outbox_delivery_cycle_key": {"type": "c", "validated": True},
            "ck_outbox_delivery_lease_facts": {"type": "c", "validated": True},
            "ck_outbox_delivery_broker_facts": {"type": "c", "validated": True},
            "ck_outbox_delivery_completion_facts": {"type": "c", "validated": True},
            "ck_outbox_delivery_error_facts": {"type": "c", "validated": True},
            "ck_outbox_delivery_retryable_facts": {"type": "c", "validated": True},
            "ck_outbox_delivery_receipt_fingerprint": {"type": "c", "validated": True},
            "ck_outbox_delivery_timestamp_order": {"type": "c", "validated": True},
            "fk_outbox_delivery_message": {"type": "f", "validated": True},
        },
        "indexes": {
            "uq_outbox_delivery_active_message": {
                "columns": ("message_id",),
                "unique": True,
                "predicate": {
                    "column": "status",
                    "operator": "in",
                    "values": ("dispatching", "awaiting_receipt"),
                },
            },
            "ix_outbox_delivery_message_status_attempt": {
                "columns": ("message_id", "status", "attempt_number"),
                "unique": False,
                "predicate": None,
            },
            "ix_outbox_delivery_dispatch_lease": {
                "columns": ("lease_expires_at", "id"),
                "unique": False,
                "predicate": {
                    "column": "status",
                    "operator": "eq",
                    "values": ("dispatching",),
                },
            },
            "ix_outbox_delivery_receipt_deadline": {
                "columns": ("receipt_deadline_at", "id"),
                "unique": False,
                "predicate": {
                    "column": "status",
                    "operator": "eq",
                    "values": ("awaiting_receipt",),
                },
            },
        },
        "triggers": {
            "trg_outbox_delivery_authority_guard": {
                "function": "ag_guard_outbox_delivery_authority",
                "type_mask": 31,
                "enabled": "O",
            },
            "trg_outbox_delivery_consistency_from_attempt": {
                "function": "ag_check_outbox_delivery_consistency",
                "type_mask": 29,
                "enabled": "O",
                "constraint": True,
                "deferrable": True,
                "initially_deferred": True,
            },
            "trg_workflow_contract_from_delivery": {
                "function": "ag_check_workflow_contract",
                "type_mask": 29,
                "enabled": "O",
                "constraint": True,
                "deferrable": True,
                "initially_deferred": True,
            },
        },
    },
}


def include_migration_name(
    name: str | None,
    type_: str,
    parent_names: dict[str, str | None],
) -> bool:
    """Prevent Alembic autogenerate from treating legacy tables as removals."""

    if type_ == "table":
        return name in MIGRATION_OWNED_TABLES
    table_name = parent_names.get("table_name")
    return table_name is None or table_name in MIGRATION_OWNED_TABLES


def include_migration_object(
    object_: Any,
    name: str | None,
    type_: str,
    reflected: bool,
    compare_to: Any,
) -> bool:
    """Object-level companion filter for offline and online comparison."""

    del name, reflected
    if type_ == "table":
        return getattr(object_, "name", None) in MIGRATION_OWNED_TABLES
    table = getattr(object_, "table", None)
    if table is None and compare_to is not None:
        table = getattr(compare_to, "table", None)
    return table is None or getattr(table, "name", None) in MIGRATION_OWNED_TABLES
