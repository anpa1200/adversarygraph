from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

from app.core.migration_policy import REQUIRED_MIGRATION_SCHEMA
from app.models.research_workflow import (
    OutboxDeliveryAttempt,
    OutboxMessage,
    OUTBOX_V1_MAX_ATTEMPTS,
    ProjectRevision,
    ResearchProject,
    StageAttempt,
    StageRun,
    WorkflowRun,
)
from app.services.outbox_engine import MAX_OUTBOX_CANONICAL_BYTES


def _constraint(table, name):
    return next(item for item in table.constraints if item.name == name)


def _foreign_key(column):
    keys = list(column.foreign_keys)
    assert len(keys) == 1
    return keys[0]


def test_research_project_authority_constraints_are_registered():
    table = ResearchProject.__table__

    assert _constraint(table, "uq_research_project_key") is not None
    assert _constraint(table, "ck_research_project_key") is not None
    assert _constraint(table, "ck_research_project_status") is not None
    assert _constraint(table, "ck_research_project_tlp") is not None
    assert _constraint(table, "ck_research_project_version") is not None
    assert _constraint(table, "ck_research_project_archive_facts") is not None
    assert "ix_research_projects_status_updated" in {index.name for index in table.indexes}


def test_project_revision_is_delete_protected_and_lineage_constrained():
    table = ProjectRevision.__table__
    project_fk = _foreign_key(table.c.project_id)
    parent_fk = _foreign_key(table.c.parent_revision_id)

    assert project_fk.target_fullname == "research_projects.id"
    assert project_fk.ondelete == "RESTRICT"
    assert parent_fk.target_fullname == "project_revisions.id"
    assert parent_fk.ondelete == "RESTRICT"
    assert _constraint(table, "uq_project_revision_number") is not None
    assert _constraint(table, "ck_project_revision_checksum") is not None
    assert _constraint(table, "ck_project_revision_parent_not_self") is not None
    assert _constraint(table, "ck_project_revision_revocation_facts") is not None


def test_project_revision_has_one_current_revision_partial_unique_index():
    index = next(item for item in ProjectRevision.__table__.indexes if item.name == "uq_project_revision_current")

    assert index.unique is True
    predicate = str(index.dialect_options["postgresql"]["where"])
    assert predicate == "status = 'current'"


def test_research_tables_compile_for_postgresql():
    dialect = postgresql.dialect()

    project_ddl = str(CreateTable(ResearchProject.__table__).compile(dialect=dialect))
    revision_ddl = str(CreateTable(ProjectRevision.__table__).compile(dialect=dialect))

    assert "CONSTRAINT ck_research_project_key CHECK" in project_ddl
    assert "FOREIGN KEY(project_id) REFERENCES research_projects" in revision_ddl
    assert "ON DELETE RESTRICT" in revision_ddl


def test_workflow_chain_is_delete_protected_and_idempotent():
    workflow_fk = _foreign_key(WorkflowRun.__table__.c.project_revision_id)
    stage_fk = _foreign_key(StageRun.__table__.c.workflow_run_id)
    attempt_fk = _foreign_key(StageAttempt.__table__.c.stage_run_id)

    assert workflow_fk.target_fullname == "project_revisions.id"
    assert stage_fk.target_fullname == "workflow_runs.id"
    assert attempt_fk.target_fullname == "stage_runs.id"
    assert workflow_fk.ondelete == "RESTRICT"
    assert stage_fk.ondelete == "RESTRICT"
    assert attempt_fk.ondelete == "RESTRICT"
    assert _constraint(WorkflowRun.__table__, "uq_workflow_run_idempotency")
    assert _constraint(StageRun.__table__, "uq_stage_run_idempotency")
    assert _constraint(StageAttempt.__table__, "uq_stage_attempt_lease_token")


def test_workflow_plan_priority_and_terminal_constraints_exist():
    table = WorkflowRun.__table__

    for name in (
        "ck_workflow_run_type",
        "ck_workflow_run_schema_versions",
        "ck_workflow_run_priority",
        "ck_workflow_run_state_version",
        "ck_workflow_run_plan_checksum",
        "ck_workflow_run_json_shapes",
        "ck_workflow_run_replay_facts",
        "ck_workflow_run_completion_facts",
        "ck_workflow_run_start_facts",
        "ck_workflow_run_cancellation_facts",
        "ck_workflow_run_reason_facts",
        "ck_workflow_run_timestamp_order",
    ):
        assert _constraint(table, name) is not None
    assert _constraint(table, "uq_workflow_run_cancel_request") is not None
    assert table.c.cancel_request_id.nullable is True
    cancellation = str(_constraint(table, "ck_workflow_run_cancellation_facts").sqltext)
    assert "cancel_request_id IS NULL" in cancellation
    assert {
        "stage_plan",
        "plan_schema_version",
        "plan_checksum",
        "priority",
        "cancel_request_id",
    } <= {column.name for column in table.columns}


def test_stage_lease_schedule_checkpoint_and_completion_constraints_exist():
    table = StageRun.__table__

    for name in (
        "ck_stage_run_identity",
        "ck_stage_run_schema_versions",
        "ck_stage_run_priority",
        "ck_stage_run_state_version",
        "ck_stage_run_attempts",
        "ck_stage_run_config_checksum",
        "ck_stage_run_checkpoint_version",
        "ck_stage_run_json_shapes",
        "ck_stage_run_lease_facts",
        "ck_stage_run_schedule_facts",
        "ck_stage_run_completion_facts",
        "ck_stage_run_start_facts",
        "ck_stage_run_output_facts",
        "ck_stage_run_error_facts",
        "ck_stage_run_lease_order",
        "ck_stage_run_timestamp_order",
    ):
        assert _constraint(table, name) is not None
    schedule = str(_constraint(table, "ck_stage_run_schedule_facts").sqltext)
    assert "status IN ('ready', 'retry_wait')" in schedule
    assert {
        "stage_type",
        "required",
        "priority",
        "config_schema_version",
        "config",
        "config_checksum",
        "checkpoint_version",
        "state_version",
    } <= {column.name for column in table.columns}
    indexes = {index.name: index for index in table.indexes}
    assert str(indexes["ix_stage_runs_claim_ready"].dialect_options["postgresql"]["where"]) == "status IN ('ready', 'retry_wait')"
    assert str(indexes["ix_stage_runs_expired_lease"].dialect_options["postgresql"]["where"]) == "status = 'running'"


def test_attempt_records_contain_fencing_and_checkpoint_evidence():
    table = StageAttempt.__table__

    for name in (
        "ck_stage_attempt_checkpoint_versions",
        "ck_stage_attempt_state_version",
        "ck_stage_attempt_completion_facts",
        "ck_stage_attempt_lease_facts",
        "ck_stage_attempt_outcome_facts",
        "ck_stage_attempt_retryable_facts",
        "ck_stage_attempt_receipt_required",
    ):
        assert _constraint(table, name) is not None
    assert {
        "lease_token",
        "lease_owner",
        "delivery_id",
        "checkpoint_start_version",
        "checkpoint_end_version",
        "heartbeat_at",
        "lease_expires_at",
        "state_version",
        "outbox_delivery_attempt_id",
    } <= {column.name for column in table.columns}
    running_index = next(item for item in table.indexes if item.name == "uq_stage_attempt_running")
    assert running_index.unique is True
    assert str(running_index.dialect_options["postgresql"]["where"]) == "status = 'running'"
    receipt_required = str(_constraint(table, "ck_stage_attempt_receipt_required").sqltext)
    assert receipt_required == "status <> 'running' OR outbox_delivery_attempt_id IS NOT NULL"


def test_workflow_tables_compile_for_postgresql():
    dialect = postgresql.dialect()

    workflow_ddl = str(CreateTable(WorkflowRun.__table__).compile(dialect=dialect))
    stage_ddl = str(CreateTable(StageRun.__table__).compile(dialect=dialect))
    attempt_ddl = str(CreateTable(StageAttempt.__table__).compile(dialect=dialect))
    message_ddl = str(CreateTable(OutboxMessage.__table__).compile(dialect=dialect))
    delivery_ddl = str(CreateTable(OutboxDeliveryAttempt.__table__).compile(dialect=dialect))

    assert "CONSTRAINT ck_workflow_run_completion_facts CHECK" in workflow_ddl
    assert "CONSTRAINT ck_stage_run_lease_facts CHECK" in stage_ddl
    assert "CONSTRAINT ck_stage_attempt_completion_facts CHECK" in attempt_ddl
    assert "CONSTRAINT ck_stage_attempt_receipt_required CHECK" in attempt_ddl
    assert "CONSTRAINT ck_outbox_message_envelope_authority CHECK" in message_ddl
    assert "CONSTRAINT ck_outbox_delivery_completion_facts CHECK" in delivery_ddl
    assert "CONSTRAINT ck_outbox_delivery_receipt_fingerprint CHECK" in delivery_ddl


def test_outbox_models_are_receipt_contracted_with_historical_null_compatibility():
    message = OutboxMessage.__table__
    delivery = OutboxDeliveryAttempt.__table__
    stage_attempt = StageAttempt.__table__

    assert stage_attempt.c.outbox_delivery_attempt_id.nullable is True
    receipt_fk = _foreign_key(stage_attempt.c.outbox_delivery_attempt_id)
    assert receipt_fk.target_fullname == "outbox_delivery_attempts.id"
    assert receipt_fk.ondelete == "RESTRICT"
    assert _constraint(stage_attempt, "uq_stage_attempt_outbox_delivery")
    for name in (
        "ck_outbox_message_registry_identity",
        "ck_outbox_message_envelope_authority",
        "ck_outbox_message_logical_authority",
        "ck_outbox_message_cycle_authority",
        "ck_outbox_message_redrive_facts",
        "ck_outbox_message_terminal_facts",
    ):
        assert _constraint(message, name) is not None
    for name in (
        "ck_outbox_delivery_numbers",
        "ck_outbox_delivery_lease_facts",
        "ck_outbox_delivery_completion_facts",
        "ck_outbox_delivery_error_facts",
        "ck_outbox_delivery_receipt_fingerprint",
    ):
        assert _constraint(delivery, name) is not None
    assert message.c.envelope_canonical.type.python_type is str
    assert message.c.max_attempts.default is None
    delivery_counts_check = str(_constraint(message, "ck_outbox_message_delivery_counts").sqltext)
    assert f"max_attempts = {OUTBOX_V1_MAX_ATTEMPTS}" in delivery_counts_check
    assert "max_attempts BETWEEN" not in delivery_counts_check
    assert "ix_outbox_messages_stage_active" in {index.name for index in message.indexes}
    envelope_check = str(_constraint(message, "ck_outbox_message_envelope_authority").sqltext)
    assert f"envelope_bytes BETWEEN 1 AND {MAX_OUTBOX_CANONICAL_BYTES}" in envelope_check
    message_error_check = str(_constraint(message, "ck_outbox_message_error_facts").sqltext)
    delivery_error_check = str(_constraint(delivery, "ck_outbox_delivery_error_facts").sqltext)
    expected_error_class = "^[A-Za-z][A-Za-z0-9_.-]{0,119}$"
    assert expected_error_class in message_error_check
    assert expected_error_class in delivery_error_check
    receipt_check = str(_constraint(delivery, "ck_outbox_delivery_receipt_fingerprint").sqltext)
    assert "status = 'delivered' AND broker_receipt_id ~ '^[0-9a-f]{64}$'" in receipt_check
    assert "status <> 'delivered' AND broker_receipt_id = ''" in receipt_check


def test_workflow_model_and_startup_physical_policy_are_exactly_aligned():
    for model in (
        WorkflowRun,
        StageRun,
        StageAttempt,
        OutboxMessage,
        OutboxDeliveryAttempt,
    ):
        table = model.__table__
        policy = REQUIRED_MIGRATION_SCHEMA[table.name]
        assert {constraint.name for constraint in table.constraints if constraint.name} == set(policy["constraints"])
        assert {index.name for index in table.indexes} == set(policy["indexes"])


def test_every_authority_table_has_exact_primary_key_and_guard_policy():
    expected_guard = {
        "research_projects": "trg_research_project_authority_guard",
        "project_revisions": "trg_project_revision_authority_guard",
        "workflow_runs": "trg_workflow_run_authority_guard",
        "stage_runs": "trg_stage_run_authority_guard",
        "stage_attempts": "trg_stage_attempt_authority_guard",
        "outbox_messages": "trg_outbox_message_authority_guard",
        "outbox_delivery_attempts": "trg_outbox_delivery_authority_guard",
    }
    for model in (
        ResearchProject,
        ProjectRevision,
        WorkflowRun,
        StageRun,
        StageAttempt,
        OutboxMessage,
        OutboxDeliveryAttempt,
    ):
        table = model.__table__
        policy = REQUIRED_MIGRATION_SCHEMA[table.name]
        assert policy["primary_key"] == {
            "name": f"{table.name}_pkey",
            "columns": ("id",),
        }
        guard = policy["triggers"][expected_guard[table.name]]
        assert guard["enabled"] == "O"
        assert guard["type_mask"] == 31


def test_deferred_stage_consistency_trigger_policy_is_symmetric():
    for table_name, trigger_name in (
        ("stage_runs", "trg_stage_authority_consistency_from_stage"),
        ("stage_attempts", "trg_stage_authority_consistency_from_attempt"),
    ):
        trigger = REQUIRED_MIGRATION_SCHEMA[table_name]["triggers"][trigger_name]
        assert trigger == {
            "function": "ag_check_stage_authority_consistency",
            "type_mask": 29,
            "enabled": "O",
            "constraint": True,
            "deferrable": True,
            "initially_deferred": True,
        }


def test_deferred_outbox_delivery_consistency_trigger_policy_is_symmetric():
    for table_name, trigger_name in (
        ("outbox_messages", "trg_outbox_delivery_consistency_from_message"),
        (
            "outbox_delivery_attempts",
            "trg_outbox_delivery_consistency_from_attempt",
        ),
    ):
        trigger = REQUIRED_MIGRATION_SCHEMA[table_name]["triggers"][trigger_name]
        assert trigger == {
            "function": "ag_check_outbox_delivery_consistency",
            "type_mask": 29,
            "enabled": "O",
            "constraint": True,
            "deferrable": True,
            "initially_deferred": True,
        }


def test_deferred_workflow_contract_trigger_policy_covers_every_domain():
    for table_name, trigger_name in (
        ("workflow_runs", "trg_workflow_contract_from_workflow"),
        ("stage_runs", "trg_workflow_contract_from_stage"),
        ("stage_attempts", "trg_workflow_contract_from_attempt"),
        ("outbox_messages", "trg_workflow_contract_from_message"),
        ("outbox_delivery_attempts", "trg_workflow_contract_from_delivery"),
    ):
        assert REQUIRED_MIGRATION_SCHEMA[table_name]["triggers"][trigger_name] == {
            "function": "ag_check_workflow_contract",
            "type_mask": 29,
            "enabled": "O",
            "constraint": True,
            "deferrable": True,
            "initially_deferred": True,
        }


def test_0004_immediate_guards_are_ordered_before_legacy_authority_guards():
    expected = {
        "workflow_runs": (
            "trg_0004_workflow_contract_plan_guard",
            "ag_guard_workflow_contract_plan",
            23,
        ),
        "stage_runs": (
            "trg_0004_stage_run_plan_guard",
            "ag_guard_stage_run_plan_contract",
            7,
        ),
        "outbox_messages": (
            "trg_0004_outbox_message_parent_contract_guard",
            "ag_guard_outbox_message_parent_contract",
            7,
        ),
        "stage_attempts": (
            "trg_0004_stage_attempt_receipt_contract_guard",
            "ag_guard_stage_attempt_receipt_contract",
            7,
        ),
    }
    for table_name, (trigger_name, function_name, type_mask) in expected.items():
        trigger = REQUIRED_MIGRATION_SCHEMA[table_name]["triggers"][trigger_name]
        assert trigger == {
            "function": function_name,
            "type_mask": type_mask,
            "enabled": "O",
        }
        legacy_names = [
            name
            for name in REQUIRED_MIGRATION_SCHEMA[table_name]["triggers"]
            if name != trigger_name and not name.startswith("trg_workflow_contract_from_")
        ]
        assert all(trigger_name < legacy_name for legacy_name in legacy_names)
