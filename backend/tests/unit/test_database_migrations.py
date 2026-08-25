from pathlib import Path
import re

import pytest

from app.core.database import (
    MIGRATION_OWNED_TABLES,
    _authority_schema_fingerprint,
    _decode_catalog_char,
    _index_predicate_matches,
    _normalize_catalog_definition,
    startup_managed_tables,
)
from app.core.migration_policy import (
    MIGRATION_SCHEMA_AUTHORITY_FINGERPRINT,
    REQUIRED_MIGRATION_FUNCTIONS,
    REQUIRED_MIGRATION_SCHEMA,
    REQUIRED_SCHEMA_REVISION,
    include_migration_name,
    include_migration_object,
)


def test_research_authority_tables_are_not_owned_by_startup_create_all():
    startup_names = {table.name for table in startup_managed_tables()}

    assert MIGRATION_OWNED_TABLES == {
        "research_projects",
        "project_revisions",
        "workflow_runs",
        "stage_runs",
        "stage_attempts",
        "outbox_messages",
        "outbox_delivery_attempts",
    }
    assert MIGRATION_OWNED_TABLES.isdisjoint(startup_names)


def test_first_formal_revision_and_operator_config_are_present():
    backend_root = Path(__file__).resolve().parents[2]
    migration = (backend_root / "alembic" / "versions" / "20260823_0001_research_projects.py").read_text(encoding="utf-8")
    config = (backend_root / "alembic.ini").read_text(encoding="utf-8")

    assert 'revision: str = "20260823_0001"' in migration
    assert "down_revision: str | None = None" in migration
    assert '"research_projects"' in migration
    assert '"project_revisions"' in migration
    assert "script_location = %(here)s/alembic" in config

    workflow_migration = (backend_root / "alembic" / "versions" / "20260823_0002_workflow_runs.py").read_text(encoding="utf-8")
    assert 'revision: str = "20260823_0002"' in workflow_migration
    assert 'down_revision: str | None = "20260823_0001"' in workflow_migration
    assert '"workflow_runs"' in workflow_migration
    assert '"stage_runs"' in workflow_migration
    assert '"stage_attempts"' in workflow_migration
    assert 'name="ck_workflow_run_plan_checksum"' in workflow_migration
    assert 'name="ck_stage_run_schedule_facts"' in workflow_migration
    assert 'name="ck_stage_attempt_lease_facts"' in workflow_migration
    assert 'name="ck_stage_attempt_state_version"' in workflow_migration
    assert '"uq_stage_attempt_running"' in workflow_migration
    assert "trg_project_revision_authority_guard" in workflow_migration
    assert "trg_research_project_authority_guard" in workflow_migration
    assert "trg_workflow_run_authority_guard" in workflow_migration
    assert "trg_stage_run_authority_guard" in workflow_migration
    assert "trg_stage_attempt_authority_guard" in workflow_migration
    assert "CREATE CONSTRAINT TRIGGER trg_stage_authority_consistency_from_stage" in workflow_migration
    assert "CREATE CONSTRAINT TRIGGER trg_stage_authority_consistency_from_attempt" in workflow_migration
    assert "DEFERRABLE INITIALLY DEFERRED" in workflow_migration
    outbox_migration = (backend_root / "alembic" / "versions" / "20260823_0003_outbox.py").read_text(encoding="utf-8")
    assert 'revision: str = "20260823_0003"' in outbox_migration
    assert 'down_revision: str | None = "20260823_0002"' in outbox_migration
    assert '"outbox_messages"' in outbox_migration
    assert '"outbox_delivery_attempts"' in outbox_migration
    assert "ag_outbox_stage_ready_envelope" in outbox_migration
    assert "ag_outbox_retry_delay_seconds" in outbox_migration
    assert "trg_outbox_message_authority_guard" in outbox_migration
    assert "trg_outbox_message_delivery_clock_guard" in outbox_migration
    assert "wall_now timestamptz" in outbox_migration
    assert "NEW.receipt_received_at := event_at" in outbox_migration
    assert "trg_outbox_delivery_consistency_from_attempt" in outbox_migration
    assert "only untouched migration_backfill messages" in outbox_migration
    contract_migration = (backend_root / "alembic" / "versions" / "20260824_0004_workflow_contract.py").read_text(encoding="utf-8")
    assert 'revision: str = "20260824_0004"' in contract_migration
    assert 'down_revision: str | None = "20260823_0003"' in contract_migration
    assert "ag_workflow_stage_matches_plan" in contract_migration
    assert "ag_workflow_contract_valid" in contract_migration
    assert "CREATE CONSTRAINT TRIGGER trg_workflow_contract_from_{suffix}" in contract_migration
    assert '("workflow_runs", "workflow")' in contract_migration
    assert '("outbox_delivery_attempts", "delivery")' in contract_migration
    assert "ck_stage_attempt_receipt_required" in contract_migration
    assert "ck_outbox_delivery_receipt_fingerprint" in contract_migration
    assert "uq_workflow_run_cancel_request" in contract_migration
    assert "CREATE OR REPLACE FUNCTION ag_guard_outbox_delivery_authority()" in contract_migration
    assert "CREATE OR REPLACE FUNCTION ag_align_outbox_message_delivery_time()" in contract_migration
    assert REQUIRED_SCHEMA_REVISION == "20260824_0004"


def test_autogenerate_scope_never_treats_legacy_tables_as_owned():
    assert include_migration_name("workflow_runs", "table", {"schema_name": None})
    assert not include_migration_name("analysis_sessions", "table", {"schema_name": None})
    assert include_migration_name(
        "ix_stage_runs_claim_ready",
        "index",
        {"table_name": "stage_runs"},
    )
    assert not include_migration_name(
        "ix_analysis_sessions_status",
        "index",
        {"table_name": "analysis_sessions"},
    )

    class _Table:
        def __init__(self, name):
            self.name = name

    assert include_migration_object(
        _Table("research_projects"),
        "research_projects",
        "table",
        True,
        None,
    )
    assert not include_migration_object(
        _Table("report_intake"),
        "report_intake",
        "table",
        True,
        None,
    )


def test_startup_physical_schema_policy_covers_every_owned_table():
    assert set(REQUIRED_MIGRATION_SCHEMA) == MIGRATION_OWNED_TABLES
    assert "trg_project_revision_authority_guard" in REQUIRED_MIGRATION_SCHEMA["project_revisions"]["triggers"]
    assert "ix_stage_runs_claim_ready" in REQUIRED_MIGRATION_SCHEMA["stage_runs"]["indexes"]
    assert "ck_workflow_run_plan_checksum" in REQUIRED_MIGRATION_SCHEMA["workflow_runs"]["constraints"]
    assert "ck_stage_run_schedule_facts" in REQUIRED_MIGRATION_SCHEMA["stage_runs"]["constraints"]
    assert "ck_stage_attempt_lease_facts" in REQUIRED_MIGRATION_SCHEMA["stage_attempts"]["constraints"]
    assert "uq_stage_attempt_running" in REQUIRED_MIGRATION_SCHEMA["stage_attempts"]["indexes"]
    assert "trg_outbox_message_authority_guard" in REQUIRED_MIGRATION_SCHEMA["outbox_messages"]["triggers"]
    assert "trg_outbox_message_delivery_clock_guard" in REQUIRED_MIGRATION_SCHEMA["outbox_messages"]["triggers"]
    assert "uq_outbox_delivery_active_message" in REQUIRED_MIGRATION_SCHEMA["outbox_delivery_attempts"]["indexes"]
    for table_name, policy in REQUIRED_MIGRATION_SCHEMA.items():
        assert policy["primary_key"] == {
            "name": f"{table_name}_pkey",
            "columns": ("id",),
        }
        assert all(
            definition["validated"] is True and definition["type"] in {"c", "f", "u"} for definition in policy["constraints"].values()
        )
        assert all({"columns", "unique", "predicate"} <= set(definition) for definition in policy["indexes"].values())
        assert all(definition["enabled"] == "O" for definition in policy["triggers"].values())
    assert re.fullmatch(r"[0-9a-f]{64}", MIGRATION_SCHEMA_AUTHORITY_FINGERPRINT)
    assert MIGRATION_SCHEMA_AUTHORITY_FINGERPRINT != "0" * 64


def test_migration_helpers_are_explicit_physical_authority():
    assert {name for name, _ in REQUIRED_MIGRATION_FUNCTIONS} == {
        "ag_workflow_stage_matches_plan",
        "ag_workflow_has_exact_stage_plan",
        "ag_workflow_contract_valid",
        "ag_outbox_stage_ready_envelope",
        "ag_outbox_stage_ready_logical_key",
        "ag_outbox_delivery_cycle_key",
        "ag_outbox_retry_delay_seconds",
    }
    text_helpers = {
        identity: expected
        for identity, expected in REQUIRED_MIGRATION_FUNCTIONS.items()
        if identity[0]
        in {
            "ag_outbox_stage_ready_envelope",
            "ag_outbox_stage_ready_logical_key",
            "ag_outbox_delivery_cycle_key",
        }
    }
    for expected in text_helpers.values():
        assert expected == {
            "language": "sql",
            "result": "text",
            "volatility": "i",
            "parallel": "s",
            "security_definer": False,
            "strict": True,
            "config": ("search_path=pg_catalog",),
        }
    assert REQUIRED_MIGRATION_FUNCTIONS[
        (
            "ag_outbox_retry_delay_seconds",
            "message_logical_key text, delivery_attempt integer",
        )
    ] == {
        "language": "plpgsql",
        "result": "integer",
        "volatility": "i",
        "parallel": "s",
        "security_definer": False,
        "strict": True,
        "config": ("search_path=pg_catalog",),
    }
    assert REQUIRED_MIGRATION_FUNCTIONS[
        (
            "ag_workflow_stage_matches_plan",
            "workflow_row workflow_runs, stage_row stage_runs",
        )
    ] == {
        "language": "plpgsql",
        "result": "boolean",
        "volatility": "s",
        "parallel": "s",
        "security_definer": False,
        "strict": True,
        "config": ("search_path=pg_catalog, public",),
    }
    for identity in (
        (
            "ag_workflow_has_exact_stage_plan",
            "workflow_row workflow_runs",
        ),
        ("ag_workflow_contract_valid", "target_workflow_id uuid"),
    ):
        assert REQUIRED_MIGRATION_FUNCTIONS[identity] == {
            "language": "plpgsql",
            "result": "boolean",
            "volatility": "s",
            "parallel": "u",
            "security_definer": False,
            "strict": True,
            "config": ("search_path=pg_catalog, public",),
        }


def test_workflow_contract_migration_is_serialized_deferred_and_fail_closed():
    migration_path = Path(__file__).resolve().parents[2] / "alembic" / "versions" / "20260824_0004_workflow_contract.py"
    migration = migration_path.read_text(encoding="utf-8")

    assert "LOCK TABLE workflow_runs, stage_runs, outbox_messages, " in migration
    assert "outbox_delivery_attempts, stage_attempts IN ACCESS EXCLUSIVE MODE" in migration
    assert "CREATE TRIGGER trg_0004_workflow_contract_plan_guard" in migration
    assert "CREATE TRIGGER trg_0004_stage_run_plan_guard" in migration
    assert "CREATE TRIGGER trg_0004_outbox_message_parent_contract_guard" in migration
    assert "CREATE TRIGGER trg_0004_stage_attempt_receipt_contract_guard" in migration
    workflow_guard = migration.split("CREATE FUNCTION ag_guard_workflow_contract_plan()", 1)[1].split(
        "CREATE TRIGGER trg_0004_workflow_contract_plan_guard",
        1,
    )[0]
    projected_revision = workflow_guard.index("SELECT project_id INTO projected_project_id")
    projected_parent = workflow_guard.index("FROM project_revisions", projected_revision)
    locked_project = workflow_guard.index("FROM research_projects")
    locked_revision = workflow_guard.index("FROM project_revisions", locked_project)
    assert projected_revision < projected_parent < locked_project < locked_revision
    assert "project_row.status <> 'active'" in workflow_guard
    assert "revision_row.status <> 'current'" in workflow_guard
    assert "project_id = project_row.id\n                FOR UPDATE" in workflow_guard
    assert "FROM workflow_runs\n            WHERE id = NEW.workflow_run_id\n            FOR UPDATE" in migration
    assert "FROM stage_runs\n            WHERE id = NEW.stage_run_id" in migration
    assert "CREATE CONSTRAINT TRIGGER trg_workflow_contract_from_" in migration
    assert "DEFERRABLE INITIALLY DEFERRED" in migration
    assert "new stage attempts require delivered receipt evidence" in migration
    assert "NEW.lease_token = delivery_row.delivery_token" in migration
    assert "attempt.started_at IS DISTINCT FROM stage.leased_at" in migration
    assert "stage.status NOT IN ('pending', 'ready')" in migration
    assert "workflow_row.status = 'running' AND NOT EXISTS" in migration
    assert "stage.status IN ('pending', 'ready', 'running', 'retry_wait')" in migration
    assert "message_row.plan_checksum IS DISTINCT FROM workflow_row.plan_checksum" in migration
    assert "broker_receipt_id !~ '^[0-9a-f]{64}$'" in migration
    assert "Refusing to discard workflow cancellation request authority" in migration
    assert "Refusing to weaken the contract while workflows remain active" in migration


def test_startup_and_fingerprint_tool_require_one_exact_alembic_head():
    backend_root = Path(__file__).resolve().parents[2]
    startup_source = (backend_root / "app" / "core" / "database.py").read_text(encoding="utf-8")
    tool_source = (backend_root / "scripts" / "verify_schema_authority_fingerprint.py").read_text(encoding="utf-8")

    for source in (startup_source, tool_source):
        assert "SELECT version_num FROM alembic_version ORDER BY version_num" in source
        assert "revisions != (REQUIRED_SCHEMA_REVISION,)" in source


def test_outbox_migration_uses_canonical_lock_order_without_reverse_guard_locks():
    migration_path = Path(__file__).resolve().parents[2] / "alembic" / "versions" / "20260823_0003_outbox.py"
    migration = migration_path.read_text(encoding="utf-8")
    assert (
        "LOCK TABLE workflow_runs, stage_runs, outbox_messages, outbox_delivery_attempts, stage_attempts IN ACCESS EXCLUSIVE MODE"
    ) in migration
    message_guard = migration.split("CREATE FUNCTION ag_guard_outbox_message_authority()", 1)[1].split(
        "CREATE FUNCTION ag_guard_outbox_delivery_authority()", 1
    )[0]
    delivery_guard = migration.split("CREATE FUNCTION ag_guard_outbox_delivery_authority()", 1)[1].split(
        "CREATE FUNCTION ag_guard_stage_attempt_outbox_link()", 1
    )[0]
    assert "FOR UPDATE OF stage" not in message_guard
    assert "FOR UPDATE;" not in delivery_guard


def test_partial_index_predicate_comparison_accepts_postgresql_deparsing_only():
    membership = {
        "column": "status",
        "operator": "in",
        "values": ("ready", "retry_wait"),
    }
    assert _index_predicate_matches(
        "((status)::text = ANY (ARRAY['ready'::text, 'retry_wait'::text[]))",
        membership,
    )
    assert _index_predicate_matches(
        "status IN ('ready', 'retry_wait')",
        membership,
    )
    assert not _index_predicate_matches(
        "status IN ('ready', 'retry_wait') OR priority = 0",
        membership,
    )
    assert not _index_predicate_matches("status = 'ready'", membership)

    equality = {"column": "status", "operator": "eq", "values": ("running",)}
    assert _index_predicate_matches("((status)::text = 'running'::text)", equality)
    assert not _index_predicate_matches(
        "status = ANY (ARRAY['running'::text])",
        equality,
    )
    assert _index_predicate_matches(None, None)
    assert not _index_predicate_matches("status = 'running'", None)


def test_postgresql_catalog_char_decoder_accepts_driver_and_text_forms_only():
    assert _decode_catalog_char(b"c") == "c"
    assert _decode_catalog_char("p") == "p"
    with pytest.raises(RuntimeError, match="width"):
        _decode_catalog_char(b"check")
    with pytest.raises(RuntimeError, match="non-ASCII"):
        _decode_catalog_char(b"\xff")
    with pytest.raises(RuntimeError, match="type"):
        _decode_catalog_char(99)


def test_authority_schema_fingerprint_is_order_independent_and_definition_exact():
    facts = [
        {"kind": "constraint", "name": "b", "definition": "CHECK (b > 0)"},
        {"kind": "column", "name": "a", "type": "integer"},
    ]
    expected = _authority_schema_fingerprint(facts)

    assert _authority_schema_fingerprint(list(reversed(facts))) == expected
    assert _authority_schema_fingerprint(facts + [facts[0]]) != expected
    assert _authority_schema_fingerprint([{**facts[0], "definition": "CHECK (b >= 0)"}, facts[1]]) != expected
    assert _normalize_catalog_definition("one  \r\n two\r\n") == "one\n two"
