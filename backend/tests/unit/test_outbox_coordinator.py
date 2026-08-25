from __future__ import annotations

import ast
import inspect
import uuid
from dataclasses import FrozenInstanceError, dataclass, fields, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.models.research_workflow import (
    OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1,
    OUTBOX_TOPIC_WORKFLOW_STAGE_READY,
)
from app.services import outbox_coordinator as coordinator
from app.services import outbox_runtime as runtime
from app.services.outbox_engine import (
    delivery_cycle_idempotency_key,
    normalize_outbox_envelope,
)


NOW = datetime(2026, 8, 23, 12, 0, tzinfo=timezone.utc)


class _UnitApp:
    def __init__(self) -> None:
        self.dependency_overrides = {}


@pytest.fixture
def app():
    """Keep global auth fixtures from importing the unrelated API surface."""

    return _UnitApp()


@dataclass(frozen=True)
class _ReceiptCase:
    command: runtime.StageReceiptCommand
    workflow_run_id: uuid.UUID
    stage_run_id: uuid.UUID
    stage_attempt_id: uuid.UUID


def _receipt_case() -> _ReceiptCase:
    workflow_run_id = uuid.uuid4()
    stage_run_id = uuid.uuid4()
    stage_attempt_id = uuid.uuid4()
    normalized = normalize_outbox_envelope(
        {
            "topic": OUTBOX_TOPIC_WORKFLOW_STAGE_READY,
            "schema_version": OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1,
            "payload": {
                "workflow_run_id": str(workflow_run_id),
                "stage_run_id": str(stage_run_id),
                "stage_key": "extract_claims",
                "target_attempt_number": 1,
                "input_checksum": "b" * 64,
                "plan_checksum": "a" * 64,
            },
        }
    )
    cycle_key = delivery_cycle_idempotency_key(
        normalized.logical_key,
        delivery_cycle=1,
    )
    claim = runtime.ClaimedOutboxDelivery(
        message_id=uuid.uuid4(),
        delivery_attempt_id=uuid.uuid4(),
        delivery_token=uuid.uuid4(),
        message_state_version=2,
        delivery_state_version=1,
        delivery_cycle=1,
        cycle_key=cycle_key,
        correlation_id=uuid.uuid4(),
        topic=normalized.envelope.topic,
        schema_version=normalized.envelope.schema_version,
        envelope_checksum=normalized.checksum,
        logical_key=normalized.logical_key,
        envelope_canonical=normalized.canonical,
    )
    return _ReceiptCase(
        command=runtime.StageReceiptCommand(
            claim=claim,
            broker_name="test_broker",
            broker_message_id="broker-message-1",
            broker_receipt_id="f" * 64,
            worker_id="worker-1",
            lease_seconds=120,
        ),
        workflow_run_id=workflow_run_id,
        stage_run_id=stage_run_id,
        stage_attempt_id=stage_attempt_id,
    )


def _pending(
    case: _ReceiptCase,
    disposition: str = "activated",
) -> runtime.PendingReceiptActivation:
    has_attempt = disposition in {"activated", "replayed"}
    return runtime.PendingReceiptActivation(
        workflow_run_id=case.workflow_run_id,
        stage_run_id=case.stage_run_id,
        stage_attempt_id=case.stage_attempt_id if has_attempt else None,
        message_id=case.command.claim.message_id,
        delivery_attempt_id=case.command.claim.delivery_attempt_id,
        attempt_number=1,
        delivery_cycle=case.command.claim.delivery_cycle,
        cycle_key=case.command.claim.cycle_key,
        broker_receipt_id=case.command.broker_receipt_id,
        commit_ticket="A" * 160 if disposition == "activated" else None,
        disposition=disposition,
        should_execute=False,
    )


def _authority(case: _ReceiptCase) -> runtime.ExecutableStageAuthority:
    return runtime.ExecutableStageAuthority(
        workflow_run_id=case.workflow_run_id,
        stage_run_id=case.stage_run_id,
        stage_attempt_id=case.stage_attempt_id,
        message_id=case.command.claim.message_id,
        delivery_attempt_id=case.command.claim.delivery_attempt_id,
        stage_lease_token=uuid.uuid4(),
        workflow_state_version=2,
        stage_state_version=2,
        attempt_state_version=1,
        attempt_number=1,
        delivery_cycle=case.command.claim.delivery_cycle,
        cycle_key=case.command.claim.cycle_key,
        stage_key="extract_claims",
        input_checksum="b" * 64,
        checkpoint_version=0,
        lease_owner="worker-1",
        lease_expires_at=NOW + timedelta(seconds=120),
        broker_receipt_id=case.command.broker_receipt_id,
    )


class _TransactionContext:
    def __init__(
        self,
        label: str,
        events: list[str],
        *,
        commit_error: BaseException | None = None,
        rollback_error: BaseException | None = None,
    ) -> None:
        self.label = label
        self.events = events
        self.commit_error = commit_error
        self.rollback_error = rollback_error

    async def __aenter__(self):
        self.events.append(f"{self.label}.transaction.enter")
        return self

    async def __aexit__(self, exc_type, _exc, _traceback):
        action = "commit" if exc_type is None else "rollback"
        self.events.append(f"{self.label}.transaction.exit.{action}")
        if exc_type is None and self.commit_error is not None:
            raise self.commit_error
        if exc_type is not None and self.rollback_error is not None:
            raise self.rollback_error
        return False


class _SessionContext:
    def __init__(
        self,
        label: str,
        events: list[str],
        *,
        commit_error: BaseException | None = None,
        rollback_error: BaseException | None = None,
        exit_error: BaseException | None = None,
    ) -> None:
        self.label = label
        self.events = events
        self.commit_error = commit_error
        self.rollback_error = rollback_error
        self.exit_error = exit_error

    async def __aenter__(self):
        self.events.append(f"{self.label}.session.enter")
        return self

    async def __aexit__(self, exc_type, _exc, _traceback):
        outcome = "success" if exc_type is None else "error"
        self.events.append(f"{self.label}.session.exit.{outcome}")
        if self.exit_error is not None:
            raise self.exit_error
        return False

    def begin(self):
        self.events.append(f"{self.label}.transaction.create")
        return _TransactionContext(
            self.label,
            self.events,
            commit_error=self.commit_error,
            rollback_error=self.rollback_error,
        )


class _SessionFactory:
    def __init__(self, sessions: list[_SessionContext], events: list[str]) -> None:
        self.sessions = sessions
        self.events = events
        self.calls = 0

    def __call__(self):
        self.calls += 1
        self.events.append(f"factory.call.{self.calls}")
        return self.sessions[self.calls - 1]


def _factory(
    events: list[str],
    count: int = 2,
    *,
    commit_error_at: int | None = None,
    rollback_error_at: int | None = None,
    exit_error_at: int | None = None,
) -> _SessionFactory:
    sessions = [
        _SessionContext(
            f"uow{index}",
            events,
            commit_error=(RuntimeError(f"uow{index} commit failed") if commit_error_at == index else None),
            rollback_error=(RuntimeError(f"uow{index} rollback failed") if rollback_error_at == index else None),
            exit_error=(RuntimeError(f"uow{index} session exit failed") if exit_error_at == index else None),
        )
        for index in range(1, count + 1)
    ]
    return _SessionFactory(sessions, events)


@pytest.mark.asyncio
async def test_activated_result_is_built_only_after_both_uows_exit(
    monkeypatch,
):
    case = _receipt_case()
    pending = _pending(case)
    authority = _authority(case)
    events: list[str] = []
    factory = _factory(events)

    async def receive(db, *, command):
        events.append("receipt.runtime")
        assert db is factory.sessions[0]
        assert command == case.command
        assert command is not case.command
        return pending

    async def confirm(db, *, commit_ticket):
        events.append("confirmation.runtime")
        assert db is factory.sessions[1]
        assert commit_ticket == pending.commit_ticket
        return authority

    real_copy = coordinator._copy_executable_authority
    real_build = coordinator._build_public_result

    def copy_authority(value):
        events.append("authority.copy")
        return real_copy(value)

    def build_result(*args, **kwargs):
        events.append("public_result.build")
        return real_build(*args, **kwargs)

    monkeypatch.setattr(coordinator, "_receipt_and_claim_stage", receive)
    monkeypatch.setattr(coordinator, "_confirm_committed_activation", confirm)
    monkeypatch.setattr(coordinator, "_copy_executable_authority", copy_authority)
    monkeypatch.setattr(coordinator, "_build_public_result", build_result)

    result = await coordinator.coordinate_stage_receipt(
        factory,
        command=case.command,
    )

    assert factory.calls == 2
    assert events.index("uow1.transaction.exit.commit") < events.index("uow1.session.exit.success")
    assert events.index("uow1.session.exit.success") < events.index("factory.call.2")
    assert events.index("uow2.transaction.exit.commit") < events.index("uow2.session.exit.success")
    assert events.index("uow2.session.exit.success") < events.index("authority.copy")
    assert events.index("uow2.session.exit.success") < events.index("public_result.build")
    assert result.disposition == "activated"
    assert result.should_execute is True
    assert result.should_ack is True
    assert result.authority == authority
    assert result.authority is not authority
    assert result.stage_attempt_id == authority.stage_attempt_id
    assert not hasattr(result, "commit_ticket")
    assert "commit_ticket" not in {field.name for field in fields(result)}


@pytest.mark.asyncio
@pytest.mark.parametrize("disposition", ["replayed", "stale", "cancelled"])
async def test_nonactivated_outcome_uses_one_uow_and_never_confirms(
    monkeypatch,
    disposition,
):
    case = _receipt_case()
    pending = _pending(case, disposition)
    events: list[str] = []
    factory = _factory(events, count=1)
    confirmation_calls = 0

    async def receive(_db, *, command):
        assert command == case.command
        return pending

    async def confirm(*_args, **_kwargs):
        nonlocal confirmation_calls
        confirmation_calls += 1
        raise AssertionError("terminal receipt must not open confirmation")

    monkeypatch.setattr(coordinator, "_receipt_and_claim_stage", receive)
    monkeypatch.setattr(coordinator, "_confirm_committed_activation", confirm)

    result = await coordinator.coordinate_stage_receipt(factory, command=case.command)

    assert factory.calls == 1
    assert confirmation_calls == 0
    assert result.disposition == disposition
    assert result.should_execute is False
    assert result.should_ack is True
    assert result.authority is None
    assert (result.stage_attempt_id is not None) is (disposition == "replayed")
    assert events[-1] == "uow1.session.exit.success"


@pytest.mark.asyncio
async def test_confirmation_none_maps_to_acknowledgeable_stale_without_attempt(
    monkeypatch,
):
    case = _receipt_case()
    pending = _pending(case)
    events: list[str] = []
    factory = _factory(events)

    async def receive(_db, *, command):
        assert command == case.command
        return pending

    async def confirm(_db, *, commit_ticket):
        assert commit_ticket == pending.commit_ticket
        return None

    monkeypatch.setattr(coordinator, "_receipt_and_claim_stage", receive)
    monkeypatch.setattr(coordinator, "_confirm_committed_activation", confirm)

    result = await coordinator.coordinate_stage_receipt(factory, command=case.command)

    assert factory.calls == 2
    assert result.disposition == "stale"
    assert result.stage_attempt_id is None
    assert result.authority is None
    assert result.should_execute is False
    assert result.should_ack is True
    assert events[-1] == "uow2.session.exit.success"


@pytest.mark.asyncio
async def test_duplicate_invocation_returns_one_authority_then_replay_without_ticket(
    monkeypatch,
):
    case = _receipt_case()
    pending_results = iter([_pending(case), _pending(case, "replayed")])
    authority = _authority(case)
    events: list[str] = []
    factory = _factory(events, count=3)
    confirmation_calls = 0

    async def receive(_db, *, command):
        assert command == case.command
        return next(pending_results)

    async def confirm(_db, *, commit_ticket):
        nonlocal confirmation_calls
        confirmation_calls += 1
        assert commit_ticket == "A" * 160
        return authority

    monkeypatch.setattr(coordinator, "_receipt_and_claim_stage", receive)
    monkeypatch.setattr(coordinator, "_confirm_committed_activation", confirm)

    first = await coordinator.coordinate_stage_receipt(factory, command=case.command)
    second = await coordinator.coordinate_stage_receipt(factory, command=case.command)

    assert factory.calls == 3
    assert confirmation_calls == 1
    assert first.disposition == "activated"
    assert first.should_execute is True
    assert first.authority is not None
    assert second.disposition == "replayed"
    assert second.should_execute is False
    assert second.authority is None
    assert second.should_ack is True
    assert not hasattr(first, "commit_ticket")
    assert not hasattr(second, "commit_ticket")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure_phase", "expected_factory_calls", "expected_message"),
    [
        ("receipt_runtime", 1, "receipt runtime failed"),
        ("receipt_commit", 1, "uow1 commit failed"),
        ("receipt_session_exit", 1, "uow1 session exit failed"),
        ("confirmation_runtime", 2, "confirmation runtime failed"),
        ("confirmation_commit", 2, "uow2 commit failed"),
        ("confirmation_session_exit", 2, "uow2 session exit failed"),
    ],
)
async def test_failure_or_commit_exit_never_constructs_ack_or_authority(
    monkeypatch,
    failure_phase,
    expected_factory_calls,
    expected_message,
):
    case = _receipt_case()
    events: list[str] = []
    factory = _factory(
        events,
        commit_error_at=(1 if failure_phase == "receipt_commit" else 2 if failure_phase == "confirmation_commit" else None),
        exit_error_at=(1 if failure_phase == "receipt_session_exit" else 2 if failure_phase == "confirmation_session_exit" else None),
    )
    built_results = 0

    async def receive(_db, *, command):
        assert command == case.command
        if failure_phase == "receipt_runtime":
            raise RuntimeError("receipt runtime failed")
        return _pending(case)

    async def confirm(_db, *, commit_ticket):
        assert commit_ticket == "A" * 160
        if failure_phase == "confirmation_runtime":
            raise RuntimeError("confirmation runtime failed")
        return _authority(case)

    def build_result(*_args, **_kwargs):
        nonlocal built_results
        built_results += 1
        raise AssertionError("failure path exposed an acknowledgement decision")

    monkeypatch.setattr(coordinator, "_receipt_and_claim_stage", receive)
    monkeypatch.setattr(coordinator, "_confirm_committed_activation", confirm)
    monkeypatch.setattr(coordinator, "_build_public_result", build_result)

    with pytest.raises(RuntimeError, match=expected_message):
        await coordinator.coordinate_stage_receipt(factory, command=case.command)

    assert factory.calls == expected_factory_calls
    assert built_results == 0


@pytest.mark.asyncio
async def test_receipt_exception_and_rollback_failure_return_no_decision(
    monkeypatch,
):
    case = _receipt_case()
    events: list[str] = []
    factory = _factory(events, count=1, rollback_error_at=1)

    async def receive(_db, *, command):
        assert command == case.command
        raise ValueError("bad receipt")

    async def forbidden_confirm(*_args, **_kwargs):
        raise AssertionError("confirmation must not run")

    monkeypatch.setattr(coordinator, "_receipt_and_claim_stage", receive)
    monkeypatch.setattr(coordinator, "_confirm_committed_activation", forbidden_confirm)

    with pytest.raises(RuntimeError, match="rollback failed"):
        await coordinator.coordinate_stage_receipt(factory, command=case.command)

    assert factory.calls == 1
    assert events[-2:] == [
        "uow1.transaction.exit.rollback",
        "uow1.session.exit.error",
    ]


@pytest.mark.asyncio
async def test_forged_command_is_revalidated_before_session_factory_call(
    monkeypatch,
):
    case = _receipt_case()
    forged = object.__new__(runtime.StageReceiptCommand)
    for field_name in case.command.__dataclass_fields__:
        object.__setattr__(forged, field_name, getattr(case.command, field_name))
    object.__setattr__(forged, "broker_receipt_id", "raw-ack-handle")
    events: list[str] = []
    factory = _factory(events, count=1)

    async def forbidden_receipt(*_args, **_kwargs):
        raise AssertionError("invalid input reached receipt runtime")

    monkeypatch.setattr(coordinator, "_receipt_and_claim_stage", forbidden_receipt)

    with pytest.raises(runtime.OutboxValidation, match="SHA-256"):
        await coordinator.coordinate_stage_receipt(factory, command=forged)

    assert factory.calls == 0
    assert events == []


@pytest.mark.asyncio
async def test_confirmation_rejects_a_factory_that_reuses_receipt_session(
    monkeypatch,
):
    case = _receipt_case()
    events: list[str] = []
    shared_session = _SessionContext("shared", events)
    factory = _SessionFactory([shared_session, shared_session], events)
    confirmation_calls = 0

    async def receive(_db, *, command):
        assert command == case.command
        return _pending(case)

    async def confirm(*_args, **_kwargs):
        nonlocal confirmation_calls
        confirmation_calls += 1
        return _authority(case)

    monkeypatch.setattr(coordinator, "_receipt_and_claim_stage", receive)
    monkeypatch.setattr(coordinator, "_confirm_committed_activation", confirm)

    with pytest.raises(runtime.OutboxValidation, match="fresh session"):
        await coordinator.coordinate_stage_receipt(factory, command=case.command)

    assert factory.calls == 2
    assert confirmation_calls == 0
    assert "shared.transaction.create" in events
    assert events[-1] == "shared.session.exit.error"


@pytest.mark.asyncio
async def test_confirmation_authority_is_fixed_point_copied_after_uow_exit(
    monkeypatch,
):
    case = _receipt_case()
    forged = _authority(case)
    object.__setattr__(forged, "broker_receipt_id", "raw-ack-handle")
    events: list[str] = []
    factory = _factory(events)

    async def receive(_db, *, command):
        assert command == case.command
        return _pending(case)

    async def confirm(_db, *, commit_ticket):
        assert commit_ticket == "A" * 160
        return forged

    monkeypatch.setattr(coordinator, "_receipt_and_claim_stage", receive)
    monkeypatch.setattr(coordinator, "_confirm_committed_activation", confirm)

    with pytest.raises(runtime.OutboxStoredContractError, match="invalid executable"):
        await coordinator.coordinate_stage_receipt(factory, command=case.command)

    assert factory.calls == 2
    assert events[-1] == "uow2.session.exit.success"


def test_public_result_is_frozen_strict_and_lineage_bound():
    case = _receipt_case()
    pending = _pending(case)
    authority = _authority(case)
    result = coordinator._build_public_result(
        pending,
        disposition="activated",
        authority=authority,
    )

    assert result.authority is not authority
    with pytest.raises(FrozenInstanceError):
        result.should_ack = False

    invalid_cases = (
        {"should_ack": False},
        {"should_execute": False},
        {"disposition": "replayed"},
        {"stage_attempt_id": None},
        {"cycle_key": "F" * 64},
        {"attempt_number": True},
    )
    for changes in invalid_cases:
        with pytest.raises(runtime.OutboxValidation):
            replace(result, **changes)

    contradictory = replace(authority, message_id=uuid.uuid4())
    with pytest.raises(runtime.OutboxStoredContractError, match="contradicts"):
        replace(result, authority=contradictory)


def test_public_result_rejects_invalid_registry_types_and_attempt_shapes():
    case = _receipt_case()
    replay = coordinator._build_public_result(
        _pending(case, "replayed"),
        disposition="replayed",
        authority=None,
    )

    invalid_cases = (
        {"workflow_run_id": str(replay.workflow_run_id)},
        {"disposition": "unknown"},
        {"should_execute": 0},
        {"stage_attempt_id": None},
    )
    for changes in invalid_cases:
        with pytest.raises(runtime.OutboxValidation):
            replace(replay, **changes)

    stale = coordinator._build_public_result(
        _pending(case, "stale"),
        disposition="stale",
        authority=None,
    )
    with pytest.raises(runtime.OutboxValidation, match="replayed"):
        replace(stale, stage_attempt_id=case.stage_attempt_id)


@pytest.mark.asyncio
async def test_noncallable_factory_and_wrong_command_type_fail_before_uow():
    case = _receipt_case()

    with pytest.raises(runtime.OutboxValidation, match="command"):
        await coordinator.coordinate_stage_receipt(lambda: None, command=object())
    with pytest.raises(runtime.OutboxValidation, match="session_factory"):
        await coordinator.coordinate_stage_receipt(None, command=case.command)


def test_fixed_point_helpers_reject_wrong_or_incomplete_runtime_dtos():
    case = _receipt_case()

    with pytest.raises(runtime.OutboxValidation, match="incomplete"):
        coordinator._copy_receipt_command(object.__new__(runtime.StageReceiptCommand))
    with pytest.raises(runtime.OutboxStoredContractError, match="pending"):
        coordinator._copy_pending_activation(object())

    forged_pending = object.__new__(runtime.PendingReceiptActivation)
    valid_pending = _pending(case)
    for field_name in valid_pending.__dataclass_fields__:
        object.__setattr__(forged_pending, field_name, getattr(valid_pending, field_name))
    object.__setattr__(forged_pending, "cycle_key", "F" * 64)
    with pytest.raises(runtime.OutboxStoredContractError, match="pending"):
        coordinator._copy_pending_activation(forged_pending)

    with pytest.raises(runtime.OutboxStoredContractError, match="executable"):
        coordinator._copy_executable_authority(object())


def test_coordinator_has_no_network_ack_or_manual_transaction_escape_hatch():
    source = inspect.getsource(coordinator)
    tree = ast.parse(source)
    forbidden_imports = {"aio_pika", "celery", "httpx", "kombu", "requests"}
    forbidden_calls = {
        "ack",
        "acknowledge",
        "apply_async",
        "commit",
        "delay",
        "nack",
        "publish",
        "reject",
        "rollback",
        "send",
    }

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not ({name.name.split(".")[0] for name in node.names} & forbidden_imports)
        if isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] not in forbidden_imports
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                call_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                call_name = node.func.attr
            else:
                continue
            assert call_name not in forbidden_calls

    assert ".commit(" not in source
    assert ".rollback(" not in source
    assert "commit_ticket" not in {field.name for field in fields(coordinator.CoordinatedStageReceipt)}
    assert set(coordinator.__all__) == {
        "CoordinatedStageReceipt",
        "SessionFactory",
        "StageReceiptCommand",
        "coordinate_stage_receipt",
    }


def test_low_level_receipt_calls_are_confined_to_runtime_and_coordinator():
    app_root = Path(coordinator.__file__).resolve().parents[1]
    allowed = {
        (app_root / "services" / "outbox_runtime.py").resolve(),
        (app_root / "services" / "outbox_coordinator.py").resolve(),
    }
    forbidden_names = {"receipt_and_claim_stage", "confirm_committed_activation"}
    violations: list[str] = []

    for path in app_root.rglob("*.py"):
        if path.resolve() in allowed:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    call_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    call_name = node.func.attr
                else:
                    continue
                if call_name in forbidden_names:
                    violations.append(f"{path.relative_to(app_root)}:{node.lineno}:{call_name}")
            if isinstance(node, ast.ImportFrom) and node.module == "app.services.outbox_runtime":
                for imported in node.names:
                    if imported.name in forbidden_names:
                        violations.append(f"{path.relative_to(app_root)}:{node.lineno}:import {imported.name}")

    assert violations == []
