from __future__ import annotations

import logging
import uuid
from dataclasses import replace
from types import SimpleNamespace

import pytest
from celery.exceptions import Reject

from app.services.workflow_orchestrator import (
    BrokerAcceptance,
    ConsumerDecision,
    DiscardStageDelivery,
    PublisherDecision,
    StageDeliveryEnvelope,
    StageHandlerRegistry,
    broker_receipt_fingerprint,
)
from app.services.research_workflows import (
    RESEARCH_SCOPE_STAGE_TYPE,
    RESEARCH_SCOPE_STAGE_VERSION,
    run_research_scope_stage,
)
from app.tasks import workflow as tasks
from tests.unit.test_workflow_orchestrator import _delivery


class _UnitApp:
    def __init__(self) -> None:
        self.dependency_overrides = {}


@pytest.fixture
def app():
    return _UnitApp()


async def _dispose() -> None:
    return None


def _consumer_decision(
    delivery: StageDeliveryEnvelope,
    disposition: str = "completed",
) -> ConsumerDecision:
    payload = delivery.claim.envelope["payload"]
    return ConsumerDecision(
        disposition=disposition,
        workflow_run_id=uuid.UUID(payload["workflow_run_id"]),
        stage_run_id=uuid.UUID(payload["stage_run_id"]),
        stage_attempt_id=uuid.uuid4(),
        message_id=delivery.claim.message_id,
        delivery_attempt_id=delivery.claim.delivery_attempt_id,
        attempt_number=payload["target_attempt_number"],
        delivery_cycle=delivery.claim.delivery_cycle,
        cycle_key=delivery.claim.cycle_key,
        broker_receipt_id=broker_receipt_fingerprint(delivery),
        should_ack=True,
        durable_retry=False,
    )


def _run_delivery_task(delivery: StageDeliveryEnvelope, *, request_id: str | None = None):
    tasks.execute_stage_delivery.push_request(
        id=request_id or delivery.broker_message_id,
        hostname="worker.example",
    )
    try:
        return tasks.execute_stage_delivery.run(delivery.as_payload())
    finally:
        tasks.execute_stage_delivery.pop_request()


def test_execute_task_returns_only_coordinator_acknowledged_decision(monkeypatch):
    delivery = _delivery()
    decision = _consumer_decision(delivery, "receipt_replayed")
    calls: list[dict[str, object]] = []

    async def consume(session_factory, **kwargs):
        calls.append({"session_factory": session_factory, **kwargs})
        return decision

    monkeypatch.setattr(tasks, "engine", SimpleNamespace(dispose=_dispose))
    monkeypatch.setattr(tasks, "consume_stage_delivery", consume)
    monkeypatch.setattr(tasks, "stage_handler_registry", StageHandlerRegistry())

    result = _run_delivery_task(delivery)

    assert result == {
        "disposition": "receipt_replayed",
        "workflow_run_id": str(decision.workflow_run_id),
        "stage_run_id": str(decision.stage_run_id),
        "stage_attempt_id": str(decision.stage_attempt_id),
        "durable_retry": False,
    }
    assert calls[0]["delivery"] == delivery
    assert calls[0]["handlers"] is tasks.stage_handler_registry
    assert str(calls[0]["worker_id"]).startswith("celery-worker:")


def test_execute_task_rejects_and_requeues_uncommitted_infrastructure_error(monkeypatch):
    delivery = _delivery()

    async def consume(*_args, **_kwargs):
        raise RuntimeError("receipt commit unavailable")

    monkeypatch.setattr(tasks, "engine", SimpleNamespace(dispose=_dispose))
    monkeypatch.setattr(tasks, "consume_stage_delivery", consume)

    with pytest.raises(Reject) as raised:
        _run_delivery_task(delivery)

    assert raised.value.requeue is True
    assert raised.value.__cause__ is None


@pytest.mark.parametrize(
    ("payload_factory", "request_id"),
    [
        (lambda delivery: {"transport_schema_version": "broken"}, None),
        (lambda delivery: delivery.as_payload(), "00000000-0000-0000-0000-000000000000"),
        (
            lambda delivery: {
                **delivery.as_payload(),
                "claim": {
                    **delivery.as_payload()["claim"],
                    "topic": "attacker.valid_syntax",
                },
            },
            None,
        ),
        (
            lambda delivery: {
                **delivery.as_payload(),
                "claim": {
                    **delivery.as_payload()["claim"],
                    "schema_version": "attacker-v1",
                },
            },
            None,
        ),
        (
            lambda delivery: {
                **delivery.as_payload(),
                "claim": {
                    **delivery.as_payload()["claim"],
                    "envelope_checksum": "0" * 64,
                },
            },
            None,
        ),
        (
            lambda delivery: {
                **delivery.as_payload(),
                "claim": {
                    **delivery.as_payload()["claim"],
                    "cycle_key": "0" * 64,
                },
            },
            None,
        ),
        (
            lambda delivery: {
                **delivery.as_payload(),
                "claim": {
                    **delivery.as_payload()["claim"],
                    "envelope_canonical": "[" * 10_000 + "0" + "]" * 10_000,
                },
            },
            None,
        ),
    ],
)
def test_execute_task_discards_deterministically_invalid_transport_without_requeue(
    monkeypatch,
    payload_factory,
    request_id,
):
    delivery = _delivery()

    async def forbidden(*_args, **_kwargs):
        raise AssertionError("invalid transport must not reach the receipt coordinator")

    monkeypatch.setattr(tasks, "consume_stage_delivery", forbidden)
    tasks.execute_stage_delivery.push_request(
        id=request_id or delivery.broker_message_id,
        hostname="worker.example",
    )
    try:
        with pytest.raises(Reject) as raised:
            tasks.execute_stage_delivery.run(payload_factory(delivery))
    finally:
        tasks.execute_stage_delivery.pop_request()

    assert raised.value.requeue is False


def test_execute_task_requeues_forged_nondecision_result(monkeypatch):
    delivery = _delivery()

    async def consume(*_args, **_kwargs):
        return object()

    monkeypatch.setattr(tasks, "engine", SimpleNamespace(dispose=_dispose))
    monkeypatch.setattr(tasks, "consume_stage_delivery", consume)

    with pytest.raises(Reject) as raised:
        _run_delivery_task(delivery)

    assert raised.value.requeue is True
    assert raised.value.__cause__ is None


def test_execute_task_revalidates_mutated_exact_decision_before_ack(monkeypatch):
    delivery = _delivery()
    decision = _consumer_decision(delivery, "receipt_replayed")
    object.__setattr__(decision, "disposition", "forged_ack")

    async def consume(*_args, **_kwargs):
        return decision

    monkeypatch.setattr(tasks, "engine", SimpleNamespace(dispose=_dispose))
    monkeypatch.setattr(tasks, "consume_stage_delivery", consume)

    with pytest.raises(Reject) as raised:
        _run_delivery_task(delivery)

    assert raised.value.requeue is True
    assert raised.value.__cause__ is None


def test_execute_task_discards_durably_stale_delivery_without_raw_cause(monkeypatch):
    delivery = _delivery()

    async def consume(*_args, **_kwargs):
        raise DiscardStageDelivery("internal stale detail")

    monkeypatch.setattr(tasks, "engine", SimpleNamespace(dispose=_dispose))
    monkeypatch.setattr(tasks, "consume_stage_delivery", consume)

    with pytest.raises(Reject) as raised:
        _run_delivery_task(delivery)

    assert raised.value.requeue is False
    assert raised.value.__cause__ is None


def test_execute_task_requeues_exact_decision_for_another_delivery(monkeypatch):
    delivery = _delivery()
    foreign = _consumer_decision(_delivery(), "receipt_replayed")

    async def consume(*_args, **_kwargs):
        return foreign

    monkeypatch.setattr(tasks, "engine", SimpleNamespace(dispose=_dispose))
    monkeypatch.setattr(tasks, "consume_stage_delivery", consume)

    with pytest.raises(Reject) as raised:
        _run_delivery_task(delivery)

    assert raised.value.requeue is True
    assert raised.value.__cause__ is None


def test_execute_task_requeues_correct_delivery_ids_with_foreign_workflow_lineage(monkeypatch):
    delivery = _delivery()
    foreign = replace(
        _consumer_decision(delivery, "receipt_replayed"),
        workflow_run_id=uuid.uuid4(),
        stage_run_id=uuid.uuid4(),
    )

    async def consume(*_args, **_kwargs):
        return foreign

    monkeypatch.setattr(tasks, "engine", SimpleNamespace(dispose=_dispose))
    monkeypatch.setattr(tasks, "consume_stage_delivery", consume)

    with pytest.raises(Reject) as raised:
        _run_delivery_task(delivery)

    assert raised.value.requeue is True
    assert raised.value.__cause__ is None


def test_execute_task_has_late_ack_failure_and_worker_loss_fences():
    task = tasks.execute_stage_delivery
    assert task.acks_late is True
    assert task.acks_on_failure_or_timeout is False
    assert task.reject_on_worker_lost is True


def test_celery_publisher_fixes_task_id_and_transports_full_payload(monkeypatch):
    delivery: StageDeliveryEnvelope = _delivery()
    sent: dict[str, object] = {}

    class _Result:
        id = delivery.broker_message_id

    def send_task(name, **kwargs):
        sent.update({"name": name, **kwargs})
        return _Result()

    monkeypatch.setattr(tasks.celery_app, "send_task", send_task)

    result = tasks._celery_publish(delivery)

    assert result == BrokerAcceptance("celery", delivery.broker_message_id)
    assert sent == {
        "name": "workflow.execute_stage",
        "kwargs": {"delivery": delivery.as_payload()},
        "task_id": delivery.broker_message_id,
        "kwargsrepr": "<redacted workflow delivery authority>",
    }


def test_publisher_task_stops_at_empty_decision(monkeypatch):
    decisions = iter(
        [
            PublisherDecision(
                disposition="dispatched",
                message_id=uuid.uuid4(),
                delivery_attempt_id=uuid.uuid4(),
                delivery_cycle=1,
                broker_message_id=str(uuid.uuid4()),
                durable_status="awaiting_receipt",
                replayed=False,
            ),
            PublisherDecision(
                disposition="empty",
                message_id=None,
                delivery_attempt_id=None,
                delivery_cycle=None,
                broker_message_id="",
                durable_status="",
                replayed=False,
            ),
        ]
    )
    calls = 0

    async def publish(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return next(decisions)

    monkeypatch.setattr(tasks, "engine", SimpleNamespace(dispose=_dispose))
    monkeypatch.setattr(tasks, "publish_one_outbox_delivery", publish)

    result = tasks.publish_due_workflow_deliveries.run(limit=10)

    assert calls == 2
    assert result == {
        "claimed": 1,
        "dispatched": 1,
        "publish_failed": 0,
        "empty": True,
    }


def test_publisher_task_rejects_forged_nondecision_result(monkeypatch):
    async def publish(*_args, **_kwargs):
        return object()

    monkeypatch.setattr(tasks, "engine", SimpleNamespace(dispose=_dispose))
    monkeypatch.setattr(tasks, "publish_one_outbox_delivery", publish)

    with pytest.raises(tasks.WorkflowOrchestrationError, match="invalid type"):
        tasks.publish_due_workflow_deliveries.run(limit=1)


def test_recovery_task_is_fail_closed_until_adapter_is_configured(monkeypatch):
    monkeypatch.setattr(tasks, "_recovery_adapter", None)

    with pytest.raises(tasks.WorkflowOrchestrationError, match="not configured"):
        tasks.recover_workflow_authority.run(limit=10)


def test_workflow_recovery_task_uses_the_registered_commit_owning_coordinator(
    monkeypatch,
    caplog,
):
    calls: list[tuple[object, int]] = []

    async def recover(session_factory, *, limit):
        calls.append((session_factory, limit))
        return ()

    monkeypatch.setattr(tasks, "engine", SimpleNamespace(dispose=_dispose))
    monkeypatch.setattr(tasks, "coordinate_expired_stage_recovery_pass", recover)
    caplog.set_level(logging.INFO, logger=tasks.__name__)

    assert tasks.recover_workflow_authority.run(limit=25) == {"recovered": 0}
    assert calls == [(tasks.async_session_factory, 25)]
    assert any(
        "metric=adversarygraph_workflow_recovery_success_total kind=stage count=1 recovered=0" in record.getMessage()
        for record in caplog.records
        if record.name == tasks.__name__
    )


def test_outbox_recovery_task_uses_commit_owning_adapter(monkeypatch, caplog):
    calls: list[tuple[object, int]] = []

    async def recover(session_factory, *, limit):
        calls.append((session_factory, limit))
        return 4

    monkeypatch.setattr(tasks, "engine", SimpleNamespace(dispose=_dispose))
    monkeypatch.setattr(tasks, "recover_expired_outbox_pass", recover)
    caplog.set_level(logging.INFO, logger=tasks.__name__)

    assert tasks.recover_expired_outbox_authority.run(limit=25) == {"recovered": 4}
    assert calls == [(tasks.async_session_factory, 25)]
    assert any(
        "metric=adversarygraph_workflow_recovery_success_total kind=outbox count=1 recovered=4" in record.getMessage()
        for record in caplog.records
        if record.name == tasks.__name__
    )


@pytest.mark.parametrize(
    ("task_name", "coordinator_name", "error_type", "kind"),
    [
        (
            "recover_workflow_authority",
            "coordinate_expired_stage_recovery_pass",
            tasks.WorkflowStoredContractError,
            "stage",
        ),
        (
            "recover_expired_outbox_authority",
            "recover_expired_outbox_pass",
            tasks.OutboxStoredContractError,
            "outbox",
        ),
    ],
)
def test_recovery_tasks_emit_generic_stored_contract_quarantine_signals(
    monkeypatch,
    caplog,
    task_name,
    coordinator_name,
    error_type,
    kind,
):
    secret = "authority-token-that-must-not-be-logged"

    async def fail(*_args, **_kwargs):
        raise error_type(secret)

    monkeypatch.setattr(tasks, "engine", SimpleNamespace(dispose=_dispose))
    monkeypatch.setattr(tasks, coordinator_name, fail)
    caplog.set_level(logging.INFO, logger=tasks.__name__)

    task = getattr(tasks, task_name)
    with pytest.raises(tasks.WorkflowOrchestrationError, match="operator review") as raised:
        task.run(limit=25)

    messages = [record.getMessage() for record in caplog.records if record.name == tasks.__name__]
    assert raised.value.__cause__ is None
    assert secret not in "\n".join(messages)
    assert any(
        f"metric=adversarygraph_workflow_recovery_failure_total kind={kind} count=1" in message and "stored_contract=true" in message
        for message in messages
    )
    assert any(
        f"metric=adversarygraph_workflow_recovery_stored_contract_quarantine_total kind={kind} count=1" in message for message in messages
    )


def test_recovery_task_failure_signal_does_not_log_exception_text(monkeypatch, caplog):
    secret = "postgresql://operator:secret@example.invalid/workflows"

    async def fail(*_args, **_kwargs):
        raise RuntimeError(secret)

    monkeypatch.setattr(tasks, "engine", SimpleNamespace(dispose=_dispose))
    monkeypatch.setattr(tasks, "recover_expired_outbox_pass", fail)
    caplog.set_level(logging.INFO, logger=tasks.__name__)

    with pytest.raises(tasks.WorkflowOrchestrationError, match="recovery pass failed") as raised:
        tasks.recover_expired_outbox_authority.run(limit=25)

    messages = [record.getMessage() for record in caplog.records if record.name == tasks.__name__]
    assert raised.value.__cause__ is None
    assert secret not in "\n".join(messages)
    assert any(
        "metric=adversarygraph_workflow_recovery_failure_total kind=outbox count=1" in message
        and "error_class=RuntimeError stored_contract=false" in message
        for message in messages
    )
    assert all("stored_contract_quarantine" not in message for message in messages)


@pytest.mark.parametrize("task_name", ["recover_workflow_authority", "recover_expired_outbox_authority"])
def test_recovery_tasks_enforce_the_worker_batch_maximum(task_name):
    task = getattr(tasks, task_name)

    with pytest.raises(tasks.WorkflowOrchestrationError, match="from 1 to 500"):
        task.run(limit=501)


def test_canonical_research_scope_handler_is_registered_at_worker_startup():
    assert (
        tasks.stage_handler_registry.resolve(
            RESEARCH_SCOPE_STAGE_TYPE,
            RESEARCH_SCOPE_STAGE_VERSION,
        )
        is run_research_scope_stage
    )


def test_publisher_is_scheduled_as_a_production_outbox_drain():
    schedule = tasks.celery_app.conf.beat_schedule["workflow-publish-due"]

    assert schedule["task"] == "workflow.publish_due"
    assert schedule["args"] == (100,)
    assert schedule["options"] == {"queue": "celery", "expires": 9}
    assert 0 < schedule["options"]["expires"] < schedule["schedule"].total_seconds()

    recovery = tasks.celery_app.conf.beat_schedule["workflow-recover-outbox"]
    assert recovery["task"] == "workflow.recover_outbox"
    assert recovery["args"] == (100,)
    assert recovery["options"] == {"queue": "celery", "expires": 29}
    assert 0 < recovery["options"]["expires"] < recovery["schedule"].total_seconds()

    stage_recovery = tasks.celery_app.conf.beat_schedule["workflow-recover-expired"]
    assert stage_recovery["task"] == "workflow.recover_expired"
    assert stage_recovery["args"] == (100,)
    assert stage_recovery["options"] == {"queue": "celery", "expires": 29}
    assert 0 < stage_recovery["options"]["expires"] < stage_recovery["schedule"].total_seconds()
