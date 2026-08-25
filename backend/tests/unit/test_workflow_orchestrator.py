from __future__ import annotations

import copy
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone

import pytest

from app.models.research_workflow import (
    OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1,
    OUTBOX_TOPIC_WORKFLOW_STAGE_READY,
    OutboxDeliveryAttempt,
    OutboxMessage,
    StageRun,
)
from app.services import workflow_orchestrator as orchestrator
from app.services.outbox_coordinator import CoordinatedStageReceipt
from app.services.outbox_engine import delivery_cycle_idempotency_key, normalize_outbox_envelope
from app.services.outbox_runtime import (
    ClaimedOutboxDelivery,
    ExecutableStageAuthority,
    OutboxDeliveryMutation,
    OutboxLeaseLost,
    OutboxNotFound,
    OutboxRecoveryResult,
    OutboxStoredContractError,
)


NOW = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)


class _UnitApp:
    def __init__(self) -> None:
        self.dependency_overrides = {}


@pytest.fixture
def app():
    return _UnitApp()


def _claim() -> ClaimedOutboxDelivery:
    workflow_id = uuid.uuid4()
    stage_id = uuid.uuid4()
    normalized = normalize_outbox_envelope(
        {
            "topic": OUTBOX_TOPIC_WORKFLOW_STAGE_READY,
            "schema_version": OUTBOX_SCHEMA_WORKFLOW_STAGE_READY_V1,
            "payload": {
                "workflow_run_id": str(workflow_id),
                "stage_run_id": str(stage_id),
                "stage_key": "extract_claims",
                "target_attempt_number": 1,
                "input_checksum": "b" * 64,
                "plan_checksum": "a" * 64,
            },
        }
    )
    return ClaimedOutboxDelivery(
        message_id=uuid.uuid4(),
        delivery_attempt_id=uuid.uuid4(),
        delivery_token=uuid.uuid4(),
        message_state_version=2,
        delivery_state_version=1,
        delivery_cycle=1,
        cycle_key=delivery_cycle_idempotency_key(normalized.logical_key, delivery_cycle=1),
        correlation_id=uuid.uuid4(),
        topic=normalized.envelope.topic,
        schema_version=normalized.envelope.schema_version,
        envelope_checksum=normalized.checksum,
        logical_key=normalized.logical_key,
        envelope_canonical=normalized.canonical,
    )


def _delivery(claim: ClaimedOutboxDelivery | None = None) -> orchestrator.StageDeliveryEnvelope:
    return orchestrator.StageDeliveryEnvelope(
        claim=claim or _claim(),
        broker_name="celery",
        broker_message_id=str(uuid.uuid4()),
    )


def _authority(
    delivery: orchestrator.StageDeliveryEnvelope,
    *,
    broker_receipt_id: str | None = None,
) -> ExecutableStageAuthority:
    payload = delivery.claim.envelope["payload"]
    return ExecutableStageAuthority(
        workflow_run_id=uuid.UUID(payload["workflow_run_id"]),
        stage_run_id=uuid.UUID(payload["stage_run_id"]),
        stage_attempt_id=uuid.uuid4(),
        message_id=delivery.claim.message_id,
        delivery_attempt_id=delivery.claim.delivery_attempt_id,
        stage_lease_token=uuid.uuid4(),
        workflow_state_version=2,
        stage_state_version=2,
        attempt_state_version=1,
        attempt_number=1,
        delivery_cycle=delivery.claim.delivery_cycle,
        cycle_key=delivery.claim.cycle_key,
        stage_key="extract_claims",
        input_checksum="b" * 64,
        checkpoint_version=0,
        lease_owner="worker-1",
        lease_expires_at=NOW + timedelta(minutes=5),
        broker_receipt_id=broker_receipt_id or orchestrator.broker_receipt_fingerprint(delivery),
    )


def _activated_receipt(delivery: orchestrator.StageDeliveryEnvelope) -> CoordinatedStageReceipt:
    authority = _authority(delivery)
    return CoordinatedStageReceipt(
        workflow_run_id=authority.workflow_run_id,
        stage_run_id=authority.stage_run_id,
        stage_attempt_id=authority.stage_attempt_id,
        message_id=authority.message_id,
        delivery_attempt_id=authority.delivery_attempt_id,
        attempt_number=authority.attempt_number,
        delivery_cycle=authority.delivery_cycle,
        cycle_key=authority.cycle_key,
        broker_receipt_id=authority.broker_receipt_id,
        disposition="activated",
        authority=authority,
        should_execute=True,
        should_ack=True,
    )


def _nonexecuting_receipt(
    delivery: orchestrator.StageDeliveryEnvelope,
    disposition: str,
) -> CoordinatedStageReceipt:
    authority = _authority(delivery)
    replayed = disposition == "replayed"
    return CoordinatedStageReceipt(
        workflow_run_id=authority.workflow_run_id,
        stage_run_id=authority.stage_run_id,
        stage_attempt_id=authority.stage_attempt_id if replayed else None,
        message_id=authority.message_id,
        delivery_attempt_id=authority.delivery_attempt_id,
        attempt_number=authority.attempt_number,
        delivery_cycle=authority.delivery_cycle,
        cycle_key=authority.cycle_key,
        broker_receipt_id=authority.broker_receipt_id,
        disposition=disposition,
        authority=None,
        should_execute=False,
        should_ack=True,
    )


def _context(authority: ExecutableStageAuthority) -> orchestrator.StageHandlerContext:
    return orchestrator.StageHandlerContext(
        authority=authority,
        stage_type="claims.extract",
        stage_version="1.0.0",
        config_schema_version="research-stage-config-v1",
        config={"mode": "strict"},
        input_manifest={"source_id": "source-1"},
    )


def _consumer_decision(
    authority: ExecutableStageAuthority,
    *,
    disposition: str = "failed",
    durable_retry: bool = False,
) -> orchestrator.ConsumerDecision:
    return orchestrator.ConsumerDecision(
        disposition=disposition,
        workflow_run_id=authority.workflow_run_id,
        stage_run_id=authority.stage_run_id,
        stage_attempt_id=authority.stage_attempt_id,
        message_id=authority.message_id,
        delivery_attempt_id=authority.delivery_attempt_id,
        attempt_number=authority.attempt_number,
        delivery_cycle=authority.delivery_cycle,
        cycle_key=authority.cycle_key,
        broker_receipt_id=authority.broker_receipt_id,
        should_ack=True,
        durable_retry=durable_retry,
    )


def _stale_completion(authority: ExecutableStageAuthority):
    return orchestrator.CoordinatedStageCompletion(
        workflow_run_id=authority.workflow_run_id,
        stage_run_id=authority.stage_run_id,
        stage_attempt_id=authority.stage_attempt_id,
        message_id=authority.message_id,
        delivery_attempt_id=authority.delivery_attempt_id,
        stage_lease_token=authority.stage_lease_token,
        attempt_number=authority.attempt_number,
        delivery_cycle=authority.delivery_cycle,
        cycle_key=authority.cycle_key,
        broker_receipt_id=authority.broker_receipt_id,
        stage_key=authority.stage_key,
        input_checksum=authority.input_checksum,
        checkpoint_version=authority.checkpoint_version,
        lease_owner=authority.lease_owner,
        lease_expires_at=authority.lease_expires_at,
        outcome="succeeded",
        requested_output_checksum="d" * 64,
        committed_output_checksum=None,
        previous_workflow_state_version=authority.workflow_state_version,
        workflow_state_version=authority.workflow_state_version,
        workflow_status="running",
        previous_stage_state_version=authority.stage_state_version,
        stage_state_version=authority.stage_state_version,
        previous_attempt_state_version=authority.attempt_state_version,
        attempt_state_version=authority.attempt_state_version,
        completed_at=None,
        workflow_completed_at=None,
        emissions=(),
        disposition="stale",
        should_continue=False,
        should_ack=True,
    )


class _Transaction:
    def __init__(self, label: str, events: list[str]) -> None:
        self.label = label
        self.events = events

    async def __aenter__(self):
        self.events.append(f"{self.label}.transaction.enter")
        return self

    async def __aexit__(self, exc_type, _exc, _traceback):
        self.events.append(f"{self.label}.transaction.exit.{'commit' if exc_type is None else 'rollback'}")
        return False


class _Session:
    def __init__(self, label: str, events: list[str]) -> None:
        self.label = label
        self.events = events

    async def __aenter__(self):
        self.events.append(f"{self.label}.session.enter")
        return self

    async def __aexit__(self, exc_type, _exc, _traceback):
        self.events.append(f"{self.label}.session.exit.{'success' if exc_type is None else 'error'}")
        return False

    def begin(self):
        self.events.append(f"{self.label}.transaction.create")
        return _Transaction(self.label, self.events)


class _SessionFactory:
    def __init__(self, events: list[str], count: int) -> None:
        self.events = events
        self.sessions = [_Session(f"uow{index}", events) for index in range(1, count + 1)]
        self.calls = 0

    def __call__(self):
        self.calls += 1
        self.events.append(f"factory.call.{self.calls}")
        return self.sessions[self.calls - 1]


def _mutation(claim: ClaimedOutboxDelivery, *, status: str, replayed: bool = False) -> OutboxDeliveryMutation:
    message = OutboxMessage(id=claim.message_id, status=status)
    delivery = OutboxDeliveryAttempt(
        id=claim.delivery_attempt_id,
        message_id=claim.message_id,
    )
    return OutboxDeliveryMutation(message=message, delivery=delivery, replayed=replayed)


def test_delivery_payload_round_trip_is_exact_and_receipt_is_stable():
    delivery = _delivery()

    payload = delivery.as_payload()
    rebuilt = orchestrator.StageDeliveryEnvelope.from_payload(payload)

    assert rebuilt == delivery
    assert rebuilt is not delivery
    assert rebuilt.claim is not delivery.claim
    assert rebuilt.as_payload() == payload
    assert orchestrator.broker_receipt_fingerprint(rebuilt) == orchestrator.broker_receipt_fingerprint(delivery)


@pytest.mark.parametrize(
    ("path", "mutation"),
    [
        (("top",), lambda payload: payload.update({"extra": True})),
        (("top",), lambda payload: payload.pop("broker")),
        (("claim",), lambda payload: payload["claim"].update({"extra": True})),
        (("claim",), lambda payload: payload["claim"].pop("delivery_token")),
        (("broker",), lambda payload: payload["broker"].update({"extra": True})),
        (("broker",), lambda payload: payload["broker"].pop("message_id")),
    ],
)
def test_delivery_payload_rejects_every_extra_or_missing_field(path, mutation):
    del path
    payload = _delivery().as_payload()
    mutation(payload)

    with pytest.raises(orchestrator.WorkflowOrchestrationError, match="missing or unexpected"):
        orchestrator.StageDeliveryEnvelope.from_payload(payload)


@pytest.mark.asyncio
async def test_publisher_releases_claim_uow_before_broker_and_uses_fresh_mark_uow(monkeypatch):
    claim = _claim()
    events: list[str] = []
    factory = _SessionFactory(events, 2)

    async def claim_one(db, *, publisher_id, lease_seconds):
        events.append("claim.runtime")
        assert db is factory.sessions[0]
        assert publisher_id == "publisher-1"
        assert lease_seconds == 60
        return claim

    async def mark(db, **kwargs):
        events.append("mark.runtime")
        assert db is factory.sessions[1]
        assert kwargs["message_id"] == claim.message_id
        return _mutation(claim, status="awaiting_receipt")

    async def publish(delivery):
        events.append("broker.publish")
        assert factory.calls == 1
        assert events[-2] == "uow1.session.exit.success"
        return orchestrator.BrokerAcceptance(
            broker_name=delivery.broker_name,
            broker_message_id=delivery.broker_message_id,
        )

    monkeypatch.setattr(orchestrator, "_claim_outbox_delivery", claim_one)
    monkeypatch.setattr(orchestrator, "_mark_outbox_dispatched", mark)

    result = await orchestrator.publish_one_outbox_delivery(
        factory,
        publisher=publish,
        publisher_id="publisher-1",
    )

    assert result.disposition == "dispatched"
    assert result.durable_status == "awaiting_receipt"
    assert events.index("uow1.transaction.exit.commit") < events.index("uow1.session.exit.success")
    assert events.index("uow1.session.exit.success") < events.index("broker.publish")
    assert events.index("broker.publish") < events.index("factory.call.2")
    assert events.index("uow2.session.exit.success") < len(events)


@pytest.mark.asyncio
async def test_publish_error_is_persisted_only_after_network_scope_and_in_fresh_uow(monkeypatch):
    claim = _claim()
    events: list[str] = []
    factory = _SessionFactory(events, 2)

    async def claim_one(_db, **_kwargs):
        events.append("claim.runtime")
        return claim

    def publish(_delivery):
        events.append("broker.publish.error")
        raise OSError("broker unavailable")

    async def fail(db, **kwargs):
        events.append("fail.runtime")
        assert db is factory.sessions[1]
        assert kwargs["error"].code == "outbox.publish_failed"
        return _mutation(claim, status="retry_wait")

    monkeypatch.setattr(orchestrator, "_claim_outbox_delivery", claim_one)
    monkeypatch.setattr(orchestrator, "_fail_outbox_delivery", fail)

    result = await orchestrator.publish_one_outbox_delivery(
        factory,
        publisher=publish,
        publisher_id="publisher-1",
    )

    assert result.disposition == "publish_failed"
    assert result.durable_status == "retry_wait"
    assert events.index("uow1.session.exit.success") < events.index("broker.publish.error")
    assert events.index("broker.publish.error") < events.index("factory.call.2")
    assert events.index("uow2.transaction.exit.commit") < events.index("uow2.session.exit.success")


@pytest.mark.asyncio
async def test_mark_error_propagates_after_broker_acceptance(monkeypatch):
    claim = _claim()
    factory = _SessionFactory([], 2)

    async def claim_one(_db, **_kwargs):
        return claim

    def publish(delivery):
        return orchestrator.BrokerAcceptance(delivery.broker_name, delivery.broker_message_id)

    async def mark(_db, **_kwargs):
        raise RuntimeError("mark commit unavailable")

    monkeypatch.setattr(orchestrator, "_claim_outbox_delivery", claim_one)
    monkeypatch.setattr(orchestrator, "_mark_outbox_dispatched", mark)

    with pytest.raises(RuntimeError, match="mark commit unavailable"):
        await orchestrator.publish_one_outbox_delivery(
            factory,
            publisher=publish,
            publisher_id="publisher-1",
        )


def test_handler_registry_is_exact_duplicate_safe_and_seals_on_lookup():
    registry = orchestrator.StageHandlerRegistry()

    async def handler(_context):
        return orchestrator.StageHandlerOutcome(output_manifest={})

    registry.register("claims.extract", "1.0.0", handler)
    with pytest.raises(orchestrator.WorkflowOrchestrationError, match="already registered"):
        registry.register("claims.extract", "1.0.0", handler)

    assert registry.resolve("claims.extract", "1.0.0") is handler
    assert registry.frozen is True
    with pytest.raises(orchestrator.WorkflowOrchestrationError, match="frozen"):
        registry.register("claims.other", "1.0.0", handler)
    with pytest.raises(orchestrator.UnknownStageHandler, match="claims.missing"):
        registry.resolve("claims.missing", "1.0.0")


@pytest.mark.asyncio
async def test_consumer_receipts_and_releases_load_uow_before_lookup_or_handler(monkeypatch):
    delivery = _delivery()
    receipt = _activated_receipt(delivery)
    authority = receipt.authority
    assert authority is not None
    context = _context(authority)
    events: list[str] = []
    factory = _SessionFactory(events, 1)
    registry = orchestrator.StageHandlerRegistry()

    async def handler(presented):
        events.append("handler.execute")
        assert presented == context
        assert "uow1.session.exit.success" in events
        return orchestrator.StageHandlerOutcome(output_manifest={"count": 3})

    registry.register("claims.extract", "1.0.0", handler)

    monkeypatch.setattr(orchestrator, "_coordinate_stage_receipt", _receipt_coordinator(events, receipt))

    async def load(db, *, authority):
        events.append("context.load")
        assert db is factory.sessions[0]
        assert authority == receipt.authority
        return context

    async def complete(_factory, **kwargs):
        events.append("completion.coordinate")
        assert kwargs["authority"] == authority
        assert kwargs["output_manifest"] == {"count": 3}
        return object()

    decision = _consumer_decision(authority, disposition="completed")
    monkeypatch.setattr(orchestrator, "_load_handler_context", load)
    monkeypatch.setattr(orchestrator, "_coordinate_stage_complete", complete)
    monkeypatch.setattr(
        orchestrator,
        "_completion_consumer_decision",
        lambda _result, *, authority: decision,
    )

    result = await orchestrator.consume_stage_delivery(
        factory,
        delivery=delivery.as_payload(),
        worker_id="worker-1",
        handlers=registry,
    )

    assert result == decision
    assert events.index("receipt.coordinate") < events.index("factory.call.1")
    assert events.index("uow1.session.exit.success") < events.index("handler.execute")
    assert events.index("handler.execute") < events.index("completion.coordinate")


@pytest.mark.asyncio
async def test_unknown_handler_fails_closed_without_business_execution(monkeypatch):
    delivery = _delivery()
    receipt = _activated_receipt(delivery)
    authority = receipt.authority
    assert authority is not None
    factory = _SessionFactory([], 1)
    registry = orchestrator.StageHandlerRegistry()
    failure_calls: list[dict[str, object]] = []

    monkeypatch.setattr(orchestrator, "_coordinate_stage_receipt", _receipt_coordinator([], receipt))
    monkeypatch.setattr(orchestrator, "_load_handler_context", _context_loader(_context(authority)))

    async def record(_factory, **kwargs):
        failure_calls.append(kwargs)
        return _consumer_decision(authority)

    monkeypatch.setattr(orchestrator, "_record_stage_failure", record)

    result = await orchestrator.consume_stage_delivery(
        factory,
        delivery=delivery,
        worker_id="worker-1",
        handlers=registry,
    )

    assert result.disposition == "failed"
    assert failure_calls[0]["error_code"] == "workflow.stage_handler_unregistered"
    assert failure_calls[0]["retryable"] is False
    assert registry.frozen is True


@pytest.mark.asyncio
@pytest.mark.parametrize("disposition", ["replayed", "stale", "cancelled"])
async def test_immutable_noexecute_receipt_is_acknowledged_without_lookup_or_db(monkeypatch, disposition):
    delivery = _delivery()
    receipt = _nonexecuting_receipt(delivery, disposition)
    events: list[str] = []
    factory = _SessionFactory(events, 0)
    registry = orchestrator.StageHandlerRegistry()
    monkeypatch.setattr(orchestrator, "_coordinate_stage_receipt", _receipt_coordinator(events, receipt))

    result = await orchestrator.consume_stage_delivery(
        factory,
        delivery=delivery,
        worker_id="worker-1",
        handlers=registry,
    )

    assert result.disposition == f"receipt_{disposition}"
    assert result.should_ack is True
    assert factory.calls == 0
    assert registry.frozen is False


@pytest.mark.asyncio
async def test_consumer_rejects_exact_receipt_for_another_transport(monkeypatch):
    delivery = _delivery()
    foreign_receipt = replace(
        _nonexecuting_receipt(delivery, "stale"),
        workflow_run_id=uuid.uuid4(),
        stage_run_id=uuid.uuid4(),
    )
    monkeypatch.setattr(
        orchestrator,
        "_coordinate_stage_receipt",
        _receipt_coordinator([], foreign_receipt),
    )

    with pytest.raises(orchestrator.WorkflowOrchestrationError, match="transported delivery lineage"):
        await orchestrator.consume_stage_delivery(
            _SessionFactory([], 0),
            delivery=delivery,
            worker_id="worker-1",
            handlers=orchestrator.StageHandlerRegistry(),
        )


def test_worker_result_must_preserve_the_complete_executable_lease_lineage():
    authority = _authority(_delivery())
    valid = _stale_completion(authority)
    orchestrator._assert_worker_result_matches_authority(valid, authority=authority)

    changed = replace(
        valid,
        lease_expires_at=authority.lease_expires_at + timedelta(seconds=1),
    )
    with pytest.raises(orchestrator.WorkflowOrchestrationError, match="executable receipt lineage"):
        orchestrator._assert_worker_result_matches_authority(changed, authority=authority)


@pytest.mark.asyncio
async def test_consumer_revalidates_mutated_exact_receipt_before_ack(monkeypatch):
    delivery = _delivery()
    receipt = _nonexecuting_receipt(delivery, "stale")
    object.__setattr__(receipt, "disposition", "activated")
    monkeypatch.setattr(
        orchestrator,
        "_coordinate_stage_receipt",
        _receipt_coordinator([], receipt),
    )

    with pytest.raises(orchestrator.WorkflowOrchestrationError, match="fixed point"):
        await orchestrator.consume_stage_delivery(
            _SessionFactory([], 0),
            delivery=delivery,
            worker_id="worker-1",
            handlers=orchestrator.StageHandlerRegistry(),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error_type",
    [OutboxNotFound, OutboxLeaseLost, OutboxStoredContractError],
)
async def test_consumer_classifies_durably_stale_receipt_authority_for_discard(
    monkeypatch,
    error_type,
):
    delivery = _delivery()

    async def stale(*_args, **_kwargs):
        raise error_type("sensitive durable detail")

    monkeypatch.setattr(orchestrator, "_coordinate_stage_receipt", stale)

    with pytest.raises(orchestrator.DiscardStageDelivery) as raised:
        await orchestrator.consume_stage_delivery(
            _SessionFactory([], 0),
            delivery=delivery,
            worker_id="worker-1",
            handlers=orchestrator.StageHandlerRegistry(),
        )

    assert str(raised.value) == "Workflow delivery authority is no longer live"
    assert raised.value.__cause__ is None


@pytest.mark.asyncio
async def test_handler_exception_records_retryable_failure_after_handler_scope(monkeypatch):
    delivery = _delivery()
    receipt = _activated_receipt(delivery)
    authority = receipt.authority
    assert authority is not None
    factory = _SessionFactory([], 1)
    registry = orchestrator.StageHandlerRegistry()

    async def handler(_context):
        raise RuntimeError("transient dependency failed")

    registry.register("claims.extract", "1.0.0", handler)
    monkeypatch.setattr(orchestrator, "_coordinate_stage_receipt", _receipt_coordinator([], receipt))
    monkeypatch.setattr(orchestrator, "_load_handler_context", _context_loader(_context(authority)))
    recorded: dict[str, object] = {}

    async def record(_factory, **kwargs):
        recorded.update(kwargs)
        return _consumer_decision(authority, durable_retry=True)

    monkeypatch.setattr(orchestrator, "_record_stage_failure", record)

    result = await orchestrator.consume_stage_delivery(
        factory,
        delivery=delivery,
        worker_id="worker-1",
        handlers=registry,
    )

    assert result.should_ack is True
    assert result.durable_retry is True
    assert recorded["error_code"] == "workflow.stage_handler_error"
    assert recorded["retryable"] is True


@pytest.mark.asyncio
async def test_handler_contract_exception_records_nonretryable_failure(monkeypatch):
    delivery = _delivery()
    receipt = _activated_receipt(delivery)
    authority = receipt.authority
    assert authority is not None
    registry = orchestrator.StageHandlerRegistry()
    recorded: dict[str, object] = {}

    async def handler(_context):
        return orchestrator.StageHandlerOutcome(output_manifest={}, outcome="not-supported")

    async def record(_factory, **kwargs):
        recorded.update(kwargs)
        return _consumer_decision(authority)

    registry.register("claims.extract", "1.0.0", handler)
    monkeypatch.setattr(orchestrator, "_coordinate_stage_receipt", _receipt_coordinator([], receipt))
    monkeypatch.setattr(orchestrator, "_load_handler_context", _context_loader(_context(authority)))
    monkeypatch.setattr(orchestrator, "_record_stage_failure", record)

    result = await orchestrator.consume_stage_delivery(
        _SessionFactory([], 1),
        delivery=delivery,
        worker_id="worker-1",
        handlers=registry,
    )

    assert result.disposition == "failed"
    assert recorded["error_code"] == "workflow.stage_handler_contract"
    assert recorded["retryable"] is False


@pytest.mark.asyncio
async def test_mutated_exact_handler_outcome_records_nonretryable_contract_failure(monkeypatch):
    delivery = _delivery()
    receipt = _activated_receipt(delivery)
    authority = receipt.authority
    assert authority is not None
    registry = orchestrator.StageHandlerRegistry()
    recorded: dict[str, object] = {}

    async def handler(_context):
        outcome = orchestrator.StageHandlerOutcome(output_manifest={})
        object.__setattr__(outcome, "outcome", "forged")
        return outcome

    async def record(_factory, **kwargs):
        recorded.update(kwargs)
        return _consumer_decision(authority)

    registry.register("claims.extract", "1.0.0", handler)
    monkeypatch.setattr(orchestrator, "_coordinate_stage_receipt", _receipt_coordinator([], receipt))
    monkeypatch.setattr(orchestrator, "_load_handler_context", _context_loader(_context(authority)))
    monkeypatch.setattr(orchestrator, "_record_stage_failure", record)

    result = await orchestrator.consume_stage_delivery(
        _SessionFactory([], 1),
        delivery=delivery,
        worker_id="worker-1",
        handlers=registry,
    )

    assert result.disposition == "failed"
    assert recorded["error_code"] == "workflow.stage_handler_contract"
    assert recorded["retryable"] is False


@pytest.mark.asyncio
async def test_persisted_handler_contract_error_is_bounded_before_dispatch():
    delivery = _delivery()
    authority = _authority(delivery)
    stage = StageRun(
        id=authority.stage_run_id,
        workflow_run_id=authority.workflow_run_id,
        stage_key=authority.stage_key,
        stage_type="claims.extract",
        stage_version="invalid version",
        status="running",
        state_version=authority.stage_state_version,
        attempt_count=authority.attempt_number,
        lease_token=authority.stage_lease_token,
        lease_owner=authority.lease_owner,
        lease_expires_at=authority.lease_expires_at,
        input_checksum=authority.input_checksum,
        checkpoint_version=authority.checkpoint_version,
        config_schema_version="research-stage-config-v1",
        config={},
        input_manifest={},
    )

    class _DB:
        async def scalar(self, _query):
            return stage

    with pytest.raises(orchestrator._StoredStageContractError, match="handler contract"):
        await orchestrator._load_handler_context(_DB(), authority=authority)


@pytest.mark.asyncio
async def test_receipt_and_completion_infrastructure_errors_propagate(monkeypatch):
    delivery = _delivery()
    registry = orchestrator.StageHandlerRegistry()

    async def handler(_context):
        return orchestrator.StageHandlerOutcome(output_manifest={})

    registry.register("claims.extract", "1.0.0", handler)

    async def receipt_error(*_args, **_kwargs):
        raise RuntimeError("receipt commit unavailable")

    monkeypatch.setattr(orchestrator, "_coordinate_stage_receipt", receipt_error)
    with pytest.raises(RuntimeError, match="receipt commit unavailable"):
        await orchestrator.consume_stage_delivery(
            _SessionFactory([], 0),
            delivery=delivery,
            worker_id="worker-1",
            handlers=registry,
        )

    receipt = _activated_receipt(delivery)
    authority = receipt.authority
    assert authority is not None
    registry = orchestrator.StageHandlerRegistry()
    registry.register("claims.extract", "1.0.0", handler)
    monkeypatch.setattr(orchestrator, "_coordinate_stage_receipt", _receipt_coordinator([], receipt))
    monkeypatch.setattr(orchestrator, "_load_handler_context", _context_loader(_context(authority)))

    async def completion_error(*_args, **_kwargs):
        raise RuntimeError("completion commit unavailable")

    monkeypatch.setattr(orchestrator, "_coordinate_stage_complete", completion_error)
    with pytest.raises(RuntimeError, match="completion commit unavailable"):
        await orchestrator.consume_stage_delivery(
            _SessionFactory([], 1),
            delivery=delivery,
            worker_id="worker-1",
            handlers=registry,
        )


@pytest.mark.asyncio
async def test_recovery_pass_is_injected_and_bounded():
    calls: list[tuple[object, int]] = []
    factory = lambda: None

    async def adapter(session_factory, limit):
        calls.append((session_factory, limit))
        return 3

    assert await orchestrator.run_recovery_pass(factory, adapter=adapter, limit=10) == 3
    assert calls == [(factory, 10)]


@pytest.mark.asyncio
async def test_recovery_pass_limit_matches_the_worker_maximum():
    calls: list[int] = []
    factory = lambda: None

    async def adapter(_session_factory, limit):
        calls.append(limit)
        return 0

    assert orchestrator.WORKFLOW_RECOVERY_LIMIT_MAX == 500
    assert await orchestrator.run_recovery_pass(factory, adapter=adapter, limit=500) == 0
    with pytest.raises(orchestrator.WorkflowOrchestrationError, match="from 1 to 500"):
        await orchestrator.run_recovery_pass(factory, adapter=adapter, limit=501)
    with pytest.raises(orchestrator.WorkflowOrchestrationError, match="from 1 to 500"):
        await orchestrator.recover_expired_outbox_pass(factory, limit=501)
    assert calls == [500]


@pytest.mark.asyncio
async def test_outbox_recovery_pass_commits_exact_bounded_results(monkeypatch):
    events: list[str] = []
    factory = _SessionFactory(events, 1)
    result = OutboxRecoveryResult(
        message_id=uuid.uuid4(),
        delivery_attempt_id=uuid.uuid4(),
        message_status="retry_wait",
        available_at=NOW,
    )

    async def recover(db, *, limit):
        events.append("outbox.recover")
        assert db is factory.sessions[0]
        assert limit == 7
        return [result]

    monkeypatch.setattr(orchestrator, "_recover_expired_outbox_deliveries", recover)

    assert await orchestrator.recover_expired_outbox_pass(factory, limit=7) == 1
    assert events[-2:] == [
        "uow1.transaction.exit.commit",
        "uow1.session.exit.success",
    ]


@pytest.mark.asyncio
async def test_outbox_recovery_rejects_invalid_result_before_commit(monkeypatch):
    events: list[str] = []
    factory = _SessionFactory(events, 1)

    async def recover(_db, *, limit):
        assert limit == 1
        return [
            OutboxRecoveryResult(
                message_id=uuid.uuid4(),
                delivery_attempt_id=uuid.uuid4(),
                message_status="forged",
                available_at=None,
            )
        ]

    monkeypatch.setattr(orchestrator, "_recover_expired_outbox_deliveries", recover)

    with pytest.raises(orchestrator.WorkflowOrchestrationError, match="closed registry"):
        await orchestrator.recover_expired_outbox_pass(factory, limit=1)
    assert "uow1.transaction.exit.rollback" in events


def _receipt_coordinator(events: list[str], receipt: CoordinatedStageReceipt):
    async def coordinate(_factory, *, command):
        events.append("receipt.coordinate")
        assert command.broker_receipt_id == orchestrator.broker_receipt_fingerprint(
            orchestrator.StageDeliveryEnvelope(
                claim=command.claim,
                broker_name=command.broker_name,
                broker_message_id=command.broker_message_id,
            )
        )
        return receipt

    return coordinate


def _context_loader(context: orchestrator.StageHandlerContext):
    async def load(_db, *, authority):
        assert authority == context.authority
        return context

    return load
