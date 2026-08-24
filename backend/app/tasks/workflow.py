"""Celery transport adapters for durable workflow publisher and workers."""

from __future__ import annotations

import asyncio
import inspect
import logging
import threading
from collections.abc import Coroutine
from dataclasses import fields
from typing import Any
from uuid import UUID

from celery.exceptions import Reject

from app.core.database import async_session_factory, engine
from app.services.research_workflows import (
    RESEARCH_SCOPE_STAGE_TYPE,
    RESEARCH_SCOPE_STAGE_VERSION,
    run_research_scope_stage,
)
from app.services.outbox_runtime import OutboxStoredContractError
from app.services.workflow_orchestrator import (
    BrokerAcceptance,
    ConsumerDecision,
    DiscardStageDelivery,
    PublisherDecision,
    RecoveryAdapter,
    SessionFactory,
    StageDeliveryEnvelope,
    StageHandler,
    StageHandlerRegistry,
    WORKFLOW_RECOVERY_LIMIT_MAX,
    WorkflowOrchestrationError,
    broker_receipt_fingerprint,
    consume_stage_delivery,
    publish_one_outbox_delivery,
    recover_expired_outbox_pass,
    run_recovery_pass,
)
from app.services.workflow_runtime import WorkflowStoredContractError
from app.services.workflow_worker import (
    CoordinatedStageRecovery,
    coordinate_expired_stage_recovery_pass,
)
from app.tasks.celery_app import celery_app


logger = logging.getLogger(__name__)
stage_handler_registry = StageHandlerRegistry()
stage_handler_registry.register(
    RESEARCH_SCOPE_STAGE_TYPE,
    RESEARCH_SCOPE_STAGE_VERSION,
    run_research_scope_stage,
)
_recovery_lock = threading.RLock()
_recovery_adapter: RecoveryAdapter | None = None
_RECOVERY_FAILURE_METRIC = "adversarygraph_workflow_recovery_failure_total"
_RECOVERY_QUARANTINE_METRIC = "adversarygraph_workflow_recovery_stored_contract_quarantine_total"
_RECOVERY_SUCCESS_METRIC = "adversarygraph_workflow_recovery_success_total"
_STORED_CONTRACT_ERRORS = (OutboxStoredContractError, WorkflowStoredContractError)

__all__ = (
    "configure_workflow_recovery",
    "execute_stage_delivery",
    "freeze_stage_handlers",
    "publish_due_workflow_deliveries",
    "recover_expired_outbox_authority",
    "recover_workflow_authority",
    "register_stage_handler",
    "stage_handler_registry",
)


def register_stage_handler(stage_type: str, stage_version: str, handler: StageHandler) -> None:
    """Register one exact business handler during worker process startup."""

    stage_handler_registry.register(stage_type, stage_version, handler)


def freeze_stage_handlers() -> None:
    """Explicitly seal registration; first consumer lookup also seals it."""

    stage_handler_registry.freeze()


def configure_workflow_recovery(adapter: RecoveryAdapter) -> None:
    """Bind the recovery coordinator once its public API has frozen."""

    if not callable(adapter) or not inspect.iscoroutinefunction(adapter):
        raise WorkflowOrchestrationError("Recovery adapter must be an async callable")
    global _recovery_adapter
    with _recovery_lock:
        if _recovery_adapter is not None:
            raise WorkflowOrchestrationError("Workflow recovery adapter is already configured")
        _recovery_adapter = adapter


async def _coordinate_expired_stage_recovery(
    session_factory: SessionFactory,
    limit: int,
) -> int:
    raw_results = await coordinate_expired_stage_recovery_pass(
        session_factory,
        limit=limit,
    )
    if type(raw_results) is not tuple or len(raw_results) > limit:
        raise WorkflowOrchestrationError("Workflow recovery returned an invalid result batch")
    for raw_result in raw_results:
        _fixed_task_result(
            raw_result,
            CoordinatedStageRecovery,
            field_name="workflow recovery coordinator result",
        )
    return len(raw_results)


configure_workflow_recovery(_coordinate_expired_stage_recovery)


def _celery_publish(delivery: StageDeliveryEnvelope) -> BrokerAcceptance:
    result = celery_app.send_task(
        "workflow.execute_stage",
        kwargs={"delivery": delivery.as_payload()},
        task_id=delivery.broker_message_id,
        kwargsrepr="<redacted workflow delivery authority>",
    )
    result_id = getattr(result, "id", None)
    if type(result_id) is not str or result_id != delivery.broker_message_id:
        raise WorkflowOrchestrationError("Celery acceptance changed the fixed broker message id")
    return BrokerAcceptance(
        broker_name=delivery.broker_name,
        broker_message_id=result_id,
    )


@celery_app.task(
    bind=True,
    name="workflow.publish_due",
    acks_late=True,
    acks_on_failure_or_timeout=False,
    reject_on_worker_lost=True,
)
def publish_due_workflow_deliveries(self, limit: int = 100) -> dict[str, Any]:
    """Publish a bounded batch; every delivery has its own short claim UoW."""

    if type(limit) is not int or not 1 <= limit <= 1_000:
        raise WorkflowOrchestrationError("Publisher limit must be an integer from 1 to 1000")
    publisher_id = _request_worker_id(self.request, prefix="publisher")

    async def publish_batch() -> list[PublisherDecision]:
        await engine.dispose()
        try:
            decisions: list[PublisherDecision] = []
            for _index in range(limit):
                raw_decision = await publish_one_outbox_delivery(
                    async_session_factory,
                    publisher=_celery_publish,
                    publisher_id=publisher_id,
                )
                decision = _fixed_task_result(
                    raw_decision,
                    PublisherDecision,
                    field_name="publisher coordinator decision",
                )
                decisions.append(decision)
                if decision.disposition == "empty":
                    break
            return decisions
        finally:
            await engine.dispose()

    decisions = asyncio.run(publish_batch())
    return {
        "claimed": sum(decision.disposition != "empty" for decision in decisions),
        "dispatched": sum(decision.disposition == "dispatched" for decision in decisions),
        "publish_failed": sum(decision.disposition == "publish_failed" for decision in decisions),
        "empty": bool(decisions and decisions[-1].disposition == "empty"),
    }


@celery_app.task(
    bind=True,
    name="workflow.execute_stage",
    acks_late=True,
    acks_on_failure_or_timeout=False,
    reject_on_worker_lost=True,
)
def execute_stage_delivery(self, delivery: dict[str, object]) -> dict[str, Any]:
    """Receipt and execute one stage; unsafe outcomes reject for redelivery."""

    worker_id = _request_worker_id(self.request, prefix="worker")
    try:
        transport = _validated_celery_delivery(self.request, delivery)
    except WorkflowOrchestrationError as exc:
        # Deterministically malformed or cross-bound transport cannot become
        # valid through redelivery. Reject it without a poison-message loop.
        raise Reject("invalid workflow delivery transport", requeue=False) from None

    async def execute() -> ConsumerDecision:
        await engine.dispose()
        try:
            return await consume_stage_delivery(
                async_session_factory,
                delivery=transport,
                worker_id=worker_id,
                handlers=stage_handler_registry,
            )
        finally:
            await engine.dispose()

    try:
        raw_decision = asyncio.run(execute())
        decision = _fixed_task_result(
            raw_decision,
            ConsumerDecision,
            field_name="workflow coordinator decision",
        )
        _assert_consumer_decision_matches_transport(decision, transport=transport)
    except DiscardStageDelivery:
        raise Reject("workflow delivery authority is no longer live", requeue=False) from None
    except Exception:
        # No coordinator result authorized acknowledgement.  Reject the
        # original delivery so its exact broker identity is redelivered.
        raise Reject("workflow delivery was not acknowledgement-safe", requeue=True) from None
    if not decision.should_ack:  # pragma: no cover - sealed DTO invariant
        raise Reject("workflow coordinator withheld acknowledgement", requeue=True)
    return {
        "disposition": decision.disposition,
        "workflow_run_id": str(decision.workflow_run_id),
        "stage_run_id": str(decision.stage_run_id),
        "stage_attempt_id": str(decision.stage_attempt_id) if decision.stage_attempt_id is not None else None,
        "durable_retry": decision.durable_retry,
    }


@celery_app.task(
    bind=True,
    name="workflow.recover_outbox",
    acks_late=True,
    acks_on_failure_or_timeout=False,
    reject_on_worker_lost=True,
)
def recover_expired_outbox_authority(self, limit: int = 100) -> dict[str, int]:
    """Recover expired publisher and receipt leases in one committed batch."""

    del self
    clean_limit = _recovery_limit(limit)

    async def recover() -> int:
        await engine.dispose()
        try:
            return await recover_expired_outbox_pass(
                async_session_factory,
                limit=clean_limit,
            )
        finally:
            await engine.dispose()

    return _run_recovery_with_observability(recover(), kind="outbox")


@celery_app.task(
    bind=True,
    name="workflow.recover_expired",
    acks_late=True,
    acks_on_failure_or_timeout=False,
    reject_on_worker_lost=True,
)
def recover_workflow_authority(self, limit: int = 100) -> dict[str, int]:
    """Periodic entrypoint kept fail-closed until recovery is configured."""

    del self
    clean_limit = _recovery_limit(limit)
    with _recovery_lock:
        adapter = _recovery_adapter
    if adapter is None:
        logger.error(
            "metric=%s kind=stage count=1 error_class=WorkflowOrchestrationError",
            _RECOVERY_FAILURE_METRIC,
        )
        raise WorkflowOrchestrationError("Workflow recovery coordinator is not configured")

    async def recover() -> int:
        await engine.dispose()
        try:
            return await run_recovery_pass(
                async_session_factory,
                adapter=adapter,
                limit=clean_limit,
            )
        finally:
            await engine.dispose()

    return _run_recovery_with_observability(recover(), kind="stage")


def _recovery_limit(value: object) -> int:
    if type(value) is not int or not 1 <= value <= WORKFLOW_RECOVERY_LIMIT_MAX:
        raise WorkflowOrchestrationError(f"Recovery limit must be an integer from 1 to {WORKFLOW_RECOVERY_LIMIT_MAX}")
    return value


def _run_recovery_with_observability(
    operation: Coroutine[Any, Any, int],
    *,
    kind: str,
) -> dict[str, int]:
    """Run one recovery pass and emit only bounded, low-cardinality signals."""

    try:
        recovered = asyncio.run(operation)
    except _STORED_CONTRACT_ERRORS as exc:
        error_class = type(exc).__name__
        logger.error(
            "metric=%s kind=%s count=1 error_class=%s stored_contract=true",
            _RECOVERY_FAILURE_METRIC,
            kind,
            error_class,
        )
        logger.error(
            "metric=%s kind=%s count=1 error_class=%s",
            _RECOVERY_QUARANTINE_METRIC,
            kind,
            error_class,
        )
        raise WorkflowOrchestrationError("Workflow recovery detected invalid stored authority; operator review is required") from None
    except Exception as exc:
        logger.error(
            "metric=%s kind=%s count=1 error_class=%s stored_contract=false",
            _RECOVERY_FAILURE_METRIC,
            kind,
            type(exc).__name__,
        )
        raise WorkflowOrchestrationError("Workflow recovery pass failed") from None
    logger.info(
        "metric=%s kind=%s count=1 recovered=%d",
        _RECOVERY_SUCCESS_METRIC,
        kind,
        recovered,
    )
    return {"recovered": recovered}


def _request_worker_id(request: object, *, prefix: str) -> str:
    hostname = getattr(request, "hostname", None)
    if type(hostname) is not str or not hostname.strip():
        hostname = "unknown"
    normalized = " ".join(hostname.strip().split())
    value = f"celery-{prefix}:{normalized}"
    return value[:255]


def _validated_celery_delivery(request: object, value: object) -> StageDeliveryEnvelope:
    transport = StageDeliveryEnvelope.from_payload(value)
    request_id = getattr(request, "id", None)
    if type(request_id) is not str or request_id != transport.broker_message_id:
        raise WorkflowOrchestrationError("Celery request id does not match the fixed broker message id")
    if transport.broker_name != "celery":
        raise WorkflowOrchestrationError("Celery task received delivery authority for another broker")
    return transport


def _assert_consumer_decision_matches_transport(
    decision: ConsumerDecision,
    *,
    transport: StageDeliveryEnvelope,
) -> None:
    claim = transport.claim
    payload = claim.envelope["payload"]
    if (
        decision.workflow_run_id != UUID(str(payload["workflow_run_id"]))
        or decision.stage_run_id != UUID(str(payload["stage_run_id"]))
        or decision.attempt_number != payload["target_attempt_number"]
        or decision.message_id != claim.message_id
        or decision.delivery_attempt_id != claim.delivery_attempt_id
        or decision.delivery_cycle != claim.delivery_cycle
        or decision.cycle_key != claim.cycle_key
        or decision.broker_receipt_id != broker_receipt_fingerprint(transport)
    ):
        raise WorkflowOrchestrationError("Workflow decision changed the transported delivery lineage")


def _fixed_task_result(
    value: object,
    result_type: type[Any],
    *,
    field_name: str,
) -> Any:
    if type(value) is not result_type:
        raise WorkflowOrchestrationError(f"{field_name} has an invalid type")
    try:
        return result_type(**{field.name: getattr(value, field.name) for field in fields(result_type) if field.init})
    except Exception as exc:
        raise WorkflowOrchestrationError(f"{field_name} violates its fixed point") from exc
