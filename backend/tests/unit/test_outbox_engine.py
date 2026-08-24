import ast
import hashlib
import inspect
import math
import time
from types import MappingProxyType
from uuid import UUID

import pytest
from pydantic import ValidationError

from app.services import outbox_engine, workflow_engine
from app.services.outbox_engine import (
    MAX_DELIVERY_CYCLE,
    MAX_ERROR_WORKING_BYTES,
    MAX_OUTBOX_CANONICAL_BYTES,
    MAX_OUTBOX_JSON_ITEMS,
    SCHEMA_WORKFLOW_STAGE_READY_V1,
    TOPIC_SCHEMA_REGISTRY,
    TOPIC_WORKFLOW_STAGE_READY,
    NormalizedOutboxEnvelope,
    OutboxCanonicalJSONError,
    OutboxContractError,
    OutboxEnvelope,
    OutboxEnvelopeValidationError,
    OutboxKeyError,
    OutboxRetryPolicy,
    SanitizedOutboxError,
    WorkflowStageReadyPayload,
    canonical_outbox_json,
    delivery_cycle_idempotency_key,
    derive_outbox_logical_key,
    deterministic_delivery_retry_delay_seconds,
    normalize_outbox_envelope,
    sanitize_outbox_error,
)
from app.services.workflow_engine import sanitize_workflow_error


WORKFLOW_ID = "018f7f31-6f00-7a11-8b33-0123456789ab"
STAGE_ID = "018f7f31-7000-7f22-9c44-abcdef012345"
INPUT_CHECKSUM = "1" * 64
PLAN_CHECKSUM = "2" * 64


def _envelope(**payload_overrides):
    payload = {
        "workflow_run_id": WORKFLOW_ID,
        "stage_run_id": STAGE_ID,
        "stage_key": "report.review",
        "target_attempt_number": 1,
        "input_checksum": INPUT_CHECKSUM,
        "plan_checksum": PLAN_CHECKSUM,
    }
    payload.update(payload_overrides)
    return {
        "topic": TOPIC_WORKFLOW_STAGE_READY,
        "schema_version": SCHEMA_WORKFLOW_STAGE_READY_V1,
        "payload": payload,
    }


def test_registry_and_payload_are_closed_pointer_only_contracts():
    assert isinstance(TOPIC_SCHEMA_REGISTRY, MappingProxyType)
    assert dict(TOPIC_SCHEMA_REGISTRY) == {"workflow.stage.ready": "workflow-stage-ready-v1"}
    with pytest.raises(TypeError):
        TOPIC_SCHEMA_REGISTRY["new.topic"] = "new-schema-v1"  # type: ignore[index]

    assert set(WorkflowStageReadyPayload.model_fields) == {
        "workflow_run_id",
        "stage_run_id",
        "stage_key",
        "target_attempt_number",
        "input_checksum",
        "plan_checksum",
    }
    assert set(OutboxEnvelope.model_fields) == {"topic", "schema_version", "payload"}

    normalized = normalize_outbox_envelope(_envelope())
    assert isinstance(normalized.payload.workflow_run_id, UUID)
    assert normalized.as_payload()["payload"] == _envelope()["payload"]
    assert len(normalized.canonical.encode("utf-8")) <= MAX_OUTBOX_CANONICAL_BYTES
    assert normalized.checksum == hashlib.sha256(normalized.canonical.encode()).hexdigest()


def test_envelope_is_strict_registry_bound_and_database_bounded():
    with pytest.raises(OutboxEnvelopeValidationError, match="Extra inputs"):
        normalize_outbox_envelope({**_envelope(), "metadata": {"safe": True}})

    wrong_topic = _envelope()
    wrong_topic["topic"] = "workflow.stage.finished"
    with pytest.raises(OutboxEnvelopeValidationError, match="workflow.stage.ready"):
        normalize_outbox_envelope(wrong_topic)

    wrong_schema = _envelope()
    wrong_schema["schema_version"] = "workflow-stage-ready-v2"
    with pytest.raises(OutboxEnvelopeValidationError, match="workflow-stage-ready-v1"):
        normalize_outbox_envelope(wrong_schema)

    for overrides, message in [
        ({"workflow_run_id": "not-a-uuid"}, "UUID"),
        ({"target_attempt_number": True}, "valid integer"),
        ({"target_attempt_number": 21}, "less than or equal to 20"),
        ({"input_checksum": "A" * 64}, "pattern"),
        ({"stage_key": "Invalid Stage"}, "pattern"),
    ]:
        with pytest.raises(OutboxEnvelopeValidationError, match=message):
            normalize_outbox_envelope(_envelope(**overrides))

    for noncanonical_uuid in [
        WORKFLOW_ID.upper(),
        WORKFLOW_ID.replace("-", ""),
        f"{{{WORKFLOW_ID}}}",
        f"urn:uuid:{WORKFLOW_ID}",
    ]:
        with pytest.raises(OutboxEnvelopeValidationError, match="canonical lowercase hyphenated"):
            normalize_outbox_envelope(_envelope(workflow_run_id=noncanonical_uuid))

    with pytest.raises(ValidationError, match="Extra inputs"):
        WorkflowStageReadyPayload.model_validate({**_envelope()["payload"], "source_url": "https://example.test"})


def test_normalization_is_deterministic_and_business_identity_is_content_aware():
    first = normalize_outbox_envelope(_envelope())
    reordered = _envelope()
    reordered["payload"] = dict(reversed(list(reordered["payload"].items())))
    reordered = dict(reversed(list(reordered.items())))
    second = normalize_outbox_envelope(reordered)

    assert first == second
    assert derive_outbox_logical_key(_envelope()) == first.logical_key

    changed = normalize_outbox_envelope(_envelope(input_checksum="3" * 64, plan_checksum="4" * 64))
    # One business event cannot acquire a second identity merely because its
    # supposedly immutable authority drifted. Persistence can flag the same
    # logical key carrying a contradictory exact-content checksum.
    assert changed.logical_key == first.logical_key
    assert changed.checksum != first.checksum

    next_attempt = normalize_outbox_envelope(_envelope(target_attempt_number=2))
    assert next_attempt.logical_key != first.logical_key


def test_normalization_revalidates_mutated_models_and_detaches_authority():
    payload = WorkflowStageReadyPayload.model_validate(_envelope()["payload"])
    payload.target_attempt_number = 0
    with pytest.raises(OutboxEnvelopeValidationError, match="greater than or equal to 1"):
        normalize_outbox_envelope(
            {
                "topic": TOPIC_WORKFLOW_STAGE_READY,
                "schema_version": SCHEMA_WORKFLOW_STAGE_READY_V1,
                "payload": payload,
            }
        )

    envelope = OutboxEnvelope.model_validate(_envelope())
    envelope.payload.input_checksum = "A" * 64
    with pytest.raises(OutboxEnvelopeValidationError, match="pattern"):
        normalize_outbox_envelope(envelope)

    normalized = normalize_outbox_envelope(_envelope())
    detached = normalized.envelope
    detached.payload.target_attempt_number = 19
    detached_dict = normalized.as_payload()
    detached_dict["payload"]["stage_key"] = "tampered"

    assert normalized.payload.target_attempt_number == 1
    assert normalized.payload.stage_key == "report.review"


def test_normalized_constructor_rejects_tampering_and_noncanonical_authority():
    normalized = normalize_outbox_envelope(_envelope())
    with pytest.raises(OutboxEnvelopeValidationError, match="metadata"):
        NormalizedOutboxEnvelope(
            canonical=normalized.canonical,
            checksum="0" * 64,
            logical_key=normalized.logical_key,
        )
    with pytest.raises(OutboxEnvelopeValidationError, match="metadata"):
        NormalizedOutboxEnvelope(
            canonical=normalized.canonical,
            checksum=normalized.checksum,
            logical_key="0" * 64,
        )

    pretty = __import__("json").dumps(normalized.as_payload(), indent=2)
    with pytest.raises(OutboxEnvelopeValidationError, match="metadata"):
        NormalizedOutboxEnvelope(
            canonical=pretty,
            checksum=hashlib.sha256(pretty.encode()).hexdigest(),
            logical_key=normalized.logical_key,
        )


def test_normalized_constructor_and_detached_read_bound_recursive_json_poison():
    nested = "[" * 10_000 + "0" + "]" * 10_000
    with pytest.raises(OutboxEnvelopeValidationError, match="invalid canonical authority"):
        NormalizedOutboxEnvelope(
            canonical=nested,
            checksum="0" * 64,
            logical_key="1" * 64,
        )

    normalized = normalize_outbox_envelope(_envelope())
    object.__setattr__(normalized, "canonical", nested)
    with pytest.raises(OutboxEnvelopeValidationError, match="invalid canonical authority"):
        normalized.as_payload()


def test_normalized_constructor_rejects_hostile_python_string_types():
    normalized = normalize_outbox_envelope(_envelope())

    class HostileStr(str):
        def encode(self, *args, **kwargs):
            raise AssertionError("hostile encode must never run")

        def __eq__(self, other):
            return True

        def __ne__(self, other):
            return False

    class EqualityObject:
        comparisons = 0

        def __eq__(self, other):
            self.comparisons += 1
            return True

        def __ne__(self, other):
            self.comparisons += 1
            return False

    hostile_values = [
        {
            "canonical": HostileStr(normalized.canonical),
            "checksum": normalized.checksum,
            "logical_key": normalized.logical_key,
        },
        {
            "canonical": normalized.canonical,
            "checksum": HostileStr(normalized.checksum),
            "logical_key": normalized.logical_key,
        },
        {
            "canonical": normalized.canonical,
            "checksum": normalized.checksum,
            "logical_key": HostileStr(normalized.logical_key),
        },
    ]
    liar = EqualityObject()
    hostile_values.append(
        {
            "canonical": normalized.canonical,
            "checksum": liar,
            "logical_key": normalized.logical_key,
        }
    )
    for values in hostile_values:
        with pytest.raises(OutboxEnvelopeValidationError, match="exact strings"):
            NormalizedOutboxEnvelope(**values)
    assert liar.comparisons == 0


def test_unicode_key_collisions_and_confusable_secret_keys_fail_closed():
    collision = _envelope()
    collision["metadata"] = {"é": 1, "e\u0301": 2}
    with pytest.raises(OutboxCanonicalJSONError, match="duplicate object key"):
        normalize_outbox_envelope(collision)

    confusable = _envelope()
    confusable["metadata"] = {"sｅcret": "must-never-cross"}
    with pytest.raises(OutboxEnvelopeValidationError, match="prohibited"):
        normalize_outbox_envelope(confusable)

    with pytest.raises(OutboxCanonicalJSONError, match="UTF-8"):
        canonical_outbox_json({"\ud800": "invalid-key"})


@pytest.mark.parametrize(
    "nested",
    [
        {"raw_report": "full report text"},
        {"context": [{"evidence": "verbatim evidence"}]},
        {"config": {"api_token": "secret-value"}},
        {"private-key": "secret-value"},
        {"document_body": "large source body"},
        {"rawReport": "full report text"},
        {"apiToken": "secret-value"},
    ],
)
def test_raw_content_evidence_and_secret_fields_are_rejected_recursively(nested):
    candidate = _envelope()
    candidate["metadata"] = nested
    with pytest.raises(OutboxEnvelopeValidationError, match="prohibited"):
        normalize_outbox_envelope(candidate)


def test_canonical_outbox_json_enforces_48k_and_portable_numbers(monkeypatch):
    with pytest.raises(OutboxCanonicalJSONError, match=str(MAX_OUTBOX_CANONICAL_BYTES)):
        canonical_outbox_json({"padding": "x" * MAX_OUTBOX_CANONICAL_BYTES})

    for value, message in [
        (math.nan, "finite"),
        (math.inf, "finite"),
        (9_007_199_254_740_992, "53-bit"),
    ]:
        candidate = _envelope()
        candidate["metadata"] = {"confidence": value}
        with pytest.raises(OutboxCanonicalJSONError, match=message):
            normalize_outbox_envelope(candidate)

    with pytest.raises(OutboxCanonicalJSONError, match="aggregate items"):
        canonical_outbox_json({"items": [None] * MAX_OUTBOX_JSON_ITEMS})

    with pytest.raises(OutboxCanonicalJSONError, match="key exceeds"):
        canonical_outbox_json({"k" * (MAX_OUTBOX_CANONICAL_BYTES + 1): None})

    with pytest.raises(OutboxCanonicalJSONError, match="string exceeds"):
        canonical_outbox_json({"padding": "é" * MAX_OUTBOX_CANONICAL_BYTES})

    canonical_calls = 0

    def fail_if_canonicalized(value):
        nonlocal canonical_calls
        canonical_calls += 1
        raise AssertionError("aggregate amplification reached canonical_json")

    monkeypatch.setattr(outbox_engine, "canonical_json", fail_if_canonicalized)
    shared = "x" * MAX_OUTBOX_CANONICAL_BYTES
    with pytest.raises(OutboxCanonicalJSONError, match="aggregate UTF-8 budget"):
        canonical_outbox_json({"items": [shared] * 1_998})
    assert canonical_calls == 0


def test_domain_separated_keys_and_retry_delays_are_stable():
    normalized = normalize_outbox_envelope(_envelope())
    assert normalized.logical_key == "cb86503620b8aaa6734e2b44826f2cade2d16eaf2c0c13e327b0c936d1cddc72"  # gitleaks:allow
    assert delivery_cycle_idempotency_key(normalized.logical_key, delivery_cycle=1) == (
        "3097221c0f4002a9cf2c1f5d3b46126751dad07953e6746626a722c110b6ef95"
    )
    assert delivery_cycle_idempotency_key(normalized.logical_key, delivery_cycle=2) != (
        delivery_cycle_idempotency_key(normalized.logical_key, delivery_cycle=1)
    )

    policy = OutboxRetryPolicy(
        base_delay_seconds=10,
        max_delay_seconds=300,
        jitter_percent=20,
    )
    delays = [
        deterministic_delivery_retry_delay_seconds(
            attempt,
            logical_key=normalized.logical_key,
            policy=policy,
        )
        for attempt in range(1, 7)
    ]
    assert delays == [8, 16, 45, 80, 134, 288]
    assert all(1 <= delay <= 300 for delay in delays)
    assert delays == [
        deterministic_delivery_retry_delay_seconds(
            attempt,
            logical_key=normalized.logical_key,
            policy=policy.model_dump(),
        )
        for attempt in range(1, 7)
    ]


def test_key_retry_and_mutated_policy_inputs_fail_closed():
    logical_key = normalize_outbox_envelope(_envelope()).logical_key
    for invalid in ["not-a-hash", "A" * 64, "0" * 63]:
        with pytest.raises(OutboxKeyError, match="lowercase SHA-256"):
            delivery_cycle_idempotency_key(invalid, delivery_cycle=1)
    for cycle in [True, 0, MAX_DELIVERY_CYCLE + 1]:
        with pytest.raises(OutboxKeyError, match="delivery_cycle"):
            delivery_cycle_idempotency_key(logical_key, delivery_cycle=cycle)

    for attempt in [True, 0, 33]:
        with pytest.raises(OutboxContractError, match="attempt_number"):
            deterministic_delivery_retry_delay_seconds(
                attempt,
                logical_key=logical_key,
            )

    policy = OutboxRetryPolicy()
    policy.max_delay_seconds = 0
    with pytest.raises(OutboxContractError, match="max_delay_seconds"):
        deterministic_delivery_retry_delay_seconds(
            1,
            logical_key=logical_key,
            policy=policy,
        )

    class HostileStr(str):
        def encode(self, *args, **kwargs):
            raise AssertionError("hostile encode must never run")

        def strip(self, *args, **kwargs):
            raise AssertionError("hostile strip must never run")

    hostile_key = HostileStr(logical_key)
    with pytest.raises(OutboxKeyError, match="lowercase SHA-256"):
        delivery_cycle_idempotency_key(hostile_key, delivery_cycle=1)
    with pytest.raises(OutboxKeyError, match="lowercase SHA-256"):
        deterministic_delivery_retry_delay_seconds(1, logical_key=hostile_key)
    with pytest.raises(OutboxContractError, match="error code"):
        sanitize_outbox_error(
            "failure",
            code=HostileStr("outbox.error"),
            retryable=False,
        )


def test_error_sanitization_redacts_secrets_and_is_bounded_valid_utf8():
    error_text = (
        "publish failed "
        "postgresql://alice:hunter2@db.local/x "
        "Authorization: Bearer abc.def.ghi "
        "api_key='super-secret' password=also-secret "
        "-----BEGIN PRIVATE KEY----- key-material -----END PRIVATE KEY----- " + ("detail " * 100) + "\ud800spoofed"
    )
    sanitized = sanitize_outbox_error(
        error_text,
        code="outbox.publish_failed",
        retryable=True,
        error_class="RuntimeError",
    )

    assert sanitized.code == "outbox.publish_failed"
    assert sanitized.error_class == "RuntimeError"
    assert sanitized.retryable is True
    assert len(sanitized.summary) == 500
    assert sanitized.summary.endswith("...")
    for secret in ["hunter2", "abc.def.ghi", "super-secret", "also-secret", "key-material"]:
        assert secret not in sanitized.summary
    assert "postgresql://[REDACTED]@db.local/x" in sanitized.summary
    assert sanitized.summary.encode("utf-8").decode("utf-8") == sanitized.summary
    assert "\ud800" not in sanitized.summary


def test_error_sanitization_has_strict_metadata_and_safe_empty_fallback():
    sanitized = sanitize_outbox_error("\n\t", code="outbox.error", retryable=False)
    assert sanitized.error_class == "ExternalError"
    assert sanitized.summary == "Outbox delivery failed"

    spoofed = sanitize_outbox_error(
        "left\u202eright\u2066isolated",
        code="outbox.error",
        retryable=False,
    )
    assert spoofed.summary == "left right isolated"

    disguised_key = sanitize_outbox_error(
        "-----BE\u202eGIN PRIVATE KEY----- hidden-material -----END PRIVATE KEY-----",  # gitleaks:allow
        code="outbox.error",
        retryable=False,
    )
    assert disguised_key.summary == outbox_engine._CONTROL_REDACTED_ERROR_SUMMARY
    assert "hidden-material" not in disguised_key.summary

    displaced_end = sanitize_outbox_error(
        "-----BEGIN PRIVATE KEY----- private-material "  # gitleaks:allow
        + ("x" * (MAX_ERROR_WORKING_BYTES * 2))
        + " -----END PRIVATE KEY-----",
        code="outbox.error",
        retryable=False,
    )
    assert displaced_end.summary == "[REDACTED PRIVATE KEY]"
    assert "private-material" not in displaced_end.summary

    huge_provider_error = sanitize_outbox_error(
        "api_token=multi-megabyte-secret " + ("x" * 3_000_000),
        code="outbox.error",
        retryable=True,
    )
    assert "multi-megabyte-secret" not in huge_provider_error.summary
    assert len(huge_provider_error.summary) == 500
    assert huge_provider_error.summary.endswith("...")

    structured_secrets = sanitize_outbox_error(
        "AWS_SECRET_ACCESS_KEY=aws-secret "
        "redis://:redis-secret@cache.local/0 "
        "token=control-secret "
        '{"password":"json-secret"} nonsensitive=value',
        code="outbox.error",
        retryable=False,
    )
    for secret in ["aws-secret", "redis-secret", "control-secret", "json-secret"]:
        assert secret not in structured_secrets.summary
    assert "AWS_SECRET_ACCESS_KEY=[REDACTED]" in structured_secrets.summary
    assert "redis://[REDACTED]@cache.local/0" in structured_secrets.summary
    assert "token=[REDACTED]" in structured_secrets.summary
    assert '"password":"[REDACTED]"' in structured_secrets.summary
    assert "nonsensitive=value" in structured_secrets.summary

    with pytest.raises(OutboxContractError, match="error code"):
        sanitize_outbox_error("failed", code="Not Valid", retryable=False)
    with pytest.raises(OutboxContractError, match="retryable must be a boolean"):
        sanitize_outbox_error("failed", code="outbox.error", retryable=1)
    with pytest.raises(OutboxContractError, match="error_class"):
        sanitize_outbox_error(
            "failed",
            code="outbox.error",
            retryable=False,
            error_class="Invalid Error Class",
        )

    class StatefulError(RuntimeError):
        calls = 0

        def __str__(self):
            self.calls += 1
            return "stateful-secret"

    stateful = StatefulError()
    with pytest.raises(OutboxContractError, match="error_text must be an exact string"):
        sanitize_outbox_error(
            stateful,
            code="outbox.error",
            retryable=False,
        )
    assert stateful.calls == 0


@pytest.mark.parametrize(
    ("raw", "secret"),
    [
        ("to\x00ken=split-key-secret", "split-key-secret"),
        ("pass\nword='split-password-secret'", "split-password-secret"),
        (
            "AWS_SECRET_\tACCESS_KEY=split-aws-secret",
            "split-aws-secret",
        ),
        ("token='split-\nvalue-secret'", "split-value-secret"),
        (
            "redis://:split-\rurl-secret@cache.local/0",
            "split-url-secret",
        ),
        (
            "-----BE\x00GIN PRI\nVATE KEY----- split-pem-secret -----END PRIVATE K\tEY-----",
            "split-pem-secret",
        ),
        ("x\x00password=prefix-boundary-secret", "prefix-boundary-secret"),
        ("x\u200bpassword=format-boundary-secret", "format-boundary-secret"),
        ("message=oops\npassword=line-boundary-secret", "line-boundary-secret"),
        ("message=oops\nAWS_SECRET_ACCESS_KEY=aws-boundary-secret", "aws-boundary-secret"),
    ],
)
def test_error_contract_control_shadows_fail_closed_with_parity(raw, secret):
    outbox = sanitize_outbox_error(
        raw,
        code="outbox.error",
        retryable=False,
    )
    workflow = sanitize_workflow_error(
        raw,
        code="worker.error",
        retryable=False,
    )

    assert outbox.summary == outbox_engine._CONTROL_REDACTED_ERROR_SUMMARY
    assert workflow.summary == workflow_engine._CONTROL_REDACTED_ERROR_SUMMARY
    assert secret not in outbox.summary
    assert secret not in workflow.summary


def test_error_contract_control_shadows_preserve_boundaries_fixed_points_and_bounded_parity():
    raw_benign = "left\x00right\nnext\u2066field"
    assert sanitize_outbox_error(raw_benign, code="outbox.error", retryable=False).summary == "left right next field"
    assert sanitize_workflow_error(raw_benign, code="worker.error", retryable=False).summary == "left right next field"

    hostile = ("a\x00" * 3_000) + "message=oops\npassword=bounded-shadow-secret" + ("x" * 3_000_000)
    started = time.perf_counter()
    outbox = sanitize_outbox_error(
        hostile,
        code="outbox.error",
        retryable=False,
        error_class="ProviderError",
    )
    workflow = sanitize_workflow_error(
        hostile,
        code="worker.error",
        retryable=False,
        error_class="ProviderError",
    )
    assert time.perf_counter() - started < 0.5
    assert outbox.summary == outbox_engine._CONTROL_REDACTED_ERROR_SUMMARY
    assert workflow.summary == workflow_engine._CONTROL_REDACTED_ERROR_SUMMARY
    assert (
        sanitize_outbox_error(
            outbox.summary,
            code=outbox.code,
            retryable=outbox.retryable,
            error_class=outbox.error_class,
        )
        == outbox
    )
    assert (
        sanitize_workflow_error(
            workflow.summary,
            code=workflow.code,
            retryable=workflow.retryable,
            error_class=workflow.error_class,
        )
        == workflow
    )


def test_sanitized_error_authority_cannot_bypass_the_sanitizer():
    expected = sanitize_outbox_error(
        "Bounded safe failure",
        code="outbox.publish_failed",
        retryable=True,
        error_class="BrokerError",
    )
    assert (
        SanitizedOutboxError(
            code=expected.code,
            error_class=expected.error_class,
            summary=expected.summary,
            retryable=expected.retryable,
        )
        == expected
    )

    invalid_facts = (
        {"code": " outbox.publish_failed"},
        {"error_class": "Invalid Error"},
        {"summary": "api_token=unsanitized-secret"},
        {"summary": "line one\nline two"},
        {"retryable": 1},
    )
    baseline = {
        "code": expected.code,
        "error_class": expected.error_class,
        "summary": expected.summary,
        "retryable": expected.retryable,
    }
    for override in invalid_facts:
        with pytest.raises(OutboxContractError):
            SanitizedOutboxError(**(baseline | override))

    with pytest.raises(TypeError, match="sealed"):

        class ForgedSanitizedOutboxError(SanitizedOutboxError):
            def __post_init__(self) -> None:
                pass


def test_sanitizer_matchers_have_bounded_linear_matching():
    assert "{0,127}" in outbox_engine._ASSIGNMENT_RE.pattern
    assert "(?:[a-z0-9]+[-_])*" not in outbox_engine._ASSIGNMENT_RE.pattern
    assert "(?<![A-Za-z0-9_.-])" in outbox_engine._ASSIGNMENT_RE.pattern
    assert "{0,31}" in outbox_engine._URL_CREDENTIAL_RE.pattern
    assert "[a-z0-9+.-]*://" not in outbox_engine._URL_CREDENTIAL_RE.pattern

    durations = []
    sanitized = None
    for size in (2_048, 4_096, 8_192):
        adversarial = ("a-" * (size // 2)) + "nonsensitive=value"
        started = time.perf_counter()
        sanitized = sanitize_outbox_error(
            adversarial,
            code="outbox.error",
            retryable=False,
        )
        durations.append(time.perf_counter() - started)

    assert durations[-1] < 0.1
    assert durations[-1] <= durations[0] * 8 + 0.01
    assert sanitized is not None and sanitized.summary.endswith("...")


def test_pure_contract_source_has_no_operational_escape_hatches():
    source = inspect.getsource(outbox_engine)
    tree = ast.parse(source)
    forbidden_import_roots = {
        "aiohttp",
        "celery",
        "datetime",
        "httpx",
        "kombu",
        "os",
        "pathlib",
        "random",
        "requests",
        "socket",
        "sqlalchemy",
        "subprocess",
        "time",
    }
    imported_roots = set()
    forbidden_calls = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_roots.add(node.module.split(".", 1)[0])
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in {"eval", "exec", "open", "compile", "__import__"}:
                forbidden_calls.add(node.func.id)

    assert not (imported_roots & forbidden_import_roots)
    assert not forbidden_calls
