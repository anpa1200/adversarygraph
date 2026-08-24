import hashlib
import math
import time

import pytest
from pydantic import ValidationError

from app.services import workflow_engine
from app.services.workflow_engine import (
    MAX_CANONICAL_BYTES,
    MAX_ERROR_SUMMARY_CHARS,
    MAX_ERROR_WORKING_BYTES,
    MAX_IDEMPOTENCY_TOKEN_BYTES,
    CanonicalJSONError,
    IdempotencyTokenError,
    NormalizedStagePlan,
    RetryPolicy,
    SanitizedWorkflowError,
    StageDefinition,
    WorkflowContractError,
    WorkflowPlanValidationError,
    WorkflowStagePlan,
    canonical_json,
    checksum_json,
    deterministic_retry_backoff_seconds,
    hash_idempotency_token,
    normalize_stage_plan,
    sanitize_workflow_error,
)


def _stage(
    key: str,
    ordinal: int,
    *,
    depends_on: list[str] | None = None,
    **overrides,
):
    value = {
        "stage_key": key,
        "stage_type": f"{key}.worker",
        "stage_version": "1.0.0",
        "ordinal": ordinal,
        "depends_on": depends_on or [],
        "config": {"enabled": True},
    }
    value.update(overrides)
    return value


def test_canonical_json_normalizes_keys_unicode_and_negative_zero():
    first = {"z": -0.0, "e\u0301": {"b": 2, "a": 1}}
    second = {"é": {"a": 1, "b": 2}, "z": 0.0}

    assert canonical_json(first) == '{"z":0.0,"é":{"a":1,"b":2}}'
    assert canonical_json(first) == canonical_json(second)
    assert checksum_json(first) == checksum_json(second)
    assert checksum_json(first) == hashlib.sha256(canonical_json(first).encode("utf-8")).hexdigest()


def test_canonical_json_uses_actual_string_types_without_class_spoof_dispatch():
    class StringSubclass(str):
        pass

    class SpoofedString:
        @property
        def __class__(self):
            return str

    class RaisingClass:
        @property
        def __class__(self):
            raise RuntimeError("hostile class dispatch")

    class HostileMeta(type):
        def __getattribute__(cls, name):
            if name == "__name__":
                raise RuntimeError("hostile metaclass name dispatch")
            return super().__getattribute__(name)

    class HostileName(metaclass=HostileMeta):
        pass

    assert canonical_json({StringSubclass("e\u0301"): StringSubclass("value-e\u0301")}) == '{"é":"value-é"}'
    for hostile_value in (SpoofedString(), RaisingClass()):
        with pytest.raises(CanonicalJSONError, match="Unsupported JSON value type"):
            canonical_json({"value": hostile_value})
        with pytest.raises(CanonicalJSONError, match="keys must be strings"):
            canonical_json({hostile_value: "value"})
    with pytest.raises(CanonicalJSONError, match="Unsupported JSON value type: HostileName"):
        canonical_json({"value": HostileName()})
    with pytest.raises(CanonicalJSONError, match="keys must be strings"):
        canonical_json({HostileName(): "value"})


@pytest.mark.parametrize(
    "value, message",
    [
        ({"number": math.nan}, "finite"),
        ({"number": math.inf}, "finite"),
        ({"tuple": (1, 2)}, "tuple"),
        ({"integer": 9_007_199_254_740_992}, "53-bit"),
        ({1: "not a JSON key"}, "keys must be strings"),
        ({"é": 1, "e\u0301": 2}, "duplicate object key"),
    ],
)
def test_canonical_json_rejects_nonportable_values(value, message):
    with pytest.raises(CanonicalJSONError, match=message):
        canonical_json(value)


def test_canonical_json_enforces_depth_item_and_byte_bounds():
    nested: object = "leaf"
    for _ in range(22):
        nested = [nested]
    with pytest.raises(CanonicalJSONError, match="nesting"):
        canonical_json(nested)

    with pytest.raises(CanonicalJSONError, match="aggregate items"):
        canonical_json(list(range(2_001)))

    # Several individually valid strings can still exceed the aggregate cap.
    chunk = "x" * (MAX_CANONICAL_BYTES // 2)
    with pytest.raises(CanonicalJSONError, match="exceeds"):
        canonical_json([chunk, chunk, chunk])


def test_plan_normalization_is_order_independent_and_content_addressed():
    unordered = [
        _stage("publish", 3, depends_on=["collect", "review"]),
        _stage("collect", 1, config={"z": 1, "a": 2}),
        _stage("review", 2, depends_on=["collect"]),
    ]
    reordered = [
        _stage("review", 2, depends_on=["collect"]),
        _stage("publish", 3, depends_on=["review", "collect"]),
        _stage("collect", 1, config={"a": 2, "z": 1}),
    ]

    first = normalize_stage_plan(unordered)
    second = normalize_stage_plan(reordered)

    assert [stage.stage_key for stage in first.stages] == [
        "collect",
        "review",
        "publish",
    ]
    assert first.stages[-1].depends_on == ["collect", "review"]
    assert first.canonical == second.canonical
    assert first.checksum == second.checksum
    assert len(first.checksum) == 64
    assert [item["stage_key"] for item in first.as_payload()] == [
        "collect",
        "review",
        "publish",
    ]


def test_plan_normalization_revalidates_mutated_model_instances():
    stage = StageDefinition.model_validate(_stage("collect", 1))
    stage.depends_on.append("missing")
    with pytest.raises(WorkflowPlanValidationError, match="unknown stage"):
        normalize_stage_plan([stage])

    model = WorkflowStagePlan.model_validate({"stages": [_stage("collect", 1), _stage("review", 2)]})
    model.stages[1].ordinal = 1
    with pytest.raises(WorkflowPlanValidationError, match="ordinals must be unique"):
        normalize_stage_plan(model)

    retry_stage = StageDefinition.model_validate(_stage("collect", 1))
    retry_stage.retry_policy.max_delay_seconds = 0
    with pytest.raises(WorkflowPlanValidationError, match="max_delay_seconds"):
        normalize_stage_plan([retry_stage])


def test_normalized_plan_never_exposes_mutable_checksum_authority():
    normalized = normalize_stage_plan([_stage("collect", 1)])
    detached = normalized.plan
    detached.stages[0].config["enabled"] = False
    detached.stages.append(StageDefinition.model_validate(_stage("injected", 2)))

    assert normalized.as_payload()[0]["config"] == {"enabled": True}
    assert len(normalized.plan.stages) == 1
    assert normalized.checksum == hashlib.sha256(normalized.canonical.encode("utf-8")).hexdigest()


def test_normalized_plan_constructor_rejects_mismatch_and_noncanonical_order():
    normalized = normalize_stage_plan([_stage("collect", 1), _stage("review", 2)])
    with pytest.raises(WorkflowPlanValidationError, match="checksum"):
        NormalizedStagePlan(canonical=normalized.canonical, checksum="0" * 64)

    reversed_canonical = canonical_json(list(reversed(normalized.as_payload())))
    reversed_checksum = hashlib.sha256(reversed_canonical.encode("utf-8")).hexdigest()
    with pytest.raises(WorkflowPlanValidationError, match="canonical dependency order"):
        NormalizedStagePlan(
            canonical=reversed_canonical,
            checksum=reversed_checksum,
        )


@pytest.mark.parametrize(
    "stages, message",
    [
        ([_stage("one", 1), _stage("one", 2)], "stage_key values must be unique"),
        ([_stage("one", 1), _stage("two", 1)], "ordinals must be unique"),
        ([_stage("one", 1), _stage("two", 3)], "contiguous"),
        ([_stage("one", 1, depends_on=["missing"])], "unknown stage"),
        ([_stage("one", 1, depends_on=["one"])], "depend on itself"),
        (
            [_stage("one", 1), _stage("two", 2, depends_on=["one", "one"])],
            "duplicate stage keys",
        ),
        (
            [_stage("one", 1, depends_on=["two"]), _stage("two", 2)],
            "earlier ordinal",
        ),
        (
            [
                _stage("one", 1, depends_on=["two"]),
                _stage("two", 2, depends_on=["one"]),
            ],
            "earlier ordinal",
        ),
    ],
)
def test_plan_rejects_ambiguous_or_cyclic_dependency_graphs(stages, message):
    with pytest.raises(WorkflowPlanValidationError, match=message):
        normalize_stage_plan(stages)


def test_stage_definition_is_strict_bounded_and_forbids_extra_fields():
    with pytest.raises(ValidationError, match="required must be a boolean"):
        StageDefinition.model_validate(_stage("collect", 1, required=1))
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        StageDefinition.model_validate(_stage("collect", 1, surprise=True))
    with pytest.raises(ValidationError, match="depends_on must be a JSON array"):
        StageDefinition.model_validate(_stage("collect", 1, depends_on=("prior",)))
    with pytest.raises(ValidationError, match="finite"):
        StageDefinition.model_validate(_stage("collect", 1, config={"confidence": math.nan}))
    with pytest.raises(ValidationError, match="max_delay_seconds"):
        StageDefinition.model_validate(
            _stage(
                "collect",
                1,
                retry_policy={
                    "base_delay_seconds": 100,
                    "max_delay_seconds": 10,
                    "jitter_percent": 10,
                },
            )
        )


def test_plan_rejects_more_than_the_bounded_number_of_stages():
    stages = [_stage(f"s{index}", index) for index in range(1, 66)]
    with pytest.raises(WorkflowPlanValidationError, match="at most 64"):
        normalize_stage_plan(stages)


def test_idempotency_hash_is_stable_domain_separated_and_never_raw():
    token = "customer-request-2026-08-23"
    first = hash_idempotency_token(token, namespace="report-analysis")

    assert first == hash_idempotency_token(token, namespace="report-analysis")
    assert first != hash_idempotency_token(token, namespace="report-replay")
    assert first != hash_idempotency_token(f"{token}-2", namespace="report-analysis")
    assert token not in first
    assert len(first) == 64
    assert first == first.lower()


@pytest.mark.parametrize(
    "token, namespace, message",
    [
        ("", "report-analysis", "1-1024"),
        ("x\nsecret", "report-analysis", "control"),
        ("x" * (MAX_IDEMPOTENCY_TOKEN_BYTES + 1), "report-analysis", "1-1024"),
        ("valid", "Report Analysis", "lowercase workflow identity"),
    ],
)
def test_idempotency_hash_rejects_unsafe_inputs(token, namespace, message):
    with pytest.raises(IdempotencyTokenError, match=message):
        hash_idempotency_token(token, namespace=namespace)


def test_retry_backoff_is_deterministic_bounded_and_exponential():
    policy = RetryPolicy(
        base_delay_seconds=10,
        max_delay_seconds=100,
        jitter_percent=20,
    )
    values = [
        deterministic_retry_backoff_seconds(
            attempt,
            seed="stable-stage-id",
            policy=policy,
        )
        for attempt in range(1, 7)
    ]

    assert values == [
        deterministic_retry_backoff_seconds(
            attempt,
            seed="stable-stage-id",
            policy=policy,
        )
        for attempt in range(1, 7)
    ]
    for attempt, value in enumerate(values, start=1):
        target = min(100, 10 * (2 ** (attempt - 1)))
        assert max(1, target - target // 5) <= value <= min(100, target + target // 5)

    assert [
        deterministic_retry_backoff_seconds(
            attempt,
            seed="no-jitter",
            policy={
                "base_delay_seconds": 10,
                "max_delay_seconds": 100,
                "jitter_percent": 0,
            },
        )
        for attempt in range(1, 7)
    ] == [10, 20, 40, 80, 100, 100]


def test_retry_backoff_revalidates_mutated_policy_instances():
    policy = RetryPolicy()
    policy.max_delay_seconds = 0

    with pytest.raises(WorkflowContractError, match="max_delay_seconds"):
        deterministic_retry_backoff_seconds(1, seed="stage", policy=policy)


def test_retry_backoff_rejects_non_utf8_seed():
    with pytest.raises(WorkflowContractError, match="valid UTF-8"):
        deterministic_retry_backoff_seconds(1, seed="bad-\ud800-seed")


@pytest.mark.parametrize("attempt", [0, 21, True, 1.0])
def test_retry_backoff_rejects_invalid_attempt_number(attempt):
    with pytest.raises(WorkflowContractError, match="attempt_number"):
        deterministic_retry_backoff_seconds(attempt, seed="stage")


def test_error_sanitization_redacts_secrets_and_is_database_bounded():
    error_text = (
        "request failed "
        "postgresql://alice:hunter2@db.local/x "
        "Authorization: Bearer abc.def.ghi "
        "api_key='super-secret' password=also-secret "
        "-----BEGIN PRIVATE KEY----- key-material -----END PRIVATE KEY----- " + ("detail " * 100) + "\ud800spoofed"
    )

    sanitized = sanitize_workflow_error(
        error_text,
        code="source.fetch_failed",
        retryable=True,
        error_class="RuntimeError",
    )

    assert sanitized.code == "source.fetch_failed"
    assert sanitized.error_class == "RuntimeError"
    assert sanitized.retryable is True
    assert len(sanitized.summary) == MAX_ERROR_SUMMARY_CHARS
    assert sanitized.summary.endswith("...")
    for secret in ["hunter2", "abc.def.ghi", "super-secret", "also-secret", "key-material"]:
        assert secret not in sanitized.summary
    assert "postgresql://[REDACTED]@db.local/x" in sanitized.summary
    assert sanitized.summary.encode("utf-8").decode("utf-8") == sanitized.summary
    assert "\ud800" not in sanitized.summary


def test_error_sanitization_handles_external_empty_errors_and_strict_metadata():
    sanitized = sanitize_workflow_error(
        "\n\t",
        code="worker.error",
        retryable=False,
    )
    assert sanitized.error_class == "ExternalError"
    assert sanitized.summary == "Stage execution failed"

    spoofed = sanitize_workflow_error(
        "left\u202eright\u2066isolated",
        code="worker.error",
        retryable=False,
    )
    assert spoofed.summary == "left right isolated"

    disguised_key = sanitize_workflow_error(
        "-----BE\u202eGIN PRIVATE KEY----- hidden-material -----END PRIVATE KEY-----",  # gitleaks:allow
        code="worker.error",
        retryable=False,
    )
    assert disguised_key.summary == workflow_engine._CONTROL_REDACTED_ERROR_SUMMARY

    displaced_end = sanitize_workflow_error(
        "-----BEGIN PRIVATE KEY----- private-material "  # gitleaks:allow
        + ("x" * (MAX_ERROR_WORKING_BYTES * 2))
        + " -----END PRIVATE KEY-----",
        code="worker.error",
        retryable=False,
    )
    assert displaced_end.summary == "[REDACTED PRIVATE KEY]"

    structured_secrets = sanitize_workflow_error(
        "AWS_SECRET_ACCESS_KEY=aws-secret "
        "redis://:redis-secret@cache.local/0 "
        "CLOUDFLARE_API_TOKEN=cloudflare-secret "
        "token=control-secret "
        '{"password":"json-secret"} nonsensitive=value',
        code="worker.error",
        retryable=False,
    )
    for secret in ["aws-secret", "redis-secret", "cloudflare-secret", "control-secret", "json-secret"]:
        assert secret not in structured_secrets.summary
    assert "AWS_SECRET_ACCESS_KEY=[REDACTED]" in structured_secrets.summary
    assert "redis://[REDACTED]@cache.local/0" in structured_secrets.summary
    assert "CLOUDFLARE_API_TOKEN=[REDACTED]" in structured_secrets.summary
    assert "token=[REDACTED]" in structured_secrets.summary
    assert '"password":"[REDACTED]"' in structured_secrets.summary
    assert "nonsensitive=value" in structured_secrets.summary

    with pytest.raises(WorkflowContractError, match="error code"):
        sanitize_workflow_error("failure", code="Not Valid", retryable=False)
    with pytest.raises(WorkflowContractError, match="retryable must be a boolean"):
        sanitize_workflow_error("failure", code="worker.error", retryable=1)
    with pytest.raises(WorkflowContractError, match="error_class"):
        sanitize_workflow_error(
            "failure",
            code="worker.error",
            retryable=False,
            error_class="Invalid Error Class",
        )


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
def test_workflow_error_control_shadows_fail_closed_on_sensitive_material(raw, secret):
    sanitized = sanitize_workflow_error(
        raw,
        code="worker.error",
        retryable=False,
    )

    assert sanitized.summary == workflow_engine._CONTROL_REDACTED_ERROR_SUMMARY
    assert secret not in sanitized.summary


def test_workflow_error_control_shadows_preserve_benign_boundaries_and_fixed_point():
    benign = sanitize_workflow_error(
        "left\x00right\nnext\u2066field",
        code="worker.error",
        retryable=False,
    )
    assert benign.summary == "left right next field"

    hostile = sanitize_workflow_error(
        "x\x00password=fixed-point-secret",
        code="worker.error",
        retryable=False,
        error_class="ProviderError",
    )
    assert hostile.summary == workflow_engine._CONTROL_REDACTED_ERROR_SUMMARY
    assert (
        sanitize_workflow_error(
            hostile.summary,
            code=hostile.code,
            retryable=hostile.retryable,
            error_class=hostile.error_class,
        )
        == hostile
    )
    assert (
        SanitizedWorkflowError(
            code=hostile.code,
            error_class=hostile.error_class,
            summary=hostile.summary,
            retryable=hostile.retryable,
        )
        == hostile
    )


def test_error_sanitization_repairs_surrogates_to_valid_utf8():
    sanitized = sanitize_workflow_error(
        "upstream returned \ud800 in an error",
        code="worker.error",
        retryable=False,
    )

    assert "upstream returned" in sanitized.summary
    assert sanitized.summary.encode("utf-8").decode("utf-8") == sanitized.summary
    assert "\ud800" not in sanitized.summary


def test_error_sanitization_rejects_hostile_values_without_dispatching_magic():
    class HostileStr(str):
        calls = 0

        def strip(self, *_args, **_kwargs):
            type(self).calls += 1
            raise AssertionError("hostile strip must not run")

        def encode(self, *_args, **_kwargs):
            type(self).calls += 1
            raise AssertionError("hostile encode must not run")

        def __getitem__(self, _key):
            type(self).calls += 1
            raise AssertionError("hostile slicing must not run")

    class ClassSpoof:
        calls = 0

        @property
        def __class__(self):
            type(self).calls += 1
            return str

        def __str__(self):
            type(self).calls += 1
            return "hidden-secret"

    class StatefulError(RuntimeError):
        calls = 0

        def __str__(self):
            type(self).calls += 1
            return "stateful-secret"

    hostile = HostileStr("failure")
    for kwargs in (
        {"error_text": hostile, "code": "worker.error", "retryable": False},
        {"error_text": "failure", "code": hostile, "retryable": False},
        {
            "error_text": "failure",
            "code": "worker.error",
            "retryable": False,
            "error_class": hostile,
        },
    ):
        with pytest.raises(WorkflowContractError):
            sanitize_workflow_error(**kwargs)
    assert HostileStr.calls == 0

    spoof = ClassSpoof()
    stateful = StatefulError()
    for value in (spoof, stateful):
        with pytest.raises(WorkflowContractError, match="error_text must be an exact string"):
            sanitize_workflow_error(
                value,
                code="worker.error",
                retryable=False,
            )
    assert ClassSpoof.calls == 0
    assert StatefulError.calls == 0


def test_sanitized_workflow_error_cannot_bypass_the_sanitizer():
    expected = sanitize_workflow_error(
        "Bounded safe failure",
        code="source.fetch_failed",
        retryable=True,
        error_class="ProviderError",
    )
    assert (
        SanitizedWorkflowError(
            code=expected.code,
            error_class=expected.error_class,
            summary=expected.summary,
            retryable=expected.retryable,
        )
        == expected
    )

    baseline = {
        "code": expected.code,
        "error_class": expected.error_class,
        "summary": expected.summary,
        "retryable": expected.retryable,
    }
    for override in (
        {"code": " source.fetch_failed"},
        {"error_class": "Invalid Error"},
        {"summary": "api_token=unsanitized-secret"},
        {"summary": "line one\nline two"},
        {"retryable": 1},
    ):
        with pytest.raises(WorkflowContractError):
            SanitizedWorkflowError(**(baseline | override))

    with pytest.raises(TypeError, match="sealed"):

        class ForgedSanitizedWorkflowError(SanitizedWorkflowError):
            def __post_init__(self) -> None:
                pass


def test_workflow_error_sanitizer_is_bounded_and_linear():
    huge = "api_token=multi-megabyte-secret " + ("x" * 3_000_000)
    started = time.perf_counter()
    sanitized = sanitize_workflow_error(
        huge,
        code="worker.error",
        retryable=True,
    )
    elapsed = time.perf_counter() - started
    assert elapsed < 0.25
    assert "multi-megabyte-secret" not in sanitized.summary
    assert len(sanitized.summary) == MAX_ERROR_SUMMARY_CHARS
    assert sanitized.summary.endswith("...")

    multibyte = sanitize_workflow_error(
        "password=secret " + ("😀" * MAX_ERROR_WORKING_BYTES),
        code="worker.error",
        retryable=False,
    )
    assert "secret" not in multibyte.summary
    assert len(multibyte.summary) <= MAX_ERROR_SUMMARY_CHARS
    assert len(multibyte.summary.encode("utf-8")) <= MAX_ERROR_SUMMARY_CHARS * 4

    controlled = ("a\x00" * 3_000) + "message=oops\npassword=bounded-shadow-secret" + ("x" * 3_000_000)
    started = time.perf_counter()
    controlled_result = sanitize_workflow_error(
        controlled,
        code="worker.error",
        retryable=False,
    )
    assert time.perf_counter() - started < 0.25
    assert controlled_result.summary == workflow_engine._CONTROL_REDACTED_ERROR_SUMMARY

    assert "{0,127}" in workflow_engine._ASSIGNMENT_RE.pattern
    assert "(?:[a-z0-9]+[-_])*" not in workflow_engine._ASSIGNMENT_RE.pattern
    assert "(?<![A-Za-z0-9_.-])" in workflow_engine._ASSIGNMENT_RE.pattern
    assert "{0,31}" in workflow_engine._URL_CREDENTIAL_RE.pattern
    assert "[a-z0-9+.-]*://" not in workflow_engine._URL_CREDENTIAL_RE.pattern
