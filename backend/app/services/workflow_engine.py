"""Pure deterministic contracts for durable research workflows.

This module intentionally contains no database or queue operations.  It is the
single authority for validating a stage DAG and deriving content addresses,
idempotency keys, retry delays, and safe persisted error facts.  Transition
code can therefore consume these values without asking a model, a clock, or a
random-number generator to make a state-machine decision.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from dataclasses import dataclass
from typing import Annotated, Any

from pydantic import Field, StringConstraints, ValidationError, field_validator, model_validator

from app.core.payload_limits import BoundedPayloadModel


MAX_PLAN_STAGES = 64
MAX_DEPENDENCIES_PER_STAGE = 32
MAX_CANONICAL_BYTES = 1024 * 1024
MAX_JSON_STRING_BYTES = 256 * 1024
MAX_JSON_ITEMS = 2_000
MAX_JSON_DEPTH = 20
MAX_IDEMPOTENCY_TOKEN_BYTES = 1_024
MAX_ERROR_SUMMARY_CHARS = 500
MAX_ERROR_WORKING_BYTES = 8 * 1024
MAX_SAFE_JSON_INTEGER = 9_007_199_254_740_991
STAGE_CONFIG_SCHEMA_VERSION = "research-stage-config-v1"
STAGE_CHECKPOINT_SCHEMA_VERSION = "research-stage-checkpoint-v1"

_IDENTITY_PATTERN = r"^[a-z][a-z0-9_.-]{0,79}$"
_VERSION_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,79}$"
_IDENTITY_RE = re.compile(_IDENTITY_PATTERN)
_ERROR_CLASS_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,119}$")
_AUTH_SCHEME_RE = re.compile(r"(?i)\b(Bearer|Basic|Digest|Token)\s+[A-Za-z0-9._~+/=-]+")
_ASSIGNMENT_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])(?P<leading>[-_.]{0,4})(?P<quote>[\"']?)"
    r"(?P<key>[A-Za-z0-9][A-Za-z0-9_.-]{0,127})(?P=quote)"
    r"[ \t]{0,32}(?P<separator>[:=])[ \t]{0,32}"
    r"(?P<value>\"[^\"\r\n]{0,8192}\"|'[^'\r\n]{0,8192}'|[^\s,;]{0,8192})"
)
_URL_CREDENTIAL_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9+.-])"
    r"([a-z][a-z0-9+.-]{0,31}://)"
    r"([^\s/@:]{0,256}):([^\s/@]{1,2048})@"
)
_PRIVATE_KEY_BEGIN_PATTERN = (
    r"(?:-\s*){5}B\s*E\s*G\s*I\s*N\s+"
    r"(?:[A-Z0-9]+\s+){0,8}P\s*R\s*I\s*V\s*A\s*T\s*E\s+K\s*E\s*Y\s*(?:-\s*){5}"
)
_PRIVATE_KEY_END_PATTERN = (
    r"(?:-\s*){5}E\s*N\s*D\s+"
    r"(?:[A-Z0-9]+\s+){0,8}P\s*R\s*I\s*V\s*A\s*T\s*E\s+K\s*E\s*Y\s*(?:-\s*){5}"
)
_PRIVATE_KEY_BLOCK_RE = re.compile(
    _PRIVATE_KEY_BEGIN_PATTERN + r".*?" + _PRIVATE_KEY_END_PATTERN,
    re.DOTALL | re.IGNORECASE,
)
_PRIVATE_KEY_UNTERMINATED_RE = re.compile(
    _PRIVATE_KEY_BEGIN_PATTERN + r".*\Z",
    re.DOTALL | re.IGNORECASE,
)
_PROHIBITED_KEY_TOKENS = frozenset(
    {
        "apikey",
        "artifact",
        "authorization",
        "binary",
        "blob",
        "body",
        "content",
        "cookie",
        "credential",
        "document",
        "evidence",
        "excerpt",
        "password",
        "passwd",
        "privatekey",
        "prompt",
        "pwd",
        "raw",
        "report",
        "response",
        "secret",
        "setcookie",
        "token",
    }
)
_PROHIBITED_COMPACT_SUFFIXES = frozenset(
    {
        "apikey",
        "authtoken",
        "clientsecret",
        "privatekey",
        "refreshtoken",
        "sessiontoken",
        "setcookie",
    }
)
_STRIPPED_ERROR_CATEGORIES = frozenset({"Cc", "Cf"})
_CONTROL_REDACTED_ERROR_SUMMARY = "Stage execution failed: [REDACTED]"
_KEY_SEPARATOR_RE = re.compile(r"[^a-z0-9]+")
_CAMEL_CASE_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")

StageIdentity = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=80,
        pattern=_IDENTITY_PATTERN,
    ),
]
VersionIdentity = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=80,
        pattern=_VERSION_PATTERN,
    ),
]


class WorkflowContractError(ValueError):
    """Base class for deterministic workflow contract failures."""


class WorkflowPlanValidationError(WorkflowContractError):
    """A stage definition or dependency graph is invalid."""


class CanonicalJSONError(WorkflowContractError):
    """A value cannot be represented by the canonical JSON contract."""


class IdempotencyTokenError(WorkflowContractError):
    """An idempotency token or namespace is outside the accepted contract."""


class RetryPolicy(BoundedPayloadModel):
    """Bounded retry policy embedded in the immutable workflow plan."""

    base_delay_seconds: int = Field(default=30, ge=1, le=3_600, strict=True)
    max_delay_seconds: int = Field(default=3_600, ge=1, le=86_400, strict=True)
    jitter_percent: int = Field(default=20, ge=0, le=50, strict=True)

    @model_validator(mode="after")
    def _validate_delay_bounds(self):
        if self.max_delay_seconds < self.base_delay_seconds:
            raise ValueError("max_delay_seconds must be at least base_delay_seconds")
        return self


class StageDefinition(BoundedPayloadModel):
    """Strict, versioned definition for one deterministic workflow stage."""

    stage_key: StageIdentity
    stage_type: StageIdentity
    stage_version: VersionIdentity
    ordinal: int = Field(ge=1, le=MAX_PLAN_STAGES, strict=True)
    depends_on: list[StageIdentity] = Field(
        default_factory=list,
        max_length=MAX_DEPENDENCIES_PER_STAGE,
    )
    required: bool = True
    priority: int = Field(default=5, ge=0, le=9, strict=True)
    max_attempts: int = Field(default=3, ge=1, le=20, strict=True)
    config_schema_version: VersionIdentity = STAGE_CONFIG_SCHEMA_VERSION
    checkpoint_schema_version: VersionIdentity = STAGE_CHECKPOINT_SCHEMA_VERSION
    config: dict[str, Any] = Field(default_factory=dict)
    input_manifest: dict[str, Any] | None = None
    retry_policy: RetryPolicy = Field(default_factory=RetryPolicy)

    @field_validator("required", mode="before")
    @classmethod
    def _require_real_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("required must be a boolean")
        return value

    @field_validator("depends_on", mode="before")
    @classmethod
    def _require_dependency_array(cls, value: object) -> object:
        if type(value) is not list:
            raise ValueError("depends_on must be a JSON array")
        return value

    @field_validator("config", mode="before")
    @classmethod
    def _validate_config(cls, value: object) -> dict[str, Any]:
        return _validate_json_object(value, field_name="config")

    @field_validator("input_manifest", mode="before")
    @classmethod
    def _validate_input_manifest(cls, value: object) -> dict[str, Any] | None:
        if value is None:
            return None
        return _validate_json_object(value, field_name="input_manifest")

    @field_validator("retry_policy", mode="before")
    @classmethod
    def _revalidate_retry_policy(cls, value: object) -> object:
        if isinstance(value, RetryPolicy):
            return value.model_dump(mode="python")
        return value

    @model_validator(mode="after")
    def _validate_local_dependencies(self):
        if len(self.depends_on) != len(set(self.depends_on)):
            raise ValueError("depends_on must not contain duplicate stage keys")
        if self.stage_key in self.depends_on:
            raise ValueError("a stage cannot depend on itself")
        return self


class WorkflowStagePlan(BoundedPayloadModel):
    """A bounded acyclic plan whose ordinals define canonical execution order."""

    stages: list[StageDefinition] = Field(
        min_length=1,
        max_length=MAX_PLAN_STAGES,
    )

    @field_validator("stages", mode="before")
    @classmethod
    def _require_stage_array_and_revalidate_instances(cls, value: object) -> object:
        if type(value) is not list:
            raise ValueError("stages must be a JSON array")
        return [item.model_dump(mode="python") if isinstance(item, StageDefinition) else item for item in value]

    @model_validator(mode="after")
    def _validate_graph(self):
        keys = [stage.stage_key for stage in self.stages]
        ordinals = [stage.ordinal for stage in self.stages]
        if len(keys) != len(set(keys)):
            raise ValueError("stage_key values must be unique")
        if len(ordinals) != len(set(ordinals)):
            raise ValueError("stage ordinals must be unique")

        expected_ordinals = list(range(1, len(self.stages) + 1))
        if sorted(ordinals) != expected_ordinals:
            raise ValueError("stage ordinals must be contiguous and start at 1")

        ordinal_by_key = {stage.stage_key: stage.ordinal for stage in self.stages}
        for stage in self.stages:
            for dependency in stage.depends_on:
                dependency_ordinal = ordinal_by_key.get(dependency)
                if dependency_ordinal is None:
                    raise ValueError(f"stage {stage.stage_key!r} depends on unknown stage {dependency!r}")
                if dependency_ordinal >= stage.ordinal:
                    raise ValueError(f"stage {stage.stage_key!r} dependency {dependency!r} must have an earlier ordinal")
        return self


@dataclass(frozen=True)
class NormalizedStagePlan:
    """Validated plan plus the exact bytes and checksum persisted as authority."""

    canonical: str
    checksum: str

    def __post_init__(self) -> None:
        try:
            payload = json.loads(self.canonical)
            rebuilt_canonical = canonical_json(payload)
            rebuilt_plan = WorkflowStagePlan.model_validate({"stages": payload})
        except (json.JSONDecodeError, ValidationError, WorkflowContractError) as exc:
            raise WorkflowPlanValidationError("Normalized stage plan contains invalid canonical authority") from exc
        expected_checksum = hashlib.sha256(rebuilt_canonical.encode("utf-8")).hexdigest()
        if rebuilt_canonical != self.canonical or expected_checksum != self.checksum:
            raise WorkflowPlanValidationError("Normalized stage plan checksum does not match its canonical authority")
        ordered = sorted(rebuilt_plan.stages, key=lambda stage: stage.ordinal)
        ordinal_by_key = {stage.stage_key: stage.ordinal for stage in ordered}
        if rebuilt_plan.stages != ordered or any(
            stage.depends_on
            != sorted(
                stage.depends_on,
                key=lambda key: (ordinal_by_key[key], key),
            )
            for stage in ordered
        ):
            raise WorkflowPlanValidationError("Normalized stage plan is not in canonical dependency order")

    @property
    def plan(self) -> WorkflowStagePlan:
        """Reconstruct a detached validated model from immutable authority."""

        return WorkflowStagePlan.model_validate({"stages": self.as_payload()})

    @property
    def stages(self) -> tuple[StageDefinition, ...]:
        return tuple(self.plan.stages)

    def as_payload(self) -> list[dict[str, Any]]:
        """Return a detached JSON-compatible plan for a JSONB column."""

        payload = json.loads(self.canonical)
        if not isinstance(payload, list):  # defensive; constructor is internal
            raise CanonicalJSONError("Normalized stage plan is not an array")
        return payload


@dataclass(frozen=True, slots=True)
class SanitizedWorkflowError:
    """Bounded error facts safe to persist and expose to an analyst."""

    code: str
    error_class: str
    summary: str
    retryable: bool

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("SanitizedWorkflowError is sealed and cannot be subclassed")

    def __post_init__(self) -> None:
        if type(self) is not SanitizedWorkflowError:
            raise WorkflowContractError("Sanitized workflow error must use its exact authority type")
        normalized = _sanitize_workflow_error_fields(
            self.summary,
            code=self.code,
            retryable=self.retryable,
            error_class=self.error_class,
        )
        if normalized != (
            self.code,
            self.error_class,
            self.summary,
            self.retryable,
        ):
            raise WorkflowContractError("Sanitized workflow error facts must be exact fixed-point output from sanitize_workflow_error")


def canonical_json(value: object) -> str:
    """Return deterministic UTF-8 JSON or fail closed.

    The accepted subset is deliberately portable: object keys are strings,
    strings are NFC-normalized, integers fit the interoperable 53-bit range,
    floats are finite, and custom Python objects/tuples/bytes are rejected.
    """

    normalized = _normalize_json_value(value, depth=0, item_count=[0])
    try:
        encoded = json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise CanonicalJSONError("Value is not canonical JSON") from exc
    if len(encoded) > MAX_CANONICAL_BYTES:
        raise CanonicalJSONError(f"Canonical JSON exceeds {MAX_CANONICAL_BYTES} bytes")
    return encoded.decode("utf-8")


def checksum_json(value: object) -> str:
    """Return a lowercase SHA-256 content address for canonical JSON."""

    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def normalize_stage_plan(
    value: WorkflowStagePlan | list[StageDefinition | dict[str, Any]] | dict[str, Any],
) -> NormalizedStagePlan:
    """Validate, canonically order, and content-address a workflow plan."""

    if isinstance(value, WorkflowStagePlan):
        candidate: object = value.model_dump(mode="python")
    elif isinstance(value, dict):
        candidate = dict(value)
        raw_stages = candidate.get("stages")
        if isinstance(raw_stages, list):
            candidate["stages"] = [item.model_dump(mode="python") if isinstance(item, StageDefinition) else item for item in raw_stages]
    elif isinstance(value, list):
        candidate = {"stages": [item.model_dump(mode="python") if isinstance(item, StageDefinition) else item for item in value]}
    else:
        raise WorkflowPlanValidationError("stage plan must be a list or an object containing stages")

    try:
        validated = WorkflowStagePlan.model_validate(candidate)
    except (ValidationError, ValueError) as exc:
        raise WorkflowPlanValidationError(_validation_summary(exc)) from exc

    ordinal_by_key = {stage.stage_key: stage.ordinal for stage in validated.stages}
    ordered_stages = []
    for stage in sorted(validated.stages, key=lambda item: item.ordinal):
        dependencies = sorted(
            stage.depends_on,
            key=lambda key: (ordinal_by_key[key], key),
        )
        ordered_stages.append(stage.model_copy(update={"depends_on": dependencies}, deep=True))
    normalized_plan = WorkflowStagePlan(stages=ordered_stages)
    payload = [stage.model_dump(mode="json") for stage in normalized_plan.stages]
    canonical = canonical_json(payload)
    checksum = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return NormalizedStagePlan(
        canonical=canonical,
        checksum=checksum,
    )


def hash_idempotency_token(token: str, *, namespace: str) -> str:
    """Hash a caller token with explicit domain separation.

    The raw token is never returned and should never be persisted.  Database
    uniqueness must still scope the resulting hash to its owning authority
    (for example, project revision plus workflow type).
    """

    if not isinstance(namespace, str) or not _IDENTITY_RE.fullmatch(namespace):
        raise IdempotencyTokenError("idempotency namespace must be a lowercase workflow identity")
    if not isinstance(token, str):
        raise IdempotencyTokenError("idempotency token must be a string")
    try:
        token_bytes = token.encode("utf-8")
    except UnicodeError as exc:
        raise IdempotencyTokenError("idempotency token is not valid UTF-8") from exc
    if not token_bytes or len(token_bytes) > MAX_IDEMPOTENCY_TOKEN_BYTES:
        raise IdempotencyTokenError(f"idempotency token must be 1-{MAX_IDEMPOTENCY_TOKEN_BYTES} UTF-8 bytes")
    if any(unicodedata.category(char) == "Cc" for char in token):
        raise IdempotencyTokenError("idempotency token must not contain control characters")

    material = b"AdversaryGraph/idempotency/v1\x00" + namespace.encode("ascii") + b"\x00" + token_bytes
    return hashlib.sha256(material).hexdigest()


def deterministic_retry_backoff_seconds(
    attempt_number: int,
    *,
    seed: str,
    policy: RetryPolicy | dict[str, Any] | None = None,
) -> int:
    """Return bounded exponential backoff with deterministic symmetric jitter."""

    if type(attempt_number) is not int or not 1 <= attempt_number <= 20:
        raise WorkflowContractError("attempt_number must be an integer from 1 to 20")
    if not isinstance(seed, str):
        raise WorkflowContractError("retry seed must be a string")
    try:
        seed_bytes = seed.encode("utf-8")
    except UnicodeError as exc:
        raise WorkflowContractError("retry seed is not valid UTF-8") from exc
    if not seed_bytes or len(seed_bytes) > MAX_IDEMPOTENCY_TOKEN_BYTES:
        raise WorkflowContractError(f"retry seed must be 1-{MAX_IDEMPOTENCY_TOKEN_BYTES} UTF-8 bytes")
    try:
        retry_policy = (
            RetryPolicy()
            if policy is None
            else RetryPolicy.model_validate(policy.model_dump(mode="python"))
            if isinstance(policy, RetryPolicy)
            else RetryPolicy.model_validate(policy)
        )
    except ValidationError as exc:
        raise WorkflowContractError(_validation_summary(exc)) from exc

    exponential = min(
        retry_policy.max_delay_seconds,
        retry_policy.base_delay_seconds * (1 << (attempt_number - 1)),
    )
    jitter_span = (exponential * retry_policy.jitter_percent) // 100
    lower = max(1, exponential - jitter_span)
    upper = min(retry_policy.max_delay_seconds, exponential + jitter_span)
    if upper <= lower:
        return lower

    digest = hashlib.sha256(b"AdversaryGraph/retry-jitter/v1\x00" + str(attempt_number).encode("ascii") + b"\x00" + seed_bytes).digest()
    selection = int.from_bytes(digest[:8], "big")
    return lower + selection % (upper - lower + 1)


def normalize_error_code(value: str) -> str:
    """Validate a controlled, database-width workflow error code."""

    code = str.strip(value) if type(value) is str else ""
    if not _IDENTITY_RE.fullmatch(code):
        raise WorkflowContractError("error code must be a lowercase workflow identity up to 80 characters")
    return code


def sanitize_workflow_error(
    error_text: str,
    *,
    code: str,
    retryable: bool,
    error_class: str = "ExternalError",
) -> SanitizedWorkflowError:
    """Create deterministic, redacted, database-bounded error facts.

    Operational callers must extract exception text and class before entering
    this pure layer.  Calling arbitrary ``__str__`` or type-name hooks here
    would permit hidden I/O, state mutation, or nondeterministic output.
    """

    normalized_code, normalized_class, summary, normalized_retryable = _sanitize_workflow_error_fields(
        error_text,
        code=code,
        retryable=retryable,
        error_class=error_class,
    )
    return SanitizedWorkflowError(
        code=normalized_code,
        error_class=normalized_class,
        summary=summary,
        retryable=normalized_retryable,
    )


def _sanitize_workflow_error_fields(
    error_text: object,
    *,
    code: object,
    retryable: object,
    error_class: object,
) -> tuple[str, str, str, bool]:
    """Return the only tuple accepted by ``SanitizedWorkflowError``."""

    normalized_code = normalize_error_code(code)  # type: ignore[arg-type]
    if type(retryable) is not bool:
        raise WorkflowContractError("retryable must be a boolean")
    if type(error_text) is not str:
        raise WorkflowContractError("error_text must be an exact string")
    if type(error_class) is not str or not _ERROR_CLASS_RE.fullmatch(error_class):
        raise WorkflowContractError("error_class must be an exact bounded error identity")

    # Bound untrusted provider text before normalization or regex matching. A
    # character prefix is the cheap first cap; the UTF-8 prefix is the exact
    # working boundary and cannot split a code point.
    summary = unicodedata.normalize("NFC", error_text[:MAX_ERROR_WORKING_BYTES])
    summary = summary.encode("utf-8", errors="replace").decode("utf-8")
    summary = _utf8_prefix(summary, MAX_ERROR_WORKING_BYTES)
    summary = _redact_control_safe_error_text(summary)
    summary = " ".join(summary.split()) or "Stage execution failed"
    if len(summary) > MAX_ERROR_SUMMARY_CHARS:
        summary = f"{summary[: MAX_ERROR_SUMMARY_CHARS - 3]}..."
    return normalized_code, error_class, summary, retryable


def _redact_control_safe_error_text(value: str) -> str:
    """Redact through bounded space and empty control shadows.

    A space shadow preserves field boundaries such as ``message\npassword``;
    an empty shadow reconstructs split tokens such as ``to\0ken``. If either
    shadow finds sensitive material, span mapping would be ambiguous, so the
    whole bounded summary is conservatively replaced with a fixed-point safe
    value. Benign controls retain their boundary through the space shadow.
    """

    if not any(unicodedata.category(char) in _STRIPPED_ERROR_CATEGORIES for char in value):
        return _redact_error_shadow(value)
    space_shadow = "".join(" " if unicodedata.category(char) in _STRIPPED_ERROR_CATEGORIES else char for char in value)
    empty_shadow = "".join(char for char in value if unicodedata.category(char) not in _STRIPPED_ERROR_CATEGORIES)
    redacted_space = _redact_error_shadow(space_shadow)
    redacted_empty = _redact_error_shadow(empty_shadow)
    if redacted_space != space_shadow or redacted_empty != empty_shadow:
        return _CONTROL_REDACTED_ERROR_SUMMARY
    return space_shadow


def _redact_error_shadow(value: str) -> str:
    redacted = _PRIVATE_KEY_BLOCK_RE.sub("[REDACTED PRIVATE KEY]", value)
    redacted = _PRIVATE_KEY_UNTERMINATED_RE.sub("[REDACTED PRIVATE KEY]", redacted)
    redacted = _URL_CREDENTIAL_RE.sub(r"\1[REDACTED]@", redacted)
    redacted = _AUTH_SCHEME_RE.sub(lambda match: f"{match.group(1)} [REDACTED]", redacted)
    return _ASSIGNMENT_RE.sub(_redact_sensitive_assignment, redacted)


def _is_prohibited_error_key(value: str) -> bool:
    compatibility_normalized = unicodedata.normalize("NFKC", value)
    normalized = _CAMEL_CASE_BOUNDARY_RE.sub("_", compatibility_normalized).casefold()
    compact = _KEY_SEPARATOR_RE.sub("", normalized)
    tokens = {token for token in _KEY_SEPARATOR_RE.split(normalized) if token}
    return (
        compact in _PROHIBITED_KEY_TOKENS
        or any(compact.endswith(suffix) for suffix in _PROHIBITED_COMPACT_SUFFIXES)
        or bool(tokens & _PROHIBITED_KEY_TOKENS)
    )


def _redact_sensitive_assignment(match: re.Match[str]) -> str:
    key = match.group("key")
    if not _is_prohibited_error_key(key):
        return match.group(0)
    key_quote = match.group("quote")
    leading = match.group("leading")
    separator = match.group("separator")
    value = match.group("value")
    if len(value) >= 2 and value[0] in {'"', "'"} and value[-1] == value[0]:
        redacted_value = f"{value[0]}[REDACTED]{value[-1]}"
    else:
        redacted_value = "[REDACTED]"
    return f"{leading}{key_quote}{key}{key_quote}{separator}{redacted_value}"


def _utf8_prefix(value: str, max_bytes: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


def _validate_json_object(value: object, *, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{field_name} must be a JSON object")
    try:
        normalized = _normalize_json_value(value, depth=0, item_count=[0])
        canonical_json(normalized)
    except CanonicalJSONError as exc:
        raise ValueError(f"{field_name} is not valid bounded JSON: {exc}") from exc
    if not isinstance(normalized, dict):  # defensive; checked above
        raise ValueError(f"{field_name} must be a JSON object")
    return normalized


def _normalize_json_value(
    value: object,
    *,
    depth: int,
    item_count: list[int],
) -> Any:
    if depth > MAX_JSON_DEPTH:
        raise CanonicalJSONError(f"JSON nesting exceeds {MAX_JSON_DEPTH} levels")
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if abs(value) > MAX_SAFE_JSON_INTEGER:
            raise CanonicalJSONError("JSON integer exceeds the interoperable 53-bit range")
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise CanonicalJSONError("JSON numbers must be finite")
        return 0.0 if value == 0 else value
    if issubclass(type(value), str):
        normalized_string = unicodedata.normalize("NFC", value)
        try:
            size = len(normalized_string.encode("utf-8"))
        except UnicodeError as exc:
            raise CanonicalJSONError("JSON string is not valid UTF-8") from exc
        if size > MAX_JSON_STRING_BYTES:
            raise CanonicalJSONError(f"JSON string exceeds {MAX_JSON_STRING_BYTES} UTF-8 bytes")
        return normalized_string
    if type(value) is list:
        item_count[0] += len(value)
        if item_count[0] > MAX_JSON_ITEMS:
            raise CanonicalJSONError(f"JSON contains more than {MAX_JSON_ITEMS} aggregate items")
        return [
            _normalize_json_value(
                item,
                depth=depth + 1,
                item_count=item_count,
            )
            for item in value
        ]
    if type(value) is dict:
        item_count[0] += len(value)
        if item_count[0] > MAX_JSON_ITEMS:
            raise CanonicalJSONError(f"JSON contains more than {MAX_JSON_ITEMS} aggregate items")
        normalized_object: dict[str, Any] = {}
        for raw_key, item in value.items():
            if not issubclass(type(raw_key), str):
                raise CanonicalJSONError("JSON object keys must be strings")
            key = unicodedata.normalize("NFC", raw_key)
            if key in normalized_object:
                raise CanonicalJSONError("Unicode normalization creates a duplicate object key")
            if len(key.encode("utf-8")) > MAX_JSON_STRING_BYTES:
                raise CanonicalJSONError(f"JSON key exceeds {MAX_JSON_STRING_BYTES} UTF-8 bytes")
            normalized_object[key] = _normalize_json_value(
                item,
                depth=depth + 1,
                item_count=item_count,
            )
        return {key: normalized_object[key] for key in sorted(normalized_object)}
    value_type_name = type.__getattribute__(type(value), "__name__")
    raise CanonicalJSONError(f"Unsupported JSON value type: {value_type_name}")


def _validation_summary(error: ValidationError | ValueError) -> str:
    if isinstance(error, ValidationError):
        details = error.errors(include_url=False)
        fragments = []
        for detail in details[:5]:
            location = ".".join(str(item) for item in detail.get("loc", ()))
            message = str(detail.get("msg", "invalid value"))
            fragments.append(f"{location}: {message}" if location else message)
        return "Invalid workflow stage plan: " + "; ".join(fragments)
    return f"Invalid workflow stage plan: {error}"
