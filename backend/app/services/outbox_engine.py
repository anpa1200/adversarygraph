"""Pure deterministic contracts for the durable workflow outbox.

This module is intentionally isolated from persistence and delivery concerns.
It validates the only event currently allowed across the workflow-to-worker
boundary and derives stable content addresses, business keys, delivery keys,
retry delays, and safe error facts without consulting a clock or external
system.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Annotated, Any, Literal, Mapping
import unicodedata
from uuid import UUID

from pydantic import ConfigDict, Field, StringConstraints, ValidationError, field_validator, model_validator

from app.core.payload_limits import BoundedPayloadModel
from app.services.workflow_engine import CanonicalJSONError, canonical_json


TOPIC_WORKFLOW_STAGE_READY = "workflow.stage.ready"
SCHEMA_WORKFLOW_STAGE_READY_V1 = "workflow-stage-ready-v1"
TOPIC_SCHEMA_REGISTRY: Mapping[str, str] = MappingProxyType({TOPIC_WORKFLOW_STAGE_READY: SCHEMA_WORKFLOW_STAGE_READY_V1})

MAX_OUTBOX_CANONICAL_BYTES = 48 * 1024
MAX_OUTBOX_JSON_DEPTH = 20
MAX_OUTBOX_JSON_ITEMS = 2_000
MAX_DELIVERY_ATTEMPTS = 32
MAX_DELIVERY_CYCLE = 9_007_199_254_740_991
MAX_ERROR_SUMMARY_CHARS = 500
MAX_ERROR_WORKING_BYTES = 8 * 1024

_IDENTITY_PATTERN = r"^[a-z][a-z0-9_.-]{0,79}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_IDENTITY_RE = re.compile(_IDENTITY_PATTERN)
_SHA256_RE = re.compile(_SHA256_PATTERN)
_CANONICAL_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
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
_CONTROL_REDACTED_ERROR_SUMMARY = "Outbox delivery failed: [REDACTED]"
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
SHA256Checksum = Annotated[
    str,
    StringConstraints(
        min_length=64,
        max_length=64,
        pattern=_SHA256_PATTERN,
    ),
]


class OutboxContractError(ValueError):
    """Base class for deterministic outbox contract failures."""


class OutboxEnvelopeValidationError(OutboxContractError):
    """An outbox envelope does not match a registered strict schema."""


class OutboxCanonicalJSONError(OutboxContractError):
    """An outbox value is not bounded portable canonical JSON."""


class OutboxKeyError(OutboxContractError):
    """An outbox business or delivery key is outside the accepted contract."""


class WorkflowStageReadyPayload(BoundedPayloadModel):
    """Pointer-only authority for one runnable workflow-stage attempt."""

    model_config = ConfigDict(extra="forbid", revalidate_instances="always")

    max_payload_bytes = MAX_OUTBOX_CANONICAL_BYTES
    max_string_bytes = MAX_OUTBOX_CANONICAL_BYTES

    workflow_run_id: UUID
    stage_run_id: UUID
    stage_key: StageIdentity
    target_attempt_number: int = Field(ge=1, le=20, strict=True)
    input_checksum: SHA256Checksum
    plan_checksum: SHA256Checksum

    @field_validator("workflow_run_id", "stage_run_id", mode="before")
    @classmethod
    def _require_canonical_uuid_text(cls, value: object) -> object:
        if isinstance(value, UUID):
            return value
        if not isinstance(value, str) or not _CANONICAL_UUID_RE.fullmatch(value):
            raise ValueError("UUID pointers must use canonical lowercase hyphenated text")
        try:
            parsed = UUID(value)
        except ValueError as exc:
            raise ValueError("UUID pointer is invalid") from exc
        if str(parsed) != value:
            raise ValueError("UUID pointers must use canonical lowercase hyphenated text")
        return value

    @model_validator(mode="before")
    @classmethod
    def _reject_embedded_content(cls, value: object) -> object:
        candidate = value.model_dump(mode="json") if isinstance(value, cls) else value
        _reject_prohibited_keys(candidate)
        return candidate


class OutboxEnvelope(BoundedPayloadModel):
    """Strict, registry-bound envelope accepted by the durable outbox."""

    model_config = ConfigDict(extra="forbid", revalidate_instances="always")

    max_payload_bytes = MAX_OUTBOX_CANONICAL_BYTES
    max_string_bytes = MAX_OUTBOX_CANONICAL_BYTES

    topic: Literal["workflow.stage.ready"]
    schema_version: Literal["workflow-stage-ready-v1"]
    payload: WorkflowStageReadyPayload

    @model_validator(mode="before")
    @classmethod
    def _reject_embedded_content(cls, value: object) -> object:
        candidate = value.model_dump(mode="json") if isinstance(value, cls) else value
        _reject_prohibited_keys(candidate)
        return candidate

    @field_validator("payload", mode="before")
    @classmethod
    def _revalidate_payload(cls, value: object) -> object:
        if isinstance(value, WorkflowStageReadyPayload):
            return value.model_dump(mode="json")
        return value

    @model_validator(mode="after")
    def _validate_registered_pair(self):
        if TOPIC_SCHEMA_REGISTRY.get(self.topic) != self.schema_version:
            raise ValueError("topic and schema_version are not a registered pair")
        return self


class OutboxRetryPolicy(BoundedPayloadModel):
    """Bounded retry policy for one delivery cycle."""

    model_config = ConfigDict(extra="forbid", revalidate_instances="always")

    base_delay_seconds: int = Field(default=5, ge=1, le=3_600, strict=True)
    max_delay_seconds: int = Field(default=900, ge=1, le=86_400, strict=True)
    jitter_percent: int = Field(default=20, ge=0, le=50, strict=True)

    @model_validator(mode="after")
    def _validate_delay_bounds(self):
        if self.max_delay_seconds < self.base_delay_seconds:
            raise ValueError("max_delay_seconds must be at least base_delay_seconds")
        return self


def _parse_bounded_outbox_canonical(value: object) -> object:
    if type(value) is not str:
        raise OutboxEnvelopeValidationError("Normalized outbox canonical authority must be an exact string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError as exc:
        raise OutboxEnvelopeValidationError("Normalized outbox canonical authority is not valid UTF-8") from exc
    if len(encoded) > MAX_OUTBOX_CANONICAL_BYTES:
        raise OutboxEnvelopeValidationError(f"Normalized outbox canonical authority exceeds {MAX_OUTBOX_CANONICAL_BYTES} bytes")
    try:
        return json.loads(value)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise OutboxEnvelopeValidationError("Normalized outbox envelope contains invalid canonical authority") from exc


@dataclass(frozen=True)
class NormalizedOutboxEnvelope:
    """Immutable canonical authority ready for atomic outbox persistence."""

    canonical: str
    checksum: str
    logical_key: str

    def __post_init__(self) -> None:
        if (
            type(self.canonical) is not str
            or type(self.checksum) is not str
            or type(self.logical_key) is not str
            or not _SHA256_RE.fullmatch(self.checksum)
            or not _SHA256_RE.fullmatch(self.logical_key)
        ):
            raise OutboxEnvelopeValidationError(
                "Normalized outbox envelope authority fields must be exact strings with lowercase SHA-256 metadata"
            )
        try:
            raw = _parse_bounded_outbox_canonical(self.canonical)
            rebuilt_raw_canonical = canonical_outbox_json(raw)
            rebuilt = OutboxEnvelope.model_validate(raw)
            rebuilt_canonical = canonical_outbox_json(rebuilt.model_dump(mode="json"))
        except (TypeError, ValidationError, OutboxContractError) as exc:
            raise OutboxEnvelopeValidationError("Normalized outbox envelope contains invalid canonical authority") from exc

        expected_checksum = hashlib.sha256(rebuilt_canonical.encode("utf-8")).hexdigest()
        expected_logical_key = _logical_key_for_envelope(rebuilt)
        if (
            rebuilt_raw_canonical != self.canonical
            or rebuilt_canonical != self.canonical
            or expected_checksum != self.checksum
            or expected_logical_key != self.logical_key
        ):
            raise OutboxEnvelopeValidationError("Normalized outbox envelope metadata does not match its canonical authority")

    @property
    def envelope(self) -> OutboxEnvelope:
        """Return a detached, fully revalidated envelope model."""

        return OutboxEnvelope.model_validate(self.as_payload())

    @property
    def payload(self) -> WorkflowStageReadyPayload:
        """Return a detached, fully revalidated event payload."""

        return self.envelope.payload

    def as_payload(self) -> dict[str, Any]:
        """Return a detached JSON-compatible envelope for a JSONB column."""

        value = _parse_bounded_outbox_canonical(self.canonical)
        if not isinstance(value, dict):  # defensive; constructor validates this
            raise OutboxEnvelopeValidationError("Normalized outbox envelope is not an object")
        return value


@dataclass(frozen=True)
class SanitizedOutboxError:
    """Bounded, redacted delivery error facts safe to persist."""

    code: str
    error_class: str
    summary: str
    retryable: bool

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("SanitizedOutboxError is sealed and cannot be subclassed")

    def __post_init__(self) -> None:
        if type(self) is not SanitizedOutboxError:
            raise OutboxContractError("Sanitized outbox error must use its exact authority type")
        normalized = _sanitize_outbox_error_fields(
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
            raise OutboxContractError("Sanitized outbox error facts must be exact fixed-point output from sanitize_outbox_error")


def canonical_outbox_json(value: object) -> str:
    """Return portable canonical JSON within the 48 KiB outbox limit."""

    _reject_prohibited_keys(value)
    try:
        encoded = canonical_json(value).encode("utf-8")
    except CanonicalJSONError as exc:
        raise OutboxCanonicalJSONError(str(exc)) from exc
    except UnicodeError as exc:
        raise OutboxCanonicalJSONError("Outbox JSON is not valid UTF-8") from exc
    if len(encoded) > MAX_OUTBOX_CANONICAL_BYTES:
        raise OutboxCanonicalJSONError(f"Canonical outbox JSON exceeds {MAX_OUTBOX_CANONICAL_BYTES} bytes")
    return encoded.decode("utf-8")


def normalize_outbox_envelope(
    value: OutboxEnvelope | dict[str, Any],
) -> NormalizedOutboxEnvelope:
    """Validate, normalize, and content-address a registered envelope."""

    if isinstance(value, OutboxEnvelope):
        candidate: object = value.model_dump(mode="json")
    elif isinstance(value, dict):
        candidate = dict(value)
        payload = candidate.get("payload")
        if isinstance(payload, WorkflowStageReadyPayload):
            candidate["payload"] = payload.model_dump(mode="json")
    else:
        raise OutboxEnvelopeValidationError("outbox envelope must be a JSON object")

    # Canonicalize the caller's raw shape before Pydantic can discard, coerce,
    # or mask a non-portable value or Unicode-normalized key collision.
    canonical_outbox_json(candidate)
    try:
        envelope = OutboxEnvelope.model_validate(candidate)
    except (ValidationError, ValueError) as exc:
        raise OutboxEnvelopeValidationError(_validation_summary(exc)) from exc

    canonical = canonical_outbox_json(envelope.model_dump(mode="json"))
    checksum = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return NormalizedOutboxEnvelope(
        canonical=canonical,
        checksum=checksum,
        logical_key=_logical_key_for_envelope(envelope),
    )


def derive_outbox_logical_key(value: OutboxEnvelope | dict[str, Any]) -> str:
    """Return the stable business identity for a strict outbox event."""

    return normalize_outbox_envelope(value).logical_key


def delivery_cycle_idempotency_key(logical_key: str, *, delivery_cycle: int) -> str:
    """Derive a stable, domain-separated key for one redelivery cycle."""

    normalized_key = _validate_logical_key(logical_key)
    if type(delivery_cycle) is not int or not 1 <= delivery_cycle <= MAX_DELIVERY_CYCLE:
        raise OutboxKeyError(f"delivery_cycle must be an integer from 1 to {MAX_DELIVERY_CYCLE}")
    material = (
        b"AdversaryGraph/outbox/delivery-cycle/v1\x00" + normalized_key.encode("ascii") + b"\x00" + str(delivery_cycle).encode("ascii")
    )
    return hashlib.sha256(material).hexdigest()


def deterministic_delivery_retry_delay_seconds(
    attempt_number: int,
    *,
    logical_key: str,
    policy: OutboxRetryPolicy | dict[str, Any] | None = None,
) -> int:
    """Return bounded exponential delivery backoff with stable jitter."""

    if type(attempt_number) is not int or not 1 <= attempt_number <= MAX_DELIVERY_ATTEMPTS:
        raise OutboxContractError(f"attempt_number must be an integer from 1 to {MAX_DELIVERY_ATTEMPTS}")
    normalized_key = _validate_logical_key(logical_key)
    try:
        retry_policy = (
            OutboxRetryPolicy()
            if policy is None
            else OutboxRetryPolicy.model_validate(policy.model_dump(mode="python"))
            if isinstance(policy, OutboxRetryPolicy)
            else OutboxRetryPolicy.model_validate(policy)
        )
    except ValidationError as exc:
        raise OutboxContractError(_retry_validation_summary(exc)) from exc

    exponential = min(
        retry_policy.max_delay_seconds,
        retry_policy.base_delay_seconds * (1 << (attempt_number - 1)),
    )
    jitter_span = (exponential * retry_policy.jitter_percent) // 100
    lower = max(1, exponential - jitter_span)
    upper = min(retry_policy.max_delay_seconds, exponential + jitter_span)
    if upper <= lower:
        return lower

    digest = hashlib.sha256(
        b"AdversaryGraph/outbox/delivery-retry-jitter/v1\x00"
        + str(attempt_number).encode("ascii")
        + b"\x00"
        + normalized_key.encode("ascii")
    ).digest()
    selection = int.from_bytes(digest[:8], "big")
    return lower + selection % (upper - lower + 1)


def sanitize_outbox_error(
    error_text: str,
    *,
    code: str,
    retryable: bool,
    error_class: str = "ExternalError",
) -> SanitizedOutboxError:
    """Create deterministic, redacted, database-bounded delivery error facts.

    Operational adapters must extract exception text and class before entering
    this pure layer.  Calling an arbitrary exception's ``__str__`` here would
    permit hidden I/O, state mutation, or nondeterministic output.
    """

    normalized_code, normalized_class, summary, normalized_retryable = _sanitize_outbox_error_fields(
        error_text,
        code=code,
        retryable=retryable,
        error_class=error_class,
    )
    return SanitizedOutboxError(
        code=normalized_code,
        error_class=normalized_class,
        summary=summary,
        retryable=normalized_retryable,
    )


def _sanitize_outbox_error_fields(
    error_text: object,
    *,
    code: object,
    retryable: object,
    error_class: object,
) -> tuple[str, str, str, bool]:
    """Return the only error tuple accepted by ``SanitizedOutboxError``."""

    normalized_code = _normalize_error_code(code)
    if type(retryable) is not bool:
        raise OutboxContractError("retryable must be a boolean")
    if type(error_text) is not str:
        raise OutboxContractError("error_text must be an exact string")
    if type(error_class) is not str or not _ERROR_CLASS_RE.fullmatch(error_class):
        raise OutboxContractError("error_class must be an exact bounded error identity")
    # Bound hostile provider text before normalization and regex matching.  A
    # character prefix is a cheap first cap; the UTF-8 cap below is the exact
    # service boundary and cannot split a code point.
    summary = unicodedata.normalize("NFC", error_text[:MAX_ERROR_WORKING_BYTES])
    summary = summary.encode("utf-8", errors="replace").decode("utf-8")
    summary = _utf8_prefix(summary, MAX_ERROR_WORKING_BYTES)
    summary = _redact_control_safe_error_text(summary)
    summary = " ".join(summary.split()) or "Outbox delivery failed"
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


def _logical_key_for_envelope(envelope: OutboxEnvelope) -> str:
    payload = envelope.payload
    identity = {
        "schema_version": envelope.schema_version,
        "stage_key": payload.stage_key,
        "stage_run_id": str(payload.stage_run_id),
        "target_attempt_number": payload.target_attempt_number,
        "topic": envelope.topic,
        "workflow_run_id": str(payload.workflow_run_id),
    }
    canonical_identity = canonical_json(identity).encode("utf-8")
    return hashlib.sha256(b"AdversaryGraph/outbox/logical-key/v1\x00" + canonical_identity).hexdigest()


def _validate_logical_key(value: object) -> str:
    if type(value) is not str or not _SHA256_RE.fullmatch(value):
        raise OutboxKeyError("logical_key must be a lowercase SHA-256 digest")
    return value


def _normalize_error_code(value: object) -> str:
    code = value.strip() if type(value) is str else ""
    if not _IDENTITY_RE.fullmatch(code):
        raise OutboxContractError("error code must be a lowercase outbox identity up to 80 characters")
    return code


def _reject_prohibited_keys(
    value: object,
    *,
    depth: int = 0,
    item_count: list[int] | None = None,
    byte_count: list[int] | None = None,
) -> None:
    if item_count is None:
        item_count = [0]
    if byte_count is None:
        byte_count = [0]
    if depth > MAX_OUTBOX_JSON_DEPTH:
        raise OutboxCanonicalJSONError(f"Outbox JSON nesting exceeds {MAX_OUTBOX_JSON_DEPTH} levels")
    if type(value) is dict:
        _consume_raw_byte_budget(byte_count, 2 + len(value))
        item_count[0] += len(value)
        if item_count[0] > MAX_OUTBOX_JSON_ITEMS:
            raise OutboxCanonicalJSONError(f"Outbox JSON contains more than {MAX_OUTBOX_JSON_ITEMS} aggregate items")
        for raw_key, item in value.items():
            if type(raw_key) is str:
                key_size = _validate_raw_string_bound(raw_key, field_name="key")
                _consume_raw_byte_budget(byte_count, key_size + 3)
                if _is_prohibited_key(raw_key):
                    raise OutboxEnvelopeValidationError("outbox payload contains a prohibited raw-content or secret-bearing field")
            elif isinstance(raw_key, str):
                raise OutboxCanonicalJSONError("Outbox JSON keys must be exact strings")
            else:
                _consume_raw_byte_budget(byte_count, 16)
            _reject_prohibited_keys(
                item,
                depth=depth + 1,
                item_count=item_count,
                byte_count=byte_count,
            )
    elif type(value) is list:
        _consume_raw_byte_budget(byte_count, 2 + len(value))
        item_count[0] += len(value)
        if item_count[0] > MAX_OUTBOX_JSON_ITEMS:
            raise OutboxCanonicalJSONError(f"Outbox JSON contains more than {MAX_OUTBOX_JSON_ITEMS} aggregate items")
        for item in value:
            _reject_prohibited_keys(
                item,
                depth=depth + 1,
                item_count=item_count,
                byte_count=byte_count,
            )
    elif type(value) is str:
        string_size = _validate_raw_string_bound(value, field_name="string")
        _consume_raw_byte_budget(byte_count, string_size + 2)
    elif isinstance(value, str):
        raise OutboxCanonicalJSONError("Outbox JSON strings must be exact strings")
    else:
        _consume_raw_byte_budget(byte_count, 16)


def _is_prohibited_key(value: str) -> bool:
    compact, tokens = _normalized_key_parts(value)
    return (
        compact in _PROHIBITED_KEY_TOKENS
        or any(compact.endswith(suffix) for suffix in _PROHIBITED_COMPACT_SUFFIXES)
        or bool(tokens & _PROHIBITED_KEY_TOKENS)
    )


def _normalized_key_parts(value: str) -> tuple[str, set[str]]:
    compatibility_normalized = unicodedata.normalize("NFKC", value)
    normalized = _CAMEL_CASE_BOUNDARY_RE.sub("_", compatibility_normalized).casefold()
    compact = _KEY_SEPARATOR_RE.sub("", normalized)
    tokens = {token for token in _KEY_SEPARATOR_RE.split(normalized) if token}
    return compact, tokens


def _redact_sensitive_assignment(match: re.Match[str]) -> str:
    key = match.group("key")
    if not _is_prohibited_key(key):
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


def _validate_raw_string_bound(value: str, *, field_name: str) -> int:
    if len(value) > MAX_OUTBOX_CANONICAL_BYTES:
        raise OutboxCanonicalJSONError(f"Outbox JSON {field_name} exceeds {MAX_OUTBOX_CANONICAL_BYTES} UTF-8 bytes")
    try:
        encoded_size = len(value.encode("utf-8"))
    except UnicodeError as exc:
        raise OutboxCanonicalJSONError(f"Outbox JSON {field_name} is not valid UTF-8") from exc
    if encoded_size > MAX_OUTBOX_CANONICAL_BYTES:
        raise OutboxCanonicalJSONError(f"Outbox JSON {field_name} exceeds {MAX_OUTBOX_CANONICAL_BYTES} UTF-8 bytes")
    return encoded_size


def _consume_raw_byte_budget(byte_count: list[int], amount: int) -> None:
    byte_count[0] += amount
    if byte_count[0] > MAX_OUTBOX_CANONICAL_BYTES:
        raise OutboxCanonicalJSONError(f"Raw outbox JSON exceeds the {MAX_OUTBOX_CANONICAL_BYTES}-byte aggregate UTF-8 budget")


def _utf8_prefix(value: str, max_bytes: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


def _validation_summary(error: ValidationError | ValueError) -> str:
    if isinstance(error, ValidationError):
        fragments = []
        for detail in error.errors(include_url=False)[:5]:
            location = ".".join(str(item) for item in detail.get("loc", ()))
            message = str(detail.get("msg", "invalid value"))
            fragments.append(f"{location}: {message}" if location else message)
        return "Invalid outbox envelope: " + "; ".join(fragments)
    return f"Invalid outbox envelope: {error}"


def _retry_validation_summary(error: ValidationError) -> str:
    fragments = []
    for detail in error.errors(include_url=False)[:5]:
        location = ".".join(str(item) for item in detail.get("loc", ()))
        message = str(detail.get("msg", "invalid value"))
        fragments.append(f"{location}: {message}" if location else message)
    return "Invalid outbox retry policy: " + "; ".join(fragments)
