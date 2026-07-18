"""Reusable limits for JSON request models persisted by the platform."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, model_validator


class BoundedPayloadModel(BaseModel):
    """Reject unexpectedly large or deeply nested structured payloads.

    Per-field constraints remain the source of truth for database-width fields.
    These aggregate limits cover free-form JSON fields and nested collections
    that cannot be expressed completely in an OpenAPI schema.
    """

    model_config = ConfigDict(extra="forbid")

    max_payload_bytes: ClassVar[int] = 1024 * 1024
    max_string_bytes: ClassVar[int] = 256 * 1024
    max_collection_items: ClassVar[int] = 2000
    max_nesting_depth: ClassVar[int] = 20

    @model_validator(mode="after")
    def enforce_payload_limits(self):
        size = _bounded_size(
            self.model_dump(mode="json"),
            max_string_bytes=self.max_string_bytes,
            max_collection_items=self.max_collection_items,
            max_nesting_depth=self.max_nesting_depth,
        )
        if size > self.max_payload_bytes:
            raise ValueError(
                f"Request payload exceeds the {self.max_payload_bytes}-byte structured-data limit"
            )
        return self


def _bounded_size(
    value: Any,
    *,
    max_string_bytes: int,
    max_collection_items: int,
    max_nesting_depth: int,
    depth: int = 0,
) -> int:
    if depth > max_nesting_depth:
        raise ValueError(f"Request payload nesting exceeds {max_nesting_depth} levels")
    if isinstance(value, str):
        size = len(value.encode("utf-8"))
        if size > max_string_bytes:
            raise ValueError(f"Request string exceeds the {max_string_bytes}-byte limit")
        return size
    if isinstance(value, Mapping):
        if len(value) > max_collection_items:
            raise ValueError(
                f"Request object contains more than {max_collection_items} keys"
            )
        return sum(
            _bounded_size(
                str(key),
                max_string_bytes=max_string_bytes,
                max_collection_items=max_collection_items,
                max_nesting_depth=max_nesting_depth,
                depth=depth + 1,
            )
            + _bounded_size(
                item,
                max_string_bytes=max_string_bytes,
                max_collection_items=max_collection_items,
                max_nesting_depth=max_nesting_depth,
                depth=depth + 1,
            )
            for key, item in value.items()
        )
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        if len(value) > max_collection_items:
            raise ValueError(
                f"Request collection contains more than {max_collection_items} items"
            )
        return sum(
            _bounded_size(
                item,
                max_string_bytes=max_string_bytes,
                max_collection_items=max_collection_items,
                max_nesting_depth=max_nesting_depth,
                depth=depth + 1,
            )
            for item in value
        )
    return 16
