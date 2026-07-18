from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.payload_limits import BoundedPayloadModel


class TinyPayload(BoundedPayloadModel):
    max_payload_bytes = 32
    max_string_bytes = 16
    max_collection_items = 3
    max_nesting_depth = 2

    value: object


@pytest.mark.parametrize(
    "value, message",
    [
        ("x" * 17, "string exceeds"),
        ([1, 2, 3, 4], "more than 3 items"),
        ({"a": {"b": {"c": "d"}}}, "nesting exceeds"),
    ],
)
def test_structured_payload_limits_reject_oversized_values(value, message):
    with pytest.raises(ValidationError, match=message):
        TinyPayload(value=value)


def test_structured_payload_limit_rejects_aggregate_size_and_extra_fields():
    with pytest.raises(ValidationError, match="structured-data limit"):
        TinyPayload(value=["123456789012", "abcdefghijkl", "ABCDEFGHIJKL"])

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        TinyPayload(value="ok", unexpected=True)
