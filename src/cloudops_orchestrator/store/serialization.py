"""DynamoDB item (de)serialization helpers.

The boto3 *resource* API (used everywhere in ``store/``) requires floats to
be ``Decimal`` and rejects empty string sets, so every model round-trips
through these two converters rather than being put/read directly.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any


def to_dynamo_value(value: Any) -> Any:
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, dict):
        return {k: to_dynamo_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [to_dynamo_value(v) for v in value]
    return value


def from_dynamo_value(value: Any) -> Any:
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, dict):
        return {k: from_dynamo_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [from_dynamo_value(v) for v in value]
    return value


__all__ = ["from_dynamo_value", "to_dynamo_value"]
