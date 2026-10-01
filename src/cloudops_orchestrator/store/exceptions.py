"""SOP exception storage (``EXCEPTION#<id>``/``META``, TTL) and the
higher-level functions the CLI's ``exceptions`` commands call directly
(SHARED-003). SHARED-003-3.2's duration caps and SEC-006-6.3's CISO
approval for Critical exceptions are process controls enforced by the
humans in that RACI, not by this storage layer — see
``knowledge_base/shared/SHARED-003.md``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from boto3.dynamodb.conditions import Attr

from cloudops_orchestrator.config import Settings
from cloudops_orchestrator.models.exceptions import SOPException
from cloudops_orchestrator.store.client import get_table
from cloudops_orchestrator.store.serialization import from_dynamo_value, to_dynamo_value


def exception_key(exception_id: str) -> dict[str, str]:
    return {"pk": f"EXCEPTION#{exception_id}", "sk": "META"}


def put_exception(table: Any, exception: SOPException) -> None:
    item: dict[str, Any] = to_dynamo_value(exception.model_dump(mode="json"))
    item.update(exception_key(exception.exception_id))
    item["ttl"] = int(exception.expires_at.timestamp())
    table.put_item(Item=item)


def get_exception(table: Any, exception_id: str) -> SOPException | None:
    response = table.get_item(Key=exception_key(exception_id))
    item = response.get("Item")
    if item is None:
        return None
    data = {k: v for k, v in item.items() if k not in ("pk", "sk", "ttl")}
    return SOPException.model_validate(from_dynamo_value(data))


def delete_exception(table: Any, exception_id: str) -> None:
    table.delete_item(Key=exception_key(exception_id))


def scan_exceptions(table: Any) -> list[SOPException]:
    response = table.scan(
        FilterExpression=Attr("pk").begins_with("EXCEPTION#") & Attr("sk").eq("META")
    )
    exceptions = []
    for item in response.get("Items", []):
        data = {k: v for k, v in item.items() if k not in ("pk", "sk", "ttl")}
        exceptions.append(SOPException.model_validate(from_dynamo_value(data)))
    return exceptions


def add_exception(
    settings: Settings,
    *,
    clause_id: str,
    duration_days: int,
    compensating_control: str,
    justification: str = "",
    fingerprint: str | None = None,
    owner: str | None = None,
    now: datetime | None = None,
) -> SOPException:
    table = get_table(settings)
    now = now or datetime.now(UTC)
    exception = SOPException(
        exception_id=str(uuid4()),
        clause_id=clause_id,
        fingerprint=fingerprint,
        justification=justification or f"Exception requested for {clause_id}.",
        compensating_control=compensating_control,
        owner=owner,
        created_at=now,
        expires_at=now + timedelta(days=duration_days),
    )
    put_exception(table, exception)
    return exception


def list_exceptions(settings: Settings) -> list[SOPException]:
    table = get_table(settings)
    return scan_exceptions(table)


def remove_exception(settings: Settings, *, exception_id: str) -> None:
    table = get_table(settings)
    delete_exception(table, exception_id)


__all__ = [
    "add_exception",
    "delete_exception",
    "exception_key",
    "get_exception",
    "list_exceptions",
    "put_exception",
    "remove_exception",
    "scan_exceptions",
]
