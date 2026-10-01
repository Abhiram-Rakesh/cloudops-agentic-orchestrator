"""Audit event log (``AUDIT#<entity>`` / ``<iso-ts>#<event>``).

Every consequential decision — an approval recorded, a lock refused, a
policy-recheck rejection, a remediation dispatched — is written here so the
full history of an action or finding is queryable by entity, in order.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from cloudops_orchestrator.store.serialization import from_dynamo_value, to_dynamo_value


def audit_key(entity: str, *, event: str, at: datetime) -> dict[str, str]:
    return {"pk": f"AUDIT#{entity}", "sk": f"{at.isoformat()}#{event}"}


def record_audit_event(
    table: Any,
    *,
    entity: str,
    event: str,
    details: dict[str, Any] | None = None,
    at: datetime | None = None,
) -> None:
    at = at or datetime.now(UTC)
    item: dict[str, Any] = audit_key(entity, event=event, at=at)
    item["entity"] = entity
    item["event"] = event
    item["at"] = at.isoformat()
    item["details"] = to_dynamo_value(details or {})
    table.put_item(Item=item)


def list_audit_events(table: Any, entity: str) -> list[dict[str, Any]]:
    response = table.query(
        KeyConditionExpression="pk = :pk", ExpressionAttributeValues={":pk": f"AUDIT#{entity}"}
    )
    events = []
    for item in response.get("Items", []):
        events.append(
            {
                "entity": item["entity"],
                "event": item["event"],
                "at": item["at"],
                "details": from_dynamo_value(item.get("details", {})),
            }
        )
    return events


__all__ = ["audit_key", "list_audit_events", "record_audit_event"]
