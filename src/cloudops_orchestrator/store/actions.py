"""Action plan, approval, and conditional-lock storage (single-table).

``ACTION#<id>``/``PLAN`` (+ a ``status`` attribute alongside the plan's own
fields), ``ACTION#<id>``/``APPROVAL#<approver>`` per distinct approver, and
``LOCK#<id>``/``LOCK`` (TTL) preventing two concurrent resumes of the same
action thread.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Final

from cloudops_orchestrator.models.actions import ActionPlan, Approval
from cloudops_orchestrator.store.serialization import from_dynamo_value, to_dynamo_value

LOCK_TTL_MINUTES: Final = 30


class ActionStatus:
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    EXECUTED = "EXECUTED"
    REJECTED = "REJECTED"
    SNOOZED = "SNOOZED"
    EXPIRED = "EXPIRED"


def action_plan_key(action_id: str) -> dict[str, str]:
    return {"pk": f"ACTION#{action_id}", "sk": "PLAN"}


def approval_key(action_id: str, approver_slack_id: str) -> dict[str, str]:
    return {"pk": f"ACTION#{action_id}", "sk": f"APPROVAL#{approver_slack_id}"}


def lock_key(action_id: str) -> dict[str, str]:
    return {"pk": f"LOCK#{action_id}", "sk": "LOCK"}


def put_action_plan(
    table: Any, plan: ActionPlan, *, status: str = ActionStatus.AWAITING_APPROVAL
) -> None:
    item: dict[str, Any] = to_dynamo_value(plan.model_dump(mode="json"))
    item.update(action_plan_key(plan.action_id))
    item["status"] = status
    table.put_item(Item=item)


def get_action_plan(table: Any, action_id: str) -> tuple[ActionPlan, str] | None:
    response = table.get_item(Key=action_plan_key(action_id))
    item = response.get("Item")
    if item is None:
        return None
    status: str = item["status"]
    data = {k: v for k, v in item.items() if k not in ("pk", "sk", "status")}
    return ActionPlan.model_validate(from_dynamo_value(data)), status


def set_action_status(table: Any, action_id: str, status: str) -> None:
    table.update_item(
        Key=action_plan_key(action_id),
        UpdateExpression="SET #s = :status",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":status": status},
    )


def put_approval(table: Any, approval: Approval) -> None:
    item: dict[str, Any] = to_dynamo_value(approval.model_dump(mode="json"))
    item.update(approval_key(approval.action_id, approval.approver_slack_id))
    table.put_item(Item=item)


def get_approvals(table: Any, action_id: str) -> list[Approval]:
    response = table.query(
        KeyConditionExpression="pk = :pk AND begins_with(sk, :prefix)",
        ExpressionAttributeValues={":pk": f"ACTION#{action_id}", ":prefix": "APPROVAL#"},
    )
    approvals = []
    for item in response.get("Items", []):
        data = {k: v for k, v in item.items() if k not in ("pk", "sk")}
        approvals.append(Approval.model_validate(from_dynamo_value(data)))
    return approvals


def has_approved(table: Any, action_id: str, approver_slack_id: str) -> bool:
    response = table.get_item(Key=approval_key(action_id, approver_slack_id))
    return "Item" in response


def acquire_lock(table: Any, action_id: str, *, now: datetime | None = None) -> bool:
    """Conditional put: ``True`` if the lock was acquired, ``False`` if
    already held by a non-expired lock (real DynamoDB TTL deletion is lazy
    — a lock past its TTL but not yet swept is still treated as free)."""
    now = now or datetime.now(UTC)
    ttl = int((now + timedelta(minutes=LOCK_TTL_MINUTES)).timestamp())
    try:
        table.put_item(
            Item={**lock_key(action_id), "ttl": ttl, "locked_at": now.isoformat()},
            ConditionExpression="attribute_not_exists(pk) OR #ttl < :now",
            ExpressionAttributeNames={"#ttl": "ttl"},  # ttl is a DynamoDB reserved word
            ExpressionAttributeValues={":now": int(now.timestamp())},
        )
        return True
    except table.meta.client.exceptions.ConditionalCheckFailedException:
        return False


def release_lock(table: Any, action_id: str) -> None:
    table.delete_item(Key=lock_key(action_id))


__all__ = [
    "LOCK_TTL_MINUTES",
    "ActionStatus",
    "acquire_lock",
    "action_plan_key",
    "approval_key",
    "get_action_plan",
    "get_approvals",
    "has_approved",
    "lock_key",
    "put_action_plan",
    "put_approval",
    "release_lock",
    "set_action_status",
]
