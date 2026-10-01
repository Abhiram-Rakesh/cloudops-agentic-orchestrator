"""Single-table DynamoDB access.

Key design (see README.md (How it works) once written, and `infra/modules/data`):
``pk``/``sk`` (String), GSI1 on ``gsi1pk``/``gsi1sk``.

| Entity | pk | sk |
|---|---|---|
| Finding | ``FINDING#<fingerprint>`` | ``META`` |
| Run summary | ``RUN#<run_id>`` | ``SUMMARY`` |
| Action plan | ``ACTION#<action_id>`` | ``PLAN`` |
| Approval | ``ACTION#<action_id>`` | ``APPROVAL#<approver_slack_id>`` |
| Exception | ``EXCEPTION#<scope>`` | ``META`` (TTL) |
| Audit event | ``AUDIT#<entity>`` | ``<iso-ts>#<event>`` |
| Lock | ``LOCK#<action_id>`` | ``LOCK`` (TTL) |
| Month-to-date spend | ``SPEND#<yyyy-mm>`` | ``LLM`` |

GSI1: ``gsi1pk=STATUS#<domain>#<status>``, ``gsi1sk=<last_seen iso>`` for
finding-by-status lookups.
"""

from __future__ import annotations

from typing import Any

from cloudops_orchestrator.config import Settings


def get_table(settings: Settings) -> Any:
    """Return the single-table store (a DynamoDB ``Table`` resource)."""
    from cloudops_orchestrator.aws.clients import get_dynamodb_resource

    resource = get_dynamodb_resource(region_name=settings.aws.region)
    table: Any = resource.Table(settings.storage.state_table)
    return table


__all__ = ["get_table"]
