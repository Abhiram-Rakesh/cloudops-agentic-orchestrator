"""Moto-backed tests for store/actions.py: plan storage, approvals, locks."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from moto import mock_aws

from cloudops_orchestrator.models.actions import ActionPlan, Approval
from cloudops_orchestrator.models.enums import ActionType, ApprovalDecision, RiskTier
from cloudops_orchestrator.store import actions as store_actions

TABLE_NAME = "cloudops-lite-state-test"


@pytest.fixture
def table() -> Any:
    with mock_aws():
        import boto3

        resource = boto3.resource("dynamodb", region_name="ap-south-1")
        resource.create_table(
            TableName=TABLE_NAME,
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PROVISIONED",
            ProvisionedThroughput={"ReadCapacityUnits": 8, "WriteCapacityUnits": 8},
        )
        yield resource.Table(TABLE_NAME)


def _plan(**overrides: object) -> ActionPlan:
    defaults: dict[str, object] = {
        "action_id": "action-1",
        "recommendation_id": "rec-1",
        "action_type": ActionType.SSM_AUTOMATION,
        "parameters": {"document": "CloudOps-RevokeSGIngressWorld"},
        "targets": ["sg-1"],
        "effective_risk_tier": RiskTier.T1,
        "required_approvals": 1,
        "expires_at": datetime(2026, 2, 1, tzinfo=UTC),
        "plan_hash": "a" * 64,
    }
    defaults.update(overrides)
    return ActionPlan(**defaults)  # type: ignore[arg-type]


def _approval(**overrides: object) -> Approval:
    defaults: dict[str, object] = {
        "action_id": "action-1",
        "plan_hash": "a" * 64,
        "decision": ApprovalDecision.APPROVE,
        "approver_slack_id": "U1",
        "approver_name": "Alice",
        "decided_at": datetime(2026, 1, 20, tzinfo=UTC),
    }
    defaults.update(overrides)
    return Approval(**defaults)  # type: ignore[arg-type]


class TestActionPlan:
    def test_round_trip(self, table: Any) -> None:
        store_actions.put_action_plan(table, _plan())
        result = store_actions.get_action_plan(table, "action-1")
        assert result is not None
        plan, status = result
        assert plan.action_id == "action-1"
        assert status == store_actions.ActionStatus.AWAITING_APPROVAL

    def test_missing_plan_returns_none(self, table: Any) -> None:
        assert store_actions.get_action_plan(table, "missing") is None

    def test_set_status(self, table: Any) -> None:
        store_actions.put_action_plan(table, _plan())
        store_actions.set_action_status(table, "action-1", store_actions.ActionStatus.APPROVED)
        _, status = store_actions.get_action_plan(table, "action-1")  # type: ignore[misc]
        assert status == store_actions.ActionStatus.APPROVED


class TestApprovals:
    def test_put_and_get(self, table: Any) -> None:
        store_actions.put_approval(table, _approval())
        approvals = store_actions.get_approvals(table, "action-1")
        assert len(approvals) == 1
        assert approvals[0].approver_slack_id == "U1"

    def test_distinct_approvers_both_recorded(self, table: Any) -> None:
        store_actions.put_approval(table, _approval(approver_slack_id="U1"))
        store_actions.put_approval(table, _approval(approver_slack_id="U2", approver_name="Bob"))
        approvals = store_actions.get_approvals(table, "action-1")
        assert {a.approver_slack_id for a in approvals} == {"U1", "U2"}

    def test_has_approved(self, table: Any) -> None:
        store_actions.put_approval(table, _approval(approver_slack_id="U1"))
        assert store_actions.has_approved(table, "action-1", "U1") is True
        assert store_actions.has_approved(table, "action-1", "U2") is False

    def test_repeated_approval_same_approver_does_not_duplicate(self, table: Any) -> None:
        store_actions.put_approval(table, _approval(approver_slack_id="U1"))
        store_actions.put_approval(table, _approval(approver_slack_id="U1", comment="again"))
        approvals = store_actions.get_approvals(table, "action-1")
        assert len(approvals) == 1


class TestLocks:
    def test_acquire_when_free(self, table: Any) -> None:
        assert store_actions.acquire_lock(table, "action-1") is True

    def test_cannot_acquire_when_held(self, table: Any) -> None:
        now = datetime(2026, 1, 1, tzinfo=UTC)
        assert store_actions.acquire_lock(table, "action-1", now=now) is True
        assert (
            store_actions.acquire_lock(table, "action-1", now=now + timedelta(minutes=5)) is False
        )

    def test_can_reacquire_after_release(self, table: Any) -> None:
        store_actions.acquire_lock(table, "action-1")
        store_actions.release_lock(table, "action-1")
        assert store_actions.acquire_lock(table, "action-1") is True

    def test_can_reacquire_after_ttl_expiry(self, table: Any) -> None:
        now = datetime(2026, 1, 1, tzinfo=UTC)
        store_actions.acquire_lock(table, "action-1", now=now)
        later = now + timedelta(minutes=store_actions.LOCK_TTL_MINUTES + 1)
        assert store_actions.acquire_lock(table, "action-1", now=later) is True

    def test_different_actions_independent_locks(self, table: Any) -> None:
        assert store_actions.acquire_lock(table, "action-1") is True
        assert store_actions.acquire_lock(table, "action-2") is True
