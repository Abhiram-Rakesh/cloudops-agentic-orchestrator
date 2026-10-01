from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode

import pytest
from moto import mock_aws

from cloudops_orchestrator.handlers.slack_handler import (
    Interaction,
    is_authorized,
    is_fresh,
    parse_form_payload,
    parse_interaction,
    process_interaction,
    verify_signature,
)
from cloudops_orchestrator.models.actions import ActionPlan, Approval
from cloudops_orchestrator.models.enums import ActionType, ApprovalDecision, RiskTier
from cloudops_orchestrator.store.actions import ActionStatus, put_action_plan, put_approval

TABLE_NAME = "cloudops-lite-state-test"


def _plan(**overrides: object) -> ActionPlan:
    defaults: dict[str, object] = {
        "action_id": "action-1",
        "recommendation_id": "rec-1",
        "action_type": ActionType.SSM_AUTOMATION,
        "parameters": {"document": "CloudOps-RevokeSGIngressWorld"},
        "targets": ["sg-1"],
        "effective_risk_tier": RiskTier.T1,
        "required_approvals": 2,
        "expires_at": datetime(2026, 2, 1, tzinfo=UTC),
        "plan_hash": "a" * 64,
    }
    defaults.update(overrides)
    return ActionPlan(**defaults)  # type: ignore[arg-type]


def _interaction(**overrides: object) -> Interaction:
    defaults: dict[str, object] = {
        "action_id": "approve_action",
        "plan_action_id": "action-1",
        "user_id": "U1",
        "user_name": "alice",
        "channel_id": "C1",
        "message_ts": "169.1",
    }
    defaults.update(overrides)
    return Interaction(**defaults)  # type: ignore[arg-type]


class FakeSlackClient:
    def __init__(self) -> None:
        self.updates: list[dict[str, Any]] = []
        self.ephemeral: list[dict[str, Any]] = []

    def chat_update(self, *, channel: str, ts: str, text: str) -> None:
        self.updates.append({"channel": channel, "ts": ts, "text": text})

    def post_ephemeral(self, *, channel: str, user: str, text: str) -> None:
        self.ephemeral.append({"channel": channel, "user": user, "text": text})


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


class TestVerifySignature:
    def test_valid_signature_accepted(self) -> None:
        secret = "shhh"
        timestamp = "1700000000"
        body = "payload=%7B%7D"
        basestring = f"v0:{timestamp}:{body}".encode()
        signature = "v0=" + hmac.new(secret.encode(), basestring, hashlib.sha256).hexdigest()
        assert verify_signature(
            signing_secret=secret, timestamp=timestamp, body=body, signature=signature
        )

    def test_invalid_signature_rejected(self) -> None:
        assert not verify_signature(
            signing_secret="shhh", timestamp="1700000000", body="payload=%7B%7D", signature="v0=bad"
        )

    def test_signature_wrong_secret_rejected(self) -> None:
        timestamp = "1700000000"
        body = "payload=%7B%7D"
        basestring = f"v0:{timestamp}:{body}".encode()
        signature = "v0=" + hmac.new(b"other-secret", basestring, hashlib.sha256).hexdigest()
        assert not verify_signature(
            signing_secret="shhh", timestamp=timestamp, body=body, signature=signature
        )


class TestIsFresh:
    def test_fresh_timestamp_accepted(self) -> None:
        now = datetime(2026, 1, 1, 0, 5, 0, tzinfo=UTC)
        timestamp = str(int(datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC).timestamp()))
        assert is_fresh(timestamp, now=now, max_age_seconds=300)

    def test_stale_timestamp_rejected(self) -> None:
        now = datetime(2026, 1, 1, 0, 10, 1, tzinfo=UTC)
        timestamp = str(int(datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC).timestamp()))
        assert not is_fresh(timestamp, now=now, max_age_seconds=300)

    def test_non_numeric_timestamp_rejected(self) -> None:
        assert not is_fresh("not-a-number", now=datetime.now(UTC))


class TestParseFormPayload:
    def test_extracts_payload_json(self) -> None:
        body = urlencode({"payload": json.dumps({"type": "block_actions"})})
        assert parse_form_payload(body) == {"type": "block_actions"}

    def test_missing_payload_raises(self) -> None:
        with pytest.raises(ValueError, match="payload"):
            parse_form_payload("foo=bar")


class TestParseInteraction:
    def _payload(self, **overrides: object) -> dict[str, Any]:
        base: dict[str, Any] = {
            "type": "block_actions",
            "user": {"id": "U1", "username": "alice"},
            "actions": [{"action_id": "approve_action", "value": "action-1", "type": "button"}],
            "channel": {"id": "C1"},
            "message": {"ts": "169.1"},
        }
        base.update(overrides)
        return base

    def test_parses_approve(self) -> None:
        interaction = parse_interaction(self._payload())
        assert interaction.action_id == "approve_action"
        assert interaction.plan_action_id == "action-1"
        assert interaction.user_id == "U1"
        assert interaction.decision == ApprovalDecision.APPROVE

    def test_wrong_type_raises(self) -> None:
        with pytest.raises(ValueError, match="unsupported interaction type"):
            parse_interaction(self._payload(type="view_submission"))

    def test_no_actions_raises(self) -> None:
        with pytest.raises(ValueError, match="no actions"):
            parse_interaction(self._payload(actions=[]))

    def test_unrecognized_action_id_raises(self) -> None:
        payload = self._payload()
        payload["actions"][0]["action_id"] = "open_report"
        with pytest.raises(ValueError, match="unrecognized action_id"):
            parse_interaction(payload)


class TestIsAuthorized:
    def test_approver_authorized(self) -> None:
        assert is_authorized("U1", approvers=["U1", "U2"])

    def test_non_approver_unauthorized(self) -> None:
        assert not is_authorized("U999", approvers=["U1", "U2"])


class TestProcessInteraction:
    def test_unknown_action_id(self, table: Any) -> None:
        result = process_interaction(_interaction(), table=table, slack_client=FakeSlackClient())
        assert result.invoked_worker is False
        assert "unknown" in result.reason

    def test_expired_plan(self, table: Any) -> None:
        put_action_plan(table, _plan(expires_at=datetime(2020, 1, 1, tzinfo=UTC)))
        result = process_interaction(
            _interaction(),
            table=table,
            slack_client=FakeSlackClient(),
            now=datetime(2026, 1, 1, tzinfo=UTC),
        )
        assert result.invoked_worker is False
        assert "expired" in result.reason

    def test_already_terminal_status(self, table: Any) -> None:
        put_action_plan(table, _plan(), status=ActionStatus.EXECUTED)
        result = process_interaction(_interaction(), table=table, slack_client=FakeSlackClient())
        assert result.invoked_worker is False
        assert "already" in result.reason

    def test_duplicate_approval_is_idempotent(self, table: Any) -> None:
        plan = _plan()
        put_action_plan(table, plan)
        put_approval(
            table,
            Approval(
                action_id=plan.action_id,
                plan_hash=plan.plan_hash,
                decision=ApprovalDecision.APPROVE,
                approver_slack_id="U1",
                approver_name="alice",
                decided_at=datetime(2026, 1, 1, tzinfo=UTC),
            ),
        )
        result = process_interaction(
            _interaction(),
            table=table,
            slack_client=FakeSlackClient(),
            now=datetime(2026, 1, 15, tzinfo=UTC),
        )
        assert result.invoked_worker is False
        assert "duplicate" in result.reason

    def test_first_approval_below_threshold_does_not_invoke(self, table: Any) -> None:
        put_action_plan(table, _plan(required_approvals=2))
        slack_client = FakeSlackClient()
        result = process_interaction(
            _interaction(),
            table=table,
            slack_client=slack_client,
            now=datetime(2026, 1, 15, tzinfo=UTC),
        )
        assert result.invoked_worker is False
        assert result.reason == "awaiting more approvals"
        assert len(slack_client.updates) == 1

    def test_second_distinct_approval_meets_threshold(self, table: Any) -> None:
        plan = _plan(required_approvals=2)
        put_action_plan(table, plan)
        put_approval(
            table,
            Approval(
                action_id=plan.action_id,
                plan_hash=plan.plan_hash,
                decision=ApprovalDecision.APPROVE,
                approver_slack_id="U2",
                approver_name="bob",
                decided_at=datetime(2026, 1, 1, tzinfo=UTC),
            ),
        )
        result = process_interaction(
            _interaction(user_id="U1", user_name="alice"),
            table=table,
            slack_client=FakeSlackClient(),
            now=datetime(2026, 1, 15, tzinfo=UTC),
        )
        assert result.invoked_worker is True
        assert result.reason == "threshold reached"

    def test_reject_invokes_immediately_regardless_of_threshold(self, table: Any) -> None:
        put_action_plan(table, _plan(required_approvals=2))
        result = process_interaction(
            _interaction(action_id="reject_action"),
            table=table,
            slack_client=FakeSlackClient(),
            now=datetime(2026, 1, 15, tzinfo=UTC),
        )
        assert result.invoked_worker is True
        assert result.approval is not None
        assert result.approval.decision == ApprovalDecision.REJECT

    def test_snooze_invokes_immediately(self, table: Any) -> None:
        put_action_plan(table, _plan(required_approvals=2))
        result = process_interaction(
            _interaction(action_id="snooze_action"),
            table=table,
            slack_client=FakeSlackClient(),
            now=datetime(2026, 1, 15, tzinfo=UTC),
        )
        assert result.invoked_worker is True
        assert result.approval is not None
        assert result.approval.decision == ApprovalDecision.SNOOZE
