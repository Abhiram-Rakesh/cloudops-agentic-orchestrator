"""Tests for graph/action_graph.py: interrupt/resume, multi-approver loop,
rejection, snooze, expiry, and the kill switch — moto-backed throughout."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from langgraph.types import Command
from moto import mock_aws

from cloudops_orchestrator.checkpoint.factory import get_checkpointer
from cloudops_orchestrator.config import load_settings
from cloudops_orchestrator.graph.action_graph import (
    ActionGraphDeps,
    NullRemediator,
    RemediationOutcome,
    build_action_graph,
    check_kill_switch,
    count_distinct_approvals,
    has_decision,
    validate_approval,
)
from cloudops_orchestrator.models.actions import ActionPlan, Approval
from cloudops_orchestrator.models.enums import ActionType, ApprovalDecision, RiskTier
from cloudops_orchestrator.policy.config import load_risk_tiers
from cloudops_orchestrator.store.actions import ActionStatus, get_action_plan, put_action_plan

REPO_ROOT = Path(__file__).resolve().parents[2]
TABLE_NAME = "cloudops-lite-state-test"


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


@pytest.fixture
def env(tmp_path: Path) -> Any:
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
        table = resource.Table(TABLE_NAME)

        settings = load_settings(REPO_ROOT / "config" / "settings.local.yaml", env={})
        settings = settings.model_copy(
            update={"checkpoint": settings.checkpoint.model_copy(update={"backend": "sqlite"})}
        )
        checkpointer = get_checkpointer(settings, sqlite_path=tmp_path / "cp.sqlite")
        deps = ActionGraphDeps(
            settings=settings,
            risk_tiers=load_risk_tiers(),
            remediator=NullRemediator(),
            table=table,
        )
        graph = build_action_graph(deps, checkpointer=checkpointer)
        yield graph, table, deps


def _start(
    graph: Any, plan: ActionPlan, *, approvers: list[str], now: datetime, table: Any
) -> tuple[dict[str, Any], dict[str, Any]]:
    put_action_plan(table, plan)
    config = {"configurable": {"thread_id": f"action:{plan.action_id}"}}
    result = graph.invoke(
        {
            "action_id": plan.action_id,
            "plan": plan,
            "approvers": approvers,
            "approvals": [],
            "decision": None,
            "remediation": None,
            "now": now,
        },
        config,
    )
    return result, config


class TestValidateApproval:
    def test_valid_approval_passes(self) -> None:
        error = validate_approval(
            approval=_approval(),
            plan=_plan(),
            approvers=["U1"],
            existing_approvals=[],
            now=datetime(2026, 1, 20, tzinfo=UTC),
        )
        assert error is None

    def test_unauthorized_approver_rejected(self) -> None:
        error = validate_approval(
            approval=_approval(approver_slack_id="U999"),
            plan=_plan(),
            approvers=["U1"],
            existing_approvals=[],
            now=datetime(2026, 1, 20, tzinfo=UTC),
        )
        assert error is not None and "not an authorized approver" in error

    def test_wrong_plan_hash_rejected(self) -> None:
        error = validate_approval(
            approval=_approval(plan_hash="b" * 64),
            plan=_plan(),
            approvers=["U1"],
            existing_approvals=[],
            now=datetime(2026, 1, 20, tzinfo=UTC),
        )
        assert error is not None and "plan_hash" in error

    def test_expired_plan_rejected(self) -> None:
        error = validate_approval(
            approval=_approval(),
            plan=_plan(expires_at=datetime(2026, 1, 1, tzinfo=UTC)),
            approvers=["U1"],
            existing_approvals=[],
            now=datetime(2026, 1, 20, tzinfo=UTC),
        )
        assert error is not None and "expired" in error

    def test_duplicate_approver_rejected(self) -> None:
        existing = [_approval()]
        error = validate_approval(
            approval=_approval(),
            plan=_plan(),
            approvers=["U1"],
            existing_approvals=existing,
            now=datetime(2026, 1, 20, tzinfo=UTC),
        )
        assert error is not None and "already approved" in error

    def test_reject_decision_not_subject_to_duplicate_check(self) -> None:
        existing = [_approval(decision=ApprovalDecision.APPROVE)]
        error = validate_approval(
            approval=_approval(decision=ApprovalDecision.REJECT),
            plan=_plan(),
            approvers=["U1"],
            existing_approvals=existing,
            now=datetime(2026, 1, 20, tzinfo=UTC),
        )
        assert error is None


class TestCountingHelpers:
    def test_count_distinct_approvals(self) -> None:
        approvals = [
            _approval(approver_slack_id="U1"),
            _approval(approver_slack_id="U2", approver_name="Bob"),
        ]
        assert count_distinct_approvals(approvals) == 2

    def test_reject_not_counted_as_approval(self) -> None:
        approvals = [_approval(decision=ApprovalDecision.REJECT)]
        assert count_distinct_approvals(approvals) == 0

    def test_has_decision(self) -> None:
        approvals = [_approval(decision=ApprovalDecision.SNOOZE)]
        assert has_decision(approvals, ApprovalDecision.SNOOZE) is True
        assert has_decision(approvals, ApprovalDecision.REJECT) is False


class TestSingleApprovalFlow:
    def test_t1_single_approval_executes(self, env: Any) -> None:
        graph, table, _deps = env
        now = datetime(2026, 1, 20, tzinfo=UTC)  # Tuesday
        result, config = _start(graph, _plan(), approvers=["U1"], now=now, table=table)
        assert "__interrupt__" in result

        result2 = graph.invoke(Command(resume=_approval().model_dump(mode="json")), config)
        assert result2["decision"] == "approved"
        assert result2["remediation"]["success"] is True

        _, status = get_action_plan(table, "action-1")  # type: ignore[misc]
        assert status == ActionStatus.EXECUTED

    def test_invalid_approval_does_not_advance(self, env: Any) -> None:
        graph, table, _deps = env
        now = datetime(2026, 1, 20, tzinfo=UTC)
        _result, config = _start(graph, _plan(), approvers=["U1"], now=now, table=table)

        bad_approval = _approval(approver_slack_id="U999")
        result = graph.invoke(Command(resume=bad_approval.model_dump(mode="json")), config)
        assert "__interrupt__" in result  # still waiting

        good_result = graph.invoke(Command(resume=_approval().model_dump(mode="json")), config)
        assert good_result["decision"] == "approved"


class TestMultiApproverFlow:
    def test_t2_requires_two_distinct_approvers(self, env: Any) -> None:
        graph, table, _deps = env
        now = datetime(
            2026, 1, 20, 11, 0, tzinfo=UTC
        )  # Tue 11:00 UTC = within window in IST too? adjust below
        plan = _plan(effective_risk_tier=RiskTier.T2, required_approvals=2)
        _result, config = _start(graph, plan, approvers=["U1", "U2"], now=now, table=table)

        after_first = graph.invoke(
            Command(resume=_approval(approver_slack_id="U1").model_dump(mode="json")), config
        )
        assert "__interrupt__" in after_first  # still needs a second approver

        after_second = graph.invoke(
            Command(
                resume=_approval(approver_slack_id="U2", approver_name="Bob").model_dump(
                    mode="json"
                )
            ),
            config,
        )
        assert after_second["decision"] == "approved"

    def test_same_approver_twice_does_not_satisfy_t2(self, env: Any) -> None:
        graph, table, _deps = env
        now = datetime(2026, 1, 20, 11, 0, tzinfo=UTC)
        plan = _plan(effective_risk_tier=RiskTier.T2, required_approvals=2)
        _result, config = _start(graph, plan, approvers=["U1", "U2"], now=now, table=table)

        graph.invoke(
            Command(resume=_approval(approver_slack_id="U1").model_dump(mode="json")), config
        )
        still_waiting = graph.invoke(
            Command(resume=_approval(approver_slack_id="U1").model_dump(mode="json")), config
        )
        assert "__interrupt__" in still_waiting


class TestRejectAndSnooze:
    def test_reject_ends_thread(self, env: Any) -> None:
        graph, table, _deps = env
        now = datetime(2026, 1, 20, tzinfo=UTC)
        _result, config = _start(graph, _plan(), approvers=["U1"], now=now, table=table)

        result = graph.invoke(
            Command(resume=_approval(decision=ApprovalDecision.REJECT).model_dump(mode="json")),
            config,
        )
        assert result["decision"] == "rejected"
        _, status = get_action_plan(table, "action-1")  # type: ignore[misc]
        assert status == ActionStatus.REJECTED

    def test_snooze_creates_exception_path(self, env: Any) -> None:
        graph, table, _deps = env
        now = datetime(2026, 1, 20, tzinfo=UTC)
        _result, config = _start(graph, _plan(), approvers=["U1"], now=now, table=table)

        result = graph.invoke(
            Command(resume=_approval(decision=ApprovalDecision.SNOOZE).model_dump(mode="json")),
            config,
        )
        assert result["decision"] == "snoozed"
        _, status = get_action_plan(table, "action-1")  # type: ignore[misc]
        assert status == ActionStatus.SNOOZED


class TestChangeWindow:
    def test_t2_outside_window_is_queued_not_remediated(self, env: Any) -> None:
        graph, table, _deps = env
        # Saturday — never in the MON-THU window regardless of time.
        now = datetime(2026, 1, 24, 12, 0, tzinfo=UTC)
        plan = _plan(effective_risk_tier=RiskTier.T2, required_approvals=1)
        _result, config = _start(graph, plan, approvers=["U1"], now=now, table=table)

        result = graph.invoke(Command(resume=_approval().model_dump(mode="json")), config)
        assert result["decision"] == "queued_outside_window"
        assert result.get("remediation") is None


class TestKillSwitch:
    def test_kill_switch_off_by_default(self, env: Any) -> None:
        _graph, _table, deps = env
        assert check_kill_switch(settings=deps["settings"]) is False

    def test_kill_switch_on_refuses_remediation(self, env: Any, tmp_path: Path) -> None:
        # ``env``'s settings have environment: local (settings.local.yaml), so
        # check_kill_switch reads the local sentinel file, never live SSM —
        # see check_kill_switch's docstring for why local/CI never calls AWS.
        graph, table, _deps = env
        import cloudops_orchestrator.graph.action_graph as action_graph_module

        sentinel = tmp_path / "kill_switch"
        sentinel.write_text("on", encoding="utf-8")
        original_path = action_graph_module._LOCAL_KILL_SWITCH_PATH
        action_graph_module._LOCAL_KILL_SWITCH_PATH = sentinel
        try:
            now = datetime(2026, 1, 20, tzinfo=UTC)
            _result, config = _start(graph, _plan(), approvers=["U1"], now=now, table=table)
            result = graph.invoke(Command(resume=_approval().model_dump(mode="json")), config)
        finally:
            action_graph_module._LOCAL_KILL_SWITCH_PATH = original_path
        assert result["decision"] == "refused_kill_switch"
        assert result["remediation"]["success"] is False

    def test_kill_switch_local_mode_never_calls_ssm(self, tmp_path: Path) -> None:
        """environment: local must never touch live SSM, on or off."""
        settings = load_settings(REPO_ROOT / "config" / "settings.local.yaml", env={})
        assert settings.environment == "local"

        import cloudops_orchestrator.graph.action_graph as action_graph_module

        sentinel = tmp_path / "kill_switch"
        original_path = action_graph_module._LOCAL_KILL_SWITCH_PATH
        action_graph_module._LOCAL_KILL_SWITCH_PATH = sentinel
        try:
            assert check_kill_switch(settings=settings) is False  # no sentinel file yet
            sentinel.write_text("ON\n", encoding="utf-8")
            assert check_kill_switch(settings=settings) is True
            sentinel.write_text("off", encoding="utf-8")
            assert check_kill_switch(settings=settings) is False
        finally:
            action_graph_module._LOCAL_KILL_SWITCH_PATH = original_path

    def test_kill_switch_live_mode_reads_ssm(self) -> None:
        with mock_aws():
            settings = load_settings(REPO_ROOT / "config" / "settings.local.yaml", env={})
            settings = settings.model_copy(update={"environment": "dev"})

            assert check_kill_switch(settings=settings) is False  # parameter absent

            from cloudops_orchestrator.aws.clients import get_ssm_client

            client = get_ssm_client(region_name=settings.aws.region)
            client.put_parameter(
                Name=f"{settings.storage.parameter_prefix}/kill_switch",
                Value="on",
                Type="String",
                Overwrite=True,
            )
            assert check_kill_switch(settings=settings) is True


def test_null_remediator_reports_dry_run() -> None:
    outcome = NullRemediator().dispatch(_plan())
    assert isinstance(outcome, RemediationOutcome)
    assert outcome.dry_run is True
