from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from moto import mock_aws

from cloudops_orchestrator.checkpoint.factory import get_checkpointer
from cloudops_orchestrator.config import load_settings
from cloudops_orchestrator.graph.action_graph import ActionGraphDeps, NullRemediator
from cloudops_orchestrator.handlers.action_worker import resume_action_thread
from cloudops_orchestrator.models.actions import ActionPlan, Approval
from cloudops_orchestrator.models.enums import ActionType, ApprovalDecision, RiskTier
from cloudops_orchestrator.policy.config import load_risk_tiers
from cloudops_orchestrator.store.actions import acquire_lock, get_action_plan, put_action_plan

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
        yield table, deps, checkpointer


def _start(table: Any, deps: Any, checkpointer: Any, plan: ActionPlan, *, now: datetime) -> None:
    from cloudops_orchestrator.graph.action_graph import build_action_graph

    put_action_plan(table, plan)
    graph = build_action_graph(deps, checkpointer=checkpointer)
    graph.invoke(
        {
            "action_id": plan.action_id,
            "plan": plan,
            "approvers": ["U1"],
            "approvals": [],
            "decision": None,
            "remediation": None,
            "now": now,
        },
        {"configurable": {"thread_id": f"action:{plan.action_id}"}},
    )


class TestResumeActionThread:
    def test_resumes_and_returns_result(self, env: Any) -> None:
        table, deps, checkpointer = env
        now = datetime(2026, 1, 20, tzinfo=UTC)
        _start(table, deps, checkpointer, _plan(), now=now)

        result = resume_action_thread(
            "action-1", _approval(), deps=deps, checkpointer=checkpointer, now=now
        )

        assert result is not None
        assert result["decision"] == "approved"

    def test_lock_held_returns_none(self, env: Any) -> None:
        table, deps, checkpointer = env
        now = datetime(2026, 1, 20, tzinfo=UTC)
        _start(table, deps, checkpointer, _plan(), now=now)
        assert acquire_lock(table, "action-1", now=now)  # pre-hold the lock

        result = resume_action_thread(
            "action-1", _approval(), deps=deps, checkpointer=checkpointer, now=now
        )

        assert result is None

    def test_lock_released_after_resume(self, env: Any) -> None:
        table, deps, checkpointer = env
        now = datetime(2026, 1, 20, tzinfo=UTC)
        _start(table, deps, checkpointer, _plan(), now=now)

        resume_action_thread("action-1", _approval(), deps=deps, checkpointer=checkpointer, now=now)

        assert acquire_lock(table, "action-1", now=now)  # lock is free again

    def test_updates_action_status_on_disk(self, env: Any) -> None:
        table, deps, checkpointer = env
        now = datetime(2026, 1, 20, tzinfo=UTC)
        _start(table, deps, checkpointer, _plan(), now=now)

        resume_action_thread("action-1", _approval(), deps=deps, checkpointer=checkpointer, now=now)

        found = get_action_plan(table, "action-1")
        assert found is not None
        _plan_obj, status = found
        assert status == "EXECUTED"
