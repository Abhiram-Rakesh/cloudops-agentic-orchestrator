from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from cloudops_orchestrator.models.actions import ActionPlan
from cloudops_orchestrator.models.enums import ActionType, RiskTier
from cloudops_orchestrator.remediation.revert_dispatch import RevertDispatchRemediator


class FakeGithubClient:
    def __init__(self) -> None:
        self.dispatched: list[dict[str, Any]] = []

    def dispatch_workflow(
        self, workflow_file: str, *, ref: str, inputs: dict[str, str] | None = None
    ) -> None:
        self.dispatched.append({"workflow_file": workflow_file, "ref": ref, "inputs": inputs})


def _plan(**overrides: object) -> ActionPlan:
    defaults: dict[str, object] = {
        "action_id": "action-1",
        "recommendation_id": "rec-1",
        "action_type": ActionType.TERRAFORM_REVERT_DISPATCH,
        "parameters": {"reason": "drift detected on aws_security_group.web"},
        "targets": ["sg-1"],
        "effective_risk_tier": RiskTier.T1,
        "required_approvals": 1,
        "expires_at": datetime(2026, 2, 1, tzinfo=UTC),
        "plan_hash": "a" * 64,
    }
    defaults.update(overrides)
    return ActionPlan(**defaults)  # type: ignore[arg-type]


def test_dispatches_workflow_with_action_context() -> None:
    github: Any = FakeGithubClient()
    remediator = RevertDispatchRemediator(
        github_client=github, workflow_file="demo-apply.yml", ref="main"
    )

    outcome = remediator.dispatch(_plan())

    assert outcome.success is True
    assert outcome.dry_run is False
    assert outcome.external_ref == "demo-apply.yml"
    assert len(github.dispatched) == 1
    call = github.dispatched[0]
    assert call["workflow_file"] == "demo-apply.yml"
    assert call["ref"] == "main"
    assert call["inputs"] == {
        "action_id": "action-1",
        "plan_hash": "a" * 64,
        "reason": "drift detected on aws_security_group.web",
    }


def test_default_reason_when_not_provided() -> None:
    github: Any = FakeGithubClient()
    remediator = RevertDispatchRemediator(github_client=github, workflow_file="demo-apply.yml")

    remediator.dispatch(_plan(parameters={}))

    assert github.dispatched[0]["inputs"]["reason"] == "cloudops revert"
