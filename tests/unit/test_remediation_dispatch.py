from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cloudops_orchestrator.config import load_settings
from cloudops_orchestrator.graph.action_graph import NullRemediator
from cloudops_orchestrator.models.actions import ActionPlan
from cloudops_orchestrator.models.enums import ActionType, RiskTier
from cloudops_orchestrator.policy.config import load_action_allowlist, load_protected_resources
from cloudops_orchestrator.remediation.dispatch import remediator_for
from cloudops_orchestrator.remediation.revert_dispatch import RevertDispatchRemediator
from cloudops_orchestrator.remediation.runbook_executor import RunbookExecutor
from cloudops_orchestrator.remediation.terraform_pr import TerraformPRRemediator

REPO_ROOT = Path(__file__).resolve().parents[2]


def _plan(action_type: ActionType, **overrides: object) -> ActionPlan:
    defaults: dict[str, object] = {
        "action_id": "action-1",
        "recommendation_id": "rec-1",
        "action_type": action_type,
        "parameters": {},
        "targets": ["fp-1"],
        "effective_risk_tier": RiskTier.T1,
        "required_approvals": 1,
        "expires_at": datetime(2026, 2, 1, tzinfo=UTC),
        "plan_hash": "a" * 64,
    }
    defaults.update(overrides)
    return ActionPlan(**defaults)  # type: ignore[arg-type]


def _kwargs() -> dict[str, Any]:
    settings = load_settings(REPO_ROOT / "config" / "settings.local.yaml", env={})
    return {
        "settings": settings,
        "github_client": object(),
        "llm_model": object(),
        "ssm_client": object(),
        "table": object(),
        "protected_resources": load_protected_resources(),
        "action_allowlist": load_action_allowlist(),
        "automation_assume_role_arn": "arn:aws:iam::111111111111:role/cloudops-lite-automation",
    }


def test_terraform_pr_action_type_gets_terraform_pr_remediator() -> None:
    remediator = remediator_for(_plan(ActionType.TERRAFORM_PR), **_kwargs())
    assert isinstance(remediator, TerraformPRRemediator)


def test_terraform_pr_disabled_gets_null_remediator() -> None:
    kwargs = _kwargs()
    kwargs["settings"] = kwargs["settings"].model_copy(
        update={
            "remediation": kwargs["settings"].remediation.model_copy(
                update={
                    "terraform_pr": kwargs["settings"].remediation.terraform_pr.model_copy(
                        update={"enabled": False}
                    )
                }
            )
        }
    )
    remediator = remediator_for(_plan(ActionType.TERRAFORM_PR), **kwargs)
    assert isinstance(remediator, NullRemediator)


def test_terraform_revert_dispatch_action_type_gets_revert_remediator() -> None:
    remediator = remediator_for(_plan(ActionType.TERRAFORM_REVERT_DISPATCH), **_kwargs())
    assert isinstance(remediator, RevertDispatchRemediator)


def test_ssm_automation_action_type_gets_runbook_executor() -> None:
    remediator = remediator_for(_plan(ActionType.SSM_AUTOMATION), **_kwargs())
    assert isinstance(remediator, RunbookExecutor)


def test_manual_ticket_action_type_gets_null_remediator() -> None:
    remediator = remediator_for(_plan(ActionType.MANUAL_TICKET), **_kwargs())
    assert isinstance(remediator, NullRemediator)


def test_notify_owner_action_type_gets_null_remediator() -> None:
    remediator = remediator_for(_plan(ActionType.NOTIFY_OWNER), **_kwargs())
    assert isinstance(remediator, NullRemediator)
