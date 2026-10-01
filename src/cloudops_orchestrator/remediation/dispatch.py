"""Remediator selection: which concrete ``Remediator`` handles a
given ``ActionPlan``, by its ``action_type``. Used by ``action_worker``'s
real ``lambda_handler`` — local CLI/test runs keep using ``NullRemediator``
directly, since there's no live GitHub/AWS credential available there.
"""

from __future__ import annotations

from typing import Any

from cloudops_orchestrator.config import Settings
from cloudops_orchestrator.graph.action_graph import NullRemediator, Remediator
from cloudops_orchestrator.integrations.github_client import GithubClient
from cloudops_orchestrator.models.actions import ActionPlan
from cloudops_orchestrator.models.enums import ActionType
from cloudops_orchestrator.policy.config import ActionAllowlistConfig, ProtectedResourcesConfig
from cloudops_orchestrator.remediation.revert_dispatch import RevertDispatchRemediator
from cloudops_orchestrator.remediation.runbook_executor import RunbookExecutor
from cloudops_orchestrator.remediation.terraform_pr import TerraformPRRemediator


def remediator_for(
    plan: ActionPlan,
    *,
    settings: Settings,
    github_client: GithubClient,
    llm_model: Any,
    ssm_client: Any,
    table: Any,
    protected_resources: ProtectedResourcesConfig,
    action_allowlist: ActionAllowlistConfig,
    automation_assume_role_arn: str,
) -> Remediator:
    if plan.action_type == ActionType.TERRAFORM_PR:
        if not settings.remediation.terraform_pr.enabled:
            return NullRemediator()
        return TerraformPRRemediator(
            github_client=github_client,
            model=llm_model,
            allowed_paths=settings.remediation.terraform_pr.allowed_paths,
        )
    if plan.action_type == ActionType.TERRAFORM_REVERT_DISPATCH:
        if not settings.remediation.terraform_revert_dispatch.enabled:
            return NullRemediator()
        return RevertDispatchRemediator(
            github_client=github_client,
            workflow_file=settings.remediation.terraform_revert_dispatch.workflow_file,
        )
    if plan.action_type == ActionType.SSM_AUTOMATION:
        return RunbookExecutor(
            enabled=settings.remediation.runbook_executor.enabled,
            dry_run=settings.remediation.runbook_executor.dry_run,
            ssm_client=ssm_client,
            table=table,
            protected_resources=protected_resources,
            action_allowlist=action_allowlist,
            automation_assume_role_arn=automation_assume_role_arn,
        )
    return NullRemediator()  # MANUAL_TICKET / NOTIFY_OWNER never reach a remediator anyway


__all__ = ["remediator_for"]
