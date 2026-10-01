"""Revert dispatch: re-assert last-known-good IaC state by
``workflow_dispatch``-ing the demo stack's apply pipeline. Implements
``graph.action_graph.Remediator`` — the actual revert happens in
``demo-apply.yml`` once a human reviews the dispatched run; this module
only ever triggers it and records what was dispatched.
"""

from __future__ import annotations

from cloudops_orchestrator.graph.action_graph import RemediationOutcome
from cloudops_orchestrator.integrations.github_client import GithubClient
from cloudops_orchestrator.models.actions import ActionPlan


class RevertDispatchRemediator:
    def __init__(
        self, *, github_client: GithubClient, workflow_file: str, ref: str = "main"
    ) -> None:
        self._github = github_client
        self._workflow_file = workflow_file
        self._ref = ref

    def dispatch(self, plan: ActionPlan) -> RemediationOutcome:
        reason = str(plan.parameters.get("reason", "cloudops revert"))
        inputs = {"action_id": plan.action_id, "plan_hash": plan.plan_hash, "reason": reason}
        self._github.dispatch_workflow(self._workflow_file, ref=self._ref, inputs=inputs)
        return RemediationOutcome(
            dry_run=False,
            success=True,
            detail=f"dispatched {self._workflow_file} on {self._ref} with inputs {inputs}",
            external_ref=self._workflow_file,
        )


__all__ = ["RevertDispatchRemediator"]
