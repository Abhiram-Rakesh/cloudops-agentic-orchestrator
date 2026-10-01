"""Terraform PR agent: remediates ``iac_managed`` findings by
drafting a minimal Terraform HCL edit and opening a **draft** PR — it never
merges. Implements ``graph.action_graph.Remediator`` so the action graph
can dispatch to it exactly like any other remediator.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import hcl2
from lark.exceptions import LarkError

from cloudops_orchestrator.graph.action_graph import RemediationOutcome
from cloudops_orchestrator.integrations.github_client import GithubClient
from cloudops_orchestrator.llm.structured import StructuredOutputError, call_structured
from cloudops_orchestrator.models.actions import ActionPlan
from cloudops_orchestrator.models.remediation import HclEdit
from cloudops_orchestrator.remediation.hcl_locator import LocatedResource, locate_resource
from cloudops_orchestrator.remediation.path_guard import is_path_allowed

MAX_DRAFT_ATTEMPTS = 2  # one initial call + one repair attempt
PR_LABELS_BASE = ["cloudops-agent"]

SYSTEM_PROMPT = (
    "You are the CloudOps Terraform remediation agent. You draft a MINIMAL "
    "HCL edit to exactly one resource block that satisfies the given "
    "requirement. You never rewrite unrelated attributes, never touch other "
    "resources, and never invent resource addresses or attribute names not "
    "already present in the block you were given."
)


def _user_prompt(
    *, plan: ActionPlan, located_block: str, file_path: str, previous_error: str | None
) -> str:
    prompt = (
        f"File: {file_path}\n\n"
        f"Current resource block:\n<untrusted_data>\n{located_block}\n</untrusted_data>\n\n"
        f"Required change (from the approved action plan): {plan.action_type.value} with "
        f"parameters {plan.parameters}\n\n"
        "Return an HclEdit: file_path (exactly as given above), original_block (the EXACT "
        "block text above, verbatim), new_block (the minimal fix applied), an explanation, "
        "and risk_notes."
    )
    if previous_error is not None:
        prompt += f"\n\nYour previous attempt was rejected: {previous_error}. Fix this and retry."
    return prompt


@dataclass(frozen=True)
class _DraftResult:
    edit: HclEdit | None
    last_error: str | None


class TerraformPRRemediator:
    def __init__(
        self,
        *,
        github_client: GithubClient,
        model: Any,
        allowed_paths: list[str],
        base_path: str = "demo/infra",
        model_name: str = "terraform-pr-agent",
    ) -> None:
        self._github = github_client
        self._model = model
        self._allowed_paths = allowed_paths
        self._base_path = base_path
        self._model_name = model_name

    def dispatch(self, plan: ActionPlan) -> RemediationOutcome:
        iac_address = plan.parameters.get("resource_address")
        if not iac_address:
            return _manual_ticket("action plan has no resource_address parameter")

        located = locate_resource(self._github, iac_address=iac_address, base_path=self._base_path)
        if located is None:
            return _manual_ticket(
                f"could not locate resource {iac_address!r} under {self._base_path}"
            )
        if not is_path_allowed(located.file_path, allowed_paths=self._allowed_paths):
            return _manual_ticket(
                f"located file {located.file_path!r} is outside the allowed paths"
            )

        base_branch = self._github.get_default_branch()
        full_content, file_sha = self._github.get_file(located.file_path, ref=base_branch)

        draft = self._draft_edit(plan, located, full_content=full_content)
        if draft.edit is None:
            return _manual_ticket(
                f"LLM failed to produce a valid HCL edit after {MAX_DRAFT_ATTEMPTS} attempts: "
                f"{draft.last_error}"
            )

        return self._open_pr(
            plan, draft.edit, base_branch=base_branch, full_content=full_content, file_sha=file_sha
        )

    def _draft_edit(
        self, plan: ActionPlan, located: LocatedResource, *, full_content: str
    ) -> _DraftResult:
        last_error: str | None = None
        for _attempt in range(MAX_DRAFT_ATTEMPTS):
            try:
                edit = call_structured(
                    self._model,
                    schema=HclEdit,
                    system_prompt=SYSTEM_PROMPT,
                    user_prompt=_user_prompt(
                        plan=plan,
                        located_block=located.block,
                        file_path=located.file_path,
                        previous_error=last_error,
                    ),
                    node="hcl_edit",
                    group_id=plan.action_id,
                    model_name=self._model_name,
                )
            except StructuredOutputError as exc:
                last_error = str(exc)
                continue
            error = _validate_edit(
                edit, full_content=full_content, allowed_paths=self._allowed_paths
            )
            if error is None:
                return _DraftResult(edit=edit, last_error=None)
            last_error = error
        return _DraftResult(edit=None, last_error=last_error)

    def _open_pr(
        self,
        plan: ActionPlan,
        edit: HclEdit,
        *,
        base_branch: str,
        full_content: str,
        file_sha: str,
    ) -> RemediationOutcome:
        intent = str(plan.parameters.get("intent", "remediate"))
        branch_name = f"cloudops/{intent}/{plan.action_id[:8]}"
        base_sha = self._github.get_ref_sha(f"heads/{base_branch}")
        self._github.create_branch(branch_name, from_sha=base_sha)

        rewritten = full_content.replace(edit.original_block, edit.new_block, 1)
        self._github.create_or_update_file(
            edit.file_path,
            message=f"cloudops: {edit.explanation}",
            content=rewritten,
            branch=branch_name,
            sha=file_sha,
        )

        pr = self._github.create_pull_request(
            title=f"[CloudOps] {edit.explanation}",
            head=branch_name,
            base=base_branch,
            body=_pr_body(plan=plan, edit=edit),
            draft=True,
        )
        self._github.add_labels(
            pr.number,
            [*PR_LABELS_BASE, f"intent/{intent}", f"tier/{plan.effective_risk_tier.value}"],
        )
        return RemediationOutcome(
            dry_run=False, success=True, detail=pr.html_url, external_ref=pr.html_url
        )


def _validate_edit(edit: HclEdit, *, full_content: str, allowed_paths: list[str]) -> str | None:
    """Returns ``None`` if valid, else a human-readable rejection reason
    ."""
    if not is_path_allowed(edit.file_path, allowed_paths=allowed_paths):
        return f"file_path {edit.file_path!r} is outside the allowed paths"
    occurrences = full_content.count(edit.original_block)
    if occurrences != 1:
        return f"original_block appears {occurrences} time(s) in the file, expected exactly 1"
    rewritten = full_content.replace(edit.original_block, edit.new_block, 1)
    try:
        hcl2.loads(rewritten)
    except LarkError as exc:
        return f"edited file fails to parse as HCL: {exc}"
    return None


def _manual_ticket(reason: str) -> RemediationOutcome:
    return RemediationOutcome(dry_run=False, success=False, detail=f"MANUAL_TICKET: {reason}")


def _pr_body(*, plan: ActionPlan, edit: HclEdit) -> str:
    return (
        "## CloudOps automated remediation\n\n"
        f"**Action ID:** `{plan.action_id}`\n"
        f"**Plan hash:** `{plan.plan_hash}`\n"
        f"**Risk tier:** `{plan.effective_risk_tier.value}`\n\n"
        f"### Explanation\n{edit.explanation}\n\n"
        f"### Risk notes\n{edit.risk_notes}\n\n"
        f"### Diff\n```diff\n-{edit.original_block}\n+{edit.new_block}\n```\n\n"
        "This PR was opened by the CloudOps agent and requires human review before merge — "
        "the agent never merges its own PRs."
    )


__all__ = ["MAX_DRAFT_ATTEMPTS", "PR_LABELS_BASE", "TerraformPRRemediator"]
