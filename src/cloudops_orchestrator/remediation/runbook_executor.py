"""Runbook executor: starts one of the ``CloudOps-*`` SSM Automation
documents (``ssm_documents/``). **Built, but disabled and dry-run by
default** (``remediation.runbook_executor.enabled``/``dry_run``) — the demo
never actually calls ``ssm:StartAutomationExecution`` unless a human
flips both. Implements ``graph.action_graph.Remediator``.

Fans out one ``StartAutomationExecution`` call per target (``plan.targets``),
sourcing each target's identifying parameter (which resource to act on --
e.g. ``SecurityGroupId``) from that target's own stored ``Finding.resource_id``
rather than the model: a single ``ActionPlan`` can cover several targets
sharing one remediation, but every SSM document here only ever takes one
resource per execution, and there's no way for the model to express "a
different real value per target" in ``ActionPlan.parameters``' one flat
dict (see ``config/policy/action_allowlist.yaml``'s ``identifying_parameter``
doc comment; found live 2026-09-29, see README.md (Troubleshooting)).

Defense in depth against remediating a protected resource: each SSM
document's own first step aborts on ``cloudops:protected=true``, but this
executor also checks the *stored* finding's tags before ever calling SSM,
so a stale/incorrect document can't accidentally touch one -- all-or-nothing
across every target, not just the protected one(s).
"""

from __future__ import annotations

from typing import Any

from cloudops_orchestrator.graph.action_graph import RemediationOutcome
from cloudops_orchestrator.models.actions import ActionPlan
from cloudops_orchestrator.models.findings import Finding
from cloudops_orchestrator.policy.config import ActionAllowlistConfig, ProtectedResourcesConfig
from cloudops_orchestrator.policy.engine import is_protected
from cloudops_orchestrator.store.audit import record_audit_event
from cloudops_orchestrator.store.findings import get_finding


def _bare_resource_id(value: str) -> str:
    """Security Hub (ASFF) always reports ``Finding.resource_id`` as a full
    ARN (e.g. ``arn:aws:ec2:ap-south-1:acct:security-group/sg-0123``); every
    ``CloudOps-*`` document's identifying parameter wants the bare id
    instead (``sg-0123``). S3 bucket ARNs (``arn:aws:s3:::name``) have no
    further ``/``-separated type segment, so the bucket name *is* the bare
    id already -- both are handled by taking whatever follows the ARN's
    final ``/``, or the whole resource part if there is none. Found live: a
    real (non-fixture) Security Hub finding's ARN was passed straight
    through as ``SecurityGroupId``, which EC2 APIs don't accept (see
    README.md (Troubleshooting)). Not an ARN at all (some collectors
    already store a bare id) -- returned unchanged."""
    if not value.startswith("arn:"):
        return value
    resource = value.split(":", 5)[-1]
    return resource.rsplit("/", 1)[-1]


def _to_pascal_case(snake: str) -> str:
    """SSM documents use PascalCase parameter names (``SecurityGroupId``);
    ``action_allowlist.yaml`` and every ``Recommendation``/``ActionPlan``
    use snake_case (``security_group_id``) -- a clean 1:1 convention
    verified across all 7 ``ssm_documents/*.yaml``. Nothing converted this
    before now, which would have made any real ``StartAutomationExecution``
    call fail outright."""
    return "".join(word.capitalize() for word in snake.split("_"))


def _automation_parameters(parameters: dict[str, Any]) -> dict[str, list[str]]:
    """SSM ``StartAutomationExecution`` wants every parameter value as a
    list of strings, keyed by its PascalCase name -- ``document`` itself
    isn't an automation parameter."""
    result: dict[str, list[str]] = {}
    for key, value in parameters.items():
        if key == "document":
            continue
        values = value if isinstance(value, list) else [value]
        result[_to_pascal_case(key)] = [str(v) for v in values]
    return result


class RunbookExecutor:
    def __init__(
        self,
        *,
        enabled: bool,
        dry_run: bool,
        ssm_client: Any,
        table: Any,
        protected_resources: ProtectedResourcesConfig,
        action_allowlist: ActionAllowlistConfig,
        automation_assume_role_arn: str,
    ) -> None:
        self._enabled = enabled
        self._dry_run = dry_run
        self._ssm = ssm_client
        self._table = table
        self._protected_resources = protected_resources
        self._action_allowlist = action_allowlist
        self._automation_assume_role_arn = automation_assume_role_arn

    def dispatch(self, plan: ActionPlan) -> RemediationOutcome:
        if not self._enabled:
            return RemediationOutcome(
                dry_run=True, success=False, detail="runbook_executor is disabled"
            )

        document = plan.parameters.get("document")
        if not document:
            return RemediationOutcome(
                dry_run=True, success=False, detail="action plan has no 'document' parameter"
            )

        doc_spec = self._action_allowlist.ssm_automation.get(document)
        if doc_spec is None:
            return RemediationOutcome(
                dry_run=True, success=False, detail=f"{document!r} is not in the allowlist"
            )

        targets: list[Finding] = []
        for fingerprint in plan.targets:
            finding = get_finding(self._table, fingerprint)
            if finding is None:
                return RemediationOutcome(
                    dry_run=True,
                    success=False,
                    detail=(
                        f"target {fingerprint!r} has no stored finding -- "
                        f"refusing to dispatch {document}"
                    ),
                )
            targets.append(finding)

        protected = [f for f in targets if is_protected(f, self._protected_resources)]
        if protected:
            record_audit_event(
                self._table,
                entity=f"ACTION#{plan.action_id}",
                event="runbook_executor_refused_protected",
                details={"targets": [f.resource_id for f in protected]},
            )
            return RemediationOutcome(
                dry_run=True,
                success=False,
                detail=(
                    f"target(s) {[f.resource_id for f in protected]} are protected -- "
                    f"refusing to dispatch {document}"
                ),
            )

        shared_parameters = _automation_parameters(plan.parameters)
        identifying_key = _to_pascal_case(doc_spec.identifying_parameter)

        results: list[str] = []
        execution_ids: list[str] = []
        all_succeeded = True
        for finding in targets:
            bare_id = _bare_resource_id(finding.resource_id)
            automation_parameters = {
                **shared_parameters,
                identifying_key: [bare_id],
                "AutomationAssumeRole": [self._automation_assume_role_arn],
            }
            if self._dry_run:
                results.append(
                    f"{bare_id}: DRY RUN, would StartAutomationExecution "
                    f"{document!r} with parameters {automation_parameters}"
                )
                continue
            try:
                response = self._ssm.start_automation_execution(
                    DocumentName=document,
                    Parameters=automation_parameters,
                    Tags=[
                        {"Key": "action_id", "Value": plan.action_id},
                        {"Key": "cloudops:managed", "Value": "true"},
                    ],
                )
            except Exception as exc:  # a single target's failure mustn't abort the rest
                all_succeeded = False
                results.append(f"{bare_id}: FAILED, {exc}")
                continue
            execution_id: str = response["AutomationExecutionId"]
            execution_ids.append(execution_id)
            results.append(f"{bare_id}: started (execution {execution_id})")

        return RemediationOutcome(
            dry_run=self._dry_run,
            success=all_succeeded,
            detail="; ".join(results),
            external_ref=",".join(execution_ids) if execution_ids else None,
        )


__all__ = ["RunbookExecutor"]
