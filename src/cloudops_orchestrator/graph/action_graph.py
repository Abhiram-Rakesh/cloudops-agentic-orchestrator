"""Action (approval) graph — thread ``action:{action_id}``.

::

    START -> await_approval (loops on itself) -> policy_recheck -> remediate -> verify -> record -> END
                  REJECT -> record_rejected -> END       SNOOZE -> create_exception -> END

Checkpointed (unlike the domain agent graph): this thread can pause for
days waiting on a second Slack approval. ``await_approval`` calls
``interrupt()`` and re-runs from the top on every resume — see
``checkpoint/factory.py`` for the DynamoDB/sqlite/memory backends and
README.md (Troubleshooting) for what's confirmed against the installed
LangGraph 1.2.12 wheel versus what still needs a live check.
"""

from __future__ import annotations

import operator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Protocol, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from cloudops_orchestrator.config import Settings
from cloudops_orchestrator.logging import get_logger
from cloudops_orchestrator.models.actions import ActionPlan, Approval
from cloudops_orchestrator.models.enums import ApprovalDecision, RiskTier
from cloudops_orchestrator.policy.change_window import is_within_change_window
from cloudops_orchestrator.policy.config import RiskTiersConfig
from cloudops_orchestrator.store.actions import ActionStatus, set_action_status
from cloudops_orchestrator.store.audit import record_audit_event

logger = get_logger()


def validate_approval(
    *,
    approval: Approval,
    plan: ActionPlan,
    approvers: list[str],
    existing_approvals: list[Approval],
    now: datetime,
) -> str | None:
    """Return ``None`` if the approval is valid, else a rejection reason.

    A rejected/invalid *attempt* (wrong approver, stale hash, expired plan,
    duplicate approver) is simply dropped — the thread keeps waiting rather
    than erroring out, since it may just be a stray or malicious request.
    """
    if approval.approver_slack_id not in approvers:
        return f"{approval.approver_slack_id} is not an authorized approver"
    if approval.plan_hash != plan.plan_hash:
        return "plan_hash does not match the stored plan (stale or tampered approval)"
    if now > plan.expires_at:
        return "action plan has expired"
    if approval.decision == ApprovalDecision.APPROVE and any(
        a.approver_slack_id == approval.approver_slack_id and a.decision == ApprovalDecision.APPROVE
        for a in existing_approvals
    ):
        return f"{approval.approver_slack_id} has already approved this action"
    return None


def count_distinct_approvals(approvals: list[Approval]) -> int:
    return len({a.approver_slack_id for a in approvals if a.decision == ApprovalDecision.APPROVE})


def has_decision(approvals: list[Approval], decision: ApprovalDecision) -> bool:
    return any(a.decision == decision for a in approvals)


@dataclass(frozen=True)
class RemediationOutcome:
    dry_run: bool
    detail: str
    success: bool = True
    external_ref: str | None = None


class Remediator(Protocol):
    def dispatch(self, plan: ActionPlan) -> RemediationOutcome: ...


class NullRemediator:
    """Default remediator: never actually calls GitHub/SSM.

    Real ``terraform_pr``/``terraform_revert_dispatch``/``runbook_executor``
    dispatch lives in ``remediation/`` and is injected via
    ``ActionGraphDeps["remediator"]`` — this keeps the graph itself complete
    and testable without depending on that code.
    """

    def dispatch(self, plan: ActionPlan) -> RemediationOutcome:
        return RemediationOutcome(
            dry_run=True,
            detail=f"NullRemediator: would dispatch {plan.action_type.value} with parameters {plan.parameters}",
        )


_LOCAL_KILL_SWITCH_PATH = Path(".cache/kill_switch")


def check_kill_switch(*, settings: Settings) -> bool:
    """``on`` refuses remediation. Live mode reads the real SSM parameter;
    ``environment: local`` reads a local sentinel file instead (no live AWS
    call from local/CI)."""
    if settings.environment == "local":
        if not _LOCAL_KILL_SWITCH_PATH.exists():
            return False
        return _LOCAL_KILL_SWITCH_PATH.read_text(encoding="utf-8").strip().lower() == "on"

    from cloudops_orchestrator.aws.clients import get_ssm_client

    client = get_ssm_client(region_name=settings.aws.region)
    parameter_name = f"{settings.storage.parameter_prefix}/kill_switch"
    try:
        response = client.get_parameter(Name=parameter_name)
    except client.exceptions.ParameterNotFound:
        return False
    value: str = response["Parameter"]["Value"]
    return value.strip().lower() == "on"


class ActionGraphDeps(TypedDict):
    settings: Settings
    risk_tiers: RiskTiersConfig
    remediator: Remediator
    table: Any


class ActionGraphState(TypedDict):
    action_id: str
    plan: ActionPlan
    approvers: list[str]
    approvals: Annotated[list[Approval], operator.add]
    decision: str | None
    remediation: dict[str, Any] | None
    now: datetime


def _await_approval(state: ActionGraphState) -> dict[str, Any]:
    plan = state["plan"]
    approvals = state["approvals"]

    if count_distinct_approvals(approvals) >= plan.required_approvals:
        return {"decision": "approved"}
    if has_decision(approvals, ApprovalDecision.REJECT):
        return {"decision": "rejected"}
    if has_decision(approvals, ApprovalDecision.SNOOZE):
        return {"decision": "snoozed"}

    payload = interrupt(
        {
            "action_id": state["action_id"],
            "plan_hash": plan.plan_hash,
            "required_approvals": plan.required_approvals,
        }
    )
    candidate = Approval.model_validate(payload)
    error = validate_approval(
        approval=candidate,
        plan=plan,
        approvers=state["approvers"],
        existing_approvals=approvals,
        now=state["now"],
    )
    if error is not None:
        logger.warning("action_graph.approval_rejected", action_id=state["action_id"], reason=error)
        return {}
    return {"approvals": [candidate]}


def _route_after_await(state: ActionGraphState) -> str:
    decision = state.get("decision")
    if decision is None:
        return "await_approval"
    return {
        "approved": "policy_recheck",
        "rejected": "record_rejected",
        "snoozed": "create_exception",
    }[decision]


def _policy_recheck(state: ActionGraphState, *, deps: ActionGraphDeps) -> dict[str, Any]:
    plan = state["plan"]
    if plan.effective_risk_tier == RiskTier.T2:
        change_window = deps["risk_tiers"].tiers["T2"].change_window
        if change_window is not None and not is_within_change_window(
            state["now"], change_window=change_window
        ):
            return {"decision": "queued_outside_window"}
    return {}


def _route_after_policy_recheck(state: ActionGraphState) -> str:
    return "record" if state.get("decision") == "queued_outside_window" else "remediate"


def _remediate(state: ActionGraphState, *, deps: ActionGraphDeps) -> dict[str, Any]:
    if check_kill_switch(settings=deps["settings"]):
        return {
            "decision": "refused_kill_switch",
            "remediation": {"success": False, "detail": "kill switch is on"},
        }
    outcome = deps["remediator"].dispatch(state["plan"])
    return {
        "remediation": {
            "dry_run": outcome.dry_run,
            "detail": outcome.detail,
            "success": outcome.success,
            "external_ref": outcome.external_ref,
        }
    }


def _verify(state: ActionGraphState) -> dict[str, Any]:
    # Real verification (poll SSM execution / PR status) is not implemented;
    # the remediation outcome is the final word.
    return {}


def _record(state: ActionGraphState, *, deps: ActionGraphDeps) -> dict[str, Any]:
    status = (
        ActionStatus.EXECUTED
        if (state.get("remediation") or {}).get("success", True)
        else ActionStatus.EXPIRED
    )
    set_action_status(deps["table"], state["action_id"], status)
    record_audit_event(
        deps["table"],
        entity=f"ACTION#{state['action_id']}",
        event="remediation_recorded",
        details=state.get("remediation") or {},
        at=state["now"],
    )
    return {}


def _record_rejected(state: ActionGraphState, *, deps: ActionGraphDeps) -> dict[str, Any]:
    set_action_status(deps["table"], state["action_id"], ActionStatus.REJECTED)
    record_audit_event(
        deps["table"], entity=f"ACTION#{state['action_id']}", event="rejected", at=state["now"]
    )
    return {}


def _create_exception(state: ActionGraphState, *, deps: ActionGraphDeps) -> dict[str, Any]:
    set_action_status(deps["table"], state["action_id"], ActionStatus.SNOOZED)
    record_audit_event(
        deps["table"], entity=f"ACTION#{state['action_id']}", event="snoozed", at=state["now"]
    )
    return {}


def build_action_graph(deps: ActionGraphDeps, *, checkpointer: Any) -> Any:
    graph = StateGraph(ActionGraphState)
    graph.add_node("await_approval", _await_approval)
    graph.add_node("policy_recheck", lambda state: _policy_recheck(state, deps=deps))
    graph.add_node("remediate", lambda state: _remediate(state, deps=deps))
    graph.add_node("verify", _verify)
    graph.add_node("record", lambda state: _record(state, deps=deps))
    graph.add_node("record_rejected", lambda state: _record_rejected(state, deps=deps))
    graph.add_node("create_exception", lambda state: _create_exception(state, deps=deps))

    graph.add_edge(START, "await_approval")
    graph.add_conditional_edges(
        "await_approval",
        _route_after_await,
        ["await_approval", "policy_recheck", "record_rejected", "create_exception"],
    )
    graph.add_conditional_edges(
        "policy_recheck", _route_after_policy_recheck, ["remediate", "record"]
    )
    graph.add_edge("remediate", "verify")
    graph.add_edge("verify", "record")
    graph.add_edge("record", END)
    graph.add_edge("record_rejected", END)
    graph.add_edge("create_exception", END)

    return graph.compile(checkpointer=checkpointer)


__all__ = [
    "ActionGraphDeps",
    "ActionGraphState",
    "NullRemediator",
    "RemediationOutcome",
    "Remediator",
    "build_action_graph",
    "check_kill_switch",
    "count_distinct_approvals",
    "has_decision",
    "validate_approval",
]
