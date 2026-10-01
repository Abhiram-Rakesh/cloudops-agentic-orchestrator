"""Create action-graph threads for automatable recommendations: for
each ``ReportItem`` whose recommendation is automatable at its effective
risk tier (T1/T2), build an ``ActionPlan`` and invoke the action graph once
so it checkpoints at its first ``interrupt`` — ready for a human's approval
to resume it (Slack in production, ``cloudops resume`` for local testing).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

from cloudops_orchestrator.graph.action_graph import ActionGraphDeps, build_action_graph
from cloudops_orchestrator.models.report import ReportItem
from cloudops_orchestrator.policy.config import RiskTiersConfig
from cloudops_orchestrator.policy.engine import is_automatable, required_approvals_for
from cloudops_orchestrator.policy.plan_hash import build_action_plan
from cloudops_orchestrator.store.actions import put_action_plan


@dataclass(frozen=True)
class CreatedActionThread:
    action_id: str
    recommendation_id: str
    group_id: str


def create_action_threads(
    items: list[ReportItem],
    *,
    deps: ActionGraphDeps,
    checkpointer: Any,
    risk_tiers: RiskTiersConfig,
    approvers: list[str],
    expiry_days: int,
    now: datetime,
) -> list[CreatedActionThread]:
    created: list[CreatedActionThread] = []
    graph = build_action_graph(deps, checkpointer=checkpointer)

    for item in items:
        recommendation = item.recommendation
        if recommendation is None or recommendation.effective_risk_tier is None:
            continue
        if not is_automatable(recommendation, recommendation.effective_risk_tier, risk_tiers):
            continue

        action_id = str(uuid4())
        required_approvals = required_approvals_for(recommendation.effective_risk_tier, risk_tiers)
        plan = build_action_plan(
            action_id=action_id,
            recommendation_id=recommendation.recommendation_id,
            action_type=recommendation.action_type,
            parameters=recommendation.parameters,
            targets=recommendation.target_fingerprints,
            effective_risk_tier=recommendation.effective_risk_tier,
            required_approvals=required_approvals,
            expires_at=now + timedelta(days=expiry_days),
        )
        put_action_plan(deps["table"], plan)

        thread_config = {"configurable": {"thread_id": f"action:{action_id}"}}
        graph.invoke(
            {
                "action_id": action_id,
                "plan": plan,
                "approvers": approvers,
                "approvals": [],
                "decision": None,
                "remediation": None,
                "now": now,
            },
            thread_config,
        )
        created.append(
            CreatedActionThread(
                action_id=action_id,
                recommendation_id=recommendation.recommendation_id,
                group_id=item.group_id,
            )
        )

    return created


__all__ = ["CreatedActionThread", "create_action_threads"]
