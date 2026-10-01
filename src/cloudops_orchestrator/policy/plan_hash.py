"""Approval-bound plan hashing.

Canonical JSON (sorted keys, UTF-8, no whitespace, datetimes ISO UTC) of an
``ActionPlan``'s fields *except* ``plan_hash`` itself, SHA-256 hex-digested.
Slack button values carry only ``action_id``; the Lambda that renders the
digest stores the ``plan_hash`` it displayed, and the executor recomputes
this hash from the stored plan and refuses to act on a mismatch — this is
the entire mechanism behind the rule that the LLM never holds write
credentials.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from cloudops_orchestrator.models.actions import ActionPlan
from cloudops_orchestrator.models.enums import ActionType, RiskTier


def _canonical_json(fields: dict[str, Any]) -> str:
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _plan_fields(
    *,
    action_id: str,
    recommendation_id: str,
    action_type: str,
    parameters: dict[str, Any],
    targets: list[str],
    effective_risk_tier: str,
    required_approvals: int,
    expires_at: datetime,
) -> dict[str, Any]:
    return {
        "action_id": action_id,
        "recommendation_id": recommendation_id,
        "action_type": action_type,
        "parameters": parameters,
        "targets": targets,
        "effective_risk_tier": effective_risk_tier,
        "required_approvals": required_approvals,
        "expires_at": expires_at.astimezone(UTC).isoformat(),
    }


def compute_plan_hash(
    *,
    action_id: str,
    recommendation_id: str,
    action_type: str,
    parameters: dict[str, Any],
    targets: list[str],
    effective_risk_tier: str,
    required_approvals: int,
    expires_at: datetime,
) -> str:
    fields = _plan_fields(
        action_id=action_id,
        recommendation_id=recommendation_id,
        action_type=action_type,
        parameters=parameters,
        targets=targets,
        effective_risk_tier=effective_risk_tier,
        required_approvals=required_approvals,
        expires_at=expires_at,
    )
    return hashlib.sha256(_canonical_json(fields).encode("utf-8")).hexdigest()


def build_action_plan(
    *,
    action_id: str,
    recommendation_id: str,
    action_type: ActionType,
    parameters: dict[str, Any],
    targets: list[str],
    effective_risk_tier: RiskTier,
    required_approvals: int,
    expires_at: datetime,
) -> ActionPlan:
    plan_hash = compute_plan_hash(
        action_id=action_id,
        recommendation_id=recommendation_id,
        action_type=action_type.value,
        parameters=parameters,
        targets=targets,
        effective_risk_tier=effective_risk_tier.value,
        required_approvals=required_approvals,
        expires_at=expires_at,
    )
    return ActionPlan(
        action_id=action_id,
        recommendation_id=recommendation_id,
        action_type=action_type,
        parameters=parameters,
        targets=targets,
        effective_risk_tier=effective_risk_tier,
        required_approvals=required_approvals,
        expires_at=expires_at,
        plan_hash=plan_hash,
    )


def verify_plan_hash(plan: ActionPlan) -> bool:
    """Recompute the hash from the plan's own fields and compare — the
    executor's last line of defense against a tampered or stale plan."""
    expected = compute_plan_hash(
        action_id=plan.action_id,
        recommendation_id=plan.recommendation_id,
        action_type=plan.action_type.value,
        parameters=plan.parameters,
        targets=plan.targets,
        effective_risk_tier=plan.effective_risk_tier.value,
        required_approvals=plan.required_approvals,
        expires_at=plan.expires_at,
    )
    return expected == plan.plan_hash


__all__ = ["build_action_plan", "compute_plan_hash", "verify_plan_hash"]
