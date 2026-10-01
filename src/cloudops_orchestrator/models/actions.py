"""Triage, recommendation, action-plan and approval models.

These form the chain of custody from "an LLM noticed something" to "a human
approved a specific, hashed, executable plan" — see ``policy/plan_hash.py``
and the rule that the LLM never holds write credentials.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from cloudops_orchestrator.models.common import UTCDatetime
from cloudops_orchestrator.models.enums import (
    ActionType,
    ApprovalDecision,
    Domain,
    RiskTier,
    Severity,
    TriageVerdict,
)
from cloudops_orchestrator.models.sop import SOPCitation


class TriageResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    group_id: str
    verdict: TriageVerdict
    adjusted_severity: Severity
    rationale: str
    citations: list[SOPCitation] = Field(default_factory=list)
    sop_gap: bool = False


class Recommendation(BaseModel):
    model_config = ConfigDict(frozen=True)

    recommendation_id: str  # uuid7
    run_id: str
    group_id: str
    domain: Domain
    title: str
    summary: str
    action_type: ActionType
    parameters: dict[str, Any] = Field(default_factory=dict)
    target_fingerprints: list[str]
    proposed_risk_tier: RiskTier
    effective_risk_tier: RiskTier | None = None
    rationale: str
    citations: list[SOPCitation] = Field(default_factory=list)
    blast_radius: str
    estimated_monthly_savings_usd: float | None = None
    iac_managed: bool = False
    rejected_reason: str | None = None


class ActionPlan(BaseModel):
    """What a human approves in Slack; hashed via ``policy/plan_hash.py``."""

    model_config = ConfigDict(frozen=True)

    action_id: str
    recommendation_id: str
    action_type: ActionType
    parameters: dict[str, Any] = Field(default_factory=dict)
    targets: list[str]
    effective_risk_tier: RiskTier
    required_approvals: int
    expires_at: UTCDatetime
    plan_hash: str


class Approval(BaseModel):
    model_config = ConfigDict(frozen=True)

    action_id: str
    plan_hash: str
    decision: ApprovalDecision
    approver_slack_id: str
    approver_name: str
    decided_at: UTCDatetime
    comment: str | None = None
