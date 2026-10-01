"""Deterministic policy engine — the LLM proposes, this decides.

``evaluate_recommendation`` runs every validation rule and returns a new
``Recommendation`` with ``effective_risk_tier`` set and, on any validation
failure, ``action_type`` downgraded to ``MANUAL_TICKET`` and
``rejected_reason`` explaining why — never silently dropped.
"""

from __future__ import annotations

import re
from typing import Any

from cloudops_orchestrator.models.actions import Recommendation
from cloudops_orchestrator.models.enums import ActionType, RiskTier
from cloudops_orchestrator.models.findings import Finding
from cloudops_orchestrator.policy.config import (
    ActionAllowlistConfig,
    ProtectedResourcesConfig,
    RiskTiersConfig,
)

_IAM_KMS_ORG_PREFIXES = ("AwsIam", "AwsKms", "AwsOrganizations")
_TIER_ORDER = ["T0", "T1", "T2", "T3"]


def is_protected(finding: Finding, protected: ProtectedResourcesConfig) -> bool:
    for rule in protected.tags:
        if finding.resource_tags.get(rule.key) == rule.value:
            return True
    return finding.resource_id in protected.resource_ids


def is_iam_kms_org(finding: Finding) -> bool:
    return finding.resource_type.startswith(_IAM_KMS_ORG_PREFIXES)


def _validate_parameter_schema(parameters: dict[str, Any], schema: Any) -> str | None:
    missing = [key for key in schema.required if key not in parameters]
    if missing:
        return f"missing required parameter(s): {', '.join(missing)}"
    for key, spec in schema.properties.items():
        if key not in parameters:
            continue
        enum = spec.get("enum")
        if enum is not None and parameters[key] not in enum:
            return f"parameter {key!r} value {parameters[key]!r} not in allowed set {enum}"
    return None


def _validate_action_allowed(
    recommendation: Recommendation, allowlist: ActionAllowlistConfig
) -> str | None:
    """Rule 1: action_type known; for SSM_AUTOMATION, document allowlisted and params match its schema."""
    if recommendation.action_type == ActionType.SSM_AUTOMATION:
        document = recommendation.parameters.get("document")
        if document not in allowlist.ssm_automation:
            return f"SSM document {document!r} is not in the allowlist"
        doc_spec = allowlist.ssm_automation[document]
        # The identifying parameter (which resource to act on) is supplied
        # by the orchestrator per-target at execution time
        # (remediation/runbook_executor.py), never by the model -- a single
        # recommendation can cover multiple targets, and there's no way for
        # the model to express one real value per target in one flat
        # parameters dict. See config/policy/action_allowlist.yaml's
        # identifying_parameter doc comment.
        schema_without_identifying = doc_spec.parameters.model_copy(
            update={
                "required": [
                    r for r in doc_spec.parameters.required if r != doc_spec.identifying_parameter
                ]
            }
        )
        return _validate_parameter_schema(recommendation.parameters, schema_without_identifying)
    if recommendation.action_type == ActionType.TERRAFORM_PR:
        return _validate_parameter_schema(
            recommendation.parameters, allowlist.terraform_pr.parameters
        )
    if recommendation.action_type == ActionType.TERRAFORM_REVERT_DISPATCH:
        return _validate_parameter_schema(
            recommendation.parameters, allowlist.terraform_revert_dispatch.parameters
        )
    # MANUAL_TICKET / NOTIFY_OWNER take no parameters worth validating.
    return None


def _validate_iac_managed_action(
    recommendation: Recommendation, target_findings: list[Finding]
) -> str | None:
    """Rule 2: an iac_managed target may only use terraform_pr / terraform_revert_dispatch."""
    if not any(f.iac_managed for f in target_findings):
        return None
    allowed = {
        ActionType.TERRAFORM_PR,
        ActionType.TERRAFORM_REVERT_DISPATCH,
        ActionType.MANUAL_TICKET,
    }
    if recommendation.action_type not in allowed:
        return (
            f"target is iac_managed but action_type is {recommendation.action_type.value!r} "
            "(must be terraform_pr, terraform_revert_dispatch, or manual_ticket)"
        )
    return None


_WHITESPACE_RE = re.compile(r"\s+")


def _normalize_whitespace(text: str) -> str:
    """Collapse runs of whitespace (including the hard line-wraps every
    knowledge_base/**/*.md clause is wrapped at for readability) to a single
    space. A citation quote must still match the clause's actual words
    exactly -- this only forgives *where* the source markdown happened to
    wrap a line, which a model reading prose has no way to reproduce and no
    reason to (confirmed live: a real Anthropic call quoted SEC-002-2.1
    correctly, word for word, and was rejected purely because it merged the
    source's mid-sentence `\\n` into a space)."""
    return _WHITESPACE_RE.sub(" ", text).strip()


def _validate_citations(
    recommendation: Recommendation, *, clause_texts: dict[str, str]
) -> str | None:
    """Rule 3: every citation's clause_id must exist and quote must be verbatim
    (modulo whitespace normalization -- see ``_normalize_whitespace``)."""
    for citation in recommendation.citations:
        text = clause_texts.get(citation.clause_id)
        if text is None:
            return f"citation references unknown clause_id {citation.clause_id!r}"
        if _normalize_whitespace(citation.quote) not in _normalize_whitespace(text):
            return f"citation quote for {citation.clause_id!r} is not a verbatim substring of the clause"
    return None


def _rule_matches(
    rule_match: dict[str, list[str]],
    *,
    recommendation: Recommendation,
    target_findings: list[Finding],
) -> bool:
    """All keys present in ``rule_match`` must match (AND) — none currently
    combine more than one key, but this stays correct if one ever does."""
    if (
        "action_type" in rule_match
        and recommendation.action_type.value not in rule_match["action_type"]
    ):
        return False
    if (
        "document" in rule_match
        and recommendation.parameters.get("document") not in rule_match["document"]
    ):
        return False
    if "environment" in rule_match:
        environments = {(f.environment or "").lower() for f in target_findings}
        if not environments & {e.lower() for e in rule_match["environment"]}:
            return False
    if "resource_type_prefix" in rule_match:
        prefixes = tuple(rule_match["resource_type_prefix"])
        if not any(f.resource_type.startswith(prefixes) for f in target_findings):
            return False
    return True


def compute_effective_tier(
    *,
    proposed: RiskTier,
    recommendation: Recommendation,
    target_findings: list[Finding],
    risk_tiers: RiskTiersConfig,
    protected: ProtectedResourcesConfig,
) -> RiskTier:
    """Rule 6 (+4, +5): effective tier is the max of proposed and every matching floor."""
    candidates = [proposed]

    if any(is_protected(f, protected) for f in target_findings):
        candidates.append(RiskTier.T3)
    if any(is_iam_kms_org(f) for f in target_findings):
        candidates.append(RiskTier.T3)

    for rule in risk_tiers.rules:
        if not _rule_matches(
            rule.match, recommendation=recommendation, target_findings=target_findings
        ):
            continue
        tier_value = rule.min_tier or rule.tier
        if tier_value:
            candidates.append(RiskTier(tier_value))

    return max(candidates, key=lambda t: _TIER_ORDER.index(t.value))


def is_automatable(
    recommendation: Recommendation, effective_tier: RiskTier, risk_tiers: RiskTiersConfig
) -> bool:
    """Whether the aggregate/action-graph step should create an action thread at all."""
    if recommendation.action_type in (ActionType.MANUAL_TICKET, ActionType.NOTIFY_OWNER):
        return False
    for rule in risk_tiers.rules:
        if (
            rule.automatable is False
            and "action_type" in rule.match
            and recommendation.action_type.value in rule.match["action_type"]
        ):
            return False
    return risk_tiers.tiers[effective_tier.value].automatable


def required_approvals_for(tier: RiskTier, risk_tiers: RiskTiersConfig) -> int:
    """Rule 7. T3 has ``approvals: null`` — not automatable, so 0 (never executed)."""
    approvals = risk_tiers.tiers[tier.value].approvals
    return approvals if approvals is not None else 0


def evaluate_recommendation(
    recommendation: Recommendation,
    *,
    target_findings: list[Finding],
    clause_texts: dict[str, str],
    risk_tiers: RiskTiersConfig,
    action_allowlist: ActionAllowlistConfig,
    protected_resources: ProtectedResourcesConfig,
) -> Recommendation:
    rejection = (
        _validate_citations(recommendation, clause_texts=clause_texts)
        or _validate_action_allowed(recommendation, action_allowlist)
        or _validate_iac_managed_action(recommendation, target_findings)
    )

    if rejection is not None:
        return recommendation.model_copy(
            update={
                "action_type": ActionType.MANUAL_TICKET,
                "parameters": {},
                "effective_risk_tier": RiskTier.T3,
                "rejected_reason": rejection,
            }
        )

    effective_tier = compute_effective_tier(
        proposed=recommendation.proposed_risk_tier,
        recommendation=recommendation,
        target_findings=target_findings,
        risk_tiers=risk_tiers,
        protected=protected_resources,
    )

    action_type = recommendation.action_type
    # A protected/IAM-forced T3 target must actually execute as manual_ticket,
    # regardless of what the agent proposed for action_type.
    forced_t3 = effective_tier == RiskTier.T3 and recommendation.proposed_risk_tier != RiskTier.T3
    if forced_t3:
        action_type = ActionType.MANUAL_TICKET

    return recommendation.model_copy(
        update={"action_type": action_type, "effective_risk_tier": effective_tier}
    )


__all__ = [
    "compute_effective_tier",
    "evaluate_recommendation",
    "is_automatable",
    "is_iam_kms_org",
    "is_protected",
    "required_approvals_for",
]
