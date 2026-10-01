"""Table-driven tests for every rule in policy/engine.py."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from cloudops_orchestrator.kb.parser import clause_text_index
from cloudops_orchestrator.models.actions import Recommendation
from cloudops_orchestrator.models.enums import ActionType, Domain, RiskTier, Severity
from cloudops_orchestrator.models.findings import Finding
from cloudops_orchestrator.models.sop import SOPCitation
from cloudops_orchestrator.policy.config import (
    load_action_allowlist,
    load_protected_resources,
    load_risk_tiers,
)
from cloudops_orchestrator.policy.engine import (
    compute_effective_tier,
    evaluate_recommendation,
    is_automatable,
    is_iam_kms_org,
    is_protected,
    required_approvals_for,
)

REPO_ROOT = Path(__file__).resolve().parents[2]

RISK_TIERS = load_risk_tiers()
ACTION_ALLOWLIST = load_action_allowlist()
PROTECTED_RESOURCES = load_protected_resources()
CLAUSE_TEXTS = clause_text_index(REPO_ROOT / "knowledge_base")


def _finding(**overrides: object) -> Finding:
    defaults: dict[str, object] = {
        "fingerprint": "a" * 32,
        "domain": Domain.SECURITY,
        "source": "securityhub",
        "rule_id": "EC2.13",
        "control_ids": ["EC2.13"],
        "title": "t",
        "description": "d",
        "severity": Severity.HIGH,
        "account_id": "1",
        "region": "r",
        "resource_type": "AwsEc2SecurityGroup",
        "resource_id": "sg-1",
        "evidence_uri": "s3://b/k",
        "first_seen": datetime(2026, 1, 1, tzinfo=UTC),
        "last_seen": datetime(2026, 1, 1, tzinfo=UTC),
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


def _recommendation(**overrides: object) -> Recommendation:
    defaults: dict[str, object] = {
        "recommendation_id": "rec-1",
        "run_id": "run-1",
        "group_id": "group-1",
        "domain": Domain.SECURITY,
        "title": "t",
        "summary": "s",
        "action_type": ActionType.SSM_AUTOMATION,
        "parameters": {
            "document": "CloudOps-RevokeSGIngressWorld",
            "security_group_id": "sg-1",
            "ports": [22],
        },
        "target_fingerprints": ["a" * 32],
        "proposed_risk_tier": RiskTier.T1,
        "rationale": "r",
        "citations": [
            SOPCitation(
                sop_id="SEC-002",
                clause_id="SEC-002-2.1",
                quote="No unrestricted administrative ingress",
            )
        ],
        "blast_radius": "b",
    }
    defaults.update(overrides)
    return Recommendation(**defaults)  # type: ignore[arg-type]


class TestRule1ActionAllowlist:
    def test_valid_ssm_document_passes(self) -> None:
        result = evaluate_recommendation(
            _recommendation(),
            target_findings=[_finding()],
            clause_texts=CLAUSE_TEXTS,
            risk_tiers=RISK_TIERS,
            action_allowlist=ACTION_ALLOWLIST,
            protected_resources=PROTECTED_RESOURCES,
        )
        assert result.rejected_reason is None

    def test_unknown_ssm_document_rejected(self) -> None:
        rec = _recommendation(parameters={"document": "CloudOps-DoesNotExist"})
        result = evaluate_recommendation(
            rec,
            target_findings=[_finding()],
            clause_texts=CLAUSE_TEXTS,
            risk_tiers=RISK_TIERS,
            action_allowlist=ACTION_ALLOWLIST,
            protected_resources=PROTECTED_RESOURCES,
        )
        assert result.rejected_reason is not None
        assert result.action_type == ActionType.MANUAL_TICKET
        assert result.effective_risk_tier == RiskTier.T3

    def test_missing_required_parameter_rejected(self) -> None:
        rec = _recommendation(
            parameters={"document": "CloudOps-RevokeSGIngressWorld"}
        )  # missing security_group_id, ports
        result = evaluate_recommendation(
            rec,
            target_findings=[_finding()],
            clause_texts=CLAUSE_TEXTS,
            risk_tiers=RISK_TIERS,
            action_allowlist=ACTION_ALLOWLIST,
            protected_resources=PROTECTED_RESOURCES,
        )
        assert result.rejected_reason is not None
        assert "missing required parameter" in result.rejected_reason

    def test_terraform_pr_valid_intent_passes(self) -> None:
        rec = _recommendation(
            action_type=ActionType.TERRAFORM_PR,
            parameters={
                "repo": "r",
                "workspace": "w",
                "intent": "remediate_security",
                "resource_address": "a",
            },
        )
        result = evaluate_recommendation(
            rec,
            target_findings=[_finding()],
            clause_texts=CLAUSE_TEXTS,
            risk_tiers=RISK_TIERS,
            action_allowlist=ACTION_ALLOWLIST,
            protected_resources=PROTECTED_RESOURCES,
        )
        assert result.rejected_reason is None

    def test_terraform_pr_invalid_intent_rejected(self) -> None:
        rec = _recommendation(
            action_type=ActionType.TERRAFORM_PR,
            parameters={
                "repo": "r",
                "workspace": "w",
                "intent": "bogus_intent",
                "resource_address": "a",
            },
        )
        result = evaluate_recommendation(
            rec,
            target_findings=[_finding()],
            clause_texts=CLAUSE_TEXTS,
            risk_tiers=RISK_TIERS,
            action_allowlist=ACTION_ALLOWLIST,
            protected_resources=PROTECTED_RESOURCES,
        )
        assert result.rejected_reason is not None


class TestRule2IacManaged:
    def test_iac_managed_with_ssm_automation_rejected(self) -> None:
        result = evaluate_recommendation(
            _recommendation(),
            target_findings=[_finding(iac_managed=True)],
            clause_texts=CLAUSE_TEXTS,
            risk_tiers=RISK_TIERS,
            action_allowlist=ACTION_ALLOWLIST,
            protected_resources=PROTECTED_RESOURCES,
        )
        assert result.rejected_reason is not None
        assert "iac_managed" in result.rejected_reason

    def test_iac_managed_with_terraform_pr_passes(self) -> None:
        rec = _recommendation(
            action_type=ActionType.TERRAFORM_PR,
            parameters={
                "repo": "r",
                "workspace": "w",
                "intent": "remediate_security",
                "resource_address": "a",
            },
        )
        result = evaluate_recommendation(
            rec,
            target_findings=[_finding(iac_managed=True)],
            clause_texts=CLAUSE_TEXTS,
            risk_tiers=RISK_TIERS,
            action_allowlist=ACTION_ALLOWLIST,
            protected_resources=PROTECTED_RESOURCES,
        )
        assert result.rejected_reason is None

    def test_not_iac_managed_ssm_automation_passes(self) -> None:
        result = evaluate_recommendation(
            _recommendation(),
            target_findings=[_finding(iac_managed=False)],
            clause_texts=CLAUSE_TEXTS,
            risk_tiers=RISK_TIERS,
            action_allowlist=ACTION_ALLOWLIST,
            protected_resources=PROTECTED_RESOURCES,
        )
        assert result.rejected_reason is None


class TestRule3Citations:
    def test_valid_citation_passes(self) -> None:
        result = evaluate_recommendation(
            _recommendation(),
            target_findings=[_finding()],
            clause_texts=CLAUSE_TEXTS,
            risk_tiers=RISK_TIERS,
            action_allowlist=ACTION_ALLOWLIST,
            protected_resources=PROTECTED_RESOURCES,
        )
        assert result.rejected_reason is None

    def test_unknown_clause_id_rejected(self) -> None:
        rec = _recommendation(
            citations=[SOPCitation(sop_id="SEC-002", clause_id="SEC-999-9.9", quote="anything")]
        )
        result = evaluate_recommendation(
            rec,
            target_findings=[_finding()],
            clause_texts=CLAUSE_TEXTS,
            risk_tiers=RISK_TIERS,
            action_allowlist=ACTION_ALLOWLIST,
            protected_resources=PROTECTED_RESOURCES,
        )
        assert result.rejected_reason is not None
        assert "unknown clause_id" in result.rejected_reason

    def test_non_verbatim_quote_rejected(self) -> None:
        rec = _recommendation(
            citations=[
                SOPCitation(
                    sop_id="SEC-002",
                    clause_id="SEC-002-2.1",
                    quote="this text does not appear anywhere",
                )
            ]
        )
        result = evaluate_recommendation(
            rec,
            target_findings=[_finding()],
            clause_texts=CLAUSE_TEXTS,
            risk_tiers=RISK_TIERS,
            action_allowlist=ACTION_ALLOWLIST,
            protected_resources=PROTECTED_RESOURCES,
        )
        assert result.rejected_reason is not None
        assert "verbatim" in result.rejected_reason

    def test_quote_reflowing_a_source_line_wrap_still_passes(self) -> None:
        # Confirmed live against a real Anthropic call: the model quotes
        # SEC-002-2.1 correctly, word for word, but naturally collapses the
        # source markdown's mid-sentence hard line-wrap into a space -- that
        # must not be treated as a non-verbatim quote.
        rec = _recommendation(
            citations=[
                SOPCitation(
                    sop_id="SEC-002",
                    clause_id="SEC-002-2.1",
                    quote="No security group MUST permit ingress on TCP 22 or TCP 3389 from `0.0.0.0/0` or `::/0`.",
                )
            ]
        )
        result = evaluate_recommendation(
            rec,
            target_findings=[_finding()],
            clause_texts=CLAUSE_TEXTS,
            risk_tiers=RISK_TIERS,
            action_allowlist=ACTION_ALLOWLIST,
            protected_resources=PROTECTED_RESOURCES,
        )
        assert result.rejected_reason is None

    def test_no_citations_at_all_passes(self) -> None:
        rec = _recommendation(citations=[])
        result = evaluate_recommendation(
            rec,
            target_findings=[_finding()],
            clause_texts=CLAUSE_TEXTS,
            risk_tiers=RISK_TIERS,
            action_allowlist=ACTION_ALLOWLIST,
            protected_resources=PROTECTED_RESOURCES,
        )
        assert result.rejected_reason is None


class TestRule4Protected:
    def test_protected_tag_forces_t3_and_manual_ticket(self) -> None:
        finding = _finding(resource_tags={"cloudops:protected": "true"})
        result = evaluate_recommendation(
            _recommendation(proposed_risk_tier=RiskTier.T1),
            target_findings=[finding],
            clause_texts=CLAUSE_TEXTS,
            risk_tiers=RISK_TIERS,
            action_allowlist=ACTION_ALLOWLIST,
            protected_resources=PROTECTED_RESOURCES,
        )
        assert result.effective_risk_tier == RiskTier.T3
        assert result.action_type == ActionType.MANUAL_TICKET
        assert result.rejected_reason is None  # forced tier, not a validation failure

    def test_platform_self_protection_tag_forces_t3(self) -> None:
        finding = _finding(resource_tags={"app": "cloudops-agentic-orchestrator"})
        assert is_protected(finding, PROTECTED_RESOURCES) is True

    def test_unprotected_resource_not_forced(self) -> None:
        finding = _finding(resource_tags={"environment": "dev"})
        assert is_protected(finding, PROTECTED_RESOURCES) is False


class TestRule5IamKmsOrg:
    def test_iam_resource_type_detected(self) -> None:
        assert is_iam_kms_org(_finding(resource_type="AwsIamRole")) is True

    def test_kms_resource_type_detected(self) -> None:
        assert is_iam_kms_org(_finding(resource_type="AwsKmsKey")) is True

    def test_non_iam_not_detected(self) -> None:
        assert is_iam_kms_org(_finding(resource_type="AwsEc2SecurityGroup")) is False

    def test_iam_target_forces_t3(self) -> None:
        finding = _finding(resource_type="AwsIamRole")
        result = evaluate_recommendation(
            _recommendation(proposed_risk_tier=RiskTier.T1),
            target_findings=[finding],
            clause_texts=CLAUSE_TEXTS,
            risk_tiers=RISK_TIERS,
            action_allowlist=ACTION_ALLOWLIST,
            protected_resources=PROTECTED_RESOURCES,
        )
        assert result.effective_risk_tier == RiskTier.T3
        assert result.action_type == ActionType.MANUAL_TICKET


class TestRule6EffectiveTier:
    def test_prod_environment_raises_to_t2(self) -> None:
        finding = _finding(environment="prod")
        tier = compute_effective_tier(
            proposed=RiskTier.T1,
            recommendation=_recommendation(),
            target_findings=[finding],
            risk_tiers=RISK_TIERS,
            protected=PROTECTED_RESOURCES,
        )
        assert tier == RiskTier.T2

    def test_terraform_revert_dispatch_raises_to_at_least_t1(self) -> None:
        rec = _recommendation(
            action_type=ActionType.TERRAFORM_REVERT_DISPATCH,
            parameters={"repo": "r", "workflow_file": "w.yml", "ref": "main", "workspace": "w"},
            proposed_risk_tier=RiskTier.T0,
        )
        tier = compute_effective_tier(
            proposed=RiskTier.T0,
            recommendation=rec,
            target_findings=[_finding()],
            risk_tiers=RISK_TIERS,
            protected=PROTECTED_RESOURCES,
        )
        assert tier == RiskTier.T1

    def test_snapshot_and_delete_document_raises_to_t2(self) -> None:
        rec = _recommendation(
            parameters={"document": "CloudOps-SnapshotAndDeleteVolume", "volume_id": "vol-1"}
        )
        tier = compute_effective_tier(
            proposed=RiskTier.T1,
            recommendation=rec,
            target_findings=[_finding()],
            risk_tiers=RISK_TIERS,
            protected=PROTECTED_RESOURCES,
        )
        assert tier == RiskTier.T2

    def test_agent_cannot_lower_tier_below_its_own_proposal(self) -> None:
        # Proposed T2 in dev with no raising rule matched -> stays T2, never drops to T1.
        tier = compute_effective_tier(
            proposed=RiskTier.T2,
            recommendation=_recommendation(proposed_risk_tier=RiskTier.T2),
            target_findings=[_finding(environment="dev")],
            risk_tiers=RISK_TIERS,
            protected=PROTECTED_RESOURCES,
        )
        assert tier == RiskTier.T2

    def test_notify_owner_matches_t0(self) -> None:
        rec = _recommendation(
            action_type=ActionType.NOTIFY_OWNER, parameters={}, proposed_risk_tier=RiskTier.T0
        )
        tier = compute_effective_tier(
            proposed=RiskTier.T0,
            recommendation=rec,
            target_findings=[_finding()],
            risk_tiers=RISK_TIERS,
            protected=PROTECTED_RESOURCES,
        )
        assert tier == RiskTier.T0


class TestRule7RequiredApprovals:
    def test_t0_requires_zero(self) -> None:
        assert required_approvals_for(RiskTier.T0, RISK_TIERS) == 0

    def test_t1_requires_one(self) -> None:
        assert required_approvals_for(RiskTier.T1, RISK_TIERS) == 1

    def test_t2_requires_two(self) -> None:
        assert required_approvals_for(RiskTier.T2, RISK_TIERS) == 2

    def test_t3_requires_zero_never_executed(self) -> None:
        assert required_approvals_for(RiskTier.T3, RISK_TIERS) == 0


class TestIsAutomatable:
    def test_t1_ssm_automation_is_automatable(self) -> None:
        assert is_automatable(_recommendation(), RiskTier.T1, RISK_TIERS) is True

    def test_t3_never_automatable(self) -> None:
        assert is_automatable(_recommendation(), RiskTier.T3, RISK_TIERS) is False

    def test_manual_ticket_never_automatable_even_at_t1(self) -> None:
        rec = _recommendation(action_type=ActionType.MANUAL_TICKET, parameters={})
        assert is_automatable(rec, RiskTier.T1, RISK_TIERS) is False

    def test_notify_owner_never_automatable(self) -> None:
        rec = _recommendation(action_type=ActionType.NOTIFY_OWNER, parameters={})
        assert is_automatable(rec, RiskTier.T0, RISK_TIERS) is False
