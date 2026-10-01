"""Round-trip tests for the S3 payload (de)serialization Lambda handlers use
to hand off state between InitRun -> Collect -> DomainBatch -> Aggregate."""

from __future__ import annotations

from datetime import UTC, datetime

from cloudops_orchestrator.graph.domain_agent import GroupAnalysis
from cloudops_orchestrator.models.actions import Recommendation, TriageResult
from cloudops_orchestrator.models.enums import (
    ActionType,
    Domain,
    RiskTier,
    Severity,
    TriageVerdict,
)
from cloudops_orchestrator.models.findings import Finding, FindingGroup
from cloudops_orchestrator.normalize.masking import Masker
from cloudops_orchestrator.steps.run_domain_batch import DomainBatchResult
from cloudops_orchestrator.steps.serialization import (
    deserialize_domain_result,
    deserialize_findings,
    deserialize_groups,
    deserialize_masker,
    serialize_domain_result,
    serialize_findings,
    serialize_groups,
    serialize_masker,
)


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
        "account_id": "111111111111",
        "region": "ap-south-1",
        "resource_type": "AwsEc2SecurityGroup",
        "resource_id": "sg-1",
        "evidence_uri": "s3://b/k",
        "first_seen": datetime(2026, 1, 1, tzinfo=UTC),
        "last_seen": datetime(2026, 1, 1, tzinfo=UTC),
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


def _group(**overrides: object) -> FindingGroup:
    defaults: dict[str, object] = {
        "group_id": "g1",
        "domain": Domain.SECURITY,
        "rule_id": "EC2.13",
        "control_ids": ["EC2.13"],
        "resource_type": "AwsEc2SecurityGroup",
        "findings": ["a" * 32],
        "sample": [],
        "count": 1,
        "max_severity": Severity.HIGH,
    }
    defaults.update(overrides)
    return FindingGroup(**defaults)  # type: ignore[arg-type]


def _triage(**overrides: object) -> TriageResult:
    defaults: dict[str, object] = {
        "group_id": "g1",
        "verdict": TriageVerdict.ACTIONABLE,
        "adjusted_severity": Severity.HIGH,
        "rationale": "r",
        "citations": [],
        "sop_gap": False,
    }
    defaults.update(overrides)
    return TriageResult(**defaults)  # type: ignore[arg-type]


def _recommendation(**overrides: object) -> Recommendation:
    defaults: dict[str, object] = {
        "recommendation_id": "rec-1",
        "run_id": "run-1",
        "group_id": "g1",
        "domain": Domain.SECURITY,
        "title": "t",
        "summary": "s",
        "action_type": ActionType.SSM_AUTOMATION,
        "parameters": {},
        "target_fingerprints": ["a" * 32],
        "proposed_risk_tier": RiskTier.T1,
        "rationale": "r",
        "citations": [],
        "blast_radius": "b",
    }
    defaults.update(overrides)
    return Recommendation(**defaults)  # type: ignore[arg-type]


def test_findings_round_trip() -> None:
    findings = [_finding(), _finding(fingerprint="b" * 32, resource_id="sg-2")]
    assert deserialize_findings(serialize_findings(findings)) == findings


def test_findings_round_trip_empty() -> None:
    assert deserialize_findings(serialize_findings([])) == []


def test_groups_round_trip() -> None:
    groups = [_group(), _group(group_id="g2", domain=Domain.COST)]
    assert deserialize_groups(serialize_groups(groups)) == groups


def test_domain_result_round_trip_with_recommendation() -> None:
    result = DomainBatchResult(
        batch_id="security-0",
        domain="security",
        analyses=[
            GroupAnalysis(
                group=_group(),
                triage=_triage(),
                recommendation=_recommendation(),
                carried_over=False,
                error=None,
            )
        ],
        budget_exhausted=False,
        cost_usd=0.05,
    )
    restored = deserialize_domain_result(serialize_domain_result(result))
    assert restored.batch_id == result.batch_id
    assert restored.domain == result.domain
    assert restored.budget_exhausted is False
    assert restored.cost_usd == 0.05
    assert len(restored.analyses) == 1
    assert restored.analyses[0].group == result.analyses[0].group
    assert restored.analyses[0].triage == result.analyses[0].triage
    assert restored.analyses[0].recommendation == result.analyses[0].recommendation


def test_masker_round_trips_across_the_s3_handoff() -> None:
    # This is the exact scenario handlers/collect.py -> handlers/domain_batch.py
    # need: a masker masks findings in one Lambda invocation, its state
    # crosses an S3 round trip as plain JSON, and a reconstructed masker in
    # a SEPARATE invocation must still unmask() what the first one produced.
    original = Masker()
    masked_text = original.mask("account 111111111111, sg-0123456789abcdef0")

    restored = deserialize_masker(serialize_masker(original))
    assert restored.unmask(masked_text) == "account 111111111111, sg-0123456789abcdef0"


def test_masker_round_trip_empty() -> None:
    restored = deserialize_masker(serialize_masker(Masker()))
    assert restored.reverse_map() == {}


def test_domain_result_round_trip_without_recommendation() -> None:
    result = DomainBatchResult(
        batch_id="cost-0",
        domain="cost",
        analyses=[
            GroupAnalysis(
                group=_group(),
                triage=_triage(),
                recommendation=None,
                carried_over=True,
                error="boom",
            )
        ],
        budget_exhausted=True,
        cost_usd=2.0,
    )
    restored = deserialize_domain_result(serialize_domain_result(result))
    assert restored.analyses[0].recommendation is None
    assert restored.analyses[0].carried_over is True
    assert restored.analyses[0].error == "boom"
