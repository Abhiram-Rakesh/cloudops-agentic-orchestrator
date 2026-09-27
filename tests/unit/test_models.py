from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from cloudops_orchestrator.models import (
    ActionPlan,
    ActionType,
    Domain,
    Finding,
    FindingStatus,
    RiskTier,
    Severity,
    SOPCitation,
)


def _now() -> datetime:
    return datetime(2026, 1, 15, 8, 45, tzinfo=UTC)


def make_finding(**overrides: object) -> Finding:
    defaults: dict[str, object] = {
        "fingerprint": "a" * 32,
        "domain": Domain.SECURITY,
        "source": "securityhub",
        "rule_id": "EC2.13",
        "control_ids": ["EC2.13"],
        "title": "Unrestricted SSH ingress",
        "description": "Security group allows 0.0.0.0/0 on port 22.",
        "severity": Severity.HIGH,
        "account_id": "111111111111",
        "region": "ap-south-1",
        "resource_type": "AwsEc2SecurityGroup",
        "resource_id": "sg-0123456789abcdef0",
        "evidence_uri": "s3://bucket/evidence/1.json",
        "first_seen": _now(),
        "last_seen": _now(),
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


class TestSeverity:
    def test_weight_ordering(self) -> None:
        assert Severity.INFO.weight < Severity.LOW.weight < Severity.MEDIUM.weight
        assert Severity.MEDIUM.weight < Severity.HIGH.weight < Severity.CRITICAL.weight

    def test_comparable(self) -> None:
        assert Severity.LOW < Severity.HIGH
        assert Severity.CRITICAL > Severity.INFO
        assert max(Severity.LOW, Severity.CRITICAL, Severity.MEDIUM) is Severity.CRITICAL


class TestRiskTier:
    def test_ordering(self) -> None:
        assert RiskTier.T0 < RiskTier.T1 < RiskTier.T2 < RiskTier.T3

    def test_max_picks_highest_tier(self) -> None:
        assert max(RiskTier.T1, RiskTier.T0) is RiskTier.T1
        assert max(RiskTier.T3, RiskTier.T2, RiskTier.T1) is RiskTier.T3


class TestFinding:
    def test_round_trip(self) -> None:
        finding = make_finding()
        dumped = finding.model_dump_json()
        restored = Finding.model_validate_json(dumped)
        assert restored == finding

    def test_frozen(self) -> None:
        finding = make_finding()
        with pytest.raises(ValidationError):
            finding.status = FindingStatus.RESOLVED  # type: ignore[misc]

    def test_naive_datetime_rejected(self) -> None:
        with pytest.raises(ValidationError):
            make_finding(first_seen=datetime(2026, 1, 15, 8, 45))  # no tzinfo

    def test_non_utc_datetime_normalized_to_utc(self) -> None:
        from datetime import timedelta, timezone

        ist = timezone(timedelta(hours=5, minutes=30))
        finding = make_finding(first_seen=datetime(2026, 1, 15, 14, 15, tzinfo=ist))
        assert finding.first_seen == _now()
        assert finding.first_seen.tzinfo == UTC

    def test_defaults(self) -> None:
        finding = make_finding()
        assert finding.status == FindingStatus.NEW
        assert finding.iac_managed is False
        assert finding.sources == []
        assert finding.resource_tags == {}


class TestSOPCitation:
    def test_quote_too_long_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SOPCitation(sop_id="SEC-002", clause_id="SEC-002-2.1", quote="x" * 301)

    def test_quote_at_limit_accepted(self) -> None:
        citation = SOPCitation(sop_id="SEC-002", clause_id="SEC-002-2.1", quote="x" * 300)
        assert len(citation.quote) == 300


class TestActionPlan:
    def test_requires_utc_expiry(self) -> None:
        plan = ActionPlan(
            action_id="action-1",
            recommendation_id="rec-1",
            action_type=ActionType.SSM_AUTOMATION,
            parameters={"document": "CloudOps-RevokeSGIngressWorld"},
            targets=["sg-0123456789abcdef0"],
            effective_risk_tier=RiskTier.T1,
            required_approvals=1,
            expires_at=_now(),
            plan_hash="b" * 64,
        )
        assert plan.expires_at.tzinfo == UTC
