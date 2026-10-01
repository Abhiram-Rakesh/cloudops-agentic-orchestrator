from __future__ import annotations

from datetime import UTC, datetime

from cloudops_orchestrator.models.enums import Domain, FindingStatus, Severity
from cloudops_orchestrator.models.findings import Finding
from cloudops_orchestrator.policy.priority import (
    compute_age_factor,
    compute_priority_score,
    is_internet_exposed,
    is_prod_environment,
    priority_score_for_finding,
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
        "account_id": "1",
        "region": "r",
        "resource_type": "AwsEc2SecurityGroup",
        "resource_id": "sg-1",
        "evidence_uri": "s3://b/k",
        "first_seen": datetime(2026, 1, 1, tzinfo=UTC),
        "last_seen": datetime(2026, 1, 1, tzinfo=UTC),
        "status": FindingStatus.NEW,
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


class TestAgeFactor:
    def test_zero_days_open(self) -> None:
        now = datetime(2026, 1, 1, tzinfo=UTC)
        assert compute_age_factor(first_seen=now, now=now) == 1.0

    def test_fifteen_days_open(self) -> None:
        first_seen = datetime(2026, 1, 1, tzinfo=UTC)
        now = datetime(2026, 1, 16, tzinfo=UTC)
        assert compute_age_factor(first_seen=first_seen, now=now) == 1.5

    def test_capped_at_thirty_days(self) -> None:
        first_seen = datetime(2026, 1, 1, tzinfo=UTC)
        now = datetime(2026, 3, 1, tzinfo=UTC)  # 59 days
        assert compute_age_factor(first_seen=first_seen, now=now) == 2.0


class TestExposure:
    def test_explicit_flag_true(self) -> None:
        finding = _finding(details={"internet_exposed": True})
        assert is_internet_exposed(finding) is True

    def test_explicit_flag_false(self) -> None:
        finding = _finding(
            details={"internet_exposed": False}, description="mentions 0.0.0.0/0 anyway"
        )
        assert is_internet_exposed(finding) is False

    def test_cidr_in_description_detected(self) -> None:
        finding = _finding(description="allows ingress from 0.0.0.0/0")
        assert is_internet_exposed(finding) is True

    def test_ipv6_world_open_detected(self) -> None:
        finding = _finding(description="allows ingress from ::/0")
        assert is_internet_exposed(finding) is True

    def test_no_signal_not_exposed(self) -> None:
        finding = _finding(description="missing a tag")
        assert is_internet_exposed(finding) is False


class TestProdEnvironment:
    def test_prod(self) -> None:
        assert is_prod_environment("prod") is True

    def test_production(self) -> None:
        assert is_prod_environment("PRODUCTION") is True

    def test_dev(self) -> None:
        assert is_prod_environment("dev") is False

    def test_none(self) -> None:
        assert is_prod_environment(None) is False


class TestComputePriorityScore:
    def test_baseline_medium_no_modifiers(self) -> None:
        now = datetime(2026, 1, 1, tzinfo=UTC)
        score = compute_priority_score(
            severity=Severity.MEDIUM,
            internet_exposed=False,
            environment="dev",
            first_seen=now,
            now=now,
        )
        assert score == Severity.MEDIUM.weight  # 15 * 1 * 1 * 1

    def test_exposed_and_prod_and_aged(self) -> None:
        first_seen = datetime(2026, 1, 1, tzinfo=UTC)
        now = datetime(2026, 1, 31, tzinfo=UTC)  # 30 days -> age_factor 2.0
        score = compute_priority_score(
            severity=Severity.HIGH,
            internet_exposed=True,
            environment="prod",
            first_seen=first_seen,
            now=now,
        )
        assert score == Severity.HIGH.weight * 1.5 * 1.5 * 2.0

    def test_priority_score_for_finding_uses_finding_fields(self) -> None:
        finding = _finding(
            severity=Severity.CRITICAL,
            environment="prod",
            description="0.0.0.0/0",
            first_seen=datetime(2026, 1, 1, tzinfo=UTC),
        )
        now = datetime(2026, 1, 1, tzinfo=UTC)
        score = priority_score_for_finding(finding, now=now)
        assert score == Severity.CRITICAL.weight * 1.5 * 1.5 * 1.0
