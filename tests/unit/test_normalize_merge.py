from __future__ import annotations

from datetime import UTC, datetime

from cloudops_orchestrator.models.enums import Domain, FindingStatus, Severity
from cloudops_orchestrator.models.findings import Finding
from cloudops_orchestrator.normalize.merge import merge_duplicate_findings


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


def test_no_duplicates_passes_through() -> None:
    findings = [_finding(fingerprint="a" * 32), _finding(fingerprint="b" * 32, resource_id="sg-2")]
    merged = merge_duplicate_findings(findings)
    assert len(merged) == 2


def test_duplicate_fingerprint_merges_sources() -> None:
    sh = _finding(fingerprint="a" * 32, source="securityhub", control_ids=["EC2.13"])
    prowler = _finding(
        fingerprint="a" * 32,
        source="prowler",
        control_ids=["EC2.13"],
        rule_id="ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
    )
    (merged,) = merge_duplicate_findings([sh, prowler])
    assert set(merged.sources) == {"securityhub", "prowler"}
    assert merged.source == "securityhub"  # primary source is the first one seen


def test_merge_takes_max_severity() -> None:
    low = _finding(fingerprint="a" * 32, severity=Severity.LOW)
    high = _finding(fingerprint="a" * 32, severity=Severity.HIGH)
    (merged,) = merge_duplicate_findings([low, high])
    assert merged.severity == Severity.HIGH


def test_merge_widens_first_last_seen() -> None:
    early = _finding(
        fingerprint="a" * 32,
        first_seen=datetime(2026, 1, 1, tzinfo=UTC),
        last_seen=datetime(2026, 1, 1, tzinfo=UTC),
    )
    late = _finding(
        fingerprint="a" * 32,
        first_seen=datetime(2026, 1, 5, tzinfo=UTC),
        last_seen=datetime(2026, 1, 10, tzinfo=UTC),
    )
    (merged,) = merge_duplicate_findings([early, late])
    assert merged.first_seen == datetime(2026, 1, 1, tzinfo=UTC)
    assert merged.last_seen == datetime(2026, 1, 10, tzinfo=UTC)


def test_merge_dedupes_control_ids() -> None:
    a = _finding(fingerprint="a" * 32, control_ids=["EC2.13", "CIS-5.2"])
    b = _finding(fingerprint="a" * 32, control_ids=["EC2.13", "EC2.14"])
    (merged,) = merge_duplicate_findings([a, b])
    assert merged.control_ids == ["EC2.13", "CIS-5.2", "EC2.14"]


def test_empty_list() -> None:
    assert merge_duplicate_findings([]) == []
