from __future__ import annotations

from datetime import UTC, datetime

from cloudops_orchestrator.models.enums import Domain, Severity
from cloudops_orchestrator.models.findings import Finding
from cloudops_orchestrator.normalize.grouping import compute_group_id, group_findings
from cloudops_orchestrator.normalize.masking import Masker


def _finding(**overrides: object) -> Finding:
    defaults: dict[str, object] = {
        "fingerprint": "a" * 32,
        "domain": Domain.SECURITY,
        "source": "securityhub",
        "rule_id": "EC2.13",
        "control_ids": ["EC2.13"],
        "title": "Unrestricted ingress on sg-0123456789abcdef0",
        "description": "Security group sg-0123456789abcdef0 allows 0.0.0.0/0 on port 22 for account 111111111111.",
        "severity": Severity.HIGH,
        "account_id": "111111111111",
        "region": "ap-south-1",
        "resource_type": "AwsEc2SecurityGroup",
        "resource_id": "sg-0123456789abcdef0",
        "evidence_uri": "s3://b/k",
        "details": {"port": 22},
        "first_seen": datetime(2026, 1, 1, tzinfo=UTC),
        "last_seen": datetime(2026, 1, 1, tzinfo=UTC),
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


def test_group_id_deterministic() -> None:
    gid1 = compute_group_id(
        domain=Domain.SECURITY, rule_id="EC2.13", resource_type="AwsEc2SecurityGroup"
    )
    gid2 = compute_group_id(
        domain=Domain.SECURITY, rule_id="EC2.13", resource_type="AwsEc2SecurityGroup"
    )
    assert gid1 == gid2
    assert len(gid1) == 16


def test_findings_group_by_domain_rule_resource_type() -> None:
    findings = [
        _finding(fingerprint="a" * 32, resource_id="sg-1"),
        _finding(fingerprint="b" * 32, resource_id="sg-2"),
        _finding(fingerprint="c" * 32, rule_id="EC2.19", resource_id="sg-3"),
    ]
    groups = group_findings(findings, masker=Masker())
    assert len(groups) == 2
    ec2_13_group = next(g for g in groups if g.rule_id == "EC2.13")
    assert ec2_13_group.count == 2
    assert set(ec2_13_group.findings) == {"a" * 32, "b" * 32}


def test_max_severity_and_control_id_union() -> None:
    findings = [
        _finding(fingerprint="a" * 32, severity=Severity.MEDIUM, control_ids=["EC2.13"]),
        _finding(
            fingerprint="b" * 32, severity=Severity.CRITICAL, control_ids=["EC2.13", "CIS-5.2"]
        ),
    ]
    (group,) = group_findings(findings, masker=Masker())
    assert group.max_severity == Severity.CRITICAL
    assert group.control_ids == ["EC2.13", "CIS-5.2"]


def test_sample_is_masked_and_capped() -> None:
    findings = [
        _finding(fingerprint=chr(97 + i) * 32, resource_id=f"sg-{i:012x}") for i in range(8)
    ]
    (group,) = group_findings(findings, masker=Masker(), max_sample=5)
    assert group.count == 8
    assert len(group.sample) == 5
    for masked in group.sample:
        assert "111111111111" not in masked.title
        assert "111111111111" not in masked.description
        assert masked.masked_resource_id != findings[0].resource_id


def test_group_findings_share_masker_reuses_tokens() -> None:
    findings = [
        _finding(
            fingerprint="a" * 32, resource_id="sg-1", description="account 111111111111 finding"
        ),
        _finding(
            fingerprint="b" * 32,
            rule_id="EC2.19",
            resource_id="sg-2",
            description="account 111111111111 finding again",
        ),
    ]
    masker = Masker()
    groups = group_findings(findings, masker=masker)
    assert len(groups) == 2  # sanity: two distinct groups produced
    combined_text = " ".join(g.sample[0].description for g in groups)
    assert combined_text.count("ACCT_1") == 2  # same account -> same token, reused across groups
