from __future__ import annotations

from cloudops_orchestrator.models.enums import Domain
from cloudops_orchestrator.normalize.fingerprint import (
    security_finding_fingerprint,
    standard_fingerprint,
)


def test_fingerprint_is_32_hex_chars() -> None:
    fp = standard_fingerprint(
        domain=Domain.COST,
        source="cost_waste",
        account_id="111111111111",
        region="ap-south-1",
        resource_id="vol-1",
        rule_id="COST-WASTE-GP2",
    )
    assert len(fp) == 32
    assert all(c in "0123456789abcdef" for c in fp)


def test_fingerprint_stable_across_calls() -> None:
    kwargs: dict[str, object] = {
        "domain": Domain.COST,
        "source": "cost_waste",
        "account_id": "111111111111",
        "region": "ap-south-1",
        "resource_id": "vol-1",
        "rule_id": "COST-WASTE-GP2",
    }
    assert standard_fingerprint(**kwargs) == standard_fingerprint(**kwargs)  # type: ignore[arg-type]


def test_fingerprint_differs_on_resource() -> None:
    a = standard_fingerprint(
        domain=Domain.COST, source="x", account_id="1", region="r", resource_id="a", rule_id="RULE"
    )
    b = standard_fingerprint(
        domain=Domain.COST, source="x", account_id="1", region="r", resource_id="b", rule_id="RULE"
    )
    assert a != b


def test_security_hub_and_prowler_collide_on_same_control_and_resource() -> None:
    sh_fp = security_finding_fingerprint(
        account_id="111111111111", region="ap-south-1", resource_id="sg-abc123", control_id="EC2.13"
    )
    prowler_fp = security_finding_fingerprint(
        account_id="111111111111", region="ap-south-1", resource_id="sg-abc123", control_id="EC2.13"
    )
    assert sh_fp == prowler_fp


def test_different_controls_do_not_collide() -> None:
    a = security_finding_fingerprint(
        account_id="1", region="r", resource_id="sg-x", control_id="EC2.13"
    )
    b = security_finding_fingerprint(
        account_id="1", region="r", resource_id="sg-x", control_id="EC2.14"
    )
    assert a != b
