from __future__ import annotations

from cloudops_orchestrator.models.enums import Domain, Severity
from cloudops_orchestrator.models.findings import FindingGroup
from cloudops_orchestrator.steps.plan_batches import plan_batches


def _group(group_id: str, domain: Domain) -> FindingGroup:
    return FindingGroup(
        group_id=group_id,
        domain=domain,
        rule_id="RULE",
        control_ids=[],
        resource_type="Other",
        findings=["a" * 32],
        sample=[],
        count=1,
        max_severity=Severity.LOW,
    )


def test_single_batch_when_under_limit() -> None:
    groups = [_group(f"g{i}", Domain.SECURITY) for i in range(5)]
    batches = plan_batches({Domain.SECURITY: groups}, max_groups_per_batch=12)
    assert len(batches) == 1
    assert len(batches[0].groups) == 5
    assert batches[0].batch_id == "security-0"


def test_splits_into_multiple_batches() -> None:
    groups = [_group(f"g{i}", Domain.SECURITY) for i in range(25)]
    batches = plan_batches({Domain.SECURITY: groups}, max_groups_per_batch=12)
    assert len(batches) == 3
    assert [len(b.groups) for b in batches] == [12, 12, 1]
    assert [b.batch_id for b in batches] == ["security-0", "security-1", "security-2"]


def test_separate_batches_per_domain() -> None:
    groups_by_domain = {
        Domain.SECURITY: [_group("s1", Domain.SECURITY)],
        Domain.COST: [_group("c1", Domain.COST)],
    }
    batches = plan_batches(groups_by_domain, max_groups_per_batch=12)
    assert {b.domain for b in batches} == {Domain.SECURITY, Domain.COST}


def test_empty_input_produces_no_batches() -> None:
    assert plan_batches({}, max_groups_per_batch=12) == []
