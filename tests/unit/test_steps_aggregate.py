from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from cloudops_orchestrator.config import load_settings
from cloudops_orchestrator.graph.domain_agent import GroupAnalysis
from cloudops_orchestrator.llm.budget import BudgetExceeded, BudgetTracker
from cloudops_orchestrator.models.actions import TriageResult
from cloudops_orchestrator.models.enums import Domain, FindingStatus, Severity, TriageVerdict
from cloudops_orchestrator.models.findings import Finding, FindingGroup
from cloudops_orchestrator.models.report import LLMUsage, ModelUsage
from cloudops_orchestrator.steps.aggregate import (
    aggregate,
    build_report_items,
    compute_counts,
    generate_executive_summary,
)
from cloudops_orchestrator.steps.run_domain_batch import DomainBatchResult

REPO_ROOT = Path(__file__).resolve().parents[2]
SETTINGS = load_settings(REPO_ROOT / "config" / "settings.local.yaml", env={})


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
        "verdict": TriageVerdict.NEEDS_HUMAN,
        "adjusted_severity": Severity.HIGH,
        "rationale": "r",
        "citations": [],
        "sop_gap": True,
    }
    defaults.update(overrides)
    return TriageResult(**defaults)  # type: ignore[arg-type]


class TestComputeCounts:
    def test_counts_by_domain_and_status(self) -> None:
        findings = [
            _finding(fingerprint="a" * 32, status=FindingStatus.NEW),
            _finding(
                fingerprint="b" * 32,
                status=FindingStatus.OPEN,
                domain=Domain.COST,
                rule_id="X",
                resource_type="Y",
            ),
        ]
        counts = compute_counts(findings)
        assert counts[Domain.SECURITY][FindingStatus.NEW] == 1
        assert counts[Domain.COST][FindingStatus.OPEN] == 1
        assert counts[Domain.DRIFT][FindingStatus.NEW] == 0

    def test_all_domains_present_even_if_empty(self) -> None:
        counts = compute_counts([])
        assert set(counts) == {Domain.SECURITY, Domain.COST, Domain.DRIFT}


class TestBuildReportItems:
    def test_item_priority_uses_max_of_group_findings(self) -> None:
        finding = _finding()
        result = DomainBatchResult(
            batch_id="b1",
            domain="security",
            analyses=[GroupAnalysis(group=_group(), triage=_triage(), recommendation=None)],
            budget_exhausted=False,
            cost_usd=0.0,
        )
        items = build_report_items(
            [result],
            findings_by_fingerprint={finding.fingerprint: finding},
            now=datetime(2026, 1, 1, tzinfo=UTC),
        )
        assert len(items) == 1
        assert items[0].priority_score > 0

    def test_items_sorted_by_priority_descending(self) -> None:
        low = GroupAnalysis(
            group=_group(group_id="low", max_severity=Severity.LOW, findings=["a" * 32]),
            triage=_triage(group_id="low", adjusted_severity=Severity.LOW),
            recommendation=None,
        )
        high = GroupAnalysis(
            group=_group(group_id="high", max_severity=Severity.CRITICAL, findings=["b" * 32]),
            triage=_triage(group_id="high", adjusted_severity=Severity.CRITICAL),
            recommendation=None,
        )
        findings_by_fp = {
            "a" * 32: _finding(fingerprint="a" * 32, severity=Severity.LOW),
            "b" * 32: _finding(
                fingerprint="b" * 32, severity=Severity.CRITICAL, resource_id="sg-2"
            ),
        }
        result = DomainBatchResult(
            batch_id="b1",
            domain="security",
            analyses=[low, high],
            budget_exhausted=False,
            cost_usd=0.0,
        )
        items = build_report_items(
            [result], findings_by_fingerprint=findings_by_fp, now=datetime(2026, 1, 1, tzinfo=UTC)
        )
        assert items[0].group_id == "high"
        assert items[1].group_id == "low"


def _batch(batch_id: str, cost: float) -> DomainBatchResult:
    return DomainBatchResult(
        batch_id=batch_id,
        domain="security",
        analyses=[GroupAnalysis(group=_group(), triage=_triage(), recommendation=None)],
        budget_exhausted=False,
        cost_usd=cost,
        usage=LLMUsage(
            per_model={"claude-haiku-4-5-20251001": ModelUsage(input_tokens=500, cost_usd=cost)},
            total_cost_usd=cost,
        ),
    )


class TestAggregateCost:
    def test_report_usage_includes_every_batchs_spend(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "cloudops_orchestrator.steps.aggregate.generate_executive_summary",
            lambda **_kwargs: "summary",
        )
        budget = BudgetTracker(config=SETTINGS.llm, max_cost_usd_per_run=2.0)

        report = aggregate(
            run_id="run-1",
            started_at=datetime(2026, 1, 1, tzinfo=UTC),
            finished_at=datetime(2026, 1, 1, 1, tzinfo=UTC),
            domain_results=[_batch("b1", 0.10), _batch("b2", 0.15)],
            findings=[_finding()],
            summary_model=None,
            summary_model_name="claude-sonnet-5",
            budget=budget,
        )

        assert report.llm_usage.total_cost_usd == pytest.approx(0.25)
        assert report.llm_usage.per_model["claude-haiku-4-5-20251001"].input_tokens == 1000

    def test_summary_falls_back_instead_of_failing_when_the_budget_is_exhausted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def _raise(*_args: object, **_kwargs: object) -> object:
            raise BudgetExceeded(2.5, 2.0)

        monkeypatch.setattr("cloudops_orchestrator.steps.aggregate.call_structured", _raise)
        budget = BudgetTracker(config=SETTINGS.llm, max_cost_usd_per_run=2.0)

        summary = generate_executive_summary(
            model=None,
            items=[],
            counts=compute_counts([]),
            budget=budget,
            model_name="claude-sonnet-5",
            run_id="run-1",
        )

        assert "budget was exhausted" in summary
