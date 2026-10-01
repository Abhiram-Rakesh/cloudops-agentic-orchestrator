"""Tests for the smaller collectors: access_analyzer, cost_anomaly,
cost_explorer, cloudtrail, and the registry that ties everything together.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from cloudops_orchestrator.collectors import (
    access_analyzer,
    cloudtrail,
    cost_anomaly,
    cost_explorer,
)
from cloudops_orchestrator.collectors.base import CollectorContext
from cloudops_orchestrator.collectors.registry import ALL_COLLECTORS, collect_all
from cloudops_orchestrator.config import load_settings
from cloudops_orchestrator.normalize.masking import Masker

REPO_ROOT = Path(__file__).resolve().parents[2]


def _ctx(fixtures_dir: Path) -> CollectorContext:
    settings = load_settings(REPO_ROOT / "config" / "settings.local.yaml", env={})
    return CollectorContext(
        run_id="run-1",
        settings=settings,
        account=settings.aws.accounts[0],
        now=datetime(2026, 1, 27, tzinfo=UTC),
        fixtures_dir=fixtures_dir,
    )


class TestAccessAnalyzer:
    def test_no_fixture_file_returns_empty(self, tmp_path: Path) -> None:
        assert access_analyzer.collect(_ctx(tmp_path)).findings == []

    def test_parses_finding(self, tmp_path: Path) -> None:
        (tmp_path / "access_analyzer").mkdir()
        data = [
            {
                "id": "f1",
                "resource": "arn:aws:s3:::bucket",
                "resourceType": "AWS::S3::Bucket",
                "tags": {},
            }
        ]
        (tmp_path / "access_analyzer" / "findings.json").write_text(json.dumps(data))
        result = access_analyzer.collect(_ctx(tmp_path))
        assert len(result.findings) == 1
        assert result.findings[0].rule_id == access_analyzer.RULE_ID


class TestCostAnomaly:
    def test_no_fixture_file_returns_empty(self, tmp_path: Path) -> None:
        assert cost_anomaly.collect(_ctx(tmp_path)).findings == []

    def test_parses_anomaly(self, tmp_path: Path) -> None:
        (tmp_path / "cost_anomaly").mkdir()
        data = [
            {
                "AnomalyId": "a1",
                "DimensionValue": "AmazonEC2",
                "Impact": {"TotalImpact": 12.5},
                "AnomalyStartDate": "2026-01-20T00:00:00Z",
                "AnomalyEndDate": "2026-01-21T00:00:00Z",
            }
        ]
        (tmp_path / "cost_anomaly" / "anomalies.json").write_text(json.dumps(data))
        result = cost_anomaly.collect(_ctx(tmp_path))
        assert len(result.findings) == 1
        assert result.findings[0].details["total_impact_usd"] == 12.5


class TestCostExplorer:
    def test_compute_trends_flags_large_pct_and_abs_change(self) -> None:
        current = {"AmazonEC2": 20.0}
        previous = {"AmazonEC2": 10.0}
        trends = cost_explorer.compute_trends(current, previous)
        assert len(trends) == 1
        assert trends[0]["service"] == "AmazonEC2"

    def test_small_absolute_change_not_flagged_despite_large_pct(self) -> None:
        current = {"TinyService": 3.0}
        previous = {"TinyService": 1.0}  # +200% but only +$2
        assert cost_explorer.compute_trends(current, previous) == []

    def test_small_pct_change_not_flagged_despite_large_abs(self) -> None:
        current = {"BigService": 510.0}
        previous = {"BigService": 500.0}  # +2% but +$10
        assert cost_explorer.compute_trends(current, previous) == []

    def test_new_service_with_no_previous_spend_flagged(self) -> None:
        current = {"NewService": 10.0}
        previous: dict[str, float] = {}
        trends = cost_explorer.compute_trends(current, previous)
        assert len(trends) == 1

    def test_collect_from_fixture(self, tmp_path: Path) -> None:
        (tmp_path / "cost_explorer").mkdir()
        data = {"current": {"AmazonEC2": 20.0}, "previous": {"AmazonEC2": 10.0}}
        (tmp_path / "cost_explorer" / "usage.json").write_text(json.dumps(data))
        result = cost_explorer.collect(_ctx(tmp_path))
        assert len(result.findings) == 1
        assert result.findings[0].rule_id == "COST-TREND"

    def test_no_fixture_file_returns_empty(self, tmp_path: Path) -> None:
        assert cost_explorer.collect(_ctx(tmp_path)).findings == []


class _FakeLookupPaginator:
    def __init__(self, pages: list[dict[str, object]]) -> None:
        self.pages = pages
        self.kwargs: dict[str, object] = {}

    def paginate(self, **kwargs: object) -> object:
        self.kwargs = kwargs
        return iter(self.pages)


class _FakeCloudtrailClient:
    def __init__(self, paginator: _FakeLookupPaginator) -> None:
        self.paginator = paginator

    def get_paginator(self, name: str) -> _FakeLookupPaginator:
        assert name == "lookup_events"
        return self.paginator


class TestCloudtrailLive:
    def _live_ctx(self, tmp_path: Path, max_seconds: int = 240) -> CollectorContext:
        ctx = _ctx(tmp_path)
        cloudtrail_config = ctx.settings.collectors.cloudtrail.model_copy(
            update={"max_seconds": max_seconds}
        )
        collectors = ctx.settings.collectors.model_copy(update={"cloudtrail": cloudtrail_config})
        settings = ctx.settings.model_copy(update={"collectors": collectors})
        return CollectorContext(
            run_id=ctx.run_id,
            settings=settings,
            account=ctx.account,
            now=ctx.now,
            fixtures_dir=None,
        )

    def test_requests_write_events_only_in_the_lookback_window(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        paginator = _FakeLookupPaginator([{"Events": [{"EventName": "RunInstances"}]}])
        monkeypatch.setattr(
            "cloudops_orchestrator.aws.clients.get_client",
            lambda *_a, **_k: _FakeCloudtrailClient(paginator),
        )
        ctx = self._live_ctx(tmp_path)

        result = cloudtrail.collect(ctx)

        assert result.raw_evidence["events"] == [{"EventName": "RunInstances"}]
        assert result.warnings == []
        assert paginator.kwargs["LookupAttributes"] == [
            {"AttributeKey": "ReadOnly", "AttributeValue": "false"}
        ]
        assert paginator.kwargs["EndTime"] == ctx.now
        assert paginator.kwargs["StartTime"] == ctx.now - timedelta(
            days=ctx.settings.collectors.cloudtrail.lookback_days
        )

    def test_time_budget_stops_pagination_with_a_warning(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pages: list[dict[str, object]] = [{"Events": [{"EventName": f"E{i}"}]} for i in range(5)]
        paginator = _FakeLookupPaginator(pages)
        monkeypatch.setattr(
            "cloudops_orchestrator.aws.clients.get_client",
            lambda *_a, **_k: _FakeCloudtrailClient(paginator),
        )

        result = cloudtrail.collect(self._live_ctx(tmp_path, max_seconds=0))

        assert len(result.raw_evidence["events"]) == 1  # stopped after the first page
        assert any("CloudTrail lookup stopped" in w for w in result.warnings)


class TestCloudtrail:
    def test_no_findings_ever_produced(self, tmp_path: Path) -> None:
        result = cloudtrail.collect(_ctx(tmp_path))
        assert result.findings == []

    def test_find_attribution_matches_resource(self) -> None:
        events = [
            {
                "Username": "alice",
                "EventName": "AuthorizeSecurityGroupIngress",
                "EventTime": "2026-01-20T00:00:00Z",
                "SourceIPAddress": "203.0.113.5",
                "Resources": [{"ResourceName": "sg-1"}],
            }
        ]
        attribution = cloudtrail.find_attribution(events, resource_id="sg-1", masker=Masker())
        assert attribution is not None
        assert attribution["actor"] == "alice"

    def test_find_attribution_no_match(self) -> None:
        assert cloudtrail.find_attribution([], resource_id="sg-1", masker=Masker()) is None


class TestRegistry:
    def test_all_collectors_registered(self) -> None:
        expected = {
            "security_hub",
            "prowler",
            "access_analyzer",
            "cost_anomaly",
            "cost_explorer",
            "cost_waste",
            "drift",
            "iac_inventory",
            "cloudtrail",
        }
        assert set(ALL_COLLECTORS) == expected

    def test_collect_all_merges_across_collectors(self) -> None:
        result = collect_all(_ctx(REPO_ROOT / "tests" / "fixtures" / "scenario_demo"))
        assert len(result.findings) > 0
        # Every merged security finding lists both sources.
        security_findings = [f for f in result.findings if f.domain.value == "security"]
        assert all(set(f.sources) == {"securityhub", "prowler"} for f in security_findings)

    def test_collect_all_restricted_to_subset(self) -> None:
        result = collect_all(
            _ctx(REPO_ROOT / "tests" / "fixtures" / "scenario_demo"), only=["cost_waste"]
        )
        assert all(f.source == "cost_waste" for f in result.findings)
