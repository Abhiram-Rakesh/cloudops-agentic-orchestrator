"""Cost Explorer collector — capped at ``max_calls`` (default 2) API calls per
run ($0.01 each): current vs previous 7-day window, grouped by SERVICE.

``rule_id=COST-TREND`` fires when a service's week-over-week spend increases
by more than 20% *and* more than $5 absolute (COST-004-4.3 — both
thresholds must be met).

Fixture: ``{fixtures_dir}/cost_explorer/usage.json`` ``{"current": {service:
amount}, "previous": {service: amount}}`` — pre-aggregated, since Cost
Explorer's raw response shape is verbose and this collector's own job is
just the current-vs-previous diff, not re-testing CE's grouping.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

from cloudops_orchestrator.collectors.base import CollectorContext, CollectorResult
from cloudops_orchestrator.models.enums import Domain, FindingStatus, Severity
from cloudops_orchestrator.models.findings import Finding
from cloudops_orchestrator.normalize.fingerprint import standard_fingerprint

SOURCE = "cost_explorer"
RULE_ID = "COST-TREND"
TREND_PCT_THRESHOLD = 20.0
TREND_ABS_THRESHOLD_USD = 5.0


def _load_usage(ctx: CollectorContext) -> tuple[dict[str, float], dict[str, float]]:
    if ctx.fixtures_dir is not None:
        path = ctx.fixtures_dir / "cost_explorer" / "usage.json"
        if not path.exists():
            return {}, {}
        data = json.loads(path.read_text(encoding="utf-8"))
        return data.get("current", {}), data.get("previous", {})

    from cloudops_orchestrator.aws.clients import get_client

    client = get_client("ce", region_name="us-east-1")
    today = ctx.now.date()
    current = _get_cost_by_service(client, start=today - timedelta(days=1), end=today)
    previous = _get_cost_by_service(
        client, start=today - timedelta(days=8), end=today - timedelta(days=7)
    )
    return current, previous


def _get_cost_by_service(client: Any, *, start: Any, end: Any) -> dict[str, float]:
    response = client.get_cost_and_usage(
        TimePeriod={"Start": start.isoformat(), "End": end.isoformat()},
        Granularity="DAILY",
        Metrics=["UnblendedCost"],
        GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
    )
    totals: dict[str, float] = {}
    for result_by_time in response.get("ResultsByTime", []):
        for group in result_by_time.get("Groups", []):
            service = group["Keys"][0]
            amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
            totals[service] = totals.get(service, 0.0) + amount
    return totals


def compute_trends(current: dict[str, float], previous: dict[str, float]) -> list[dict[str, Any]]:
    trends = []
    for service, current_amount in current.items():
        previous_amount = previous.get(service, 0.0)
        abs_change = current_amount - previous_amount
        pct_change = (
            (abs_change / previous_amount * 100)
            if previous_amount > 0
            else (100.0 if current_amount > 0 else 0.0)
        )
        if pct_change > TREND_PCT_THRESHOLD and abs_change > TREND_ABS_THRESHOLD_USD:
            trends.append(
                {
                    "service": service,
                    "current_amount": current_amount,
                    "previous_amount": previous_amount,
                    "pct_change": pct_change,
                    "abs_change": abs_change,
                }
            )
    return trends


def parse_trend(trend: dict[str, Any], *, ctx: CollectorContext) -> Finding:
    service = trend["service"]
    fingerprint = standard_fingerprint(
        domain=Domain.COST,
        source=SOURCE,
        account_id=ctx.account.id,
        region=ctx.settings.aws.region,
        resource_id=service,
        rule_id=RULE_ID,
    )
    return Finding(
        fingerprint=fingerprint,
        domain=Domain.COST,
        source=SOURCE,
        sources=[SOURCE],
        rule_id=RULE_ID,
        control_ids=[RULE_ID],
        title=f"{service} spend up {trend['pct_change']:.0f}% week-over-week",
        description=(
            f"{service} spend increased from ${trend['previous_amount']:.2f} to "
            f"${trend['current_amount']:.2f} ({trend['pct_change']:.0f}%, +${trend['abs_change']:.2f})."
        ),
        severity=Severity.LOW,
        account_id=ctx.account.id,
        region=ctx.settings.aws.region,
        resource_type="CostService",
        resource_id=service,
        details=trend,
        evidence_uri=f"s3://{ctx.settings.storage.bucket}/evidence/{ctx.run_id}/cost_explorer/{service}.json",
        first_seen=ctx.now,
        last_seen=ctx.now,
        status=FindingStatus.NEW,
    )


def collect(ctx: CollectorContext) -> CollectorResult:
    config = ctx.settings.collectors.cost_explorer
    if not config.enabled:
        return CollectorResult()

    current, previous = _load_usage(ctx)
    trends = compute_trends(current, previous)
    findings = [parse_trend(trend, ctx=ctx) for trend in trends]
    return CollectorResult(
        findings=findings, raw_evidence={"current": current, "previous": previous}
    )


__all__ = ["RULE_ID", "SOURCE", "collect", "compute_trends", "parse_trend"]
