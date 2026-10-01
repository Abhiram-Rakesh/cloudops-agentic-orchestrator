"""Cost Anomaly Detection collector (``ce:GetAnomalies``, 14-day lookback).

Fixture: ``{fixtures_dir}/cost_anomaly/anomalies.json`` (absent/empty is a
valid "no anomalies" result). ``rule_id=COST-ANOMALY`` maps to COST-004-4.1
(``notify_owner`` / T0 — report only, no automated action).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

from cloudops_orchestrator.collectors.base import CollectorContext, CollectorResult
from cloudops_orchestrator.models.enums import Domain, FindingStatus, Severity
from cloudops_orchestrator.models.findings import Finding
from cloudops_orchestrator.normalize.fingerprint import standard_fingerprint

SOURCE = "cost_anomaly"
RULE_ID = "COST-ANOMALY"


def _parse_time(value: str | None, fallback: datetime) -> datetime:
    if not value:
        return fallback
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return fallback


def _load_raw_anomalies(ctx: CollectorContext) -> list[dict[str, Any]]:
    if ctx.fixtures_dir is not None:
        path = ctx.fixtures_dir / "cost_anomaly" / "anomalies.json"
        if not path.exists():
            return []
        result: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))
        return result

    from cloudops_orchestrator.aws.clients import get_client

    client = get_client("ce", region_name="us-east-1")  # Cost Explorer is a global/us-east-1 API
    lookback_days = ctx.settings.collectors.cost_anomaly.lookback_days
    start = (ctx.now - timedelta(days=lookback_days)).date().isoformat()
    end = ctx.now.date().isoformat()
    response = client.get_anomalies(DateInterval={"StartDate": start, "EndDate": end})
    anomalies: list[dict[str, Any]] = response.get("Anomalies", [])
    return anomalies


def parse_anomaly(raw: dict[str, Any], *, ctx: CollectorContext) -> Finding:
    anomaly_id: str = raw.get("AnomalyId", "unknown")
    impact = raw.get("Impact", {}).get("TotalImpact", 0.0)
    dimension_value = raw.get("DimensionValue", "unknown-service")

    fingerprint = standard_fingerprint(
        domain=Domain.COST,
        source=SOURCE,
        account_id=ctx.account.id,
        region=ctx.settings.aws.region,
        resource_id=dimension_value,
        rule_id=RULE_ID,
    )

    return Finding(
        fingerprint=fingerprint,
        domain=Domain.COST,
        source=SOURCE,
        sources=[SOURCE],
        rule_id=RULE_ID,
        control_ids=[RULE_ID],
        title=f"Cost anomaly detected for {dimension_value}",
        description=f"AWS Cost Anomaly Detection reports a ${impact:.2f} anomaly for {dimension_value}.",
        severity=Severity.MEDIUM,
        account_id=ctx.account.id,
        region=ctx.settings.aws.region,
        resource_type="CostAnomaly",
        resource_id=dimension_value,
        details={"total_impact_usd": impact},
        evidence_uri=f"s3://{ctx.settings.storage.bucket}/evidence/{ctx.run_id}/cost_anomaly/{anomaly_id}.json",
        first_seen=_parse_time(raw.get("AnomalyStartDate"), ctx.now),
        last_seen=_parse_time(raw.get("AnomalyEndDate"), ctx.now),
        status=FindingStatus.NEW,
    )


def collect(ctx: CollectorContext) -> CollectorResult:
    config = ctx.settings.collectors.cost_anomaly
    if not config.enabled:
        return CollectorResult()

    raw_anomalies = _load_raw_anomalies(ctx)
    findings = [parse_anomaly(raw, ctx=ctx) for raw in raw_anomalies]
    return CollectorResult(findings=findings, raw_evidence={"cost_anomalies": raw_anomalies})


__all__ = ["RULE_ID", "SOURCE", "collect", "parse_anomaly"]
