"""IAM Access Analyzer collector — external-access findings only.

Live: ``accessanalyzer:ListFindings`` (status ACTIVE) against every analyzer
in the account. Fixture: ``{fixtures_dir}/access_analyzer/findings.json``
(absent/empty is a valid "nothing external" result, not an error).
``rule_id=ACCESS-ANALYZER-EXTERNAL`` maps to SEC-001-1.5.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from cloudops_orchestrator.collectors.base import CollectorContext, CollectorResult
from cloudops_orchestrator.models.enums import Domain, FindingStatus, Severity
from cloudops_orchestrator.models.findings import Finding
from cloudops_orchestrator.normalize.fingerprint import standard_fingerprint

SOURCE = "access_analyzer"
RULE_ID = "ACCESS-ANALYZER-EXTERNAL"


def _parse_time(value: str | datetime | None, fallback: datetime) -> datetime:
    if not value:
        return fallback
    # boto3 auto-converts "timestamp"-shaped API fields (e.g. Access
    # Analyzer's createdAt) to native datetime objects; only fixture JSON
    # (and string-shaped fields like Security Hub's ASFF CreatedAt) ever
    # hands this a str. Calling value.replace("Z", "+00:00") on a real
    # datetime resolves to datetime.replace(year="Z", ...) instead of a
    # string replace, raising "'str' object cannot be interpreted as an
    # integer" -- found live on the first real end-to-end run 2026-09-28
    # (see README.md (Troubleshooting); collectors/cloudtrail.py has the
    # identical bug for the same reason, EventTime is timestamp-shaped too).
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return fallback


def _load_raw_findings(ctx: CollectorContext) -> list[dict[str, Any]]:
    if ctx.fixtures_dir is not None:
        path = ctx.fixtures_dir / "access_analyzer" / "findings.json"
        if not path.exists():
            return []
        result: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))
        return result

    from cloudops_orchestrator.aws.clients import get_client

    client = get_client("accessanalyzer", region_name=ctx.settings.aws.region)
    analyzers = client.list_analyzers().get("analyzers", [])
    findings: list[dict[str, Any]] = []
    for analyzer in analyzers:
        paginator = client.get_paginator("list_findings")
        for page in paginator.paginate(
            analyzerArn=analyzer["arn"], filter={"status": {"eq": ["ACTIVE"]}}
        ):
            findings.extend(page["findings"])
    return findings


def parse_finding(raw: dict[str, Any], *, ctx: CollectorContext) -> Finding:
    resource_id: str = raw.get("resource", "unknown")
    resource_type: str = raw.get("resourceType", "Other")
    tags: dict[str, str] = raw.get("tags") or {}

    fingerprint = standard_fingerprint(
        domain=Domain.SECURITY,
        source=SOURCE,
        account_id=ctx.account.id,
        region=ctx.settings.aws.region,
        resource_id=resource_id,
        rule_id=RULE_ID,
    )

    return Finding(
        fingerprint=fingerprint,
        domain=Domain.SECURITY,
        source=SOURCE,
        sources=[SOURCE],
        rule_id=RULE_ID,
        control_ids=[RULE_ID],
        title="External access granted via resource policy",
        description=f"Access Analyzer reports external access to {resource_id}.",
        severity=Severity.HIGH,
        account_id=ctx.account.id,
        region=ctx.settings.aws.region,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_tags=tags,
        environment=tags.get("environment"),
        evidence_uri=f"s3://{ctx.settings.storage.bucket}/evidence/{ctx.run_id}/access_analyzer/{raw.get('id', 'unknown')}.json",
        first_seen=_parse_time(raw.get("createdAt"), ctx.now),
        last_seen=_parse_time(raw.get("updatedAt"), ctx.now),
        status=FindingStatus.NEW,
    )


def collect(ctx: CollectorContext) -> CollectorResult:
    config = ctx.settings.collectors.access_analyzer
    if not config.enabled:
        return CollectorResult()

    raw_findings = _load_raw_findings(ctx)
    findings = [parse_finding(raw, ctx=ctx) for raw in raw_findings]
    return CollectorResult(
        findings=findings, raw_evidence={"access_analyzer_findings": raw_findings}
    )


__all__ = ["RULE_ID", "SOURCE", "collect", "parse_finding"]
