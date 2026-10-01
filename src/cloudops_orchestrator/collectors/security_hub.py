"""Security Hub collector — Phase A only (``collectors.security_hub.enabled``).

Live: ``securityhub:GetFindings`` (paginated), filtered to
``RecordState=ACTIVE``, ``WorkflowStatus in {NEW, NOTIFIED}``,
``ComplianceStatus=FAILED`` (or a threat-type finding — GuardDuty findings
arrive into Security Hub this way), severity >= ``min_severity``.

Fixture: ``{fixtures_dir}/securityhub/findings.json`` (ASFF-lite — see
``scripts/gen_demo_artifacts.py``), same filtering/parsing code either way.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from cloudops_orchestrator.collectors.base import CollectorContext, CollectorResult
from cloudops_orchestrator.models.enums import Domain, FindingStatus, Severity
from cloudops_orchestrator.models.findings import Finding
from cloudops_orchestrator.normalize.fingerprint import security_finding_fingerprint

SOURCE = "securityhub"

_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFORMATIONAL": Severity.INFO,
}
_SEVERITY_RANK: dict[str, int] = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
    "INFORMATIONAL": -1,
}
_THREAT_TYPE_MARKERS = ("Threat", "Unusual Behaviors", "TTPs")


def _parse_time(value: str | None, fallback: datetime) -> datetime:
    if not value:
        return fallback
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return fallback


def _load_raw_findings(ctx: CollectorContext) -> list[dict[str, Any]]:
    if ctx.fixtures_dir is not None:
        path = ctx.fixtures_dir / "securityhub" / "findings.json"
        if not path.exists():
            return []
        result: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))
        return result

    from cloudops_orchestrator.aws.clients import get_client

    client = get_client("securityhub", region_name=ctx.settings.aws.region)
    filters = {
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        "WorkflowStatus": [
            {"Value": "NEW", "Comparison": "EQUALS"},
            {"Value": "NOTIFIED", "Comparison": "EQUALS"},
        ],
    }
    findings: list[dict[str, Any]] = []
    paginator = client.get_paginator("get_findings")
    for page in paginator.paginate(Filters=filters):
        findings.extend(page["Findings"])
    return findings


def _passes_filters(raw: dict[str, Any], *, min_severity_rank: int) -> bool:
    if raw.get("RecordState") != "ACTIVE":
        return False
    workflow_status = raw.get("WorkflowState") or raw.get("Workflow", {}).get("Status")
    if workflow_status not in ("NEW", "NOTIFIED"):
        return False

    compliance_status = raw.get("Compliance", {}).get("Status")
    types = raw.get("Types", [])
    is_threat_finding = any(marker in type_ for type_ in types for marker in _THREAT_TYPE_MARKERS)
    if compliance_status != "FAILED" and not is_threat_finding:
        return False

    severity_label = raw.get("Severity", {}).get("Label", "LOW")
    return _SEVERITY_RANK.get(severity_label, 0) >= min_severity_rank


def parse_finding(raw: dict[str, Any], *, ctx: CollectorContext) -> Finding:
    resources = raw.get("Resources") or [{}]
    resource = resources[0]
    resource_id: str = resource.get("Id", "unknown")
    resource_type: str = resource.get("Type", "Other")
    control_id: str = raw.get("Compliance", {}).get("SecurityControlId") or raw.get(
        "Title", "UNKNOWN"
    )
    severity = _SEVERITY_MAP.get(raw.get("Severity", {}).get("Label", "LOW"), Severity.LOW)
    tags: dict[str, str] = resource.get("Tags") or {}

    fingerprint = security_finding_fingerprint(
        account_id=ctx.account.id,
        region=ctx.settings.aws.region,
        resource_id=resource_id,
        control_id=control_id,
    )

    return Finding(
        fingerprint=fingerprint,
        domain=Domain.SECURITY,
        source=SOURCE,
        sources=[SOURCE],
        rule_id=control_id,
        control_ids=[control_id],
        title=raw.get("Title", control_id),
        description=raw.get("Description", ""),
        severity=severity,
        account_id=ctx.account.id,
        region=ctx.settings.aws.region,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_tags=tags,
        environment=tags.get("environment"),
        evidence_uri=(
            f"s3://{ctx.settings.storage.bucket}/evidence/{ctx.run_id}/securityhub/{raw.get('Id', 'unknown')}.json"
        ),
        first_seen=_parse_time(raw.get("CreatedAt"), ctx.now),
        last_seen=_parse_time(raw.get("UpdatedAt"), ctx.now),
        status=FindingStatus.NEW,
    )


def collect(ctx: CollectorContext) -> CollectorResult:
    config = ctx.settings.collectors.security_hub
    if not config.enabled:
        return CollectorResult()

    raw_findings = _load_raw_findings(ctx)
    min_rank = _SEVERITY_RANK.get(config.min_severity.upper(), 0)
    findings = [
        parse_finding(raw, ctx=ctx)
        for raw in raw_findings
        if _passes_filters(raw, min_severity_rank=min_rank)
    ]
    return CollectorResult(findings=findings, raw_evidence={"securityhub_findings": raw_findings})


__all__ = ["SOURCE", "collect", "parse_finding"]
