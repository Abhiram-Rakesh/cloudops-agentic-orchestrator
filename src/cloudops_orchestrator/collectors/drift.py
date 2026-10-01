"""Drift collector — one finding per ``resource_drift`` entry (``DRIFT-ATTR``).

Live: ``s3://<bucket>/<prefix><workspace>/plan.json`` (+ ``inventory.json``,
uploaded by ``drift.yml``). Fixture: ``{fixtures_dir}/drift/plan.json``.
An empty/missing plan (workspace not deployed, e.g. the demo is down) is an
informational note, not a finding — see ``README.md (How it works)``. Staleness
(> ``max_age_days``) is a report warning.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from cloudops_orchestrator.collectors.base import CollectorContext, CollectorResult
from cloudops_orchestrator.config import DriftWorkspaceConfig
from cloudops_orchestrator.models.enums import Domain, FindingStatus, Severity
from cloudops_orchestrator.models.findings import Finding
from cloudops_orchestrator.normalize.fingerprint import standard_fingerprint

SOURCE = "drift"
RULE_ID = "DRIFT-ATTR"


def _parse_time(value: str | None, fallback: datetime) -> datetime:
    if not value:
        return fallback
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return fallback


def _load_plan(ctx: CollectorContext, workspace: DriftWorkspaceConfig) -> dict[str, Any] | None:
    if ctx.fixtures_dir is not None:
        path = ctx.fixtures_dir / "drift" / "plan.json"
        if not path.exists():
            return None
        result: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        return result

    from cloudops_orchestrator.aws.clients import get_s3_client

    client = get_s3_client(region_name=ctx.settings.aws.region)
    prefix = ctx.settings.collectors.drift.prefix.rstrip("/")
    key = f"{prefix}/{workspace.name}/plan.json"
    try:
        response = client.get_object(Bucket=ctx.settings.storage.bucket, Key=key)
    except client.exceptions.NoSuchKey:
        return None
    loaded: dict[str, Any] = json.loads(response["Body"].read())
    return loaded


def parse_drift_entry(
    entry: dict[str, Any], *, ctx: CollectorContext, workspace: DriftWorkspaceConfig
) -> Finding:
    # Terraform's plan JSON puts `address`/`type`/`change.actions` directly on
    # each `resource_drift` entry -- there is no nested "resource" sub-object.
    # Found live 2026-09-29: 4 real drift entries all defaulted to
    # resource_id="unknown", so `merge_duplicate_findings` collapsed them into
    # one degenerate finding (see README.md (Troubleshooting)).
    address: str = entry.get("address", "unknown")
    resource_type: str = entry.get("type", "Other")
    actions: list[str] = entry.get("change", {}).get("actions", [])

    fingerprint = standard_fingerprint(
        domain=Domain.DRIFT,
        source=SOURCE,
        account_id=ctx.account.id,
        region=ctx.settings.aws.region,
        resource_id=address,
        rule_id=RULE_ID,
    )

    return Finding(
        fingerprint=fingerprint,
        domain=Domain.DRIFT,
        source=SOURCE,
        sources=[SOURCE],
        rule_id=RULE_ID,
        control_ids=[RULE_ID],
        title=f"Drift detected on {address}",
        description=entry.get("notes", f"{address} differs from its Terraform-defined state."),
        severity=Severity.MEDIUM,
        account_id=ctx.account.id,
        region=ctx.settings.aws.region,
        resource_type=resource_type,
        resource_id=address,
        iac_managed=True,
        iac_address=address,
        details={"actions": actions, "workspace": workspace.name},
        evidence_uri=f"s3://{ctx.settings.storage.bucket}/evidence/{ctx.run_id}/drift/{workspace.name}/{address}.json",
        first_seen=_parse_time(entry.get("detected_at"), ctx.now),
        last_seen=_parse_time(entry.get("detected_at"), ctx.now),
        status=FindingStatus.NEW,
    )


def collect(ctx: CollectorContext) -> CollectorResult:
    config = ctx.settings.collectors.drift
    if not config.enabled:
        return CollectorResult()

    findings: list[Finding] = []
    warnings: list[str] = []
    raw_evidence: dict[str, Any] = {}

    for workspace in config.workspaces:
        plan = _load_plan(ctx, workspace)
        raw_evidence[workspace.name] = plan
        if plan is None:
            warnings.append(f"drift: workspace {workspace.name!r} not deployed — no plan data.")
            continue
        for entry in plan.get("resource_drift", []):
            findings.append(parse_drift_entry(entry, ctx=ctx, workspace=workspace))

    return CollectorResult(findings=findings, raw_evidence=raw_evidence, warnings=warnings)


__all__ = ["RULE_ID", "SOURCE", "collect", "parse_drift_entry"]
