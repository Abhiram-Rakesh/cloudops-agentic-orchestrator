"""IaC inventory collector.

Two jobs: (1) expose a resource-id -> Terraform address lookup (built from
the latest ``inventory.json``) that ``steps/collect.py`` uses to set
``iac_managed``/``iac_address`` on every *other* collector's findings, and
(2) emit ``DRIFT-UNMANAGED`` findings for resources matching
``collectors.drift.unmanaged_selector`` that are absent from that inventory.

Live: the same ``inventory.json`` `drift.yml` uploads, plus EC2/S3 describe
calls filtered by the selector tag. Fixture:
``{fixtures_dir}/drift/inventory.json`` (managed) and
``{fixtures_dir}/drift/unmanaged.json`` (known-unmanaged, tagged resources)
— see ``scripts/gen_demo_artifacts.py``.
"""

from __future__ import annotations

import json
from typing import Any

from cloudops_orchestrator.collectors.base import CollectorContext, CollectorResult
from cloudops_orchestrator.models.enums import Domain, FindingStatus, Severity
from cloudops_orchestrator.models.findings import Finding
from cloudops_orchestrator.normalize.fingerprint import standard_fingerprint

SOURCE = "iac_inventory"
RULE_ID = "DRIFT-UNMANAGED"


def build_inventory_lookup(inventory: dict[str, Any]) -> dict[str, str]:
    """Map a resource's live id (``values.id``) to its Terraform address."""
    resources = inventory.get("root_module", {}).get("resources", [])
    return {r["values"]["id"]: r["address"] for r in resources if r.get("values", {}).get("id")}


def _load_inventory(ctx: CollectorContext) -> dict[str, Any]:
    if ctx.fixtures_dir is not None:
        path = ctx.fixtures_dir / "drift" / "inventory.json"
        if not path.exists():
            return {"root_module": {"resources": []}}
        result: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        return result

    from cloudops_orchestrator.aws.clients import get_s3_client

    client = get_s3_client(region_name=ctx.settings.aws.region)
    prefix = ctx.settings.collectors.drift.prefix.rstrip("/")
    workspace_names = [w.name for w in ctx.settings.collectors.drift.workspaces]
    combined: list[dict[str, Any]] = []
    for name in workspace_names:
        key = f"{prefix}/{name}/inventory.json"
        try:
            response = client.get_object(Bucket=ctx.settings.storage.bucket, Key=key)
        except client.exceptions.NoSuchKey:
            continue
        data = json.loads(response["Body"].read())
        combined.extend(data.get("root_module", {}).get("resources", []))
    return {"root_module": {"resources": combined}}


def _load_unmanaged_candidates(ctx: CollectorContext) -> list[dict[str, Any]]:
    """Resources matching the unmanaged_selector tag, regardless of IaC status.

    Live mode would run describe-* calls (EC2 instances/SGs/volumes/EIPs,
    S3 list-buckets + get-bucket-tagging) filtered by the selector tag; not
    yet implemented here (no live AWS calls made while building this repo —
    Hard Rule #2). Fixture mode supplies the already-filtered candidate set
    directly, since generating one is exactly what `demo/scripts/
    simulate_clickops.sh` does against a real account.
    """
    if ctx.fixtures_dir is not None:
        path = ctx.fixtures_dir / "drift" / "unmanaged.json"
        if not path.exists():
            return []
        result: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))
        return result
    return []


def parse_unmanaged_finding(raw: dict[str, Any], *, ctx: CollectorContext) -> Finding:
    resource_id: str = raw.get("resource_id", "unknown")
    resource_type: str = raw.get("resource_type", "Other")
    resource_name: str = raw.get("resource_name", resource_id)
    tags: dict[str, str] = raw.get("tags", {})

    fingerprint = standard_fingerprint(
        domain=Domain.DRIFT,
        source=SOURCE,
        account_id=ctx.account.id,
        region=ctx.settings.aws.region,
        resource_id=resource_id,
        rule_id=RULE_ID,
    )

    return Finding(
        fingerprint=fingerprint,
        domain=Domain.DRIFT,
        source=SOURCE,
        sources=[SOURCE],
        rule_id=RULE_ID,
        control_ids=[RULE_ID],
        title=f"{resource_name} is not managed by Terraform",
        description=f"{resource_name} is tagged {tags} but has no corresponding Terraform resource.",
        severity=Severity.MEDIUM,
        account_id=ctx.account.id,
        region=ctx.settings.aws.region,
        resource_type=resource_type,
        resource_id=resource_id,
        resource_tags=tags,
        environment=tags.get("environment"),
        iac_managed=False,
        evidence_uri=f"s3://{ctx.settings.storage.bucket}/evidence/{ctx.run_id}/iac_inventory/{resource_id}.json",
        first_seen=ctx.now,
        last_seen=ctx.now,
        status=FindingStatus.NEW,
    )


def collect(ctx: CollectorContext) -> CollectorResult:
    inventory = _load_inventory(ctx)
    lookup = build_inventory_lookup(inventory)
    candidates = _load_unmanaged_candidates(ctx)
    unmanaged = [c for c in candidates if c.get("resource_id") not in lookup]

    findings = [parse_unmanaged_finding(raw, ctx=ctx) for raw in unmanaged]
    return CollectorResult(
        findings=findings, raw_evidence={"inventory": inventory, "lookup": lookup}
    )


__all__ = ["RULE_ID", "SOURCE", "build_inventory_lookup", "collect", "parse_unmanaged_finding"]
