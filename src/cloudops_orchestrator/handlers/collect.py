"""``collect`` Lambda: runs every enabled collector, writes findings
and per-domain groups to S3 for later steps, and returns only
``{run_id, batches}`` (small enough to fit a Step Functions payload).

Real AWS wiring only; not exercised by tests — ``steps/collect.py``'s
``run_collect`` and ``steps/plan_batches.py``'s ``plan_batches`` carry the
tested logic.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    import os

    from cloudops_orchestrator.aws.clients import get_s3_client
    from cloudops_orchestrator.config import load_settings
    from cloudops_orchestrator.steps.collect import run_collect
    from cloudops_orchestrator.steps.plan_batches import plan_batches
    from cloudops_orchestrator.steps.serialization import (
        serialize_findings,
        serialize_groups,
        serialize_masker,
    )
    from cloudops_orchestrator.store.client import get_table

    settings = load_settings(os.environ.get("CLOUDOPS_CONFIG", "config/settings.dev.yaml"))
    run_id = event["run_id"]
    account = settings.aws.accounts[0]
    now = datetime.now(UTC)
    table = get_table(settings)

    result = run_collect(
        run_id=run_id,
        settings=settings,
        account=account,
        now=now,
        fixtures_dir=None,
        table=table,
    )

    s3 = get_s3_client(region_name=settings.aws.region)
    bucket = settings.storage.bucket
    s3.put_object(
        Bucket=bucket,
        Key=f"runs/{run_id}/findings.json",
        Body=serialize_findings(result.findings).encode("utf-8"),
        ContentType="application/json",
    )
    for domain, groups in result.groups_by_domain.items():
        s3.put_object(
            Bucket=bucket,
            Key=f"runs/{run_id}/groups/{domain.value}.json",
            Body=serialize_groups(groups).encode("utf-8"),
            ContentType="application/json",
        )
    # domain_batch (a separate Lambda invocation) needs this same masker's
    # reverse mapping to unmask() any token an LLM echoes back — see
    # normalize/masking.py's class docstring.
    s3.put_object(
        Bucket=bucket,
        Key=f"runs/{run_id}/masker.json",
        Body=serialize_masker(result.masker).encode("utf-8"),
        ContentType="application/json",
    )

    batches = plan_batches(
        result.groups_by_domain, max_groups_per_batch=settings.orchestration.max_groups_per_batch
    )
    return {
        "run_id": run_id,
        # Collect's Task state has no ResultPath in the ASL, so this return
        # value REPLACES the entire Step Functions state (the default `$`)
        # rather than merging into it -- started_at (set by InitRun) must be
        # threaded through here or Aggregate can't find it. Found live:
        # aggregate failed with KeyError: 'started_at' on the first run to
        # ever reach it, since nothing before this surfaced the gap (see
        # README.md (Troubleshooting)).
        "started_at": event["started_at"],
        "warnings": result.warnings,
        "batches": [{"domain": b.domain.value, "batch_id": b.batch_id} for b in batches],
    }


__all__ = ["lambda_handler"]
