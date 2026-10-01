"""Registry tying every collector together — used by ``steps/collect.py``
to run "every enabled collector" without hardcoding the list in more
than one place. Each collector already handles its own
``ctx.fixtures_dir`` branch (see each module's docstring), so
``collect_all`` behaves identically whether ``ctx`` is fixture- or
live-backed.
"""

from __future__ import annotations

from collections.abc import Callable

from cloudops_orchestrator.collectors import (
    access_analyzer,
    cloudtrail,
    cost_anomaly,
    cost_explorer,
    cost_waste,
    drift,
    iac_inventory,
    prowler,
    security_hub,
)
from cloudops_orchestrator.collectors.base import CollectorContext, CollectorResult
from cloudops_orchestrator.normalize.merge import merge_duplicate_findings

CollectorFn = Callable[[CollectorContext], CollectorResult]

# cloudtrail runs last conceptually (attribution enrichment consumes its
# raw_evidence) but order doesn't matter for `collect_all` itself, since
# each collector is independent and findings are merged by fingerprint
# afterward regardless of which order they were produced in.
ALL_COLLECTORS: dict[str, CollectorFn] = {
    "security_hub": security_hub.collect,
    "prowler": prowler.collect,
    "access_analyzer": access_analyzer.collect,
    "cost_anomaly": cost_anomaly.collect,
    "cost_explorer": cost_explorer.collect,
    "cost_waste": cost_waste.collect,
    "drift": drift.collect,
    "iac_inventory": iac_inventory.collect,
    "cloudtrail": cloudtrail.collect,
}


def collect_all(ctx: CollectorContext, *, only: list[str] | None = None) -> CollectorResult:
    """Run every (or a `only`-restricted subset of) collector(s) and merge duplicates."""
    names = only if only is not None else list(ALL_COLLECTORS)
    all_findings = []
    raw_evidence: dict[str, object] = {}
    warnings: list[str] = []

    for name in names:
        collector = ALL_COLLECTORS[name]
        result = collector(ctx)
        all_findings.extend(result.findings)
        raw_evidence[name] = result.raw_evidence
        warnings.extend(f"[{name}] {w}" for w in result.warnings)

    merged = merge_duplicate_findings(all_findings)
    return CollectorResult(findings=merged, raw_evidence=raw_evidence, warnings=warnings)


__all__ = ["ALL_COLLECTORS", "CollectorFn", "collect_all"]
