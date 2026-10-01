"""``Collect`` step: run every enabled collector, enrich `iac_managed`
from the IaC inventory lookup, persist the NEW -> OPEN -> RESOLVED finding
lifecycle against the single-table store, and group findings per domain
for batching.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from cloudops_orchestrator.collectors.base import CollectorContext
from cloudops_orchestrator.collectors.registry import collect_all
from cloudops_orchestrator.config import AccountConfig, Settings
from cloudops_orchestrator.models.enums import Domain
from cloudops_orchestrator.models.findings import Finding, FindingGroup
from cloudops_orchestrator.normalize.grouping import group_findings
from cloudops_orchestrator.normalize.masking import Masker
from cloudops_orchestrator.store.findings import reconcile_resolved, upsert_finding


@dataclass
class CollectStepResult:
    findings: list[Finding]
    groups_by_domain: dict[Domain, list[FindingGroup]]
    # The masker actually used to build every group's masked samples --
    # callers MUST reuse this same instance (or its reverse_map(), across a
    # Lambda invocation boundary) when unmasking an LLM's response later, or
    # unmask() silently no-ops. See normalize/masking.py's class docstring.
    masker: Masker
    resolved: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    raw_evidence: dict[str, Any] = field(default_factory=dict)


def enrich_iac_managed(
    findings: list[Finding], *, inventory_lookup: dict[str, str]
) -> list[Finding]:
    """A finding whose resource_id appears in the Terraform inventory lookup
    is iac_managed, regardless of what its own collector already set —
    iac_inventory is the single source of truth for this field."""
    enriched: list[Finding] = []
    for finding in findings:
        address = inventory_lookup.get(finding.resource_id)
        if address is not None:
            enriched.append(
                finding.model_copy(update={"iac_managed": True, "iac_address": address})
            )
        else:
            enriched.append(finding)
    return enriched


def run_collect(
    *,
    run_id: str,
    settings: Settings,
    account: AccountConfig,
    now: datetime,
    fixtures_dir: Path | None,
    table: Any,
    masker: Masker | None = None,
) -> CollectStepResult:
    ctx = CollectorContext(
        run_id=run_id, settings=settings, account=account, now=now, fixtures_dir=fixtures_dir
    )
    result = collect_all(ctx)

    inventory_lookup: dict[str, str] = result.raw_evidence.get("iac_inventory", {}).get(
        "lookup", {}
    )
    findings = enrich_iac_managed(result.findings, inventory_lookup=inventory_lookup)

    # NEW -> OPEN -> RESOLVED lifecycle (store/findings.py): every collected
    # finding is upserted (first_seen preserved, status becomes NEW or OPEN),
    # then anything previously open for a domain that *wasn't* seen this run
    # is marked RESOLVED — one domain at a time, since reconcile_resolved's
    # "not seen" comparison is scoped per domain.
    persisted = [upsert_finding(table, finding) for finding in findings]
    resolved: list[str] = []
    seen_by_domain: dict[Domain, set[str]] = {domain: set() for domain in Domain}
    for finding in persisted:
        seen_by_domain[finding.domain].add(finding.fingerprint)
    # Every domain is reconciled every run (all enabled collectors run for
    # every domain), so a domain with zero findings this run correctly
    # resolves everything that was previously open for it.
    for domain, seen_fingerprints in seen_by_domain.items():
        resolved.extend(
            reconcile_resolved(table, domain=domain, seen_fingerprints=seen_fingerprints)
        )

    effective_masker = masker or Masker()
    groups = group_findings(persisted, masker=effective_masker)
    groups_by_domain: dict[Domain, list[FindingGroup]] = {}
    for group in groups:
        groups_by_domain.setdefault(group.domain, []).append(group)

    return CollectStepResult(
        findings=persisted,
        groups_by_domain=groups_by_domain,
        masker=effective_masker,
        resolved=sorted(resolved),
        warnings=result.warnings,
        raw_evidence=result.raw_evidence,
    )


__all__ = ["CollectStepResult", "enrich_iac_managed", "run_collect"]
