"""Merge duplicate findings sharing a fingerprint (e.g. Security Hub + Prowler
reporting the same control on the same resource) into one ``Finding``.

Called once per `collect` step, after every enabled collector has run and
before fingerprint/status upsert against the store.
"""

from __future__ import annotations

from cloudops_orchestrator.models.findings import Finding


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def merge_duplicate_findings(findings: list[Finding]) -> list[Finding]:
    merged: dict[str, Finding] = {}
    for finding in findings:
        existing = merged.get(finding.fingerprint)
        if existing is None:
            merged[finding.fingerprint] = finding.model_copy(
                update={"sources": _dedupe_preserve_order(finding.sources or [finding.source])}
            )
            continue

        merged[finding.fingerprint] = existing.model_copy(
            update={
                "sources": _dedupe_preserve_order(
                    [*existing.sources, *(finding.sources or [finding.source])]
                ),
                "control_ids": _dedupe_preserve_order(
                    [*existing.control_ids, *finding.control_ids]
                ),
                "severity": max(existing.severity, finding.severity),
                "first_seen": min(existing.first_seen, finding.first_seen),
                "last_seen": max(existing.last_seen, finding.last_seen),
            }
        )
    return list(merged.values())


__all__ = ["merge_duplicate_findings"]
