"""Group findings into ``FindingGroup``s — the unit of LLM work.

Findings sharing ``(domain, rule_id, resource_type)`` group together;
``group_id = sha256(domain|rule_id|resource_type)[:16]``. Each group carries
up to ``max_sample`` masked examples for the prompt (never full ``Finding``
objects — see ``normalize/masking.py``).
"""

from __future__ import annotations

import hashlib
from typing import Any

from cloudops_orchestrator.models.enums import Domain
from cloudops_orchestrator.models.findings import Finding, FindingGroup, MaskedFinding
from cloudops_orchestrator.normalize.masking import Masker

DEFAULT_MAX_SAMPLE = 5


def compute_group_id(*, domain: Domain, rule_id: str, resource_type: str) -> str:
    raw = f"{domain.value}|{rule_id}|{resource_type}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def _mask_details(details: dict[str, Any], masker: Masker) -> dict[str, Any]:
    return {key: masker.mask(str(value)) for key, value in details.items()}


def to_masked_finding(finding: Finding, masker: Masker) -> MaskedFinding:
    return MaskedFinding(
        fingerprint=finding.fingerprint,
        title=masker.mask(finding.title),
        description=masker.mask(finding.description),
        resource_type=finding.resource_type,
        masked_resource_id=masker.mask(finding.resource_id),
        control_ids=finding.control_ids,
        severity=finding.severity,
        masked_details=_mask_details(finding.details, masker),
        iac_managed=finding.iac_managed,
        iac_address=masker.mask(finding.iac_address) if finding.iac_address else None,
        environment=finding.environment,
    )


def group_findings(
    findings: list[Finding], *, masker: Masker, max_sample: int = DEFAULT_MAX_SAMPLE
) -> list[FindingGroup]:
    buckets: dict[str, list[Finding]] = {}
    for finding in findings:
        group_id = compute_group_id(
            domain=finding.domain, rule_id=finding.rule_id, resource_type=finding.resource_type
        )
        buckets.setdefault(group_id, []).append(finding)

    groups: list[FindingGroup] = []
    for group_id, bucket in buckets.items():
        first = bucket[0]
        control_ids = _dedupe_preserve_order([c for f in bucket for c in f.control_ids])
        max_severity = max(f.severity for f in bucket)
        sample = [to_masked_finding(f, masker) for f in bucket[:max_sample]]
        groups.append(
            FindingGroup(
                group_id=group_id,
                domain=first.domain,
                rule_id=first.rule_id,
                control_ids=control_ids,
                resource_type=first.resource_type,
                findings=[f.fingerprint for f in bucket],
                sample=sample,
                count=len(bucket),
                max_severity=max_severity,
            )
        )
    return groups


__all__ = ["DEFAULT_MAX_SAMPLE", "compute_group_id", "group_findings", "to_masked_finding"]
