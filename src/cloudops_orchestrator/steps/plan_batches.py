"""Split each domain's groups into batches of at most
``orchestration.max_groups_per_batch`` (default 12) — the Step Functions
Map state fans out over these."""

from __future__ import annotations

from dataclasses import dataclass

from cloudops_orchestrator.models.enums import Domain
from cloudops_orchestrator.models.findings import FindingGroup


@dataclass(frozen=True)
class Batch:
    batch_id: str
    domain: Domain
    groups: list[FindingGroup]


def plan_batches(
    groups_by_domain: dict[Domain, list[FindingGroup]], *, max_groups_per_batch: int
) -> list[Batch]:
    batches: list[Batch] = []
    for domain, groups in groups_by_domain.items():
        for index in range(0, len(groups), max_groups_per_batch):
            chunk = groups[index : index + max_groups_per_batch]
            batch_number = index // max_groups_per_batch
            batches.append(
                Batch(batch_id=f"{domain.value}-{batch_number}", domain=domain, groups=chunk)
            )
    return batches


__all__ = ["Batch", "plan_batches"]
