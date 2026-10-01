"""``DomainBatch`` step: run the domain agent graph over one batch.

``analyze_group`` never raises (a group's own failure becomes a NEEDS_HUMAN
result — see graph/domain_agent.py), including a ``BudgetExceeded`` from
inside a structured LLM call: it's caught there too, so once the run budget
is exhausted every remaining group in the batch degrades to NEEDS_HUMAN
automatically. This step only needs to check the shared ``BudgetTracker``
afterward to flag the batch (and, upstream, the report) as partial.
"""

from __future__ import annotations

from dataclasses import dataclass

from cloudops_orchestrator.graph.domain_agent import (
    DomainAgentDeps,
    GroupAnalysis,
    run_domain_graph,
)
from cloudops_orchestrator.steps.plan_batches import Batch


@dataclass(frozen=True)
class DomainBatchResult:
    batch_id: str
    domain: str
    analyses: list[GroupAnalysis]
    budget_exhausted: bool
    cost_usd: float


def run_domain_batch(batch: Batch, *, deps: DomainAgentDeps) -> DomainBatchResult:
    analyses = run_domain_graph(batch.groups, deps=deps)
    return DomainBatchResult(
        batch_id=batch.batch_id,
        domain=batch.domain.value,
        analyses=analyses,
        budget_exhausted=deps["budget"].budget_exhausted,
        cost_usd=deps["budget"].total_cost_usd,
    )


__all__ = ["DomainBatchResult", "run_domain_batch"]
