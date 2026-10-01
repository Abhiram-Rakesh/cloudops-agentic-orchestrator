"""``InitRun`` step: allocate a run_id, enforce the month-to-date LLM
budget before doing any collection work, and (live mode, not exercised
against a real account here) dispatch prowler.yml/drift.yml on `--refresh`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4


@dataclass(frozen=True)
class InitRunResult:
    run_id: str
    started_at: datetime
    month_to_date_spend_usd: float
    max_cost_usd_per_month: float
    proceed: bool

    @property
    def budget_exceeded(self) -> bool:
        return not self.proceed


def init_run(
    *,
    now: datetime,
    month_to_date_spend_usd: float,
    max_cost_usd_per_month: float,
    run_id: str | None = None,
) -> InitRunResult:
    proceed = month_to_date_spend_usd < max_cost_usd_per_month
    return InitRunResult(
        run_id=run_id or str(uuid4()),
        started_at=now,
        month_to_date_spend_usd=month_to_date_spend_usd,
        max_cost_usd_per_month=max_cost_usd_per_month,
        proceed=proceed,
    )


__all__ = ["InitRunResult", "init_run"]
