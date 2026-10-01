from __future__ import annotations

from cloudops_orchestrator.graph.domains.base import DomainSpec
from cloudops_orchestrator.models.enums import Domain

COST_SPEC = DomainSpec(
    domain=Domain.COST,
    guidance="""
When triaging, distinguish **expected spend** (a documented, business-
justified cost — a planned load test, a seasonal promotion) from
**unexpected spend** (no plausible business justification visible in the
finding's tags or details). Only mark a cost anomaly `accepted_risk` if the
finding's own details indicate a known cause; otherwise triage it as
`actionable` or `needs_human` so a human makes the expected/unexpected call,
per COST-004-4.1.

When recommending, estimate `estimated_monthly_savings_usd` using the
resource's known size/type and Meridian's ap-south-1 price table where
available; if you cannot produce a defensible estimate from the data given,
leave it null rather than guessing a number. For non-production scheduling
findings, recommend `office-hours` (09:00-21:00 IST Mon-Fri) unless the
finding's tags suggest a different pattern is already in use elsewhere on
the same resource family.
""".strip(),
)

__all__ = ["COST_SPEC"]
