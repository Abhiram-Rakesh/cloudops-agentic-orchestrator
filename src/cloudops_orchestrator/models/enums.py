"""Enumerations shared across the domain model.

Field names and values here are a contract shared with the knowledge base
catalog (`knowledge_base/`), the policy engine config
(`config/policy/*.yaml`), and fixtures (`tests/fixtures/scenario_demo/`).
Do not rename without updating all three.
"""

from __future__ import annotations

from enum import StrEnum


class Domain(StrEnum):
    """The three operational domains agents reason about."""

    SECURITY = "security"
    COST = "cost"
    DRIFT = "drift"


class KBDomain(StrEnum):
    """SOP knowledge-base domain, which additionally allows ``shared``."""

    SECURITY = "security"
    COST = "cost"
    DRIFT = "drift"
    SHARED = "shared"


_SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 100,
    "high": 40,
    "medium": 15,
    "low": 5,
    "info": 1,
}


class Severity(StrEnum):
    """Ordered by severity weight, *not* alphabetically.

    ``StrEnum`` already inherits ``__lt__``/``__le__``/``__gt__``/``__ge__``
    from ``str`` (lexicographic), so ``functools.total_ordering`` is a no-op
    here — it only fills in comparisons a class doesn't already define, and
    all four already exist via inheritance. Every comparison is overridden
    explicitly below instead.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return _SEVERITY_WEIGHTS[self.value]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        # Higher weight = more severe; sort ascending by weight so
        # Severity.INFO < Severity.LOW < ... < Severity.CRITICAL.
        return self.weight < other.weight

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.weight <= other.weight

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.weight > other.weight

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.weight >= other.weight


class FindingStatus(StrEnum):
    NEW = "new"
    OPEN = "open"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


class TriageVerdict(StrEnum):
    ACTIONABLE = "actionable"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"
    NEEDS_HUMAN = "needs_human"


class ActionType(StrEnum):
    TERRAFORM_PR = "terraform_pr"
    TERRAFORM_REVERT_DISPATCH = "terraform_revert_dispatch"
    SSM_AUTOMATION = "ssm_automation"
    MANUAL_TICKET = "manual_ticket"
    NOTIFY_OWNER = "notify_owner"


_RISK_TIER_RANK: dict[str, int] = {"T0": 0, "T1": 1, "T2": 2, "T3": 3}


class RiskTier(StrEnum):
    """Ordered T0 < T1 < T2 < T3 (T3 = human-only, never automated).

    See ``Severity`` above for why all four comparisons are overridden
    explicitly rather than relying on ``functools.total_ordering``.
    """

    T0 = "T0"
    T1 = "T1"
    T2 = "T2"
    T3 = "T3"

    @property
    def rank(self) -> int:
        return _RISK_TIER_RANK[self.value]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, RiskTier):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, RiskTier):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, RiskTier):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, RiskTier):
            return NotImplemented
        return self.rank >= other.rank


class ApprovalDecision(StrEnum):
    APPROVE = "approve"
    REJECT = "reject"
    SNOOZE = "snooze"
