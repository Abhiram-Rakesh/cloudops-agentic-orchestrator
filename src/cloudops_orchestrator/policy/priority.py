"""Deterministic priority score: never left to LLM judgment.

``priority_score = severity.weight x exposure_multiplier x env_multiplier x
age_factor``, where ``exposure_multiplier`` is 1.5 if the resource is
internet-exposed, ``env_multiplier`` is 1.5 if ``environment`` is
``prod``/``production``, and ``age_factor = 1 + min(days_open, 30) / 30``.
"""

from __future__ import annotations

from datetime import datetime

from cloudops_orchestrator.models.enums import Severity
from cloudops_orchestrator.models.findings import Finding

EXPOSURE_MULTIPLIER = 1.5
ENV_MULTIPLIER = 1.5
AGE_FACTOR_CAP_DAYS = 30
_PROD_ENVIRONMENTS = frozenset({"prod", "production"})


def compute_age_factor(*, first_seen: datetime, now: datetime) -> float:
    days_open = max((now - first_seen).days, 0)
    return 1 + min(days_open, AGE_FACTOR_CAP_DAYS) / AGE_FACTOR_CAP_DAYS


def is_internet_exposed(finding: Finding) -> bool:
    """Best-effort exposure check: an explicit collector-set flag first,
    falling back to a `0.0.0.0/0`/`::/0` mention in the finding's own text
    (both Security Hub and Prowler descriptions for open-ingress findings
    include the offending CIDR literally — see normalize/masking.py, which
    deliberately never masks these two values because they're semantically
    load-bearing exactly like this).
    """
    if isinstance(finding.details.get("internet_exposed"), bool):
        return bool(finding.details["internet_exposed"])
    haystack = f"{finding.title} {finding.description}"
    return "0.0.0.0/0" in haystack or "::/0" in haystack


def is_prod_environment(environment: str | None) -> bool:
    return (environment or "").lower() in _PROD_ENVIRONMENTS


def compute_priority_score(
    *,
    severity: Severity,
    internet_exposed: bool,
    environment: str | None,
    first_seen: datetime,
    now: datetime,
) -> float:
    exposure_multiplier = EXPOSURE_MULTIPLIER if internet_exposed else 1.0
    env_multiplier = ENV_MULTIPLIER if is_prod_environment(environment) else 1.0
    age_factor = compute_age_factor(first_seen=first_seen, now=now)
    return severity.weight * exposure_multiplier * env_multiplier * age_factor


def priority_score_for_finding(finding: Finding, *, now: datetime) -> float:
    return compute_priority_score(
        severity=finding.severity,
        internet_exposed=is_internet_exposed(finding),
        environment=finding.environment,
        first_seen=finding.first_seen,
        now=now,
    )


__all__ = [
    "AGE_FACTOR_CAP_DAYS",
    "ENV_MULTIPLIER",
    "EXPOSURE_MULTIPLIER",
    "compute_age_factor",
    "compute_priority_score",
    "is_internet_exposed",
    "is_prod_environment",
    "priority_score_for_finding",
]
