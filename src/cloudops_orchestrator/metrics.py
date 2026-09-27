"""EMF metric emission, capped at the free-plan metric budget.

Hard Rule #8 caps this system at 5 custom CloudWatch metrics and 6 alarms.
This module is the single choke point for metric emission so that cap is
enforced in code, not just by convention — see ``ALLOWED_METRICS`` and
``infra/modules/observability`` for the matching alarms.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Final

from aws_embedded_metrics.logger.metrics_logger import MetricsLogger
from aws_embedded_metrics.metric_scope import metric_scope
from aws_embedded_metrics.unit import Unit

NAMESPACE: Final[str] = "CloudOps"

# Exactly the 5 metrics named in docs/DESIGN.md §13.1 / the free-plan ledger.
# Emitting anything else is a bug, not a feature — it will blow the alarm
# budget or the free-plan metric-count allowance.
ALLOWED_METRICS: Final[frozenset[str]] = frozenset(
    {
        "RunFailed",
        "RunDurationSeconds",
        "LLMCostUSD",
        "FindingsNew",
        "ActionsAwaitingApproval",
    }
)

_METRIC_UNITS: Final[dict[str, Unit]] = {
    "RunFailed": Unit.COUNT,
    "RunDurationSeconds": Unit.SECONDS,
    "LLMCostUSD": Unit.NONE,
    "FindingsNew": Unit.COUNT,
    "ActionsAwaitingApproval": Unit.COUNT,
}


class UnknownMetricError(ValueError):
    pass


def put_metric(
    logger: MetricsLogger, name: str, value: float, *, run_id: str | None = None
) -> None:
    """Emit one of the 5 allowed EMF metrics with its correct unit."""
    if name not in ALLOWED_METRICS:
        allowed = ", ".join(sorted(ALLOWED_METRICS))
        msg = f"Metric {name!r} is not in the free-plan metric allowlist ({allowed})"
        raise UnknownMetricError(msg)
    logger.set_namespace(NAMESPACE)
    if run_id is not None:
        logger.set_property("run_id", run_id)
    logger.put_metric(name, value, _METRIC_UNITS[name].value)


def with_metrics[**P, T](fn: Callable[P, T]) -> Callable[P, T]:
    """Thin wrapper around ``aws_embedded_metrics.metric_scope`` for handler code."""
    return metric_scope(fn)


__all__ = [
    "ALLOWED_METRICS",
    "NAMESPACE",
    "MetricsLogger",
    "UnknownMetricError",
    "put_metric",
    "with_metrics",
]
