from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from cloudops_orchestrator.metrics import ALLOWED_METRICS, NAMESPACE, UnknownMetricError, put_metric


def test_allowed_metrics_is_exactly_five() -> None:
    assert len(ALLOWED_METRICS) == 5


def test_put_metric_accepts_allowed_name() -> None:
    logger = MagicMock()
    put_metric(logger, "RunFailed", 1, run_id="run-1")
    logger.set_namespace.assert_called_once_with(NAMESPACE)
    logger.set_property.assert_called_once_with("run_id", "run-1")
    logger.put_metric.assert_called_once()
    name, value, _unit = logger.put_metric.call_args[0]
    assert name == "RunFailed"
    assert value == 1


def test_put_metric_rejects_unknown_name() -> None:
    logger = MagicMock()
    with pytest.raises(UnknownMetricError):
        put_metric(logger, "SomeRandomMetric", 1)
    logger.put_metric.assert_not_called()


@pytest.mark.parametrize("name", sorted(ALLOWED_METRICS))
def test_every_allowed_metric_emits(name: str) -> None:
    logger = MagicMock()
    put_metric(logger, name, 42)
    logger.put_metric.assert_called_once()
