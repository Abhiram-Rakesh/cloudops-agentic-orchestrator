from __future__ import annotations

from datetime import UTC, datetime

from cloudops_orchestrator.steps.init_run import init_run


def test_proceeds_when_under_budget() -> None:
    result = init_run(
        now=datetime(2026, 1, 1, tzinfo=UTC),
        month_to_date_spend_usd=5.0,
        max_cost_usd_per_month=15.0,
    )
    assert result.proceed is True
    assert result.budget_exceeded is False


def test_blocks_when_at_or_over_budget() -> None:
    result = init_run(
        now=datetime(2026, 1, 1, tzinfo=UTC),
        month_to_date_spend_usd=15.0,
        max_cost_usd_per_month=15.0,
    )
    assert result.proceed is False
    assert result.budget_exceeded is True


def test_generates_run_id_when_not_given() -> None:
    result = init_run(
        now=datetime(2026, 1, 1, tzinfo=UTC),
        month_to_date_spend_usd=0.0,
        max_cost_usd_per_month=15.0,
    )
    assert result.run_id


def test_uses_provided_run_id() -> None:
    result = init_run(
        now=datetime(2026, 1, 1, tzinfo=UTC),
        month_to_date_spend_usd=0.0,
        max_cost_usd_per_month=15.0,
        run_id="fixed",
    )
    assert result.run_id == "fixed"
