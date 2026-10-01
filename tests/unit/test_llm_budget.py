from __future__ import annotations

from pathlib import Path

import pytest

from cloudops_orchestrator.config import load_settings
from cloudops_orchestrator.llm.budget import BudgetExceeded, BudgetTracker

REPO_ROOT = Path(__file__).resolve().parents[2]
SETTINGS = load_settings(REPO_ROOT / "config" / "settings.local.yaml", env={})


def _tracker(max_cost: float = 2.0) -> BudgetTracker:
    return BudgetTracker(config=SETTINGS.llm, max_cost_usd_per_run=max_cost)


class TestRecord:
    def test_records_cost_for_known_model(self) -> None:
        tracker = _tracker()
        cost = tracker.record(
            model_name="claude-haiku-4-5-20251001", input_tokens=1_000_000, output_tokens=0
        )
        assert cost == pytest.approx(1.0)  # $1 per 1M input tokens for haiku

    def test_output_priced_higher_than_input(self) -> None:
        tracker = _tracker()
        input_cost = tracker.record(
            model_name="claude-haiku-4-5-20251001", input_tokens=1_000_000, output_tokens=0
        )
        tracker2 = _tracker(max_cost=10.0)
        output_cost = tracker2.record(
            model_name="claude-haiku-4-5-20251001", input_tokens=0, output_tokens=1_000_000
        )
        assert output_cost > input_cost

    def test_cache_read_is_cheaper_than_fresh_input(self) -> None:
        tracker = _tracker()
        fresh = tracker.record(
            model_name="claude-haiku-4-5-20251001", input_tokens=1_000_000, output_tokens=0
        )
        tracker2 = _tracker()
        cached = tracker2.record(
            model_name="claude-haiku-4-5-20251001",
            input_tokens=0,
            output_tokens=0,
            cache_read_tokens=1_000_000,
        )
        assert cached == pytest.approx(fresh * 0.1)

    def test_cache_write_is_more_expensive_than_fresh_input(self) -> None:
        tracker = _tracker()
        fresh = tracker.record(
            model_name="claude-haiku-4-5-20251001", input_tokens=1_000_000, output_tokens=0
        )
        tracker2 = _tracker()
        cache_write = tracker2.record(
            model_name="claude-haiku-4-5-20251001",
            input_tokens=0,
            output_tokens=0,
            cache_creation_tokens=1_000_000,
        )
        assert cache_write == pytest.approx(fresh * 1.25)

    def test_unknown_model_costs_nothing(self) -> None:
        tracker = _tracker()
        cost = tracker.record(
            model_name="unknown-model", input_tokens=1_000_000, output_tokens=1_000_000
        )
        assert cost == 0.0

    def test_accumulates_across_calls(self) -> None:
        tracker = _tracker()
        tracker.record(
            model_name="claude-haiku-4-5-20251001", input_tokens=1_000_000, output_tokens=0
        )
        tracker.record(
            model_name="claude-haiku-4-5-20251001", input_tokens=1_000_000, output_tokens=0
        )
        assert tracker.total_cost_usd == pytest.approx(2.0)

    def test_per_model_usage_tracked_separately(self) -> None:
        tracker = _tracker()
        tracker.record(model_name="claude-haiku-4-5-20251001", input_tokens=1000, output_tokens=500)
        tracker.record(model_name="claude-sonnet-5", input_tokens=2000, output_tokens=1000)
        usage = tracker.usage()
        assert set(usage.per_model) == {"claude-haiku-4-5-20251001", "claude-sonnet-5"}
        assert usage.per_model["claude-haiku-4-5-20251001"].input_tokens == 1000


class TestBudgetExceeded:
    def test_raises_when_over_budget(self) -> None:
        tracker = _tracker(max_cost=0.5)
        with pytest.raises(BudgetExceeded):
            tracker.record(
                model_name="claude-haiku-4-5-20251001", input_tokens=1_000_000, output_tokens=0
            )

    def test_sets_budget_exhausted_flag(self) -> None:
        tracker = _tracker(max_cost=0.5)
        with pytest.raises(BudgetExceeded):
            tracker.record(
                model_name="claude-haiku-4-5-20251001", input_tokens=1_000_000, output_tokens=0
            )
        assert tracker.budget_exhausted is True
        assert tracker.usage().budget_exhausted is True

    def test_exception_carries_amounts(self) -> None:
        tracker = _tracker(max_cost=0.5)
        with pytest.raises(BudgetExceeded) as exc_info:
            tracker.record(
                model_name="claude-haiku-4-5-20251001", input_tokens=1_000_000, output_tokens=0
            )
        assert exc_info.value.spent_usd == pytest.approx(1.0)
        assert exc_info.value.limit_usd == 0.5

    def test_under_budget_does_not_raise(self) -> None:
        tracker = _tracker(max_cost=2.0)
        tracker.record(
            model_name="claude-haiku-4-5-20251001", input_tokens=100_000, output_tokens=100_000
        )
        assert tracker.budget_exhausted is False
