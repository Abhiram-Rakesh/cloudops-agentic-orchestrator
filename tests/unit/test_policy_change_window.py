from __future__ import annotations

from datetime import UTC, datetime

from cloudops_orchestrator.policy.change_window import is_within_change_window
from cloudops_orchestrator.policy.config import load_risk_tiers

T2_WINDOW = load_risk_tiers().tiers["T2"].change_window
assert T2_WINDOW is not None


def test_tuesday_afternoon_ist_is_within_window() -> None:
    # Tuesday 16:30 IST
    assert (
        is_within_change_window(datetime(2026, 1, 20, 11, 0, tzinfo=UTC), change_window=T2_WINDOW)
        is True
    )


def test_tuesday_early_morning_ist_is_outside_window() -> None:
    # Tuesday 05:30 IST — before 10:00
    assert (
        is_within_change_window(datetime(2026, 1, 20, 0, 0, tzinfo=UTC), change_window=T2_WINDOW)
        is False
    )


def test_saturday_is_always_outside_window() -> None:
    assert (
        is_within_change_window(datetime(2026, 1, 24, 12, 0, tzinfo=UTC), change_window=T2_WINDOW)
        is False
    )


def test_friday_is_outside_window() -> None:
    # Friday is not in [MON, TUE, WED, THU]
    assert (
        is_within_change_window(datetime(2026, 1, 23, 11, 0, tzinfo=UTC), change_window=T2_WINDOW)
        is False
    )


def test_boundary_start_time_inclusive() -> None:
    # Exactly 10:00 IST Tuesday
    assert (
        is_within_change_window(datetime(2026, 1, 20, 4, 30, tzinfo=UTC), change_window=T2_WINDOW)
        is True
    )


def test_boundary_end_time_inclusive() -> None:
    # Exactly 17:00 IST Tuesday
    assert (
        is_within_change_window(datetime(2026, 1, 20, 11, 30, tzinfo=UTC), change_window=T2_WINDOW)
        is True
    )


def test_just_after_end_time_excluded() -> None:
    assert (
        is_within_change_window(datetime(2026, 1, 20, 11, 31, tzinfo=UTC), change_window=T2_WINDOW)
        is False
    )
