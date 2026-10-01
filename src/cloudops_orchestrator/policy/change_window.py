"""T2 change-window enforcement: Mon-Thu
10:00-17:00 Asia/Kolkata, per ``config/policy/risk_tiers.yaml``'s
``tiers.T2.change_window``.
"""

from __future__ import annotations

from datetime import datetime, time
from zoneinfo import ZoneInfo

from cloudops_orchestrator.policy.config import ChangeWindow

_DAY_ABBREVIATIONS = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"]


def is_within_change_window(now: datetime, *, change_window: ChangeWindow) -> bool:
    local_now = now.astimezone(ZoneInfo(change_window.tz))
    day_abbrev = _DAY_ABBREVIATIONS[local_now.weekday()]
    if day_abbrev not in change_window.days:
        return False
    start_time = time.fromisoformat(change_window.start)
    end_time = time.fromisoformat(change_window.end)
    return start_time <= local_now.time() <= end_time


__all__ = ["is_within_change_window"]
