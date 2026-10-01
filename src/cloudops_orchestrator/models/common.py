"""Shared model helpers: UTC-enforced datetimes.

Project convention: every timestamp inside the system is
UTC-aware; Asia/Kolkata conversion only happens at the report/Slack
rendering boundary. ``UTCDatetime`` enforces that at the model boundary
instead of relying on callers to remember.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from pydantic import AfterValidator


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        msg = "datetime must be timezone-aware (UTC)"
        raise ValueError(msg)
    return value.astimezone(UTC)


UTCDatetime = Annotated[datetime, AfterValidator(_ensure_utc)]
