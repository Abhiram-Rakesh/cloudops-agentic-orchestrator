"""CloudTrail collector — attribution evidence for drift findings, not a
source of findings on its own (``DRIFT-004-4.3``: actor, event, time,
masked source IP, and any ``change-ticket`` request-parameter/tag).

Live: ``cloudtrail:LookupEvents`` over the run's lookback window.
Fixture: ``{fixtures_dir}/cloudtrail/events.json`` (absent/empty means no
attribution data — drift findings stay unattributed, per DRIFT-003-3.1's
"cannot be attributed" row).
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from cloudops_orchestrator.collectors.base import CollectorContext, CollectorResult
from cloudops_orchestrator.normalize.masking import Masker

SOURCE = "cloudtrail"


def _parse_time(value: str | datetime | None, fallback: datetime) -> datetime:
    if not value:
        return fallback
    # boto3 auto-converts LookupEvents' timestamp-shaped EventTime to a
    # native datetime; only fixture JSON ever hands this a str. See the
    # identical bug + fix in collectors/access_analyzer.py, found live on
    # the first real end-to-end run 2026-09-28 (README.md (Troubleshooting)).
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return fallback


def _load_events(ctx: CollectorContext) -> list[dict[str, Any]]:
    if ctx.fixtures_dir is not None:
        path = ctx.fixtures_dir / "cloudtrail" / "events.json"
        if not path.exists():
            return []
        result: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))
        return result

    from datetime import timedelta

    from cloudops_orchestrator.aws.clients import get_client

    client = get_client("cloudtrail", region_name=ctx.settings.aws.region)
    events: list[dict[str, Any]] = []
    paginator = client.get_paginator("lookup_events")
    lookback_days = ctx.settings.collectors.cloudtrail.lookback_days
    # paginate() with no StartTime/EndTime pages through the account's ENTIRE
    # CloudTrail history (up to 90 days) -- harmless on an empty account, but
    # LookupEvents is rate-limited and a real, actively-used account can have
    # thousands of events, enough to exceed the collect Lambda's 15-minute
    # timeout outright. Found live: collect timed out at exactly 900.00s with
    # zero DynamoDB writes ever made (ruled out via CloudWatch metrics),
    # meaning it never even finished collecting -- see
    # README.md (Troubleshooting).
    for page in paginator.paginate(
        StartTime=ctx.now - timedelta(days=lookback_days), EndTime=ctx.now
    ):
        events.extend(page.get("Events", []))
    return events


def find_attribution(
    events: list[dict[str, Any]], *, resource_id: str, masker: Masker
) -> dict[str, Any] | None:
    """Find the event most likely responsible for a change to ``resource_id``."""
    matches = [e for e in events if resource_id in json.dumps(e.get("Resources", []))]
    if not matches:
        return None
    event = matches[0]
    return {
        "actor": event.get("Username", "unknown"),
        "event_name": event.get("EventName", "unknown"),
        "event_time": event.get("EventTime"),
        "masked_source_ip": masker.mask(event.get("SourceIPAddress", "")),
        "change_ticket": event.get("ChangeTicket"),
    }


def collect(ctx: CollectorContext) -> CollectorResult:
    events = _load_events(ctx)
    return CollectorResult(findings=[], raw_evidence={"events": events})


__all__ = ["SOURCE", "collect", "find_attribution"]
