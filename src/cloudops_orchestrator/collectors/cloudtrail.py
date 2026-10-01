"""CloudTrail collector — attribution evidence for drift findings, not a
source of findings on its own (``DRIFT-004-4.3``: actor, event, time,
masked source IP, and any ``change-ticket`` request-parameter/tag).

Live: ``cloudtrail:LookupEvents`` (write events only) over the run's
lookback window, under a wall-clock budget.
Fixture: ``{fixtures_dir}/cloudtrail/events.json`` (absent/empty means no
attribution data — drift findings stay unattributed, per DRIFT-003-3.1's
"cannot be attributed" row).
"""

from __future__ import annotations

import json
import time
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


def _load_events(ctx: CollectorContext) -> tuple[list[dict[str, Any]], bool]:
    """Return ``(events, truncated)``; ``truncated`` means the time budget ran out."""
    if ctx.fixtures_dir is not None:
        path = ctx.fixtures_dir / "cloudtrail" / "events.json"
        if not path.exists():
            return [], False
        result: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))
        return result, False

    from datetime import timedelta

    from cloudops_orchestrator.aws.clients import get_client

    client = get_client("cloudtrail", region_name=ctx.settings.aws.region)
    events: list[dict[str, Any]] = []
    paginator = client.get_paginator("lookup_events")
    config = ctx.settings.collectors.cloudtrail
    # Attribution only needs events that *changed* something, so ask for
    # write events (ReadOnly=false). Read-only calls (Describe/Get/List from
    # Config, Security Hub, Prowler, the console...) are the vast majority of
    # CloudTrail volume, and LookupEvents is rate-limited to ~2 requests/s at
    # 50 events per page: on a busy day an unfiltered 8-day pull took hours
    # and ran the collect Lambda into its 15-minute timeout before it wrote
    # anything (found live 2026-10-01; filtering to writes cut it to ~45 s).
    # The wall-clock budget below is the backstop if that ever recurs.
    deadline = time.monotonic() + config.max_seconds
    truncated = False
    for page in paginator.paginate(
        StartTime=ctx.now - timedelta(days=config.lookback_days),
        EndTime=ctx.now,
        LookupAttributes=[{"AttributeKey": "ReadOnly", "AttributeValue": "false"}],
    ):
        events.extend(page.get("Events", []))
        if time.monotonic() >= deadline:
            truncated = True
            break
    return events, truncated


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
    events, truncated = _load_events(ctx)
    warnings = []
    if truncated:
        limit = ctx.settings.collectors.cloudtrail.max_seconds
        warnings.append(
            f"CloudTrail lookup stopped after {limit}s with {len(events)} event(s); "
            "attribution for older changes may be missing"
        )
    return CollectorResult(findings=[], raw_evidence={"events": events}, warnings=warnings)


__all__ = ["SOURCE", "collect", "find_attribution"]
