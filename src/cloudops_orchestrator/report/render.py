"""Render a ``RunReport`` to HTML and JSON.

Timestamps are UTC everywhere internally; Asia/Kolkata conversion happens
only here, at the report-rendering boundary (project convention).
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from cloudops_orchestrator.models.report import RunReport

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
    autoescape=True,
)


def to_local_time(dt: datetime, *, timezone: str) -> datetime:
    return dt.astimezone(ZoneInfo(timezone))


_env.filters["local_time"] = lambda dt, timezone: to_local_time(dt, timezone=timezone).strftime(
    "%Y-%m-%d %H:%M %Z"
)


def render_report_html(report: RunReport, *, timezone: str = "Asia/Kolkata") -> str:
    template = _env.get_template("report.html")
    return template.render(report=report, timezone=timezone)


def render_report_json(report: RunReport) -> str:
    return report.model_dump_json(indent=2)


__all__ = ["render_report_html", "render_report_json", "to_local_time"]
