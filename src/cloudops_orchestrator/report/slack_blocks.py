"""Slack Block Kit rendering for the weekly digest and per-action approval
messages. Pure functions returning plain ``dict``/``list`` block
structures — posting them via ``chat.postMessage``/``chat.update`` and
verifying interaction callbacks is ``handlers/slack_handler.py``'s job;
nothing here calls the Slack API.
"""

from __future__ import annotations

from typing import Any

from cloudops_orchestrator.models.actions import ActionPlan, Recommendation
from cloudops_orchestrator.models.enums import Domain, FindingStatus
from cloudops_orchestrator.models.report import ReportItem, RunReport
from cloudops_orchestrator.report.render import to_local_time

# Slack Block Kit hard limits (see Slack's "reference: block elements" docs).
MAX_BLOCKS_PER_MESSAGE = 50
_HEADER_TEXT_LIMIT = 150
_SECTION_TEXT_LIMIT = 3000
_BUTTON_TEXT_LIMIT = 75
_TOP_N_BY_PRIORITY = 10


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _header(text: str) -> dict[str, Any]:
    return {
        "type": "header",
        "text": {"type": "plain_text", "text": _truncate(text, _HEADER_TEXT_LIMIT), "emoji": True},
    }


def _section(text: str) -> dict[str, Any]:
    return {
        "type": "section",
        "text": {"type": "mrkdwn", "text": _truncate(text, _SECTION_TEXT_LIMIT)},
    }


def _context(*lines: str) -> dict[str, Any]:
    return {
        "type": "context",
        "elements": [
            {"type": "mrkdwn", "text": _truncate(line, _SECTION_TEXT_LIMIT)} for line in lines
        ],
    }


def _divider() -> dict[str, Any]:
    return {"type": "divider"}


def _domain_counts_line(domain: Domain, counts: dict[FindingStatus, int]) -> str:
    new = counts.get(FindingStatus.NEW, 0)
    open_ = counts.get(FindingStatus.OPEN, 0)
    resolved = counts.get(FindingStatus.RESOLVED, 0)
    suppressed = counts.get(FindingStatus.SUPPRESSED, 0)
    return f"*{domain.value}*: {new} new · {open_} open · {resolved} resolved · {suppressed} suppressed"


def render_digest_blocks(
    report: RunReport,
    *,
    timezone: str,
    security_source_mode: str,
    month_to_date_spend_usd: float,
    report_url: str | None,
    warnings: list[str] | None = None,
) -> list[dict[str, Any]]:
    """The top-level weekly digest message. Per-action approval messages are
    separate threaded replies — see ``render_action_blocks``."""
    date_str = to_local_time(report.finished_at, timezone=timezone).strftime("%Y-%m-%d")
    blocks: list[dict[str, Any]] = [_header(f"CloudOps weekly review — {date_str}")]

    blocks.append(
        _context(
            f"Security source: {security_source_mode}",
            f"Run LLM cost: ${report.llm_usage.total_cost_usd:.2f} · "
            f"Month-to-date: ${month_to_date_spend_usd:.2f}",
        )
    )
    blocks.append(_divider())

    if report.counts:
        lines = [_domain_counts_line(domain, counts) for domain, counts in report.counts.items()]
        blocks.append(_section("\n".join(lines)))
        blocks.append(_divider())

    top_items = sorted(report.items, key=lambda item: item.priority_score, reverse=True)[
        :_TOP_N_BY_PRIORITY
    ]
    if top_items:
        lines = [
            f"{i}. *{item.title}* ({item.domain.value}, {item.max_severity.value}, "
            f"score={item.priority_score:.1f})"
            for i, item in enumerate(top_items, start=1)
        ]
        blocks.append(_section("*Top findings by priority*\n" + "\n".join(lines)))
        blocks.append(_divider())

    if warnings:
        blocks.append(_context(*(f":warning: {warning}" for warning in warnings)))

    if report_url:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Open full report", "emoji": True},
                        "url": report_url,
                        "action_id": "open_report",
                    }
                ],
            }
        )

    return blocks[:MAX_BLOCKS_PER_MESSAGE]


def render_action_blocks(item: ReportItem, plan: ActionPlan) -> list[dict[str, Any]]:
    """One threaded reply per automatable action, with Approve/Reject/Snooze
    buttons. ``item.recommendation`` must be set (the caller only calls this
    for report items ``create_action_threads`` turned into a plan)."""
    recommendation: Recommendation | None = item.recommendation
    if recommendation is None:
        msg = f"ReportItem {item.group_id!r} has no recommendation to render an action for"
        raise ValueError(msg)

    citation_lines = [
        f"> _{citation.sop_id} {citation.clause_id}_: “{citation.quote}”"
        for citation in recommendation.citations
    ]
    targets_line = ", ".join(plan.targets) if plan.targets else "(none)"

    blocks: list[dict[str, Any]] = [
        _section(f"*{recommendation.title}*\nTier: `{plan.effective_risk_tier.value}`"),
        _section(recommendation.summary),
        _section(f"*Targets*\n{targets_line}"),
    ]
    if citation_lines:
        blocks.append(_section("*Citations*\n" + "\n".join(citation_lines)))
    blocks.append(
        _context(
            f"Plan hash: `{plan.plan_hash[:12]}…` · Required approvals: {plan.required_approvals}",
        )
    )
    blocks.append(
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Approve", "emoji": True},
                    "style": "primary",
                    "action_id": "approve_action",
                    "value": plan.action_id,
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Reject", "emoji": True},
                    "style": "danger",
                    "action_id": "reject_action",
                    "value": plan.action_id,
                    "confirm": {
                        "title": {"type": "plain_text", "text": "Reject this action?"},
                        "text": {
                            "type": "mrkdwn",
                            "text": _truncate(
                                f"This will reject: {recommendation.title}", _SECTION_TEXT_LIMIT
                            ),
                        },
                        "confirm": {"type": "plain_text", "text": "Reject"},
                        "deny": {"type": "plain_text", "text": "Cancel"},
                    },
                },
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": _truncate("Snooze 7d", _BUTTON_TEXT_LIMIT),
                        "emoji": True,
                    },
                    "action_id": "snooze_action",
                    "value": plan.action_id,
                },
            ],
        }
    )
    return blocks[:MAX_BLOCKS_PER_MESSAGE]


__all__ = ["MAX_BLOCKS_PER_MESSAGE", "render_action_blocks", "render_digest_blocks"]
