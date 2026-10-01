from __future__ import annotations

from datetime import UTC, datetime

import pytest

from cloudops_orchestrator.models.actions import ActionPlan, Recommendation
from cloudops_orchestrator.models.enums import ActionType, Domain, FindingStatus, RiskTier, Severity
from cloudops_orchestrator.models.report import LLMUsage, ReportItem, RunReport
from cloudops_orchestrator.models.sop import SOPCitation
from cloudops_orchestrator.report.slack_blocks import (
    MAX_BLOCKS_PER_MESSAGE,
    render_action_blocks,
    render_digest_blocks,
)


def _recommendation(**overrides: object) -> Recommendation:
    defaults: dict[str, object] = {
        "recommendation_id": "rec-1",
        "run_id": "run-1",
        "group_id": "g1",
        "domain": Domain.SECURITY,
        "title": "Revoke world-open SSH ingress",
        "summary": "Revoke the tcp/22 ingress rule from 0.0.0.0/0.",
        "action_type": ActionType.SSM_AUTOMATION,
        "parameters": {"document": "CloudOps-RevokeSGIngressWorld"},
        "target_fingerprints": ["fp-1"],
        "proposed_risk_tier": RiskTier.T1,
        "effective_risk_tier": RiskTier.T1,
        "rationale": "SEC-002-2.1 requires this.",
        "citations": [
            SOPCitation(sop_id="SEC-002", clause_id="SEC-002-2.1", quote="No SG MUST...")
        ],
        "blast_radius": "One SG rule.",
    }
    defaults.update(overrides)
    return Recommendation(**defaults)  # type: ignore[arg-type]


def _item(**overrides: object) -> ReportItem:
    defaults: dict[str, object] = {
        "group_id": "g1",
        "domain": Domain.SECURITY,
        "title": "Unrestricted SSH ingress",
        "max_severity": Severity.HIGH,
        "count": 1,
        "priority_score": 42.0,
        "recommendation": _recommendation(),
    }
    defaults.update(overrides)
    return ReportItem(**defaults)  # type: ignore[arg-type]


def _plan(**overrides: object) -> ActionPlan:
    defaults: dict[str, object] = {
        "action_id": "action-1",
        "recommendation_id": "rec-1",
        "action_type": ActionType.SSM_AUTOMATION,
        "parameters": {"document": "CloudOps-RevokeSGIngressWorld"},
        "targets": ["sg-1"],
        "effective_risk_tier": RiskTier.T1,
        "required_approvals": 1,
        "expires_at": datetime(2026, 2, 1, tzinfo=UTC),
        "plan_hash": "a" * 64,
    }
    defaults.update(overrides)
    return ActionPlan(**defaults)  # type: ignore[arg-type]


def _report(**overrides: object) -> RunReport:
    defaults: dict[str, object] = {
        "run_id": "run-1",
        "started_at": datetime(2026, 1, 26, 3, 15, tzinfo=UTC),
        "finished_at": datetime(2026, 1, 26, 3, 20, tzinfo=UTC),
        "counts": {
            Domain.SECURITY: {
                FindingStatus.NEW: 2,
                FindingStatus.OPEN: 1,
                FindingStatus.RESOLVED: 0,
                FindingStatus.SUPPRESSED: 1,
            }
        },
        "executive_summary": "A test summary.",
        "items": [_item()],
        "resolved": [],
        "suppressed": [],
        "llm_usage": LLMUsage(per_model={}, total_cost_usd=0.05, budget_exhausted=False),
    }
    defaults.update(overrides)
    return RunReport(**defaults)  # type: ignore[arg-type]


class TestDigestBlocks:
    def test_header_has_ist_date(self) -> None:
        blocks = render_digest_blocks(
            _report(),
            timezone="Asia/Kolkata",
            security_source_mode="Prowler",
            month_to_date_spend_usd=1.23,
            report_url="https://example.com/report.html",
        )
        header = blocks[0]
        assert header["type"] == "header"
        assert "CloudOps weekly review — 2026-01-26" in header["text"]["text"]

    def test_includes_domain_counts(self) -> None:
        blocks = render_digest_blocks(
            _report(),
            timezone="Asia/Kolkata",
            security_source_mode="Prowler",
            month_to_date_spend_usd=1.23,
            report_url=None,
        )
        joined = " ".join(b.get("text", {}).get("text", "") for b in blocks if "text" in b)
        assert "2 new" in joined
        assert "1 open" in joined
        assert "1 suppressed" in joined

    def test_includes_cost_and_source_mode(self) -> None:
        blocks = render_digest_blocks(
            _report(),
            timezone="Asia/Kolkata",
            security_source_mode="trial: Security Hub + Prowler",
            month_to_date_spend_usd=9.87,
            report_url=None,
        )
        context_texts = [
            el["text"] for b in blocks if b["type"] == "context" for el in b["elements"]
        ]
        joined = " ".join(context_texts)
        assert "trial: Security Hub + Prowler" in joined
        assert "$0.05" in joined
        assert "$9.87" in joined

    def test_report_url_renders_button(self) -> None:
        blocks = render_digest_blocks(
            _report(),
            timezone="Asia/Kolkata",
            security_source_mode="Prowler",
            month_to_date_spend_usd=0.0,
            report_url="https://example.com/report.html",
        )
        actions = [b for b in blocks if b["type"] == "actions"]
        assert len(actions) == 1
        assert actions[0]["elements"][0]["url"] == "https://example.com/report.html"

    def test_no_report_url_omits_button(self) -> None:
        blocks = render_digest_blocks(
            _report(),
            timezone="Asia/Kolkata",
            security_source_mode="Prowler",
            month_to_date_spend_usd=0.0,
            report_url=None,
        )
        assert not [b for b in blocks if b["type"] == "actions"]

    def test_warnings_rendered_as_context(self) -> None:
        blocks = render_digest_blocks(
            _report(),
            timezone="Asia/Kolkata",
            security_source_mode="Prowler",
            month_to_date_spend_usd=0.0,
            report_url=None,
            warnings=["Prowler data is 250 days old"],
        )
        context_texts = [
            el["text"] for b in blocks if b["type"] == "context" for el in b["elements"]
        ]
        assert any("250 days old" in text for text in context_texts)

    def test_top_10_by_priority_capped(self) -> None:
        items = [
            _item(group_id=f"g{i}", title=f"Finding {i}", priority_score=float(i))
            for i in range(15)
        ]
        blocks = render_digest_blocks(
            _report(items=items),
            timezone="Asia/Kolkata",
            security_source_mode="Prowler",
            month_to_date_spend_usd=0.0,
            report_url=None,
        )
        top_section = next(
            b for b in blocks if b.get("text", {}).get("text", "").startswith("*Top findings")
        )
        text = top_section["text"]["text"]
        assert text.count("Finding") == 10
        assert "Finding 14" in text  # highest priority_score first
        assert "Finding 4" not in text  # lowest 5 dropped

    def test_never_exceeds_block_limit(self) -> None:
        blocks = render_digest_blocks(
            _report(),
            timezone="Asia/Kolkata",
            security_source_mode="Prowler",
            month_to_date_spend_usd=0.0,
            report_url="https://example.com/report.html",
        )
        assert len(blocks) <= MAX_BLOCKS_PER_MESSAGE


class TestActionBlocks:
    def test_includes_title_tier_and_targets(self) -> None:
        blocks = render_action_blocks(_item(), _plan())
        joined = str(blocks)
        assert "Revoke world-open SSH ingress" in joined
        assert "T1" in joined
        assert "sg-1" in joined

    def test_includes_citation(self) -> None:
        blocks = render_action_blocks(_item(), _plan())
        joined = str(blocks)
        assert "SEC-002" in joined
        assert "SEC-002-2.1" in joined

    def test_includes_plan_hash_prefix_and_required_approvals(self) -> None:
        blocks = render_action_blocks(_item(), _plan(required_approvals=2))
        context = next(b for b in blocks if b["type"] == "context")
        text = context["elements"][0]["text"]
        assert "a" * 12 in text
        assert "2" in text

    def test_has_approve_reject_snooze_buttons(self) -> None:
        blocks = render_action_blocks(_item(), _plan())
        actions_block = next(b for b in blocks if b["type"] == "actions")
        action_ids = {el["action_id"] for el in actions_block["elements"]}
        assert action_ids == {"approve_action", "reject_action", "snooze_action"}
        for el in actions_block["elements"]:
            assert el["value"] == "action-1"

    def test_reject_button_has_confirm_dialog(self) -> None:
        blocks = render_action_blocks(_item(), _plan())
        actions_block = next(b for b in blocks if b["type"] == "actions")
        reject = next(el for el in actions_block["elements"] if el["action_id"] == "reject_action")
        assert "confirm" in reject

    def test_no_recommendation_raises(self) -> None:
        item = _item(recommendation=None)
        with pytest.raises(ValueError, match="no recommendation"):
            render_action_blocks(item, _plan())

    def test_never_exceeds_block_limit(self) -> None:
        blocks = render_action_blocks(_item(), _plan())
        assert len(blocks) <= MAX_BLOCKS_PER_MESSAGE
