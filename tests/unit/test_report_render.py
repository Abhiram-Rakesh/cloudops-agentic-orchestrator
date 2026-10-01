from __future__ import annotations

from datetime import UTC, datetime

from cloudops_orchestrator.models.actions import TriageResult
from cloudops_orchestrator.models.enums import Domain, FindingStatus, Severity, TriageVerdict
from cloudops_orchestrator.models.report import LLMUsage, ReportItem, RunReport
from cloudops_orchestrator.report.render import (
    render_report_html,
    render_report_json,
    to_local_time,
)


def _report(**overrides: object) -> RunReport:
    item = ReportItem(
        group_id="g1",
        domain=Domain.SECURITY,
        title="Unrestricted SSH ingress",
        max_severity=Severity.HIGH,
        count=1,
        priority_score=42.0,
        triage=TriageResult(
            group_id="g1",
            verdict=TriageVerdict.NEEDS_HUMAN,
            adjusted_severity=Severity.HIGH,
            rationale="No SOP context retrieved.",
            citations=[],
            sop_gap=True,
        ),
        recommendation=None,
    )
    defaults: dict[str, object] = {
        "run_id": "run-1",
        "started_at": datetime(2026, 1, 26, 3, 15, tzinfo=UTC),
        "finished_at": datetime(2026, 1, 26, 3, 20, tzinfo=UTC),
        "counts": {Domain.SECURITY: {FindingStatus.NEW: 1}},
        "executive_summary": "A test summary.",
        "items": [item],
        "resolved": [],
        "suppressed": [],
        "llm_usage": LLMUsage(per_model={}, total_cost_usd=0.01, budget_exhausted=False),
    }
    defaults.update(overrides)
    return RunReport(**defaults)  # type: ignore[arg-type]


def test_to_local_time_converts_utc_to_ist() -> None:
    utc_time = datetime(2026, 1, 26, 3, 15, tzinfo=UTC)
    ist_time = to_local_time(utc_time, timezone="Asia/Kolkata")
    assert ist_time.hour == 8
    assert ist_time.minute == 45


def test_render_html_contains_run_id_and_summary() -> None:
    html = render_report_html(_report())
    assert "run-1" in html
    assert "A test summary." in html
    assert "Unrestricted SSH ingress" in html


def test_render_html_flags_budget_exhausted() -> None:
    report = _report(llm_usage=LLMUsage(per_model={}, total_cost_usd=2.5, budget_exhausted=True))
    html = render_report_html(report)
    assert "PARTIAL REPORT" in html


def test_render_html_escapes_untrusted_content() -> None:
    report = _report()
    item = report.items[0].model_copy(update={"title": "<script>alert(1)</script>"})
    report = report.model_copy(update={"items": [item]})
    html = render_report_html(report)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_render_json_round_trips() -> None:
    report = _report()
    json_text = render_report_json(report)
    restored = RunReport.model_validate_json(json_text)
    assert restored.run_id == report.run_id
    assert restored.items[0].title == report.items[0].title
