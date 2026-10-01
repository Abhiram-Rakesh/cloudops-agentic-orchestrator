"""``Aggregate`` step: merge domain batch results into one ``RunReport``,
compute priority scores deterministically, and write the LLM-authored
executive summary from structured data only.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from cloudops_orchestrator.llm.budget import BudgetTracker
from cloudops_orchestrator.llm.rendering import render_prompt
from cloudops_orchestrator.llm.schemas import ExecutiveSummaryOutput
from cloudops_orchestrator.llm.structured import call_structured
from cloudops_orchestrator.models.enums import Domain, FindingStatus
from cloudops_orchestrator.models.findings import Finding
from cloudops_orchestrator.models.report import LLMUsage, ReportItem, RunReport
from cloudops_orchestrator.policy.priority import priority_score_for_finding
from cloudops_orchestrator.steps.run_domain_batch import DomainBatchResult

TOP_ITEMS_FOR_SUMMARY = 10


def compute_counts(findings: list[Finding]) -> dict[Domain, dict[FindingStatus, int]]:
    counts: dict[Domain, dict[FindingStatus, int]] = {
        domain: dict.fromkeys(FindingStatus, 0) for domain in Domain
    }
    for finding in findings:
        counts[finding.domain][finding.status] += 1
    return counts


def build_report_items(
    domain_results: list[DomainBatchResult],
    *,
    findings_by_fingerprint: dict[str, Finding],
    now: datetime,
) -> list[ReportItem]:
    items: list[ReportItem] = []
    for result in domain_results:
        for analysis in result.analyses:
            group = analysis.group
            group_findings = [
                findings_by_fingerprint[fp]
                for fp in group.findings
                if fp in findings_by_fingerprint
            ]
            priority = max(
                (priority_score_for_finding(f, now=now) for f in group_findings), default=0.0
            )
            items.append(
                ReportItem(
                    group_id=group.group_id,
                    domain=group.domain,
                    title=group.rule_id,
                    max_severity=analysis.triage.adjusted_severity,
                    count=group.count,
                    priority_score=priority,
                    triage=analysis.triage,
                    recommendation=analysis.recommendation,
                    carried_over=analysis.carried_over,
                )
            )
    items.sort(key=lambda item: item.priority_score, reverse=True)
    return items


def _summary_context(
    items: list[ReportItem], *, counts: dict[Domain, dict[FindingStatus, int]]
) -> dict[str, Any]:
    return {
        "counts": {
            domain.value: {status.value: n for status, n in by_status.items()}
            for domain, by_status in counts.items()
        },
        "top_items": [
            {
                "title": item.title,
                "domain": item.domain.value,
                "severity": item.max_severity.value,
                "count": item.count,
                "verdict": item.triage.verdict.value if item.triage else None,
            }
            for item in items[:TOP_ITEMS_FOR_SUMMARY]
        ],
    }


def generate_executive_summary(
    *,
    model: Any,
    items: list[ReportItem],
    counts: dict[Domain, dict[FindingStatus, int]],
    budget: BudgetTracker,
    model_name: str,
    run_id: str,
) -> str:
    context = _summary_context(items, counts=counts)
    system_prompt = render_prompt("report_summary_system.md")
    user_prompt = (
        f"Counts by domain and status: {context['counts']}\n"
        f"Top items by priority: {context['top_items']}\n"
        f"Total LLM spend this run: ${budget.total_cost_usd:.4f}\n"
        f"budget_exhausted: {budget.budget_exhausted}"
    )
    result = call_structured(
        model,
        schema=ExecutiveSummaryOutput,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        node="report_summary",
        group_id=f"run-summary-{run_id}",
        model_name=model_name,
        budget=budget,
    )
    return result.executive_summary


def aggregate(
    *,
    run_id: str,
    started_at: datetime,
    finished_at: datetime,
    domain_results: list[DomainBatchResult],
    findings: list[Finding],
    summary_model: Any,
    summary_model_name: str,
    budget: BudgetTracker,
    resolved: list[str] | None = None,
) -> RunReport:
    findings_by_fingerprint = {f.fingerprint: f for f in findings}
    items = build_report_items(
        domain_results, findings_by_fingerprint=findings_by_fingerprint, now=finished_at
    )
    counts = compute_counts(findings)

    executive_summary = generate_executive_summary(
        model=summary_model,
        items=items,
        counts=counts,
        budget=budget,
        model_name=summary_model_name,
        run_id=run_id,
    )

    usage: LLMUsage = budget.usage()
    return RunReport(
        run_id=run_id,
        started_at=started_at,
        finished_at=finished_at,
        counts=counts,
        executive_summary=executive_summary,
        items=items,
        resolved=resolved or [],
        suppressed=[
            fp for fp, f in findings_by_fingerprint.items() if f.status == FindingStatus.SUPPRESSED
        ],
        llm_usage=usage,
    )


__all__ = ["aggregate", "build_report_items", "compute_counts", "generate_executive_summary"]
