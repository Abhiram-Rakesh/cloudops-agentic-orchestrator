"""``aggregate`` Lambda: merges every ``DomainBatch`` result, renders
and publishes the report (S3 + presigned URL), posts the Slack digest and
per-action threads, creates action-graph threads for automatable
recommendations, records month-to-date spend, and emits EMF metrics.

Real AWS/Slack wiring only; not exercised by tests — ``steps/aggregate.py``,
``steps/publish.py``, ``report/slack_blocks.py`` and
``steps/create_action_threads.py`` carry the tested logic.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from cloudops_orchestrator.metrics import put_metric, with_metrics


def _security_source_mode(settings: Any) -> str:
    if settings.collectors.security_hub.enabled:
        return "trial: Security Hub + Prowler"
    return "Prowler"


def _handler(event: dict[str, Any], context: Any, metrics: Any) -> dict[str, Any]:
    import os

    from cloudops_orchestrator.aws.clients import get_s3_client, get_ssm_client
    from cloudops_orchestrator.checkpoint.factory import get_checkpointer
    from cloudops_orchestrator.config import load_settings
    from cloudops_orchestrator.graph.action_graph import ActionGraphDeps, NullRemediator
    from cloudops_orchestrator.integrations.slack_client import WebClientSlackAdapter
    from cloudops_orchestrator.llm.budget import BudgetTracker
    from cloudops_orchestrator.llm.factory import get_reasoning_model
    from cloudops_orchestrator.llm.tracing import enable_tracing, flush_tracing
    from cloudops_orchestrator.policy.config import load_risk_tiers
    from cloudops_orchestrator.report.slack_blocks import render_action_blocks, render_digest_blocks
    from cloudops_orchestrator.steps.aggregate import aggregate
    from cloudops_orchestrator.steps.create_action_threads import create_action_threads
    from cloudops_orchestrator.steps.publish import publish_live
    from cloudops_orchestrator.steps.serialization import (
        deserialize_domain_result,
        deserialize_findings,
    )
    from cloudops_orchestrator.store.actions import get_action_plan
    from cloudops_orchestrator.store.client import get_table
    from cloudops_orchestrator.store.spend import add_spend

    settings = load_settings(os.environ.get("CLOUDOPS_CONFIG", "config/settings.dev.yaml"))
    run_id = event["run_id"]
    started_at = datetime.fromisoformat(event["started_at"])
    finished_at = datetime.now(UTC)

    s3 = get_s3_client(region_name=settings.aws.region)
    bucket = settings.storage.bucket
    findings = deserialize_findings(
        s3.get_object(Bucket=bucket, Key=f"runs/{run_id}/findings.json")["Body"]
        .read()
        .decode("utf-8")
    )
    domain_results = [
        deserialize_domain_result(
            s3.get_object(
                Bucket=bucket, Key=f"runs/{run_id}/results/{b['domain']}/{b['batch_id']}.json"
            )["Body"]
            .read()
            .decode("utf-8")
        )
        for b in event["batches"]
    ]

    ssm_for_llm = get_ssm_client(region_name=settings.aws.region)
    anthropic_api_key = ssm_for_llm.get_parameter(
        Name=f"{settings.storage.parameter_prefix}/anthropic_api_key",
        WithDecryption=True,  # gitleaks:allow
    )["Parameter"]["Value"]
    langsmith_api_key = ssm_for_llm.get_parameter(
        Name=f"{settings.storage.parameter_prefix}/langsmith_api_key",
        WithDecryption=True,  # gitleaks:allow
    )["Parameter"]["Value"]
    enable_tracing(settings.langsmith, api_key=langsmith_api_key)

    budget = BudgetTracker(
        config=settings.llm, max_cost_usd_per_run=settings.llm.max_cost_usd_per_run
    )
    report = aggregate(
        run_id=run_id,
        started_at=started_at,
        finished_at=finished_at,
        domain_results=domain_results,
        findings=findings,
        summary_model=get_reasoning_model(settings.llm, api_key=anthropic_api_key),
        summary_model_name=settings.llm.reasoning_model,
        budget=budget,
    )
    report = publish_live(
        report,
        s3_client=s3,
        bucket=bucket,
        presign_days=settings.report.presign_days,
        timezone=settings.report.timezone,
    )

    table = get_table(settings)
    action_deps = ActionGraphDeps(
        settings=settings, risk_tiers=load_risk_tiers(), remediator=NullRemediator(), table=table
    )
    created_threads = create_action_threads(
        report.items,
        deps=action_deps,
        checkpointer=get_checkpointer(settings),
        risk_tiers=load_risk_tiers(),
        approvers=settings.approvals.approvers,
        expiry_days=settings.approvals.expiry_days,
        now=finished_at,
    )

    ssm = get_ssm_client(region_name=settings.aws.region)
    bot_token = ssm.get_parameter(
        Name=f"{settings.storage.parameter_prefix}/slack_bot_token",
        WithDecryption=True,  # gitleaks:allow
    )["Parameter"]["Value"]
    slack = WebClientSlackAdapter(bot_token)
    month_to_date_spend = add_spend(
        table, finished_at.strftime("%Y-%m"), report.llm_usage.total_cost_usd
    )
    digest_blocks = render_digest_blocks(
        report,
        timezone=settings.report.timezone,
        security_source_mode=_security_source_mode(settings),
        month_to_date_spend_usd=month_to_date_spend,
        report_url=report.report_uri,
        warnings=event.get("warnings"),
    )
    _channel, digest_ts = slack.chat_post_message(
        channel=settings.approvals.slack_channel_id,
        blocks=digest_blocks,
        text=f"CloudOps weekly review — {run_id}",
    )

    items_by_group_id = {item.group_id: item for item in report.items}
    for thread in created_threads:
        found = get_action_plan(table, thread.action_id)
        if found is None:
            continue
        plan, _status = found
        item = items_by_group_id.get(thread.group_id)
        if item is None or item.recommendation is None:
            continue
        slack.chat_post_message(
            channel=settings.approvals.slack_channel_id,
            blocks=render_action_blocks(item, plan),
            text=item.recommendation.title,
            thread_ts=digest_ts,
        )

    put_metric(
        metrics, "RunDurationSeconds", (finished_at - started_at).total_seconds(), run_id=run_id
    )
    put_metric(metrics, "LLMCostUSD", report.llm_usage.total_cost_usd, run_id=run_id)
    put_metric(
        metrics,
        "FindingsNew",
        sum(1 for f in findings if f.status.value == "new"),
        run_id=run_id,
    )
    put_metric(metrics, "ActionsAwaitingApproval", len(created_threads), run_id=run_id)

    flush_tracing()
    return {
        "run_id": run_id,
        "report_uri": report.report_uri,
        "action_threads": len(created_threads),
    }


lambda_handler = with_metrics(_handler)

__all__ = ["lambda_handler"]
