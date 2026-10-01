"""``init_run`` Lambda: allocates a run_id, enforces the month-to-date
LLM budget, and — on ``{"refresh": true}`` — dispatches ``prowler.yml``/
``drift.yml`` and (mode ``check_refresh``) polls them for completion.

Real AWS/GitHub wiring only; not exercised by tests (would need live SSM/
DynamoDB/GitHub) — ``steps/init_run.py``'s ``init_run`` carries the tested
logic.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

REFRESH_WORKFLOWS = ("prowler.yml", "drift.yml")


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    import os

    from cloudops_orchestrator.config import load_settings
    from cloudops_orchestrator.steps.init_run import init_run
    from cloudops_orchestrator.store.client import get_table
    from cloudops_orchestrator.store.spend import get_month_to_date_spend

    settings = load_settings(os.environ.get("CLOUDOPS_CONFIG", "config/settings.dev.yaml"))

    if event.get("mode") == "check_refresh":
        return _check_refresh(event, settings=settings)

    now = datetime.now(UTC)
    table = get_table(settings)
    year_month = now.strftime("%Y-%m")
    result = init_run(
        now=now,
        month_to_date_spend_usd=get_month_to_date_spend(table, year_month),
        max_cost_usd_per_month=settings.llm.max_cost_usd_per_month,
    )

    # statemachine/review.asl.json's RefreshRequestedCheck Choice state does
    # `{"Variable": "$.refresh_requested", "BooleanEquals": true}` -- Step
    # Functions raises States.Runtime ("condition path references an
    # invalid value") if that path is missing from the input at all, even
    # with a Default branch present; Default only covers "no rule matched,"
    # not "the path doesn't exist." refresh_requested must always be set.
    # Found live 2026-09-29: every execution this whole deployment had
    # always passed {"refresh": true} explicitly, so a plain trigger with
    # no refresh key (or refresh: false) had never been exercised before
    # and always failed outright (see README.md (Troubleshooting)).
    response: dict[str, Any] = {
        "run_id": result.run_id,
        "started_at": result.started_at.isoformat(),
        "proceed": result.proceed,
        "refresh_requested": False,
    }
    if not result.proceed:
        return response

    if event.get("refresh"):
        dispatched_at = now.isoformat()
        github = _github_client(settings)
        for workflow_file in REFRESH_WORKFLOWS:
            github.dispatch_workflow(workflow_file, ref="main")
        response["refresh_requested"] = True
        response["refresh_dispatched_at"] = dispatched_at
    return response


def _check_refresh(event: dict[str, Any], *, settings: Any) -> dict[str, Any]:
    github = _github_client(settings)
    dispatched_at = event["refresh_dispatched_at"]
    statuses = {
        workflow_file: _latest_status(github, workflow_file, dispatched_at)
        for workflow_file in REFRESH_WORKFLOWS
    }
    done = all(status in ("completed", "not_found") for status in statuses.values())
    return {"refresh_done": done, "refresh_statuses": statuses}


def _latest_status(github: Any, workflow_file: str, dispatched_at: str) -> str:
    runs = github.list_recent_workflow_runs(workflow_file, created_after_iso=dispatched_at)
    if not runs:
        return "not_found"
    latest = max(runs, key=lambda run: run.get("run_number", 0))
    status: str = latest.get("status", "not_found")
    return status


def _github_client(settings: Any) -> Any:
    from cloudops_orchestrator.aws.clients import get_ssm_client
    from cloudops_orchestrator.integrations.github_client import GithubClient

    ssm = get_ssm_client(region_name=settings.aws.region)
    token = ssm.get_parameter(
        Name=f"{settings.storage.parameter_prefix}/github_token",
        WithDecryption=True,  # gitleaks:allow
    )["Parameter"]["Value"]
    return GithubClient(token=token, owner=settings.github.owner, repo=settings.github.repo)


__all__ = ["lambda_handler"]
