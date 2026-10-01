"""``action_worker`` Lambda: resumes the ``action:{action_id}``
LangGraph thread with a Slack approval decision. Invoked asynchronously by
``slack_handler`` with ``{"action_id": ..., "approval": {...}, "slack": {...}}``;
afterwards it posts the outcome back to the digest thread.

``resume_action_thread`` carries all the tested logic (lock acquisition,
graph resume, lock release) and takes its dependencies by injection, so it
runs against a moto-backed table and the sqlite checkpointer in tests —
only ``lambda_handler`` touches real settings/AWS and is excluded from
mypy --strict (see pyproject.toml).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from langgraph.types import Command

from cloudops_orchestrator.graph.action_graph import ActionGraphDeps, build_action_graph
from cloudops_orchestrator.models.actions import Approval
from cloudops_orchestrator.store.actions import acquire_lock, release_lock


def resume_action_thread(
    action_id: str,
    approval: Approval,
    *,
    deps: ActionGraphDeps,
    checkpointer: Any,
    now: datetime | None = None,
) -> dict[str, Any] | None:
    """Resume the action thread with ``approval``. Returns ``None`` — a
    no-op — if the per-action lock is already held: a concurrent
    invocation (duplicate Slack retry, an overlapping approval) is already
    resuming this same thread, and DynamoDB's conditional put means at most
    one caller ever proceeds past this point."""
    now = now or datetime.now(UTC)
    if not acquire_lock(deps["table"], action_id, now=now):
        return None
    try:
        graph = build_action_graph(deps, checkpointer=checkpointer)
        thread_config = {"configurable": {"thread_id": f"action:{action_id}"}}
        result = graph.invoke(Command(resume=approval.model_dump(mode="json")), thread_config)
        return dict(result)
    finally:
        release_lock(deps["table"], action_id)


_MAX_OUTCOME_CHARS = 2800  # Slack section text limit is 3000


def format_outcome(result: dict[str, Any] | None) -> str | None:
    """Slack text describing how a resumed action thread ended, or ``None``
    when there is nothing to report (a lock-skipped resume, or a first
    approval of a two-approver action that is still waiting)."""
    if not result:
        return None
    decision = result.get("decision")
    remediation = result.get("remediation")
    if decision == "rejected":
        return ":no_entry_sign: *Rejected.* Recorded; this finding stays a manual ticket."
    if decision == "snoozed":
        return ":zzz: *Snoozed.* A time-bound exception was recorded for this finding."
    if decision == "queued_outside_window":
        return ":hourglass: *Approved, but not executed:* it is outside the T2 change window."
    if decision == "refused_kill_switch":
        return ":octagonal_sign: *Refused:* the kill switch is on. No action was taken."
    if not remediation:
        return None
    detail = str(remediation.get("detail") or "").strip()
    if len(detail) > _MAX_OUTCOME_CHARS:
        detail = detail[:_MAX_OUTCOME_CHARS] + "..."
    if not remediation.get("success", True):
        return f":x: *Remediation failed.*\n{detail}"
    if remediation.get("dry_run"):
        return f":white_check_mark: *Dry run complete.* No changes were made.\n{detail}"
    external_ref = remediation.get("external_ref")
    suffix = f"\nReference: `{external_ref}`" if external_ref else ""
    return f":white_check_mark: *Executed.*\n{detail}{suffix}"


def post_outcome(
    slack_client: Any, *, slack: dict[str, Any] | None, result: dict[str, Any] | None
) -> bool:
    """Post the outcome as a reply in the digest thread. ``slack`` is the
    ``{"channel", "thread_ts"}`` context ``slack_handler`` passed along.
    Returns whether anything was posted."""
    text = format_outcome(result)
    if not slack or text is None:
        return False
    slack_client.chat_post_message(
        channel=slack["channel"],
        thread_ts=slack.get("thread_ts"),
        text=text,
        blocks=[{"type": "section", "text": {"type": "mrkdwn", "text": text}}],
    )
    return True


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Real Lambda entrypoint. Not exercised by tests (would need live AWS
    and — for a ``terraform_pr``/``ssm_automation`` action — a live GitHub
    token or Anthropic call) — ``resume_action_thread`` above carries all
    the tested logic; this just wires it and the right ``Remediator`` for
    the resuming action's ``action_type`` to real settings/AWS/GitHub/LLM
    clients built lazily so importing this module never touches them.
    """
    import os

    from cloudops_orchestrator.aws.clients import assume_role_client, get_ssm_client
    from cloudops_orchestrator.checkpoint.factory import get_checkpointer
    from cloudops_orchestrator.config import load_settings
    from cloudops_orchestrator.integrations.github_client import GithubClient
    from cloudops_orchestrator.llm.factory import get_reasoning_model
    from cloudops_orchestrator.llm.tracing import enable_tracing, flush_tracing
    from cloudops_orchestrator.models.enums import ActionType
    from cloudops_orchestrator.policy.config import (
        load_action_allowlist,
        load_protected_resources,
        load_risk_tiers,
    )
    from cloudops_orchestrator.remediation.dispatch import remediator_for
    from cloudops_orchestrator.store.actions import get_action_plan
    from cloudops_orchestrator.store.client import get_table

    settings = load_settings(os.environ.get("CLOUDOPS_CONFIG", "config/settings.dev.yaml"))
    table = get_table(settings)
    action_id = event["action_id"]

    found = get_action_plan(table, action_id)
    if found is None:
        return {"resumed": False, "reason": "unknown action_id"}
    plan, _status = found

    ssm = get_ssm_client(region_name=settings.aws.region)
    github_token = ssm.get_parameter(
        Name=f"{settings.storage.parameter_prefix}/github_token",
        WithDecryption=True,  # gitleaks:allow
    )["Parameter"]["Value"]
    github_client = GithubClient(
        token=github_token, owner=settings.github.owner, repo=settings.github.repo
    )
    anthropic_api_key = ssm.get_parameter(
        Name=f"{settings.storage.parameter_prefix}/anthropic_api_key",
        WithDecryption=True,  # gitleaks:allow
    )["Parameter"]["Value"]
    langsmith_api_key = ssm.get_parameter(
        Name=f"{settings.storage.parameter_prefix}/langsmith_api_key",
        WithDecryption=True,  # gitleaks:allow
    )["Parameter"]["Value"]
    enable_tracing(settings.langsmith, api_key=langsmith_api_key)

    # SSM automations run as the dedicated executor role, not this Lambda's
    # own default credentials -- scoped per approved action via session
    # tags for audit trail (executor's trust policy requires both;
    # StringLike "*" means it doesn't pin a specific value, so plan_hash is
    # a meaningful, traceable stand-in for "approval_id" -- no distinct
    # concept of one exists yet). Was previously granted in IAM but never
    # actually called anywhere in the code (see README.md (Troubleshooting)).
    remediation_ssm_client = ssm
    if plan.action_type == ActionType.SSM_AUTOMATION:
        remediation_ssm_client = assume_role_client(
            "ssm",
            role_arn=os.environ["EXECUTOR_ROLE_ARN"],
            session_name=f"action-{action_id}"[:64],
            tags={"approval_id": plan.plan_hash, "action_id": action_id},
            region_name=settings.aws.region,
        )

    remediator = remediator_for(
        plan,
        settings=settings,
        github_client=github_client,
        llm_model=get_reasoning_model(settings.llm, api_key=anthropic_api_key),
        ssm_client=remediation_ssm_client,
        table=table,
        protected_resources=load_protected_resources(),
        action_allowlist=load_action_allowlist(),
        automation_assume_role_arn=os.environ.get("AUTOMATION_ROLE_ARN", ""),
    )
    deps = ActionGraphDeps(
        settings=settings, risk_tiers=load_risk_tiers(), remediator=remediator, table=table
    )
    approval = Approval.model_validate(event["approval"])
    result = resume_action_thread(
        action_id, approval, deps=deps, checkpointer=get_checkpointer(settings)
    )
    flush_tracing()
    _post_outcome_to_slack(settings, ssm, event.get("slack"), result)
    return {"resumed": result is not None}


def _post_outcome_to_slack(
    settings: Any, ssm: Any, slack: dict[str, Any] | None, result: dict[str, Any] | None
) -> None:
    """Best effort: a Slack problem must never fail an action that already ran."""
    from cloudops_orchestrator.integrations.slack_client import WebClientSlackAdapter
    from cloudops_orchestrator.logging import get_logger

    if not slack or format_outcome(result) is None:
        return
    try:
        bot_token = ssm.get_parameter(
            Name=f"{settings.storage.parameter_prefix}/slack_bot_token",
            WithDecryption=True,  # gitleaks:allow
        )["Parameter"]["Value"]
        post_outcome(WebClientSlackAdapter(bot_token), slack=slack, result=result)
    except Exception as exc:
        get_logger().warning("action_worker.slack_outcome_failed", error=str(exc))


__all__ = ["format_outcome", "lambda_handler", "post_outcome", "resume_action_thread"]
