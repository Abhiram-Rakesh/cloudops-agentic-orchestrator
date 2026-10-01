"""``slack_handler`` Lambda: Function URL, auth NONE, verifies Slack's
own HMAC signature in code instead. Handles ``block_actions`` interactions
from the digest's per-action Approve/Reject/Snooze buttons.

The business logic (signature/freshness checks, payload parsing,
authorization, and the approval bookkeeping in ``process_interaction``) is
plain, dependency-injected, and fully unit-testable with fakes. Only
``lambda_handler`` and ``build_deps`` touch real AWS/Slack clients, are
excluded from mypy --strict (see pyproject.toml), and are never exercised
by tests — this project never calls live Slack/AWS from tests.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import parse_qs

from cloudops_orchestrator.graph.action_graph import count_distinct_approvals
from cloudops_orchestrator.models.actions import Approval
from cloudops_orchestrator.models.enums import ApprovalDecision
from cloudops_orchestrator.store.actions import (
    ActionStatus,
    get_action_plan,
    get_approvals,
    has_approved,
    put_approval,
    set_action_status,
)
from cloudops_orchestrator.store.audit import record_audit_event

MAX_TIMESTAMP_AGE_SECONDS = 300
INTERACTIONS_PATH = "/slack/interactions"

_ACTION_ID_TO_DECISION = {
    "approve_action": ApprovalDecision.APPROVE,
    "reject_action": ApprovalDecision.REJECT,
    "snooze_action": ApprovalDecision.SNOOZE,
}


def verify_signature(*, signing_secret: str, timestamp: str, body: str, signature: str) -> bool:
    """Slack's v0 HMAC-SHA256 request signature."""
    basestring = f"v0:{timestamp}:{body}".encode()
    computed = "v0=" + hmac.new(signing_secret.encode(), basestring, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, signature)


def is_fresh(
    timestamp: str, *, now: datetime, max_age_seconds: int = MAX_TIMESTAMP_AGE_SECONDS
) -> bool:
    try:
        ts = int(timestamp)
    except ValueError:
        return False
    return abs(now.timestamp() - ts) <= max_age_seconds


def parse_form_payload(body: str) -> dict[str, Any]:
    """Slack posts ``application/x-www-form-urlencoded`` with a single
    ``payload`` field holding the interaction JSON."""
    fields = parse_qs(body)
    values = fields.get("payload")
    if not values:
        msg = "request body has no 'payload' field"
        raise ValueError(msg)
    parsed: dict[str, Any] = json.loads(values[0])
    return parsed


@dataclass(frozen=True)
class Interaction:
    action_id: str  # approve_action | reject_action | snooze_action
    plan_action_id: str  # the button's `value`: the ActionPlan.action_id
    user_id: str
    user_name: str
    channel_id: str
    message_ts: str
    thread_ts: str | None = None  # the digest's ts when the card is a thread reply
    message_blocks: list[dict[str, Any]] = field(default_factory=list)

    @property
    def decision(self) -> ApprovalDecision:
        return _ACTION_ID_TO_DECISION[self.action_id]


def parse_interaction(payload: dict[str, Any]) -> Interaction:
    if payload.get("type") != "block_actions":
        msg = f"unsupported interaction type: {payload.get('type')!r}"
        raise ValueError(msg)
    actions = payload.get("actions") or []
    if not actions:
        msg = "block_actions payload has no actions"
        raise ValueError(msg)
    action = actions[0]
    if action.get("action_id") not in _ACTION_ID_TO_DECISION:
        msg = f"unrecognized action_id: {action.get('action_id')!r}"
        raise ValueError(msg)
    return Interaction(
        action_id=action["action_id"],
        plan_action_id=action["value"],
        user_id=payload["user"]["id"],
        user_name=payload["user"].get("username", payload["user"]["id"]),
        channel_id=payload["channel"]["id"],
        message_ts=payload["message"]["ts"],
        thread_ts=payload["message"].get("thread_ts"),
        message_blocks=list(payload["message"].get("blocks") or []),
    )


def is_authorized(user_id: str, *, approvers: list[str]) -> bool:
    return user_id in approvers


class SlackClient(Protocol):
    def chat_update(
        self,
        *,
        channel: str,
        ts: str,
        text: str,
        blocks: list[dict[str, Any]] | None = None,
    ) -> None: ...
    def post_ephemeral(self, *, channel: str, user: str, text: str) -> None: ...


def _context_block(text: str) -> dict[str, Any]:
    return {"type": "context", "elements": [{"type": "mrkdwn", "text": text}]}


def decided_card_blocks(
    blocks: list[dict[str, Any]], status_text: str, *, keep_buttons: bool
) -> list[dict[str, Any]] | None:
    """The approval card after a click: a status line appended, and the
    Approve/Reject/Snooze buttons removed once the decision is final.

    ``None`` when the original blocks are unknown, so the caller falls back
    to a text-only update.
    """
    if not blocks:
        return None
    kept = [b for b in blocks if keep_buttons or b.get("type") != "actions"]
    return [*kept, _context_block(status_text)]


@dataclass(frozen=True)
class ProcessResult:
    invoked_worker: bool
    reason: str
    approval: Approval | None = None


def process_interaction(
    interaction: Interaction,
    *,
    table: Any,
    slack_client: SlackClient,
    now: datetime | None = None,
) -> ProcessResult:
    """The async self-invocation's work: validate the action
    is still awaiting approval and not expired, conditionally record the
    approval (idempotent per approver), update the Slack message, and
    report whether the caller should now invoke ``action_worker``."""
    now = now or datetime.now(UTC)
    found = get_action_plan(table, interaction.plan_action_id)
    if found is None:
        return ProcessResult(invoked_worker=False, reason="unknown action_id")
    plan, status = found

    if status != ActionStatus.AWAITING_APPROVAL:
        return ProcessResult(invoked_worker=False, reason=f"action already {status}")
    if now > plan.expires_at:
        set_action_status(table, plan.action_id, ActionStatus.EXPIRED)
        return ProcessResult(invoked_worker=False, reason="action plan has expired")

    decision = interaction.decision
    if decision == ApprovalDecision.APPROVE and has_approved(
        table, plan.action_id, interaction.user_id
    ):
        return ProcessResult(invoked_worker=False, reason="duplicate approval (idempotent)")

    approval = Approval(
        action_id=plan.action_id,
        plan_hash=plan.plan_hash,
        decision=decision,
        approver_slack_id=interaction.user_id,
        approver_name=interaction.user_name,
        decided_at=now,
    )
    put_approval(table, approval)
    record_audit_event(
        table,
        entity=f"ACTION#{plan.action_id}",
        event=f"slack_{decision.value}",
        details={"approver": interaction.user_id},
        at=now,
    )
    approvals_so_far = count_distinct_approvals(get_approvals(table, plan.action_id))
    should_invoke = (
        decision != ApprovalDecision.APPROVE or approvals_so_far >= plan.required_approvals
    )
    if should_invoke:
        status_text = f"{interaction.user_name} chose *{decision.value}*."
        if decision == ApprovalDecision.APPROVE:
            status_text += " The outcome will be posted in this thread."
    else:
        status_text = (
            f"{interaction.user_name} approved ({approvals_so_far} of "
            f"{plan.required_approvals}); waiting for another approver."
        )
    slack_client.chat_update(
        channel=interaction.channel_id,
        ts=interaction.message_ts,
        text=status_text,
        blocks=decided_card_blocks(
            interaction.message_blocks, status_text, keep_buttons=not should_invoke
        ),
    )
    reason = "threshold reached" if should_invoke else "awaiting more approvals"
    return ProcessResult(invoked_worker=should_invoke, reason=reason, approval=approval)


def _http_response(status_code: int) -> dict[str, Any]:
    return {"statusCode": status_code, "body": ""}


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Real Lambda Function URL entrypoint. Not exercised by tests (would
    need a live Slack signing secret + a real self-invoke) — every branch
    below delegates to a pure, tested function above; this just wires them
    to real settings/AWS/Slack clients built lazily so importing this
    module never touches AWS.
    """
    import base64
    import os

    from cloudops_orchestrator.aws.clients import get_lambda_client, get_ssm_client
    from cloudops_orchestrator.config import load_settings
    from cloudops_orchestrator.integrations.slack_client import WebClientSlackAdapter
    from cloudops_orchestrator.store.client import get_table

    settings = load_settings(os.environ.get("CLOUDOPS_CONFIG", "config/settings.dev.yaml"))
    ssm = get_ssm_client(region_name=settings.aws.region)
    signing_secret = ssm.get_parameter(
        Name=f"{settings.storage.parameter_prefix}/slack_signing_secret",
        WithDecryption=True,  # gitleaks:allow
    )["Parameter"]["Value"]

    if event.get("_async_dispatch"):
        table = get_table(settings)

        bot_token = ssm.get_parameter(
            Name=f"{settings.storage.parameter_prefix}/slack_bot_token",
            WithDecryption=True,  # gitleaks:allow
        )["Parameter"]["Value"]
        slack_client = WebClientSlackAdapter(bot_token)

        interaction = parse_interaction(event["_payload"])
        result = process_interaction(interaction, table=table, slack_client=slack_client)
        if result.invoked_worker and result.approval is not None:
            lambda_client = get_lambda_client(region_name=settings.aws.region)
            lambda_client.invoke(
                FunctionName=os.environ["ACTION_WORKER_FUNCTION_NAME"],
                InvocationType="Event",
                Payload=json.dumps(
                    {
                        "action_id": result.approval.action_id,
                        "approval": result.approval.model_dump(mode="json"),
                        # where action_worker posts the outcome
                        "slack": {
                            "channel": interaction.channel_id,
                            "thread_ts": interaction.thread_ts or interaction.message_ts,
                        },
                    }
                ),
            )
        return _http_response(200)

    method = event.get("requestContext", {}).get("http", {}).get("method")
    path = event.get("rawPath", "")
    if method != "POST" or path != INTERACTIONS_PATH:
        return _http_response(404)

    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    body = event.get("body", "") or ""
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8")

    now = datetime.now(UTC)
    timestamp = headers.get("x-slack-request-timestamp", "")
    signature = headers.get("x-slack-signature", "")
    if not is_fresh(timestamp, now=now) or not verify_signature(
        signing_secret=signing_secret, timestamp=timestamp, body=body, signature=signature
    ):
        return _http_response(401)

    payload = parse_form_payload(body)
    if payload.get("type") != "block_actions":
        return _http_response(404)

    interaction = parse_interaction(payload)
    if not is_authorized(interaction.user_id, approvers=settings.approvals.approvers):
        bot_token = ssm.get_parameter(
            Name=f"{settings.storage.parameter_prefix}/slack_bot_token",
            WithDecryption=True,  # gitleaks:allow
        )["Parameter"]["Value"]
        WebClientSlackAdapter(bot_token).post_ephemeral(
            channel=interaction.channel_id, user=interaction.user_id, text="You are not authorized."
        )
        return _http_response(200)

    lambda_client = get_lambda_client(region_name=settings.aws.region)
    lambda_client.invoke(
        FunctionName=os.environ["SLACK_HANDLER_FUNCTION_NAME"],
        InvocationType="Event",
        Payload=json.dumps({**event, "_async_dispatch": True, "_payload": payload}),
    )
    return _http_response(200)


__all__ = [
    "INTERACTIONS_PATH",
    "Interaction",
    "ProcessResult",
    "SlackClient",
    "decided_card_blocks",
    "is_authorized",
    "is_fresh",
    "lambda_handler",
    "parse_form_payload",
    "parse_interaction",
    "process_interaction",
    "verify_signature",
]
