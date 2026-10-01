"""``trial_reminder`` Lambda: the one-time day-25 reminder to switch
off the Security Hub/GuardDuty/Config trial before it starts costing money.
Publishes to the observability SNS topic (email) and posts to Slack with
the ``make trials-off`` checklist — see README.md (Security trial lifecycle).

Real AWS/Slack wiring only; not exercised by tests.
"""

from __future__ import annotations

from typing import Any

SWITCHOVER_CHECKLIST = (
    "Your CloudOps Security Hub/GuardDuty/Config trial is ending soon. To avoid charges:\n"
    "1. Run `make trials-off` (edits infra/envs/dev/terraform.tfvars and config/settings.dev.yaml)\n"
    "2. Commit and push the changes\n"
    "3. Run `gh workflow run deploy.yml`\n"
    "4. Record the two SHARED-003 exceptions it prints "
    "(`cloudops exceptions add --clause SEC-004-4.2 ...` and `--clause SEC-004-4.4 ...`)\n"
    "See README.md (Security trial lifecycle) for the full procedure."
)


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    import os

    from cloudops_orchestrator.aws.clients import get_client, get_ssm_client
    from cloudops_orchestrator.config import load_settings
    from cloudops_orchestrator.integrations.slack_client import WebClientSlackAdapter

    settings = load_settings(os.environ.get("CLOUDOPS_CONFIG", "config/settings.dev.yaml"))
    ssm = get_ssm_client(region_name=settings.aws.region)

    sns = get_client("sns", region_name=settings.aws.region)
    sns.publish(
        TopicArn=os.environ["OBSERVABILITY_TOPIC_ARN"],
        Subject="CloudOps: security trial ending soon",
        Message=SWITCHOVER_CHECKLIST,
    )

    bot_token = ssm.get_parameter(
        Name=f"{settings.storage.parameter_prefix}/slack_bot_token",
        WithDecryption=True,  # gitleaks:allow
    )["Parameter"]["Value"]
    WebClientSlackAdapter(bot_token).chat_post_message(
        channel=settings.approvals.slack_channel_id,
        blocks=[{"type": "section", "text": {"type": "mrkdwn", "text": SWITCHOVER_CHECKLIST}}],
        text="CloudOps: security trial ending soon",
    )
    return {"notified": True}


__all__ = ["SWITCHOVER_CHECKLIST", "lambda_handler"]
