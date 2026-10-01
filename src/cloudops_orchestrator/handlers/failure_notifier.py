"""``failure_notifier`` Lambda: the state machine's Catch-all target.
Posts a failure notice to Slack and emits the ``RunFailed`` EMF metric.

Real AWS/Slack wiring only; not exercised by tests.
"""

from __future__ import annotations

from typing import Any

from cloudops_orchestrator.metrics import put_metric, with_metrics


def _handler(event: dict[str, Any], context: Any, metrics: Any) -> dict[str, Any]:
    import os

    from cloudops_orchestrator.aws.clients import get_ssm_client
    from cloudops_orchestrator.config import load_settings
    from cloudops_orchestrator.integrations.slack_client import WebClientSlackAdapter

    settings = load_settings(os.environ.get("CLOUDOPS_CONFIG", "config/settings.dev.yaml"))
    run_id = event.get("run_id", "unknown")
    error = event.get("error", {})

    ssm = get_ssm_client(region_name=settings.aws.region)
    bot_token = ssm.get_parameter(
        Name=f"{settings.storage.parameter_prefix}/slack_bot_token",
        WithDecryption=True,  # gitleaks:allow
    )["Parameter"]["Value"]
    # A Slack section block's text has a hard 3000-character limit. `error`
    # is the state machine's full Catch payload -- for a Lambda exception
    # that includes its entire Python stack trace, easily exceeding that.
    # Untruncated, this call itself fails with invalid_blocks, silently
    # swallowing the original failure notification. Found live: this exact
    # scenario on the first real end-to-end run to hit a failure with a
    # long traceback (see README.md (Troubleshooting)).
    prefix = f":rotating_light: *CloudOps run {run_id} failed*\n```"
    suffix = "```"
    truncation_marker = "\n... (truncated)"
    max_error_len = 3000 - len(prefix) - len(suffix) - len(truncation_marker)
    error_text = str(error)
    if len(error_text) > max_error_len:
        error_text = error_text[:max_error_len] + truncation_marker
    WebClientSlackAdapter(bot_token).chat_post_message(
        channel=settings.approvals.slack_channel_id,
        blocks=[
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{prefix}{error_text}{suffix}",
                },
            }
        ],
        text=f"CloudOps run {run_id} failed",
    )
    put_metric(metrics, "RunFailed", 1, run_id=run_id)
    return {"notified": True}


lambda_handler = with_metrics(_handler)

__all__ = ["lambda_handler"]
