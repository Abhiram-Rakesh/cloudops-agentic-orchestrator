"""``Publish`` step: write the rendered report to S3 with a presigned
URL and post the Slack digest.
"""

from __future__ import annotations

from typing import Any

from cloudops_orchestrator.models.report import RunReport
from cloudops_orchestrator.report.render import render_report_html, render_report_json


def publish_live(
    report: RunReport,
    *,
    s3_client: Any,
    bucket: str,
    presign_days: int = 7,
    timezone: str = "Asia/Kolkata",
) -> RunReport:
    """Write the report to ``reports/{run_id}.{html,json}`` and presign a
    GET URL for the HTML report — what the Slack digest's "Open full
    report" button links to."""
    html_key = f"reports/{report.run_id}.html"
    json_key = f"reports/{report.run_id}.json"

    s3_client.put_object(
        Bucket=bucket,
        Key=html_key,
        Body=render_report_html(report, timezone=timezone).encode("utf-8"),
        ContentType="text/html",
    )
    updated = report.model_copy(update={"json_uri": f"s3://{bucket}/{json_key}"})
    s3_client.put_object(
        Bucket=bucket,
        Key=json_key,
        Body=render_report_json(updated).encode("utf-8"),
        ContentType="application/json",
    )

    presigned_url: str = s3_client.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": html_key},
        ExpiresIn=presign_days * 86400,
    )
    return updated.model_copy(update={"report_uri": presigned_url})


__all__ = ["publish_live"]
