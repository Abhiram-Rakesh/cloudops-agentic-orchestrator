from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from moto import mock_aws

from cloudops_orchestrator.models.enums import Domain, FindingStatus
from cloudops_orchestrator.models.report import LLMUsage, RunReport
from cloudops_orchestrator.steps.publish import publish_live

BUCKET = "cloudops-lite-test-artifacts"


def _report() -> RunReport:
    return RunReport(
        run_id="run-1",
        started_at=datetime(2026, 1, 1, tzinfo=UTC),
        finished_at=datetime(2026, 1, 1, 1, tzinfo=UTC),
        counts={Domain.SECURITY: {FindingStatus.NEW: 0}},
        executive_summary="summary",
        items=[],
        resolved=[],
        suppressed=[],
        llm_usage=LLMUsage(per_model={}, total_cost_usd=0.0, budget_exhausted=False),
    )


def test_publish_live_writes_to_s3_and_presigns_url() -> None:
    with mock_aws():
        import boto3

        s3: Any = boto3.client("s3", region_name="ap-south-1")
        s3.create_bucket(
            Bucket=BUCKET, CreateBucketConfiguration={"LocationConstraint": "ap-south-1"}
        )

        updated = publish_live(_report(), s3_client=s3, bucket=BUCKET, presign_days=7)

        assert updated.json_uri == f"s3://{BUCKET}/reports/run-1.json"
        assert updated.report_uri is not None
        assert updated.report_uri.startswith("https://")
        assert "reports/run-1.html" in updated.report_uri

        html_body = s3.get_object(Bucket=BUCKET, Key="reports/run-1.html")["Body"].read()
        assert b"summary" in html_body
        json_body = s3.get_object(Bucket=BUCKET, Key="reports/run-1.json")["Body"].read()
        assert b"run-1" in json_body
