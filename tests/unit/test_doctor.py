from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import boto3
import pytest
from moto import mock_aws

from cloudops_orchestrator.doctor import (
    CheckStatus,
    check_artifact_freshness,
    check_budgets,
    check_cost_explorer,
    check_dynamodb_tables,
    check_github_token,
    check_kb_index,
    check_langsmith_key,
    check_security_trial,
    check_slack_auth,
    check_ssm_parameters,
    check_state_machine_and_schedule,
    check_sts_identity,
    check_titan_access,
)

REGION = "ap-south-1"


class TestStsIdentity:
    def test_ok(self) -> None:
        with mock_aws():
            sts = boto3.client("sts", region_name=REGION)
            result = check_sts_identity(sts)
            assert result.status == CheckStatus.OK
            assert "Account" in result.detail

    def test_client_error_becomes_fail(self) -> None:
        class BrokenClient:
            def get_caller_identity(self) -> dict[str, Any]:
                raise RuntimeError("boom")

        result = check_sts_identity(BrokenClient())
        assert result.status == CheckStatus.FAIL
        assert "boom" in result.detail


class TestDynamoDbTables:
    @pytest.fixture
    def client(self) -> Any:
        with mock_aws():
            client = boto3.client("dynamodb", region_name=REGION)
            client.create_table(
                TableName="t1",
                KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
                AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
                BillingMode="PROVISIONED",
                ProvisionedThroughput={"ReadCapacityUnits": 8, "WriteCapacityUnits": 8},
            )
            yield client

    def test_provisioned_within_budget_is_ok(self, client: Any) -> None:
        result = check_dynamodb_tables(client, ["t1"])
        assert result.status == CheckStatus.OK

    def test_missing_table_is_fail(self, client: Any) -> None:
        result = check_dynamodb_tables(client, ["nonexistent"])
        assert result.status == CheckStatus.FAIL


class TestSsmParameters:
    @pytest.fixture
    def client(self) -> Any:
        with mock_aws():
            client = boto3.client("ssm", region_name=REGION)
            client.put_parameter(Name="/app/good", Value="real-value", Type="SecureString")
            client.put_parameter(Name="/app/placeholder", Value="CHANGE_ME", Type="SecureString")
            yield client

    def test_all_set_is_ok(self, client: Any) -> None:
        result = check_ssm_parameters(client, ["/app/good"])
        assert result.status == CheckStatus.OK

    def test_placeholder_is_warn(self, client: Any) -> None:
        result = check_ssm_parameters(client, ["/app/good", "/app/placeholder"])
        assert result.status == CheckStatus.WARN
        assert "/app/placeholder" in result.detail

    def test_missing_is_fail(self, client: Any) -> None:
        result = check_ssm_parameters(client, ["/app/missing"])
        assert result.status == CheckStatus.FAIL


class TestTitanAccess:
    def test_warns_on_failure_without_crashing(self) -> None:
        class FakeBedrock:
            def get_foundation_model(self, modelIdentifier: str) -> None:
                raise RuntimeError("AccessDeniedException")

        result = check_titan_access(FakeBedrock())
        assert result.status == CheckStatus.WARN

    def test_ok_when_listed(self) -> None:
        class FakeBedrock:
            def get_foundation_model(self, modelIdentifier: str) -> dict[str, Any]:
                return {"modelDetails": {"modelId": modelIdentifier}}

        result = check_titan_access(FakeBedrock())
        assert result.status == CheckStatus.OK


class TestSecurityTrial:
    def test_reports_days_remaining(self) -> None:
        class Disabled:
            def describe_hub(self) -> None:
                raise RuntimeError("not subscribed")

            def list_detectors(self) -> dict[str, Any]:
                return {"DetectorIds": []}

            def describe_configuration_recorders(self) -> dict[str, Any]:
                return {"ConfigurationRecorders": []}

        result = check_security_trial(
            securityhub_client=Disabled(),
            guardduty_client=Disabled(),
            config_client=Disabled(),
            trial_start_date="2026-01-01",
            now=datetime(2026, 1, 27, tzinfo=UTC),
        )
        assert "4 day(s)" in result.detail
        assert result.status == CheckStatus.WARN

    def test_ok_when_far_from_trial_end(self) -> None:
        class Enabled:
            def describe_hub(self) -> dict[str, Any]:
                return {}

            def list_detectors(self) -> dict[str, Any]:
                return {"DetectorIds": ["d1"]}

            def describe_configuration_recorders(self) -> dict[str, Any]:
                return {"ConfigurationRecorders": [{"name": "r1"}]}

        result = check_security_trial(
            securityhub_client=Enabled(),
            guardduty_client=Enabled(),
            config_client=Enabled(),
            trial_start_date="2026-01-01",
            now=datetime(2026, 1, 5, tzinfo=UTC),
        )
        assert result.status == CheckStatus.OK
        assert "enabled" in result.detail


class TestCostExplorer:
    def test_warns_when_no_monitors(self) -> None:
        class FakeCe:
            def get_anomaly_monitors(self) -> dict[str, Any]:
                return {"AnomalyMonitors": []}

        assert check_cost_explorer(FakeCe()).status == CheckStatus.WARN

    def test_ok_when_monitors_exist(self) -> None:
        class FakeCe:
            def get_anomaly_monitors(self) -> dict[str, Any]:
                return {"AnomalyMonitors": [{"MonitorArn": "x"}]}

        assert check_cost_explorer(FakeCe()).status == CheckStatus.OK


class TestKbIndex:
    def test_ok_when_present(self) -> None:
        import gzip
        import json

        with mock_aws():
            s3 = boto3.client("s3", region_name=REGION)
            s3.create_bucket(
                Bucket="test-bucket", CreateBucketConfiguration={"LocationConstraint": REGION}
            )
            body = gzip.compress(json.dumps({"kb_version": "abc123"}).encode())
            s3.put_object(Bucket="test-bucket", Key="kb/index/sop_index.json.gz", Body=body)
            result = check_kb_index(s3, bucket="test-bucket", key="kb/index/sop_index.json.gz")
            assert result.status == CheckStatus.OK
            assert "abc123" in result.detail

    def test_fail_when_missing(self) -> None:
        with mock_aws():
            s3 = boto3.client("s3", region_name=REGION)
            s3.create_bucket(
                Bucket="test-bucket", CreateBucketConfiguration={"LocationConstraint": REGION}
            )
            result = check_kb_index(s3, bucket="test-bucket", key="kb/index/sop_index.json.gz")
            assert result.status == CheckStatus.FAIL


class TestArtifactFreshness:
    def test_warns_on_missing_object(self) -> None:
        with mock_aws():
            s3 = boto3.client("s3", region_name=REGION)
            s3.create_bucket(
                Bucket="test-bucket", CreateBucketConfiguration={"LocationConstraint": REGION}
            )
            result = check_artifact_freshness(
                s3, bucket="test-bucket", key="prowler/latest/findings.json", max_age_days=8
            )
            assert result.status == CheckStatus.WARN


class TestSlackAuth:
    def test_ok(self) -> None:
        class FakeSlack:
            def auth_test(self) -> dict[str, Any]:
                return {"user": "cloudops-bot"}

        result = check_slack_auth(FakeSlack())
        assert result.status == CheckStatus.OK
        assert "cloudops-bot" in result.detail

    def test_failure_becomes_fail(self) -> None:
        class FakeSlack:
            def auth_test(self) -> dict[str, Any]:
                raise RuntimeError("invalid_auth")

        assert check_slack_auth(FakeSlack()).status == CheckStatus.FAIL


class TestGithubToken:
    def test_ok(self) -> None:
        class FakeGithub:
            def get_default_branch(self) -> str:
                return "main"

        result = check_github_token(FakeGithub(), owner="acme", repo="demo")
        assert result.status == CheckStatus.OK


class TestLangsmithKey:
    def test_ok_when_set(self) -> None:
        with mock_aws():
            ssm = boto3.client("ssm", region_name=REGION)
            ssm.put_parameter(Name="/app/langsmith_api_key", Value="real", Type="SecureString")
            result = check_langsmith_key(ssm, parameter_name="/app/langsmith_api_key")
            assert result.status == CheckStatus.OK

    def test_warn_when_placeholder(self) -> None:
        with mock_aws():
            ssm = boto3.client("ssm", region_name=REGION)
            ssm.put_parameter(Name="/app/langsmith_api_key", Value="CHANGE_ME", Type="SecureString")
            result = check_langsmith_key(ssm, parameter_name="/app/langsmith_api_key")
            assert result.status == CheckStatus.WARN


class TestStateMachineAndSchedule:
    def test_ok(self) -> None:
        class FakeScheduler:
            def get_schedule(self, Name: str) -> dict[str, Any]:
                return {"State": "ENABLED"}

        result = check_state_machine_and_schedule(FakeScheduler(), name_prefix="cloudops-lite")
        assert result.status == CheckStatus.OK
        assert "ENABLED" in result.detail


class TestBudgets:
    def test_warns_when_no_budgets(self) -> None:
        with mock_aws():
            client = boto3.client("budgets", region_name="us-east-1")
            result = check_budgets(client, account_id="111111111111")
            assert result.status == CheckStatus.WARN
