from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from moto import mock_aws

from cloudops_orchestrator.models.actions import ActionPlan
from cloudops_orchestrator.models.enums import ActionType, Domain, RiskTier, Severity
from cloudops_orchestrator.models.findings import Finding
from cloudops_orchestrator.policy.config import (
    ProtectedResourcesConfig,
    ProtectedTagRule,
    load_action_allowlist,
)
from cloudops_orchestrator.remediation.runbook_executor import RunbookExecutor, _bare_resource_id
from cloudops_orchestrator.store.audit import list_audit_events
from cloudops_orchestrator.store.findings import put_finding

TABLE_NAME = "cloudops-lite-state-test"
AUTOMATION_ROLE_ARN = "arn:aws:iam::111111111111:role/cloudops-lite-automation"
ALLOWLIST = load_action_allowlist()


def _plan(**overrides: object) -> ActionPlan:
    defaults: dict[str, object] = {
        "action_id": "action-1",
        "recommendation_id": "rec-1",
        "action_type": ActionType.SSM_AUTOMATION,
        # No identifying parameter here by design -- the executor sources it
        # from each target's own Finding.resource_id, never from the plan.
        "parameters": {"document": "CloudOps-ReleaseEIP"},
        "targets": ["fp-1"],
        "effective_risk_tier": RiskTier.T1,
        "required_approvals": 1,
        "expires_at": datetime(2026, 2, 1, tzinfo=UTC),
        "plan_hash": "a" * 64,
    }
    defaults.update(overrides)
    return ActionPlan(**defaults)  # type: ignore[arg-type]


def _finding(**overrides: object) -> Finding:
    defaults: dict[str, object] = {
        "fingerprint": "fp-1",
        "domain": Domain.COST,
        "source": "cost_waste",
        "rule_id": "COST-WASTE-UNASSOCIATED-EIP",
        "title": "t",
        "description": "d",
        "severity": Severity.LOW,
        "account_id": "111111111111",
        "region": "ap-south-1",
        "resource_type": "AwsEc2Eip",
        "resource_id": "eipalloc-1",
        "evidence_uri": "s3://b/k",
        "first_seen": datetime(2026, 1, 1, tzinfo=UTC),
        "last_seen": datetime(2026, 1, 1, tzinfo=UTC),
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


PROTECTED = ProtectedResourcesConfig(
    tags=[ProtectedTagRule(key="cloudops:protected", value="true")]
)


def _executor(**overrides: object) -> RunbookExecutor:
    defaults: dict[str, object] = {
        "enabled": True,
        "dry_run": True,
        "ssm_client": None,
        "protected_resources": PROTECTED,
        "action_allowlist": ALLOWLIST,
        "automation_assume_role_arn": AUTOMATION_ROLE_ARN,
    }
    defaults.update(overrides)
    return RunbookExecutor(**defaults)  # type: ignore[arg-type]


@pytest.fixture
def table() -> Any:
    with mock_aws():
        import boto3

        resource = boto3.resource("dynamodb", region_name="ap-south-1")
        resource.create_table(
            TableName=TABLE_NAME,
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PROVISIONED",
            ProvisionedThroughput={"ReadCapacityUnits": 8, "WriteCapacityUnits": 8},
        )
        yield resource.Table(TABLE_NAME)


class TestDisabled:
    def test_disabled_refuses_without_calling_ssm(self, table: Any) -> None:
        executor = _executor(enabled=False, table=table)
        outcome = executor.dispatch(_plan())
        assert outcome.success is False
        assert "disabled" in outcome.detail


class TestNoDocument:
    def test_missing_document_parameter_refuses(self, table: Any) -> None:
        executor = _executor(table=table)
        outcome = executor.dispatch(_plan(parameters={}))
        assert outcome.success is False
        assert "document" in outcome.detail


class TestMissingFinding:
    def test_target_with_no_stored_finding_refuses(self, table: Any) -> None:
        executor = _executor(table=table)
        outcome = executor.dispatch(_plan())  # fp-1 never put_finding'd
        assert outcome.success is False
        assert "fp-1" in outcome.detail


class TestProtectedTarget:
    def test_protected_target_refuses_and_audits(self, table: Any) -> None:
        put_finding(table, _finding(resource_tags={"cloudops:protected": "true"}))
        executor = _executor(table=table)
        outcome = executor.dispatch(_plan())
        assert outcome.success is False
        assert "protected" in outcome.detail
        events = list_audit_events(table, "ACTION#action-1")
        assert any(e["event"] == "runbook_executor_refused_protected" for e in events)

    def test_unprotected_target_proceeds_to_dry_run(self, table: Any) -> None:
        put_finding(table, _finding(resource_tags={}))
        executor = _executor(table=table)
        outcome = executor.dispatch(_plan())
        assert outcome.success is True
        assert outcome.dry_run is True
        assert "DRY RUN" in outcome.detail


class TestDryRun:
    def test_dry_run_never_calls_ssm(self, table: Any) -> None:
        put_finding(table, _finding())
        executor = _executor(table=table)
        outcome = executor.dispatch(_plan())
        assert outcome.success is True
        assert outcome.dry_run is True
        assert "CloudOps-ReleaseEIP" in outcome.detail
        # The identifying parameter is sourced from the Finding, PascalCased,
        # and paired with a real AutomationAssumeRole -- never left to the
        # model to guess.
        assert "AllocationId" in outcome.detail
        assert "eipalloc-1" in outcome.detail
        assert AUTOMATION_ROLE_ARN in outcome.detail

    def test_security_hub_arn_resource_id_is_reduced_to_the_bare_id(self, table: Any) -> None:
        # Matches a real Security Hub finding exactly: resource_id is a full
        # ARN, not the bare security group id EC2 APIs expect.
        put_finding(
            table,
            _finding(
                resource_id="arn:aws:ec2:ap-south-1:111111111111:security-group/sg-0123456789abcdef0"
            ),
        )
        executor = _executor(table=table)
        plan = _plan(parameters={"document": "CloudOps-RevokeSGIngressWorld", "ports": [22]})
        outcome = executor.dispatch(plan)
        assert outcome.success is True
        assert "sg-0123456789abcdef0" in outcome.detail
        assert "arn:aws:ec2" not in outcome.detail


class TestBareResourceId:
    """Security Hub (ASFF) always reports Finding.resource_id as a full ARN
    -- found live against a real (non-fixture, non-GuardDuty-sample)
    Security Hub finding, whose ARN was passed straight through as
    SecurityGroupId, which EC2 APIs reject outright."""

    def test_ec2_style_arn_extracts_the_part_after_the_last_slash(self) -> None:
        arn = "arn:aws:ec2:ap-south-1:111111111111:security-group/sg-0123456789abcdef0"
        assert _bare_resource_id(arn) == "sg-0123456789abcdef0"

    def test_s3_bucket_arn_has_no_slash_so_the_whole_resource_is_the_bucket_name(self) -> None:
        # arn:aws:s3:::name -- unlike EC2-style ARNs, there's no
        # type/id segment; the part after the final colon already is the id.
        assert _bare_resource_id("arn:aws:s3:::my-real-bucket") == "my-real-bucket"

    def test_non_arn_value_is_returned_unchanged(self) -> None:
        assert _bare_resource_id("sg-already-bare") == "sg-already-bare"


class TestMultiTargetFanOut:
    """The core fix: one Recommendation/ActionPlan can cover several
    targets sharing one remediation (e.g. the same world-open-SSH violation
    on multiple security groups) -- dispatch must call
    start_automation_execution once per target, each with that target's own
    real resource id, not try to cram every target into one call."""

    def test_dry_run_reports_one_line_per_target(self, table: Any) -> None:
        put_finding(table, _finding(fingerprint="fp-1", resource_id="sg-111"))
        put_finding(table, _finding(fingerprint="fp-2", resource_id="sg-222"))
        executor = _executor(table=table)
        plan = _plan(
            parameters={"document": "CloudOps-RevokeSGIngressWorld", "ports": [22, 3389]},
            targets=["fp-1", "fp-2"],
        )
        outcome = executor.dispatch(plan)
        assert outcome.success is True
        assert outcome.dry_run is True
        assert "sg-111" in outcome.detail
        assert "sg-222" in outcome.detail
        assert outcome.detail.count("SecurityGroupId") == 2

    def test_live_dispatch_calls_ssm_once_per_target(self, table: Any) -> None:
        import boto3
        from botocore.stub import Stubber

        put_finding(table, _finding(fingerprint="fp-1", resource_id="sg-111"))
        put_finding(table, _finding(fingerprint="fp-2", resource_id="sg-222"))
        ssm = boto3.client(
            "ssm", region_name="ap-south-1", aws_access_key_id="x", aws_secret_access_key="x"
        )
        stubber = Stubber(ssm)
        expected_tags = [
            {"Key": "action_id", "Value": "action-1"},
            {"Key": "cloudops:managed", "Value": "true"},
        ]
        for sg_id, exec_id in [
            ("sg-111", "00000000-0000-0000-0000-000000000001"),
            ("sg-222", "00000000-0000-0000-0000-000000000002"),
        ]:
            stubber.add_response(
                "start_automation_execution",
                {"AutomationExecutionId": exec_id},
                {
                    "DocumentName": "CloudOps-RevokeSGIngressWorld",
                    "Parameters": {
                        "Ports": ["22", "3389"],
                        "SecurityGroupId": [sg_id],
                        "AutomationAssumeRole": [AUTOMATION_ROLE_ARN],
                    },
                    "Tags": expected_tags,
                },
            )
        with stubber:
            executor = _executor(dry_run=False, ssm_client=ssm, table=table)
            plan = _plan(
                parameters={"document": "CloudOps-RevokeSGIngressWorld", "ports": [22, 3389]},
                targets=["fp-1", "fp-2"],
            )
            outcome = executor.dispatch(plan)
        assert outcome.success is True
        assert outcome.dry_run is False
        assert outcome.external_ref == (
            "00000000-0000-0000-0000-000000000001,00000000-0000-0000-0000-000000000002"
        )
        stubber.assert_no_pending_responses()


class TestLiveDispatch:
    def test_starts_automation_execution(self, table: Any) -> None:
        # moto has no start_automation_execution support (NotImplementedError),
        # so this exercises the live-call path against botocore.stub instead.
        import boto3
        from botocore.stub import Stubber

        put_finding(table, _finding())
        ssm = boto3.client(
            "ssm", region_name="ap-south-1", aws_access_key_id="x", aws_secret_access_key="x"
        )
        stubber = Stubber(ssm)
        stubber.add_response(
            "start_automation_execution",
            {"AutomationExecutionId": "00000000-0000-0000-0000-000000000123"},
            {
                "DocumentName": "CloudOps-ReleaseEIP",
                "Parameters": {
                    "AllocationId": ["eipalloc-1"],
                    "AutomationAssumeRole": [AUTOMATION_ROLE_ARN],
                },
                "Tags": [
                    {"Key": "action_id", "Value": "action-1"},
                    {"Key": "cloudops:managed", "Value": "true"},
                ],
            },
        )
        with stubber:
            executor = _executor(dry_run=False, ssm_client=ssm, table=table)
            outcome = executor.dispatch(_plan())
        assert outcome.success is True
        assert outcome.dry_run is False
        assert outcome.external_ref == "00000000-0000-0000-0000-000000000123"
        stubber.assert_no_pending_responses()

    def test_one_target_failure_does_not_abort_the_rest(self, table: Any) -> None:
        import boto3
        from botocore.stub import Stubber

        put_finding(table, _finding(fingerprint="fp-1", resource_id="sg-111"))
        put_finding(table, _finding(fingerprint="fp-2", resource_id="sg-222"))
        ssm = boto3.client(
            "ssm", region_name="ap-south-1", aws_access_key_id="x", aws_secret_access_key="x"
        )
        stubber = Stubber(ssm)
        stubber.add_client_error(
            "start_automation_execution", service_error_code="ValidationException"
        )
        stubber.add_response(
            "start_automation_execution",
            {"AutomationExecutionId": "00000000-0000-0000-0000-000000000002"},
            {
                "DocumentName": "CloudOps-RevokeSGIngressWorld",
                "Parameters": {
                    "Ports": ["22"],
                    "SecurityGroupId": ["sg-222"],
                    "AutomationAssumeRole": [AUTOMATION_ROLE_ARN],
                },
                "Tags": [
                    {"Key": "action_id", "Value": "action-1"},
                    {"Key": "cloudops:managed", "Value": "true"},
                ],
            },
        )
        with stubber:
            executor = _executor(dry_run=False, ssm_client=ssm, table=table)
            plan = _plan(
                parameters={"document": "CloudOps-RevokeSGIngressWorld", "ports": [22]},
                targets=["fp-1", "fp-2"],
            )
            outcome = executor.dispatch(plan)
        assert outcome.success is False  # one target failed
        assert "sg-111" in outcome.detail
        assert "FAILED" in outcome.detail
        assert outcome.external_ref == "00000000-0000-0000-0000-000000000002"  # sg-222 still ran
        stubber.assert_no_pending_responses()
