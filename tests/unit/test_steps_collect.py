from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import boto3
from moto import mock_aws

from cloudops_orchestrator.config import load_settings
from cloudops_orchestrator.models.enums import Domain
from cloudops_orchestrator.models.findings import Finding
from cloudops_orchestrator.steps.collect import enrich_iac_managed, run_collect

REPO_ROOT = Path(__file__).resolve().parents[2]


def _finding(**overrides: object) -> Finding:
    defaults: dict[str, object] = {
        "fingerprint": "a" * 32,
        "domain": Domain.SECURITY,
        "source": "securityhub",
        "rule_id": "EC2.13",
        "control_ids": ["EC2.13"],
        "title": "t",
        "description": "d",
        "severity": "high",
        "account_id": "1",
        "region": "r",
        "resource_type": "AwsEc2SecurityGroup",
        "resource_id": "sg-1",
        "evidence_uri": "s3://b/k",
        "first_seen": datetime(2026, 1, 1, tzinfo=UTC),
        "last_seen": datetime(2026, 1, 1, tzinfo=UTC),
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


def test_enrich_iac_managed_sets_address_when_matched() -> None:
    finding = _finding(resource_id="sg-1", iac_managed=False)
    (enriched,) = enrich_iac_managed([finding], inventory_lookup={"sg-1": "aws_security_group.app"})
    assert enriched.iac_managed is True
    assert enriched.iac_address == "aws_security_group.app"


def test_enrich_iac_managed_leaves_unmatched_alone() -> None:
    finding = _finding(resource_id="sg-unmatched", iac_managed=False)
    (enriched,) = enrich_iac_managed([finding], inventory_lookup={"sg-1": "aws_security_group.app"})
    assert enriched.iac_managed is False
    assert enriched.iac_address is None


def _create_state_table() -> Any:
    resource = boto3.resource("dynamodb", region_name="ap-south-1")
    return resource.create_table(
        TableName="state-test",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "gsi1pk", "AttributeType": "S"},
            {"AttributeName": "gsi1sk", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "gsi1",
                "KeySchema": [
                    {"AttributeName": "gsi1pk", "KeyType": "HASH"},
                    {"AttributeName": "gsi1sk", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
                "ProvisionedThroughput": {"ReadCapacityUnits": 3, "WriteCapacityUnits": 3},
            }
        ],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 8, "WriteCapacityUnits": 8},
    )


@mock_aws
def test_run_collect_against_real_fixtures() -> None:
    settings = load_settings(REPO_ROOT / "config" / "settings.local.yaml", env={})
    table = _create_state_table()
    result = run_collect(
        run_id="run-1",
        settings=settings,
        account=settings.aws.accounts[0],
        now=datetime(2026, 1, 27, tzinfo=UTC),
        fixtures_dir=REPO_ROOT / "tests" / "fixtures" / "scenario_demo",
        table=table,
    )
    assert len(result.findings) > 0
    assert set(result.groups_by_domain) <= {Domain.SECURITY, Domain.COST, Domain.DRIFT}
    assert sum(len(groups) for groups in result.groups_by_domain.values()) > 0
    # Security-Hub-managed sg findings should have been enriched as iac_managed
    # via the drift inventory (they're all Terraform-managed in the baseline).
    sec_findings = [f for f in result.findings if f.domain == Domain.SECURITY]
    assert any(f.iac_managed for f in sec_findings)
