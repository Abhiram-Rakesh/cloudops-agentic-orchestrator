from __future__ import annotations

from pathlib import Path

from moto import mock_aws

from cloudops_orchestrator.config import load_settings
from cloudops_orchestrator.store.client import get_table

REPO_ROOT = Path(__file__).resolve().parents[2]


@mock_aws
def test_get_table_returns_named_table() -> None:
    import boto3

    settings = load_settings(REPO_ROOT / "config" / "settings.local.yaml", env={})
    settings = settings.model_copy(update={"environment": "dev"})
    resource = boto3.resource("dynamodb", region_name=settings.aws.region)
    resource.create_table(
        TableName=settings.storage.state_table,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PROVISIONED",
        ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
    )

    table = get_table(settings)
    assert table.table_name == settings.storage.state_table
