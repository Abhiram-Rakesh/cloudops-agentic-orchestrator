"""Moto-backed tests for store/spend.py's month-to-date LLM spend tracking."""

from __future__ import annotations

from typing import Any

import pytest
from moto import mock_aws

from cloudops_orchestrator.store.spend import add_spend, get_month_to_date_spend

TABLE_NAME = "cloudops-lite-state-test"


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
            ProvisionedThroughput={"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
        )
        yield resource.Table(TABLE_NAME)


def test_get_spend_defaults_to_zero(table: Any) -> None:
    assert get_month_to_date_spend(table, "2026-01") == 0.0


def test_add_spend_accumulates(table: Any) -> None:
    add_spend(table, "2026-01", 1.5)
    total = add_spend(table, "2026-01", 0.75)
    assert total == pytest.approx(2.25)
    assert get_month_to_date_spend(table, "2026-01") == pytest.approx(2.25)


def test_add_spend_independent_per_month(table: Any) -> None:
    add_spend(table, "2026-01", 1.0)
    add_spend(table, "2026-02", 5.0)
    assert get_month_to_date_spend(table, "2026-01") == pytest.approx(1.0)
    assert get_month_to_date_spend(table, "2026-02") == pytest.approx(5.0)
