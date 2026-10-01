"""Moto-backed tests for store/findings.py's NEW -> OPEN -> RESOLVED lifecycle."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from moto import mock_aws

from cloudops_orchestrator.models.enums import Domain, FindingStatus, Severity
from cloudops_orchestrator.models.findings import Finding
from cloudops_orchestrator.store import findings as store_findings

TABLE_NAME = "cloudops-lite-state-test"


def _finding(**overrides: object) -> Finding:
    defaults: dict[str, object] = {
        "fingerprint": "a" * 32,
        "domain": Domain.SECURITY,
        "source": "securityhub",
        "rule_id": "EC2.13",
        "control_ids": ["EC2.13"],
        "title": "t",
        "description": "d",
        "severity": Severity.HIGH,
        "account_id": "111111111111",
        "region": "ap-south-1",
        "resource_type": "AwsEc2SecurityGroup",
        "resource_id": "sg-1",
        "evidence_uri": "s3://b/k",
        "first_seen": datetime(2026, 1, 1, tzinfo=UTC),
        "last_seen": datetime(2026, 1, 1, tzinfo=UTC),
    }
    defaults.update(overrides)
    return Finding(**defaults)  # type: ignore[arg-type]


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
        yield resource.Table(TABLE_NAME)


class TestUpsert:
    def test_new_finding_gets_new_status(self, table: Any) -> None:
        stored = store_findings.upsert_finding(table, _finding())
        assert stored.status == FindingStatus.NEW

    def test_reupserting_transitions_to_open(self, table: Any) -> None:
        store_findings.upsert_finding(table, _finding())
        stored = store_findings.upsert_finding(
            table, _finding(last_seen=datetime(2026, 1, 5, tzinfo=UTC))
        )
        assert stored.status == FindingStatus.OPEN

    def test_first_seen_preserved_across_upserts(self, table: Any) -> None:
        store_findings.upsert_finding(table, _finding(first_seen=datetime(2026, 1, 1, tzinfo=UTC)))
        stored = store_findings.upsert_finding(
            table,
            _finding(
                first_seen=datetime(2026, 1, 10, tzinfo=UTC),
                last_seen=datetime(2026, 1, 10, tzinfo=UTC),
            ),
        )
        assert stored.first_seen == datetime(2026, 1, 1, tzinfo=UTC)

    def test_latest_severity_and_details_reflected(self, table: Any) -> None:
        store_findings.upsert_finding(table, _finding(severity=Severity.LOW))
        stored = store_findings.upsert_finding(table, _finding(severity=Severity.CRITICAL))
        assert stored.severity == Severity.CRITICAL

    def test_suppressed_status_survives_reupsert(self, table: Any) -> None:
        store_findings.upsert_finding(table, _finding())
        store_findings.put_finding(
            table,
            store_findings.get_finding(table, "a" * 32).model_copy(
                update={"status": FindingStatus.SUPPRESSED}
            ),
        )
        stored = store_findings.upsert_finding(
            table, _finding(last_seen=datetime(2026, 1, 5, tzinfo=UTC))
        )
        assert stored.status == FindingStatus.SUPPRESSED


class TestGetAndPut:
    def test_get_missing_returns_none(self, table: Any) -> None:
        assert store_findings.get_finding(table, "z" * 32) is None

    def test_round_trip_preserves_fields(self, table: Any) -> None:
        original = _finding(details={"port": 22}, resource_tags={"environment": "dev"})
        store_findings.put_finding(table, original)
        loaded = store_findings.get_finding(table, "a" * 32)
        assert loaded is not None
        assert loaded.details == {"port": 22}
        assert loaded.resource_tags == {"environment": "dev"}
        assert loaded.first_seen == original.first_seen


class TestResolve:
    def test_mark_resolved(self, table: Any) -> None:
        store_findings.upsert_finding(table, _finding())
        resolved = store_findings.mark_resolved(table, "a" * 32)
        assert resolved is not None
        assert resolved.status == FindingStatus.RESOLVED

    def test_mark_resolved_missing_finding_returns_none(self, table: Any) -> None:
        assert store_findings.mark_resolved(table, "z" * 32) is None

    def test_mark_resolved_idempotent(self, table: Any) -> None:
        store_findings.upsert_finding(table, _finding())
        store_findings.mark_resolved(table, "a" * 32)
        again = store_findings.mark_resolved(table, "a" * 32)
        assert again is not None
        assert again.status == FindingStatus.RESOLVED


class TestReconcile:
    def test_finding_absent_from_new_run_gets_resolved(self, table: Any) -> None:
        store_findings.upsert_finding(table, _finding(fingerprint="a" * 32))
        store_findings.upsert_finding(table, _finding(fingerprint="b" * 32, resource_id="sg-2"))

        resolved = store_findings.reconcile_resolved(
            table, domain=Domain.SECURITY, seen_fingerprints={"a" * 32}
        )

        assert resolved == ["b" * 32]
        assert store_findings.get_finding(table, "b" * 32).status == FindingStatus.RESOLVED  # type: ignore[union-attr]
        assert store_findings.get_finding(table, "a" * 32).status == FindingStatus.NEW  # type: ignore[union-attr]

    def test_reconcile_only_affects_its_own_domain(self, table: Any) -> None:
        store_findings.upsert_finding(table, _finding(fingerprint="a" * 32, domain=Domain.SECURITY))
        store_findings.upsert_finding(
            table,
            _finding(
                fingerprint="b" * 32,
                domain=Domain.COST,
                rule_id="COST-WASTE-GP2",
                resource_type="AwsEc2Volume",
            ),
        )

        store_findings.reconcile_resolved(table, domain=Domain.SECURITY, seen_fingerprints=set())

        assert store_findings.get_finding(table, "a" * 32).status == FindingStatus.RESOLVED  # type: ignore[union-attr]
        assert store_findings.get_finding(table, "b" * 32).status == FindingStatus.NEW  # type: ignore[union-attr]

    def test_already_resolved_not_reprocessed(self, table: Any) -> None:
        store_findings.upsert_finding(table, _finding())
        store_findings.mark_resolved(table, "a" * 32)
        resolved = store_findings.reconcile_resolved(
            table, domain=Domain.SECURITY, seen_fingerprints=set()
        )
        assert resolved == []

    def test_query_open_fingerprints_excludes_resolved(self, table: Any) -> None:
        store_findings.upsert_finding(table, _finding(fingerprint="a" * 32))
        store_findings.upsert_finding(table, _finding(fingerprint="b" * 32, resource_id="sg-2"))
        store_findings.mark_resolved(table, "b" * 32)

        open_fps = store_findings.query_open_fingerprints_for_domain(table, Domain.SECURITY)
        assert open_fps == {"a" * 32}
