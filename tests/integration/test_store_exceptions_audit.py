"""Moto-backed tests for store/exceptions.py and store/audit.py."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from moto import mock_aws

from cloudops_orchestrator.config import load_settings
from cloudops_orchestrator.store import audit as store_audit
from cloudops_orchestrator.store import exceptions as store_exceptions

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def settings_and_table() -> Any:
    with mock_aws():
        import boto3

        # store_exceptions' internal get_table(settings) calls resolve to
        # this moto-backed table.
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
            ProvisionedThroughput={"ReadCapacityUnits": 8, "WriteCapacityUnits": 8},
        )
        yield settings, resource.Table(settings.storage.state_table)


class TestExceptions:
    def test_add_and_list(self, settings_and_table: Any) -> None:
        settings, _table = settings_and_table
        exc = store_exceptions.add_exception(
            settings,
            clause_id="SEC-004-4.2",
            duration_days=90,
            compensating_control="weekly Prowler scan",
        )
        listed = store_exceptions.list_exceptions(settings)
        assert len(listed) == 1
        assert listed[0].exception_id == exc.exception_id
        assert listed[0].clause_id == "SEC-004-4.2"

    def test_expires_at_matches_duration(self, settings_and_table: Any) -> None:
        settings, _table = settings_and_table
        now = datetime(2026, 1, 1, tzinfo=UTC)
        exc = store_exceptions.add_exception(
            settings, clause_id="SEC-004-4.2", duration_days=30, compensating_control="x", now=now
        )
        assert (exc.expires_at - exc.created_at).days == 30

    def test_remove(self, settings_and_table: Any) -> None:
        settings, _table = settings_and_table
        exc = store_exceptions.add_exception(
            settings, clause_id="SEC-004-4.2", duration_days=30, compensating_control="x"
        )
        store_exceptions.remove_exception(settings, exception_id=exc.exception_id)
        assert store_exceptions.list_exceptions(settings) == []

    def test_scoped_to_fingerprint_when_given(self, settings_and_table: Any) -> None:
        settings, _table = settings_and_table
        exc = store_exceptions.add_exception(
            settings,
            clause_id="COST-002-2.1",
            duration_days=30,
            compensating_control="x",
            fingerprint="a" * 32,
        )
        assert exc.fingerprint == "a" * 32

    def test_multiple_exceptions_independent(self, settings_and_table: Any) -> None:
        settings, _table = settings_and_table
        store_exceptions.add_exception(
            settings, clause_id="A", duration_days=30, compensating_control="x"
        )
        store_exceptions.add_exception(
            settings, clause_id="B", duration_days=30, compensating_control="y"
        )
        assert len(store_exceptions.list_exceptions(settings)) == 2


class TestAudit:
    def test_record_and_list(self, settings_and_table: Any) -> None:
        _settings, table = settings_and_table
        store_audit.record_audit_event(
            table, entity="ACTION#action-1", event="approved", details={"approver": "U1"}
        )
        events = store_audit.list_audit_events(table, "ACTION#action-1")
        assert len(events) == 1
        assert events[0]["event"] == "approved"
        assert events[0]["details"]["approver"] == "U1"

    def test_events_ordered_by_time(self, settings_and_table: Any) -> None:
        _settings, table = settings_and_table
        store_audit.record_audit_event(
            table, entity="ACTION#action-1", event="created", at=datetime(2026, 1, 1, tzinfo=UTC)
        )
        store_audit.record_audit_event(
            table, entity="ACTION#action-1", event="approved", at=datetime(2026, 1, 2, tzinfo=UTC)
        )
        events = store_audit.list_audit_events(table, "ACTION#action-1")
        assert [e["event"] for e in events] == ["created", "approved"]

    def test_different_entities_independent(self, settings_and_table: Any) -> None:
        _settings, table = settings_and_table
        store_audit.record_audit_event(table, entity="ACTION#a1", event="x")
        store_audit.record_audit_event(table, entity="ACTION#a2", event="y")
        assert len(store_audit.list_audit_events(table, "ACTION#a1")) == 1
        assert len(store_audit.list_audit_events(table, "ACTION#a2")) == 1
