from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from moto import mock_aws

from cloudops_orchestrator.collectors import security_hub
from cloudops_orchestrator.collectors.base import CollectorContext
from cloudops_orchestrator.config import load_settings

REPO_ROOT = Path(__file__).resolve().parents[2]


def _ctx(*, fixtures_dir: Path | None) -> CollectorContext:
    settings = load_settings(REPO_ROOT / "config" / "settings.local.yaml", env={})
    return CollectorContext(
        run_id="run-1",
        settings=settings,
        account=settings.aws.accounts[0],
        now=datetime(2026, 1, 27, tzinfo=UTC),
        fixtures_dir=fixtures_dir,
    )


def _raw(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "Id": "f-1",
        "Title": "EC2.13",
        "Description": "desc",
        "Severity": {"Label": "HIGH"},
        "Resources": [
            {
                "Type": "AwsEc2SecurityGroup",
                "Id": "arn:aws:ec2:...:sg-1",
                "Tags": {"environment": "dev"},
            }
        ],
        "Compliance": {"Status": "FAILED", "SecurityControlId": "EC2.13"},
        "RecordState": "ACTIVE",
        "WorkflowState": "NEW",
        "Types": ["Software and Configuration Checks"],
        "CreatedAt": "2026-01-20T03:00:00Z",
        "UpdatedAt": "2026-01-20T03:00:00Z",
    }
    base.update(overrides)
    return base


class TestFilters:
    def test_inactive_record_state_excluded(self) -> None:
        assert not security_hub._passes_filters(_raw(RecordState="ARCHIVED"), min_severity_rank=0)

    def test_resolved_workflow_status_excluded(self) -> None:
        assert not security_hub._passes_filters(_raw(WorkflowState="RESOLVED"), min_severity_rank=0)

    def test_passed_compliance_excluded_unless_threat(self) -> None:
        assert not security_hub._passes_filters(
            _raw(Compliance={"Status": "PASSED"}), min_severity_rank=0
        )

    def test_threat_finding_included_despite_no_compliance_status(self) -> None:
        raw = _raw(Compliance={}, Types=["TTPs/Unusual Behaviors/Malware"])
        assert security_hub._passes_filters(raw, min_severity_rank=0)

    def test_below_min_severity_excluded(self) -> None:
        assert not security_hub._passes_filters(
            _raw(Severity={"Label": "LOW"}), min_severity_rank=2
        )

    def test_at_min_severity_included(self) -> None:
        assert security_hub._passes_filters(_raw(Severity={"Label": "HIGH"}), min_severity_rank=2)


class TestParseFinding:
    def test_parses_core_fields(self) -> None:
        ctx = _ctx(fixtures_dir=None)
        finding = security_hub.parse_finding(_raw(), ctx=ctx)
        assert finding.domain.value == "security"
        assert finding.source == "securityhub"
        assert finding.control_ids == ["EC2.13"]
        assert finding.resource_type == "AwsEc2SecurityGroup"
        assert finding.severity.value == "high"
        assert finding.environment == "dev"


class TestFixtureMode:
    def test_collect_from_fixture_dir(self) -> None:
        ctx = _ctx(fixtures_dir=REPO_ROOT / "tests" / "fixtures" / "scenario_demo")
        result = security_hub.collect(ctx)
        assert len(result.findings) > 0
        assert all(f.source == "securityhub" for f in result.findings)

    def test_missing_fixture_file_returns_empty(self, tmp_path: Path) -> None:
        ctx = _ctx(fixtures_dir=tmp_path)
        result = security_hub.collect(ctx)
        assert result.findings == []

    def test_disabled_collector_returns_nothing(self) -> None:
        settings = load_settings(REPO_ROOT / "config" / "settings.local.yaml", env={})
        disabled = settings.collectors.model_copy(
            update={
                "security_hub": settings.collectors.security_hub.model_copy(
                    update={"enabled": False}
                )
            }
        )
        settings = settings.model_copy(update={"collectors": disabled})
        ctx = CollectorContext(
            run_id="r",
            settings=settings,
            account=settings.aws.accounts[0],
            now=datetime(2026, 1, 27, tzinfo=UTC),
            fixtures_dir=REPO_ROOT / "tests" / "fixtures" / "scenario_demo",
        )
        assert security_hub.collect(ctx).findings == []


@mock_aws
def test_live_mode_paginates_get_findings() -> None:
    from cloudops_orchestrator.aws.clients import get_client

    client = get_client("securityhub", region_name="ap-south-1")
    client.enable_security_hub()

    ctx = _ctx(fixtures_dir=None)
    result = security_hub.collect(ctx)
    # moto's Security Hub has no findings by default — this just proves the
    # live pagination path doesn't raise against a real (moto) API surface.
    assert result.findings == []
