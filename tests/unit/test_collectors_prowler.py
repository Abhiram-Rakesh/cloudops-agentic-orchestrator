from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from cloudops_orchestrator.collectors import prowler
from cloudops_orchestrator.collectors.base import CollectorContext
from cloudops_orchestrator.config import load_settings

REPO_ROOT = Path(__file__).resolve().parents[2]


def _ctx(*, fixtures_dir: Path | None, now: datetime | None = None) -> CollectorContext:
    settings = load_settings(REPO_ROOT / "config" / "settings.local.yaml", env={})
    return CollectorContext(
        run_id="run-1",
        settings=settings,
        account=settings.aws.accounts[0],
        now=now or datetime(2026, 1, 27, tzinfo=UTC),
        fixtures_dir=fixtures_dir,
    )


class TestPickFingerprintControl:
    def test_prefers_security_hub_style_id_over_cis_ref(self) -> None:
        assert prowler._pick_fingerprint_control(["CIS-5.2", "EC2.13"], fallback="x") == "EC2.13"

    def test_falls_back_to_first_when_no_sh_style_id(self) -> None:
        assert prowler._pick_fingerprint_control(["CIS-5.2", "CIS-5.3"], fallback="x") == "CIS-5.2"

    def test_falls_back_to_check_id_when_no_controls(self) -> None:
        assert prowler._pick_fingerprint_control([], fallback="some_check") == "some_check"


class TestParseFinding:
    def test_parses_and_maps_control(self) -> None:
        ctx = _ctx(fixtures_dir=None)
        raw = {
            "check_id": "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
            "status": "FAIL",
            "severity": "high",
            "region": "ap-south-1",
            "resource_uid": "arn:aws:ec2:...:sg-1",
            "resource_name": "web-admin-sg",
            "resource_type": "AwsEc2SecurityGroup",
            "tags": {"environment": "dev"},
            "timestamp": "2026-01-20T03:00:00Z",
        }
        control_map = {
            "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22": ["CIS-5.2", "EC2.13"]
        }
        finding = prowler.parse_finding(raw, ctx=ctx, control_map=control_map)
        assert finding.source == "prowler"
        assert set(finding.control_ids) == {"CIS-5.2", "EC2.13"}
        assert finding.severity.value == "high"

    def test_unmapped_check_keeps_check_id_as_control(self) -> None:
        ctx = _ctx(fixtures_dir=None)
        raw = {
            "check_id": "some_unmapped_check",
            "status": "FAIL",
            "resource_uid": "r-1",
            "timestamp": "2026-01-20T03:00:00Z",
        }
        finding = prowler.parse_finding(raw, ctx=ctx, control_map={})
        assert finding.control_ids == ["some_unmapped_check"]


class TestStaleness:
    def test_stale_data_produces_warning(self) -> None:
        ctx = _ctx(fixtures_dir=None, now=datetime(2026, 2, 1, tzinfo=UTC))
        raw_findings = [{"timestamp": "2026-01-01T00:00:00Z"}]
        warnings = prowler._check_staleness(raw_findings, ctx=ctx, max_age_days=8)
        assert warnings and "stale" in warnings[0]

    def test_fresh_data_no_warning(self) -> None:
        ctx = _ctx(fixtures_dir=None, now=datetime(2026, 1, 27, tzinfo=UTC))
        raw_findings = [{"timestamp": "2026-01-26T00:00:00Z"}]
        assert prowler._check_staleness(raw_findings, ctx=ctx, max_age_days=8) == []

    def test_no_data_no_warning(self) -> None:
        ctx = _ctx(fixtures_dir=None)
        assert prowler._check_staleness([], ctx=ctx, max_age_days=8) == []


class TestFixtureMode:
    def test_collect_from_fixture_dir(self) -> None:
        ctx = _ctx(fixtures_dir=REPO_ROOT / "tests" / "fixtures" / "scenario_demo")
        result = prowler.collect(ctx)
        assert len(result.findings) > 0
        assert all(f.source == "prowler" for f in result.findings)

    def test_only_fail_status_included(self, tmp_path: Path) -> None:
        import json

        fixtures_dir = tmp_path
        (fixtures_dir / "prowler").mkdir()
        data = [
            {
                "check_id": "a",
                "status": "FAIL",
                "resource_uid": "r1",
                "timestamp": "2026-01-20T00:00:00Z",
            },
            {
                "check_id": "b",
                "status": "PASS",
                "resource_uid": "r2",
                "timestamp": "2026-01-20T00:00:00Z",
            },
        ]
        (fixtures_dir / "prowler" / "findings.json").write_text(json.dumps(data))
        ctx = _ctx(fixtures_dir=fixtures_dir)
        result = prowler.collect(ctx)
        assert len(result.findings) == 1
        assert result.findings[0].rule_id == "a"

    def test_missing_fixture_returns_empty(self, tmp_path: Path) -> None:
        ctx = _ctx(fixtures_dir=tmp_path)
        assert prowler.collect(ctx).findings == []


def test_load_control_map_reads_real_config() -> None:
    control_map = prowler.load_control_map()
    assert "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22" in control_map
