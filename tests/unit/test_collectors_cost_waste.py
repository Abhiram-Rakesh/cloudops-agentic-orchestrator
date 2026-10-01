from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from cloudops_orchestrator.collectors import cost_waste
from cloudops_orchestrator.collectors.base import CollectorContext
from cloudops_orchestrator.config import CostWasteCollectorConfig, load_settings

REPO_ROOT = Path(__file__).resolve().parents[2]
REQUIRED_TAGS = ["owner", "cost-center", "environment", "application"]
COMPLIANT_TAGS = {
    "owner": "team",
    "cost-center": "CC-2040",
    "environment": "dev",
    "application": "orders",
}


class TestIdleEc2:
    def test_idle_flagged(self) -> None:
        instance = cost_waste.Ec2InstanceInfo(
            instance_id="i-1",
            name="n",
            tags={"environment": "dev"},
            state="running",
            instance_type="t4g.micro",
            avg_cpu_pct=1.0,
            avg_network_bytes_per_day=1000,
        )
        violation = cost_waste.check_idle_ec2(instance, cpu_threshold_pct=5)
        assert violation is not None
        assert violation.rule_id == "COST-WASTE-IDLE-EC2"

    def test_busy_instance_not_flagged(self) -> None:
        instance = cost_waste.Ec2InstanceInfo(
            instance_id="i-1",
            name="n",
            tags={"environment": "dev"},
            state="running",
            instance_type="t4g.micro",
            avg_cpu_pct=40.0,
            avg_network_bytes_per_day=10 * 1024 * 1024,
        )
        assert cost_waste.check_idle_ec2(instance, cpu_threshold_pct=5) is None

    def test_stopped_instance_not_flagged(self) -> None:
        instance = cost_waste.Ec2InstanceInfo(
            instance_id="i-1",
            name="n",
            tags={},
            state="stopped",
            instance_type="t4g.micro",
            avg_cpu_pct=1.0,
            avg_network_bytes_per_day=1000,
        )
        assert cost_waste.check_idle_ec2(instance, cpu_threshold_pct=5) is None

    def test_missing_data_skipped_gracefully(self) -> None:
        instance = cost_waste.Ec2InstanceInfo(
            instance_id="i-1",
            name="n",
            tags={},
            state="running",
            instance_type="t4g.micro",
        )
        assert cost_waste.check_idle_ec2(instance, cpu_threshold_pct=5) is None

    def test_prod_instance_never_flagged(self) -> None:
        instance = cost_waste.Ec2InstanceInfo(
            instance_id="i-1",
            name="n",
            tags={"environment": "prod"},
            state="running",
            instance_type="t4g.micro",
            avg_cpu_pct=1.0,
            avg_network_bytes_per_day=1000,
        )
        assert cost_waste.check_idle_ec2(instance, cpu_threshold_pct=5) is None


class TestUnattachedEbs:
    def test_unattached_over_threshold_flagged(self) -> None:
        volume = cost_waste.EbsVolumeInfo(
            volume_id="vol-1",
            name="n",
            tags={},
            size_gb=1,
            volume_type="gp3",
            encrypted=True,
            attached=False,
            days_unattached=10,
        )
        assert cost_waste.check_unattached_ebs(volume) is not None

    def test_attached_never_flagged(self) -> None:
        volume = cost_waste.EbsVolumeInfo(
            volume_id="vol-1",
            name="n",
            tags={},
            size_gb=1,
            volume_type="gp3",
            encrypted=True,
            attached=True,
            days_unattached=100,
        )
        assert cost_waste.check_unattached_ebs(volume) is None

    def test_under_threshold_not_flagged(self) -> None:
        volume = cost_waste.EbsVolumeInfo(
            volume_id="vol-1",
            name="n",
            tags={},
            size_gb=1,
            volume_type="gp3",
            encrypted=True,
            attached=False,
            days_unattached=2,
        )
        assert cost_waste.check_unattached_ebs(volume) is None


class TestGp2:
    def test_gp2_flagged(self) -> None:
        volume = cost_waste.EbsVolumeInfo(
            volume_id="vol-1",
            name="n",
            tags={},
            size_gb=1,
            volume_type="gp2",
            encrypted=True,
            attached=True,
        )
        assert cost_waste.check_gp2(volume) is not None

    def test_gp3_not_flagged(self) -> None:
        volume = cost_waste.EbsVolumeInfo(
            volume_id="vol-1",
            name="n",
            tags={},
            size_gb=1,
            volume_type="gp3",
            encrypted=True,
            attached=True,
        )
        assert cost_waste.check_gp2(volume) is None


class TestUnassociatedEip:
    def test_unassociated_over_threshold_flagged(self) -> None:
        eip = cost_waste.EipInfo(
            allocation_id="eipalloc-1", name="n", tags={}, associated=False, hours_unassociated=48
        )
        assert cost_waste.check_unassociated_eip(eip) is not None

    def test_associated_not_flagged(self) -> None:
        eip = cost_waste.EipInfo(
            allocation_id="eipalloc-1", name="n", tags={}, associated=True, hours_unassociated=1000
        )
        assert cost_waste.check_unassociated_eip(eip) is None


class TestOrphanSnapshot:
    def test_no_source_volume_flagged(self) -> None:
        snapshot = cost_waste.SnapshotInfo(
            snapshot_id="snap-1", name="n", tags={}, source_volume_exists=False, age_days=5
        )
        assert cost_waste.check_orphan_snapshot(snapshot) is not None

    def test_referenced_by_ami_not_flagged_even_if_source_gone(self) -> None:
        snapshot = cost_waste.SnapshotInfo(
            snapshot_id="snap-1",
            name="n",
            tags={},
            source_volume_exists=False,
            age_days=5,
            referenced_by_ami=True,
        )
        assert cost_waste.check_orphan_snapshot(snapshot) is None

    def test_over_retention_flagged(self) -> None:
        snapshot = cost_waste.SnapshotInfo(
            snapshot_id="snap-1", name="n", tags={}, source_volume_exists=True, age_days=200
        )
        assert cost_waste.check_orphan_snapshot(snapshot) is not None

    def test_fresh_with_source_not_flagged(self) -> None:
        snapshot = cost_waste.SnapshotInfo(
            snapshot_id="snap-1", name="n", tags={}, source_volume_exists=True, age_days=10
        )
        assert cost_waste.check_orphan_snapshot(snapshot) is None


class TestRequiredTags:
    def test_all_present_not_flagged(self) -> None:
        violation = cost_waste.check_required_tags(
            resource_id="i-1",
            resource_type="AwsEc2Instance",
            resource_name="n",
            tags=COMPLIANT_TAGS,
            required_tags=REQUIRED_TAGS,
        )
        assert violation is None

    def test_missing_one_flagged_with_name(self) -> None:
        tags = {k: v for k, v in COMPLIANT_TAGS.items() if k != "cost-center"}
        violation = cost_waste.check_required_tags(
            resource_id="i-1",
            resource_type="AwsEc2Instance",
            resource_name="n",
            tags=tags,
            required_tags=REQUIRED_TAGS,
        )
        assert violation is not None
        assert violation.details["missing_tags"] == ["cost-center"]

    def test_missing_multiple_reported_as_one_violation(self) -> None:
        violation = cost_waste.check_required_tags(
            resource_id="i-1",
            resource_type="AwsEc2Instance",
            resource_name="n",
            tags={},
            required_tags=REQUIRED_TAGS,
        )
        assert violation is not None
        assert violation.details["missing_tags"] == REQUIRED_TAGS


class TestCostCenterFormat:
    def test_valid_format_not_flagged(self) -> None:
        assert (
            cost_waste.check_cost_center_format(
                resource_id="i-1",
                resource_type="x",
                resource_name="n",
                tags={"cost-center": "CC-2040"},
            )
            is None
        )

    def test_malformed_flagged(self) -> None:
        violation = cost_waste.check_cost_center_format(
            resource_id="i-1", resource_type="x", resource_name="n", tags={"cost-center": "finance"}
        )
        assert violation is not None

    def test_absent_tag_not_flagged_here(self) -> None:
        # Absence is COST-TAG-MISSING's job (check_required_tags), not this check's.
        assert (
            cost_waste.check_cost_center_format(
                resource_id="i-1", resource_type="x", resource_name="n", tags={}
            )
            is None
        )


class TestNonprodSchedule:
    def test_nonprod_without_schedule_flagged(self) -> None:
        instance = cost_waste.Ec2InstanceInfo(
            instance_id="i-1",
            name="n",
            tags={"environment": "dev"},
            state="running",
            instance_type="t4g.micro",
        )
        assert cost_waste.check_nonprod_schedule(instance) is not None

    def test_prod_never_flagged(self) -> None:
        instance = cost_waste.Ec2InstanceInfo(
            instance_id="i-1",
            name="n",
            tags={"environment": "prod"},
            state="running",
            instance_type="t4g.micro",
        )
        assert cost_waste.check_nonprod_schedule(instance) is None

    def test_with_schedule_tag_not_flagged(self) -> None:
        instance = cost_waste.Ec2InstanceInfo(
            instance_id="i-1",
            name="n",
            tags={"environment": "dev", "schedule": "office-hours"},
            state="running",
            instance_type="t4g.micro",
        )
        assert cost_waste.check_nonprod_schedule(instance) is None


class TestOverprovisioned:
    def test_overprovisioned_flagged(self) -> None:
        rec = cost_waste.ComputeOptimizerRecommendation(
            instance_id="i-1", name="n", tags={}, finding="Overprovisioned"
        )
        assert cost_waste.check_overprovisioned(rec) is not None

    def test_optimized_not_flagged(self) -> None:
        rec = cost_waste.ComputeOptimizerRecommendation(
            instance_id="i-1", name="n", tags={}, finding="Optimized"
        )
        assert cost_waste.check_overprovisioned(rec) is None


class TestFixtureModeAgainstDemoStack:
    def _ctx(self) -> CollectorContext:
        settings = load_settings(REPO_ROOT / "config" / "settings.local.yaml", env={})
        return CollectorContext(
            run_id="run-1",
            settings=settings,
            account=settings.aws.accounts[0],
            now=datetime(2026, 1, 27, tzinfo=UTC),
            fixtures_dir=REPO_ROOT / "tests" / "fixtures" / "scenario_demo",
        )

    def test_collect_produces_expected_rule_ids(self) -> None:
        result = cost_waste.collect(self._ctx())
        rule_ids = {f.rule_id for f in result.findings}
        assert "COST-WASTE-IDLE-EC2" in rule_ids
        assert "COST-WASTE-UNATTACHED-EBS" in rule_ids
        assert "COST-WASTE-UNASSOCIATED-EIP" in rule_ids
        assert "COST-WASTE-GP2" in rule_ids
        assert "COST-TAG-MISSING" in rule_ids
        assert "COST-NONPROD-SCHEDULE" in rule_ids

    def test_web_instance_only_missing_cost_center(self) -> None:
        result = cost_waste.collect(self._ctx())
        tag_findings = [
            f
            for f in result.findings
            if f.rule_id == "COST-TAG-MISSING" and f.resource_id == "i-0aaaaaaaaaaaaaaaa"
        ]
        assert len(tag_findings) == 1
        assert tag_findings[0].details["missing_tags"] == ["cost-center"]


def test_disabled_collector_returns_nothing() -> None:
    settings = load_settings(REPO_ROOT / "config" / "settings.local.yaml", env={})
    disabled = settings.collectors.model_copy(
        update={"cost_waste": settings.collectors.cost_waste.model_copy(update={"enabled": False})}
    )
    settings = settings.model_copy(update={"collectors": disabled})
    ctx = CollectorContext(
        run_id="r",
        settings=settings,
        account=settings.aws.accounts[0],
        now=datetime(2026, 1, 27, tzinfo=UTC),
        fixtures_dir=REPO_ROOT / "tests" / "fixtures" / "scenario_demo",
    )
    assert cost_waste.collect(ctx).findings == []


def test_run_all_checks_with_empty_input() -> None:
    config = CostWasteCollectorConfig()
    violations = cost_waste.run_all_checks(
        instances=[],
        volumes=[],
        addresses=[],
        snapshots=[],
        buckets=[],
        compute_optimizer=[],
        config=config,
    )
    assert violations == []
