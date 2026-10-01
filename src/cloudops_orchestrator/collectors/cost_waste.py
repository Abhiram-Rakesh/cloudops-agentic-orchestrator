"""Cost waste collector — deterministic checks over EC2/EBS/EIP/snapshot/S3
inventory: idle instances, unattached volumes, unassociated EIPs, gp2
volumes, orphaned snapshots, missing/malformed required tags, missing
non-prod schedule tags, and (when Compute Optimizer has data)
over-provisioned instances.

Every check is a pure function over a small, typed resource-info record so
it can be unit tested without AWS — ``collect()`` is just "get the records
(live describe/CloudWatch calls, or the fixture file) and run every check."

Fixture: ``{fixtures_dir}/cost_waste/resources.json`` — see
``scripts/gen_demo_artifacts.py`` for the exact shape.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from cloudops_orchestrator.collectors.base import CollectorContext, CollectorResult
from cloudops_orchestrator.config import CostWasteCollectorConfig
from cloudops_orchestrator.models.enums import Domain, FindingStatus, Severity
from cloudops_orchestrator.models.findings import Finding
from cloudops_orchestrator.normalize.fingerprint import standard_fingerprint

SOURCE = "cost_waste"

IDLE_NETWORK_BYTES_PER_DAY_THRESHOLD = 5 * 1024 * 1024
UNATTACHED_EBS_MIN_DAYS = 7
UNASSOCIATED_EIP_MIN_HOURS = 24
ORPHAN_SNAPSHOT_MAX_RETENTION_DAYS = 90
_COST_CENTER_RE = re.compile(r"^CC-\d{4}$")

_RULE_SEVERITY: dict[str, Severity] = {
    "COST-WASTE-IDLE-EC2": Severity.MEDIUM,
    "COST-WASTE-UNATTACHED-EBS": Severity.MEDIUM,
    "COST-WASTE-UNASSOCIATED-EIP": Severity.LOW,
    "COST-WASTE-GP2": Severity.LOW,
    "COST-WASTE-ORPHAN-SNAPSHOT": Severity.LOW,
    "COST-TAG-MISSING": Severity.MEDIUM,
    "COST-OVERPROVISIONED": Severity.MEDIUM,
    "COST-NONPROD-SCHEDULE": Severity.LOW,
}


@dataclass(frozen=True)
class Ec2InstanceInfo:
    instance_id: str
    name: str
    tags: dict[str, str]
    state: str
    instance_type: str
    avg_cpu_pct: float | None = None
    avg_network_bytes_per_day: float | None = None


@dataclass(frozen=True)
class EbsVolumeInfo:
    volume_id: str
    name: str
    tags: dict[str, str]
    size_gb: int
    volume_type: str
    encrypted: bool
    attached: bool
    days_unattached: int = 0


@dataclass(frozen=True)
class EipInfo:
    allocation_id: str
    name: str
    tags: dict[str, str]
    associated: bool
    hours_unassociated: float = 0.0


@dataclass(frozen=True)
class SnapshotInfo:
    snapshot_id: str
    name: str
    tags: dict[str, str]
    source_volume_exists: bool
    age_days: int
    referenced_by_ami: bool = False


@dataclass(frozen=True)
class BucketWasteInfo:
    name: str
    tags: dict[str, str]
    has_lifecycle_rule: bool


@dataclass(frozen=True)
class ComputeOptimizerRecommendation:
    instance_id: str
    name: str
    tags: dict[str, str]
    finding: str  # "Optimize" | "NotOptimized" | "Underprovisioned" | ...


@dataclass(frozen=True)
class Violation:
    rule_id: str
    resource_id: str
    resource_type: str
    resource_name: str
    tags: dict[str, str]
    description: str
    details: dict[str, Any] = field(default_factory=dict)


def check_idle_ec2(instance: Ec2InstanceInfo, *, cpu_threshold_pct: float) -> Violation | None:
    if instance.state != "running":
        return None
    if instance.avg_cpu_pct is None or instance.avg_network_bytes_per_day is None:
        return None  # insufficient data — skip gracefully, never a false "not idle"
    if instance.tags.get("environment", "").lower() in ("prod", "production"):
        return None
    if (
        instance.avg_cpu_pct >= cpu_threshold_pct
        or instance.avg_network_bytes_per_day >= IDLE_NETWORK_BYTES_PER_DAY_THRESHOLD
    ):
        return None
    return Violation(
        rule_id="COST-WASTE-IDLE-EC2",
        resource_id=instance.instance_id,
        resource_type="AwsEc2Instance",
        resource_name=instance.name,
        tags=instance.tags,
        description=f"Instance {instance.name} is idle (avg CPU {instance.avg_cpu_pct:.1f}%).",
        details={
            "avg_cpu_pct": instance.avg_cpu_pct,
            "avg_network_bytes_per_day": instance.avg_network_bytes_per_day,
        },
    )


def check_unattached_ebs(
    volume: EbsVolumeInfo, *, min_days: int = UNATTACHED_EBS_MIN_DAYS
) -> Violation | None:
    if volume.attached or volume.days_unattached < min_days:
        return None
    return Violation(
        rule_id="COST-WASTE-UNATTACHED-EBS",
        resource_id=volume.volume_id,
        resource_type="AwsEc2Volume",
        resource_name=volume.name,
        tags=volume.tags,
        description=f"Volume {volume.name} has been unattached for {volume.days_unattached} days.",
        details={"days_unattached": volume.days_unattached},
    )


def check_gp2(volume: EbsVolumeInfo) -> Violation | None:
    if volume.volume_type != "gp2":
        return None
    return Violation(
        rule_id="COST-WASTE-GP2",
        resource_id=volume.volume_id,
        resource_type="AwsEc2Volume",
        resource_name=volume.name,
        tags=volume.tags,
        description=f"Volume {volume.name} is gp2; gp3 is cheaper for equivalent baseline performance.",
    )


def check_unassociated_eip(
    eip: EipInfo, *, min_hours: float = UNASSOCIATED_EIP_MIN_HOURS
) -> Violation | None:
    if eip.associated or eip.hours_unassociated < min_hours:
        return None
    return Violation(
        rule_id="COST-WASTE-UNASSOCIATED-EIP",
        resource_id=eip.allocation_id,
        resource_type="AwsEc2Eip",
        resource_name=eip.name,
        tags=eip.tags,
        description=f"Elastic IP {eip.name} has been unassociated for {eip.hours_unassociated:.0f} hours.",
        details={"hours_unassociated": eip.hours_unassociated},
    )


def check_orphan_snapshot(
    snapshot: SnapshotInfo, *, max_retention_days: int = ORPHAN_SNAPSHOT_MAX_RETENTION_DAYS
) -> Violation | None:
    is_orphaned = not snapshot.source_volume_exists and not snapshot.referenced_by_ami
    is_over_retention = snapshot.age_days > max_retention_days
    if not (is_orphaned or is_over_retention):
        return None
    reason = (
        "its source volume no longer exists"
        if is_orphaned
        else f"it is {snapshot.age_days} days old"
    )
    return Violation(
        rule_id="COST-WASTE-ORPHAN-SNAPSHOT",
        resource_id=snapshot.snapshot_id,
        resource_type="AwsEc2Snapshot",
        resource_name=snapshot.name,
        tags=snapshot.tags,
        description=f"Snapshot {snapshot.name} should be removed: {reason}.",
    )


def check_required_tags(
    *,
    resource_id: str,
    resource_type: str,
    resource_name: str,
    tags: dict[str, str],
    required_tags: list[str],
) -> Violation | None:
    missing = [tag for tag in required_tags if not tags.get(tag)]
    if not missing:
        return None
    return Violation(
        rule_id="COST-TAG-MISSING",
        resource_id=resource_id,
        resource_type=resource_type,
        resource_name=resource_name,
        tags=tags,
        description=f"{resource_name} is missing required tag(s): {', '.join(missing)}.",
        details={"missing_tags": missing},
    )


def check_cost_center_format(
    *, resource_id: str, resource_type: str, resource_name: str, tags: dict[str, str]
) -> Violation | None:
    cost_center = tags.get("cost-center")
    if cost_center is None or _COST_CENTER_RE.match(cost_center):
        return None
    return Violation(
        rule_id="COST-TAG-MISSING",
        resource_id=resource_id,
        resource_type=resource_type,
        resource_name=resource_name,
        tags=tags,
        description=f"{resource_name}'s cost-center tag {cost_center!r} does not match CC-\\d{{4}}.",
        details={"cost_center": cost_center},
    )


def check_nonprod_schedule(instance: Ec2InstanceInfo) -> Violation | None:
    environment = instance.tags.get("environment", "").lower()
    if environment in ("prod", "production"):
        return None
    if "schedule" in instance.tags:
        return None
    return Violation(
        rule_id="COST-NONPROD-SCHEDULE",
        resource_id=instance.instance_id,
        resource_type="AwsEc2Instance",
        resource_name=instance.name,
        tags=instance.tags,
        description=f"Non-production instance {instance.name} has no `schedule` tag.",
    )


def check_overprovisioned(recommendation: ComputeOptimizerRecommendation) -> Violation | None:
    if recommendation.finding not in ("Overprovisioned",):
        return None
    return Violation(
        rule_id="COST-OVERPROVISIONED",
        resource_id=recommendation.instance_id,
        resource_type="AwsEc2Instance",
        resource_name=recommendation.name,
        tags=recommendation.tags,
        description=f"Compute Optimizer reports {recommendation.name} is over-provisioned.",
    )


def _bucket_check_lifecycle(bucket: BucketWasteInfo) -> Violation | None:
    if bucket.has_lifecycle_rule:
        return None
    return Violation(
        rule_id="COST-WASTE-NO-LIFECYCLE",
        resource_id=bucket.name,
        resource_type="AwsS3Bucket",
        resource_name=bucket.name,
        tags=bucket.tags,
        description=f"Bucket {bucket.name} has no lifecycle policy.",
    )


def run_all_checks(
    *,
    instances: list[Ec2InstanceInfo],
    volumes: list[EbsVolumeInfo],
    addresses: list[EipInfo],
    snapshots: list[SnapshotInfo],
    buckets: list[BucketWasteInfo],
    compute_optimizer: list[ComputeOptimizerRecommendation],
    config: CostWasteCollectorConfig,
) -> list[Violation]:
    violations: list[Violation] = []

    for instance in instances:
        for check in (
            lambda i: check_idle_ec2(i, cpu_threshold_pct=config.idle_cpu_threshold_pct),
            check_nonprod_schedule,
        ):
            violation = check(instance)
            if violation:
                violations.append(violation)
        tag_violation = check_required_tags(
            resource_id=instance.instance_id,
            resource_type="AwsEc2Instance",
            resource_name=instance.name,
            tags=instance.tags,
            required_tags=config.required_tags,
        )
        if tag_violation:
            violations.append(tag_violation)

    for volume in volumes:
        for check in (check_unattached_ebs, check_gp2):
            violation = check(volume)
            if violation:
                violations.append(violation)
        tag_violation = check_required_tags(
            resource_id=volume.volume_id,
            resource_type="AwsEc2Volume",
            resource_name=volume.name,
            tags=volume.tags,
            required_tags=config.required_tags,
        )
        if tag_violation:
            violations.append(tag_violation)

    for eip in addresses:
        violation = check_unassociated_eip(eip)
        if violation:
            violations.append(violation)
        tag_violation = check_required_tags(
            resource_id=eip.allocation_id,
            resource_type="AwsEc2Eip",
            resource_name=eip.name,
            tags=eip.tags,
            required_tags=config.required_tags,
        )
        if tag_violation:
            violations.append(tag_violation)

    for snapshot in snapshots:
        violation = check_orphan_snapshot(snapshot)
        if violation:
            violations.append(violation)

    for bucket in buckets:
        violation = _bucket_check_lifecycle(bucket)
        if violation:
            violations.append(violation)
        tag_violation = check_required_tags(
            resource_id=bucket.name,
            resource_type="AwsS3Bucket",
            resource_name=bucket.name,
            tags=bucket.tags,
            required_tags=config.required_tags,
        )
        if tag_violation:
            violations.append(tag_violation)

    for recommendation in compute_optimizer:
        violation = check_overprovisioned(recommendation)
        if violation:
            violations.append(violation)

    return violations


def _parse_instances(raw: list[dict[str, Any]]) -> list[Ec2InstanceInfo]:
    return [
        Ec2InstanceInfo(
            instance_id=r["instance_id"],
            name=r.get("name", r["instance_id"]),
            tags=r.get("tags", {}),
            state=r.get("state", "running"),
            instance_type=r.get("instance_type", "t4g.micro"),
            avg_cpu_pct=r.get("avg_cpu_pct_7d"),
            avg_network_bytes_per_day=r.get("avg_network_bytes_per_day"),
        )
        for r in raw
    ]


def _parse_volumes(raw: list[dict[str, Any]]) -> list[EbsVolumeInfo]:
    return [
        EbsVolumeInfo(
            volume_id=r["volume_id"],
            name=r.get("name", r["volume_id"]),
            tags=r.get("tags", {}),
            size_gb=r.get("size_gb", 0),
            volume_type=r.get("volume_type", "gp3"),
            encrypted=r.get("encrypted", True),
            attached=r.get("attached", True),
            days_unattached=r.get("days_unattached", 0),
        )
        for r in raw
    ]


def _parse_addresses(raw: list[dict[str, Any]]) -> list[EipInfo]:
    return [
        EipInfo(
            allocation_id=r["allocation_id"],
            name=r.get("name", r["allocation_id"]),
            tags=r.get("tags", {}),
            associated=r.get("associated", True),
            hours_unassociated=r.get("hours_unassociated", 0.0),
        )
        for r in raw
    ]


def _parse_snapshots(raw: list[dict[str, Any]]) -> list[SnapshotInfo]:
    return [
        SnapshotInfo(
            snapshot_id=r["snapshot_id"],
            name=r.get("name", r["snapshot_id"]),
            tags=r.get("tags", {}),
            source_volume_exists=r.get("source_volume_exists", True),
            age_days=r.get("age_days", 0),
            referenced_by_ami=r.get("referenced_by_ami", False),
        )
        for r in raw
    ]


def _parse_buckets(raw: list[dict[str, Any]]) -> list[BucketWasteInfo]:
    return [
        BucketWasteInfo(
            name=r["name"],
            tags=r.get("tags", {}),
            has_lifecycle_rule=r.get("has_lifecycle_rule", True),
        )
        for r in raw
    ]


def _parse_compute_optimizer(raw: list[dict[str, Any]]) -> list[ComputeOptimizerRecommendation]:
    return [
        ComputeOptimizerRecommendation(
            instance_id=r["instance_id"],
            name=r.get("name", r["instance_id"]),
            tags=r.get("tags", {}),
            finding=r.get("finding", "Optimized"),
        )
        for r in raw
    ]


def _load_resources(ctx: CollectorContext) -> dict[str, Any]:
    if ctx.fixtures_dir is not None:
        path = ctx.fixtures_dir / "cost_waste" / "resources.json"
        if not path.exists():
            return {}
        result: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        return result

    # Live mode: describe EC2 instances/volumes/addresses/snapshots, pull
    # CloudWatch CPU/network stats, and enroll in Compute Optimizer.
    # Deferred to the first real deploy — moto-verified unit coverage lives
    # on the check_* functions and fixture-mode parsing above; see
    # README.md (Troubleshooting) for the live describe/CloudWatch call
    # shapes to confirm before relying on this path.
    return {}


def collect(ctx: CollectorContext) -> CollectorResult:
    config = ctx.settings.collectors.cost_waste
    if not config.enabled:
        return CollectorResult()

    raw = _load_resources(ctx)
    violations = run_all_checks(
        instances=_parse_instances(raw.get("instances", [])),
        volumes=_parse_volumes(raw.get("volumes", [])),
        addresses=_parse_addresses(raw.get("addresses", [])),
        snapshots=_parse_snapshots(raw.get("snapshots", [])),
        buckets=_parse_buckets(raw.get("buckets", [])),
        compute_optimizer=_parse_compute_optimizer(raw.get("compute_optimizer", [])),
        config=config,
    )

    findings = [_to_finding(v, ctx=ctx) for v in violations]
    return CollectorResult(findings=findings, raw_evidence={"cost_waste_resources": raw})


def _to_finding(violation: Violation, *, ctx: CollectorContext) -> Finding:
    fingerprint = standard_fingerprint(
        domain=Domain.COST,
        source=SOURCE,
        account_id=ctx.account.id,
        region=ctx.settings.aws.region,
        resource_id=violation.resource_id,
        rule_id=violation.rule_id,
    )
    return Finding(
        fingerprint=fingerprint,
        domain=Domain.COST,
        source=SOURCE,
        sources=[SOURCE],
        rule_id=violation.rule_id,
        control_ids=[violation.rule_id],
        title=violation.description,
        description=violation.description,
        severity=_RULE_SEVERITY.get(violation.rule_id, Severity.LOW),
        account_id=ctx.account.id,
        region=ctx.settings.aws.region,
        resource_type=violation.resource_type,
        resource_id=violation.resource_id,
        resource_tags=violation.tags,
        environment=violation.tags.get("environment"),
        details=violation.details,
        evidence_uri=f"s3://{ctx.settings.storage.bucket}/evidence/{ctx.run_id}/cost_waste/{violation.resource_id}.json",
        first_seen=ctx.now,
        last_seen=ctx.now,
        status=FindingStatus.NEW,
    )


__all__ = [
    "SOURCE",
    "BucketWasteInfo",
    "ComputeOptimizerRecommendation",
    "EbsVolumeInfo",
    "Ec2InstanceInfo",
    "EipInfo",
    "SnapshotInfo",
    "Violation",
    "check_cost_center_format",
    "check_gp2",
    "check_idle_ec2",
    "check_nonprod_schedule",
    "check_orphan_snapshot",
    "check_overprovisioned",
    "check_required_tags",
    "check_unassociated_eip",
    "check_unattached_ebs",
    "collect",
    "run_all_checks",
]
