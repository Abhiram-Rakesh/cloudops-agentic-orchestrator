"""Prowler collector — status FAIL only, merges with Security Hub on mapped
control ID + resource (see ``normalize/fingerprint.py`` and
``normalize/merge.py``, applied by ``steps/collect.py``).

Live: reads the latest Prowler JSON `prowler.yml` uploaded to
``s3://<bucket>/<collectors.prowler.prefix>findings.json``. Fixture:
``{fixtures_dir}/prowler/findings.json`` (OCSF-lite — see
``scripts/gen_demo_artifacts.py``). Staleness (> ``max_age_days``) is a
report warning, not a hard failure — the previous run's Prowler data is
still better than nothing.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from cloudops_orchestrator.collectors.base import CollectorContext, CollectorResult
from cloudops_orchestrator.models.enums import Domain, FindingStatus, Severity
from cloudops_orchestrator.models.findings import Finding
from cloudops_orchestrator.normalize.fingerprint import security_finding_fingerprint

SOURCE = "prowler"

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
}


# Locally this file lives at src/cloudops_orchestrator/collectors/prowler.py
# (config/ is 3 parents up), but scripts/build_lambda_zip.sh deliberately
# flattens src/cloudops_orchestrator to the zip root for Lambda's import
# path, with config/ as a direct sibling (only 2 parents up there) -- a
# fixed parents[N] index can't be correct for both layouts at once. Found
# live: collect's prowler sub-collector failed with FileNotFoundError:
# '/var/config/prowler_control_map.yaml' on the first real end-to-end run
# 2026-09-28 (see docs/VERIFY_BEFORE_DEPLOY.md; policy/config.py has the
# same bug for the same reason). Search upward instead of guessing a depth.
def _find_repo_root(file: Path) -> Path:
    for candidate in file.resolve().parents:
        if (candidate / "config").is_dir():
            return candidate
    msg = f"no 'config' directory found above {file}"
    raise FileNotFoundError(msg)


# Security Hub's own `SecurityControlId` format is "Service.Number" (EC2.13,
# S3.1, GuardDuty.1, ...) — a CIS reference (CIS-5.2) never merges with a
# real Security Hub finding, so when a check maps to both, the SH-style ID
# must be preferred as the fingerprint key or the two collectors' findings
# for the very same issue quietly fail to merge.
_SECURITY_HUB_CONTROL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]*\.\d+$")

REPO_ROOT = _find_repo_root(Path(__file__))
DEFAULT_CONTROL_MAP_PATH = REPO_ROOT / "config" / "prowler_control_map.yaml"


def load_control_map(path: Path = DEFAULT_CONTROL_MAP_PATH) -> dict[str, list[str]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    checks: dict[str, list[str]] = data["checks"]
    return checks


def _parse_time(value: str | None, fallback: datetime) -> datetime:
    if not value:
        return fallback
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return fallback


def _load_raw_findings(ctx: CollectorContext) -> list[dict[str, Any]]:
    if ctx.fixtures_dir is not None:
        path = ctx.fixtures_dir / "prowler" / "findings.json"
        if not path.exists():
            return []
        result: list[dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))
        return result

    from cloudops_orchestrator.aws.clients import get_s3_client

    client = get_s3_client(region_name=ctx.settings.aws.region)
    prefix = ctx.settings.collectors.prowler.prefix
    key = f"{prefix.rstrip('/')}/findings.json"
    try:
        response = client.get_object(Bucket=ctx.settings.storage.bucket, Key=key)
    except client.exceptions.NoSuchKey:
        return []
    loaded: list[dict[str, Any]] = json.loads(response["Body"].read())
    return loaded


def _check_staleness(
    raw_findings: list[dict[str, Any]], *, ctx: CollectorContext, max_age_days: int
) -> list[str]:
    if not raw_findings:
        return []
    timestamps = [_parse_time(f.get("timestamp"), ctx.now) for f in raw_findings]
    newest = max(timestamps)
    age_days = (ctx.now - newest).days
    if age_days > max_age_days:
        return [
            f"Prowler data is {age_days} days old (max_age_days={max_age_days}) — results may be stale."
        ]
    return []


def _pick_fingerprint_control(control_ids: list[str], *, fallback: str) -> str:
    """Prefer a Security-Hub-style control id so this merges with SH's finding."""
    for control_id in control_ids:
        if _SECURITY_HUB_CONTROL_RE.match(control_id):
            return control_id
    return control_ids[0] if control_ids else fallback


def parse_finding(
    raw: dict[str, Any], *, ctx: CollectorContext, control_map: dict[str, list[str]]
) -> Finding:
    check_id: str = raw["check_id"]
    control_ids = control_map.get(check_id, [])
    fingerprint_key = _pick_fingerprint_control(control_ids, fallback=check_id)
    resource_id: str = raw.get("resource_uid", "unknown")
    severity = _SEVERITY_MAP.get(str(raw.get("severity", "low")).lower(), Severity.LOW)
    tags: dict[str, str] = raw.get("tags") or {}

    fingerprint = security_finding_fingerprint(
        account_id=ctx.account.id,
        region=raw.get("region", ctx.settings.aws.region),
        resource_id=resource_id,
        control_id=fingerprint_key,
    )

    return Finding(
        fingerprint=fingerprint,
        domain=Domain.SECURITY,
        source=SOURCE,
        sources=[SOURCE],
        rule_id=check_id,
        control_ids=control_ids or [check_id],
        title=check_id,
        description=f"Prowler check {check_id} failed for {raw.get('resource_name', resource_id)}.",
        severity=severity,
        account_id=ctx.account.id,
        region=raw.get("region", ctx.settings.aws.region),
        resource_type=raw.get("resource_type", "Other"),
        resource_id=resource_id,
        resource_tags=tags,
        environment=tags.get("environment"),
        evidence_uri=f"s3://{ctx.settings.storage.bucket}/evidence/{ctx.run_id}/prowler/{check_id}.json",
        first_seen=_parse_time(raw.get("timestamp"), ctx.now),
        last_seen=_parse_time(raw.get("timestamp"), ctx.now),
        status=FindingStatus.NEW,
    )


def collect(ctx: CollectorContext) -> CollectorResult:
    config = ctx.settings.collectors.prowler
    if not config.enabled:
        return CollectorResult()

    raw_findings = _load_raw_findings(ctx)
    failed = [raw for raw in raw_findings if raw.get("status") == "FAIL"]
    warnings = _check_staleness(raw_findings, ctx=ctx, max_age_days=config.max_age_days)

    control_map = load_control_map()
    findings = [parse_finding(raw, ctx=ctx, control_map=control_map) for raw in failed]
    return CollectorResult(
        findings=findings, raw_evidence={"prowler_findings": raw_findings}, warnings=warnings
    )


__all__ = ["SOURCE", "collect", "load_control_map", "parse_finding"]
