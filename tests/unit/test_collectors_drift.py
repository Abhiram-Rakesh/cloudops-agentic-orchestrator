from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from cloudops_orchestrator.collectors import drift
from cloudops_orchestrator.collectors.base import CollectorContext
from cloudops_orchestrator.config import load_settings

REPO_ROOT = Path(__file__).resolve().parents[2]


def _ctx(fixtures_dir: Path) -> CollectorContext:
    settings = load_settings(REPO_ROOT / "config" / "settings.local.yaml", env={})
    return CollectorContext(
        run_id="run-1",
        settings=settings,
        account=settings.aws.accounts[0],
        now=datetime(2026, 1, 27, tzinfo=UTC),
        fixtures_dir=fixtures_dir,
    )


def test_collect_from_real_fixtures() -> None:
    result = drift.collect(_ctx(REPO_ROOT / "tests" / "fixtures" / "scenario_demo"))
    assert len(result.findings) > 0
    assert all(f.rule_id == "DRIFT-ATTR" for f in result.findings)
    assert all(f.iac_managed for f in result.findings)


def test_each_resource_drift_entry_produces_a_distinct_finding() -> None:
    # Terraform's real plan JSON puts `address`/`type`/`change.actions`
    # directly on each `resource_drift` entry, not nested under a
    # "resource" sub-object -- a prior bug defaulted every entry's
    # resource_id to "unknown", collapsing 3 distinct fixture entries into
    # 1 degenerate finding via fingerprint dedup (found live 2026-09-29).
    result = drift.collect(_ctx(REPO_ROOT / "tests" / "fixtures" / "scenario_demo"))
    assert len(result.findings) == 3
    assert "unknown" not in {f.resource_id for f in result.findings}
    assert len({f.fingerprint for f in result.findings}) == 3


def test_missing_plan_produces_warning_not_error(tmp_path: Path) -> None:
    result = drift.collect(_ctx(tmp_path))
    assert result.findings == []
    assert result.warnings
    assert "not deployed" in result.warnings[0]


def test_empty_resource_drift_list_produces_no_findings(tmp_path: Path) -> None:
    (tmp_path / "drift").mkdir()
    (tmp_path / "drift" / "plan.json").write_text(json.dumps({"resource_drift": []}))
    result = drift.collect(_ctx(tmp_path))
    assert result.findings == []
    assert result.warnings == []


def test_parse_drift_entry() -> None:
    from cloudops_orchestrator.config import DriftWorkspaceConfig

    ctx = _ctx(REPO_ROOT / "tests" / "fixtures" / "scenario_demo")
    workspace = DriftWorkspaceConfig(name="orders-demo", path="demo/infra", state_key="k")
    entry = {
        "address": "aws_security_group.app",
        "mode": "managed",
        "type": "aws_security_group",
        "name": "app",
        "change": {"actions": ["update"]},
        "notes": "port 8080 opened",
    }
    finding = drift.parse_drift_entry(entry, ctx=ctx, workspace=workspace)
    assert finding.iac_address == "aws_security_group.app"
    assert finding.resource_type == "aws_security_group"
    assert finding.details["workspace"] == "orders-demo"


def test_disabled_collector() -> None:
    settings = load_settings(REPO_ROOT / "config" / "settings.local.yaml", env={})
    disabled = settings.collectors.model_copy(
        update={"drift": settings.collectors.drift.model_copy(update={"enabled": False})}
    )
    settings = settings.model_copy(update={"collectors": disabled})
    ctx = CollectorContext(
        run_id="r",
        settings=settings,
        account=settings.aws.accounts[0],
        now=datetime(2026, 1, 27, tzinfo=UTC),
        fixtures_dir=REPO_ROOT / "tests/fixtures/scenario_demo",
    )
    assert drift.collect(ctx).findings == []
