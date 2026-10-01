"""Tests for scripts/gen_demo_artifacts.py — the demo_matrix.yaml -> fixtures/docs generator."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_generated_fixtures_are_up_to_date() -> None:
    """Committed fixture output must match what the generator produces right now.

    If this fails, someone edited demo_matrix.yaml (or a SOP's severity)
    without re-running `uv run python scripts/gen_demo_artifacts.py`.
    """
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "gen_demo_artifacts.py"), "--check"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_every_security_hub_case_has_a_finding() -> None:
    import yaml

    matrix = yaml.safe_load(
        (REPO_ROOT / "tests/fixtures/scenario_demo/demo_matrix.yaml").read_text()
    )
    expected = sum(1 for c in matrix["cases"] if c.get("source") == "security_hub")
    findings = json.loads(
        (REPO_ROOT / "tests/fixtures/scenario_demo/securityhub/findings.json").read_text()
    )
    assert len(findings) == expected


def test_every_security_hub_finding_has_a_matching_prowler_finding() -> None:
    """Every security_hub-sourced demo case has an external control mapped in
    prowler_control_map.yaml, so it should get a parallel Prowler finding —
    exercising the SH+Prowler merge-on-control-ID path collectors will use.
    """
    sh_findings = json.loads(
        (REPO_ROOT / "tests/fixtures/scenario_demo/securityhub/findings.json").read_text()
    )
    prowler_findings = json.loads(
        (REPO_ROOT / "tests/fixtures/scenario_demo/prowler/findings.json").read_text()
    )
    assert len(prowler_findings) == len(sh_findings)


def test_drift_fixtures_reference_only_iac_managed_resources() -> None:
    inventory = json.loads(
        (REPO_ROOT / "tests/fixtures/scenario_demo/drift/inventory.json").read_text()
    )
    plan = json.loads((REPO_ROOT / "tests/fixtures/scenario_demo/drift/plan.json").read_text())
    inventory_addresses = {r["address"] for r in inventory["root_module"]["resources"]}
    for drift in plan["resource_drift"]:
        assert drift["address"] in inventory_addresses


def test_unmanaged_resources_are_not_in_inventory() -> None:
    inventory = json.loads(
        (REPO_ROOT / "tests/fixtures/scenario_demo/drift/inventory.json").read_text()
    )
    unmanaged = json.loads(
        (REPO_ROOT / "tests/fixtures/scenario_demo/drift/unmanaged.json").read_text()
    )
    inventory_names = {r["name"] for r in inventory["root_module"]["resources"]}
    for resource in unmanaged:
        assert resource["resource_name"] not in inventory_names


def test_violations_md_mentions_every_case() -> None:
    import yaml

    matrix = yaml.safe_load(
        (REPO_ROOT / "tests/fixtures/scenario_demo/demo_matrix.yaml").read_text()
    )
    violations_md = (REPO_ROOT / "demo/docs/VIOLATIONS.md").read_text()
    for case in matrix["cases"]:
        assert case["resource_name"] in violations_md
