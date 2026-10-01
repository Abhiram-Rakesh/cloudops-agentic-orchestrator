#!/usr/bin/env python3
"""Generate demo fixtures and docs from the single source of truth:
tests/fixtures/scenario_demo/demo_matrix.yaml.

Outputs (never hand-edit these — regenerate with this script instead):
  - tests/fixtures/scenario_demo/securityhub/findings.json  (ASFF-lite)
  - tests/fixtures/scenario_demo/prowler/findings.json      (OCSF-lite)
  - tests/fixtures/scenario_demo/drift/inventory.json + plan.json
  - demo/docs/VIOLATIONS.md

The generated fixture set represents the demo stack's state *after*
`make drift` (simulate_clickops.sh) has run — the richer scenario that
exercises every row in the matrix, including the `post_clickops` ones. A
second, "pre-drift" fixture snapshot (for the "a later run marks a finding
RESOLVED" pipeline test) is generated separately alongside that specific
test.

Fixture schema note: `drift/inventory.json` and `drift/plan.json` are a
deliberately simplified stand-in for `terraform show -json` output, not a
byte-for-byte match of Terraform's real schema (this repo never runs
`terraform apply`/`plan` against a real backend — Hard Rule #1). Collectors
parse exactly this simplified shape; verify it against real
`terraform show -json` / `plan -json` output before relying on it against a
live `demo/infra` stack (see README.md (Troubleshooting)).
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from cloudops_orchestrator.kb.parser import ClauseMeta, clause_meta_index

REPO_ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = REPO_ROOT / "tests" / "fixtures" / "scenario_demo" / "demo_matrix.yaml"
KB_DIR = REPO_ROOT / "knowledge_base"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "scenario_demo"
PROWLER_MAP_PATH = REPO_ROOT / "config" / "prowler_control_map.yaml"
VIOLATIONS_PATH = REPO_ROOT / "demo" / "docs" / "VIOLATIONS.md"

ACCOUNT_ID = "111111111111"
REGION = "ap-south-1"
BASE_TIME = datetime(2026, 1, 20, 3, 0, tzinfo=UTC)

_ASFF_SEVERITY = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFORMATIONAL",
}


def load_matrix() -> list[dict[str, Any]]:
    data = yaml.safe_load(MATRIX_PATH.read_text(encoding="utf-8"))
    cases: list[dict[str, Any]] = data["cases"]
    return cases


def load_prowler_map() -> dict[str, list[str]]:
    data = yaml.safe_load(PROWLER_MAP_PATH.read_text(encoding="utf-8"))
    checks: dict[str, list[str]] = data["checks"]
    return checks


def _severity_of(case: dict[str, Any], meta_index: dict[str, ClauseMeta]) -> str:
    for clause_id in case["expected_clause_ids"]:
        meta = meta_index.get(clause_id)
        if meta and meta.severity:
            return meta.severity.value
    return "medium"


def _resource_id(case: dict[str, Any]) -> str:
    rtype = case.get("resource_type", "Other")
    name = case["resource_name"]
    return f"arn:aws:demo:{REGION}:{ACCOUNT_ID}:{rtype}/{name}"


def _resource_tags(case: dict[str, Any]) -> dict[str, str]:
    """Tags collectors read via ``resource_tags`` — the policy engine's
    ``is_protected()`` check needs a case's own ``protected: true`` field
    to actually show up here, or the demo's protected-resource scenario
    (orders-demo-legacy-payments) would never really trigger it."""
    tags = {"environment": case.get("environment", "dev")}
    if case.get("protected"):
        tags["cloudops:protected"] = "true"
    return tags


def build_securityhub_findings(
    cases: list[dict[str, Any]], meta_index: dict[str, ClauseMeta]
) -> list[dict[str, Any]]:
    findings = []
    for case in cases:
        if case.get("source") != "security_hub":
            continue
        severity = _severity_of(case, meta_index)
        findings.append(
            {
                "Id": f"{case['resource_name']}/{case['rule_id']}",
                "ProductArn": f"arn:aws:securityhub:{REGION}::product/aws/securityhub",
                "AwsAccountId": ACCOUNT_ID,
                "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                "CreatedAt": BASE_TIME.isoformat(),
                "UpdatedAt": BASE_TIME.isoformat(),
                "Severity": {"Label": _ASFF_SEVERITY[severity]},
                "Title": case["rule_id"],
                "Description": case.get("notes", ""),
                "Resources": [
                    {
                        "Type": case.get("resource_type", "Other"),
                        "Id": _resource_id(case),
                        "Tags": _resource_tags(case),
                    }
                ],
                # SecurityControlId is the *authoritative* control (control_ids[0],
                # not rule_id — a case's rule_id is just a human label and can
                # differ from the primary control when several controls apply,
                # e.g. EC2.18+EC2.19 both covering one high-risk-port check).
                "Compliance": {
                    "Status": "FAILED",
                    "SecurityControlId": (case.get("control_ids") or [case["rule_id"]])[0],
                },
                "RecordState": "ACTIVE",
                "WorkflowState": "NEW",
            }
        )
    return findings


def build_prowler_findings(
    cases: list[dict[str, Any]],
    prowler_map: dict[str, list[str]],
    meta_index: dict[str, ClauseMeta],
) -> list[dict[str, Any]]:
    reverse_map: dict[str, list[str]] = {}
    for check_id, controls in prowler_map.items():
        for control in controls:
            reverse_map.setdefault(control, []).append(check_id)

    findings = []
    for case in cases:
        if case.get("source") != "security_hub":
            continue
        matching_checks = [
            check_id
            for control_id in case.get("control_ids", [])
            for check_id in reverse_map.get(control_id, [])
        ]
        if not matching_checks:
            continue
        severity = _severity_of(case, meta_index)
        check_id = matching_checks[0]
        findings.append(
            {
                "check_id": check_id,
                "status": "FAIL",
                "severity": severity,
                "region": REGION,
                "account_id": ACCOUNT_ID,
                "resource_uid": _resource_id(case),
                "resource_name": case["resource_name"],
                "resource_type": case.get("resource_type", "Other"),
                "tags": _resource_tags(case),
                "timestamp": BASE_TIME.isoformat(),
            }
        )
    return findings


def build_drift_fixtures(cases: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    iac_managed_resources = {c["resource_name"]: c for c in cases if c.get("iac_managed")}
    drift_cases = [c for c in cases if c.get("source") == "drift"]

    inventory_resources = [
        {
            "address": f"{c.get('resource_type', 'resource').lower()}.{name.replace('-', '_')}",
            "type": c.get("resource_type", "Other"),
            "name": name,
            "values": {"id": _resource_id(c), "tags": {"environment": c.get("environment", "dev")}},
        }
        for name, c in iac_managed_resources.items()
    ]

    resource_drift = [
        {
            # Terraform's real plan JSON has address/type/change.actions as
            # top-level keys on each resource_drift entry, not nested under
            # a "resource" sub-object -- see collectors/drift.py.
            "address": f"{c.get('resource_type', 'resource').lower()}.{c['resource_name'].replace('-', '_')}",
            "type": c.get("resource_type", "Other"),
            "name": c["resource_name"],
            "change": {"actions": ["update"]},
            "notes": c.get("notes", ""),
        }
        for c in drift_cases
        if c.get("iac_managed")
    ]

    inventory = {"root_module": {"resources": inventory_resources}}
    plan = {"resource_drift": resource_drift, "generated_at": BASE_TIME.isoformat()}
    return inventory, plan


def build_unmanaged_resources(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Resources tagged app=orders-demo but absent from Terraform state (DRIFT-001)."""
    return [
        {
            "resource_id": _resource_id(c),
            "resource_type": c.get("resource_type", "Other"),
            "resource_name": c["resource_name"],
            "tags": {"environment": c.get("environment", "dev"), "app": "orders-demo"},
        }
        for c in cases
        if c.get("source") == "drift" and not c.get("iac_managed")
    ]


def build_cost_waste_resources() -> dict[str, Any]:
    """The demo stack's EC2/EBS/EIP/S3 inventory, for the cost_waste collector.

    Hand-authored (not derived from demo_matrix.yaml, which is finding-
    oriented, not resource-inventory-oriented) to match exactly the
    per-resource violations `demo/infra` and `knowledge_base/cost/*.md`
    describe. Kept in sync with demo_matrix.yaml by
    `tests/unit/test_gen_demo_artifacts.py`, which runs the real
    `collectors.cost_waste` checks against this fixture and asserts the
    output matches the matrix's cost-domain rows.
    """
    compliant_tags = {"owner": "orders-team", "environment": "dev", "application": "orders"}
    return {
        "instances": [
            {
                "instance_id": "i-0aaaaaaaaaaaaaaaa",
                "name": "orders-demo-web",
                "tags": {**compliant_tags},  # missing cost-center, missing schedule
                "state": "running",
                "instance_type": "t4g.micro",
                "avg_cpu_pct_7d": 35.0,
                "avg_network_bytes_per_day": 50 * 1024 * 1024,
            },
            {
                "instance_id": "i-0bbbbbbbbbbbbbbbb",
                "name": "orders-demo-batch-worker",
                "tags": {
                    "environment": "dev",
                    "application": "orders",
                },  # missing owner, cost-center, schedule
                "state": "running",
                "instance_type": "t4g.micro",
                "avg_cpu_pct_7d": 1.2,
                "avg_network_bytes_per_day": 512 * 1024,
            },
        ],
        "volumes": [
            {
                "volume_id": "vol-0ccccccccccccccc",
                "name": "orders-demo-scratch",
                "tags": {
                    "environment": "dev",
                    "application": "orders",
                },  # missing owner, cost-center
                "size_gb": 1,
                "volume_type": "gp2",
                "encrypted": False,
                "attached": False,
                "days_unattached": 14,
            }
        ],
        "addresses": [
            {
                "allocation_id": "eipalloc-0ddddddddddddddd",
                "name": "orders-demo-eip-unused",
                "tags": {
                    "environment": "dev",
                    "application": "orders",
                },  # missing owner, cost-center
                "associated": False,
                "hours_unassociated": 168.0,
            }
        ],
        "snapshots": [],
        "buckets": [
            {
                "name": "orders-demo-exports",
                "tags": {**compliant_tags},  # missing cost-center
                "has_lifecycle_rule": False,
            }
        ],
        "compute_optimizer": [],
    }


def render_violations_md(cases: list[dict[str, Any]], meta_index: dict[str, ClauseMeta]) -> str:
    lines = [
        "# Demo Stack Violations",
        "",
        "Generated from `tests/fixtures/scenario_demo/demo_matrix.yaml` by",
        "`scripts/gen_demo_artifacts.py` — do not hand-edit this file.",
        "",
        "Every row below is an intentional, safe-by-construction SOP violation",
        "the demo stack (`demo/infra`) is built to exhibit, so the CloudOps",
        "agents have something real to find, triage, and (with approval) fix.",
        "",
        "| Resource | Domain | Clause(s) | Severity | Action | Tier | Notes |",
        "|---|---|---|---|---|---|---|",
    ]
    for case in cases:
        clauses = ", ".join(case["expected_clause_ids"])
        severity = _severity_of(case, meta_index)
        flag = f" (requires `{case['requires_flag']}=true`)" if case.get("requires_flag") else ""
        lines.append(
            f"| `{case['resource_name']}` | {case['domain']} | {clauses} | {severity} | "
            f"{case['expected_action_type']} | {case['expected_tier']} | {case.get('notes', '')}{flag} |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="Exit non-zero if outputs would change"
    )
    args = parser.parse_args()

    cases = load_matrix()
    prowler_map = load_prowler_map()
    meta_index = clause_meta_index(KB_DIR)

    outputs: dict[Path, str] = {
        FIXTURES_DIR / "securityhub" / "findings.json": json.dumps(
            build_securityhub_findings(cases, meta_index), indent=2
        )
        + "\n",
        FIXTURES_DIR / "prowler" / "findings.json": json.dumps(
            build_prowler_findings(cases, prowler_map, meta_index), indent=2
        )
        + "\n",
        VIOLATIONS_PATH: render_violations_md(cases, meta_index),
    }
    inventory, plan = build_drift_fixtures(cases)
    outputs[FIXTURES_DIR / "drift" / "inventory.json"] = json.dumps(inventory, indent=2) + "\n"
    outputs[FIXTURES_DIR / "drift" / "plan.json"] = json.dumps(plan, indent=2) + "\n"
    outputs[FIXTURES_DIR / "drift" / "unmanaged.json"] = (
        json.dumps(build_unmanaged_resources(cases), indent=2) + "\n"
    )
    outputs[FIXTURES_DIR / "cost_waste" / "resources.json"] = (
        json.dumps(build_cost_waste_resources(), indent=2) + "\n"
    )

    changed = []
    for path, content in outputs.items():
        existing = path.read_text(encoding="utf-8") if path.exists() else None
        if existing != content:
            changed.append(path)
        if not args.check:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

    if args.check and changed:
        for path in changed:
            print(f"OUT OF DATE: {path.relative_to(REPO_ROOT)}")
        raise SystemExit(1)

    if not args.check:
        for path in outputs:
            print(f"wrote {path.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
