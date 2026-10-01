"""Cross-reference consistency between the knowledge base, the Prowler
control map, and the demo matrix — the "single source of truth" checks.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from cloudops_orchestrator.kb.parser import parse_knowledge_base

REPO_ROOT = Path(__file__).resolve().parents[2]
KB_DIR = REPO_ROOT / "knowledge_base"
PROWLER_MAP_PATH = REPO_ROOT / "config" / "prowler_control_map.yaml"
DEMO_MATRIX_PATH = REPO_ROOT / "tests" / "fixtures" / "scenario_demo" / "demo_matrix.yaml"

# Internal, non-Security-Hub rule IDs (cost/drift domains, or informational
# checks with no external control system) never need a Prowler mapping.
_INTERNAL_RULE_PREFIXES = ("COST-", "DRIFT-")


def _is_external_control(control_id: str) -> bool:
    return not any(control_id.startswith(prefix) for prefix in _INTERNAL_RULE_PREFIXES)


def _load_prowler_map() -> dict[str, list[str]]:
    data = yaml.safe_load(PROWLER_MAP_PATH.read_text(encoding="utf-8"))
    checks: dict[str, list[str]] = data["checks"]
    return checks


def _load_demo_matrix() -> list[dict[str, object]]:
    data = yaml.safe_load(DEMO_MATRIX_PATH.read_text(encoding="utf-8"))
    cases: list[dict[str, object]] = data["cases"]
    return cases


class TestProwlerControlMapCoverage:
    def test_every_clause_prowler_check_is_in_the_map(self) -> None:
        prowler_map = _load_prowler_map()
        documents = parse_knowledge_base(KB_DIR)
        missing = []
        for doc in documents:
            for clause in doc.clauses:
                for check in clause.meta.prowler_checks:
                    if check not in prowler_map:
                        missing.append(
                            f"{clause.clause_id}: prowler check {check!r} not in {PROWLER_MAP_PATH.name}"
                        )
        assert not missing, "\n".join(missing)

    def test_mapped_controls_match_clause_controls(self) -> None:
        prowler_map = _load_prowler_map()
        documents = parse_knowledge_base(KB_DIR)
        mismatches = []
        for doc in documents:
            for clause in doc.clauses:
                external_controls = {c for c in clause.meta.controls if _is_external_control(c)}
                if not external_controls:
                    continue
                for check in clause.meta.prowler_checks:
                    mapped = set(prowler_map.get(check, []))
                    if mapped and not external_controls & mapped:
                        mismatches.append(
                            f"{clause.clause_id}: check {check!r} maps to {mapped} but clause "
                            f"declares controls {external_controls}"
                        )
        assert not mismatches, "\n".join(mismatches)

    def test_every_external_control_has_at_least_one_prowler_check(self) -> None:
        documents = parse_knowledge_base(KB_DIR)
        uncovered = []
        for doc in documents:
            for clause in doc.clauses:
                external_controls = [c for c in clause.meta.controls if _is_external_control(c)]
                if external_controls and not clause.meta.prowler_checks:
                    uncovered.append(clause.clause_id)
        assert not uncovered, (
            f"Clauses with external controls but no prowler_checks (so Prowler-only "
            f"coverage after the trial would miss them): {uncovered}"
        )


class TestDemoMatrixConsistency:
    def test_every_expected_clause_exists_in_the_kb(self) -> None:
        documents = parse_knowledge_base(KB_DIR)
        all_clause_ids = {clause.clause_id for doc in documents for clause in doc.clauses}
        cases = _load_demo_matrix()
        missing = []
        for case in cases:
            for clause_id in case["expected_clause_ids"]:
                if clause_id not in all_clause_ids:
                    missing.append(f"{case['resource_name']}: unknown clause_id {clause_id!r}")
        assert not missing, "\n".join(missing)

    def test_every_case_has_required_fields(self) -> None:
        cases = _load_demo_matrix()
        required = {
            "resource_name",
            "domain",
            "source",
            "expected_clause_ids",
            "expected_action_type",
            "expected_tier",
            "iac_managed",
        }
        for case in cases:
            missing_fields = required - case.keys()
            assert not missing_fields, f"{case['resource_name']}: missing fields {missing_fields}"

    def test_matrix_has_cases(self) -> None:
        assert len(_load_demo_matrix()) > 0
