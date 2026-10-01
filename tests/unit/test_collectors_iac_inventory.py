from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from cloudops_orchestrator.collectors import iac_inventory
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


def test_build_inventory_lookup() -> None:
    inventory = {
        "root_module": {
            "resources": [
                {"address": "aws_instance.web", "values": {"id": "i-1"}},
                {"address": "aws_instance.no_id", "values": {}},
            ]
        }
    }
    lookup = iac_inventory.build_inventory_lookup(inventory)
    assert lookup == {"i-1": "aws_instance.web"}


def test_collect_flags_unmanaged_resource_from_real_fixtures() -> None:
    result = iac_inventory.collect(_ctx(REPO_ROOT / "tests" / "fixtures" / "scenario_demo"))
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "DRIFT-UNMANAGED"
    assert result.findings[0].iac_managed is False
    assert "temp-debug-sg" in result.findings[0].resource_id


def test_managed_resource_not_flagged_unmanaged(tmp_path: Path) -> None:
    import json

    (tmp_path / "drift").mkdir()
    (tmp_path / "drift" / "inventory.json").write_text(
        json.dumps({"root_module": {"resources": [{"address": "a", "values": {"id": "r-1"}}]}})
    )
    (tmp_path / "drift" / "unmanaged.json").write_text(
        json.dumps([{"resource_id": "r-1", "resource_type": "x", "resource_name": "n", "tags": {}}])
    )
    result = iac_inventory.collect(_ctx(tmp_path))
    assert result.findings == []


def test_no_candidates_no_findings(tmp_path: Path) -> None:
    result = iac_inventory.collect(_ctx(tmp_path))
    assert result.findings == []
