from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from build_inventory import build_inventory  # noqa: E402


def test_flattens_root_module_resources() -> None:
    show_output = {
        "values": {
            "root_module": {
                "resources": [
                    {"address": "aws_security_group.web", "values": {"id": "sg-1", "name": "web"}},
                ]
            }
        }
    }
    assert build_inventory(show_output) == {
        "root_module": {
            "resources": [{"address": "aws_security_group.web", "values": {"id": "sg-1"}}]
        }
    }


def test_flattens_nested_child_modules() -> None:
    show_output = {
        "values": {
            "root_module": {
                "resources": [{"address": "aws_vpc.main", "values": {"id": "vpc-1"}}],
                "child_modules": [
                    {
                        "resources": [
                            {"address": "module.network.aws_subnet.a", "values": {"id": "subnet-1"}}
                        ]
                    }
                ],
            }
        }
    }
    result = build_inventory(show_output)
    addresses = {r["address"] for r in result["root_module"]["resources"]}
    assert addresses == {"aws_vpc.main", "module.network.aws_subnet.a"}


def test_empty_state_produces_empty_inventory() -> None:
    assert build_inventory({}) == {"root_module": {"resources": []}}


def test_resources_without_id_are_skipped() -> None:
    show_output = {
        "values": {
            "root_module": {
                "resources": [
                    {"address": "null_resource.noop", "values": {}},
                    {"address": "aws_vpc.main", "values": {"id": "vpc-1"}},
                ]
            }
        }
    }
    result = build_inventory(show_output)
    assert len(result["root_module"]["resources"]) == 1
