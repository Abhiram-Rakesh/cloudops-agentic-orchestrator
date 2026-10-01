"""Builds ``inventory.json`` from a ``terraform show -json`` state dump
(``drift.yml``): flattens ``values.root_module`` (and any ``child_modules``)
into the ``{"root_module": {"resources": [{"address", "values": {"id"}}]}}``
shape ``collectors/iac_inventory.py``'s ``build_inventory_lookup`` reads —
just the two fields it needs, not the full state.

Usage: python scripts/build_inventory.py <terraform-show-output.json> <out.json>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def _flatten_resources(module: dict[str, Any]) -> list[dict[str, Any]]:
    resources = [
        {"address": r["address"], "values": {"id": r["values"]["id"]}}
        for r in module.get("resources", [])
        if r.get("values", {}).get("id") is not None
    ]
    for child in module.get("child_modules", []):
        resources.extend(_flatten_resources(child))
    return resources


def build_inventory(show_output: dict[str, Any]) -> dict[str, Any]:
    root_module = show_output.get("values", {}).get("root_module", {})
    return {"root_module": {"resources": _flatten_resources(root_module)}}


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(f"usage: {argv[0]} <terraform-show-output.json> <out.json>", file=sys.stderr)
        return 2
    show_output = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    inventory = build_inventory(show_output)
    Path(argv[2]).write_text(json.dumps(inventory, indent=2), encoding="utf-8")
    print(f"Wrote {argv[2]} ({len(inventory['root_module']['resources'])} resources)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
