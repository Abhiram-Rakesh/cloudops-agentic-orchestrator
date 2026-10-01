"""Structural validation of statemachine/review.asl.json: valid
JSON, every Task's ``Resource`` placeholder names a Lambda that actually
exists (a ``handlers/*.py`` module), and every ``Next``/``Default`` target
(including inside the Map state's ``ItemProcessor``) resolves to a real
state. This is the "local parity" test the spec calls for — it doesn't run
the state machine, just its shape.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
ASL_PATH = REPO_ROOT / "statemachine" / "review.asl.json"
HANDLERS_DIR = REPO_ROOT / "src" / "cloudops_orchestrator" / "handlers"

_PLACEHOLDER_RE = re.compile(r"^\$\{(\w+)_arn\}$")


def _load_asl() -> dict[str, Any]:
    return json.loads(ASL_PATH.read_text(encoding="utf-8"))


def _handler_names() -> set[str]:
    return {p.stem for p in HANDLERS_DIR.glob("*.py") if p.stem != "__init__"}


def _iter_states(states: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Flatten top-level states plus any nested Map ItemProcessor states."""
    flat: list[tuple[str, dict[str, Any]]] = []
    for name, state in states.items():
        flat.append((name, state))
        processor = state.get("ItemProcessor")
        if processor:
            flat.extend(_iter_states(processor["States"]))
    return flat


def test_asl_file_is_valid_json() -> None:
    assert ASL_PATH.exists()
    _load_asl()  # raises if invalid


def test_every_task_resource_maps_to_a_real_handler() -> None:
    asl = _load_asl()
    handlers = _handler_names()
    for name, state in _iter_states(asl["States"]):
        if state.get("Type") != "Task":
            continue
        resource = state["Resource"]
        match = _PLACEHOLDER_RE.match(resource)
        assert match is not None, (
            f"state {name!r} has an unrecognized Resource placeholder: {resource!r}"
        )
        assert match.group(1) in handlers, (
            f"state {name!r} references {resource!r}, but there is no handlers/{match.group(1)}.py"
        )


def test_every_next_and_default_target_exists() -> None:
    asl = _load_asl()
    all_states = dict(_iter_states(asl["States"]))
    # Next/Default targets are scoped to their own States block (top-level or
    # one Map's ItemProcessor) — collect each scope's own key set separately.
    scopes = [asl["States"]] + [
        state["ItemProcessor"]["States"]
        for _name, state in _iter_states(asl["States"])
        if "ItemProcessor" in state
    ]
    for scope in scopes:
        keys = set(scope)
        for name, state in scope.items():
            for target in _targets_of(state):
                assert target in keys, (
                    f"state {name!r} points to {target!r}, which doesn't exist in its scope"
                )
    assert all_states  # sanity: the walk found something


def _targets_of(state: dict[str, Any]) -> list[str]:
    targets = []
    if "Next" in state:
        targets.append(state["Next"])
    if "Default" in state:
        targets.append(state["Default"])
    for choice in state.get("Choices", []):
        if "Next" in choice:
            targets.append(choice["Next"])
    for catcher in state.get("Catch", []):
        targets.append(catcher["Next"])
    return targets


def test_start_at_exists() -> None:
    asl = _load_asl()
    assert asl["StartAt"] in asl["States"]


def test_every_state_is_reachable_from_start_at() -> None:
    """No orphan states: a breadth-first walk from StartAt (following every
    Choice branch and Catch, not just the first) visits every state.
    ``DomainBatch`` (inside the Map's ItemProcessor) is reachable via its own
    ``ItemProcessor.StartAt``, not the top-level walk, so it's checked
    separately."""
    asl = _load_asl()
    states = asl["States"]

    def reachable_from(start: str, scope: dict[str, Any]) -> set[str]:
        seen: set[str] = set()
        queue = [start]
        while queue:
            current = queue.pop()
            if current in seen:
                continue
            seen.add(current)
            queue.extend(_targets_of(scope[current]))
        return seen

    top_level_reachable = reachable_from(asl["StartAt"], states)
    assert top_level_reachable == set(states), set(states) - top_level_reachable

    for name, state in states.items():
        processor = state.get("ItemProcessor")
        if not processor:
            continue
        inner_states = processor["States"]
        inner_reachable = reachable_from(processor["StartAt"], inner_states)
        assert inner_reachable == set(inner_states), (
            f"{name!r}'s ItemProcessor has unreachable states: {set(inner_states) - inner_reachable}"
        )
