from __future__ import annotations

from pathlib import Path

import pytest

from cloudops_orchestrator.checkpoint.factory import get_checkpointer
from cloudops_orchestrator.config import load_settings

REPO_ROOT = Path(__file__).resolve().parents[2]
SETTINGS = load_settings(REPO_ROOT / "config" / "settings.local.yaml", env={})


def test_memory_backend() -> None:
    settings = SETTINGS.model_copy(
        update={"checkpoint": SETTINGS.checkpoint.model_copy(update={"backend": "memory"})}
    )
    checkpointer = get_checkpointer(settings)
    assert type(checkpointer).__name__ == "InMemorySaver"


def test_sqlite_backend(tmp_path: Path) -> None:
    settings = SETTINGS.model_copy(
        update={"checkpoint": SETTINGS.checkpoint.model_copy(update={"backend": "sqlite"})}
    )
    checkpointer = get_checkpointer(settings, sqlite_path=tmp_path / "checkpoints.sqlite")
    assert type(checkpointer).__name__ == "SqliteSaver"
    assert (tmp_path / "checkpoints.sqlite").exists()


def test_dynamodb_backend_constructs_without_live_call() -> None:
    settings = SETTINGS.model_copy(
        update={"checkpoint": SETTINGS.checkpoint.model_copy(update={"backend": "dynamodb"})}
    )
    checkpointer = get_checkpointer(settings)
    assert type(checkpointer).__name__ == "DynamoDBSaver"


def test_unknown_backend_raises() -> None:
    settings = SETTINGS.model_copy(
        update={"checkpoint": SETTINGS.checkpoint.model_copy(update={"backend": "memory"})}
    )
    object.__setattr__(settings.checkpoint, "backend", "bogus")
    with pytest.raises(ValueError, match="Unknown checkpoint backend"):
        get_checkpointer(settings)


def test_sqlite_graph_round_trip(tmp_path: Path) -> None:
    """A real LangGraph checkpointed graph actually round-trips through sqlite."""
    from typing import TypedDict

    from langgraph.graph import END, START, StateGraph

    class State(TypedDict):
        value: int

    settings = SETTINGS.model_copy(
        update={"checkpoint": SETTINGS.checkpoint.model_copy(update={"backend": "sqlite"})}
    )
    checkpointer = get_checkpointer(settings, sqlite_path=tmp_path / "cp.sqlite")

    builder = StateGraph(State)
    builder.add_node("increment", lambda s: {"value": s["value"] + 1})
    builder.add_edge(START, "increment")
    builder.add_edge("increment", END)
    graph = builder.compile(checkpointer=checkpointer)

    config = {"configurable": {"thread_id": "t1"}}
    result = graph.invoke({"value": 1}, config)
    assert result["value"] == 2

    state = graph.get_state(config)
    assert state.values["value"] == 2
