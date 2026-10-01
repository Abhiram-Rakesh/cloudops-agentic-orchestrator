"""Checkpointer factory: ``dynamodb`` (live) | ``sqlite`` (local/CI) |
``memory`` (tests).

``langgraph-checkpoint-aws==1.2.3`` ships a ``DynamoDBSaver`` — verified
directly against its installed source (not a live call): it requires a
table keyed on partition key ``PK`` (String) + sort key ``SK`` (String),
with a Number TTL attribute named ``ttl``, and no GSI. ``infra/modules/data``
provisions exactly that schema for
``${NAME_PREFIX}-checkpoints`` — see README.md (Troubleshooting).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cloudops_orchestrator.config import Settings

DEFAULT_SQLITE_PATH = Path(".cache/checkpoints.sqlite")


def get_checkpointer(settings: Settings, *, sqlite_path: Path = DEFAULT_SQLITE_PATH) -> Any:
    backend = settings.checkpoint.backend

    if backend == "dynamodb":
        from langgraph_checkpoint_aws import DynamoDBSaver

        return DynamoDBSaver(
            table_name=settings.storage.checkpoint_table,
            region_name=settings.aws.region,
            s3_offload_config={"bucket_name": settings.storage.bucket},
        )

    if backend == "sqlite":
        import sqlite3

        from langgraph.checkpoint.sqlite import SqliteSaver

        sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(sqlite_path), check_same_thread=False)
        return SqliteSaver(conn)

    if backend == "memory":
        from langgraph.checkpoint.memory import InMemorySaver

        return InMemorySaver()

    msg = f"Unknown checkpoint backend: {backend!r} (expected dynamodb, sqlite, or memory)"
    raise ValueError(msg)


__all__ = ["DEFAULT_SQLITE_PATH", "get_checkpointer"]
