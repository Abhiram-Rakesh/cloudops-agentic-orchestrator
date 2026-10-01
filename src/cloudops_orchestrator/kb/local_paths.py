"""Shared local staging path for the built SOP index.

Was duplicated verbatim in kb/index_builder.py and kb/retriever.py, both
hardcoding a relative ".cache/sop_index.json.gz" path -- fine for local/CI
(writable CWD), but Lambda's filesystem is read-only except /tmp. Fixing
only one copy left the other with the identical bug (found live 2026-09-28:
index_builder.py's write side was fixed first, then retriever.py's read
side hit the exact same class of error immediately after -- see
README.md (Troubleshooting)). Consolidated so both always agree.
"""

from __future__ import annotations

import os
from pathlib import Path

from cloudops_orchestrator.config import Settings


def resolve_local_index_path(settings: Settings) -> Path:
    if not settings.kb.index_uri.startswith("s3://"):
        return Path(settings.kb.index_uri)
    base = "/tmp" if "AWS_LAMBDA_FUNCTION_NAME" in os.environ else ".cache"
    return Path(base) / "sop_index.json.gz"


__all__ = ["resolve_local_index_path"]
