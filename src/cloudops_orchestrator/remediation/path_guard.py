"""Path guard: the Terraform PR agent may only ever edit
files under configured allowed paths, and never under paths that must stay
under the orchestrator's own control — regardless of configuration. This
is enforced before any commit is made; a violation is always a bug (a
config mistake or a locator that wandered outside ``demo/infra``), never a
recoverable runtime condition, so callers should route it to
``MANUAL_TICKET`` and an audit event rather than retry.
"""

from __future__ import annotations

from fnmatch import fnmatch

#: Denied even if ``remediation.terraform_pr.allowed_paths`` is misconfigured
#: to include them — these paths are the orchestrator's own code and control
#: plane, never something an LLM-drafted edit should touch.
ALWAYS_DENIED_PREFIXES = (
    ".github/",
    "src/",
    "infra/",
    "config/",
    "knowledge_base/",
    "statemachine/",
)


def is_path_allowed(path: str, *, allowed_paths: list[str]) -> bool:
    """``path`` is a repo-relative file path (no leading ``/``)."""
    normalized = path.lstrip("/")
    if normalized.startswith(ALWAYS_DENIED_PREFIXES):
        return False
    return any(fnmatch(normalized, pattern) for pattern in allowed_paths)


__all__ = ["ALWAYS_DENIED_PREFIXES", "is_path_allowed"]
