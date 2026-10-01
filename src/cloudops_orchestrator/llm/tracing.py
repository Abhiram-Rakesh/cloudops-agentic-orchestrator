"""LangSmith tracing setup.

`langchain-core`'s tracer activates purely from environment variables
(`LANGCHAIN_TRACING_V2`/`LANGCHAIN_API_KEY`/`LANGCHAIN_PROJECT`/
`LANGCHAIN_ENDPOINT`) -- nothing about constructing a `ChatAnthropic`
model itself turns tracing on. `settings.langsmith` was validated and
`langsmith_api_key` fetched into SSM, but no caller ever set these before
now, so no trace was ever sent despite both existing (found live
2026-09-29, see README.md (Troubleshooting)).

Lambda-specific: the tracer posts runs to LangSmith on a background
thread, which the execution environment can freeze immediately after a
handler returns, before that thread finishes -- `flush_tracing()` must be
called at the end of every handler that calls `enable_tracing`, or traces
silently never arrive even with everything else wired correctly.
"""

from __future__ import annotations

import os

from cloudops_orchestrator.config import LangsmithConfig


def enable_tracing(config: LangsmithConfig, *, api_key: str) -> None:
    os.environ["LANGCHAIN_TRACING_V2"] = "true"
    os.environ["LANGCHAIN_API_KEY"] = api_key
    os.environ["LANGCHAIN_PROJECT"] = config.project
    os.environ["LANGCHAIN_ENDPOINT"] = config.endpoint
    if config.anonymize:
        # Verified against the installed langsmith==0.14.1 wheel:
        # Client.__init__ reads hide_inputs/hide_outputs from exactly these
        # two names via ls_utils.get_env_var(..., namespaces=("LANGSMITH",
        # "LANGCHAIN")) -- redacts run inputs/outputs client-side before a
        # trace is ever uploaded, which is also what shrinks payload size
        # (see README.md (AWS cost estimate)'s langsmith row).
        os.environ["LANGSMITH_HIDE_INPUTS"] = "true"
        os.environ["LANGSMITH_HIDE_OUTPUTS"] = "true"


def flush_tracing() -> None:
    from langchain_core.tracers.langchain import wait_for_all_tracers

    wait_for_all_tracers()


__all__ = ["enable_tracing", "flush_tracing"]
