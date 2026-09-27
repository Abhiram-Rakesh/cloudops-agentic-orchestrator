"""Structured JSON logging via structlog.

CLAUDE.md convention: every log line is JSON and, where applicable, carries
``run_id`` and/or ``thread_id``/``action_id``. Bind those once per
request/step with ``bind_context`` rather than passing them to every log
call.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, cast

import structlog
from structlog.typing import FilteringBoundLogger

_CONFIGURED = False


def configure_logging(*, level: int = logging.INFO) -> None:
    """Idempotent structlog configuration; safe to call at every Lambda cold start."""
    global _CONFIGURED
    if _CONFIGURED:
        return

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        context_class=dict,
        # No explicit `file=` here: structlog's PrintLogger special-cases
        # "the file I was given is the same object as sys.stdout was at
        # import time" to mean "print to whatever sys.stdout is *now*"
        # instead of a captured reference. Passing `file=sys.stdout`
        # explicitly captures a stale stream — pytest's capsys swaps
        # sys.stdout per-test and a captured reference goes stale (closed)
        # across tests, since structlog.configure() is intentionally
        # idempotent (safe to call at every Lambda cold start).
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )
    _CONFIGURED = True


def get_logger(**initial_context: Any) -> FilteringBoundLogger:
    configure_logging()
    return cast(FilteringBoundLogger, structlog.get_logger(**initial_context))


@contextmanager
def bind_context(**kwargs: Any) -> Iterator[None]:
    """Bind context vars (e.g. run_id, thread_id) for the duration of a block."""
    tokens = structlog.contextvars.bind_contextvars(**kwargs)
    try:
        yield
    finally:
        structlog.contextvars.reset_contextvars(**tokens)
