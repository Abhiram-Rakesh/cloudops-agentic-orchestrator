"""Anthropic chat model factory: rate-limited, tenacity-retried, cache-aware.

Verified against the installed ``langchain-anthropic==1.7.4`` /
``anthropic==1.8.0`` wheels (not a live API call — Hard Rule #2):
``ChatAnthropic`` fields are ``model`` (alias of ``model_name``),
``max_tokens``, ``max_retries``, and ``timeout`` (alias of
``default_request_timeout``); retryable errors are
``anthropic.RateLimitError`` (429), ``anthropic.InternalServerError``
(5xx), and ``anthropic.APIStatusError`` with ``status_code == 529``
(overloaded). ``max_retries=0`` on the model itself because retries are
handled here via ``tenacity`` instead, so we can honor a `Retry-After`
header and apply jitor deterministically. **``temperature`` is deliberately
never set** — confirmed via a live call (not guessed) that both
``claude-haiku-4-5``/``claude-sonnet-5`` reject it outright with `400:
temperature is deprecated for this model`; see
README.md (Troubleshooting) for what still needs a live check.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, TypeVar

import anthropic
from tenacity import (
    RetryCallState,
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_random_exponential,
)

from cloudops_orchestrator.config import LLMConfig

if TYPE_CHECKING:
    from langchain_anthropic import ChatAnthropic

TRIAGE_MAX_TOKENS = 1500
REASONING_MAX_TOKENS = 4000
REQUEST_TIMEOUT_SECONDS = 60
MAX_RETRY_ATTEMPTS = 4

T = TypeVar("T")


def _is_retryable(exc: BaseException) -> bool:
    if isinstance(exc, anthropic.RateLimitError | anthropic.InternalServerError):
        return True
    return isinstance(exc, anthropic.APIStatusError) and exc.status_code == 529


def _retry_after_seconds(exc: BaseException) -> float | None:
    if not isinstance(exc, anthropic.APIStatusError):
        return None
    response = getattr(exc, "response", None)
    header = response.headers.get("retry-after") if response is not None else None
    if header is None:
        return None
    try:
        return float(header)
    except ValueError:
        return None


def _wait_strategy(retry_state: RetryCallState) -> float:
    exc = retry_state.outcome.exception() if retry_state.outcome else None
    if exc is not None:
        retry_after = _retry_after_seconds(exc)
        if retry_after is not None:
            return retry_after
    return wait_random_exponential(multiplier=1, max=30)(retry_state)


def invoke_with_retry(runnable: Any, input_: Any) -> Any:
    """Invoke a LangChain runnable, retrying on rate-limit/5xx/overloaded errors."""

    @retry(
        retry=retry_if_exception(_is_retryable),
        stop=stop_after_attempt(MAX_RETRY_ATTEMPTS),
        wait=_wait_strategy,
        reraise=True,
    )
    def _call() -> Any:
        return runnable.invoke(input_)

    return _call()


def get_rate_limiter(config: LLMConfig) -> Any:
    from langchain_core.rate_limiters import InMemoryRateLimiter

    return InMemoryRateLimiter(
        requests_per_second=config.requests_per_minute / 60.0,
        max_bucket_size=max(config.max_concurrency, 1),
    )


def get_concurrency_semaphore(config: LLMConfig) -> asyncio.Semaphore:
    return asyncio.Semaphore(config.max_concurrency)


def get_triage_model(config: LLMConfig, *, api_key: str | None = None) -> ChatAnthropic:
    from langchain_anthropic import ChatAnthropic

    # `model`/`max_tokens` are accepted at runtime (verified against the
    # installed 1.7.4 wheel — ChatAnthropic's fields are named `model` and
    # `max_tokens` with aliases `model_name`/`max_tokens_to_sample`, and
    # populate-by-name is enabled), but mypy statically type-checks pydantic
    # constructors by alias only without the pydantic mypy plugin (not
    # installed here), hence the ignores.
    #
    # api_key defaults to None, which lets ChatAnthropic fall back to the
    # ANTHROPIC_API_KEY env var -- but nothing in infra/ ever sets that env
    # var, and no caller fetched this from SSM either (unlike
    # slack_bot_token/github_token, which both already follow this
    # fetch-at-runtime pattern). Found live: aggregate's call to this same
    # factory failed with "Anthropic authentication failed: no API key or
    # authorization credentials were provided" on the first execution to
    # ever reach it (see README.md (Troubleshooting)) -- callers must now
    # pass api_key explicitly.
    return ChatAnthropic(  # type: ignore[call-arg]
        model=config.triage_model,
        api_key=api_key,  # type: ignore[arg-type]
        max_tokens=TRIAGE_MAX_TOKENS,
        timeout=REQUEST_TIMEOUT_SECONDS,
        max_retries=0,
        rate_limiter=get_rate_limiter(config),
    )


def get_reasoning_model(config: LLMConfig, *, api_key: str | None = None) -> ChatAnthropic:
    from langchain_anthropic import ChatAnthropic

    return ChatAnthropic(  # type: ignore[call-arg]
        model=config.reasoning_model,
        api_key=api_key,  # type: ignore[arg-type]
        max_tokens=REASONING_MAX_TOKENS,
        timeout=REQUEST_TIMEOUT_SECONDS,
        max_retries=0,
        rate_limiter=get_rate_limiter(config),
    )


__all__ = [
    "MAX_RETRY_ATTEMPTS",
    "REASONING_MAX_TOKENS",
    "REQUEST_TIMEOUT_SECONDS",
    "TRIAGE_MAX_TOKENS",
    "get_concurrency_semaphore",
    "get_rate_limiter",
    "get_reasoning_model",
    "get_triage_model",
    "invoke_with_retry",
]
