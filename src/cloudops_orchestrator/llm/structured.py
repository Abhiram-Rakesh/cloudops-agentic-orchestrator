"""Structured LLM calls against the Anthropic chat model.

Every call: renders already-masked prompt text through
``with_structured_output`` (one repair retry on schema-validation failure,
appending the error to the user turn), records token usage against a
``BudgetTracker``, and unmasks any identifier the model echoed back into a
free-text field before the caller persists the result.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from cloudops_orchestrator.llm.budget import BudgetTracker
from cloudops_orchestrator.llm.factory import invoke_with_retry
from cloudops_orchestrator.normalize.masking import Masker

MAX_STRUCTURED_ATTEMPTS = 2  # one initial call + one repair retry


class StructuredOutputError(Exception):
    pass


def _unmask_value(value: Any, masker: Masker) -> Any:
    if isinstance(value, str):
        return masker.unmask(value)
    if isinstance(value, dict):
        return {key: _unmask_value(v, masker) for key, v in value.items()}
    if isinstance(value, list):
        return [_unmask_value(v, masker) for v in value]
    return value


def unmask_model[T: BaseModel](model: T, masker: Masker) -> T:
    data = model.model_dump(mode="json")
    unmasked = _unmask_value(data, masker)
    return type(model).model_validate(unmasked)


def _record_usage(raw_message: Any, *, budget: BudgetTracker | None, model_name: str) -> None:
    if budget is None or raw_message is None:
        return
    usage = getattr(raw_message, "usage_metadata", None)
    if not usage:
        return
    input_details = usage.get("input_token_details") or {}
    budget.record(
        model_name=model_name,
        input_tokens=usage.get("input_tokens", 0),
        output_tokens=usage.get("output_tokens", 0),
        cache_read_tokens=input_details.get("cache_read", 0),
        cache_creation_tokens=input_details.get("cache_creation", 0),
    )


def call_structured[T: BaseModel](
    model: Any,
    *,
    schema: type[T],
    system_prompt: str,
    user_prompt: str,
    node: str,
    group_id: str,
    model_name: str,
    budget: BudgetTracker | None = None,
    masker: Masker | None = None,
) -> T:
    from langchain_core.messages import HumanMessage, SystemMessage

    system_message = SystemMessage(
        content=[{"type": "text", "text": system_prompt, "cache_control": {"type": "ephemeral"}}]
    )
    structured_model = model.with_structured_output(schema, include_raw=True)

    last_error: Any = None
    for attempt in range(MAX_STRUCTURED_ATTEMPTS):
        extra = (
            ""
            if attempt == 0
            else (
                f"\n\nYour previous response failed schema validation: {last_error}. "
                "Return ONLY a JSON object matching the required schema exactly."
            )
        )
        messages = [system_message, HumanMessage(content=user_prompt + extra)]
        result = invoke_with_retry(structured_model, messages)
        _record_usage(result.get("raw"), budget=budget, model_name=model_name)

        parsed: T | None = result.get("parsed")
        if parsed is not None:
            return unmask_model(parsed, masker) if masker is not None else parsed
        last_error = result.get("parsing_error")

    msg = f"Structured output failed after {MAX_STRUCTURED_ATTEMPTS} attempts for node={node!r} group_id={group_id!r}: {last_error}"
    raise StructuredOutputError(msg)


__all__ = ["MAX_STRUCTURED_ATTEMPTS", "StructuredOutputError", "call_structured", "unmask_model"]
