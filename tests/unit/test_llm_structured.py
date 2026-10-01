from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from cloudops_orchestrator.config import load_settings
from cloudops_orchestrator.llm.budget import BudgetTracker
from cloudops_orchestrator.llm.structured import (
    StructuredOutputError,
    call_structured,
    unmask_model,
)
from cloudops_orchestrator.models.actions import TriageResult
from cloudops_orchestrator.models.enums import Severity, TriageVerdict
from cloudops_orchestrator.normalize.masking import Masker

REPO_ROOT = Path(__file__).resolve().parents[2]
SETTINGS = load_settings(REPO_ROOT / "config" / "settings.local.yaml", env={})


class _FakeRawMessage:
    def __init__(self, usage_metadata: dict[str, Any]) -> None:
        self.usage_metadata = usage_metadata


def _usage(input_tokens: int = 100, output_tokens: int = 50) -> dict[str, Any]:
    return {"input_tokens": input_tokens, "output_tokens": output_tokens, "input_token_details": {}}


class _FakeStructuredRunnable:
    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self._responses = list(responses)
        self.invocations: list[Any] = []

    def invoke(self, messages: Any) -> dict[str, Any]:
        self.invocations.append(messages)
        return self._responses.pop(0)


class _FakeModel:
    def __init__(self, structured_runnable: _FakeStructuredRunnable) -> None:
        self._runnable = structured_runnable

    def with_structured_output(
        self, schema: type, include_raw: bool = False, **kwargs: Any
    ) -> _FakeStructuredRunnable:
        return self._runnable


def _triage_result(**overrides: object) -> TriageResult:
    defaults: dict[str, object] = {
        "group_id": "g1",
        "verdict": TriageVerdict.ACTIONABLE,
        "adjusted_severity": Severity.HIGH,
        "rationale": "r",
        "citations": [],
        "sop_gap": False,
    }
    defaults.update(overrides)
    return TriageResult(**defaults)  # type: ignore[arg-type]


def test_success_on_first_attempt_records_budget() -> None:
    runnable = _FakeStructuredRunnable(
        [{"raw": _FakeRawMessage(_usage()), "parsed": _triage_result(), "parsing_error": None}]
    )
    budget = BudgetTracker(config=SETTINGS.llm, max_cost_usd_per_run=2.0)
    result = call_structured(
        _FakeModel(runnable),
        schema=TriageResult,
        system_prompt="sys",
        user_prompt="usr",
        node="triage",
        group_id="g1",
        model_name="claude-haiku-4-5-20251001",
        budget=budget,
    )
    assert result.verdict == TriageVerdict.ACTIONABLE
    assert len(runnable.invocations) == 1
    assert budget.total_cost_usd > 0


def test_repair_retry_on_parse_failure_then_success() -> None:
    runnable = _FakeStructuredRunnable(
        [
            {
                "raw": _FakeRawMessage(_usage()),
                "parsed": None,
                "parsing_error": ValueError("bad json"),
            },
            {"raw": _FakeRawMessage(_usage()), "parsed": _triage_result(), "parsing_error": None},
        ]
    )
    result = call_structured(
        _FakeModel(runnable),
        schema=TriageResult,
        system_prompt="sys",
        user_prompt="usr",
        node="triage",
        group_id="g1",
        model_name="claude-haiku-4-5-20251001",
    )
    assert result.verdict == TriageVerdict.ACTIONABLE
    assert len(runnable.invocations) == 2
    # The repair attempt's prompt includes the prior error.
    repair_message = runnable.invocations[1][-1]
    assert "bad json" in repair_message.content


def test_raises_after_exhausting_repair_attempts() -> None:
    runnable = _FakeStructuredRunnable(
        [
            {"raw": None, "parsed": None, "parsing_error": ValueError("bad json 1")},
            {"raw": None, "parsed": None, "parsing_error": ValueError("bad json 2")},
        ]
    )
    with pytest.raises(StructuredOutputError):
        call_structured(
            _FakeModel(runnable),
            schema=TriageResult,
            system_prompt="sys",
            user_prompt="usr",
            node="triage",
            group_id="g1",
            model_name="claude-haiku-4-5-20251001",
        )


def test_masker_unmasks_result_strings() -> None:
    masker = Masker()
    masked_rationale = masker.mask("finding on account 111111111111")
    runnable = _FakeStructuredRunnable(
        [
            {
                "raw": _FakeRawMessage(_usage()),
                "parsed": _triage_result(rationale=masked_rationale),
                "parsing_error": None,
            }
        ]
    )
    result = call_structured(
        _FakeModel(runnable),
        schema=TriageResult,
        system_prompt="sys",
        user_prompt="usr",
        node="triage",
        group_id="g1",
        model_name="claude-haiku-4-5-20251001",
        masker=masker,
    )
    assert result.rationale == "finding on account 111111111111"


def test_unmask_model_leaves_unrelated_fields_alone() -> None:
    masker = Masker()
    triage = _triage_result(rationale="no identifiers here")
    unmasked = unmask_model(triage, masker)
    assert unmasked.rationale == "no identifiers here"
    assert unmasked.verdict == triage.verdict
