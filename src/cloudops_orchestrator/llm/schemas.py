"""Small structured-output schemas that don't belong with the core domain
models in ``models/`` (they're LLM-call contracts, not persisted entities)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class ExecutiveSummaryOutput(BaseModel):
    model_config = ConfigDict(frozen=True)

    executive_summary: str


class JudgeScore(BaseModel):
    """The ``judge_quality`` eval metric: a Haiku rubric score for one
    triage/recommendation's overall quality, 1 (poor) to 5 (excellent)."""

    model_config = ConfigDict(frozen=True)

    score: int
    rationale: str


__all__ = ["ExecutiveSummaryOutput", "JudgeScore"]
