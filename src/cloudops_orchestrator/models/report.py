"""Run report models: what `aggregate` writes to S3 and posts to Slack."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from cloudops_orchestrator.models.actions import Recommendation, TriageResult
from cloudops_orchestrator.models.common import UTCDatetime
from cloudops_orchestrator.models.enums import Domain, FindingStatus, Severity


class ModelUsage(BaseModel):
    model_config = ConfigDict(frozen=True)

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0
    cost_usd: float = 0.0


class LLMUsage(BaseModel):
    model_config = ConfigDict(frozen=True)

    per_model: dict[str, ModelUsage] = Field(default_factory=dict)
    total_cost_usd: float = 0.0
    budget_exhausted: bool = False


class ReportItem(BaseModel):
    model_config = ConfigDict(frozen=True)

    group_id: str
    domain: Domain
    title: str
    max_severity: Severity
    count: int
    priority_score: float
    triage: TriageResult | None = None
    recommendation: Recommendation | None = None
    carried_over: bool = False


class RunReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    run_id: str
    started_at: UTCDatetime
    finished_at: UTCDatetime
    counts: dict[Domain, dict[FindingStatus, int]] = Field(default_factory=dict)
    executive_summary: str
    items: list[ReportItem] = Field(default_factory=list)
    resolved: list[str] = Field(default_factory=list)
    suppressed: list[str] = Field(default_factory=list)
    llm_usage: LLMUsage
    report_uri: str | None = None
    json_uri: str | None = None
