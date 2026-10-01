"""Typed settings loader.

Config lives in YAML (`config/settings.dev.yaml`, `config/settings.local.yaml`)
with `${VAR}` placeholders interpolated from the process environment (or an
explicit mapping, for tests). This module turns that YAML into a validated
`Settings` tree — nothing downstream reads raw dicts.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

_VAR_PATTERN = re.compile(r"\$\{([A-Z][A-Z0-9_]*)\}")


class ConfigError(Exception):
    """Raised for missing env interpolation values or invalid config."""


class AccountConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    reader_role_arn: str
    executor_role_arn: str


class AwsConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    region: str
    accounts: list[AccountConfig]


class StorageConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    bucket: str
    state_table: str
    checkpoint_table: str
    parameter_prefix: str


class OrchestrationConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    max_groups_per_batch: int = 12


class ModelPrice(BaseModel):
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    input_per_mtok: float = Field(alias="in")
    output_per_mtok: float = Field(alias="out")


class LLMConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    provider: Literal["anthropic"] = "anthropic"
    triage_model: str
    reasoning_model: str
    max_cost_usd_per_run: float = 2.0
    max_cost_usd_per_month: float = 15.0
    requests_per_minute: int = 30
    max_concurrency: int = 3
    masking: bool = True
    response_cache: bool = True
    prices_per_mtok: dict[str, ModelPrice] = Field(default_factory=dict)


class KBConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    index_uri: str
    query_embeddings: Literal["titan", "none"] = "none"
    embedding_model_id: str = "amazon.titan-embed-text-v2:0"
    embedding_dimensions: int = 1024
    top_k: int = 5
    min_score: float = 0.3


class CheckpointConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    backend: Literal["dynamodb", "sqlite", "memory"] = "dynamodb"


class SecurityHubCollectorConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    enabled: bool = True
    min_severity: str = "LOW"


class ProwlerCollectorConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    enabled: bool = True
    prefix: str = "prowler/latest/"
    max_age_days: int = 8


class AccessAnalyzerCollectorConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    enabled: bool = True


class CostAnomalyCollectorConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    enabled: bool = True
    lookback_days: int = 14


class CostExplorerCollectorConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    enabled: bool = True
    max_calls: int = 2


class CostWasteCollectorConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    enabled: bool = True
    idle_cpu_threshold_pct: float = 5.0
    lookback_days: int = 7
    min_datapoint_hours: int = 1
    required_tags: list[str] = Field(default_factory=list)


class DriftWorkspaceConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    path: str
    state_key: str


class DriftCollectorConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    enabled: bool = True
    prefix: str = "drift/latest/"
    max_age_days: int = 8
    workspaces: list[DriftWorkspaceConfig] = Field(default_factory=list)
    unmanaged_selector: dict[str, dict[str, str]] = Field(default_factory=dict)


class CloudtrailCollectorConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    lookback_days: int = 8
    # Wall-clock cap on the LookupEvents pagination so this collector can never
    # run the collect Lambda into its 900s timeout; hitting it yields a warning.
    max_seconds: int = 240


class CollectorsConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    security_hub: SecurityHubCollectorConfig = Field(default_factory=SecurityHubCollectorConfig)
    prowler: ProwlerCollectorConfig = Field(default_factory=ProwlerCollectorConfig)
    access_analyzer: AccessAnalyzerCollectorConfig = Field(
        default_factory=AccessAnalyzerCollectorConfig
    )
    cost_anomaly: CostAnomalyCollectorConfig = Field(default_factory=CostAnomalyCollectorConfig)
    cost_explorer: CostExplorerCollectorConfig = Field(default_factory=CostExplorerCollectorConfig)
    cost_waste: CostWasteCollectorConfig = Field(default_factory=CostWasteCollectorConfig)
    drift: DriftCollectorConfig = Field(default_factory=DriftCollectorConfig)
    cloudtrail: CloudtrailCollectorConfig = Field(default_factory=CloudtrailCollectorConfig)


class RefreshConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    prowler_workflow: str = "prowler.yml"
    drift_workflow: str = "drift.yml"
    max_wait_minutes: int = 30


class TerraformPRConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    enabled: bool = True
    allowed_paths: list[str] = Field(default_factory=lambda: ["demo/infra/**"])


class TerraformRevertDispatchConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    enabled: bool = True
    workflow_file: str = "demo-apply.yml"


class RunbookExecutorConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    enabled: bool = False
    dry_run: bool = True


class RemediationConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    terraform_pr: TerraformPRConfig = Field(default_factory=TerraformPRConfig)
    terraform_revert_dispatch: TerraformRevertDispatchConfig = Field(
        default_factory=TerraformRevertDispatchConfig
    )
    runbook_executor: RunbookExecutorConfig = Field(default_factory=RunbookExecutorConfig)


class ApprovalsConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    slack_channel_id: str
    approvers: list[str] = Field(default_factory=list)
    expiry_days: int = 7


class GithubConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    auth_mode: Literal["pat", "app"] = "pat"
    owner: str
    repo: str


class ReportConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    presign_days: int = 7
    timezone: str = "Asia/Kolkata"


class LangsmithConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    project: str
    endpoint: str = "https://api.smith.langchain.com"
    anonymize: bool = True


class Settings(BaseModel):
    """Top-level validated configuration tree."""

    model_config = ConfigDict(frozen=True)

    environment: str
    aws: AwsConfig
    storage: StorageConfig
    orchestration: OrchestrationConfig
    llm: LLMConfig
    kb: KBConfig
    checkpoint: CheckpointConfig
    collectors: CollectorsConfig
    refresh: RefreshConfig
    remediation: RemediationConfig
    approvals: ApprovalsConfig
    github: GithubConfig
    report: ReportConfig
    langsmith: LangsmithConfig


def _interpolate(text: str, env: Mapping[str, str]) -> str:
    missing: set[str] = set()

    def repl(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in env:
            missing.add(name)
            return match.group(0)
        return env[name]

    result = _VAR_PATTERN.sub(repl, text)
    if missing:
        names = ", ".join(sorted(missing))
        msg = f"Missing required environment variables for config interpolation: {names}"
        raise ConfigError(msg)
    return result


def load_settings(path: str | Path, *, env: Mapping[str, str] | None = None) -> Settings:
    """Load and validate a settings YAML file, interpolating ``${VAR}`` placeholders."""
    import os

    resolved_env: Mapping[str, str] = env if env is not None else os.environ
    raw_text = Path(path).read_text(encoding="utf-8")
    interpolated = _interpolate(raw_text, resolved_env)
    data = yaml.safe_load(interpolated)
    return Settings.model_validate(data)
