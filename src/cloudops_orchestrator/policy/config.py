"""Typed loaders for config/policy/*.yaml."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict


# See the identical helper + comment in collectors/prowler.py: a fixed
# parents[N] index can't resolve correctly both locally (config/ is 3
# parents up, under src/) and in the Lambda zip (config/ is a direct
# sibling of the flattened package, only 2 parents up) at the same time.
def _find_repo_root(file: Path) -> Path:
    for candidate in file.resolve().parents:
        if (candidate / "config").is_dir():
            return candidate
    msg = f"no 'config' directory found above {file}"
    raise FileNotFoundError(msg)


REPO_ROOT = _find_repo_root(Path(__file__))
DEFAULT_RISK_TIERS_PATH = REPO_ROOT / "config" / "policy" / "risk_tiers.yaml"
DEFAULT_ACTION_ALLOWLIST_PATH = REPO_ROOT / "config" / "policy" / "action_allowlist.yaml"
DEFAULT_PROTECTED_RESOURCES_PATH = REPO_ROOT / "config" / "policy" / "protected_resources.yaml"


class ChangeWindow(BaseModel):
    model_config = ConfigDict(frozen=True)

    days: list[str]
    start: str
    end: str
    tz: str


class TierDef(BaseModel):
    model_config = ConfigDict(frozen=True)

    approvals: int | None
    automatable: bool
    description: str
    change_window: ChangeWindow | None = None


class TierRule(BaseModel):
    model_config = ConfigDict(frozen=True)

    match: dict[str, list[str]]
    min_tier: str | None = None
    tier: str | None = None
    automatable: bool | None = None


class RiskTiersConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    tiers: dict[str, TierDef]
    rules: list[TierRule]


class ParameterSchema(BaseModel):
    model_config = ConfigDict(frozen=True)

    required: list[str] = []
    properties: dict[str, dict[str, Any]] = {}


class SsmDocumentSpec(BaseModel):
    model_config = ConfigDict(frozen=True)

    description: str
    default_tier: dict[str, str]
    identifying_parameter: str
    parameters: ParameterSchema


class ActionSpec(BaseModel):
    model_config = ConfigDict(frozen=True)

    description: str
    parameters: ParameterSchema


class ActionAllowlistConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    ssm_automation: dict[str, SsmDocumentSpec]
    terraform_pr: ActionSpec
    terraform_revert_dispatch: ActionSpec
    manual_ticket: ActionSpec
    notify_owner: ActionSpec


class ProtectedTagRule(BaseModel):
    model_config = ConfigDict(frozen=True)

    key: str
    value: str


class ProtectedResourcesConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    tags: list[ProtectedTagRule]
    resource_ids: list[str] = []


def load_risk_tiers(path: Path = DEFAULT_RISK_TIERS_PATH) -> RiskTiersConfig:
    return RiskTiersConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def load_action_allowlist(path: Path = DEFAULT_ACTION_ALLOWLIST_PATH) -> ActionAllowlistConfig:
    return ActionAllowlistConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def load_protected_resources(
    path: Path = DEFAULT_PROTECTED_RESOURCES_PATH,
) -> ProtectedResourcesConfig:
    return ProtectedResourcesConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


__all__ = [
    "ActionAllowlistConfig",
    "ActionSpec",
    "ChangeWindow",
    "ParameterSchema",
    "ProtectedResourcesConfig",
    "ProtectedTagRule",
    "RiskTiersConfig",
    "SsmDocumentSpec",
    "TierDef",
    "TierRule",
    "load_action_allowlist",
    "load_protected_resources",
    "load_risk_tiers",
]
