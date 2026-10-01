from __future__ import annotations

from pathlib import Path

import pytest

from cloudops_orchestrator.config import ConfigError, load_settings

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_load_local_settings_needs_no_env() -> None:
    settings = load_settings(REPO_ROOT / "config" / "settings.local.yaml", env={})
    assert settings.environment == "local"
    assert settings.llm.provider == "anthropic"
    assert settings.checkpoint.backend == "sqlite"
    assert settings.kb.query_embeddings == "none"


def test_load_dev_settings_interpolates_env() -> None:
    env = {
        "AWS_ACCOUNT_ID": "222222222222",
        "ARTIFACT_BUCKET": "cloudops-lite-222222222222",
        "SLACK_CHANNEL_ID": "C1234567890",
        "APPROVER_SLACK_ID": "U1234567890",
        "GH_OWNER": "octocat",
        "REPO_NAME": "cloudops-agentic-orchestrator-lite",
    }
    settings = load_settings(REPO_ROOT / "config" / "settings.dev.yaml", env=env)
    assert settings.aws.accounts[0].id == "222222222222"
    assert settings.storage.bucket == "cloudops-lite-222222222222"
    assert settings.github.owner == "octocat"
    assert "222222222222" in settings.aws.accounts[0].reader_role_arn


def test_load_dev_settings_missing_env_raises_with_names() -> None:
    with pytest.raises(ConfigError) as exc_info:
        load_settings(REPO_ROOT / "config" / "settings.dev.yaml", env={})
    message = str(exc_info.value)
    assert "AWS_ACCOUNT_ID" in message
    assert "ARTIFACT_BUCKET" in message


def test_llm_price_alias_round_trip() -> None:
    settings = load_settings(REPO_ROOT / "config" / "settings.local.yaml", env={})
    haiku_price = settings.llm.prices_per_mtok["claude-haiku-4-5-20251001"]
    assert haiku_price.input_per_mtok == 1.0
    assert haiku_price.output_per_mtok == 5.0
