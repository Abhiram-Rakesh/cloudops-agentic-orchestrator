from __future__ import annotations

from cloudops_orchestrator.policy.config import (
    load_action_allowlist,
    load_protected_resources,
    load_risk_tiers,
)


def test_load_risk_tiers_has_all_four_tiers() -> None:
    config = load_risk_tiers()
    assert set(config.tiers) == {"T0", "T1", "T2", "T3"}
    assert config.tiers["T3"].approvals is None
    assert config.tiers["T3"].automatable is False
    assert config.tiers["T2"].change_window is not None


def test_load_action_allowlist_has_seven_ssm_documents() -> None:
    config = load_action_allowlist()
    assert len(config.ssm_automation) == 7
    assert "CloudOps-RevokeSGIngressWorld" in config.ssm_automation
    assert config.terraform_pr.parameters.required == [
        "repo",
        "workspace",
        "intent",
        "resource_address",
    ]


def test_load_protected_resources_has_expected_tags() -> None:
    config = load_protected_resources()
    keys_values = {(t.key, t.value) for t in config.tags}
    assert ("cloudops:protected", "true") in keys_values
    assert ("app", "cloudops-agentic-orchestrator") in keys_values
