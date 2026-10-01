from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cloudops_orchestrator.models.enums import ActionType, RiskTier
from cloudops_orchestrator.policy.plan_hash import (
    build_action_plan,
    compute_plan_hash,
    verify_plan_hash,
)


def _kwargs(**overrides: object) -> dict[str, object]:
    defaults: dict[str, object] = {
        "action_id": "action-1",
        "recommendation_id": "rec-1",
        "action_type": "ssm_automation",
        "parameters": {"document": "CloudOps-RevokeSGIngressWorld"},
        "targets": ["sg-1"],
        "effective_risk_tier": "T1",
        "required_approvals": 1,
        "expires_at": datetime(2026, 2, 1, tzinfo=UTC),
    }
    defaults.update(overrides)
    return defaults


def test_hash_is_deterministic() -> None:
    assert compute_plan_hash(**_kwargs()) == compute_plan_hash(**_kwargs())  # type: ignore[arg-type]


def test_hash_changes_with_any_field() -> None:
    base = compute_plan_hash(**_kwargs())  # type: ignore[arg-type]
    assert compute_plan_hash(**_kwargs(targets=["sg-2"])) != base  # type: ignore[arg-type]
    assert compute_plan_hash(**_kwargs(required_approvals=2)) != base  # type: ignore[arg-type]
    assert compute_plan_hash(**_kwargs(effective_risk_tier="T2")) != base  # type: ignore[arg-type]


def test_hash_independent_of_dict_key_order() -> None:
    a = compute_plan_hash(**_kwargs(parameters={"a": 1, "b": 2}))  # type: ignore[arg-type]
    b = compute_plan_hash(**_kwargs(parameters={"b": 2, "a": 1}))  # type: ignore[arg-type]
    assert a == b


def test_hash_normalizes_timezone() -> None:
    ist = _kwargs(expires_at=datetime(2026, 2, 1, 5, 30, tzinfo=UTC) + timedelta(hours=0))
    utc = _kwargs(expires_at=datetime(2026, 2, 1, 5, 30, tzinfo=UTC))
    assert compute_plan_hash(**ist) == compute_plan_hash(**utc)  # type: ignore[arg-type]


def test_build_action_plan_hash_matches_compute() -> None:
    plan = build_action_plan(
        action_id="action-1",
        recommendation_id="rec-1",
        action_type=ActionType.SSM_AUTOMATION,
        parameters={"document": "CloudOps-RevokeSGIngressWorld"},
        targets=["sg-1"],
        effective_risk_tier=RiskTier.T1,
        required_approvals=1,
        expires_at=datetime(2026, 2, 1, tzinfo=UTC),
    )
    assert plan.plan_hash == compute_plan_hash(**_kwargs())  # type: ignore[arg-type]


def test_verify_plan_hash_true_for_untampered_plan() -> None:
    plan = build_action_plan(
        action_id="action-1",
        recommendation_id="rec-1",
        action_type=ActionType.MANUAL_TICKET,
        parameters={},
        targets=["r-1"],
        effective_risk_tier=RiskTier.T3,
        required_approvals=0,
        expires_at=datetime(2026, 2, 1, tzinfo=UTC),
    )
    assert verify_plan_hash(plan) is True


def test_verify_plan_hash_false_when_tampered() -> None:
    plan = build_action_plan(
        action_id="action-1",
        recommendation_id="rec-1",
        action_type=ActionType.MANUAL_TICKET,
        parameters={},
        targets=["r-1"],
        effective_risk_tier=RiskTier.T3,
        required_approvals=0,
        expires_at=datetime(2026, 2, 1, tzinfo=UTC),
    )
    tampered = plan.model_copy(update={"targets": ["r-1", "r-2"]})
    assert verify_plan_hash(tampered) is False
