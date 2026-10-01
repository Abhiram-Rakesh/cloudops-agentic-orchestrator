from __future__ import annotations

import pytest

from cloudops_orchestrator.remediation.path_guard import is_path_allowed

ALLOWED = ["demo/infra/**"]


@pytest.mark.parametrize(
    "path",
    [
        "demo/infra/main.tf",
        "demo/infra/modules/sg/main.tf",
        "/demo/infra/main.tf",
    ],
)
def test_allowed_paths(path: str) -> None:
    assert is_path_allowed(path, allowed_paths=ALLOWED)


@pytest.mark.parametrize(
    "path",
    [
        "src/cloudops_orchestrator/cli.py",
        "config/settings.local.yaml",
        ".github/workflows/deploy.yml",
        "infra/modules/lambdas/main.tf",
        "knowledge_base/security/SEC-002.md",
        "statemachine/review.asl.json",
        "demo/infra",  # the directory itself, not a file under it
        "other/path.tf",
    ],
)
def test_denied_paths(path: str) -> None:
    assert not is_path_allowed(path, allowed_paths=ALLOWED)


def test_always_denied_wins_even_if_configured_as_allowed() -> None:
    """A misconfigured allowed_paths including src/** must not override the
    hardcoded deny list."""
    assert not is_path_allowed("src/evil.py", allowed_paths=["src/**", "demo/infra/**"])
