from __future__ import annotations

import pytest
from jinja2 import UndefinedError

from cloudops_orchestrator.llm.rendering import render_prompt


def test_triage_system_renders_with_domain_and_guidance() -> None:
    rendered = render_prompt(
        "triage_system.md", domain="security", domain_guidance="Weigh exposure carefully."
    )
    assert "security" in rendered
    assert "Weigh exposure carefully." in rendered
    assert "<untrusted_data>" in rendered


def test_missing_variable_raises_strict_undefined_error() -> None:
    with pytest.raises(UndefinedError):
        render_prompt("triage_system.md", domain="security")  # missing domain_guidance


def test_terraform_pr_user_renders_hcl_block() -> None:
    class FakeRecommendation:
        title = "Fix it"
        summary = "Summary"
        rationale = "Rationale"
        citations: tuple[object, ...] = ()

    rendered = render_prompt(
        "terraform_pr_user.md",
        intent="remediate_security",
        resource_address="aws_security_group.web_admin",
        recommendation=FakeRecommendation(),
        file_path="demo/infra/security_groups.tf",
        current_hcl='resource "aws_security_group" "web_admin" {}',
    )
    assert "aws_security_group.web_admin" in rendered
    assert "demo/infra/security_groups.tf" in rendered
