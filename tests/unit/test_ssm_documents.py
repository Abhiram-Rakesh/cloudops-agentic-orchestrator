"""Structural validation of ssm_documents/*.yaml: schemaVersion,
every branch's NextStep/Default resolves to a real step, every document
named in config/policy/action_allowlist.yaml exists with a matching
parameter set, and the protection-tag check runs before any mutating step.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from cloudops_orchestrator.policy.config import load_action_allowlist

SSM_DOCUMENTS_DIR = Path(__file__).resolve().parents[2] / "ssm_documents"


def _load_all() -> dict[str, dict[str, Any]]:
    return {
        path.stem: yaml.safe_load(path.read_text(encoding="utf-8"))
        for path in sorted(SSM_DOCUMENTS_DIR.glob("*.yaml"))
    }


DOCUMENTS = _load_all()


def test_every_allowlisted_document_exists_on_disk() -> None:
    allowlist = load_action_allowlist()
    for document_name in allowlist.ssm_automation:
        assert document_name in DOCUMENTS, (
            f"{document_name} is in action_allowlist.yaml but missing"
        )


def test_every_document_on_disk_is_allowlisted() -> None:
    allowlist = load_action_allowlist()
    for document_name in DOCUMENTS:
        assert document_name in allowlist.ssm_automation, (
            f"{document_name} is not in action_allowlist.yaml"
        )


@pytest.mark.parametrize("name", sorted(DOCUMENTS))
def test_document_parameters_match_allowlist(name: str) -> None:
    allowlist = load_action_allowlist()
    spec = allowlist.ssm_automation[name]
    doc = DOCUMENTS[name]
    doc_params = set(doc["parameters"]) - {"AutomationAssumeRole"}
    # action_allowlist uses lower_snake_case (e.g. bucket_name); SSM
    # documents use UpperCamelCase (BucketName) by convention.
    expected = {
        "".join(part.title() for part in key.split("_")) for key in spec.parameters.required
    }
    assert expected <= doc_params, (name, expected, doc_params)


@pytest.mark.parametrize("name", sorted(DOCUMENTS))
def test_schema_version_is_0_3(name: str) -> None:
    assert DOCUMENTS[name]["schemaVersion"] == "0.3"


@pytest.mark.parametrize("name", sorted(DOCUMENTS))
def test_assumes_role_and_declares_it_as_a_parameter(name: str) -> None:
    doc = DOCUMENTS[name]
    assert doc["assumeRole"] == "{{ AutomationAssumeRole }}"
    assert "AutomationAssumeRole" in doc["parameters"]


@pytest.mark.parametrize("name", sorted(DOCUMENTS))
def test_branch_targets_resolve_to_real_steps(name: str) -> None:
    doc = DOCUMENTS[name]
    step_names = {step["name"] for step in doc["mainSteps"]}
    for step in doc["mainSteps"]:
        if step["action"] != "aws:branch":
            continue
        for choice in step["inputs"]["Choices"]:
            assert choice["NextStep"] in step_names
        assert step["inputs"]["Default"] in step_names


@pytest.mark.parametrize("name", sorted(DOCUMENTS))
def test_first_step_checks_the_protected_tag(name: str) -> None:
    first_step = DOCUMENTS[name]["mainSteps"][0]
    assert first_step["name"] == "CheckProtectedTag"
    assert "cloudops:protected" in first_step["inputs"]["Script"]


@pytest.mark.parametrize("name", sorted(DOCUMENTS))
def test_has_a_terminal_step(name: str) -> None:
    """Every document ends somewhere — at least one step sets isEnd: true."""
    assert any(step.get("isEnd") for step in DOCUMENTS[name]["mainSteps"])
