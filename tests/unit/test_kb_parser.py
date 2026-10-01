from __future__ import annotations

from pathlib import Path

import pytest

from cloudops_orchestrator.kb.parser import (
    SOPParseError,
    parse_action_spec,
    parse_sop_text,
    validate_knowledge_base,
)

VALID_SOP = """\
---
sop_id: TEST-001
title: Test SOP
domain: security
version: 1.0.0
owner: test@example.com
effective_date: 2026-01-01
review_cycle_days: 180
applies_to: [dev]
references: []
---

## Purpose

This is the overview text, describing purpose and scope.

## Policy Clauses

### TEST-001-1.1 — First clause

```clause-meta
controls: [EC2.13]
prowler_checks: [some_check]
severity: high
default_action: manual_ticket
iac_managed_action: terraform_pr
risk_tier: {non_prod: T1, prod: T2}
references: []
```

This is the prose for clause 1.1, describing the rule in detail.

### TEST-001-1.2 — Second clause

```clause-meta
controls: []
prowler_checks: []
severity: null
default_action: null
iac_managed_action: null
risk_tier: {}
references: [TEST-001-1.1]
```

This is the prose for clause 1.2.

## Procedures

1. Do the thing.

## Exceptions

None.
"""


def test_parse_valid_sop() -> None:
    doc = parse_sop_text(VALID_SOP, source_path="test.md")
    assert doc.front_matter.sop_id == "TEST-001"
    assert len(doc.clauses) == 2
    assert doc.clauses[0].clause_id == "TEST-001-1.1"
    assert doc.clauses[0].meta.severity is not None
    assert doc.clauses[0].meta.severity.value == "high"
    assert "This is the overview text" in doc.overview_text
    assert "### TEST-001-1.1" not in doc.overview_text


def test_clause_body_stops_before_next_top_level_heading() -> None:
    doc = parse_sop_text(VALID_SOP, source_path="test.md")
    second_clause_body = doc.clauses[1].body
    assert "Procedures" not in second_clause_body
    assert "Do the thing" not in second_clause_body


def test_clause_meta_missing_raises() -> None:
    bad = VALID_SOP.replace("```clause-meta", "not-a-fence", 1)
    with pytest.raises(SOPParseError, match="no fenced"):
        parse_sop_text(bad, source_path="bad.md")


def test_missing_front_matter_raises() -> None:
    with pytest.raises(SOPParseError, match="missing YAML front matter"):
        parse_sop_text("# just a heading, no front matter", source_path="bad.md")


def test_invalid_action_spec_rejected() -> None:
    bad = VALID_SOP.replace("default_action: manual_ticket", "default_action: not_a_real_action")
    with pytest.raises(SOPParseError, match="Unknown action_type"):
        parse_sop_text(bad, source_path="bad.md")


def test_invalid_risk_tier_key_rejected() -> None:
    bad = VALID_SOP.replace("{non_prod: T1, prod: T2}", "{staging: T1}")
    with pytest.raises(SOPParseError, match="risk_tier key"):
        parse_sop_text(bad, source_path="bad.md")


def test_invalid_risk_tier_value_rejected() -> None:
    bad = VALID_SOP.replace("{non_prod: T1, prod: T2}", "{non_prod: T9}")
    with pytest.raises(SOPParseError, match="risk_tier value"):
        parse_sop_text(bad, source_path="bad.md")


def test_parse_action_spec_splits_document() -> None:
    assert parse_action_spec("ssm_automation:CloudOps-ApplyTags") == (
        "ssm_automation",
        "CloudOps-ApplyTags",
    )
    assert parse_action_spec("manual_ticket") == ("manual_ticket", None)


class TestRealKnowledgeBase:
    def test_validate_real_kb_has_no_errors(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        errors = validate_knowledge_base(repo_root / "knowledge_base")
        assert errors == []
