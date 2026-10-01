from __future__ import annotations

from cloudops_orchestrator.kb.chunker import MAX_CHUNK_TOKENS, chunk_document, chunk_documents
from cloudops_orchestrator.kb.parser import parse_sop_text

SOP_WITH_ONE_CLAUSE = """\
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

Overview prose here.

## Policy Clauses

### TEST-001-1.1 — A clause

```clause-meta
controls: [EC2.13]
prowler_checks: [some_check]
severity: high
default_action: manual_ticket
iac_managed_action: terraform_pr
risk_tier: {non_prod: T1, prod: T2}
references: []
```

Short clause prose.
"""


def test_chunk_document_produces_overview_plus_one_per_clause() -> None:
    doc = parse_sop_text(SOP_WITH_ONE_CLAUSE, source_path="t.md")
    chunks = chunk_document(doc)
    assert len(chunks) == 2
    overview = next(c for c in chunks if c.clause_id is None)
    clause_chunk = next(c for c in chunks if c.clause_id == "TEST-001-1.1")
    assert overview.key == "TEST-001:overview"
    assert clause_chunk.key == "TEST-001-1.1"


def test_contextual_header_present_and_informative() -> None:
    doc = parse_sop_text(SOP_WITH_ONE_CLAUSE, source_path="t.md")
    chunks = chunk_document(doc)
    clause_chunk = next(c for c in chunks if c.clause_id == "TEST-001-1.1")
    header_line = clause_chunk.text.splitlines()[0]
    assert "TEST-001 TEST-001-1.1" in header_line
    assert "EC2.13" in header_line
    assert "some_check" in header_line
    assert "high" in header_line
    assert "Short clause prose." in clause_chunk.text


def test_long_clause_is_split_with_overlap() -> None:
    # Build a clause body long enough to exceed MAX_CHUNK_TOKENS, as separate
    # paragraphs so the paragraph-boundary splitter has something to split on.
    long_body = "\n\n".join(f"Paragraph {i} " + ("word " * 50) for i in range(80))
    sop_text = SOP_WITH_ONE_CLAUSE.replace("Short clause prose.", long_body)
    doc = parse_sop_text(sop_text, source_path="t.md")
    chunks = chunk_document(doc)
    clause_chunks = [
        c for c in chunks if c.clause_id is not None or c.key.startswith("TEST-001-1.1")
    ]
    assert len(clause_chunks) > 1
    assert clause_chunks[0].key == "TEST-001-1.1#p0"
    # Overlap: some trailing words of chunk 0 should reappear at the start of chunk 1's body.
    chunk0_words = clause_chunks[0].text.split()
    chunk1_words = clause_chunks[1].text.split()
    assert any(word in chunk1_words[:120] for word in chunk0_words[-20:])


def test_chunk_documents_aggregates_across_sops() -> None:
    doc = parse_sop_text(SOP_WITH_ONE_CLAUSE, source_path="t.md")
    chunks = chunk_documents([doc, doc])
    assert len(chunks) == 4


def test_max_chunk_tokens_is_1500() -> None:
    assert MAX_CHUNK_TOKENS == 1500
