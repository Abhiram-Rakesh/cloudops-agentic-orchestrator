from __future__ import annotations

from cloudops_orchestrator.kb.bm25 import BM25Index, tokenize


def test_tokenize_keeps_control_ids_intact() -> None:
    tokens = tokenize("No ingress from 0.0.0.0/0 to EC2.13 per SEC-002-2.1 and CIS-5.2")
    assert "ec2.13" in tokens
    assert "sec-002-2.1" in tokens
    assert "cis-5.2" in tokens
    # split on '/' is fine — CIDR notation isn't a single meaningful token anyway
    assert "0.0.0.0" in tokens


def test_search_ranks_relevant_document_first() -> None:
    documents = {
        "sec-002-2.1": "No unrestricted administrative ingress. EC2.13 SSH port 22 from 0.0.0.0/0.",
        "cost-001-1.1": "Required tags owner cost-center environment application.",
        "unrelated": "The quick brown fox jumps over the lazy dog.",
    }
    index = BM25Index.build(documents)
    results = index.search("EC2.13 SSH ingress 22", top_k=3)
    assert results[0][0] == "sec-002-2.1"
    assert results[0][1] > 0


def test_search_restricted_to_keys_subset() -> None:
    documents = {
        "a": "security group ingress rule",
        "b": "cost tagging rule",
    }
    index = BM25Index.build(documents)
    results = index.search("security ingress", keys=["b"], top_k=5)
    assert results == []


def test_no_match_returns_empty() -> None:
    index = BM25Index.build({"a": "completely unrelated content about widgets"})
    assert index.search("nonexistent query terms xyzzy") == []


def test_to_dict_from_dict_round_trip() -> None:
    index = BM25Index.build({"a": "security group ingress rule EC2.13"})
    restored = BM25Index.from_dict(index.to_dict())
    assert restored.search("EC2.13") == index.search("EC2.13")


def test_empty_index() -> None:
    index = BM25Index.build({})
    assert index.n_docs == 0
    assert index.search("anything") == []
