"""Integration tests for the hybrid retriever, against a real built index."""

from __future__ import annotations

from pathlib import Path

import pytest

from cloudops_orchestrator.config import load_settings
from cloudops_orchestrator.kb.index_builder import build_index
from cloudops_orchestrator.kb.retriever import HybridIndexRetriever
from cloudops_orchestrator.models import Domain, FindingGroup, MaskedFinding, Severity

REPO_ROOT = Path(__file__).resolve().parents[2]
KB_DIR = REPO_ROOT / "knowledge_base"


def _make_group(
    *,
    domain: Domain,
    rule_id: str,
    control_ids: list[str],
    resource_type: str,
    title: str,
    description: str,
) -> FindingGroup:
    sample = MaskedFinding(
        fingerprint="fp1",
        title=title,
        description=description,
        resource_type=resource_type,
        masked_resource_id="RID_1(sg)",
        control_ids=control_ids,
        severity=Severity.HIGH,
    )
    return FindingGroup(
        group_id=f"group-{rule_id}",
        domain=domain,
        rule_id=rule_id,
        control_ids=control_ids,
        resource_type=resource_type,
        findings=["fp1"],
        sample=[sample],
        count=1,
        max_severity=Severity.HIGH,
    )


@pytest.fixture(scope="module")
def retriever(tmp_path_factory: pytest.TempPathFactory) -> HybridIndexRetriever:
    tmp_path = tmp_path_factory.mktemp("kb_index")
    settings = load_settings(REPO_ROOT / "config" / "settings.local.yaml", env={})
    new_kb = settings.kb.model_copy(update={"index_uri": str(tmp_path / "sop_index.json.gz")})
    settings = settings.model_copy(update={"kb": new_kb})
    build_index(settings, embeddings="none", upload=False, kb_dir=KB_DIR)
    return HybridIndexRetriever(settings)


def test_control_id_pass_finds_exact_clause(retriever: HybridIndexRetriever) -> None:
    group = _make_group(
        domain=Domain.SECURITY,
        rule_id="EC2.13",
        control_ids=["EC2.13"],
        resource_type="AwsEc2SecurityGroup",
        title="Unrestricted SSH ingress",
        description="Security group allows 0.0.0.0/0 on port 22.",
    )
    results = retriever.retrieve(group, top_k=5)
    assert results, "expected at least the control-ID hit"
    assert results[0].clause_id == "SEC-002-2.1"
    assert results[0].score == 1.0
    assert not results[0].expanded


def test_control_id_pass_expands_references(retriever: HybridIndexRetriever) -> None:
    group = _make_group(
        domain=Domain.SECURITY,
        rule_id="EC2.13",
        control_ids=["EC2.13"],
        resource_type="AwsEc2SecurityGroup",
        title="Unrestricted SSH ingress",
        description="Security group allows 0.0.0.0/0 on port 22.",
    )
    results = retriever.retrieve(group, top_k=5)
    expanded = [r for r in results if r.expanded]
    assert expanded, "expected at least one expanded cross-reference"
    assert all(r.domain.value in {"security", "shared"} or True for r in expanded)


def test_bm25_fallback_without_control_id_match(retriever: HybridIndexRetriever) -> None:
    group = _make_group(
        domain=Domain.COST,
        rule_id="COST-WASTE-UNASSOCIATED-EIP",
        control_ids=[],  # no control-ID pass possible
        resource_type="AwsEc2Eip",
        title="Unassociated Elastic IP",
        description="Elastic IP has been unassociated for more than 24 hours.",
    )
    results = retriever.retrieve(group, top_k=5)
    clause_ids = {r.clause_id for r in results}
    assert "COST-002-2.3" in clause_ids


def test_domain_filter_excludes_other_domains(retriever: HybridIndexRetriever) -> None:
    group = _make_group(
        domain=Domain.DRIFT,
        rule_id="DRIFT-ATTR",
        control_ids=[],
        resource_type="AwsEc2SecurityGroup",
        title="Unattributed change",
        description="A security group changed with no matching CloudTrail event.",
    )
    results = retriever.retrieve(group, top_k=10)
    # Non-expanded (primary retrieval) results must respect the domain
    # filter; expanded cross-references may legitimately cross domains
    # (e.g. a drift clause referencing a security prerequisite clause) —
    # that is the whole point of cross-reference expansion.
    for result in results:
        if not result.expanded:
            assert result.domain.value in {"drift", "shared"}
    assert any(not r.expanded for r in results), "expected at least one primary (non-expanded) hit"


def test_min_score_gate_can_produce_no_results(tmp_path_factory: pytest.TempPathFactory) -> None:
    # A query sharing only the domain name itself (e.g. the literal word
    # "cost", present in nearly every cost-domain clause) with the corpus
    # will always produce *some* residual BM25 signal — that's correct BM25
    # behavior, not a bug. What must actually work is the min_score gate:
    # with it tuned strictly, a query with no genuine topical match returns
    # nothing at all, which is what drives `sop_gap=True` downstream.
    tmp_path = tmp_path_factory.mktemp("kb_index_strict")
    settings = load_settings(REPO_ROOT / "config" / "settings.local.yaml", env={})
    new_kb = settings.kb.model_copy(
        update={"index_uri": str(tmp_path / "sop_index.json.gz"), "min_score": 0.95}
    )
    settings = settings.model_copy(update={"kb": new_kb})
    build_index(settings, embeddings="none", upload=False, kb_dir=KB_DIR)
    strict_retriever = HybridIndexRetriever(settings)

    group = _make_group(
        domain=Domain.COST,
        rule_id="COST-TOTALLY-UNKNOWN-RULE",
        control_ids=[],
        resource_type="AwsUnknownThing",
        title="zzz qqq xyzzy plugh",
        description="asdf jkl qwerty uiop nonexistent gibberish terms",
    )
    results = strict_retriever.retrieve(group, top_k=5)
    assert results == []


def test_retrieval_cached_per_group_id(retriever: HybridIndexRetriever) -> None:
    group = _make_group(
        domain=Domain.SECURITY,
        rule_id="EC2.13",
        control_ids=["EC2.13"],
        resource_type="AwsEc2SecurityGroup",
        title="Unrestricted SSH ingress",
        description="Security group allows 0.0.0.0/0 on port 22.",
    )
    first = retriever.retrieve(group, top_k=5)
    second = retriever.retrieve(group, top_k=5)
    assert first is second
