"""Domain agent: retrieve_sops -> triage -> [recommend] -> validate_policy,
run once per finding group.

``analyze_group`` is the pure, directly-testable core — no LangGraph
involved. ``build_domain_graph`` wraps it in a LangGraph ``StateGraph`` using
``Send`` to fan out over a batch's groups in parallel (bounded by
``llm.max_concurrency``); no checkpointer is used because a batch is
idempotent — nothing here survives past one Lambda invocation.
"""

from __future__ import annotations

import operator
from collections.abc import Sequence
from dataclasses import dataclass
from hashlib import sha256
from typing import Annotated, Any, TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from cloudops_orchestrator.config import Settings
from cloudops_orchestrator.graph.domains import DOMAIN_SPECS
from cloudops_orchestrator.kb.retriever import SOPRetriever
from cloudops_orchestrator.llm.budget import BudgetTracker
from cloudops_orchestrator.llm.rendering import render_prompt
from cloudops_orchestrator.llm.structured import StructuredOutputError, call_structured
from cloudops_orchestrator.logging import get_logger
from cloudops_orchestrator.models.actions import Recommendation, TriageResult
from cloudops_orchestrator.models.enums import TriageVerdict
from cloudops_orchestrator.models.findings import Finding, FindingGroup
from cloudops_orchestrator.normalize.masking import Masker
from cloudops_orchestrator.policy.config import (
    ActionAllowlistConfig,
    ProtectedResourcesConfig,
    RiskTiersConfig,
)
from cloudops_orchestrator.policy.engine import evaluate_recommendation

logger = get_logger()


def compute_group_content_hash(group: FindingGroup) -> str:
    """Hash of everything that would change the LLM's answer for this group —
    used by `skip_unchanged` to reuse a prior run's triage/recommendation."""
    raw = "|".join(
        [
            group.domain.value,
            group.rule_id,
            group.resource_type,
            ",".join(sorted(group.control_ids)),
            ",".join(sorted(group.findings)),
            group.max_severity.value,
        ]
    )
    return sha256(raw.encode("utf-8")).hexdigest()[:16]


@dataclass
class GroupAnalysis:
    group: FindingGroup
    triage: TriageResult
    recommendation: Recommendation | None
    carried_over: bool = False
    error: str | None = None


class DomainAgentDeps(TypedDict):
    run_id: str
    settings: Settings
    retriever: SOPRetriever
    triage_model: Any
    reasoning_model: Any
    budget: BudgetTracker
    clause_texts: dict[str, str]
    risk_tiers: RiskTiersConfig
    action_allowlist: ActionAllowlistConfig
    protected_resources: ProtectedResourcesConfig
    findings_by_fingerprint: dict[str, Finding]
    # The SAME masker steps/collect.py used to build every group's masked
    # samples -- required so unmask() can actually reverse a token the LLM
    # echoes back (see normalize/masking.py's class docstring). A fresh,
    # empty Masker() here silently no-ops every unmask() call.
    masker: Masker


def analyze_group(group: FindingGroup, *, deps: DomainAgentDeps) -> GroupAnalysis:
    """Analyze one finding group. Never raises — a failure here becomes a
    NEEDS_HUMAN result so one bad group never fails the whole batch."""
    try:
        return _analyze_group_inner(group, deps=deps)
    except Exception as exc:
        logger.warning("domain_agent.analyze_group.failed", group_id=group.group_id, error=str(exc))
        fallback_triage = TriageResult(
            group_id=group.group_id,
            verdict=TriageVerdict.NEEDS_HUMAN,
            adjusted_severity=group.max_severity,
            rationale=f"Analysis failed for this group: {exc}",
            citations=[],
            sop_gap=True,
        )
        return GroupAnalysis(
            group=group, triage=fallback_triage, recommendation=None, error=str(exc)
        )


def _analyze_group_inner(group: FindingGroup, *, deps: DomainAgentDeps) -> GroupAnalysis:
    settings = deps["settings"]
    domain_spec = DOMAIN_SPECS[group.domain]
    masker = deps["masker"]
    sop_chunks = deps["retriever"].retrieve(group, top_k=settings.kb.top_k)

    triage_system = render_prompt(
        "triage_system.md", domain=group.domain.value, domain_guidance=domain_spec.guidance
    )
    triage_user = render_prompt("triage_user.md", group=group, sop_chunks=sop_chunks)
    triage = call_structured(
        deps["triage_model"],
        schema=TriageResult,
        system_prompt=triage_system,
        user_prompt=triage_user,
        node="triage",
        group_id=group.group_id,
        model_name=settings.llm.triage_model,
        budget=deps["budget"],
        masker=masker,
    )
    triage = triage.model_copy(update={"group_id": group.group_id})
    if not sop_chunks and not triage.sop_gap:
        triage = triage.model_copy(update={"sop_gap": True, "verdict": TriageVerdict.NEEDS_HUMAN})

    if triage.verdict != TriageVerdict.ACTIONABLE:
        return GroupAnalysis(group=group, triage=triage, recommendation=None)

    recommend_system = render_prompt(
        "recommend_system.md", domain=group.domain.value, domain_guidance=domain_spec.guidance
    )
    recommend_user = render_prompt(
        "recommend_user.md",
        group=group,
        triage=triage,
        sop_chunks=sop_chunks,
        run_id=deps["run_id"],
        action_allowlist=deps["action_allowlist"],
        github=settings.github,
        terraform_revert_workflow=settings.remediation.terraform_revert_dispatch.workflow_file,
    )
    recommendation = call_structured(
        deps["reasoning_model"],
        schema=Recommendation,
        system_prompt=recommend_system,
        user_prompt=recommend_user,
        node="recommend",
        group_id=group.group_id,
        model_name=settings.llm.reasoning_model,
        budget=deps["budget"],
        masker=masker,
    )
    recommendation = recommendation.model_copy(
        update={
            "group_id": group.group_id,
            "run_id": deps["run_id"],
            "domain": group.domain,
            "target_fingerprints": group.findings,
        }
    )

    target_findings = [
        deps["findings_by_fingerprint"][fp]
        for fp in group.findings
        if fp in deps["findings_by_fingerprint"]
    ]
    recommendation = evaluate_recommendation(
        recommendation,
        target_findings=target_findings,
        clause_texts=deps["clause_texts"],
        risk_tiers=deps["risk_tiers"],
        action_allowlist=deps["action_allowlist"],
        protected_resources=deps["protected_resources"],
    )

    return GroupAnalysis(group=group, triage=triage, recommendation=recommendation)


def skip_unchanged(
    groups: Sequence[FindingGroup],
    *,
    previous_hashes: dict[str, str],
    previous_results: dict[str, GroupAnalysis],
) -> tuple[list[FindingGroup], list[GroupAnalysis]]:
    """Split groups into (need fresh analysis, reusable from a prior run)."""
    to_analyze: list[FindingGroup] = []
    carried_over: list[GroupAnalysis] = []
    for group in groups:
        content_hash = compute_group_content_hash(group)
        previous = previous_results.get(group.group_id)
        if previous is not None and previous_hashes.get(group.group_id) == content_hash:
            carried_over.append(
                GroupAnalysis(
                    group=group,
                    triage=previous.triage,
                    recommendation=previous.recommendation,
                    carried_over=True,
                )
            )
        else:
            to_analyze.append(group)
    return to_analyze, carried_over


def analyze_groups(groups: Sequence[FindingGroup], *, deps: DomainAgentDeps) -> list[GroupAnalysis]:
    """Sequential fallback / local-runner path. `build_domain_graph` below is
    the LangGraph-parallel version used inside the `domain_batch` Lambda."""
    return [analyze_group(group, deps=deps) for group in groups]


class _GraphState(TypedDict):
    groups: list[FindingGroup]
    results: Annotated[list[GroupAnalysis], operator.add]


class _GroupState(TypedDict):
    group: FindingGroup


def build_domain_graph(deps: DomainAgentDeps) -> Any:
    """``START -> load_groups -(Send per group)-> analyze_group -> merge -> END``.

    No checkpointer: a batch is idempotent, so nothing here needs to
    survive past one ``domain_batch`` Lambda invocation.
    """

    def load_groups(state: _GraphState) -> dict[str, Any]:
        return {}

    def fan_out(state: _GraphState) -> list[Send]:
        return [Send("analyze_group_node", {"group": group}) for group in state["groups"]]

    def analyze_group_node(state: _GroupState) -> dict[str, Any]:
        result = analyze_group(state["group"], deps=deps)
        return {"results": [result]}

    def merge(state: _GraphState) -> dict[str, Any]:
        return {}

    graph = StateGraph(_GraphState)
    graph.add_node("load_groups", load_groups)
    graph.add_node("analyze_group_node", analyze_group_node)
    graph.add_node("merge", merge)
    graph.add_edge(START, "load_groups")
    graph.add_conditional_edges("load_groups", fan_out, ["analyze_group_node"])
    graph.add_edge("analyze_group_node", "merge")
    graph.add_edge("merge", END)
    return graph.compile()


def run_domain_graph(
    groups: Sequence[FindingGroup], *, deps: DomainAgentDeps
) -> list[GroupAnalysis]:
    """Invoke the compiled graph for a batch of groups and return results in
    the same order they were submitted (Send fan-out does not guarantee
    completion order, so we re-key by group_id)."""
    if not groups:
        return []
    graph = build_domain_graph(deps)
    final_state = graph.invoke({"groups": list(groups), "results": []})
    results_by_group_id = {r.group.group_id: r for r in final_state["results"]}
    return [results_by_group_id[g.group_id] for g in groups]


__all__ = [
    "DomainAgentDeps",
    "GroupAnalysis",
    "StructuredOutputError",
    "analyze_group",
    "analyze_groups",
    "build_domain_graph",
    "compute_group_content_hash",
    "run_domain_graph",
    "skip_unchanged",
]
