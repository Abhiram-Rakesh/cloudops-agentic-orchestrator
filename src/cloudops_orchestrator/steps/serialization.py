"""JSON (de)serialization for the payloads that cross Lambda invocation
boundaries via S3: Step Functions payloads must stay small (IDs and
S3 keys only), so ``Collect`` writes each domain's groups and the full
finding list to S3 for ``DomainBatch``/``Aggregate`` to reload, and each
``DomainBatch`` writes its ``DomainBatchResult`` for ``Aggregate`` to merge.
"""

from __future__ import annotations

import json
from typing import Any

from cloudops_orchestrator.graph.domain_agent import GroupAnalysis
from cloudops_orchestrator.models.actions import Recommendation, TriageResult
from cloudops_orchestrator.models.findings import Finding, FindingGroup
from cloudops_orchestrator.normalize.masking import Masker
from cloudops_orchestrator.steps.run_domain_batch import DomainBatchResult


def serialize_findings(findings: list[Finding]) -> str:
    return json.dumps([f.model_dump(mode="json") for f in findings])


def deserialize_findings(text: str) -> list[Finding]:
    return [Finding.model_validate(item) for item in json.loads(text)]


def serialize_masker(masker: Masker) -> str:
    """The masker's reverse (token -> original) mapping only -- enough to
    ``unmask()`` with, and nothing more; a fresh forward-mapping counter is
    fine since nothing downstream of ``collect`` ever calls ``mask()``
    again (see ``normalize/masking.py``'s class docstring)."""
    return json.dumps(masker.reverse_map())


def deserialize_masker(text: str) -> Masker:
    return Masker(reverse=json.loads(text))


def serialize_groups(groups: list[FindingGroup]) -> str:
    return json.dumps([g.model_dump(mode="json") for g in groups])


def deserialize_groups(text: str) -> list[FindingGroup]:
    return [FindingGroup.model_validate(item) for item in json.loads(text)]


def _analysis_to_dict(analysis: GroupAnalysis) -> dict[str, Any]:
    return {
        "group": analysis.group.model_dump(mode="json"),
        "triage": analysis.triage.model_dump(mode="json"),
        "recommendation": (
            analysis.recommendation.model_dump(mode="json") if analysis.recommendation else None
        ),
        "carried_over": analysis.carried_over,
        "error": analysis.error,
    }


def _analysis_from_dict(data: dict[str, Any]) -> GroupAnalysis:
    return GroupAnalysis(
        group=FindingGroup.model_validate(data["group"]),
        triage=TriageResult.model_validate(data["triage"]),
        recommendation=(
            Recommendation.model_validate(data["recommendation"])
            if data["recommendation"] is not None
            else None
        ),
        carried_over=data["carried_over"],
        error=data.get("error"),
    )


def serialize_domain_result(result: DomainBatchResult) -> str:
    return json.dumps(
        {
            "batch_id": result.batch_id,
            "domain": result.domain,
            "analyses": [_analysis_to_dict(a) for a in result.analyses],
            "budget_exhausted": result.budget_exhausted,
            "cost_usd": result.cost_usd,
        }
    )


def deserialize_domain_result(text: str) -> DomainBatchResult:
    data = json.loads(text)
    return DomainBatchResult(
        batch_id=data["batch_id"],
        domain=data["domain"],
        analyses=[_analysis_from_dict(a) for a in data["analyses"]],
        budget_exhausted=data["budget_exhausted"],
        cost_usd=data["cost_usd"],
    )


__all__ = [
    "deserialize_domain_result",
    "deserialize_findings",
    "deserialize_groups",
    "deserialize_masker",
    "serialize_domain_result",
    "serialize_findings",
    "serialize_groups",
    "serialize_masker",
]
