"""Per-domain LangGraph specs: prompts, grouping keys, domain guidance."""

from __future__ import annotations

from cloudops_orchestrator.graph.domains.base import DomainSpec
from cloudops_orchestrator.graph.domains.cost import COST_SPEC
from cloudops_orchestrator.graph.domains.drift import DRIFT_SPEC
from cloudops_orchestrator.graph.domains.security import SECURITY_SPEC
from cloudops_orchestrator.models.enums import Domain

DOMAIN_SPECS: dict[Domain, DomainSpec] = {
    Domain.SECURITY: SECURITY_SPEC,
    Domain.COST: COST_SPEC,
    Domain.DRIFT: DRIFT_SPEC,
}

__all__ = ["COST_SPEC", "DOMAIN_SPECS", "DRIFT_SPEC", "SECURITY_SPEC", "DomainSpec"]
