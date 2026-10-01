"""``DomainSpec``: the per-domain guidance text injected into the triage and
recommend system prompts.
"""

from __future__ import annotations

from dataclasses import dataclass

from cloudops_orchestrator.models.enums import Domain


@dataclass(frozen=True)
class DomainSpec:
    domain: Domain
    guidance: str


__all__ = ["DomainSpec"]
