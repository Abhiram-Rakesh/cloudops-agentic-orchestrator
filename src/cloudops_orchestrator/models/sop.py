"""Knowledge-base citation and retrieval chunk models."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from cloudops_orchestrator.models.enums import KBDomain, Severity


class SOPCitation(BaseModel):
    """A citation an LLM attaches to a triage/recommendation.

    ``quote`` must be a verbatim substring (<= 300 chars) of the retrieved
    clause text — the policy engine validates this (§7.5 rule 3).
    """

    model_config = ConfigDict(frozen=True)

    sop_id: str
    clause_id: str
    quote: str = Field(max_length=300)


class SOPChunk(BaseModel):
    """A retrievable chunk of the knowledge base: one clause, or a SOP overview."""

    model_config = ConfigDict(frozen=True)

    key: str
    sop_id: str
    clause_id: str | None = None  # None for the SOP overview chunk
    domain: KBDomain
    controls: list[str] = Field(default_factory=list)
    prowler_checks: list[str] = Field(default_factory=list)
    severity: Severity | None = None
    version: str
    references: list[str] = Field(default_factory=list)
    title: str
    source_path: str
    text: str
    score: float = 0.0
    expanded: bool = False
