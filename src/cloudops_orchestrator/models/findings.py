"""Finding, masked-finding and finding-group models.

``Finding`` holds the full (unmasked) record and is only ever stored — never
sent to an LLM. ``MaskedFinding`` is the reversibly-masked view
(`normalize/masking.py`) that is safe to put in a prompt, and is what
``FindingGroup.sample`` carries.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from cloudops_orchestrator.models.common import UTCDatetime
from cloudops_orchestrator.models.enums import Domain, FindingStatus, Severity


class Finding(BaseModel):
    """A single normalized, deduplicated finding.

    ``fingerprint = sha256(domain|source|account|region|resource_id|rule_id)[:32]``
    — see ``normalize/fingerprint.py``. Security Hub and Prowler findings for
    the same mapped control + resource merge into one ``Finding`` with both
    entries in ``sources``.
    """

    model_config = ConfigDict(frozen=True)

    fingerprint: str
    domain: Domain
    source: str
    sources: list[str] = Field(default_factory=list)
    rule_id: str
    control_ids: list[str] = Field(default_factory=list)
    title: str
    description: str
    severity: Severity
    account_id: str
    region: str
    resource_type: str
    resource_id: str
    resource_tags: dict[str, str] = Field(default_factory=dict)
    iac_managed: bool = False
    iac_address: str | None = None
    environment: str | None = None
    evidence_uri: str
    details: dict[str, Any] = Field(default_factory=dict)
    first_seen: UTCDatetime
    last_seen: UTCDatetime
    status: FindingStatus = FindingStatus.NEW


class MaskedFinding(BaseModel):
    """The LLM-visible projection of a ``Finding`` after ``normalize/masking.py``.

    Never carries the raw ``account_id``, ARNs, IPs, resource IDs or emails —
    only their masked tokens (e.g. ``ACCT_1``, ``ARN_7(ec2:security-group)``).
    """

    model_config = ConfigDict(frozen=True)

    fingerprint: str
    title: str
    description: str
    resource_type: str
    masked_resource_id: str
    control_ids: list[str] = Field(default_factory=list)
    severity: Severity
    masked_details: dict[str, Any] = Field(default_factory=dict)
    iac_managed: bool = False
    iac_address: str | None = None
    environment: str | None = None


class FindingGroup(BaseModel):
    """The unit of LLM work: findings sharing (domain, rule_id, resource_type)."""

    model_config = ConfigDict(frozen=True)

    group_id: str
    domain: Domain
    rule_id: str
    control_ids: list[str] = Field(default_factory=list)
    resource_type: str
    findings: list[str]  # fingerprints
    sample: list[MaskedFinding] = Field(default_factory=list)
    count: int
    max_severity: Severity
