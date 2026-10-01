"""Stable finding fingerprints.

``sha256(domain|source|account|region|resource_id|rule_id)[:32]``. For the
security domain, Security Hub and Prowler findings on the same *mapped
control ID* + resource must land on the *same* fingerprint so they merge
into one ``Finding`` with both collectors listed in ``sources`` — see
``normalize/merge.py``. That only works if the fingerprint's "source" and
"rule_id" components are the *canonical* ones (a fixed placeholder, and the
mapped control ID) rather than each collector's own name and raw check
id/title, which is what ``security_finding_fingerprint`` encodes.
"""

from __future__ import annotations

import hashlib

from cloudops_orchestrator.models.enums import Domain

SECURITY_SCAN_SOURCE = "security_scan"


def compute_fingerprint(
    *,
    domain: Domain,
    fingerprint_source: str,
    account_id: str,
    region: str,
    resource_id: str,
    fingerprint_rule_id: str,
) -> str:
    raw = f"{domain.value}|{fingerprint_source}|{account_id}|{region}|{resource_id}|{fingerprint_rule_id}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def security_finding_fingerprint(
    *, account_id: str, region: str, resource_id: str, control_id: str
) -> str:
    """Fingerprint for a security_hub/prowler finding, keyed by mapped control ID.

    Both collectors call this with the same ``control_id`` for the same
    underlying issue, so their findings collide on fingerprint and merge.
    """
    return compute_fingerprint(
        domain=Domain.SECURITY,
        fingerprint_source=SECURITY_SCAN_SOURCE,
        account_id=account_id,
        region=region,
        resource_id=resource_id,
        fingerprint_rule_id=control_id,
    )


def standard_fingerprint(
    *, domain: Domain, source: str, account_id: str, region: str, resource_id: str, rule_id: str
) -> str:
    """Fingerprint for any non-merging collector (cost, drift, access analyzer, ...)."""
    return compute_fingerprint(
        domain=domain,
        fingerprint_source=source,
        account_id=account_id,
        region=region,
        resource_id=resource_id,
        fingerprint_rule_id=rule_id,
    )


__all__ = [
    "SECURITY_SCAN_SOURCE",
    "compute_fingerprint",
    "security_finding_fingerprint",
    "standard_fingerprint",
]
