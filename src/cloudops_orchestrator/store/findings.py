"""Finding upsert / status lifecycle (NEW -> OPEN -> RESOLVED, or SUPPRESSED
while an exception is active) against the single-table store.

``upsert_finding`` is called once per collected finding, every run.
``reconcile_resolved`` is called once per domain, after every collector for
that domain has run in the current invocation, to flip any previously
OPEN/NEW/SUPPRESSED finding that *didn't* show up this time to RESOLVED.
"""

from __future__ import annotations

from typing import Any

from cloudops_orchestrator.models.enums import Domain, FindingStatus
from cloudops_orchestrator.models.findings import Finding
from cloudops_orchestrator.store.serialization import from_dynamo_value, to_dynamo_value


def finding_key(fingerprint: str) -> dict[str, str]:
    return {"pk": f"FINDING#{fingerprint}", "sk": "META"}


def _status_gsi1pk(domain: Domain, status: FindingStatus) -> str:
    return f"STATUS#{domain.value}#{status.value}"


def _to_item(finding: Finding) -> dict[str, Any]:
    data = finding.model_dump(mode="json")
    item: dict[str, Any] = to_dynamo_value(data)
    item.update(finding_key(finding.fingerprint))
    item["gsi1pk"] = _status_gsi1pk(finding.domain, finding.status)
    item["gsi1sk"] = finding.last_seen.isoformat()
    return item


def _from_item(item: dict[str, Any]) -> Finding:
    data = {k: v for k, v in item.items() if k not in ("pk", "sk", "gsi1pk", "gsi1sk")}
    return Finding.model_validate(from_dynamo_value(data))


def get_finding(table: Any, fingerprint: str) -> Finding | None:
    response = table.get_item(Key=finding_key(fingerprint))
    item = response.get("Item")
    return _from_item(item) if item else None


def put_finding(table: Any, finding: Finding) -> None:
    table.put_item(Item=_to_item(finding))


def upsert_finding(table: Any, finding: Finding) -> Finding:
    """Insert a new finding as NEW, or refresh an existing one to OPEN.

    Preserves ``first_seen`` and an active SUPPRESSED status across re-seeing
    the same fingerprint; everything else (severity, details, tags, ...)
    reflects the latest collected snapshot.
    """
    existing = get_finding(table, finding.fingerprint)
    if existing is None:
        to_store = finding.model_copy(update={"status": FindingStatus.NEW})
    else:
        status = (
            FindingStatus.SUPPRESSED
            if existing.status == FindingStatus.SUPPRESSED
            else FindingStatus.OPEN
        )
        to_store = finding.model_copy(update={"first_seen": existing.first_seen, "status": status})
    put_finding(table, to_store)
    return to_store


def mark_resolved(table: Any, fingerprint: str) -> Finding | None:
    existing = get_finding(table, fingerprint)
    if existing is None or existing.status == FindingStatus.RESOLVED:
        return existing
    resolved = existing.model_copy(update={"status": FindingStatus.RESOLVED})
    put_finding(table, resolved)
    return resolved


def query_open_fingerprints_for_domain(table: Any, domain: Domain) -> set[str]:
    """All fingerprints currently NEW, OPEN, or SUPPRESSED for a domain."""
    fingerprints: set[str] = set()
    for status in (FindingStatus.NEW, FindingStatus.OPEN, FindingStatus.SUPPRESSED):
        response = table.query(
            IndexName="gsi1",
            KeyConditionExpression="gsi1pk = :pk",
            ExpressionAttributeValues={":pk": _status_gsi1pk(domain, status)},
        )
        for item in response.get("Items", []):
            fingerprints.add(_from_item(item).fingerprint)
    return fingerprints


def reconcile_resolved(table: Any, *, domain: Domain, seen_fingerprints: set[str]) -> list[str]:
    """Mark every previously-open finding for ``domain`` not in ``seen_fingerprints`` RESOLVED.

    Returns the list of fingerprints that were newly resolved.
    """
    previously_open = query_open_fingerprints_for_domain(table, domain)
    to_resolve = previously_open - seen_fingerprints
    for fingerprint in to_resolve:
        mark_resolved(table, fingerprint)
    return sorted(to_resolve)


__all__ = [
    "finding_key",
    "get_finding",
    "mark_resolved",
    "put_finding",
    "query_open_fingerprints_for_domain",
    "reconcile_resolved",
    "upsert_finding",
]
