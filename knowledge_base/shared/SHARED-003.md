---
sop_id: SHARED-003
title: SOP Exception Management
domain: shared
version: 1.1.0
owner: cloud-security@meridianretailtech.example
effective_date: 2026-01-15
review_cycle_days: 180
applies_to: [dev, staging, prod]
references: [SHARED-001, SHARED-002]
---

## Purpose

Defines how a finding, or an entire SOP clause, may be temporarily excepted
from enforcement — with a required justification, compensating control,
owner, and hard expiry — so that legitimate operational realities (a
Security Hub trial ending, a vendor integration that cannot yet meet a
control) do not force a false choice between "silently ignore" and "block
everything."

## Scope

Applies to every finding and every clause in this knowledge base. An
exception suppresses reporting and SLA enforcement for its scope and
duration; it does not fix the underlying issue, and it does not apply
retroactively to findings that predate it.

## Roles & Responsibilities (RACI)

| Activity | Requesting Engineer | Cloud Security Lead | Engineering Manager | CISO |
|---|---|---|---|---|
| Request exception | R | C | I | I |
| Approve Medium/Low exception | I | A/R | C | I |
| Approve High exception | I | R | A | I |
| Approve Critical exception | I | R | C | A |
| Review exceptions at expiry | I | R | I | I |

## Definitions

- **Exception**: a time-bound, scoped suppression of a finding's SLA
  enforcement and default reporting weight, recorded with
  `cloudops exceptions add`.
- **Compensating control**: an alternative safeguard that reduces the risk
  the excepted clause would otherwise mitigate (e.g. "weekly Prowler scan +
  Access Analyzer + CloudTrail" in place of a live GuardDuty detector).
- **Scope**: either a single finding (`fingerprint`) or an entire clause
  (`clause_id`, applied account/region-wide) — the latter is reserved for
  structural situations like the security-services trial switchover
  (DOCS/TRIAL_SWITCHOVER.md), not individual resource exceptions.

## Policy Clauses

### SHARED-003-3.1 — Exception request fields

```clause-meta
controls: []
prowler_checks: []
severity: null
default_action: null
iac_managed_action: null
risk_tier: {}
references: []
```

Every exception request MUST record all of the following before it is
granted:

1. **Scope** — `fingerprint` (single finding) or `clause_id` (clause-wide).
2. **Justification** — why the finding cannot be remediated within its
   SHARED-001-1.2 SLA.
3. **Compensating control** — what reduces risk in the interim.
4. **Owner** — the individual or team accountable for eventually closing
   the gap.
5. **Requested duration** — subject to the caps in SHARED-003-3.2.

An exception missing any of these fields MUST be rejected by
`cloudops exceptions add` at the validation layer, not merely flagged for
later review.

### SHARED-003-3.2 — Maximum exception durations

```clause-meta
controls: []
prowler_checks: []
severity: null
default_action: null
iac_managed_action: null
risk_tier: {}
references: [SHARED-001-1.1]
```

An exception's duration MUST NOT exceed the following, based on the
underlying finding's (post-modifier) severity at the time of request:

| Severity | Maximum exception duration |
|---|---|
| Critical | 30 days |
| High | 60 days |
| Medium | 90 days |
| Low | 90 days |

A renewal is a new exception request, not an extension — it requires the
same approval level as the original (SEC-006-6.3 for Critical-severity
exceptions) and a fresh compensating-control justification; a renewal
that simply repeats "still working on it" without a new justification MUST
be rejected.

### SHARED-003-3.3 — Expiry reverts to OPEN

```clause-meta
controls: []
prowler_checks: []
severity: null
default_action: null
iac_managed_action: null
risk_tier: {}
references: []
```

When an exception's `expires_at` passes, the store layer MUST treat the
excepted finding(s) as fully OPEN again — subject to normal SLA enforcement
and reporting weight — without requiring any human action to "turn the
exception off." A finding whose exception has expired and which remains
unresolved MUST appear in the next weekly report with its full, unmodified
severity and age.

## Procedures

1. Request: `cloudops exceptions add --clause <ID> --days <N>
   --compensating-control "<text>" [--fingerprint <fp>] [--owner <team>]`.
2. Review: `cloudops exceptions list` shows all active exceptions with time
   remaining; the Cloud Security Lead reviews this list monthly against the
   RACI table above.
3. Early removal: `cloudops exceptions remove --exception-id <id>` when the
   underlying issue is fixed before expiry.
4. To manually verify an exception is suppressing a finding correctly,
   confirm the finding's `EXCEPTION#<fingerprint>` record in the state table
   carries a TTL matching `expires_at`, and that the weekly report's
   `suppressed` list includes its fingerprint while active.

## Exceptions

This SOP is itself the exception mechanism; it has no exception path of its
own. A request to except SHARED-003's own requirements would be a process
change, handled outside this system.

## Compliance Mapping

| Clause | Security Hub / Prowler | CIS v3.0 | ISO 27001:2022 Annex A | SOC 2 CC |
|---|---|---|---|---|
| SHARED-003-3.1..3.3 | N/A (process control) | N/A | A.5.36 (Compliance review) | CC4.2, CC7.1 |

## Revision History

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2025-04-10 | Initial exception fields and durations |
| 1.1.0 | 2026-01-15 | Clarified renewals require fresh justification, not extension |
