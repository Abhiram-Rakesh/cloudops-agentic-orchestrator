---
sop_id: DRIFT-003
title: Drift Disposition Decision Table
domain: drift
version: 1.2.0
owner: platform@meridianretailtech.example
effective_date: 2026-01-15
review_cycle_days: 180
applies_to: [dev, staging, prod]
references: [DRIFT-002, SHARED-004]
---

## Purpose

DRIFT-002 establishes ticketed-vs-unticketed as the primary axis for
attribute drift. This SOP adds the two axes that actually determine
Meridian's response — whether the drift is security-weakening or
cost-increasing, and whether it can be attributed at all — and combines all
three into one authoritative decision table that both the LLM drift agent
and a human reviewer use identically.

## Scope

Applies to every attribute-level drift finding (`DRIFT-ATTR`) on a
Terraform-managed resource. Resource-existence drift (a resource missing
from IaC entirely) is DRIFT-001's concern, not this SOP's.

## Roles & Responsibilities (RACI)

| Activity | Platform/DevOps Engineer | Cloud Security Lead | Engineering Manager |
|---|---|---|---|
| Classify drift as security-weakening | C | A/R | I |
| Classify drift as cost-increasing | R | I | A |
| Investigate unattributed drift | R | C | A |
| Execute revert / open codify PR | R | I | I |

## Definitions

- **Security-weakening drift**: a change that increases exposure or
  removes a security control — e.g. opening ingress to `0.0.0.0/0`,
  disabling encryption, suspending S3 versioning, removing a Block Public
  Access setting.
- **Cost-increasing drift**: a change that increases spend without a
  corresponding ticket — e.g. resizing an instance upward, disabling a
  lifecycle rule.
- **Unattributed drift**: a change for which CloudTrail (DRIFT-004-4.3)
  cannot identify an actor, event, or source IP within the lookback window
  — most commonly because CloudTrail logging had a gap, or the change
  predates the trail's creation.

## Policy Clauses

### DRIFT-003-3.1 — Disposition decision table

```clause-meta
controls: [DRIFT-ATTR]
prowler_checks: []
severity: null
default_action: null
iac_managed_action: null
risk_tier: {}
references: [DRIFT-002-2.2, DRIFT-002-2.3, SHARED-004-4.1]
```

Every attribute-level drift finding MUST be disposed of according to the
following table, evaluated top to bottom — the first matching row wins:

| Condition | Disposition | Action | Tier |
|---|---|---|---|
| Resource tagged `cloudops:protected=true` | Protected | `manual_ticket` | T3 |
| Security-weakening (regardless of ticket status) | Revert | `terraform_revert_dispatch` | T1 |
| Cost-increasing **and** unticketed | Revert | `terraform_revert_dispatch` | T1 |
| Ticketed **and** benign (neither security-weakening nor cost-increasing) | Codify | `terraform_pr` (`codify_drift`) | T1 |
| Unticketed **and** benign | Revert | `terraform_revert_dispatch` | T1 |
| Cannot be attributed via CloudTrail | Needs human | `NEEDS_HUMAN` triage verdict, no automated recommendation | — |

A security-weakening change is reverted even if it carries a valid change
ticket — a ticket documents authorization for the change process, it does
not override the requirement that security controls not regress
(SHARED-002-2.5's spirit applied to drift). The demo's `orders-demo-app-sg`
port-8080-world-open simulation and the `orders-demo-assets` versioning
suspension are both canonical security-weakening examples and both revert
under this table regardless of any ticket tag present.

### DRIFT-003-3.2 — Reverts execute only through the IaC pipeline

```clause-meta
controls: []
prowler_checks: []
severity: null
default_action: "terraform_revert_dispatch"
iac_managed_action: "terraform_revert_dispatch"
risk_tier: {non_prod: T1, prod: T1}
references: [SHARED-002-2.3]
```

A revert disposition (DRIFT-003-3.1) MUST execute as a `workflow_dispatch`
of the Terraform apply pipeline (re-asserting the last-known-good state
from the state file), never as a direct API call undoing the drifted
attribute by hand. This keeps the revert itself auditable through the same
CI pipeline as every other infrastructure change.

### DRIFT-003-3.3 — Codify PRs must reference the change ticket

```clause-meta
controls: []
prowler_checks: []
severity: null
default_action: null
iac_managed_action: null
risk_tier: {}
references: [DRIFT-002-2.2]
```

A codify disposition's resulting pull request MUST reference the
change-ticket ID in both the PR title and description, and MUST NOT be
merged until the linked ticket shows a status of "resolved" or
"implemented" in Meridian's ticketing system.

## Procedures

1. Determine security-weakening status: compare the drift's before/after
   attribute values against the SEC-00x clause catalog — e.g. an
   `ingress` rule diff adding `0.0.0.0/0` matches SEC-002-2.1/2.5's
   pattern directly.
2. Determine cost-increasing status: compare before/after instance type,
   volume size/type, or lifecycle configuration against Meridian's
   ap-south-1 price table (`config/settings.dev.yaml`'s cost-waste price
   table).
3. Determine attribution: `aws cloudtrail lookup-events
   --lookup-attributes AttributeKey=ResourceName,AttributeValue=<id>
   --start-time <drift-window-start>`; if no matching event is found within
   the drift detection window, treat as unattributed.

## Exceptions

There is no exception path for a security-weakening revert — see
DRIFT-002-2.3's rationale, which applies equally here. A cost-increasing,
ticketed change that the team wants to keep (not codify-vs-revert but
"accept the cost") requires a SHARED-003 exception on the underlying
COST-00x clause, evaluated separately from this table's drift disposition.

## Compliance Mapping

| Clause | Internal rule | ISO 27001:2022 Annex A | SOC 2 CC |
|---|---|---|---|
| DRIFT-003-3.1..3.3 | DRIFT-ATTR | A.8.32, A.5.26 | CC7.3, CC8.1 |

## Revision History

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2025-05-15 | Initial revert-vs-codify table (ticketed axis only) |
| 1.1.0 | 2025-12-10 | Added security-weakening and cost-increasing axes |
| 1.2.0 | 2026-01-15 | Added protected-resource and unattributed rows |
