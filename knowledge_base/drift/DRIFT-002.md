---
sop_id: DRIFT-002
title: Break-Glass Changes and Ticketed Drift Codification
domain: drift
version: 1.1.0
owner: platform@meridianretailtech.example
effective_date: 2026-01-15
review_cycle_days: 180
applies_to: [dev, staging, prod]
references: [SHARED-002, DRIFT-001]
---

## Purpose

Sometimes an engineer must make a console or CLI change directly, outside
Terraform, to resolve an urgent incident — a break-glass change. This SOP
defines the change-ticket requirement that makes a break-glass change
traceable, the 72-hour window to codify a properly-ticketed change back
into Terraform, and the consequence for a change with no ticket at all.

## Scope

Applies to any attribute-level change to an already Terraform-managed
resource, detected as a `terraform plan -refresh-only` diff (as opposed to
DRIFT-001, which covers resources missing from Terraform entirely).

## Roles & Responsibilities (RACI)

| Activity | Engineer making the change | Platform/DevOps Engineer | Cloud Security Lead |
|---|---|---|---|
| Perform a break-glass change | R | I | I |
| Attach a change-ticket tag | R | I | I |
| Codify the change into Terraform within 72h | C | A/R | I |
| Investigate an unticketed change | I | R | A |

## Definitions

- **Break-glass change**: a direct API/console change to a Terraform-managed
  resource, made outside the normal PR workflow, during an incident or
  other time-critical situation.
- **Change ticket**: a Meridian incident/change ticket ID (format
  `CHG-\d{4}`), recorded as a `change-ticket` tag on the changed resource
  at the time of the change.
- **Ticketed change**: a break-glass change whose resource carries a valid
  `change-ticket` tag matching an actual, open Meridian ticket.

## Policy Clauses

### DRIFT-002-2.1 — Break-glass changes require a change ticket

```clause-meta
controls: [DRIFT-ATTR]
prowler_checks: []
severity: medium
default_action: null
iac_managed_action: null
risk_tier: {}
references: [SHARED-002-2.4]
```

Any break-glass change MUST be accompanied by a `change-ticket` tag applied
to the changed resource at the time of the change, referencing an open
Meridian incident or change ticket. This clause itself does not name an
`action_type` — it is the precondition DRIFT-002-2.2 and DRIFT-002-2.3
branch on, evaluated by whichever of those two actually fires for a given
attribute drift finding.

### DRIFT-002-2.2 — Ticketed changes codified within 72 hours

```clause-meta
controls: [DRIFT-ATTR]
prowler_checks: []
severity: medium
default_action: "terraform_pr:codify_drift"
iac_managed_action: "terraform_pr:codify_drift"
risk_tier: {non_prod: T1, prod: T1}
references: [DRIFT-002-2.1, DRIFT-003-3.3]
```

A ticketed change (Definitions, above) MUST be codified back into Terraform
— a PR updating the managing resource's HCL to match the live, ticketed
state — within 72 hours of detection. The resulting PR MUST reference the
change ticket per DRIFT-003-3.3. Since the finding is, by construction, on
an already-Terraform-managed resource, this clause's action is always
`terraform_pr` regardless of the general `default_action`/`iac_managed_action`
split used elsewhere in this knowledge base.

### DRIFT-002-2.3 — Unticketed changes are unauthorized and must be reverted

```clause-meta
controls: [DRIFT-ATTR]
prowler_checks: []
severity: high
default_action: "terraform_revert_dispatch"
iac_managed_action: "terraform_revert_dispatch"
risk_tier: {non_prod: T1, prod: T1}
references: [DRIFT-002-2.1, DRIFT-003-3.2]
```

An attribute-level drift finding on a Terraform-managed resource with no
valid `change-ticket` tag MUST be treated as unauthorized and reverted —
dispatched through the IaC pipeline's re-apply (DRIFT-003-3.2), restoring
the resource to its Terraform-defined state. This is High, not Medium,
because an unticketed change to production infrastructure is exactly the
pattern an attacker with stolen console access would produce, and
Meridian's policy is to treat it as such until proven otherwise by a human
investigation.

## Procedures

1. When responding to an incident that requires a break-glass change:
   immediately tag the changed resource with `change-ticket=CHG-<id>`
   referencing the incident ticket, before or immediately after making the
   change.
2. To identify whether a drift finding is ticketed: check the finding's
   `resource_tags` for a `change-ticket` value, and independently confirm
   via CloudTrail (`DRIFT-004-4.3`) that the tagging action and the
   underlying change share the same actor and a close timestamp (a
   change-ticket tag applied by someone other than the person who made the
   change, hours later, is a signal worth flagging even if technically
   present).
3. To codify a ticketed change: `terraform plan -refresh-only` shows the
   diff; write the matching HCL change, open a PR referencing the ticket,
   and let `demo-plan.yml` confirm `terraform plan` then reports no further
   changes.

## Exceptions

There is no exception path for DRIFT-002-2.3 — an unticketed change is
reverted, not excepted, because the alternative (documenting an
"exception" for an unauthorized change) would create a paper trail an
attacker could exploit to legitimize further changes. A ticketed change
that genuinely cannot be codified within 72 hours (e.g. blocked on a
vendor dependency) requires a SHARED-003 exception extending the
DRIFT-002-2.2 SLA, not an exception to the ticketing requirement itself.

## Compliance Mapping

| Clause | Internal rule | ISO 27001:2022 Annex A | SOC 2 CC |
|---|---|---|---|
| DRIFT-002-2.1 | DRIFT-ATTR | A.8.32 | CC8.1 |
| DRIFT-002-2.2 | DRIFT-ATTR | A.8.32 | CC8.1 |
| DRIFT-002-2.3 | DRIFT-ATTR | A.5.26 (Incident response) | CC7.3 |

## Revision History

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2025-05-10 | Initial break-glass ticketing requirement |
| 1.1.0 | 2026-01-15 | Added explicit unticketed-change revert clause |
