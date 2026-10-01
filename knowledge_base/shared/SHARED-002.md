---
sop_id: SHARED-002
title: Risk Tiers, Approvals and Automation Boundaries
domain: shared
version: 1.3.0
owner: cloud-security@meridianretailtech.example
effective_date: 2026-01-15
review_cycle_days: 180
applies_to: [dev, staging, prod]
references: [SHARED-001]
---

## Purpose

Defines the four-tier risk classification that governs whether, and how, a
remediation may be automated; the approval requirements for each tier; the
change window automated changes must respect; the principle that
Terraform-managed infrastructure is always changed through Terraform; and
the categories of change that Meridian Retail Technologies will never let an
automated agent perform, full stop.

## Scope

Applies to every `Recommendation` and `ActionPlan` the CloudOps Agentic
Orchestrator produces, and to every human approver acting on one in Slack.
Does not apply to changes made through Meridian's standard change-management
process outside of this system (e.g. a planned application deployment).

## Roles & Responsibilities (RACI)

| Activity | On-call Approver | Second Approver (T2) | Platform Lead | CISO |
|---|---|---|---|---|
| Approve T1 action | A/R | — | I | I |
| Approve T2 action | R | R | A | I |
| Define tier→approval mapping | C | C | A | R |
| Grant/revoke approver status | I | I | A | R |

## Definitions

- **Automatable**: a remediation category the policy engine is permitted to
  execute after sufficient human approval, without a human performing the
  change by hand.
- **Distinct approver**: a Slack user ID different from any other approver
  who has already approved the same `action_id`, and different from the
  author of the change being approved (self-approval is never permitted,
  regardless of tier).
- **Change window**: the time range during which an automated T2 change may
  execute; outside it, the action is refused and re-queued rather than
  executed at reduced review capacity.

## Policy Clauses

### SHARED-002-2.1 — Risk tier definitions

```clause-meta
controls: []
prowler_checks: []
severity: null
default_action: null
iac_managed_action: null
risk_tier: {}
references: []
```

Every `Recommendation` MUST be assigned exactly one risk tier, ordered
T0 < T1 < T2 < T3:

| Tier | Approvals required | Automatable | Description |
|---|---|---|---|
| T0 | 0 | No (report/notify only) | The finding is reported or an owner is notified; no action is executed by this system. |
| T1 | 1 | Yes | Low-risk, reversible, non-production impact. |
| T2 | 2 (distinct) | Yes, within the change window (SHARED-002-2.4) | Production impact, or a destructive-but-backed-up change (e.g. delete-after-snapshot). |
| T3 | — | No, human-only | IAM, KMS, Organizations, protected resources, or anything else listed in SHARED-002-2.5. A human must perform the change through Meridian's standard change process. |

A recommendation's `proposed_risk_tier` (an agent's suggestion) and
`effective_risk_tier` (the policy engine's final, binding decision) MAY
differ; the effective tier is always `max(proposed, tier implied by the
matching rules in `config/policy/risk_tiers.yaml`)` — an agent may only ever
cause a tier increase relative to its own proposal being overridden upward,
never a decrease.

### SHARED-002-2.2 — Approver roles and self-approval

```clause-meta
controls: []
prowler_checks: []
severity: null
default_action: null
iac_managed_action: null
risk_tier: {}
references: []
```

Only Slack users listed in `approvals.approvers` (per environment) MAY
approve an action. A T2 action MUST receive approvals from two **distinct**
approvers before it executes; a repeated approval from the same approver
does not count twice. No approver may approve an action they themselves
authored evidence for or requested outside this system (self-approval is
prohibited at every tier, not only T2). Violations MUST be logged as an
audit event and the action returned to `AWAITING_APPROVAL`.

### SHARED-002-2.3 — IaC-first remediation

```clause-meta
controls: []
prowler_checks: []
severity: null
default_action: null
iac_managed_action: terraform_pr
risk_tier: {}
references: [DRIFT-002-2.3, DRIFT-003-3.2]
```

Any resource managed by Terraform (`iac_managed=true`) MUST be remediated
through the IaC repository — a pull request that edits the managing
Terraform code, or a `workflow_dispatch` of the pipeline that re-applies
existing Terraform — and MUST NOT be changed by a direct API call, console
action, or SSM Automation document, even if a faster non-IaC path exists.
This holds regardless of the finding's domain (security, cost, or drift):
an idle, Terraform-managed EC2 instance is stopped via a Terraform PR
setting its desired state, not via `CloudOps-StopInstance`.

### SHARED-002-2.4 — Change window

```clause-meta
controls: []
prowler_checks: []
severity: null
default_action: null
iac_managed_action: null
risk_tier: {}
references: [DRIFT-002-2.1]
```

A T2 automated action MUST only execute Monday–Thursday, 10:00–17:00
Asia/Kolkata. An action that becomes eligible to execute outside this window
(e.g. the second approval lands at 19:00 on a Thursday) MUST be re-queued
and executed at the next window opening, not executed immediately.
Emergency changes that cannot wait for the window follow the break-glass
procedure in DRIFT-002-2.1 and are performed by a human, not this system.

### SHARED-002-2.5 — Automation boundaries

```clause-meta
controls: []
prowler_checks: []
severity: critical
default_action: manual_ticket
iac_managed_action: null
risk_tier: {non_prod: T3, prod: T3}
references: []
```

The following categories of change MUST NEVER be executed automatically by
this system, regardless of tier, approval count, or how the policy engine
computes it — they are hard-coded to T3 / `manual_ticket`:

1. Any IAM policy, role, user, or group change (`AwsIam*` resource types).
2. Any KMS key change (`AwsKms*` resource types), including key deletion
   scheduling.
3. Any AWS Organizations change.
4. Any data deletion that is not preceded by a verified backup/snapshot
   step within the same action.
5. Any change to a resource tagged `cloudops:protected=true` or
   `app=cloudops-agentic-orchestrator` (SHARED-004).

## Procedures

1. When a `Recommendation` is created, the policy engine
   (`policy/engine.py`) evaluates it against `config/policy/risk_tiers.yaml`
   and this SOP's clauses, in code — never by asking the LLM "what tier is
   this."
2. To manually verify an approver's identity before granting Slack approver
   status: confirm via Meridian's SSO directory that the Slack user ID
   belongs to an active member of the Cloud Platform or Cloud Security team.
3. To audit change-window compliance for a given week: query
   `AUDIT#ACTION#<id>` records in the state table for `event=remediate` and
   confirm the timestamp falls within the window for any T2 action.

## Exceptions

Tier assignment itself is not exception-eligible — a resource cannot be
"excepted" into a lower tier. Only the underlying finding's SLA (SHARED-001)
may carry a SHARED-003 exception while a T3/manual remediation is pending.

## Compliance Mapping

| Clause | Security Hub / Prowler | CIS v3.0 | ISO 27001:2022 Annex A | SOC 2 CC |
|---|---|---|---|---|
| SHARED-002-2.1..2.4 | N/A (process control) | 1.1 (change control) | A.8.32 (Change management) | CC8.1 |
| SHARED-002-2.5 | IAM.1, IAM.21, KMS.* (process boundary, not a scanned control) | 1.16, 1.17 | A.8.2, A.5.15 | CC6.1, CC6.3 |

## Revision History

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2025-03-01 | Initial T0–T2 tiers |
| 1.1.0 | 2025-07-20 | Added T3 human-only tier |
| 1.2.0 | 2025-11-05 | Added change window (SHARED-002-2.4) |
| 1.3.0 | 2026-01-15 | Added explicit automation boundaries (SHARED-002-2.5) |
