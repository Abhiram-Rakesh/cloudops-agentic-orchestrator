---
sop_id: DRIFT-001
title: Infrastructure-as-Code Coverage
domain: drift
version: 1.1.0
owner: platform@meridianretailtech.example
effective_date: 2026-01-15
review_cycle_days: 180
applies_to: [dev, staging, prod]
references: [SHARED-002]
---

## Purpose

Meridian Retail Technologies manages its infrastructure exclusively through
Terraform. This SOP requires every in-scope resource to be defined in IaC,
sets the remediation window for a resource discovered outside IaC, and
restates the principle — already established in SHARED-002-2.3 — that
Terraform changes only ever land through a reviewed pull request.

## Scope

Applies to every resource type an `iac_inventory` collector run can
enumerate (currently EC2, security groups, S3 buckets, EBS volumes, and
Elastic IPs tagged `app=orders-demo` in the demo stack; the orchestrator's
own `infra/` resources are covered by the same principle but are out of
this system's own remediation scope per SHARED-004-4.2).

## Roles & Responsibilities (RACI)

| Activity | Platform/DevOps Engineer | Application Owner | Cloud Security Lead |
|---|---|---|---|
| Import or delete an unmanaged resource | R | C | I |
| Review a Terraform PR | A/R | C | C (security-relevant changes) |
| Maintain IaC coverage inventory | R | I | I |

## Definitions

- **In-scope resource**: any resource matching a collector's
  `unmanaged_selector` (e.g. tag `app=orders-demo`) — resources outside this
  selector (e.g. a personal sandbox account explicitly excluded from
  scope) are not subject to this SOP.
- **Unmanaged resource**: an in-scope resource with no corresponding
  Terraform state entry, detected by comparing live inventory against the
  latest `terraform show -json` state export.

## Policy Clauses

### DRIFT-001-1.1 — All in-scope resources must be defined in IaC

```clause-meta
controls: [DRIFT-UNMANAGED]
prowler_checks: []
severity: high
default_action: manual_ticket
iac_managed_action: null
risk_tier: {non_prod: T2, prod: T2}
references: []
```

Every in-scope resource MUST have a corresponding Terraform resource in
state. This clause's finding, by definition, only ever fires on
unmanaged resources (`iac_managed=false`), since a managed resource
trivially satisfies it — there is no `iac_managed_action` variant.

### DRIFT-001-1.2 — Remediation window for unmanaged resources

```clause-meta
controls: [DRIFT-UNMANAGED]
prowler_checks: []
severity: medium
default_action: manual_ticket
iac_managed_action: null
risk_tier: {non_prod: T2, prod: T2}
references: [DRIFT-004-4.1]
```

An unmanaged resource MUST be either imported into Terraform (`terraform
import` plus a matching HCL block, submitted as a PR) or deleted within 7
days of detection. This is `manual_ticket` — deciding whether to import or
delete requires knowing whether the resource is intentional
(under-documented but wanted) or accidental (should be removed), a judgment
this system does not make on the human's behalf.

### DRIFT-001-1.3 — Terraform changes only via reviewed PR

```clause-meta
controls: []
prowler_checks: []
severity: null
default_action: null
iac_managed_action: null
risk_tier: {}
references: [SHARED-002-2.3]
```

All Terraform changes to `infra/` and `demo/infra` MUST land through a pull
request that has passed `demo-plan.yml` / `ci.yml`'s validation, never
through a direct `terraform apply` from a workstation against the shared
backend. This restates SHARED-002-2.3's IaC-first principle at the level of
Meridian's own engineering workflow, independent of any specific finding.

## Procedures

1. Generate a fresh inventory: `terraform -chdir=demo/infra show -json
   > inventory.json` (this is what `drift.yml` uploads for the collector to
   read).
2. Cross-reference live resources against inventory: for each in-scope
   resource ID, confirm it appears in `inventory.json`'s `values.root_module`
   tree (recursively, including nested modules).
3. To import an unmanaged resource: write the matching `resource` block,
   then `terraform import <address> <id>`, then open a PR with both the
   new HCL and a comment showing `terraform plan` reports no changes.

## Exceptions

A resource intentionally excluded from IaC (rare — e.g. a manually-created
break-glass resource with a defined short lifetime) requires a SHARED-003
exception with an explicit deletion date, not an open-ended one.

## Compliance Mapping

| Clause | Internal rule | ISO 27001:2022 Annex A | SOC 2 CC |
|---|---|---|---|
| DRIFT-001-1.1 | DRIFT-UNMANAGED | A.8.9 (Configuration management) | CC8.1 |
| DRIFT-001-1.2 | DRIFT-UNMANAGED | A.8.9 | CC8.1 |
| DRIFT-001-1.3 | — | A.8.32 (Change management) | CC8.1 |

## Revision History

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2025-05-01 | Initial IaC-coverage requirement |
| 1.1.0 | 2026-01-15 | Added explicit 7-day remediation window |
