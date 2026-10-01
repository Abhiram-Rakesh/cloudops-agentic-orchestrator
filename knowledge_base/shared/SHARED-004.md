---
sop_id: SHARED-004
title: Protected Resources and Platform Self-Protection
domain: shared
version: 1.0.0
owner: cloud-security@meridianretailtech.example
effective_date: 2026-01-15
review_cycle_days: 180
applies_to: [dev, staging, prod]
references: [SHARED-002]
---

## Purpose

Defines the tagging convention that marks a resource as untouchable by
automation, and the specific rule that the CloudOps Agentic Orchestrator's
own AWS resources are always out of scope for its own automated
remediation — a platform must never be able to modify itself as a
side-effect of doing its job.

## Scope

Applies to every resource in every account this system has read access to.
A resource need only match one of the criteria in SHARED-004-4.1 or
SHARED-004-4.2 to be protected — the two are independent checks, not
alternatives requiring both.

## Roles & Responsibilities (RACI)

| Activity | Resource Owner | Cloud Security Lead | Platform Lead |
|---|---|---|---|
| Apply `cloudops:protected=true` tag | R | C | I |
| Maintain the platform's own self-protection tags | I | C | A/R |
| Review protected-resource list quarterly | C | A/R | I |

## Definitions

- **Protected resource**: a resource for which this system MUST NOT execute
  any automated change, regardless of tier or approval — findings on it are
  always reported with a drafted manual procedure, never acted on.
- **Platform resource**: any AWS resource created by this system's own
  Terraform (`infra/`), identifiable by the tag `app=cloudops-agentic-orchestrator`.

## Policy Clauses

### SHARED-004-4.1 — Explicit protection tag

```clause-meta
controls: []
prowler_checks: []
severity: null
default_action: manual_ticket
iac_managed_action: null
risk_tier: {non_prod: T3, prod: T3}
references: [SHARED-002-2.1]
```

Any resource tagged `cloudops:protected=true` MUST NOT be modified by any
automated action this system can take (SSM Automation, Terraform PR
auto-merge, or revert dispatch — a Terraform PR may still be opened for
human review, but it MUST NOT be applied automatically). This tag is the
resource owner's explicit, resource-level override, independent of the
resource's actual risk tier under other rules.

### SHARED-004-4.2 — Platform self-protection

```clause-meta
controls: []
prowler_checks: []
severity: null
default_action: manual_ticket
iac_managed_action: null
risk_tier: {non_prod: T3, prod: T3}
references: []
```

Any resource tagged `app=cloudops-agentic-orchestrator` — i.e. any resource
this system's own Terraform created — is out of scope for this system's own
automated remediation, even if such a resource would otherwise match a T1 or
T2 rule. Findings on the platform's own resources are still collected,
triaged, and reported (so that, for example, a misconfigured orchestrator
Lambda is visible), but the resulting recommendation is always
`manual_ticket` at T3.

### SHARED-004-4.3 — Reporting for protected findings

```clause-meta
controls: []
prowler_checks: []
severity: null
default_action: manual_ticket
iac_managed_action: null
risk_tier: {}
references: []
```

A finding on a protected or platform resource MUST still appear in the
weekly report with its full severity, a drafted manual remediation
procedure (the same structured `Recommendation` an automatable finding
would get, just with `action_type=manual_ticket` and no action thread
created), and its SOP citations. It MUST NOT be silently dropped from the
report on the grounds that "nothing can be done automatically."

## Procedures

1. To protect a resource: apply the tag `cloudops:protected=true` via
   Terraform (preferred, for `iac_managed` resources) or directly for
   unmanaged resources under active investigation.
2. To verify a resource's protection status during triage: `aws
   <service> describe-tags ... | grep -E "cloudops:protected|app"` or check
   the finding's `resource_tags` field directly in the report JSON.
3. Quarterly, the Platform Lead reviews all resources tagged
   `app=cloudops-agentic-orchestrator` against the actual Terraform state in
   `infra/` to confirm no drift has removed the self-protection tag.

## Exceptions

Protection status is not exception-eligible in the SHARED-003 sense — a
resource is either tagged protected or it is not. Removing the tag is a
deliberate, out-of-band decision by the resource owner, not something this
system's exception mechanism grants.

## Compliance Mapping

| Clause | Security Hub / Prowler | CIS v3.0 | ISO 27001:2022 Annex A | SOC 2 CC |
|---|---|---|---|---|
| SHARED-004-4.1..4.3 | N/A (process control) | N/A | A.5.9 (Inventory of assets), A.8.32 | CC6.8, CC8.1 |

## Revision History

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2026-01-15 | Initial protected-resource and self-protection rules |
