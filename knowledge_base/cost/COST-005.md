---
sop_id: COST-005
title: Non-Production Scheduling and Dev Resource Hygiene
domain: cost
version: 1.0.0
owner: finops@meridianretailtech.example
effective_date: 2026-01-15
review_cycle_days: 180
applies_to: [dev, staging]
references: [SHARED-001, COST-002]
---

## Purpose

Non-production environments running 24/7 are one of the largest avoidable
cost categories at most retail-scale AWS estates. This SOP requires every
non-production instance to declare an operating schedule, and requires
periodic review of long-inactive development resources for deletion.

## Scope

Applies to every EC2 instance tagged `environment` other than `prod` or
`production`. Does not apply to production resources — production always
runs on an `always-on` basis by definition and is out of scope for this SOP.

## Roles & Responsibilities (RACI)

| Activity | Application Owner | Platform/DevOps Engineer | FinOps Lead |
|---|---|---|---|
| Set the `schedule` tag | R | C | I |
| Review inactive dev resources | I | C | A/R |

## Definitions

- **`schedule` tag**: either `office-hours` (09:00–21:00 Asia/Kolkata,
  Monday–Friday; the instance is expected to be stopped outside this
  window) or `always-on` (the instance is expected to run continuously,
  with a justification recorded in its description or a linked ticket).
- **Inactive dev resource**: a `dev`-tagged resource with no CloudWatch
  activity (CPU, network, or S3 request metrics as applicable) for more
  than 30 consecutive days.

## Policy Clauses

### COST-005-5.1 — Non-production instances must carry a schedule tag

```clause-meta
controls: [COST-NONPROD-SCHEDULE]
prowler_checks: []
severity: low
default_action: "ssm_automation:CloudOps-ApplyTags"
iac_managed_action: "terraform_pr:remediate_cost"
risk_tier: {non_prod: T1, prod: T1}
references: [COST-001-1.1]
```

Every non-production EC2 instance MUST carry a `schedule` tag with value
`office-hours` or `always-on`. This clause only requires the tag to exist
and have a valid value — it does not itself stop or start the instance;
enforcing the office-hours schedule is a separate automation outside this
system's current scope (see the README's How it works section future-work notes once
written) and is deliberately not conflated with COST-002-2.1's idle-instance
detection, which is behavior-based rather than tag-based.

### COST-005-5.2 — Inactive dev resources reviewed for deletion

```clause-meta
controls: []
prowler_checks: []
severity: info
default_action: notify_owner
iac_managed_action: null
risk_tier: {non_prod: T0, prod: T0}
references: []
```

Any `dev`-tagged resource meeting the Inactive definition above MUST be
surfaced to its owner for a delete/keep decision. This is informational —
the system does not delete a resource on the owner's behalf simply because
it has been quiet for 30 days, since "quiet" is a weaker signal than
"idle" (COST-002-2.1) and false positives (e.g. a dev environment kept
warm for an upcoming demo) are common enough to require a human decision
every time.

## Procedures

1. List non-production instances missing a `schedule` tag: cross-reference
   `resourcegroupstaggingapi` output for `environment != prod` against the
   presence of a `schedule` tag.
2. Identify inactive dev resources: CloudWatch `GetMetricData` over a
   30-day window per resource, applying the domain-appropriate metric
   (CPUUtilization for EC2, BucketSizeBytes/NumberOfObjects trend for S3).

## Exceptions

An `always-on` non-production instance does not require a SHARED-003
exception — `always-on` is itself a valid, documented `schedule` value, not
a deviation from this SOP.

## Compliance Mapping

| Clause | Internal rule | Notes |
|---|---|---|
| COST-005-5.1 | COST-NONPROD-SCHEDULE | FinOps-only |
| COST-005-5.2 | — | FinOps-only, informational |

## Revision History

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2026-01-15 | Initial non-prod scheduling and dev-hygiene clauses |
