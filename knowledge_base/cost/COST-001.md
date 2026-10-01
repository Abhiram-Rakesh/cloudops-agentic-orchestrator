---
sop_id: COST-001
title: Resource Tagging and Cost Allocation
domain: cost
version: 1.2.0
owner: finops@meridianretailtech.example
effective_date: 2026-01-15
review_cycle_days: 180
applies_to: [dev, staging, prod]
references: [SHARED-001]
---

## Purpose

Cost allocation is impossible without consistent tagging. This SOP defines
Meridian Retail Technologies' required tag set, the format constraint on
`cost-center`, and the monthly review cadence for spend that cannot be
allocated to any tagged owner. Every downstream cost clause (COST-002
through COST-005) assumes these tags exist and are trustworthy.

## Scope

Applies to every billable AWS resource — EC2 instances, EBS volumes,
Elastic IPs, S3 buckets, and any other resource type Cost Explorer can
attribute spend to by tag.

## Roles & Responsibilities (RACI)

| Activity | Application Owner | Platform/DevOps Engineer | FinOps Lead |
|---|---|---|---|
| Apply required tags at resource creation | R | C | A |
| Remediate a missing/malformed tag | I | R | A |
| Monthly unallocated-spend review | I | C | A/R |

## Definitions

- **Required tags**: `owner`, `cost-center`, `environment`, `application` —
  every billable resource MUST carry all four.
- **Cost center**: Meridian's internal budget code, format `CC-\d{4}`
  (e.g. `CC-2040`).
- **Unallocated spend**: spend Cost Explorer cannot group under a value for
  every required tag (i.e., at least one required tag is missing or blank).

## Policy Clauses

### COST-001-1.1 — Required tags present

```clause-meta
controls: [COST-TAG-MISSING]
prowler_checks: []
severity: medium
default_action: "ssm_automation:CloudOps-ApplyTags"
iac_managed_action: "terraform_pr:remediate_cost"
risk_tier: {non_prod: T1, prod: T1}
references: []
```

Every billable resource MUST carry all four required tags
(`owner`, `cost-center`, `environment`, `application`) with non-empty
values. A resource missing any one of the four is a single
`COST-TAG-MISSING` finding listing every missing tag, not one finding per
missing tag.

### COST-001-1.2 — Cost-center format

```clause-meta
controls: [COST-TAG-MISSING]
prowler_checks: []
severity: low
default_action: "ssm_automation:CloudOps-ApplyTags"
iac_managed_action: "terraform_pr:remediate_cost"
risk_tier: {non_prod: T1, prod: T1}
references: []
```

Where a `cost-center` tag is present, its value MUST match `CC-\d{4}`. A
present-but-malformed cost-center (e.g. `CC-40` or `finance`) is Low
severity — the tag exists and routes spend somewhere, it just doesn't match
Meridian's budget-code format, which is a lower-urgency data-quality issue
than a fully missing tag.

### COST-001-1.3 — Monthly unallocated-spend review

```clause-meta
controls: []
prowler_checks: []
severity: info
default_action: notify_owner
iac_managed_action: null
risk_tier: {non_prod: T0, prod: T0}
references: []
```

The FinOps Lead MUST review total unallocated spend (Definitions, above)
monthly and confirm it trends toward zero as COST-001-1.1 remediations
land. This clause produces an informational report line, not a
per-resource finding — the per-resource findings are already covered by
COST-001-1.1.

## Procedures

1. To list resources missing a required tag:
   `aws resourcegroupstaggingapi get-resources --tags-per-page 100` then
   diff each resource's tag set against the required-tags list.
2. `CloudOps-ApplyTags` (the default action for COST-001-1.1/1.2) only ever
   adds or corrects the specific tag(s) named in the finding; it never
   removes an existing, unrelated tag.
3. Monthly unallocated-spend review: Cost Explorer grouped by `owner` with
   a "no tag" bucket — the FinOps Lead exports this to the monthly cost
   review deck (external to this SOP).

## Exceptions

A resource that genuinely cannot carry tags (rare — most AWS resource types
support tagging) requires a SHARED-003 exception documenting the specific
resource type limitation and an alternative attribution method (e.g. cost
allocation by linked account instead of by tag).

## Compliance Mapping

This SOP maps to Meridian's internal FinOps tagging standard, not to
Security Hub or Prowler — it is a cost-governance control, not a security
control. Mapped internally to COST-TAG-MISSING in
`config/prowler_control_map.yaml`'s cost-domain section (present for
consistency of tooling, not because Prowler evaluates tags).

## Revision History

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2025-03-01 | Initial required-tags list |
| 1.1.0 | 2025-08-01 | Added cost-center format constraint |
| 1.2.0 | 2026-01-15 | Added monthly unallocated-spend review clause |
