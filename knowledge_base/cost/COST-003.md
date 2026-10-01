---
sop_id: COST-003
title: Storage Lifecycle and Volume Type Optimization
domain: cost
version: 1.1.0
owner: finops@meridianretailtech.example
effective_date: 2026-01-15
review_cycle_days: 180
applies_to: [dev, staging, prod]
references: [SHARED-001]
---

## Purpose

Defines storage-cost hygiene beyond the waste-elimination checks in
COST-002: migrating legacy `gp2` volumes to the cheaper and faster `gp3`,
bounding snapshot retention, and requiring lifecycle policies on export/log
buckets so that storage cost does not grow unbounded over time.

## Scope

Applies to every EBS volume and every S3 bucket used for exports or logs
(`data-classification` other than the buckets already governed by SEC-004's
access-logging requirement, which is a security control with a cost
side-effect this SOP does not duplicate).

## Roles & Responsibilities (RACI)

| Activity | Platform/DevOps Engineer | FinOps Lead |
|---|---|---|
| Migrate gp2 → gp3 | R | A |
| Set snapshot retention policy | R | A |
| Configure bucket lifecycle rules | R | A |

## Definitions

- **gp3**: the current-generation General Purpose SSD EBS volume type,
  priced independently of provisioned IOPS/throughput unlike `gp2`, and
  typically 20% cheaper for equivalent baseline performance.
- **Orphaned snapshot**: an EBS snapshot whose source volume no longer
  exists and which is not referenced by any AMI.
- **Export/log bucket**: a bucket whose primary purpose is to receive
  generated exports, reports, or logs, identified by naming convention or
  the `application` tag ending in `-exports` / `-logs`.

## Policy Clauses

### COST-003-3.1 — Migrate gp2 volumes to gp3

```clause-meta
controls: [COST-WASTE-GP2]
prowler_checks: []
severity: low
default_action: manual_ticket
iac_managed_action: "terraform_pr:remediate_cost"
risk_tier: {non_prod: T1, prod: T1}
references: []
```

Every `gp2` EBS volume SHOULD be migrated to `gp3`. This is `manual_ticket`
rather than an SSM automation because the migration (via
`aws ec2 modify-volume`) is safe and online but benefits from a human
confirming the target IOPS/throughput match or exceed the workload's
current `gp2`-derived baseline before submitting the change.

### COST-003-3.2 — Snapshot retention and orphan cleanup

```clause-meta
controls: [COST-WASTE-ORPHAN-SNAPSHOT]
prowler_checks: []
severity: low
default_action: manual_ticket
iac_managed_action: "terraform_pr:remediate_cost"
risk_tier: {non_prod: T2, prod: T2}
references: [COST-002-2.2]
```

EBS snapshot retention MUST NOT exceed 90 days unless referenced by an AMI
in active use, and orphaned snapshots (Definitions, above) MUST be removed.
Deletion is T2, consistent with COST-002-2.2's treatment of any storage
deletion — even though a snapshot is itself a backup artifact, deleting one
is still irreversible.

### COST-003-3.3 — Export/log buckets require lifecycle policies

```clause-meta
controls: []
prowler_checks: [s3_bucket_lifecycle_enabled]
severity: low
default_action: manual_ticket
iac_managed_action: "terraform_pr:remediate_cost"
risk_tier: {non_prod: T1, prod: T1}
references: []
```

Every export/log bucket MUST have at least one lifecycle rule that either
expires or transitions objects to a cheaper storage class within a bounded
time window (Meridian's default: expire after 180 days unless the bucket's
owner documents a longer regulatory retention requirement).

## Procedures

1. List gp2 volumes: `aws ec2 describe-volumes --filters
   Name=volume-type,Values=gp2`.
2. Identify orphaned snapshots: `aws ec2 describe-snapshots
   --owner-ids self` cross-referenced against `aws ec2 describe-volumes`
   and `aws ec2 describe-images --owners self` (AMI block device mappings).
3. Check a bucket's lifecycle configuration:
   `aws s3api get-bucket-lifecycle-configuration --bucket <name>`.

## Exceptions

A bucket with a documented regulatory retention requirement exceeding 180
days is not an exception in the SHARED-003 sense — its lifecycle rule
should simply reflect the longer, documented retention period and still
satisfy COST-003-3.3 (having *a* bounded lifecycle rule, not specifically
the 180-day default).

## Compliance Mapping

| Clause | Security Hub / Prowler | Internal rule |
|---|---|---|
| COST-003-3.1 | — | COST-WASTE-GP2 |
| COST-003-3.2 | — | COST-WASTE-ORPHAN-SNAPSHOT |
| COST-003-3.3 | s3_bucket_lifecycle_enabled | — |

## Revision History

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2025-04-01 | Initial gp2→gp3 and snapshot-retention clauses |
| 1.1.0 | 2025-11-01 | Added export/log bucket lifecycle clause |
