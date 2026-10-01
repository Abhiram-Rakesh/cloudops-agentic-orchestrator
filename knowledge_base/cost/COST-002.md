---
sop_id: COST-002
title: Compute and Storage Waste Elimination
domain: cost
version: 1.2.0
owner: finops@meridianretailtech.example
effective_date: 2026-01-15
review_cycle_days: 180
applies_to: [dev, staging, prod]
references: [SHARED-001, SHARED-002]
---

## Purpose

Defines the deterministic waste checks Meridian Retail Technologies runs
weekly against compute and storage: idle non-production instances,
unattached EBS volumes, unassociated Elastic IPs, and over-provisioned
instances. These are the highest-signal, lowest-controversy cost findings —
resources that are, by definition, not doing useful work.

## Scope

Applies to every EC2 instance, EBS volume, and Elastic IP in every account
in scope. "Idle" and "unattached" are evaluated over a rolling 7-day
lookback by default (configurable per environment — the demo stack uses a
1-hour lookback, since it is ephemeral and torn down well within a week).

## Roles & Responsibilities (RACI)

| Activity | Application Owner | Platform/DevOps Engineer | FinOps Lead |
|---|---|---|---|
| Confirm an instance is safe to stop | R | C | I |
| Execute stop/release/snapshot-delete actions | I | R | A |
| Rightsize an over-provisioned instance | R | C | A |

## Definitions

- **Idle instance**: average CPU utilization < 5% and network throughput
  < 5 MB/day over the lookback window.
- **Unattached EBS volume**: a volume with no `Attachments` entries.
- **Unassociated Elastic IP**: an EIP with no `AssociationId`.
- **Over-provisioned**: AWS Compute Optimizer reports a "Optimize" or
  "Not-optimized" finding with a smaller recommended instance type, based on
  at least 14 days of utilization data.

## Policy Clauses

### COST-002-2.1 — Idle non-production instances stopped or rightsized

```clause-meta
controls: [COST-WASTE-IDLE-EC2]
prowler_checks: []
severity: medium
default_action: "ssm_automation:CloudOps-StopInstance"
iac_managed_action: "terraform_pr:remediate_cost"
risk_tier: {non_prod: T1, prod: T1}
references: []
```

Any non-production instance meeting the Idle definition above for the full
lookback window MUST be stopped or rightsized. This clause never applies to
`environment=prod` resources automatically — an idle production instance is
reported (COST-002-2.4 territory) but never auto-stopped, since production
idleness can be intentional (e.g. disaster-recovery standby capacity).

### COST-002-2.2 — Unattached EBS volumes snapshotted and deleted

```clause-meta
controls: [COST-WASTE-UNATTACHED-EBS]
prowler_checks: []
severity: medium
default_action: "ssm_automation:CloudOps-SnapshotAndDeleteVolume"
iac_managed_action: "terraform_pr:remediate_cost"
risk_tier: {non_prod: T2, prod: T2}
references: [SHARED-002-2.5]
```

An EBS volume unattached for more than 7 days MUST be snapshotted, then
deleted. This is T2 even in non-production because deletion is
irreversible without the snapshot, and per SHARED-002-2.5's automation
boundary on "data deletion without backup," the snapshot step is mandatory
and verified before the delete step runs — `CloudOps-SnapshotAndDeleteVolume`
fails closed if the snapshot step does not report success.

### COST-002-2.3 — Unassociated Elastic IPs released

```clause-meta
controls: [COST-WASTE-UNASSOCIATED-EIP, EC2.12]
prowler_checks: [ec2_elastic_ip_unassigned]
severity: low
default_action: "ssm_automation:CloudOps-ReleaseEIP"
iac_managed_action: "terraform_pr:remediate_cost"
risk_tier: {non_prod: T1, prod: T1}
references: []
```

An Elastic IP unassociated for more than 24 hours MUST be released. This
carries both an internal cost rule ID and a Security Hub control
(EC2.12 — unused EIPs are also a minor security-hygiene signal, since a
released-then-reused IP can carry reputation history) but is treated as a
cost finding for reporting purposes.

### COST-002-2.4 — Over-provisioned instances rightsized

```clause-meta
controls: [COST-OVERPROVISIONED]
prowler_checks: []
severity: medium
default_action: manual_ticket
iac_managed_action: manual_ticket
risk_tier: {non_prod: T1, prod: T2}
references: []
```

An instance Compute Optimizer identifies as over-provisioned MUST be
rightsized. This is always `manual_ticket`, even when `iac_managed=true` —
changing an instance type is a capacity-planning decision that benefits
from a human reviewing the Compute Optimizer recommendation's confidence
level, not a mechanical Terraform diff. If Compute Optimizer has
insufficient data (e.g. an instance younger than 14 days, or the demo
stack's short-lived instances), this check is skipped gracefully rather
than producing a false "not over-provisioned" finding.

## Procedures

1. Identify idle instances:
   `aws cloudwatch get-metric-statistics --namespace AWS/EC2 --metric-name
   CPUUtilization --dimensions Name=InstanceId,Value=<id> --start-time
   <7d-ago> --end-time <now> --period 86400 --statistics Average`.
2. Identify unattached volumes: `aws ec2 describe-volumes --filters
   Name=status,Values=available`.
3. Identify unassociated EIPs: `aws ec2 describe-addresses --query
   "Addresses[?AssociationId==null]"`.
4. Check Compute Optimizer: `aws compute-optimizer
   get-ec2-instance-recommendations --instance-arns <arn>`.

## Exceptions

An intentionally idle non-production instance (e.g. a warm standby for a
disaster-recovery drill) requires a SHARED-003 exception with a
compensating control describing the business justification and a review
date no more than 90 days out.

## Compliance Mapping

| Clause | Security Hub / Prowler | Internal rule | Notes |
|---|---|---|---|
| COST-002-2.1 | — | COST-WASTE-IDLE-EC2 | FinOps-only, no Security Hub mapping |
| COST-002-2.2 | — | COST-WASTE-UNATTACHED-EBS | FinOps-only |
| COST-002-2.3 | EC2.12 | COST-WASTE-UNASSOCIATED-EIP, ec2_elastic_ip_unassigned | Dual cost/security signal |
| COST-002-2.4 | — | COST-OVERPROVISIONED | FinOps-only |

## Revision History

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2025-03-08 | Initial idle-instance and unattached-EBS clauses |
| 1.1.0 | 2025-09-10 | Added unassociated-EIP and over-provisioned clauses |
| 1.2.0 | 2026-01-15 | Clarified snapshot-before-delete is fail-closed |
