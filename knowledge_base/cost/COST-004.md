---
sop_id: COST-004
title: Cost Anomaly Detection and Budget Governance
domain: cost
version: 1.1.0
owner: finops@meridianretailtech.example
effective_date: 2026-01-15
review_cycle_days: 180
applies_to: [dev, staging, prod]
references: [SHARED-001]
---

## Purpose

Defines how Meridian Retail Technologies reacts to unexpected spend: the
triage SLA for AWS Cost Anomaly Detection alerts, the budget threshold
escalation path, and the service-level spend-trend review that catches
gradual drift a single-day anomaly detector would miss.

## Scope

Applies to every AWS Cost Anomaly Detection alert and every AWS Budgets
notification for accounts in scope, and to the weekly per-service spend
trend the Cost Explorer collector computes.

## Roles & Responsibilities (RACI)

| Activity | Application Owner | Platform/DevOps Engineer | FinOps Lead |
|---|---|---|---|
| Triage a cost anomaly | C | R | A |
| Classify anomaly as expected/unexpected | I | C | A/R |
| Respond to a budget threshold alert | I | C | A/R |
| Review service spend trends weekly | I | I | A/R |

## Definitions

- **Cost anomaly**: an AWS Cost Anomaly Detection alert — a statistically
  unusual spend pattern for a monitored cost dimension (Meridian monitors
  by SERVICE).
- **Expected spend**: an anomaly the FinOps Lead can attribute to a known
  cause (a planned load test, a seasonal promotion, a deliberate capacity
  increase) within the triage SLA.
- **Spend trend**: week-over-week percentage and absolute change in a
  single service's spend, computed from up to 2 Cost Explorer calls per
  run (a hard cap).

## Policy Clauses

### COST-004-4.1 — Cost anomalies triaged within one business day

```clause-meta
controls: [COST-ANOMALY]
prowler_checks: []
severity: medium
default_action: notify_owner
iac_managed_action: null
risk_tier: {non_prod: T0, prod: T0}
references: [SHARED-001-1.2]
```

Every Cost Anomaly Detection alert MUST be classified as expected or
unexpected spend within one business day of detection. This clause is
`notify_owner` / T0 — the system's job is to surface the anomaly with its
dollar impact and affected service promptly; classification requires human
business context (e.g. "yes, this is the Diwali sale traffic spike") this
system does not have.

### COST-004-4.2 — Budget thresholds and escalation

```clause-meta
controls: []
prowler_checks: []
severity: info
default_action: notify_owner
iac_managed_action: null
risk_tier: {non_prod: T0, prod: T0}
references: []
```

Every account MUST have budget alerts configured at 50%, 80%, and 100% of
the monthly gross budget (see
`infra/modules/cost_free`), escalating from the FinOps Lead (50/80%) to the
Engineering Manager (100%). A missing or misconfigured budget alert is
itself an Info-level finding surfaced in the weekly report.

### COST-004-4.3 — Service spend trend review

```clause-meta
controls: [COST-TREND]
prowler_checks: []
severity: low
default_action: notify_owner
iac_managed_action: null
risk_tier: {non_prod: T0, prod: T0}
references: []
```

Any service whose week-over-week spend increases by more than 20% **and**
more than $5 absolute MUST be reviewed by the FinOps Lead. Both thresholds
must be met — a 50% increase on a $2 service, or a 5% increase on a $500
service, does not trigger this clause, since neither represents a
materially actionable signal at Meridian's current scale.

## Procedures

1. Triage a cost anomaly: `aws ce get-anomalies --date-interval
   StartDate=<14d-ago>,EndDate=<today>` and cross-reference the affected
   service/linked account against recent deploys or marketing calendar
   events.
2. Verify budget configuration: `aws budgets describe-budgets
   --account-id <id>`.
3. Compute a service spend trend manually: `aws ce get-cost-and-usage
   --time-period Start=<7d-ago>,End=<today> --granularity DAILY --metrics
   UnblendedCost --group-by Type=DIMENSION,Key=SERVICE`, compared against
   the prior 7-day window.

## Exceptions

A recurring, well-understood seasonal anomaly (e.g. a known monthly batch
job) does not require a repeated SHARED-003 exception each time it fires —
instead, the FinOps Lead documents it once in Cost Anomaly Detection's own
"expected" annotation, external to this SOP's exception mechanism.

## Compliance Mapping

| Clause | Internal rule | Notes |
|---|---|---|
| COST-004-4.1 | COST-ANOMALY | FinOps-only, no Security Hub mapping |
| COST-004-4.2 | — | Budget governance, process control |
| COST-004-4.3 | COST-TREND | FinOps-only |

## Revision History

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2025-04-05 | Initial anomaly triage SLA |
| 1.1.0 | 2025-12-01 | Added budget escalation and spend-trend clauses |
