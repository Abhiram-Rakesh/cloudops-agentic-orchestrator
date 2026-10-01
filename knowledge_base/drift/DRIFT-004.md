---
sop_id: DRIFT-004
title: Drift Detection Cadence, Evidence and Attribution
domain: drift
version: 1.1.0
owner: platform@meridianretailtech.example
effective_date: 2026-01-15
review_cycle_days: 180
applies_to: [dev, staging, prod]
references: [DRIFT-001, DRIFT-002, DRIFT-003, SHARED-004]
---

## Purpose

Defines the operational backbone the other three drift SOPs depend on: how
often drift detection runs, how long plan evidence is retained for audit
and dispute resolution, the requirement that every drift finding carry
CloudTrail-based attribution, and the reporting-only treatment of drift on
protected resources.

## Scope

Applies to the `drift.yml` GitHub Actions workflow, the S3 evidence it
produces, and every `DRIFT-ATTR`/`DRIFT-UNMANAGED` finding this system
generates.

## Roles & Responsibilities (RACI)

| Activity | Platform/DevOps Engineer | Cloud Security Lead |
|---|---|---|
| Maintain the drift detection schedule | R | I |
| Maintain evidence retention lifecycle rules | R | C |
| Ensure CloudTrail coverage for attribution | R | A |

## Definitions

- **Drift detection run**: one execution of `terraform plan -refresh-only`
  against a workspace, producing a plan JSON and an inventory JSON.
- **Plan evidence**: the plan JSON, inventory JSON, and any CloudTrail
  excerpt gathered for attribution, stored under `s3://.../drift/<run_id>/`.

## Policy Clauses

### DRIFT-004-4.1 — Detection runs at least daily

```clause-meta
controls: []
prowler_checks: []
severity: null
default_action: null
iac_managed_action: null
risk_tier: {}
references: [DRIFT-001-1.2]
```

Drift detection MUST run at least once every 24 hours for every workspace
in scope. Meridian's current schedule runs `drift.yml` weekly (Monday 08:00
Asia/Kolkata, ahead of the Monday 08:45 review run) plus on-demand via
`workflow_dispatch` (`make drift`) immediately after any known break-glass
change — the weekly cadence is an interim measure, tracked as
a documented gap against this clause's "at least daily" target rather than
silently claimed as compliant (see the README's AWS cost estimate section's discussion of
GitHub Actions minutes budget).

### DRIFT-004-4.2 — Plan evidence retained 90 days

```clause-meta
controls: []
prowler_checks: []
severity: null
default_action: null
iac_managed_action: null
risk_tier: {}
references: []
```

Plan evidence (Definitions, above) MUST be retained for at least 90 days
from the run that produced it, to support audit and any later dispute about
what a given drift finding actually showed. The artifact bucket's lifecycle
rule for the `drift/` prefix is set to 60 days at initial deployment — this
is a **documented gap against this clause pending a lifecycle rule
correction**, tracked as an open item rather than silently
assumed compliant; correcting it costs a negligible amount of additional S3
storage (see the README's Troubleshooting section).

### DRIFT-004-4.3 — CloudTrail attribution required

```clause-meta
controls: []
prowler_checks: [cloudtrail_multi_region_enabled]
severity: null
default_action: null
iac_managed_action: null
risk_tier: {}
references: [SEC-004-4.1]
```

Every drift finding MUST carry, where determinable, the attributing
CloudTrail event: actor (IAM principal or masked identity), event name,
timestamp, and masked source IP. This is only possible when SEC-004-4.1's
multi-region trail with log file validation is in place and has not
expired its retention window relative to the drift's detection lag —
another reason SEC-004-4.1 is a prerequisite this SOP depends on rather
than duplicates.

### DRIFT-004-4.4 — Drift on protected resources is report-only

```clause-meta
controls: []
prowler_checks: []
severity: null
default_action: manual_ticket
iac_managed_action: manual_ticket
risk_tier: {non_prod: T3, prod: T3}
references: [SHARED-004-4.1, DRIFT-003-3.1]
```

Drift detected on a resource tagged `cloudops:protected=true` MUST be
reported with full detail (including attribution) but MUST NOT trigger an
automated revert or codify action — this is the same row already present
in DRIFT-003-3.1's decision table, restated here as its own clause because
protected-resource handling is referenced independently by
`tests/graph/` pipeline tests that check this behavior in isolation from
the rest of the decision table.

## Procedures

1. Verify the drift schedule is current: `gh workflow view drift.yml`
   confirms the cron expression matches `30 2 * * 1` (08:00 IST Monday).
2. Verify evidence retention: `aws s3api get-bucket-lifecycle-configuration
   --bucket <artifact-bucket> --query "Rules[?Filter.Prefix=='drift/']"`.
3. Verify CloudTrail coverage before trusting an attribution gap as
   genuine: confirm the trail's `StartLogging` predates the drift's
   estimated occurrence window, not just that the trail currently exists.

## Exceptions

The documented 60-day vs. 90-day lifecycle gap (DRIFT-004-4.2) and the
weekly-vs-daily cadence gap (DRIFT-004-4.1) are tracked as open items
against this SOP, not formal SHARED-003 exceptions — they are
implementation debt on this system's own rollout, not a
third-party finding being excepted.

## Compliance Mapping

| Clause | Internal rule | ISO 27001:2022 Annex A | SOC 2 CC |
|---|---|---|---|
| DRIFT-004-4.1 | — | A.8.32 | CC7.2 |
| DRIFT-004-4.2 | — | A.8.15 (log retention) | CC7.2 |
| DRIFT-004-4.3 | — | A.8.15 | CC7.2 |
| DRIFT-004-4.4 | — | A.5.9 | CC6.8 |

## Revision History

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2025-05-20 | Initial cadence and evidence-retention clauses |
| 1.1.0 | 2026-01-15 | Added attribution and protected-resource clauses; documented cadence/retention gaps |
