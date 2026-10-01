---
sop_id: SHARED-001
title: Severity Definitions and Remediation SLAs
domain: shared
version: 1.2.0
owner: cloud-security@meridianretailtech.example
effective_date: 2026-01-15
review_cycle_days: 180
applies_to: [dev, staging, prod]
references: []
---

## Purpose

This document defines the single severity scale used across every domain —
Security, Cost and Drift — at Meridian Retail Technologies, the remediation
service-level agreements (SLAs) attached to each severity level, and the
deterministic modifiers that raise a finding's severity based on exposure,
environment and data sensitivity. Every other SOP in this knowledge base
references this document rather than redefining severity locally, so that
"High" means the same thing whether it comes from a security control
failure, a cost anomaly, or an unauthorized infrastructure change.

## Scope

Applies to every finding produced by the CloudOps Agentic Orchestrator,
across all AWS accounts and regions in scope, and to every human reviewer
who triages a finding manually. It does not apply to findings explicitly
scoped as informational-only telemetry (see SHARED-001-1.1, Info level).

## Roles & Responsibilities (RACI)

| Activity | Cloud Security Lead | Platform/DevOps Engineer | Engineering Manager | CISO |
|---|---|---|---|---|
| Define/revise severity scale | A | C | C | R |
| Apply severity modifiers in tooling | R | C | I | I |
| Approve SLA exceptions | C | I | C | A |
| Report SLA compliance | R | I | A | I |

(R = Responsible, A = Accountable, C = Consulted, I = Informed)

## Definitions

- **Finding**: a normalized record of a policy violation, cost anomaly, or
  infrastructure drift, produced by a collector and deduplicated by
  fingerprint.
- **Exposure**: whether a resource is reachable from the public internet
  (public IP, a security group or NACL permitting `0.0.0.0/0`/`::/0`, or a
  publicly readable/writable S3 bucket).
- **Data classification**: the sensitivity tag (`public`, `internal`,
  `confidential`, `restricted`) Meridian applies to data-bearing resources
  per the Data Classification Standard (external to this knowledge base).
- **SLA clock**: starts at `first_seen` (when the finding was first
  detected), not when a human first reviews it.

## Policy Clauses

### SHARED-001-1.1 — Severity scale

```clause-meta
controls: []
prowler_checks: []
severity: null
default_action: null
iac_managed_action: null
risk_tier: {}
references: []
```

Every finding MUST be assigned exactly one of the following five severity
levels. Agents and human reviewers MUST use this scale; no other five-point
or CVSS-style scale may substitute for it in this system.

| Level | Weight | Meaning | Example |
|---|---|---|---|
| Critical | 100 | Confirmed or near-certain exposure of customer data, credentials, or unrestricted account takeover paths | An IAM policy granting `"Action": "*", "Resource": "*"` attached to a role assumable from outside the account; a public S3 bucket containing a `data-classification=restricted` object |
| High | 40 | Exploitable weakness with a plausible attack path, or a confirmed security-control gap on an internet-facing resource | A security group allowing SSH (22) from `0.0.0.0/0` on an instance with a public IP; account-level S3 Block Public Access disabled |
| Medium | 15 | A control gap that requires an additional condition to be exploitable, or a moderate, correctable cost/drift issue | Default VPC security group not restricting all traffic; an EBS volume without encryption that is not internet-reachable |
| Low | 5 | Best-practice deviation with limited blast radius | A gp2 volume that should be gp3; missing S3 server access logging |
| Info | 1 | No action required; reporting/context only | A cost anomaly already explained by a known seasonal promotion |

### SHARED-001-1.2 — Remediation SLAs

```clause-meta
controls: []
prowler_checks: []
severity: null
default_action: null
iac_managed_action: null
risk_tier: {}
references: [SHARED-003-3.2]
```

Every OPEN finding MUST be remediated, or have an approved exception on file
(SHARED-003), within the following window measured from `first_seen`:

| Severity | SLA |
|---|---|
| Critical | 24 hours |
| High | 7 days |
| Medium | 30 days |
| Low | 90 days |
| Info | No SLA — reviewed at the discretion of the domain owner |

A finding that breaches its SLA without an approved exception MUST be
escalated to the Engineering Manager for the owning team and noted in the
next weekly report's executive summary.

### SHARED-001-1.3 — Severity modifiers

```clause-meta
controls: []
prowler_checks: []
severity: null
default_action: null
iac_managed_action: null
risk_tier: {}
references: []
```

The base severity in a domain SOP's clause catalog (e.g. SEC-002-2.1 is
"high") MUST be adjusted upward, one level at a time, applying each modifier
below that matches, before the finding is triaged:

1. **+1 level** if the resource is internet-exposed (SHARED-001 Definitions).
2. **+1 level** if the resource's `environment` tag is `prod` or
   `production`.
3. **+1 level** if the resource's `data-classification` tag is
   `confidential` or `restricted`.

Modifiers are cumulative but the result is capped at Critical — a Medium
finding with all three modifiers applied is Critical, not "Critical+2".
Modifiers MUST NOT lower severity; a finding with no applicable modifier
keeps its base severity from the domain SOP. This computation is
deterministic and implemented in code (`policy/engine.py` /
`report/priority.py`), not left to LLM judgment — an LLM triaging a finding
may cite this clause to justify an `adjusted_severity` but the numeric
outcome MUST match the deterministic calculation.

## Procedures

1. A collector normalizes a raw signal into a `Finding` with a base
   `severity` sourced from the owning domain SOP's clause catalog.
2. The normalization pipeline (`normalize/`) applies SHARED-001-1.3's
   modifiers deterministically based on `resource_tags`, exposure evidence,
   and any public-IP/public-bucket evidence collected.
3. The SLA clock (SHARED-001-1.2) starts at `first_seen` and is visible in
   the weekly report's per-item age.
4. To manually verify a resource's public exposure during triage:
   `aws ec2 describe-security-groups --group-ids <id> --query
   "SecurityGroups[].IpPermissions[?contains(IpRanges[].CidrIp,
   '0.0.0.0/0')]"` (security groups) or `aws s3api get-public-access-block
   --bucket <name>` (S3 buckets).

## Exceptions

SLA breaches may be covered by a SHARED-003 exception. A Critical SLA
breach exception additionally requires CISO approval per SEC-006-6.3.
Severity modifiers themselves are not exception-eligible — they are a
computation, not a judgment call.

## Compliance Mapping

This document defines cross-cutting policy and does not map to individual
Security Hub controls. Its correct application is a precondition for every
control mapped in SEC-001 through SEC-005, COST-001 through COST-005, and
DRIFT-001 through DRIFT-004.

## Revision History

| Version | Date | Change |
|---|---|---|
| 1.0.0 | 2025-03-01 | Initial severity scale (Critical/High/Medium/Low) |
| 1.1.0 | 2025-08-12 | Added Info level; added SLA table |
| 1.2.0 | 2026-01-15 | Added exposure/prod/data-classification modifiers (SHARED-001-1.3) |
