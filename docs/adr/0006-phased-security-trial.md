# 0006 — Phased security-services trial: Security Hub + GuardDuty + Config for ~30 days, then Prowler-only

## Status

Accepted.

## Context

Security Hub and GuardDuty both give new AWS accounts a free
30-day trial; AWS Config has no free trial at all and bills per
configuration item from day one (at low-cents volumes for this system's
narrow enabled resource-type list). Leaving Security Hub or GuardDuty
enabled past their trial windows converts them to a real per-check-
evaluation / per-GB-analyzed bill — not enormous, but not zero, and not
justified once a no-cost equivalent (Prowler,
running the same AWS Foundational Security Best Practices and CIS 3.0
checks via GitHub Actions) is available.

Alternatives considered: run Security Hub/GuardDuty/Config indefinitely and
accept the post-trial cost (rejected — an ongoing per-evaluation bill for
something Prowler already covers); run Prowler-only from day one, never
enabling the AWS-native services at all (rejected — the first ~30 days is
exactly the window to validate that `config/prowler_control_map.yaml`'s
Prowler-check-to-control mapping actually catches what Security Hub
catches, via the report's side-by-side coverage comparison; skipping this
comparison would mean flying blind on Prowler's actual coverage once it
becomes the *only* source).

## Decision

**Phase A** (day 0, first deploy): `enable_security_hub`, `enable_guardduty`,
`enable_config` all `true`; both the `security_hub` and `prowler`
collectors run every review, and the report includes a coverage-comparison
section. A day-25 scheduled reminder (`trial_reminder` Lambda) prompts
switchover before day 30. **Phase B** (`make trials-off`): all three
AWS-native flags flip to `false`, `collectors.security_hub.enabled: false`,
and two time-bound SHARED-003 exceptions are recorded for the two clauses
(SEC-004-4.2 GuardDuty, SEC-004-4.4 Config) that can no longer be
evaluated by a live finding.

## Consequences

- A real coverage gap exists in Phase B for anything Security Hub or
  GuardDuty catches that Prowler's AWS-FSBP/CIS-3.0 checks don't — this is
  accepted and documented (the two exceptions), not silently ignored.
- `SEC-005-5.4` (GuardDuty EC2 threat-response procedure) simply can't fire
  without a live GuardDuty detector in Phase B — per
  `knowledge_base/security/SEC-006.md` it is deliberately **not**
  exception-eligible (it's either resolved via a live finding or not
  exercised at all), so it is only covered by
  fixture-driven tests from that point forward.
  This is a real, accepted reduction in what runs against live data.
- `cloudops trials status` and `cloudops doctor`'s `security_trial` check
  both need to be re-run/re-checked periodically — nothing forces the
  switchover to actually happen at day 25; it's a reminder, not an
  automatic cutover, on the theory that a human should decide when, having
  reviewed the coverage-comparison data from Phase A.
