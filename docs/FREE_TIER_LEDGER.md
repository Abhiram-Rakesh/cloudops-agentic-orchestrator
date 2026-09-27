# AWS Free-Plan Ledger

Every AWS resource defined anywhere under `infra/` (the orchestrator) or
`demo/infra` (the ephemeral demo stack) must have a row here: what it is, what
free allowance it draws on, expected usage at the locked weekly schedule
(Monday 08:45 IST review run + Monday 07:30/08:00 IST scanner workflows), and
expected monthly cost. `tests/infra/test_free_plan_guardrails.py` enforces the
*forbidden resource list* (Hard Rule #8) automatically; it does not enforce
that this document is complete — that is a review discipline, not a test.

Allowance legend: **AF** = always-free (never expires), **CR** = covered by
the 12-month / $200-ish signup credits on an account created after
2025-07-15 (stops being free once credits or the 6-month window run out,
whichever first), **PAID** = intentionally small paid usage accepted as cost
of the design.

This document is filled in progressively as each Terraform module is built
(Milestone M7) and finalized in `docs/COSTS.md` / Milestone M9. See
`docs/COSTS.md` for the rolled-up monthly total and `docs/DESIGN.md §2.3` for
the locked cost assumptions.

## Orchestrator (`infra/`)

| Service / resource | Allowance | Expected usage (weekly schedule) | Expected monthly cost | Ledger status |
|---|---|---|---|---|
| _(filled in as each `infra/modules/*` is built — see table below for progress)_ | | | | |

## Demo stack (`demo/infra`)

| Service / resource | Allowance | Expected usage | Expected monthly cost | Ledger status |
|---|---|---|---|---|
| _(filled in with Milestone M8 — demo is ephemeral, only "up" during a demo session)_ | | | | |

## Module build progress

| Module | Status |
|---|---|
| `infra/bootstrap` | pending (M7) |
| `infra/modules/data` | pending (M7) |
| `infra/modules/lambdas` | pending (M7) |
| `infra/modules/orchestration` | pending (M7) |
| `infra/modules/slack_endpoint` | pending (M7) |
| `infra/modules/iam` | pending (M7) |
| `infra/modules/remediation` | pending (M7) |
| `infra/modules/security_trial` | pending (M7) |
| `infra/modules/security_free` | pending (M7) |
| `infra/modules/cost_free` | pending (M7) |
| `infra/modules/observability` | pending (M7) |
| `demo/infra` | pending (M8) |
