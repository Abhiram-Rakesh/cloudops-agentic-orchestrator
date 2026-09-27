# CloudOps Agentic Orchestrator (Free-Plan Edition)

A multi-agent CloudOps system — Security, Cost and Drift agents built on
LangGraph, running inside AWS Lambda orchestrated by AWS Step Functions —
that replaces a weekly dashboard review with one SOP-grounded report plus
downstream agents that execute **human-approved** remediation. Designed to
run inside the AWS Free plan (account created after 2025-07-15).

> **Status:** actively being built milestone by milestone (see
> `BUILD_PROMPT.md` for the full specification and
> [`docs/DESIGN.md`](docs/DESIGN.md) once it lands for the expanded
> architecture with diagrams). This README grows with each milestone; treat
> anything not yet described here as "not built yet," not "broken."

## Why

Security Hub, Cost Explorer and Terraform drift each have their own console.
Nobody enjoys triaging three dashboards every Monday, and manual remediation
is slow and inconsistent. This system collects from all three, reasons about
each finding against a written SOP (grounded, cited, never freelanced),
scores priority deterministically, and — only after a human clicks Approve
in Slack against a hash-pinned plan — executes the fix through the same path
a human would use (a Terraform PR, a scoped SSM document, or a ticket).

## Design principles

- **The LLM never holds write credentials.** It only ever produces a
  structured recommendation. See `docs/DESIGN.md` and CLAUDE.md.
- **IaC-first remediation.** Terraform-managed resources are only ever fixed
  through a PR or a pipeline re-apply, never a direct API call.
- **Policy in code.** The LLM can only ever *raise* a finding's risk tier,
  never lower it — a deterministic policy engine has the final say.
- **Free-plan-first.** Every AWS resource this repo defines is justified in
  `docs/FREE_TIER_LEDGER.md` and a CI test fails the build if a
  non-free-plan resource type sneaks into `infra/`.
- **Delta-based.** Stable fingerprints mean only *changed* findings ever
  reach an LLM call.

## Repository layout

See `BUILD_PROMPT.md §4` for the full target layout. In short:

- `src/cloudops_orchestrator/` — the orchestrator (Python 3.12, `uv`).
- `infra/` — Terraform for the orchestrator's own AWS resources.
- `demo/` — a small, ephemeral, **deliberately non-compliant** Terraform
  stack used to exercise the agents end to end (see `demo/README.md`).
- `knowledge_base/` — the SOP documents the agents are grounded on.
- `statemachine/`, `ssm_documents/`, `config/` — orchestration and policy
  configuration.
- `tests/`, `evals/` — unit/integration/pipeline tests and LLM-quality evals.
- `docs/` — architecture, setup, runbook, security, cost and ADR documents.

## Quickstart (local, fully offline)

```bash
uv python install 3.12
uv sync --frozen --all-extras
make lint typecheck test
make run-local        # produces out/report-<run_id>.html and .json from fixtures + a fake LLM
```

No AWS, Anthropic, Slack or GitHub credentials are needed for any of the
above — everything runs against `tests/fixtures/scenario_demo/` with a
deterministic fake LLM.

## Deploying for real

Not yet — this repo is mid-build. Once complete, `docs/SETUP.md` will carry
the exact human-run steps (bootstrap Terraform, Slack app, GitHub PAT,
`deploy.yml`, `make demo-up`). Nothing under `infra/` is ever applied by an
agent; every apply is a human-triggered GitHub Actions `workflow_dispatch`
run authenticated via OIDC.

## Free plan cost

Expected **≈$0–3/month** on AWS at the locked weekly schedule (plus ≈$0.3–2
per orchestrator run on Anthropic, and cents-per-session for the ephemeral
demo stack). See `docs/COSTS.md` and `docs/FREE_TIER_LEDGER.md` once they
land in Milestone M9 for the full breakdown, and
`docs/VERIFY_BEFORE_DEPLOY.md` for what a human should re-check before the
first real deploy.
