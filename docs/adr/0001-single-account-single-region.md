# 0001 — Single AWS account, one region

## Status

Accepted. Amended 2026-10-01: the original rationale was staying inside
the AWS Free plan. The project has since left it (it now uses Bedrock Titan
embeddings and other paid services), so the decision stands on simplicity
and blast radius alone; the free-plan resource guardrail was removed.

## Context

This project needs somewhere to run that a solo builder or small team can
operate cheaply and understand end to end.

Alternatives considered: a multi-account setup (dev/staging/prod, or a
dedicated security-tooling account) with cross-account roles; a multi-region
deployment for resilience.

## Decision

One AWS account, one region (`ap-south-1`), one environment (`dev`).

## Consequences

- No blast-radius isolation between "the orchestrator's own infra" and
  "the accounts it scans" — mitigated by `collectors/` assuming a
  cross-account reader role per configured account (`aws.accounts` in
  `config/settings.dev.yaml`), so a real multi-account setup is a config
  change, not a redesign.
- Single-region means no DR story beyond "redeploy from Terraform + the
  Git-tracked knowledge base" — acceptable for a weekly-batch, human-
  approved system with no availability SLA.
