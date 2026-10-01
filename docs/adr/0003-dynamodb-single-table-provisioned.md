# 0003 — DynamoDB single-table design, provisioned capacity only

## Status

Accepted.

## Context

The system needs to persist seven distinct entity types (findings, action
plans, approvals, locks, exceptions, audit events, month-to-date LLM
spend) plus LangGraph's own checkpoint state. Traffic is a
weekly batch plus occasional approval clicks — low, predictable and bursty
only at run time — which suits small **provisioned** capacity better than
on-demand pricing.

Alternatives considered: one table per entity type (rejected — each table
would need its own provisioned capacity, and one table sized to the actual
combined access pattern is simpler to reason about and cheaper); on-demand
mode for simplicity (rejected — the load is predictable, so provisioned is
cheaper and throttling is bounded by the retry policy below).

## Decision

Two tables, both single-table designs, both PROVISIONED:

- `${NAME_PREFIX}-state` at 8 RCU/8 WCU plus one GSI (`GSI1`) at 3 RCU/3
  WCU — every application entity in the README's single-table design
  table, keyed by `pk`/`sk`, with GSI1 powering the one cross-entity query
  this system needs (finding-by-status, for the RESOLVED-reconciliation
  sweep).
- `${NAME_PREFIX}-checkpoints` at 6 RCU/6 WCU, schema entirely owned by
  `langgraph-checkpoint-aws`'s `DynamoDBSaver` (`PK`/`SK`/`ttl` — verified
  against the installed 1.2.3 wheel's source, see
  the README's Troubleshooting section).

Combined: 17 RCU and 17 WCU.

## Consequences

- Every new entity this system ever needs must fit the existing `pk`/`sk`
  (+ GSI1) access patterns, or the provisioned capacity needs re-sizing.
- No auto-scaling, no on-demand burst capacity — a sustained spike beyond
  provisioned throughput throttles (handled by `aws/clients.py`'s adaptive
  retry mode, max 10 attempts) rather than silently costing more.
- Tests run these access patterns against `moto`, which stays a dev-only
  dependency never reachable from `src/` code that ships to Lambda.
