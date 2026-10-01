# 0002 — Step Functions Standard orchestrating Lambda, LangGraph inside each Lambda

## Status

Accepted.

## Context

The weekly review has two shapes of long-running state: a **batch
pipeline** (collect → analyze N domain batches in parallel → aggregate →
publish, minutes-scale) and a **human-approval wait** (an action sits
`AWAITING_APPROVAL` for up to `approvals.expiry_days`, days-scale, possibly
spanning a Lambda cold start or two). Neither shape is naturally expressed
in a single mechanism.

Alternatives considered: a single long-running LangGraph process on a
compute resource that stays up (rejected — needs a VPC/EC2/ECS presence
this design deliberately avoids); driving the whole pipeline
from Step Functions' own state (rejected — Step Functions' native state
manipulation is far more verbose than a graph library for the retrieve →
triage → recommend → policy sequence, and doesn't have LangGraph's
`interrupt`/`Command` primitives for the approval wait at all).

## Decision

**Step Functions Standard** (not Express — see the cost note below) is the
outer orchestrator: `InitRun → Collect → Map(DomainBatch) → Aggregate →
Publish`, each state a thin Lambda handler. **LangGraph runs inside each
Lambda invocation** for the two graphs that actually need graph semantics:
the domain agent graph (`retrieve → triage → recommend → policy`, no
checkpointer — stateless within one batch) and the action graph
(`interrupt()`-based approval wait, checkpointed in DynamoDB via
`langgraph-checkpoint-aws`, resumable across Lambda invocations days apart).

Step Functions Standard, not Express, because: Express is billed per
invocation/duration, while Standard's per-transition pricing is negligible
at a weekly need of ~15–35 transitions; and Express's 5-minute execution cap is a poor fit even ignoring cost,
since the approval wait can span days (handled entirely by the DynamoDB
checkpointer, outside the state machine's own execution lifetime — the
action graph's Lambda invocations are short, triggered on demand by Slack
interactions, not one long Step Functions execution sitting idle).

## Consequences

- The state machine itself never "waits" for a human — `Aggregate` starts
  action-graph threads and finishes; the state machine execution ends.
  Approval happens entirely through `slack_handler` → `action_worker`
  Lambda invocations against the checkpointed graph, decoupled from any
  Step Functions execution.
- Business logic lives in pure `steps/*.py` functions that the thin
  `handlers/*.py` Lambda shims call, so each state is unit-testable
  without a Step Functions emulator.
- Two different state-management stories (Step Functions' own state vs.
  LangGraph's checkpointer) is more moving parts than one — accepted
  because each is used for the shape of state it's actually good at.
