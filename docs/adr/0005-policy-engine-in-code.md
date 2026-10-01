# 0005 — Every safety decision is a deterministic code path, never an LLM judgment

## Status

Accepted.

## Context

An LLM triaging findings and proposing remediations is inherently exposed
to untrusted input: a finding's title, description, and resource tags all
originate from the cloud account being scanned (or, indirectly, from
whoever can set a tag on a resource there). A sufficiently crafted tag
value could try to talk the model into proposing an unsafe action — and
even without any adversarial intent, a model can simply be wrong about
whether a resource is IAM, protected, or IaC-managed.

Alternatives considered: trust the model's own stated risk assessment and
spot-check it after the fact (rejected — after-the-fact review doesn't
prevent an unsafe automated action from having already executed); rely on
prompt engineering alone to resist injection (rejected as insufficient on
its own — prompts can reduce but not guarantee resistance, and this system
needs a guarantee for the automation boundary specifically).

## Decision

`policy/engine.py::evaluate_recommendation` recomputes every safety-
relevant fact from the `Finding` objects themselves — `resource_type`
string prefix (`is_iam_kms_org`), resource tags (`is_protected`),
`iac_managed` boolean, the action's own parameters against an allowlist
schema — and only ever **raises** the effective risk tier above what the
model proposed, never lowers it. A rejection always downgrades to
`manual_ticket`/T3 with a recorded reason. The model's proposal is
advisory input to this function, never a trusted assertion about safety.

## Consequences

- A compromised or wrong model output can, at worst, cause an unnecessary
  manual ticket (over-cautious) — it cannot cause an unsafe automated
  action, because the code path that decides "was this OK to automate"
  never reads the model's own opinion of its safety.
- Every rule in this function needs a table-driven unit test
  exercising it against a genuinely adversarial or edge-case input, so a
  regression here fails the suite rather than relying on code-review-time
  judgment.
- This means the policy engine is the single most important module in the
  codebase to keep simple, total (no exceptions escape it — it always
  returns a valid `Recommendation`, never raises), and exhaustively tested.
  New action types or new resource categories must extend this function's
  rules explicitly, not be assumed safe by omission.
