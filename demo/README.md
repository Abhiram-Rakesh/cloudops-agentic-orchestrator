# Demo stack — `orders-demo`

A small, **ephemeral** Terraform stack (`demo/infra`) with deliberate,
safe-by-construction SOP violations, so the CloudOps agents have something
real to find, triage, and (with human approval) fix. It is a fictional
"orders" service belonging to *Meridian Retail Technologies* — see
`knowledge_base/README.md`.

Every violation is cataloged in
[`tests/fixtures/scenario_demo/demo_matrix.yaml`](../tests/fixtures/scenario_demo/demo_matrix.yaml)
(the single source of truth) and rendered to
[`docs/VIOLATIONS.md`](docs/VIOLATIONS.md) by `scripts/gen_demo_artifacts.py`
— never hand-edit either the matrix's generated outputs or `demo/infra`
directly to "fix" a finding. That is the orchestrator's job, via a reviewed
agent PR (`remediation/terraform_pr.py`) or an approved SSM automation run.

## Tagging convention

Every *compliant* demo resource carries:

| Tag | Value |
|---|---|
| `owner` | `orders-team` |
| `cost-center` | `CC-2040` |
| `environment` | `dev` |
| `application` | `orders` |
| `app` | `orders-demo` |
| `managed-by` | `terraform` |

`environment`/`application`/`app`/`managed-by` are set once via the
provider's `default_tags` (never violated). `owner`/`cost-center` are set
per resource instead, since several resources deliberately omit one as
their own SOP violation — see the matrix's `notes` column.

## Lifecycle

```
make demo-up          # terraform apply (human only, local AWS credentials)
make drift             # CONFIRM=yes make drift — simulate_clickops.sh's 4 ClickOps changes
make reset-drift       # revert those 4 changes without touching Terraform state
make seed-guardduty    # seed GuardDuty sample findings (trial period only)
make demo-down         # terraform destroy (human only)
```

- **`demo-up`**: applies `demo/infra` with the default variable values —
  `enable_idle_instance=false`, `enable_public_bucket_violation=false` —
  and sets the `demo_state` SSM parameter to `up` so `demo-apply.yml`
  knows the stack exists. Pass `-var enable_idle_instance=true` /
  `-var enable_public_bucket_violation=true` to exercise those two extra
  scenarios.
- **`drift`**: runs `demo/scripts/simulate_clickops.sh`, which makes 4
  changes directly via the AWS CLI (never through Terraform) — see the
  matrix's `post_clickops` rows for exactly what each one triggers.
- **`demo-down`**: destroys everything and sets `demo_state` back to
  `down`, so the weekly review skips demo-specific staleness warnings and
  `demo-apply.yml` refuses to run.

## CI/CD

- **`demo-plan.yml`** (PR touching `demo/**`): fmt/validate/tflint, plans
  with the `DEMO_PLAN_ROLE_ARN` OIDC role, comments the plan on the PR, and
  marks an agent's draft PR ready for review once green.
- **`demo-apply.yml`** (push to `main` touching `demo/infra/**`, or
  `workflow_dispatch` with `{action_id, plan_hash, reason}` for a
  `terraform_revert_dispatch` action): skips entirely if `demo_state=down`;
  on a dispatch, verifies the approval record in DynamoDB before applying.
  This is the human-approval-gated path an agent's PR or a revert action
  ultimately goes through — the agent itself never runs `terraform apply`.

## Why ephemeral

The whole point of `demo/` is that it costs nothing when it isn't up. Tear
it down (`make demo-down`) between demo sessions — nothing in the
orchestrator depends on it existing, and the fixture-backed test suite
never touches a live account.
