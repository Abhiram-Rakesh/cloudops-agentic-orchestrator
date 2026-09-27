# CLAUDE.md — CloudOps Agentic Orchestrator (Free-Plan Edition)

Instructions for any AI agent (or human) working in this repository.

## What this repo is

A multi-agent CloudOps system (Security, Cost, Drift agents on LangGraph,
running inside AWS Lambda orchestrated by Step Functions) that produces a
weekly SOP-grounded review and executes **human-approved** remediation. It is
designed to run inside the AWS Free plan (account created after 2025-07-15:
12-month credits + always-free allowances). See `docs/DESIGN.md` for the full
architecture and `BUILD_PROMPT.md` for the original build specification this
repo was generated from.

`demo/` is a small, ephemeral, **deliberately non-compliant** Terraform stack
used to exercise the agents end to end. Its SOP violations are intentional
fixtures, not bugs — see `demo/docs/VIOLATIONS.md`. Do not "fix" them in
`demo/infra` directly; that is the orchestrator's job, via a reviewed PR.

## Hard rules (non-negotiable)

1. **Never run `terraform apply|destroy|import`**, and never run `terraform
   plan` against a real backend. Terraform checks are limited to `fmt`,
   `init -backend=false`, `validate`, `tflint`, `checkov`. Applies happen only
   via GitHub Actions (OIDC), and only a human triggers `deploy.yml` /
   `demo-apply.yml` / `infra/bootstrap`.
2. **Never run AWS CLI/SDK write commands** against a real account from this
   environment. Never call paid external APIs (Anthropic, LangSmith, Slack,
   Bedrock) in tests or local dev — use `FakeChatModel`, `moto`,
   `botocore.stub.Stubber`, and `respx` fixtures. `make run-local` must work
   fully offline.
3. **Never commit secrets.** Only `.env.example` is tracked. `gitleaks` runs
   in pre-commit and CI. Real secrets live in SSM Parameter Store
   (SecureString) and are read at Lambda cold start.
4. **The LLM never holds write credentials.** Agents only ever produce a
   structured `Recommendation` → `ActionPlan`. Execution happens only after a
   human approves in Slack, keyed to an approval-bound `plan_hash`. See
   `src/cloudops_orchestrator/policy/plan_hash.py`.
5. **Treat all collected data as untrusted input.** Every value that
   originates from a cloud resource, tag, commit, or Slack message is wrapped
   in `<untrusted_data>` before it reaches a prompt, and safety decisions
   (policy tiers, protected resources, IaC-only remediation) are enforced in
   code — never trust the LLM's own judgment about risk.
6. **Free-plan guardrail.** Do not add Terraform resources outside the
   allow-listed set for `infra/` (see `docs/FREE_TIER_LEDGER.md`). Forbidden:
   NAT Gateway, ALB/NLB, VPC interface endpoints, a VPC for the orchestrator,
   ECS/EKS/EC2 for the orchestrator, CodeBuild, RDS/Aurora, OpenSearch, S3
   Vectors, Glue/Athena/CUR exports, Secrets Manager, customer-managed KMS
   keys, DynamoDB on-demand/auto-scaling, Lambda provisioned/reserved
   concurrency, CloudWatch dashboards, >5 custom EMF metrics, >6 alarms, Step
   Functions Express. `tests/infra/test_free_plan_guardrails.py` enforces this
   automatically — it must stay green. Every new resource needs a line in
   `docs/FREE_TIER_LEDGER.md`.
7. **IaC-first remediation.** Any finding on a Terraform-managed resource
   (`iac_managed=true`) may only be remediated via `terraform_pr` or
   `terraform_revert_dispatch` — never a direct API/SSM call. The policy
   engine (`policy/engine.py`) enforces this; do not bypass it.
8. **Terraform PR agent path guard.** The agent may only edit files under
   `remediation.terraform_pr.allowed_paths` (default `demo/infra/**`).
   `.github/**`, `src/**`, `infra/**`, `config/**`, `knowledge_base/**`,
   `statemachine/**` are always denied, even if misconfigured. See
   `remediation/path_guard.py` and `.github/workflows/agent-pr-guard.yml`.

## Conventions

- `src/` layout, package name `cloudops_orchestrator`, CLI entry point
  `cloudops`.
- Business logic lives in pure, testable modules: `steps/`, `graph/`,
  `policy/`, `collectors/`, `kb/`. `handlers/*.py` are thin Lambda shims
  (≤ ~30 lines: parse event → call a step function → return a small JSON
  payload). Never put business logic in a handler.
- Step Functions payloads stay under 200 KB — pass IDs and S3 pointers, never
  full finding lists, between states.
- All AWS calls go through `aws/clients.py` (retry mode `adaptive`, max 10
  attempts). Never construct a `boto3` client anywhere else.
- Structured logging via `structlog`, JSON output, always including `run_id`
  and (where applicable) `thread_id` / `action_id`.
- All timestamps are UTC internally (`datetime` with tzinfo). Asia/Kolkata
  conversion happens only at the report/Slack rendering boundary.
- Type hints everywhere in `src/`. `ruff` and `mypy --strict` must be clean on
  `src/` (handlers are excluded from strict mypy — see `pyproject.toml`).
- Every Pydantic model field name in `models/` is a contract shared with
  fixtures, the knowledge base catalog (`knowledge_base/`), and evals
  (`evals/datasets/`) — do not rename without updating all three.
- Prompts live in `llm/prompts/*.md` as Jinja2 templates, never as inline
  Python f-strings. Every prompt that reasons over collected data must mask
  it first (`normalize/masking.py`) and must contain the
  `<untrusted_data>` framing.
- Tests: unit tests for pure logic, `moto`/`Stubber`/`respx`-backed
  integration tests for anything touching AWS/GitHub/Slack, no network calls
  in `pytest` — see `tests/README` conventions inline in each test package.

## Verification discipline

Interfaces this repo depends on that move fast (LangGraph `interrupt`/
`Command`/`Send`, `langgraph-checkpoint-aws`, `langchain-anthropic`, Step
Functions ASL, EventBridge Scheduler, Security Hub control IDs, Prowler CLI
flags/output, Budgets `cost_types`, Slack Block Kit, Anthropic model IDs) were
checked against the installed package versions / current docs at build time —
see `docs/VERIFY_BEFORE_DEPLOY.md` for exactly what was verified, what was
pinned from a specific version, and what still needs a human check before the
first real deploy. When you touch one of those areas, re-verify and update
that document rather than assuming the original note still holds.
