# Verify Before Deploy

This document tracks every interface Hard Rule #5 requires verification for:
what was actually checked while building this repo (and against what,
when), what was pinned as a result, and what a human must still confirm
before the first real `deploy.yml` run or the first `demo-up`. Nothing in
`infra/` was ever applied and no paid API was ever called while building this
repo — everything below was checked by reading current package
metadata/source or public docs, never by testing against a live account.

Built: 2026-09-27. Re-verify anything here that is more than a few months old
before deploying.

## Verified during build (safe to trust as of 2026-09-27)

| Interface | What was checked | Result / pin |
|---|---|---|
| `langgraph` | Latest PyPI release, `interrupt()`/`Command()`/`Send()` signatures inspected directly on the installed 1.2.12 wheel | Pinned `1.2.12`. `interrupt(value, *, response_schema=None)`, `Command(*, graph=None, update=None, resume=None, goto=())`, `Send(node, arg, *, timeout=None)` — matches the usage in `graph/action_graph.py`. |
| `langgraph-checkpoint-aws` | Latest PyPI release (1.2.3); installed into a scratch venv and read `checkpoint/dynamodb/unified_repository.py` + `saver.py` source directly | Pinned `1.2.3`. **`DynamoDBSaver` exists** and is used directly (no custom `BaseCheckpointSaver` needed). Required table schema: partition key `PK` (String), sort key `SK` (String), TTL attribute name `ttl` (Number, epoch seconds). **No GSI required** — all checkpoint queries are `Query` on `PK` (optionally with an `SK` prefix condition). `infra/modules/data` provisions exactly this schema for `${NAME_PREFIX}-checkpoints`. S3 offloading (`s3_offload_config={"bucket_name": ...}`) is used for items > 350 KB, writing under `checkpoints/` in the shared artifact bucket, with lifecycle expiry synced to `ttl_seconds`. |
| `langchain-anthropic` / Anthropic model IDs | Environment-provided current model ID list | Triage model: `claude-haiku-4-5-20251001` (Haiku 4.5). Reasoning model: `claude-sonnet-5`. These are the exact IDs configured in `config/settings.dev.yaml`. **Re-check against `https://docs.claude.com/en/docs/about-claude/models` immediately before deploying** — model IDs are the single fastest-moving part of this stack. |
| Runtime dependency versions | Queried PyPI's JSON API for the latest release of every pinned package (`langgraph`, `langchain-core`, `pydantic`, `boto3`, `structlog`, `tenacity`, `httpx`, `slack-sdk`, `githubkit`, `python-hcl2`, `aws-embedded-metrics`, `typer`, `rich`, `pytest`, `moto`, `ruff`, `mypy`, `freezegun`, `respx`, etc.) on 2026-09-27 | All pinned to exact versions in `pyproject.toml`. Re-run `uv lock --upgrade` deliberately (not silently) — Dependabot will propose updates weekly. |
| `hashicorp/aws` Terraform provider | Terraform Registry API, latest stable release | Pinned `~> 6.66` in every `versions.tf`. |
| Terraform / tflint / tflint-ruleset-aws / checkov / pre-commit hook versions | GitHub Releases API / PyPI for each tool | `terraform >= 1.10` (installed: 1.15.9), `tflint 0.49.0`, `tflint-ruleset-aws 0.49.0`, `checkov 3.3.19`, `pre-commit-hooks v6.0.0`, `ruff-pre-commit v0.16.9`, `gitleaks v8.30.1`, `pre-commit-terraform v1.109.1`. |
| GitHub Actions versions | GitHub Releases API for each action | `actions/checkout@v7`, `astral-sh/setup-uv@v10`, `hashicorp/setup-terraform@v4`, `terraform-linters/setup-tflint@v6`, `aws-actions/configure-aws-credentials@v6`, `gitleaks/gitleaks-action@v3`. |

## NOT verified — human must confirm before deploy

These require either a live AWS account/console, a live Slack/GitHub App
console, or a live Bedrock/Security Hub/Prowler run — none of which this
build touched (Hard Rules #1–#3).

| Area | Why it couldn't be verified here | What to check, and where |
|---|---|---|
| Security Hub control IDs (§11.2 catalog: `IAM.1`, `IAM.5`, `IAM.6`, `IAM.9`, `EC2.2`, `EC2.3`, `EC2.6`, `EC2.7`, `EC2.8`, `EC2.9`, `EC2.12`, `EC2.13`, `EC2.14`, `EC2.18`, `EC2.19`, `S3.1`, `S3.2`, `S3.5`, `S3.8`, `S3.9`, `S3.14`, `CloudTrail.1`, `CloudTrail.4`, `Config.1`, `GuardDuty.1`, `SSM.1`) | These IDs are retired/renumbered periodically by AWS and the current set can only be confirmed against a live account or the current published reference | AWS Console → Security Hub → Security standards → AWS Foundational Security Best Practices v1.0.0, or `aws securityhub describe-standards-controls`. Update `knowledge_base/security/*.md` clause-meta and `config/prowler_control_map.yaml` together if any ID changed — a repo test (`tests/unit/test_kb_control_coverage.py`) will fail loudly if the catalog and KB drift apart, but it cannot tell you if AWS itself renamed a control. |
| Prowler check IDs (`config/prowler_control_map.yaml`) | Requires either running Prowler once or reading its current `compliance/aws_well_architected_framework_*` / `aws_foundational_security_best_practices_aws.json` metadata files from the Prowler GitHub repo at deploy time | Run `prowler aws --list-checks --compliance aws_foundational_security_best_practices_aws` and `--compliance cis_3.0_aws` once (read-only, no write calls) against a real or sandbox account before the first `prowler.yml` run, and diff against `config/prowler_control_map.yaml`. |
| Prowler CLI flags and output format (OCSF vs legacy JSON) | Same — CLI flags for compliance framework selection and the exact output schema (`-M json-ocsf` vs `-M json`) change between Prowler releases | Pin an exact Prowler version in `.github/workflows/prowler.yml` (currently `prowler-cloud/prowler` pip package, unpinned placeholder — **pin before first run**) and run `prowler --version` + `prowler aws --help` to confirm flags match `collectors/prowler.py`'s parser. |
| AWS Budgets `cost_types` semantics (net-of-credits vs gross) | Requires a live Budgets API call / console to confirm which `cost_types` combination yields "net of credits" vs "gross before credits" in the current API version | AWS Console → Billing → Budgets → create budget manually once, matching the intended semantics, then diff its generated JSON against `infra/modules/cost_free/budgets.tf`. |
| AWS Free plan APIs (account plan / free-tier-usage APIs) | No live account available in this environment | `aws freetier get-free-tier-usage` (if available on the account) or Billing Console → Free Tier page. `cloudops doctor --free-plan` degrades gracefully (warn-only) if the API is unavailable. |
| Bedrock Titan Text Embeddings V2 availability in `ap-south-1` | No Bedrock access in this environment | AWS Console → Bedrock → Model access, in `ap-south-1`, before relying on `kb-sync.yml`. If unavailable, `kb.query_embeddings: none` and `--embeddings fake` keep the system working (control-ID + BM25 only), degraded per §6.4. |
| Lambda account concurrency quota | Cannot query a live account | `aws lambda get-account-settings` — new accounts may have a quota as low as 10; the state machine's `MaxConcurrency: 2` was chosen to stay well under this, but confirm before relying on it. |
| GitHub ruleset / branch protection on `main` | Attempted during build; GitHub returned 403 | Confirmed: **GitHub Free private repositories cannot create rulesets** ("Upgrade to GitHub Pro or make this repository public"). `agent-pr-guard.yml` + required-status-check-less CI, plus the fact that only `deploy.yml`/`demo-apply.yml` can mutate infrastructure (both `workflow_dispatch`-gated and OIDC-scoped), are the compensating controls — see `docs/SETUP.md`. |
| SSM Automation document schema/action nuances (`ssm_documents/*.yaml`) | No live SSM access | Run each document with `--dry-run`/against a disposable instance before flipping `remediation.runbook_executor.enabled: true`. |
| Slack Block Kit limits (block count, text length per block) | No live Slack workspace | Post a synthetic digest with the most crowded weekly report the fixtures produce to a test channel before relying on it in production; `report/slack_blocks.py` chunks/truncates conservatively but hasn't been checked against a live Slack API response. |
| `langsmith` SaaS free-plan trace volume limits | No LangSmith account credentials available here | Check current free-plan trace/event limits at `smith.langchain.com` pricing page before assuming weekly runs stay within them; `langsmith.anonymize: true` reduces payload size but not trace count. |

## Process note

Every item above is either read-only-verifiable (and was verified) or
requires a live account/console (and is listed here per Hard Rule #5 instead
of being guessed). `tests/unit/test_kb_control_coverage.py` and
`tests/infra/test_free_plan_guardrails.py` catch internal drift (catalog vs.
KB vs. Terraform) automatically in CI; they cannot catch AWS/Prowler/Slack
changing something out from under this repo, which is why this file exists.
