.DEFAULT_GOAL := help
SHELL := /bin/bash

NAME_PREFIX ?= cloudops-lite
AWS_REGION ?= ap-south-1
ENVIRONMENT ?= dev

.PHONY: help sync lint typecheck test test-cov run-local package tf-check \
        demo-up demo-down drift reset-drift seed-guardduty trials-off \
        kb-build kb-validate eval pre-commit clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

sync: ## Install/sync all Python dependencies (runtime + dev)
	uv sync --frozen --all-extras

lint: ## Ruff lint + format check
	uv run ruff check src tests
	uv run ruff format --check src tests

typecheck: ## mypy --strict on src/
	uv run mypy

test: ## Run pytest with coverage gate
	uv run pytest --cov --cov-report=term-missing

test-cov: test ## Alias for test (kept for CI readability)

run-local: ## Run the full pipeline locally against fixtures with a fake LLM
	uv run cloudops run --config config/settings.local.yaml --fake-llm --fixtures tests/fixtures/scenario_demo --no-publish

kb-build: ## Build the SOP knowledge base index with deterministic fake embeddings
	uv run cloudops kb build --embeddings fake

kb-validate: ## Validate SOP front-matter and clause-meta schema
	uv run cloudops kb validate

eval: ## Run offline evals (deterministic evaluators, no LLM/API calls)
	uv run python evals/run_evals.py --offline

package: ## Build the shared Lambda deployment zip
	bash scripts/build_lambda_zip.sh

tf-check: ## fmt/validate/tflint/checkov for infra/ and demo/infra (no backend, no apply)
	terraform -chdir=infra/envs/dev fmt -check -recursive ../../
	terraform -chdir=infra/envs/dev init -backend=false
	terraform -chdir=infra/envs/dev validate
	terraform -chdir=demo/infra init -backend=false
	terraform -chdir=demo/infra validate
	tflint --chdir=infra/envs/dev --init
	tflint --chdir=infra/envs/dev
	tflint --chdir=demo/infra --init
	tflint --chdir=demo/infra
	checkov --config-file .checkov.yml
	checkov -d demo/infra --compact --quiet

pre-commit: ## Run all pre-commit hooks against the full repo
	uv run pre-commit run --all-files

# --- Demo lifecycle (human-run, requires local AWS credentials; never invoked by an agent) ---

demo-up: ## Deploy the ephemeral demo stack (terraform apply — human only)
	@echo "This target requires local AWS credentials and runs 'terraform apply'."
	@echo "It is intentionally NOT run by any agent. See demo/README.md."
	terraform -chdir=demo/infra apply
	aws ssm put-parameter --name "/$(NAME_PREFIX)/$(ENVIRONMENT)/demo_state" --value up --type String --overwrite --region $(AWS_REGION)

demo-down: ## Tear down the ephemeral demo stack (terraform destroy — human only)
	terraform -chdir=demo/infra destroy
	aws ssm put-parameter --name "/$(NAME_PREFIX)/$(ENVIRONMENT)/demo_state" --value down --type String --overwrite --region $(AWS_REGION)

drift: ## Simulate ClickOps drift on the demo stack (requires CONFIRM=yes)
	CONFIRM=$(CONFIRM) bash demo/scripts/simulate_clickops.sh

reset-drift: ## Revert the simulated drift (does not re-apply Terraform)
	bash demo/scripts/reset_drift.sh

seed-guardduty: ## Seed GuardDuty sample findings (Phase A / trial period only)
	bash demo/scripts/seed_guardduty_samples.sh

trials-off: ## Print the steps to switch off the Security Hub/GuardDuty/Config trial
	@echo "1. Set enable_security_hub/enable_guardduty/enable_config = false in infra/envs/dev/terraform.tfvars"
	@echo "2. Set collectors.security_hub.enabled: false in config/settings.dev.yaml"
	@echo "3. git add -A && git commit -m 'trials-off: switch to Prowler-only security findings'"
	@echo "4. gh workflow run deploy.yml"
	@echo "5. uv run cloudops exceptions add --clause SEC-004-4.2 --days 90 --compensating-control 'weekly Prowler scan + Access Analyzer + CloudTrail'"
	@echo "6. uv run cloudops exceptions add --clause SEC-004-4.4 --days 90 --compensating-control 'weekly Prowler scan + Access Analyzer + CloudTrail'"

clean: ## Remove local caches and build artifacts
	rm -rf .venv build dist out .cache .mypy_cache .ruff_cache .pytest_cache htmlcov .coverage
