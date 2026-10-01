#!/usr/bin/env bash
# Store the real secret values in SSM Parameter Store (SecureString) after
# `terraform apply` has created the CHANGE_ME placeholders
# (infra/modules/data/main.tf). This script is meant to be run BY A HUMAN,
# once, right after the first deploy -- it is never invoked by CI or by any
# agent in this repo (no AWS write commands from automation, and no
# secrets ever committed).
#
# Usage:
#   NAME_PREFIX=cloudops-lite ENVIRONMENT=dev AWS_REGION=ap-south-1 \
#     ./scripts/put_parameters.sh
#
# For each of the five parameters below, you'll be prompted for a value
# (hidden input, via `read -rs`) unless the matching environment variable is
# already set (handy for a non-interactive first run, e.g. piping from a
# password manager's CLI -- never hardcode a real value into a shell history
# file or into this script).
set -euo pipefail

NAME_PREFIX="${NAME_PREFIX:-cloudops-lite}"
ENVIRONMENT="${ENVIRONMENT:-dev}"
AWS_REGION="${AWS_REGION:-ap-south-1}"
PREFIX="/${NAME_PREFIX}/${ENVIRONMENT}"

if ! command -v aws >/dev/null 2>&1; then
  echo "aws CLI not found on PATH." >&2
  exit 1
fi

put_secret() {
  local param_name="$1"
  local env_var_name="$2"
  local value="${!env_var_name:-}"

  if [[ -z "${value}" ]]; then
    read -rsp "Value for ${PREFIX}/${param_name} (input hidden): " value
    echo
  fi
  if [[ -z "${value}" || "${value}" == "CHANGE_ME" ]]; then
    echo "Skipping ${param_name}: no value provided." >&2
    return
  fi

  aws ssm put-parameter \
    --region "${AWS_REGION}" \
    --name "${PREFIX}/${param_name}" \
    --type SecureString \
    --value "${value}" \
    --overwrite \
    >/dev/null
  echo "Set ${PREFIX}/${param_name}"
}

put_secret anthropic_api_key ANTHROPIC_API_KEY
put_secret langsmith_api_key LANGSMITH_API_KEY
put_secret slack_bot_token SLACK_BOT_TOKEN
put_secret slack_signing_secret SLACK_SIGNING_SECRET
put_secret github_token GITHUB_TOKEN

echo
echo "Done. Verify with: cloudops doctor --config config/settings.dev.yaml"
