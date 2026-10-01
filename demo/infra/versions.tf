# Ephemeral demo stack: deliberate, safe-by-construction SOP
# violations for the CloudOps agents to find, triage, and (with approval)
# fix — see tests/fixtures/scenario_demo/demo_matrix.yaml (the single
# source of truth this file's resources are built to match) and
# demo/docs/VIOLATIONS.md (generated from it). Never applied by an agent or
# any tooling; `make demo-up`/`make demo-down` are human-run.
terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.66"
    }
  }
}

provider "aws" {
  region = "ap-south-1"

  default_tags {
    tags = {
      # Universal, never-violated baseline tags (see demo/README.md).
      # owner/cost-center/schedule are set per-resource instead, since
      # several resources deliberately omit one of them as their
      # violation — a provider-level default would silently mask that.
      application = "orders"
      environment = "dev"
      app         = "orders-demo"
      managed-by  = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}
