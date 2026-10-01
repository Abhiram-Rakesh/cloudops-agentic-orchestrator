# Bootstrap is its own root module with LOCAL state (chicken-and-egg: it
# creates the S3 bucket envs/dev's backend then uses). Run once by a human
# with local AWS credentials — never applied by an
# agent, and never even `plan`-ed against a real backend from this repo's
# automation.
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
  region = var.region
  default_tags {
    tags = {
      application          = "cloudops-agentic-orchestrator"
      app                  = "cloudops-agentic-orchestrator"
      environment          = var.environment
      owner                = "platform-team"
      "cost-center"        = "CC-1001"
      "managed-by"         = "terraform"
      "cloudops:protected" = "true"
    }
  }
}
