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
      application          = "cloudops-agentic-orchestrator"
      app                  = "cloudops-agentic-orchestrator"
      environment          = "dev"
      owner                = "platform-team"
      "cost-center"        = "CC-1001"
      "managed-by"         = "terraform"
      "cloudops:protected" = "true"
    }
  }
}
