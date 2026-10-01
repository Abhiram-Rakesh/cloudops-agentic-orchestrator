terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.66"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.14"
    }
  }
}
