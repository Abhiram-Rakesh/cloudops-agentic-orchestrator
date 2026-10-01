variable "region" {
  type    = string
  default = "ap-south-1"
}

variable "environment" {
  type    = string
  default = "dev"
}

variable "name_prefix" {
  type    = string
  default = "cloudops-lite"
}

variable "account_id" {
  type        = string
  description = "AWS account ID — used in the state bucket name and GitHub OIDC trust conditions."
}

variable "github_owner" {
  type = string
}

variable "github_repo" {
  type = string
}

variable "github_owner_id" {
  type        = string
  description = "Numeric GitHub account ID for github_owner (`gh api users/<owner> -q .id`). GitHub now appends this immutable ID to the OIDC sub claim (repo:OWNER@OWNER_ID/REPO@REPO_ID:...) instead of the classic repo:OWNER/REPO:... form — verified 2026-09-28 by decoding a real token (see README.md (Troubleshooting))."
}

variable "github_repo_id" {
  type        = string
  description = "Numeric GitHub repository ID for github_repo (`gh api repos/<owner>/<repo> -q .id`). See github_owner_id."
}

variable "create_github_oidc_provider" {
  type        = bool
  default     = true
  description = "false when the target AWS account already has a GitHub Actions OIDC provider registered (common on a shared/company account other pipelines already trust) -- an account can only have one per issuer URL, so this references the existing one read-only instead of trying to create a duplicate."
}
