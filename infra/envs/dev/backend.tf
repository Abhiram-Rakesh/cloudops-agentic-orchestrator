# S3 backend with native locking (Terraform >= 1.10's use_lockfile — no
# separate DynamoDB lock table needed). Bucket/region come from
# -backend-config=backend.hcl (see backend.hcl.example), created once by
# infra/bootstrap and never committed with real values.
terraform {
  backend "s3" {
    key          = "orchestrator/dev/terraform.tfstate"
    use_lockfile = true
    encrypt      = true
  }
}
