terraform {
  backend "s3" {
    key          = "demo/dev/terraform.tfstate"
    use_lockfile = true
    encrypt      = true
  }
}
