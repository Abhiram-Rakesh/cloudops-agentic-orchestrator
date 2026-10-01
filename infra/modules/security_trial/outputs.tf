output "config_bucket_policy_json" {
  value = data.aws_iam_policy_document.config_bucket_access.json
}
