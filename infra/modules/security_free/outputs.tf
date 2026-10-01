output "cloudtrail_bucket_policy_json" {
  value = data.aws_iam_policy_document.cloudtrail_bucket_access.json
}
