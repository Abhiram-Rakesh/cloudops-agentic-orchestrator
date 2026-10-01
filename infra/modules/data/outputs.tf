output "state_table_name" {
  value = aws_dynamodb_table.state.name
}

output "state_table_arn" {
  value = aws_dynamodb_table.state.arn
}

output "checkpoints_table_name" {
  value = aws_dynamodb_table.checkpoints.name
}

output "checkpoints_table_arn" {
  value = aws_dynamodb_table.checkpoints.arn
}

output "artifacts_bucket_name" {
  value = aws_s3_bucket.artifacts.id
}

output "artifacts_bucket_arn" {
  value = aws_s3_bucket.artifacts.arn
}

output "parameter_prefix" {
  value = local.parameter_prefix
}

output "parameter_arns" {
  description = "ARNs of every parameter under the prefix, for IAM read scoping."
  value = concat(
    [
      aws_ssm_parameter.kill_switch.arn,
      aws_ssm_parameter.demo_state.arn,
      aws_ssm_parameter.trial_start_date.arn,
    ],
    [for p in aws_ssm_parameter.secrets : p.arn],
  )
}

output "secret_parameter_arns" {
  description = "ARNs of only the SecureString secret placeholders."
  value       = [for p in aws_ssm_parameter.secrets : p.arn]
}

output "artifacts_bucket_tls_only_policy_json" {
  description = "The TLS-only deny statement for the artifacts bucket — envs/dev merges this with any other module's statements into the one aws_s3_bucket_policy the bucket can have."
  value       = data.aws_iam_policy_document.tls_only.json
}
