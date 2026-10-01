output "lambda_role_arns" {
  value = { for name, role in aws_iam_role.lambda : name => role.arn }
}

output "reader_role_arn" {
  value = aws_iam_role.reader.arn
}

output "executor_role_arn" {
  value = aws_iam_role.executor.arn
}

output "automation_role_arn" {
  value = aws_iam_role.automation.arn
}

output "boundary_policy_arn" {
  value = aws_iam_policy.boundary.arn
}
