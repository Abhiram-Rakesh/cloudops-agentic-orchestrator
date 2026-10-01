output "tfstate_bucket_name" {
  value = aws_s3_bucket.tfstate.id
}

output "gha_deploy_role_arn" {
  value = aws_iam_role.gha_deploy.arn
}

output "gha_scanner_role_arn" {
  value = aws_iam_role.gha_scanner.arn
}

output "gha_demo_plan_role_arn" {
  value = aws_iam_role.gha_demo_plan.arn
}

output "gha_demo_apply_role_arn" {
  value = aws_iam_role.gha_demo_apply.arn
}

output "gha_kb_role_arn" {
  value = aws_iam_role.gha_kb.arn
}
