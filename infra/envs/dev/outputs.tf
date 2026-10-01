output "state_machine_arn" {
  value = module.orchestration.state_machine_arn
}

output "slack_function_url" {
  value = module.slack_endpoint.function_url
}

output "artifacts_bucket_name" {
  value = module.data.artifacts_bucket_name
}

output "state_table_name" {
  value = module.data.state_table_name
}

output "runbook_executor_enabled" {
  description = "Documents the value var.enable_runbook_executor was set to — it must match config/settings.dev.yaml's remediation.runbook_executor.enabled by hand; Terraform itself always creates the SSM documents and automation role regardless of this flag."
  value       = var.enable_runbook_executor
}
