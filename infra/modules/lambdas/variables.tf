variable "name_prefix" {
  type = string
}

variable "region" {
  type = string
}

variable "account_id" {
  type = string
}

variable "lambda_zip_path" {
  type        = string
  description = "Path to the shared deployment zip built by scripts/build_lambda_zip.sh."
}

variable "lambda_role_arns" {
  type        = map(string)
  description = "Function name => execution role ARN, from modules/iam."
}

variable "config_path" {
  type        = string
  description = "CLOUDOPS_CONFIG env var value, e.g. config/settings.dev.yaml (packaged into the zip)."
  default     = "config/settings.dev.yaml"
}

variable "artifacts_bucket_name" {
  type = string
}

variable "state_table_name" {
  type = string
}

variable "checkpoints_table_name" {
  type = string
}

variable "executor_role_arn" {
  type        = string
  description = "modules/iam's executor role -- action_worker assumes this (scoped per approved action via session tags) before dispatching an ssm_automation remediation, rather than using its own default Lambda credentials."
}

variable "automation_role_arn" {
  type        = string
  description = "modules/iam's automation role -- the AutomationAssumeRole every CloudOps-* SSM document requires, already trust-scoped to ssm.amazonaws.com and already grantable via executor's iam:PassRole."
}

variable "slack_channel_id" {
  type = string
}

variable "approver_slack_id" {
  type        = string
  description = "config/settings.dev.yaml's approvers list has exactly one $${APPROVER_SLACK_ID} placeholder today — a known single-approver limitation (see envs/dev/terraform.tfvars.example's note on T2's two-distinct-approver requirement)."
}

variable "github_owner" {
  type = string
}

variable "github_repo" {
  type = string
}

variable "log_retention_days" {
  type    = number
  default = 14
}
