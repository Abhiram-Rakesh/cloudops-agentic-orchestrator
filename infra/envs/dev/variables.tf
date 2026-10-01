variable "name_prefix" {
  type    = string
  default = "cloudops-lite"
}

variable "region" {
  type    = string
  default = "ap-south-1"
}

variable "alert_email" {
  type        = string
  description = "Destination for budget/anomaly/alarm/trial-reminder notifications."
}

variable "existing_service_anomaly_monitor_arn" {
  type        = string
  default     = ""
  description = "See module.cost_free's variable of the same name — deploy.yml resolves this via a read-only `aws ce get-anomaly-monitors` lookup before every apply."
}

variable "github_owner" {
  type = string
}

variable "repo_name" {
  type = string
}

variable "slack_channel_id" {
  type = string
}

variable "approver_slack_ids" {
  type        = list(string)
  description = "T2 actions require two DISTINCT approvers — list at least 2 if any T2 automation is expected to ever proceed."
}

variable "trial_start_date" {
  type        = string
  description = "ISO date (YYYY-MM-DD) the Security Hub/GuardDuty/Config trial started."
}

variable "enable_security_hub" {
  type = bool
  # Phase A default: Security Hub runs alongside Prowler during the ~30-day
  # trial window (see README.md, Security trial lifecycle).
  default = true
}

variable "enable_guardduty" {
  type    = bool
  default = true
}

variable "enable_config" {
  type    = bool
  default = true
}

variable "enable_runbook_executor" {
  type        = bool
  default     = false
  description = "Mirrors config/settings.dev.yaml's remediation.runbook_executor.enabled — Terraform always creates the SSM documents and the automation role; this flag only documents the matching Python-side gate (RunbookExecutor.dispatch() checks it at runtime, not Terraform)."
}

variable "monthly_budget_usd" {
  type        = number
  default     = 25
  description = "Monthly AWS cost budget in USD (see modules/cost_free)."
}
