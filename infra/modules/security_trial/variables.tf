variable "name_prefix" {
  type = string
}

variable "region" {
  type = string
}

variable "account_id" {
  type = string
}

variable "enable_security_hub" {
  type    = bool
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

variable "trial_start_date" {
  type        = string
  description = "ISO date (YYYY-MM-DD) the trial started — the day-25 reminder is scheduled from this."
}

variable "artifacts_bucket_name" {
  type = string
}

variable "artifacts_bucket_arn" {
  type = string
}

variable "trial_reminder_function_arn" {
  type = string
}

variable "boundary_policy_arn" {
  type = string
}

variable "bucket_policy_ready" {
  type        = string
  description = "The root module's merged aws_s3_bucket_policy.artifacts id — forces the Config delivery channel to wait for the bucket policy that grants config.amazonaws.com write access, without a real module-to-module depends_on cycle (this module's own output feeds that policy). Mirrors modules/security_free's identical pattern for CloudTrail."
}
