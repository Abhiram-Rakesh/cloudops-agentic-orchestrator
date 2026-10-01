variable "name_prefix" {
  type        = string
  description = "Resource name prefix, e.g. cloudops-lite."
}

variable "account_id" {
  type        = string
  description = "AWS account ID, used to make the artifact bucket name globally unique."
}

variable "environment" {
  type        = string
  description = "Environment name, e.g. dev. Used in the SSM parameter path prefix."
}

variable "trial_start_date" {
  type        = string
  description = "ISO date (YYYY-MM-DD) the Security Hub/GuardDuty/Config trial started, seeded into SSM for modules/security_trial's one-time reminder schedule."
}
