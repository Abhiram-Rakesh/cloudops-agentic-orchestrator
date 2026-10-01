variable "name_prefix" {
  type = string
}

variable "account_id" {
  type = string
}

variable "region" {
  type = string
}

variable "state_table_arn" {
  type = string
}

variable "checkpoints_table_arn" {
  type = string
}

variable "artifacts_bucket_arn" {
  type = string
}

variable "parameter_arns" {
  type        = list(string)
  description = "Every SSM parameter ARN under the app's prefix."
}

variable "secret_parameter_arns" {
  type        = list(string)
  description = "The SecureString secret placeholder ARNs only."
}

variable "ssm_document_arns" {
  type        = list(string)
  description = "aws_ssm_document ARNs from modules/remediation, for the executor role."
}
