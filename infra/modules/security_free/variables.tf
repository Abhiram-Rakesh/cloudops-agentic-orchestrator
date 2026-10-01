variable "name_prefix" {
  type = string
}

variable "account_id" {
  type = string
}

variable "artifacts_bucket_name" {
  type = string
}

variable "artifacts_bucket_arn" {
  type = string
}

variable "bucket_policy_ready" {
  type        = string
  description = "The root module's merged aws_s3_bucket_policy.artifacts id — forces the CloudTrail trail to wait for the bucket policy that grants it write access, without a real module-to-module depends_on cycle (this module's own output feeds that policy)."
}
