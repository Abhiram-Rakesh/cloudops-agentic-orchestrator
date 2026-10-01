variable "name_prefix" {
  type = string
}

variable "alert_email" {
  type = string
}

variable "existing_service_anomaly_monitor_arn" {
  type        = string
  default     = ""
  description = "ARN of a pre-existing SERVICE-dimensional Cost Anomaly Monitor to reuse instead of creating a new one. AWS accounts get a DIMENSIONAL/SERVICE monitor auto-created (named 'Default-Services-Monitor') at various points, and the account-wide quota is one such monitor -- creating a second one fails with 'Limit exceeded on dimensional spend monitor creation' (seen on a real deploy 2026-09-28; see README.md (Troubleshooting)). deploy.yml looks this up read-only via `aws ce get-anomaly-monitors` before every apply and passes it here; empty string means none exists yet, so this module creates one."
}

variable "monthly_budget_usd" {
  type        = number
  default     = 25
  description = "Monthly AWS cost budget in USD (gross, before credits). Default sized from README.md's steady-state estimate (~$13-17) plus headroom for a few days of the demo stack; retune after the first full month in Cost Explorer."
}

variable "anomaly_threshold_usd" {
  type        = number
  default     = 3
  description = "Minimum absolute impact in USD for a Cost Anomaly Detection daily email. Daily baseline spend is roughly $0.5, so $3 flags a real spike without alerting on noise."
}
