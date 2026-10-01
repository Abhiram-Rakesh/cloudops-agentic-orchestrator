variable "name_prefix" {
  type = string
}

variable "lambda_function_arns" {
  type        = map(string)
  description = "Function name => ARN, from modules/lambdas — used to template the ASL."
}

variable "boundary_policy_arn" {
  type        = string
  description = "modules/iam's permission boundary, applied to this module's own roles too."
}

variable "log_retention_days" {
  type    = number
  default = 14
}
