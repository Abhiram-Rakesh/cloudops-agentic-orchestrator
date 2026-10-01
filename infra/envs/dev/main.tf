# Composition root — wires the 10 infra/modules together. See each
# module's own comments for why a few cross-module references are
# constructed by naming convention instead of a real output reference
# (breaking what would otherwise be dependency cycles).

data "aws_caller_identity" "current" {}

locals {
  account_id      = data.aws_caller_identity.current.account_id
  lambda_zip_path = abspath("${path.module}/../../../dist/lambda.zip")
}

module "data" {
  source = "../../modules/data"

  name_prefix      = var.name_prefix
  account_id       = local.account_id
  environment      = "dev"
  trial_start_date = var.trial_start_date
}

module "remediation" {
  source = "../../modules/remediation"
}

module "iam" {
  source = "../../modules/iam"

  name_prefix           = var.name_prefix
  account_id            = local.account_id
  region                = var.region
  state_table_arn       = module.data.state_table_arn
  checkpoints_table_arn = module.data.checkpoints_table_arn
  artifacts_bucket_arn  = module.data.artifacts_bucket_arn
  parameter_arns        = module.data.parameter_arns
  secret_parameter_arns = module.data.secret_parameter_arns
  ssm_document_arns     = values(module.remediation.document_arns)
}

module "lambdas" {
  source = "../../modules/lambdas"

  name_prefix            = var.name_prefix
  region                 = var.region
  account_id             = local.account_id
  lambda_zip_path        = local.lambda_zip_path
  lambda_role_arns       = module.iam.lambda_role_arns
  config_path            = "config/settings.dev.yaml"
  artifacts_bucket_name  = module.data.artifacts_bucket_name
  state_table_name       = module.data.state_table_name
  checkpoints_table_name = module.data.checkpoints_table_name
  slack_channel_id       = var.slack_channel_id
  approver_slack_id      = var.approver_slack_ids[0]
  github_owner           = var.github_owner
  github_repo            = var.repo_name
  executor_role_arn      = module.iam.executor_role_arn
  automation_role_arn    = module.iam.automation_role_arn
}

module "orchestration" {
  source = "../../modules/orchestration"

  name_prefix          = var.name_prefix
  lambda_function_arns = module.lambdas.function_arns
  boundary_policy_arn  = module.iam.boundary_policy_arn
}

module "slack_endpoint" {
  source = "../../modules/slack_endpoint"

  slack_handler_function_name = module.lambdas.function_names["slack_handler"]
}

module "security_free" {
  source = "../../modules/security_free"

  name_prefix           = var.name_prefix
  account_id            = local.account_id
  artifacts_bucket_name = module.data.artifacts_bucket_name
  artifacts_bucket_arn  = module.data.artifacts_bucket_arn
  bucket_policy_ready   = aws_s3_bucket_policy.artifacts.id
}

# ---------------------------------------------------------------------------
# Artifacts bucket policy: only one aws_s3_bucket_policy can exist per
# bucket, so modules/data's TLS-only statement and modules/security_free's
# CloudTrail statement are merged here. module.security_free's own
# aws_cloudtrail resource waits for this via its bucket_policy_ready
# variable above, not a module-level depends_on (which would cycle, since
# this policy also needs that module's cloudtrail_bucket_policy_json output).
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "artifacts_bucket_policy" {
  source_policy_documents = [
    module.data.artifacts_bucket_tls_only_policy_json,
    module.security_free.cloudtrail_bucket_policy_json,
    module.security_trial.config_bucket_policy_json,
  ]
}

resource "aws_s3_bucket_policy" "artifacts" {
  bucket = module.data.artifacts_bucket_name
  policy = data.aws_iam_policy_document.artifacts_bucket_policy.json
}

module "security_trial" {
  source = "../../modules/security_trial"

  name_prefix                 = var.name_prefix
  region                      = var.region
  account_id                  = local.account_id
  enable_security_hub         = var.enable_security_hub
  enable_guardduty            = var.enable_guardduty
  enable_config               = var.enable_config
  trial_start_date            = var.trial_start_date
  artifacts_bucket_name       = module.data.artifacts_bucket_name
  artifacts_bucket_arn        = module.data.artifacts_bucket_arn
  trial_reminder_function_arn = module.lambdas.function_arns["trial_reminder"]
  boundary_policy_arn         = module.iam.boundary_policy_arn
  bucket_policy_ready         = aws_s3_bucket_policy.artifacts.id
}

module "cost_free" {
  source = "../../modules/cost_free"

  name_prefix                          = var.name_prefix
  alert_email                          = var.alert_email
  existing_service_anomaly_monitor_arn = var.existing_service_anomaly_monitor_arn
  monthly_budget_usd                   = var.monthly_budget_usd
}

module "observability" {
  source = "../../modules/observability"

  name_prefix        = var.name_prefix
  alert_email        = var.alert_email
  state_machine_arn  = module.orchestration.state_machine_arn
  scheduler_dlq_name = module.orchestration.scheduler_dlq_name
}
