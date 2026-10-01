# One shared deployment zip (built by scripts/build_lambda_zip.sh before
# `terraform apply` — see Makefile's `package` target), 8 arm64/python3.12
# functions, one 14-day log group each.
#
# The SNS topic ARN below is constructed by name rather than taken as a
# module output from modules/observability, to avoid a dependency cycle:
# modules/observability's alarms reference this module's function names
# (also constructed, not passed as an output) and modules/orchestration's
# state machine ARN, and this module needs the topic ARN for
# trial_reminder — a real output-to-output reference either way would
# create modules/lambdas -> observability -> orchestration -> modules/lambdas.

locals {
  functions = {
    init_run         = { timeout = 60, memory = 256 }
    collect          = { timeout = 900, memory = 1024 }
    domain_batch     = { timeout = 900, memory = 1024 }
    aggregate        = { timeout = 600, memory = 1024 }
    action_worker    = { timeout = 900, memory = 1024 }
    slack_handler    = { timeout = 30, memory = 256 }
    failure_notifier = { timeout = 30, memory = 256 }
    trial_reminder   = { timeout = 30, memory = 256 }
  }

  observability_topic_arn = "arn:aws:sns:${var.region}:${var.account_id}:${var.name_prefix}-alerts"
}

resource "aws_cloudwatch_log_group" "lambda" {
  for_each          = local.functions
  name              = "/aws/lambda/${var.name_prefix}-${each.key}"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "this" {
  for_each      = local.functions
  function_name = "${var.name_prefix}-${each.key}"
  role          = var.lambda_role_arns[each.key]
  handler       = "cloudops_orchestrator.handlers.${each.key}.lambda_handler"
  runtime       = "python3.12"
  architectures = ["arm64"]
  timeout       = each.value.timeout
  memory_size   = each.value.memory

  filename         = var.lambda_zip_path
  source_code_hash = try(filebase64sha256(var.lambda_zip_path), "")

  environment {
    variables = {
      CLOUDOPS_CONFIG             = var.config_path
      ARTIFACT_BUCKET             = var.artifacts_bucket_name
      STATE_TABLE                 = var.state_table_name
      CHECKPOINTS_TABLE           = var.checkpoints_table_name
      ACTION_WORKER_FUNCTION_NAME = "${var.name_prefix}-action_worker"
      SLACK_HANDLER_FUNCTION_NAME = "${var.name_prefix}-slack_handler"
      OBSERVABILITY_TOPIC_ARN     = local.observability_topic_arn
      EXECUTOR_ROLE_ARN           = var.executor_role_arn
      AUTOMATION_ROLE_ARN         = var.automation_role_arn
      # config/settings.dev.yaml's remaining ${VAR} interpolation points:
      AWS_ACCOUNT_ID    = var.account_id
      SLACK_CHANNEL_ID  = var.slack_channel_id
      APPROVER_SLACK_ID = var.approver_slack_id
      GH_OWNER          = var.github_owner
      REPO_NAME         = var.github_repo
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda]
}
