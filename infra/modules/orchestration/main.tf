# Step Functions Standard state machine templated from
# statemachine/review.asl.json, plus the weekly EventBridge Scheduler
# trigger and its SQS dead-letter queue.

locals {
  asl_path = abspath("${path.module}/../../../statemachine/review.asl.json")
}

# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "state_machine" {
  name              = "/aws/vendedlogs/states/${var.name_prefix}-review"
  retention_in_days = var.log_retention_days
}

data "aws_iam_policy_document" "state_machine_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "state_machine" {
  name                 = "${var.name_prefix}-review-state-machine"
  assume_role_policy   = data.aws_iam_policy_document.state_machine_assume.json
  permissions_boundary = var.boundary_policy_arn
}

data "aws_iam_policy_document" "state_machine" {
  statement {
    effect  = "Allow"
    actions = ["lambda:InvokeFunction"]
    resources = [
      var.lambda_function_arns["init_run"],
      var.lambda_function_arns["collect"],
      var.lambda_function_arns["domain_batch"],
      var.lambda_function_arns["aggregate"],
      var.lambda_function_arns["failure_notifier"],
    ]
  }
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery",
      "logs:DeleteLogDelivery", "logs:ListLogDeliveries", "logs:PutResourcePolicy",
      "logs:DescribeResourcePolicies", "logs:DescribeLogGroups",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "state_machine" {
  name   = "invoke-lambdas-and-log"
  role   = aws_iam_role.state_machine.id
  policy = data.aws_iam_policy_document.state_machine.json
}

# CreateStateMachine validates the role's logging permissions synchronously,
# but IAM's PutRolePolicy write above is only eventually consistent --
# without an explicit wait, Step Functions sometimes rejects the brand new
# role with "not authorized to access the Log Destination" (seen on a real
# deploy 2026-09-28; see README.md (Troubleshooting)). There was previously
# no dependency at all between the two resources.
resource "time_sleep" "state_machine_role_propagation" {
  depends_on      = [aws_iam_role_policy.state_machine]
  create_duration = "15s"
}

resource "aws_sfn_state_machine" "review" {
  depends_on = [time_sleep.state_machine_role_propagation]
  name       = "${var.name_prefix}-review"
  type       = "STANDARD"
  role_arn   = aws_iam_role.state_machine.arn

  definition = templatefile(local.asl_path, {
    init_run_arn         = var.lambda_function_arns["init_run"]
    collect_arn          = var.lambda_function_arns["collect"]
    domain_batch_arn     = var.lambda_function_arns["domain_batch"]
    aggregate_arn        = var.lambda_function_arns["aggregate"]
    failure_notifier_arn = var.lambda_function_arns["failure_notifier"]
  })

  logging_configuration {
    level                  = "ERROR"
    include_execution_data = false
    log_destination        = "${aws_cloudwatch_log_group.state_machine.arn}:*"
  }
}

# ---------------------------------------------------------------------------
# EventBridge Scheduler — Monday 08:45 IST, {"refresh": false}
# ---------------------------------------------------------------------------

resource "aws_sqs_queue" "scheduler_dlq" {
  name                      = "${var.name_prefix}-scheduler-dlq"
  message_retention_seconds = 1209600 # 14 days
  sqs_managed_sse_enabled   = true
}

data "aws_iam_policy_document" "scheduler_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "scheduler" {
  name                 = "${var.name_prefix}-review-scheduler"
  assume_role_policy   = data.aws_iam_policy_document.scheduler_assume.json
  permissions_boundary = var.boundary_policy_arn
}

data "aws_iam_policy_document" "scheduler" {
  statement {
    effect    = "Allow"
    actions   = ["states:StartExecution"]
    resources = [aws_sfn_state_machine.review.arn]
  }
  statement {
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.scheduler_dlq.arn]
  }
}

resource "aws_iam_role_policy" "scheduler" {
  name   = "start-execution"
  role   = aws_iam_role.scheduler.id
  policy = data.aws_iam_policy_document.scheduler.json
}

resource "aws_scheduler_schedule" "weekly_review" {
  name = "${var.name_prefix}-weekly-review"

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression          = "cron(45 8 ? * MON *)"
  schedule_expression_timezone = "Asia/Kolkata"

  target {
    arn      = aws_sfn_state_machine.review.arn
    role_arn = aws_iam_role.scheduler.arn
    input    = jsonencode({ refresh = false })

    retry_policy {
      maximum_retry_attempts = 1
    }

    dead_letter_config {
      arn = aws_sqs_queue.scheduler_dlq.arn
    }
  }
}
