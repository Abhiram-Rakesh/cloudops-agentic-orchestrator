# SNS topic (AWS-managed key) + exactly 6 alarms —
# see metrics.py's ALLOWED_METRICS for the 5 EMF metrics these alarms watch.
#
# Lambda function names below are constructed from name_prefix rather than
# taken as a modules/lambdas output, to avoid a dependency cycle: this
# module -> orchestration (state machine ARN) -> lambdas -> this module
# (SNS topic ARN, needed by trial_reminder's env var) would otherwise be
# circular. See infra/modules/lambdas/main.tf's matching comment.

resource "aws_sns_topic" "alerts" {
  name              = "${var.name_prefix}-alerts"
  kms_master_key_id = "alias/aws/sns" # AWS-managed key; no customer-managed CMK
}

resource "aws_sns_topic_subscription" "alerts_email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_metric_alarm" "state_machine_executions_failed" {
  alarm_name          = "${var.name_prefix}-state-machine-executions-failed"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "ExecutionsFailed"
  namespace           = "AWS/States"
  period              = 3600
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  dimensions = {
    StateMachineArn = var.state_machine_arn
  }
}

resource "aws_cloudwatch_metric_alarm" "slack_handler_errors" {
  alarm_name          = "${var.name_prefix}-slack-handler-errors"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 3600
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  dimensions = {
    FunctionName = "${var.name_prefix}-slack_handler"
  }
}

resource "aws_cloudwatch_metric_alarm" "action_worker_errors" {
  alarm_name          = "${var.name_prefix}-action-worker-errors"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 3600
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  dimensions = {
    FunctionName = "${var.name_prefix}-action_worker"
  }
}

resource "aws_cloudwatch_metric_alarm" "run_failed" {
  alarm_name          = "${var.name_prefix}-run-failed"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "RunFailed"
  namespace           = "CloudOps"
  period              = 3600
  statistic           = "Sum"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "llm_cost_usd" {
  alarm_name          = "${var.name_prefix}-llm-cost-usd"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "LLMCostUSD"
  namespace           = "CloudOps"
  period              = 3600
  statistic           = "Maximum"
  threshold           = 2
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "scheduler_dlq_visible" {
  alarm_name          = "${var.name_prefix}-scheduler-dlq-visible"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 3600
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  dimensions = {
    QueueName = var.scheduler_dlq_name
  }
}
