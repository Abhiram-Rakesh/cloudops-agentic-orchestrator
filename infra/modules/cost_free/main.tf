# Cost Anomaly Detection, Compute Optimizer enrollment, and one AWS Budget —
# all cost-visibility tooling.
#
# The budget is sized from the steady-state estimate in README.md (AWS cost
# estimate): ~$13-17/month, dominated by provisioned DynamoDB capacity, plus
# roughly $15/month more if the demo stack is left up around the clock.
# Anthropic spend is billed outside AWS, so it is NOT in this budget — the
# in-app caps in llm/budget.py cover it.
#
# VERIFY BEFORE DEPLOY: aws_budgets_budget's cost_types.include_credit
# semantics (which value means "net of credits" vs "gross before credits")
# were not checked against a live account — see README.md (Troubleshooting).
# include_credit = false is read as "credits are excluded" (gross), so the
# budget tracks total consumption whether or not credits offset it.

resource "aws_ce_anomaly_monitor" "service" {
  count             = var.existing_service_anomaly_monitor_arn == "" ? 1 : 0
  name              = "${var.name_prefix}-service-anomalies"
  monitor_type      = "DIMENSIONAL"
  monitor_dimension = "SERVICE"
}

locals {
  service_anomaly_monitor_arn = (
    var.existing_service_anomaly_monitor_arn != ""
    ? var.existing_service_anomaly_monitor_arn
    : aws_ce_anomaly_monitor.service[0].arn
  )
}

resource "aws_ce_anomaly_subscription" "daily_email" {
  name             = "${var.name_prefix}-anomaly-daily-email"
  frequency        = "DAILY"
  monitor_arn_list = [local.service_anomaly_monitor_arn]

  subscriber {
    type    = "EMAIL"
    address = var.alert_email
  }

  threshold_expression {
    dimension {
      key           = "ANOMALY_TOTAL_IMPACT_ABSOLUTE"
      values        = [tostring(var.anomaly_threshold_usd)]
      match_options = ["GREATER_THAN_OR_EQUAL"]
    }
  }
}

resource "aws_computeoptimizer_enrollment_status" "this" {
  status = "Active"
}

resource "aws_budgets_budget" "monthly" {
  name         = "${var.name_prefix}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_types {
    include_credit = false # gross before credits — tracks total consumption
  }

  # 50/80/100% matches knowledge_base COST-004-4.2. At the default limit the
  # 50% alert fires most months (steady state is ~60%); the FORECASTED alert
  # is the early warning for a demo stack or trial service left running.
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 50
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.alert_email]
  }
}
