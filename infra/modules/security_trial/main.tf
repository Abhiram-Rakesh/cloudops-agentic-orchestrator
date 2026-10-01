# Phase A trial: Security Hub + GuardDuty + Config, each behind its own
# enable_* flag so the day-25 switchover (README.md (Security trial lifecycle)) can turn
# them off with a single tfvars edit. Config has no trial — its
# small per-item cost starts accruing from day one, unlike Security Hub and
# GuardDuty's 30-day trials.
#
# VERIFY BEFORE DEPLOY: the Security Hub standard ARNs below (FSBP v1.0.0,
# CIS v3.0.0) were not checked against a live account — see
# README.md (Troubleshooting).

# ---------------------------------------------------------------------------
# Security Hub
# ---------------------------------------------------------------------------

resource "aws_securityhub_account" "this" {
  count                    = var.enable_security_hub ? 1 : 0
  enable_default_standards = false
}

resource "aws_securityhub_standards_subscription" "fsbp" {
  count         = var.enable_security_hub ? 1 : 0
  standards_arn = "arn:aws:securityhub:${var.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.this]
}

resource "aws_securityhub_standards_subscription" "cis" {
  count         = var.enable_security_hub ? 1 : 0
  standards_arn = "arn:aws:securityhub:${var.region}::standards/cis-aws-foundations-benchmark/v/3.0.0"
  depends_on    = [aws_securityhub_account.this]
}

# ---------------------------------------------------------------------------
# GuardDuty — core detector only; every optional paid protection plan off.
# ---------------------------------------------------------------------------

resource "aws_guardduty_detector" "this" {
  count                        = var.enable_guardduty ? 1 : 0
  enable                       = true
  finding_publishing_frequency = "SIX_HOURS"
}

resource "aws_guardduty_detector_feature" "s3_data_events" {
  count       = var.enable_guardduty ? 1 : 0
  detector_id = aws_guardduty_detector.this[0].id
  name        = "S3_DATA_EVENTS"
  status      = "DISABLED"
}

resource "aws_guardduty_detector_feature" "eks_audit_logs" {
  count       = var.enable_guardduty ? 1 : 0
  detector_id = aws_guardduty_detector.this[0].id
  name        = "EKS_AUDIT_LOGS"
  status      = "DISABLED"
}

resource "aws_guardduty_detector_feature" "ebs_malware_protection" {
  count       = var.enable_guardduty ? 1 : 0
  detector_id = aws_guardduty_detector.this[0].id
  name        = "EBS_MALWARE_PROTECTION"
  status      = "DISABLED"
}

resource "aws_guardduty_detector_feature" "rds_login_events" {
  count       = var.enable_guardduty ? 1 : 0
  detector_id = aws_guardduty_detector.this[0].id
  name        = "RDS_LOGIN_EVENTS"
  status      = "DISABLED"
}

resource "aws_guardduty_detector_feature" "lambda_network_logs" {
  count       = var.enable_guardduty ? 1 : 0
  detector_id = aws_guardduty_detector.this[0].id
  name        = "LAMBDA_NETWORK_LOGS"
  status      = "DISABLED"
}

resource "aws_guardduty_detector_feature" "runtime_monitoring" {
  count       = var.enable_guardduty ? 1 : 0
  detector_id = aws_guardduty_detector.this[0].id
  name        = "RUNTIME_MONITORING"
  status      = "DISABLED"
}

# ---------------------------------------------------------------------------
# AWS Config — narrow resource_types, DAILY recording, no trial.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "config_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "config" {
  count                = var.enable_config ? 1 : 0
  name                 = "${var.name_prefix}-config-recorder"
  assume_role_policy   = data.aws_iam_policy_document.config_assume.json
  permissions_boundary = var.boundary_policy_arn
}

resource "aws_iam_role_policy_attachment" "config_managed" {
  count      = var.enable_config ? 1 : 0
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

data "aws_iam_policy_document" "config_s3" {
  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:GetBucketAcl"]
    resources = [var.artifacts_bucket_arn, "${var.artifacts_bucket_arn}/config/*"]
  }
}

# PutDeliveryChannel validates that the target bucket's own resource policy
# (not just this role's identity policy above) explicitly grants
# config.amazonaws.com access, the same way CloudTrail requires -- otherwise
# it fails fast with InsufficientDeliveryPolicyException (seen on a real
# deploy 2026-09-28; see README.md (Troubleshooting)). Exposed as JSON, not
# attached here, for the same only-one-bucket-policy-per-bucket reason as
# modules/security_free's CloudTrail statement -- envs/dev merges all three.
data "aws_iam_policy_document" "config_bucket_access" {
  statement {
    sid       = "AWSConfigBucketPermissionsCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [var.artifacts_bucket_arn]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
  statement {
    sid       = "AWSConfigBucketExistenceCheck"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [var.artifacts_bucket_arn]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
  statement {
    sid       = "AWSConfigBucketDelivery"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${var.artifacts_bucket_arn}/config/AWSLogs/${var.account_id}/Config/*"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_iam_role_policy" "config_s3" {
  count  = var.enable_config ? 1 : 0
  name   = "deliver-to-artifacts-bucket"
  role   = aws_iam_role.config[0].id
  policy = data.aws_iam_policy_document.config_s3.json
}

resource "aws_config_configuration_recorder" "this" {
  count    = var.enable_config ? 1 : 0
  name     = "${var.name_prefix}-recorder"
  role_arn = aws_iam_role.config[0].arn

  recording_group {
    all_supported = false
    resource_types = [
      "AWS::EC2::Instance", "AWS::EC2::SecurityGroup", "AWS::EC2::Volume",
      "AWS::EC2::EIP", "AWS::EC2::VPC", "AWS::EC2::Subnet",
      "AWS::S3::Bucket",
      "AWS::IAM::Role", "AWS::IAM::Policy", "AWS::IAM::User",
    ]
  }

  recording_mode {
    recording_frequency = "DAILY"
  }
}


# aws_config_delivery_channel has no tags argument to piggyback a value
# dependency on (unlike aws_cloudtrail in modules/security_free), so this
# terraform_data resource exists purely to carry the bucket_policy_ready
# value across the module boundary and give the delivery channel something
# to depends_on.
resource "terraform_data" "config_bucket_policy_ready" {
  count = var.enable_config ? 1 : 0
  input = var.bucket_policy_ready
}

resource "aws_config_delivery_channel" "this" {
  count          = var.enable_config ? 1 : 0
  name           = "${var.name_prefix}-delivery"
  s3_bucket_name = var.artifacts_bucket_name
  s3_key_prefix  = "config"

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [
    aws_config_configuration_recorder.this,
    terraform_data.config_bucket_policy_ready,
  ]
}

resource "aws_config_configuration_recorder_status" "this" {
  count      = var.enable_config ? 1 : 0
  name       = aws_config_configuration_recorder.this[0].name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.this]
}

# ---------------------------------------------------------------------------
# One-time day-25 trial reminder
# ---------------------------------------------------------------------------

locals {
  trial_reminder_date = formatdate("YYYY-MM-DD", timeadd("${var.trial_start_date}T00:00:00Z", "600h")) # +25 days
}

data "aws_iam_policy_document" "trial_reminder_scheduler_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "trial_reminder_scheduler" {
  name                 = "${var.name_prefix}-trial-reminder-scheduler"
  assume_role_policy   = data.aws_iam_policy_document.trial_reminder_scheduler_assume.json
  permissions_boundary = var.boundary_policy_arn
}

data "aws_iam_policy_document" "trial_reminder_scheduler" {
  statement {
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = [var.trial_reminder_function_arn]
  }
}

resource "aws_iam_role_policy" "trial_reminder_scheduler" {
  name   = "invoke-trial-reminder"
  role   = aws_iam_role.trial_reminder_scheduler.id
  policy = data.aws_iam_policy_document.trial_reminder_scheduler.json
}

resource "aws_scheduler_schedule" "trial_reminder" {
  name = "${var.name_prefix}-trial-reminder"

  flexible_time_window {
    mode = "OFF"
  }

  schedule_expression          = "at(${local.trial_reminder_date}T03:30:00)"
  schedule_expression_timezone = "Asia/Kolkata"

  target {
    arn      = var.trial_reminder_function_arn
    role_arn = aws_iam_role.trial_reminder_scheduler.arn
  }
}
