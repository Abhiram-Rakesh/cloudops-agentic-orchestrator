# Single-table DynamoDB store, the LangGraph checkpoints table, the
# artifact/evidence S3 bucket, and the SSM Parameter Store tree — see
# README.md (How it works) for the key design and store/client.py for the entity
# catalog this schema backs.

locals {
  parameter_prefix = "/${var.name_prefix}/${var.environment}"
}

# ---------------------------------------------------------------------------
# DynamoDB: single-table state store
# ---------------------------------------------------------------------------

resource "aws_dynamodb_table" "state" {
  name                        = "${var.name_prefix}-state"
  billing_mode                = "PROVISIONED"
  read_capacity               = 8
  write_capacity              = 8
  hash_key                    = "pk"
  range_key                   = "sk"
  deletion_protection_enabled = true

  attribute {
    name = "pk"
    type = "S"
  }

  attribute {
    name = "sk"
    type = "S"
  }

  attribute {
    name = "gsi1pk"
    type = "S"
  }

  attribute {
    name = "gsi1sk"
    type = "S"
  }

  global_secondary_index {
    name            = "gsi1"
    hash_key        = "gsi1pk"
    range_key       = "gsi1sk"
    read_capacity   = 3
    write_capacity  = 3
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  # AWS-owned key (no customer-managed CMK by design; see
  # .checkov.yml's CKV_AWS_119 skip and the README's Security section's pre-seeded
  # SHARED-003 exception).
  server_side_encryption {
    enabled = true
  }

  # No point-in-time recovery (extra cost at this scale — see
  # .checkov.yml's CKV_AWS_28 skip) and no auto scaling (provisioned
  # capacity only, by design).
}

# ---------------------------------------------------------------------------
# DynamoDB: LangGraph checkpoints (langgraph-checkpoint-aws DynamoDBSaver
# schema — verified against the installed 1.2.3 wheel, README.md (Troubleshooting))
# ---------------------------------------------------------------------------

resource "aws_dynamodb_table" "checkpoints" {
  name                        = "${var.name_prefix}-checkpoints"
  billing_mode                = "PROVISIONED"
  read_capacity               = 6
  write_capacity              = 6
  hash_key                    = "PK"
  range_key                   = "SK"
  deletion_protection_enabled = true

  attribute {
    name = "PK"
    type = "S"
  }

  attribute {
    name = "SK"
    type = "S"
  }

  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  server_side_encryption {
    enabled = true
  }
}

# ---------------------------------------------------------------------------
# S3: artifacts / evidence bucket
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "artifacts" {
  bucket = "${var.name_prefix}-${var.account_id}"
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration {
    status = "Disabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_logging" "artifacts" {
  bucket        = aws_s3_bucket.artifacts.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "s3-access/${var.name_prefix}-${var.account_id}/"
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "abort-incomplete-multipart-uploads"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  dynamic "rule" {
    for_each = {
      evidence   = 30
      runs       = 30
      llm_cache  = 30
      "prowler/" = 60
      "drift/"   = 60
      reports    = 180
      audit      = 365
      cloudtrail = 90
      config     = 30
    }
    content {
      id     = "${trimsuffix(rule.key, "/")}-expiry"
      status = "Enabled"
      filter {
        prefix = "${trimsuffix(rule.key, "/")}/"
      }
      expiration {
        days = rule.value
      }
    }
  }
}

# Not attached here as an aws_s3_bucket_policy resource: modules/security_free's
# CloudTrail trail also needs a statement on this same bucket, and only one
# aws_s3_bucket_policy resource can exist per bucket — envs/dev combines this
# module's tls_only_policy_json output with security_free's CloudTrail
# statement into the single final policy attached to the bucket.
data "aws_iam_policy_document" "tls_only" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.artifacts.arn, "${aws_s3_bucket.artifacts.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

# ---------------------------------------------------------------------------
# S3: access-logs bucket for the artifacts bucket above
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "access_logs" {
  bucket = "${var.name_prefix}-${var.account_id}-access-logs"
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    id     = "expire-14d"
    status = "Enabled"
    filter {}
    expiration {
      days = 14
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "access_logs_tls_only" {
  bucket = aws_s3_bucket.access_logs.id
  policy = data.aws_iam_policy_document.access_logs_tls_only.json
}

data "aws_iam_policy_document" "access_logs_tls_only" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.access_logs.arn, "${aws_s3_bucket.access_logs.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

# ---------------------------------------------------------------------------
# SSM Parameter Store
# ---------------------------------------------------------------------------

resource "aws_ssm_parameter" "kill_switch" {
  name  = "${local.parameter_prefix}/kill_switch"
  type  = "String"
  value = "off"
}

resource "aws_ssm_parameter" "demo_state" {
  name  = "${local.parameter_prefix}/demo_state"
  type  = "String"
  value = "down"
}

resource "aws_ssm_parameter" "trial_start_date" {
  name  = "${local.parameter_prefix}/trial_start_date"
  type  = "String"
  value = var.trial_start_date
}

resource "aws_ssm_parameter" "secrets" {
  for_each = toset([
    "anthropic_api_key",
    "langsmith_api_key",
    "slack_bot_token",
    "slack_signing_secret",
    "github_token",
  ])

  name  = "${local.parameter_prefix}/${each.value}"
  type  = "SecureString"
  value = "CHANGE_ME"

  lifecycle {
    ignore_changes = [value]
  }
}
