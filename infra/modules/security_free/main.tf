# IAM Access Analyzer and a multi-region CloudTrail
# management-events trail (first trail free; only S3 storage costs apply).

resource "aws_accessanalyzer_analyzer" "external_access" {
  analyzer_name = "${var.name_prefix}-external-access"
  type          = "ACCOUNT"
}

# CloudTrail needs GetBucketAcl + a conditional PutObject on the artifacts
# bucket's cloudtrail/ prefix. This is exposed as JSON (not attached here)
# because only one aws_s3_bucket_policy resource can exist per bucket —
# envs/dev merges this with modules/data's TLS-only statement.
data "aws_iam_policy_document" "cloudtrail_bucket_access" {
  statement {
    sid       = "CloudTrailGetBucketAcl"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [var.artifacts_bucket_arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
  statement {
    sid       = "CloudTrailPutObject"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${var.artifacts_bucket_arn}/cloudtrail/AWSLogs/${var.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_cloudtrail" "management_events" {
  name                          = "${var.name_prefix}-trail"
  s3_bucket_name                = var.artifacts_bucket_name
  s3_key_prefix                 = "cloudtrail"
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = {
    # Forces this resource to wait for the root module's merged bucket
    # policy (which grants CloudTrail write access) — see the
    # bucket_policy_ready variable's description.
    "cloudops:bucket-policy-ready" = var.bucket_policy_ready
  }
}
