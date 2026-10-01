# Permission boundary, one execution role per Lambda function, and the
# assumable reader/executor/automation roles.

locals {
  log_group_arn_for = { for name in local.lambda_function_names :
    name => "arn:aws:logs:${var.region}:${var.account_id}:log-group:/aws/lambda/${var.name_prefix}-${name}:*"
  }

  lambda_function_names = [
    "init_run", "collect", "domain_batch", "aggregate",
    "action_worker", "slack_handler", "failure_notifier", "trial_reminder",
  ]
}

# ---------------------------------------------------------------------------
# Permission boundary — attached to every role this module creates.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "boundary" {
  # A permissions boundary's effective grant is the INTERSECTION of this
  # policy and each role's own identity-based policy -- without an explicit
  # baseline Allow, every role bound by this policy (all 8 Lambda roles, the
  # state machine role, and others below) is restricted to nothing at all,
  # regardless of what its own inline policies grant. This is a deny-list
  # boundary by design (see the deny statements below), so it needs that baseline.
  # Explicit Deny always wins over explicit Allow regardless of statement
  # order, so this is safe to declare first.
  #
  # Missing until a real deploy's aws_sfn_state_machine.review failed with
  # "not authorized to access the Log Destination" even though its own
  # inline policy already granted the needed logs:* actions -- Step
  # Functions validates effective (boundary-intersected) permissions
  # synchronously at CreateStateMachine time, surfacing this immediately;
  # every Lambda role had the identical gap but it would only have surfaced
  # at first invocation. See README.md (Troubleshooting).
  statement {
    sid       = "AllowEverythingSubjectToDenylistBelow"
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }

  # Guardrails for services this system must never use, plus the AWS actions that would let a
  # compromised role weaken the security services this system relies on.
  statement {
    sid    = "DenyIamWrites"
    effect = "Deny"
    actions = [
      "iam:Create*", "iam:Delete*", "iam:Put*", "iam:Update*",
      "iam:Attach*", "iam:Detach*", "iam:Tag*", "iam:Untag*",
      "iam:Add*", "iam:Remove*", "iam:Set*", "iam:Upload*",
      "iam:Deactivate*", "iam:Enable*", "iam:Resync*",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "DenyOrganizations"
    effect    = "Deny"
    actions   = ["organizations:*"]
    resources = ["*"]
  }

  statement {
    sid       = "DenyDisablingCloudTrail"
    effect    = "Deny"
    actions   = ["cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:UpdateTrail"]
    resources = ["*"]
  }

  statement {
    sid       = "DenyDisablingGuardDuty"
    effect    = "Deny"
    actions   = ["guardduty:Delete*", "guardduty:Disable*", "guardduty:UpdateDetector"]
    resources = ["*"]
  }

  statement {
    sid       = "DenyDisablingSecurityHub"
    effect    = "Deny"
    actions   = ["securityhub:Disable*", "securityhub:Delete*"]
    resources = ["*"]
  }

  statement {
    sid       = "DenyDisablingConfig"
    effect    = "Deny"
    actions   = ["config:Stop*", "config:Delete*"]
    resources = ["*"]
  }

  statement {
    sid       = "DenyKmsKeyDeletion"
    effect    = "Deny"
    actions   = ["kms:ScheduleKeyDeletion"]
    resources = ["*"]
  }

  # Defense in depth: even if some other statement ever granted more than
  # intended, no role bounded by this policy can delete or restructure the
  # orchestrator's own tagged infrastructure — only the data-plane
  # operations (GetItem/PutItem/PutObject/GetParameter, ...) each role
  # actually needs remain allowed.
  statement {
    sid    = "DenyStructuralChangesToOwnInfra"
    effect = "Deny"
    actions = [
      "dynamodb:DeleteTable", "dynamodb:UpdateTable", "dynamodb:UpdateTimeToLive",
      "s3:DeleteBucket", "s3:DeleteBucketPolicy", "s3:PutBucketPolicy",
      "ssm:DeleteParameter", "ssm:DeleteParameters",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/app"
      values   = ["cloudops-agentic-orchestrator"]
    }
  }
}

resource "aws_iam_policy" "boundary" {
  name   = "${var.name_prefix}-boundary"
  policy = data.aws_iam_policy_document.boundary.json
}

# ---------------------------------------------------------------------------
# Lambda execution roles — trust policy shared by all 8 functions.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  for_each             = toset(local.lambda_function_names)
  name                 = "${var.name_prefix}-${each.value}"
  assume_role_policy   = data.aws_iam_policy_document.lambda_assume.json
  permissions_boundary = aws_iam_policy.boundary.arn
}

data "aws_iam_policy_document" "logs" {
  for_each = toset(local.lambda_function_names)
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [local.log_group_arn_for[each.value]]
  }
}

resource "aws_iam_role_policy" "logs" {
  for_each = toset(local.lambda_function_names)
  name     = "logs"
  role     = aws_iam_role.lambda[each.value].id
  policy   = data.aws_iam_policy_document.logs[each.value].json
}

# --- init_run: month-to-date spend read, GitHub token read ----------------

data "aws_iam_policy_document" "init_run" {
  statement {
    effect    = "Allow"
    actions   = ["dynamodb:GetItem", "dynamodb:UpdateItem"]
    resources = [var.state_table_arn]
  }
  statement {
    effect    = "Allow"
    actions   = ["ssm:GetParameter"]
    resources = [for arn in var.secret_parameter_arns : arn if endswith(arn, "/github_token")]
  }
}

resource "aws_iam_role_policy" "init_run" {
  name   = "init-run"
  role   = aws_iam_role.lambda["init_run"].id
  policy = data.aws_iam_policy_document.init_run.json
}

# --- collect: findings read/write, evidence S3, assume reader -------------

data "aws_iam_policy_document" "collect" {
  statement {
    effect    = "Allow"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query"]
    resources = [var.state_table_arn, "${var.state_table_arn}/index/*"]
  }
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
    resources = [var.artifacts_bucket_arn, "${var.artifacts_bucket_arn}/*"]
  }
  statement {
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = [aws_iam_role.reader.arn]
  }
  # collectors/*.py call these services directly with the Lambda's own
  # ambient credentials (aws/clients.py's get_client has no assume-role
  # logic, and no code anywhere in src/ ever calls sts:AssumeRole despite
  # the grant above and the reader role's SecurityAudit/ViewOnlyAccess/
  # reader_extra permissions existing for exactly this purpose) -- so this
  # role needs the real read permissions directly. Found live: collect
  # failed with AccessDeniedException on securityhub:GetFindings on the
  # first real deploy.yml + demo-stack run 2026-09-28 (see
  # README.md (Troubleshooting)); the other four were found by reading
  # every collector's actual API calls rather than waiting for each to
  # fail in turn. Same "account-level read API, no resource-level ARN
  # support" reasoning as modules/iam's reader_extra statement.
  statement {
    effect = "Allow"
    actions = [
      "securityhub:GetFindings",
      "ce:GetAnomalies",
      "ce:GetCostAndUsage",
      "access-analyzer:ListAnalyzers",
      "access-analyzer:ListFindings",
      "cloudtrail:LookupEvents",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "collect" {
  name   = "collect"
  role   = aws_iam_role.lambda["collect"].id
  policy = data.aws_iam_policy_document.collect.json
}

# --- domain_batch: KB/cache S3, Titan embeddings (query-time retrieval) ---

data "aws_iam_policy_document" "domain_batch" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
    resources = [var.artifacts_bucket_arn, "${var.artifacts_bucket_arn}/*"]
  }
  statement {
    effect    = "Allow"
    actions   = ["bedrock:InvokeModel"]
    resources = ["arn:aws:bedrock:${var.region}::foundation-model/amazon.titan-embed-text-v2:0"]
  }
  # get_triage_model/get_reasoning_model (llm/factory.py) need a real
  # Anthropic API key -- nothing set ANTHROPIC_API_KEY as a Lambda env var
  # and this role never had SSM access to fetch it either. Found live:
  # aggregate's identical call failed outright with "no API key or
  # authorization credentials were provided" on the first execution to
  # ever reach it -- domain_batch's own calls to this same factory were
  # never actually verified to succeed either (see
  # README.md (Troubleshooting)).
  # LangSmith tracing (llm/tracing.py) needs langsmith_api_key too -- built
  # and unit-tested but never wired to actually set the LANGCHAIN_* env vars
  # until now, so no trace was ever sent despite the parameter already
  # existing (found live 2026-09-29, see README.md (Troubleshooting)).
  statement {
    effect  = "Allow"
    actions = ["ssm:GetParameter"]
    resources = [
      for arn in var.secret_parameter_arns :
      arn if endswith(arn, "/anthropic_api_key") || endswith(arn, "/langsmith_api_key")
    ]
  }
}

resource "aws_iam_role_policy" "domain_batch" {
  name   = "domain-batch"
  role   = aws_iam_role.lambda["domain_batch"].id
  policy = data.aws_iam_policy_document.domain_batch.json
}

# --- aggregate: findings/spend/report, presigned URLs, Slack token --------

data "aws_iam_policy_document" "aggregate" {
  statement {
    effect    = "Allow"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query"]
    resources = [var.state_table_arn, "${var.state_table_arn}/index/*"]
  }
  # aggregate calls create_action_threads -> get_checkpointer (DynamoDBSaver)
  # to persist the action-approval graph's initial state, same as
  # action_worker does to resume it later -- found live: aggregate failed
  # with AccessDeniedException on this table on the first real end-to-end
  # run 2026-09-28 (see README.md (Troubleshooting)).
  statement {
    effect    = "Allow"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query"]
    resources = [var.checkpoints_table_arn]
  }
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
    resources = [var.artifacts_bucket_arn, "${var.artifacts_bucket_arn}/*"]
  }
  statement {
    effect  = "Allow"
    actions = ["ssm:GetParameter"]
    resources = [
      for arn in var.secret_parameter_arns :
      arn if endswith(arn, "/slack_bot_token") || endswith(arn, "/anthropic_api_key") || endswith(arn, "/langsmith_api_key")
    ]
  }
}

resource "aws_iam_role_policy" "aggregate" {
  name   = "aggregate"
  role   = aws_iam_role.lambda["aggregate"].id
  policy = data.aws_iam_policy_document.aggregate.json
}

# --- action_worker: action/approval/lock/audit + checkpoints, assume executor

data "aws_iam_policy_document" "action_worker" {
  statement {
    effect    = "Allow"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query"]
    resources = [var.state_table_arn, "${var.state_table_arn}/index/*"]
  }
  statement {
    effect    = "Allow"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query"]
    resources = [var.checkpoints_table_arn]
  }
  statement {
    effect    = "Allow"
    actions   = ["sts:AssumeRole"]
    resources = [aws_iam_role.executor.arn, aws_iam_role.reader.arn]
  }
  statement {
    effect  = "Allow"
    actions = ["ssm:GetParameter"]
    resources = [
      for arn in var.secret_parameter_arns :
      arn if endswith(arn, "/github_token") || endswith(arn, "/anthropic_api_key") || endswith(arn, "/langsmith_api_key")
    ]
  }
  statement {
    # check_kill_switch() (graph/action_graph.py) reads this live in
    # non-local environments before ever dispatching a remediator.
    effect    = "Allow"
    actions   = ["ssm:GetParameter"]
    resources = [for arn in var.parameter_arns : arn if endswith(arn, "/kill_switch")]
  }
}

resource "aws_iam_role_policy" "action_worker" {
  name   = "action-worker"
  role   = aws_iam_role.lambda["action_worker"].id
  policy = data.aws_iam_policy_document.action_worker.json
}

# --- slack_handler: approvals + locks, invoke itself + action_worker ------

data "aws_iam_policy_document" "slack_handler" {
  statement {
    effect    = "Allow"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:Query"]
    resources = [var.state_table_arn, "${var.state_table_arn}/index/*"]
  }
  statement {
    effect  = "Allow"
    actions = ["lambda:InvokeFunction"]
    resources = [
      "arn:aws:lambda:${var.region}:${var.account_id}:function:${var.name_prefix}-slack_handler",
      "arn:aws:lambda:${var.region}:${var.account_id}:function:${var.name_prefix}-action_worker",
    ]
  }
  statement {
    effect  = "Allow"
    actions = ["ssm:GetParameter"]
    resources = [
      for arn in var.secret_parameter_arns :
      arn if endswith(arn, "/slack_signing_secret") || endswith(arn, "/slack_bot_token")
    ]
  }
}

resource "aws_iam_role_policy" "slack_handler" {
  name   = "slack-handler"
  role   = aws_iam_role.lambda["slack_handler"].id
  policy = data.aws_iam_policy_document.slack_handler.json
}

# --- failure_notifier: Slack token only ------------------------------------

data "aws_iam_policy_document" "failure_notifier" {
  statement {
    effect    = "Allow"
    actions   = ["ssm:GetParameter"]
    resources = [for arn in var.secret_parameter_arns : arn if endswith(arn, "/slack_bot_token")]
  }
}

resource "aws_iam_role_policy" "failure_notifier" {
  name   = "failure-notifier"
  role   = aws_iam_role.lambda["failure_notifier"].id
  policy = data.aws_iam_policy_document.failure_notifier.json
}

# --- trial_reminder: Slack token + SNS publish -----------------------------

data "aws_iam_policy_document" "trial_reminder" {
  statement {
    effect    = "Allow"
    actions   = ["ssm:GetParameter"]
    resources = [for arn in var.secret_parameter_arns : arn if endswith(arn, "/slack_bot_token")]
  }
  statement {
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = ["arn:aws:sns:${var.region}:${var.account_id}:${var.name_prefix}-alerts"]
  }
}

resource "aws_iam_role_policy" "trial_reminder" {
  name   = "trial-reminder"
  role   = aws_iam_role.lambda["trial_reminder"].id
  policy = data.aws_iam_policy_document.trial_reminder.json
}

# ---------------------------------------------------------------------------
# Assumable reader role — SecurityAudit + ViewOnlyAccess + a few read APIs
# those AWS-managed policies don't cover.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "reader_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.lambda["collect"].arn, aws_iam_role.lambda["action_worker"].arn]
    }
  }
}

resource "aws_iam_role" "reader" {
  name                 = "${var.name_prefix}-reader"
  assume_role_policy   = data.aws_iam_policy_document.reader_assume.json
  permissions_boundary = aws_iam_policy.boundary.arn
}

resource "aws_iam_role_policy_attachment" "reader_security_audit" {
  role       = aws_iam_role.reader.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "reader_view_only" {
  role       = aws_iam_role.reader.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

# Cost Explorer/Compute Optimizer/CloudWatch GetMetricData/CloudTrail LookupEvents/Access
# Analyzer List|Get are account-level read APIs with no resource-level ARN support at all —
# "*" is the only valid resource for every action below (see .checkov.yml's CKV_AWS_356 skip).
data "aws_iam_policy_document" "reader_extra" {
  statement {
    effect = "Allow"
    actions = [
      "ce:GetAnomalies",
      "ce:GetCostAndUsage",
      "compute-optimizer:Get*",
      "cloudwatch:GetMetricData",
      "cloudtrail:LookupEvents",
      "access-analyzer:List*",
      "access-analyzer:Get*",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "reader_extra" {
  name   = "extra-reads"
  role   = aws_iam_role.reader.id
  policy = data.aws_iam_policy_document.reader_extra.json
}

# ---------------------------------------------------------------------------
# Assumable executor role — starts only the CloudOps-* automation documents.
# Trust requires session tags approval_id + action_id (action_worker sets
# these via sts:AssumeRole's Tags parameter at call time).
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "executor_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole", "sts:TagSession"]
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.lambda["action_worker"].arn]
    }
    condition {
      test     = "StringLike"
      variable = "aws:RequestTag/approval_id"
      values   = ["*"]
    }
    condition {
      test     = "StringLike"
      variable = "aws:RequestTag/action_id"
      values   = ["*"]
    }
  }
}

resource "aws_iam_role" "executor" {
  name                 = "${var.name_prefix}-executor"
  assume_role_policy   = data.aws_iam_policy_document.executor_assume.json
  permissions_boundary = aws_iam_policy.boundary.arn
}

data "aws_iam_policy_document" "executor" {
  statement {
    effect    = "Allow"
    actions   = ["ssm:StartAutomationExecution", "ssm:GetAutomationExecution"]
    resources = var.ssm_document_arns
  }
  statement {
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.automation.arn]
  }
}

resource "aws_iam_role_policy" "executor" {
  name   = "executor"
  role   = aws_iam_role.executor.id
  policy = data.aws_iam_policy_document.executor.json
}

# ---------------------------------------------------------------------------
# Automation role — assumed by SSM Automation itself while a document runs;
# exact actions the 7 documents need. No customer-managed KMS keys
# to deny writes on tag-protected resources by policy alone (AWS doesn't
# support a universal resource-tag condition across every action below —
# gap documented in README.md (Security); each document's own first step is the
# primary protected-tag guard).
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "automation_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ssm.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "automation" {
  name                 = "${var.name_prefix}-automation"
  assume_role_policy   = data.aws_iam_policy_document.automation_assume.json
  permissions_boundary = aws_iam_policy.boundary.arn
}

locals {
  # ec2:* mutating actions below DO support resource-level ARNs per AWS's
  # IAM action reference, so they're scoped to the resource types the 7
  # documents actually touch instead of "*" — narrower than a checkov skip
  # would otherwise require.
  ec2_arn_prefix = "arn:aws:ec2:${var.region}:${var.account_id}"
}

data "aws_iam_policy_document" "automation_mutate" {
  statement {
    sid       = "SecurityGroupRemediation"
    effect    = "Allow"
    actions   = ["ec2:RevokeSecurityGroupIngress"]
    resources = ["${local.ec2_arn_prefix}:security-group/*"]
  }
  statement {
    sid       = "IMDSv2Enforcement"
    effect    = "Allow"
    actions   = ["ec2:ModifyInstanceMetadataOptions", "ec2:StopInstances"]
    resources = ["${local.ec2_arn_prefix}:instance/*"]
  }
  statement {
    sid       = "EipRelease"
    effect    = "Allow"
    actions   = ["ec2:ReleaseAddress"]
    resources = ["${local.ec2_arn_prefix}:elastic-ip/*"]
  }
  statement {
    sid    = "Tagging"
    effect = "Allow"
    # ApplyTags targets whichever of these resource types the finding is.
    actions = ["ec2:CreateTags"]
    resources = [
      "${local.ec2_arn_prefix}:instance/*",
      "${local.ec2_arn_prefix}:security-group/*",
      "${local.ec2_arn_prefix}:volume/*",
      "${local.ec2_arn_prefix}:elastic-ip/*",
      "${local.ec2_arn_prefix}:snapshot/*",
    ]
  }
  statement {
    sid       = "VolumeSnapshotAndDelete"
    effect    = "Allow"
    actions   = ["ec2:CreateSnapshot", "ec2:DeleteVolume"]
    resources = ["${local.ec2_arn_prefix}:volume/*", "${local.ec2_arn_prefix}:snapshot/*"]
  }
}

resource "aws_iam_role_policy" "automation_mutate" {
  name   = "automation-mutate"
  role   = aws_iam_role.automation.id
  policy = data.aws_iam_policy_document.automation_mutate.json
}

# Describe*/GetBucketTagging/PutBucketPublicAccessBlock don't support resource-level ARNs per
# AWS's IAM action reference (Describe* is always "*"; S3 bucket name is discovered at scan
# time, not known statically) — see .checkov.yml's CKV_AWS_356 skip. The SSM documents' own
# first step and the executor's protected-tag check (runbook_executor.py) are the compensating
# controls.
data "aws_iam_policy_document" "automation_read_and_s3" {
  statement {
    sid       = "S3BlockPublicAccess"
    effect    = "Allow"
    actions   = ["s3:PutBucketPublicAccessBlock", "s3:GetBucketTagging"]
    resources = ["arn:aws:s3:::*"]
  }
  statement {
    sid    = "DescribeForRemediation"
    effect = "Allow"
    actions = [
      "ec2:DescribeSecurityGroups", "ec2:DescribeTags", "ec2:DescribeInstances",
      "ec2:DescribeAddresses", "ec2:DescribeSnapshots", "ec2:DescribeVolumes",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "automation_read_and_s3" {
  name   = "automation-read-and-s3"
  role   = aws_iam_role.automation.id
  policy = data.aws_iam_policy_document.automation_read_and_s3.json
}
