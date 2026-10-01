# One-time human-run bootstrap: the Terraform state bucket and the
# GitHub OIDC provider + 5 workflow-scoped roles every other workflow
# assumes. Every ARN below referencing modules/data's or envs/dev's
# resources (the artifacts bucket, the state table) is constructed by
# naming convention, not a real Terraform reference — bootstrap runs
# BEFORE those resources exist.
#
# VERIFY BEFORE DEPLOY: the GitHub Actions OIDC thumbprint below and the
# gha-deploy role's exact permission set should be reviewed by a human
# against the real `terraform plan` output before the first live deploy —
# see README.md (Troubleshooting).

locals {
  tfstate_bucket_name  = "${var.name_prefix}-tfstate-${var.account_id}"
  artifacts_bucket_arn = "arn:aws:s3:::${var.name_prefix}-${var.account_id}"
  state_table_arn      = "arn:aws:dynamodb:${var.region}:${var.account_id}:table/${var.name_prefix}-state"
  # GitHub appends immutable owner/repo IDs to the OIDC sub claim
  # (repo:OWNER@OWNER_ID/REPO@REPO_ID:...) rather than the classic
  # repo:OWNER/REPO:... form -- verified 2026-09-28 by decoding a live
  # token (see README.md (Troubleshooting)).
  repo_subject_prefix = "repo:${var.github_owner}@${var.github_owner_id}/${var.github_repo}@${var.github_repo_id}"
}

# ---------------------------------------------------------------------------
# Terraform state bucket
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "tfstate" {
  bucket = local.tfstate_bucket_name
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket                  = aws_s3_bucket.tfstate.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id
  rule {
    id     = "expire-noncurrent-30d"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_policy" "tfstate_tls_only" {
  bucket = aws_s3_bucket.tfstate.id
  policy = data.aws_iam_policy_document.tfstate_tls_only.json
}

data "aws_iam_policy_document" "tfstate_tls_only" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.tfstate.arn, "${aws_s3_bucket.tfstate.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

# ---------------------------------------------------------------------------
# GitHub Actions OIDC provider
# ---------------------------------------------------------------------------

resource "aws_iam_openid_connect_provider" "github_actions" {
  count           = var.create_github_oidc_provider ? 1 : 0
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

# An AWS account can only have one OIDC provider per issuer URL. Shared
# accounts (e.g. a company account other pipelines already use) commonly
# already have this one registered -- set create_github_oidc_provider =
# false to reference it read-only instead of failing on EntityAlreadyExists.
data "aws_iam_openid_connect_provider" "existing" {
  count = var.create_github_oidc_provider ? 0 : 1
  url   = "https://token.actions.githubusercontent.com"
}

locals {
  github_oidc_provider_arn = (
    var.create_github_oidc_provider
    ? aws_iam_openid_connect_provider.github_actions[0].arn
    : data.aws_iam_openid_connect_provider.existing[0].arn
  )
}

data "aws_iam_policy_document" "assume_via_github_oidc" {
  for_each = {
    deploy     = "ref:refs/heads/main"
    scanner    = "ref:refs/heads/main"
    demo_plan  = "pull_request"
    demo_apply = "ref:refs/heads/main"
    kb         = "ref:refs/heads/main"
  }

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [local.github_oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["${local.repo_subject_prefix}:${each.value}"]
    }
  }
}

# ---------------------------------------------------------------------------
# gha-deploy — deploy.yml: infra/envs/dev init/plan/apply, then kb-sync.yml
# ---------------------------------------------------------------------------

resource "aws_iam_role" "gha_deploy" {
  name               = "${var.name_prefix}-gha-deploy"
  assume_role_policy = data.aws_iam_policy_document.assume_via_github_oidc["deploy"].json
}

data "aws_iam_policy_document" "gha_deploy" {
  statement {
    sid    = "TerraformStateBackend"
    effect = "Allow"
    actions = [
      "s3:GetObject", "s3:PutObject", "s3:ListBucket",
    ]
    resources = [aws_s3_bucket.tfstate.arn, "${aws_s3_bucket.tfstate.arn}/orchestrator/*"]
  }
  statement {
    sid    = "ManageOrchestratorResources"
    effect = "Allow"
    # Broad by necessity: this role provisions every infra/ resource this
    # project defines. Scoped to services this project actually uses
    # (never NAT/VPC/RDS/etc.) and reviewed against the real
    # `terraform plan` output before first deploy (see the module docstring).
    # IAM management itself is a separate, ARN-scoped statement below.
    actions = [
      "dynamodb:*", "s3:*", "ssm:*", "lambda:*", "states:*", "scheduler:*",
      "sqs:*", "sns:*", "cloudwatch:*", "logs:*",
      "securityhub:*", "guardduty:*", "config:*", "cloudtrail:*",
      "access-analyzer:*", "ce:*", "compute-optimizer:*", "budgets:*",
    ]
    resources = ["*"]
  }
  statement {
    sid    = "ManageOrchestratorRolesAndPolicies"
    effect = "Allow"
    actions = [
      "iam:GetRole", "iam:GetPolicy", "iam:GetPolicyVersion", "iam:ListRolePolicies",
      "iam:GetRolePolicy", "iam:ListAttachedRolePolicies", "iam:ListPolicyVersions",
      "iam:CreateRole", "iam:DeleteRole", "iam:UpdateRole", "iam:UpdateAssumeRolePolicy",
      "iam:CreatePolicy", "iam:DeletePolicy", "iam:CreatePolicyVersion", "iam:DeletePolicyVersion",
      "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:AttachRolePolicy", "iam:DetachRolePolicy",
      "iam:TagRole", "iam:UntagRole", "iam:TagPolicy", "iam:UntagPolicy",
      "iam:PutRolePermissionsBoundary",
    ]
    resources = [
      "arn:aws:iam::${var.account_id}:role/${var.name_prefix}-*",
      "arn:aws:iam::${var.account_id}:policy/${var.name_prefix}-*",
    ]
  }
  statement {
    sid       = "PassRolesThisSystemCreates"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::${var.account_id}:role/${var.name_prefix}-*"]
  }
  statement {
    # Several resources this project creates trigger AWS to lazily create an
    # account-wide service-linked role on first use: aws_accessanalyzer_analyzer
    # (module.security_free), aws_computeoptimizer_enrollment_status
    # (module.cost_free), aws_guardduty_detector and aws_securityhub_account
    # (module.security_trial). All four verified live 2026-09-28 (see
    # README.md (Troubleshooting)) -- guardduty/securityhub only surfaced
    # once Phase A (enable_guardduty/enable_security_hub = true) was first
    # deployed to an account without the other's plan restriction.
    sid     = "LazyServiceLinkedRoles"
    effect  = "Allow"
    actions = ["iam:CreateServiceLinkedRole"]
    resources = [
      "arn:aws:iam::${var.account_id}:role/aws-service-role/access-analyzer.amazonaws.com/*",
      "arn:aws:iam::${var.account_id}:role/aws-service-role/compute-optimizer.amazonaws.com/*",
      "arn:aws:iam::${var.account_id}:role/aws-service-role/guardduty.amazonaws.com/*",
      "arn:aws:iam::${var.account_id}:role/aws-service-role/securityhub.amazonaws.com/*",
    ]
    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"
      values = [
        "access-analyzer.amazonaws.com",
        "compute-optimizer.amazonaws.com",
        "guardduty.amazonaws.com",
        "securityhub.amazonaws.com",
      ]
    }
  }
}

resource "aws_iam_role_policy" "gha_deploy" {
  name   = "deploy"
  role   = aws_iam_role.gha_deploy.id
  policy = data.aws_iam_policy_document.gha_deploy.json
}

# ---------------------------------------------------------------------------
# gha-scanner — prowler.yml / drift.yml
# ---------------------------------------------------------------------------

resource "aws_iam_role" "gha_scanner" {
  name               = "${var.name_prefix}-gha-scanner"
  assume_role_policy = data.aws_iam_policy_document.assume_via_github_oidc["scanner"].json
}

resource "aws_iam_role_policy_attachment" "gha_scanner_security_audit" {
  role       = aws_iam_role.gha_scanner.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "gha_scanner_view_only" {
  role       = aws_iam_role.gha_scanner.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

data "aws_iam_policy_document" "gha_scanner" {
  statement {
    sid       = "ReadDemoState"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.tfstate.arn}/demo/*"]
  }
  statement {
    sid       = "UploadScanArtifacts"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${local.artifacts_bucket_arn}/prowler/*", "${local.artifacts_bucket_arn}/drift/*"]
  }
}

resource "aws_iam_role_policy" "gha_scanner" {
  name   = "scanner"
  role   = aws_iam_role.gha_scanner.id
  policy = data.aws_iam_policy_document.gha_scanner.json
}

# ---------------------------------------------------------------------------
# gha-demo-plan — demo-plan.yml (pull_request; read-only)
# ---------------------------------------------------------------------------

resource "aws_iam_role" "gha_demo_plan" {
  name               = "${var.name_prefix}-gha-demo-plan"
  assume_role_policy = data.aws_iam_policy_document.assume_via_github_oidc["demo_plan"].json
}

resource "aws_iam_role_policy_attachment" "gha_demo_plan_view_only" {
  role       = aws_iam_role.gha_demo_plan.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

data "aws_iam_policy_document" "gha_demo_plan" {
  statement {
    sid       = "ReadDemoState"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.tfstate.arn}/demo/*"]
  }
}

resource "aws_iam_role_policy" "gha_demo_plan" {
  name   = "demo-plan"
  role   = aws_iam_role.gha_demo_plan.id
  policy = data.aws_iam_policy_document.gha_demo_plan.json
}

# ---------------------------------------------------------------------------
# gha-demo-apply — demo-apply.yml (push to demo/infra/** + workflow_dispatch)
# ---------------------------------------------------------------------------

resource "aws_iam_role" "gha_demo_apply" {
  name               = "${var.name_prefix}-gha-demo-apply"
  assume_role_policy = data.aws_iam_policy_document.assume_via_github_oidc["demo_apply"].json
}

data "aws_iam_policy_document" "gha_demo_apply" {
  statement {
    sid       = "DemoStateReadWrite"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.tfstate.arn}/demo/*"]
  }
  statement {
    sid       = "VerifyApprovalRecord"
    effect    = "Allow"
    actions   = ["dynamodb:GetItem"]
    resources = [local.state_table_arn]
  }
  statement {
    sid       = "DemoStateFlag"
    effect    = "Allow"
    actions   = ["ssm:GetParameter", "ssm:PutParameter"]
    resources = ["arn:aws:ssm:${var.region}:${var.account_id}:parameter/${var.name_prefix}/*/demo_state"]
  }
  statement {
    sid    = "ManageDemoResourcesByNameOrTag"
    effect = "Allow"
    # demo/infra's resources are always named orders-demo-* or tagged
    # app=orders-demo (see demo/infra's conventions) — scoped where the
    # service supports a resource-tag condition; Describe*/List* actions
    # that don't support resource-level ARNs remain broad by necessity.
    actions = [
      "ec2:Describe*", "ec2:CreateTags", "ec2:DeleteTags",
      "ec2:RunInstances", "ec2:TerminateInstances", "ec2:StopInstances",
      "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup",
      "ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress",
      "ec2:AllocateAddress", "ec2:ReleaseAddress", "ec2:AssociateAddress", "ec2:DisassociateAddress",
      "ec2:CreateVolume", "ec2:DeleteVolume", "ec2:AttachVolume", "ec2:DetachVolume",
      "s3:CreateBucket", "s3:DeleteBucket", "s3:PutBucketTagging", "s3:PutBucketPublicAccessBlock",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:RequestTag/app"
      values   = ["orders-demo"]
    }
  }
  statement {
    sid    = "ReadDemoResourcesByTag"
    effect = "Allow"
    actions = [
      "ec2:DescribeInstances", "ec2:DescribeSecurityGroups", "ec2:DescribeVolumes",
      "ec2:DescribeAddresses", "ec2:DescribeTags", "s3:ListAllMyBuckets", "s3:GetBucketTagging",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "gha_demo_apply" {
  name   = "demo-apply"
  role   = aws_iam_role.gha_demo_apply.id
  policy = data.aws_iam_policy_document.gha_demo_apply.json
}

# ---------------------------------------------------------------------------
# gha-kb — kb-sync.yml (Titan embeddings only)
# ---------------------------------------------------------------------------

resource "aws_iam_role" "gha_kb" {
  name               = "${var.name_prefix}-gha-kb"
  assume_role_policy = data.aws_iam_policy_document.assume_via_github_oidc["kb"].json
}

data "aws_iam_policy_document" "gha_kb" {
  statement {
    sid       = "TitanEmbeddingsOnly"
    effect    = "Allow"
    actions   = ["bedrock:InvokeModel"]
    resources = ["arn:aws:bedrock:${var.region}::foundation-model/amazon.titan-embed-text-v2:0"]
  }
  statement {
    sid       = "KbIndexReadWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:GetObject"]
    resources = ["${local.artifacts_bucket_arn}/kb/*"]
  }
}

resource "aws_iam_role_policy" "gha_kb" {
  name   = "kb-sync"
  role   = aws_iam_role.gha_kb.id
  policy = data.aws_iam_policy_document.gha_kb.json
}
