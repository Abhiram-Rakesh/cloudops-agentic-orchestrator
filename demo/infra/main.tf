# Every resource below matches a row in
# tests/fixtures/scenario_demo/demo_matrix.yaml — see that file for exactly
# which SOP clause each violation is meant to trigger. checkov findings on
# this file are the *point*, not a bug: each is skipped with an inline
# skip-directive comment placed *inside* the resource block it belongs to
# (the same comment placed outside a block's braces is silently ignored —
# verified against checkov's own docs), never silently fixed here
# (fix demo violations via a reviewed agent PR, not by
# hand-editing demo/infra). NOTE: do not spell the literal directive syntax
# out in prose anywhere in this file, including this comment — checkov's
# line-matcher treats any line containing it as a real directive and
# crashes if the text after it doesn't parse as one (verified empirically).

locals {
  account_id = data.aws_caller_identity.current.account_id
}

# ---------------------------------------------------------------------------
# Network — orders-demo-vpc (SEC-002-2.3: no VPC Flow Logs;
# SEC-002-2.2: the default SG is deliberately left unmanaged below).
# ---------------------------------------------------------------------------

resource "aws_vpc" "orders_demo" {
  #checkov:skip=CKV2_AWS_11: SEC-002-2.3 — this VPC deliberately has no Flow Logs for the agent to find
  #checkov:skip=CKV2_AWS_12: SEC-002-2.2 — the default SG is deliberately left unmanaged (iac_managed=false) so the agent finds it via live description, not Terraform
  cidr_block           = "10.50.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name          = "orders-demo-vpc"
    owner         = "orders-team"
    "cost-center" = "CC-2040"
  }
}
# orders-demo-vpc-default-sg (AWS's auto-created default SG) is never
# referenced anywhere in this file — it stays unmanaged, matching
# iac_managed=false in demo_matrix.yaml.

resource "aws_internet_gateway" "orders_demo" {
  vpc_id = aws_vpc.orders_demo.id

  tags = {
    Name          = "orders-demo-igw"
    owner         = "orders-team"
    "cost-center" = "CC-2040"
  }
}

# map_public_ip_on_launch is deliberately false: only orders-demo-web (via
# its own explicit associate_public_ip_address) gets a public IP —
# SEC-002-2.4 is that ONE instance's finding, not every instance in the
# subnet's.
resource "aws_subnet" "orders_demo_public" {
  vpc_id                  = aws_vpc.orders_demo.id
  cidr_block              = "10.50.1.0/24"
  availability_zone       = "ap-south-1a"
  map_public_ip_on_launch = false

  tags = {
    Name          = "orders-demo-public"
    owner         = "orders-team"
    "cost-center" = "CC-2040"
  }
}

resource "aws_route_table" "orders_demo_public" {
  vpc_id = aws_vpc.orders_demo.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.orders_demo.id
  }

  tags = {
    Name          = "orders-demo-public-rt"
    owner         = "orders-team"
    "cost-center" = "CC-2040"
  }
}

resource "aws_route_table_association" "orders_demo_public" {
  subnet_id      = aws_subnet.orders_demo_public.id
  route_table_id = aws_route_table.orders_demo_public.id
}

# ---------------------------------------------------------------------------
# Security groups
# ---------------------------------------------------------------------------

resource "aws_security_group" "web_admin" {
  #checkov:skip=CKV_AWS_24: SEC-002-2.1 — world-open admin ingress is the finding this SG exists to demonstrate (CloudOps-RevokeSGIngressWorld's target)
  #checkov:skip=CKV_AWS_382: unrestricted egress is this demo's baseline choice, not a cataloged violation
  name        = "orders-demo-web-admin-sg"
  description = "orders-demo web tier - deliberately world-open SSH for SEC-002-2.1"
  vpc_id      = aws_vpc.orders_demo.id

  ingress {
    description = "SSH from anywhere (violation: SEC-002-2.1)"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Unrestricted egress (demo baseline, not a cataloged finding)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name          = "orders-demo-web-admin-sg"
    owner         = "orders-team"
    "cost-center" = "CC-2040"
  }
}

# Compliant at demo-up (drift target — simulate_clickops.sh step 1 opens
# tcp/8080 to 0.0.0.0/0 on this SG directly via the AWS API, outside
# Terraform, to demonstrate DRIFT-003-3.1).
resource "aws_security_group" "app" {
  #checkov:skip=CKV_AWS_382: unrestricted egress is this demo's baseline choice, not a cataloged violation
  name        = "orders-demo-app-sg"
  description = "orders-demo app tier - compliant baseline, drift target"
  vpc_id      = aws_vpc.orders_demo.id

  ingress {
    description     = "App port from the web tier only"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.web_admin.id]
  }

  egress {
    description = "Unrestricted egress (demo baseline, not a cataloged finding)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name          = "orders-demo-app-sg"
    owner         = "orders-team"
    "cost-center" = "CC-2040"
  }
}

# ---------------------------------------------------------------------------
# EC2 — orders-demo-web (multiple violations) and orders-demo-batch-worker
# (only when enable_idle_instance=true).
# ---------------------------------------------------------------------------

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-kernel-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_instance" "web" {
  #checkov:skip=CKV_AWS_79: SEC-005-5.1 — http_tokens=optional (IMDSv1 permitted) is this instance's own finding
  #checkov:skip=CKV_AWS_8: SEC-003-3.3 — the unencrypted root volume below is this instance's own finding
  #checkov:skip=CKV_AWS_88: SEC-002-2.4 — the public IP below is this instance's own finding
  #checkov:skip=CKV2_AWS_41: SEC-005-5.2 — no instance profile is this instance's own finding
  #checkov:skip=CKV_AWS_126: detailed monitoring is a paid feature, not needed for an ephemeral demo instance
  ami                         = data.aws_ami.al2023.id
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.orders_demo_public.id
  vpc_security_group_ids      = [aws_security_group.web_admin.id]
  associate_public_ip_address = true # SEC-002-2.4: public IPv4 outside the approved public tier
  ebs_optimized               = true

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional" # SEC-005-5.1
  }

  root_block_device {
    volume_size = 30 # matches the current al2023 AMI's root snapshot minimum (was smaller when this repo was built)
    volume_type = "gp3"
    encrypted   = false # SEC-003-3.3
  }

  tags = {
    Name  = "orders-demo-web"
    owner = "orders-team"
    # cost-center intentionally omitted: COST-001-1.1
    # schedule intentionally omitted: COST-005-5.1
  }
}

resource "aws_instance" "batch_worker" {
  #checkov:skip=CKV2_AWS_41: SEC-005-5.2 — no instance profile is this instance's own finding
  #checkov:skip=CKV_AWS_126: detailed monitoring is a paid feature, not needed for an ephemeral demo instance
  count = var.enable_idle_instance ? 1 : 0

  ami                    = data.aws_ami.al2023.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.orders_demo_public.id
  vpc_security_group_ids = [aws_security_group.app.id]
  ebs_optimized          = true

  root_block_device {
    volume_size = 30 # matches the current al2023 AMI's root snapshot minimum (was smaller when this repo was built)
    volume_type = "gp3"
    encrypted   = true
  }

  tags = {
    Name = "orders-demo-batch-worker"
    # owner and cost-center intentionally omitted: COST-001-1.1
  }
}

# ---------------------------------------------------------------------------
# EBS — orders-demo-scratch: unencrypted, gp2, unattached, under-tagged.
# ---------------------------------------------------------------------------

resource "aws_ebs_volume" "scratch" {
  #checkov:skip=CKV_AWS_3: SEC-003-3.3 — unencrypted is this volume's own finding
  #checkov:skip=CKV_AWS_189: SEC-003-3.3 — see above
  availability_zone = "ap-south-1a"
  size              = 1
  type              = "gp2" # COST-003-3.1

  tags = {
    Name = "orders-demo-scratch"
    # owner and cost-center intentionally omitted: COST-001-1.1
  }
}

# ---------------------------------------------------------------------------
# EIP — orders-demo-eip-unused: never associated, under-tagged.
# ---------------------------------------------------------------------------

resource "aws_eip" "unused" {
  #checkov:skip=CKV2_AWS_19: COST-002-2.3 — never associated is this EIP's own finding (CloudOps-ReleaseEIP's target)
  domain = "vpc"

  tags = {
    Name = "orders-demo-eip-unused"
    # owner and cost-center intentionally omitted: COST-001-1.1
  }
}

# ---------------------------------------------------------------------------
# S3 — orders-demo-exports (multiple violations), orders-demo-assets
# (compliant, drift target), orders-demo-legacy-payments (protected).
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "exports" {
  #checkov:skip=CKV_AWS_144: cross-region replication not needed for a demo bucket
  #checkov:skip=CKV_AWS_18: SEC-004-4.3 — no access logging is this bucket's own finding
  #checkov:skip=CKV2_AWS_61: COST-003-3.3 — no lifecycle policy is this bucket's own finding
  #checkov:skip=CKV2_AWS_6: a public access block IS attached (aws_s3_bucket_public_access_block.exports_blocked/exports_open below) — checkov's graph check can't resolve which of the two count-gated resources applies
  bucket = "orders-demo-exports-${local.account_id}"

  tags = {
    Name  = "orders-demo-exports"
    owner = "orders-team"
    # cost-center intentionally omitted: COST-001-1.1
    "data-classification" = "internal"
  }
}
# No aws_s3_bucket_server_side_encryption_configuration override: S3 now
# defaults new buckets to SSE-S3, so this stays secure without config.

# Always exists (unlike a count-conditional resource, which would leave
# this bucket with *no* public access block at all on the compliant
# default path) — its block_* values flip to false only when
# enable_public_bucket_violation=true, which is SEC-003-3.2's own finding.
# Two count-gated resources instead of one with a computed !var.x
# expression: checkov's static analysis can't resolve a boolean-negation
# on a variable reference (it only evaluates literal true/false), so this
# gives it a literal value on whichever resource is actually "on" for a
# given tfvars, instead of failing both compliant and violating cases the
# same way.
resource "aws_s3_bucket_public_access_block" "exports_blocked" {
  count  = var.enable_public_bucket_violation ? 0 : 1
  bucket = aws_s3_bucket.exports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "exports_open" {
  #checkov:skip=CKV_AWS_53: SEC-003-3.2 — gated behind enable_public_bucket_violation, this bucket's own finding
  #checkov:skip=CKV_AWS_54: SEC-003-3.2 — see above
  #checkov:skip=CKV_AWS_55: SEC-003-3.2 — see above
  #checkov:skip=CKV_AWS_56: SEC-003-3.2 — see above
  count  = var.enable_public_bucket_violation ? 1 : 0
  bucket = aws_s3_bucket.exports.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

data "aws_iam_policy_document" "exports_public_read" {
  count = var.enable_public_bucket_violation ? 1 : 0
  statement {
    sid       = "PublicReadForExportsPrefix"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.exports.arn}/public/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

resource "aws_s3_bucket_policy" "exports_public_read" {
  count      = var.enable_public_bucket_violation ? 1 : 0
  bucket     = aws_s3_bucket.exports.id
  policy     = data.aws_iam_policy_document.exports_public_read[0].json
  depends_on = [aws_s3_bucket_public_access_block.exports_open]
}
# No TLS-only statement anywhere on this bucket: SEC-003-3.4 (present
# regardless of enable_public_bucket_violation).

resource "aws_s3_bucket" "demo_logs" {
  bucket = "orders-demo-logs-${local.account_id}"

  tags = {
    Name          = "orders-demo-logs"
    owner         = "orders-team"
    "cost-center" = "CC-2040"
  }
}

resource "aws_s3_bucket_public_access_block" "demo_logs" {
  bucket                  = aws_s3_bucket.demo_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "demo_logs_tls_only" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.demo_logs.arn, "${aws_s3_bucket.demo_logs.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "demo_logs_tls_only" {
  bucket = aws_s3_bucket.demo_logs.id
  policy = data.aws_iam_policy_document.demo_logs_tls_only.json
}

resource "aws_s3_bucket_lifecycle_configuration" "demo_logs" {
  bucket = aws_s3_bucket.demo_logs.id
  rule {
    id     = "expire-90d"
    status = "Enabled"
    filter {}
    expiration {
      days = 90
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Compliant at demo-up — simulate_clickops.sh step 3 suspends versioning
# directly via the AWS API to demonstrate DRIFT-003-3.1 / SEC-003-3.5.
resource "aws_s3_bucket" "assets" {
  bucket = "orders-demo-assets-${local.account_id}"

  tags = {
    Name                  = "orders-demo-assets"
    owner                 = "orders-team"
    "cost-center"         = "CC-2040"
    "data-classification" = "internal"
  }
}

resource "aws_s3_bucket_versioning" "assets" {
  bucket = aws_s3_bucket.assets.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = aws_s3_bucket.assets.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "assets_tls_only" {
  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.assets.arn, "${aws_s3_bucket.assets.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "assets_tls_only" {
  bucket = aws_s3_bucket.assets.id
  policy = data.aws_iam_policy_document.assets_tls_only.json
}

resource "aws_s3_bucket_logging" "assets" {
  bucket        = aws_s3_bucket.assets.id
  target_bucket = aws_s3_bucket.demo_logs.id
  target_prefix = "s3-access/orders-demo-assets/"
}

resource "aws_s3_bucket_lifecycle_configuration" "assets" {
  bucket = aws_s3_bucket.assets.id
  rule {
    id     = "expire-noncurrent-90d"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 90
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# Protected — tagged cloudops:protected=true, confidential data. Still has
# a real violation (no TLS-only policy) so the agent must recommend
# manual_ticket/T3, never attempt automated remediation on it.
resource "aws_s3_bucket" "legacy_payments" {
  #checkov:skip=CKV_AWS_18: not this bucket's cataloged finding (SEC-003-3.4 is); kept minimal otherwise
  bucket = "orders-demo-legacy-payments-${local.account_id}"

  tags = {
    Name                  = "orders-demo-legacy-payments"
    owner                 = "orders-team"
    "cost-center"         = "CC-2040"
    "data-classification" = "confidential"
    "cloudops:protected"  = "true"
  }
}

resource "aws_s3_bucket_versioning" "legacy_payments" {
  bucket = aws_s3_bucket.legacy_payments.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "legacy_payments" {
  bucket                  = aws_s3_bucket.legacy_payments.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "legacy_payments" {
  bucket = aws_s3_bucket.legacy_payments.id
  rule {
    id     = "expire-noncurrent-365d"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 365
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}
# No TLS-only bucket policy: SEC-003-3.4 (this bucket's cataloged finding).

# ---------------------------------------------------------------------------
# IAM — orders-demo-legacy-admin-role: wildcard policy (SEC-001-1.1).
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "legacy_admin_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "legacy_admin" {
  name               = "orders-demo-legacy-admin-role"
  assume_role_policy = data.aws_iam_policy_document.legacy_admin_assume.json

  tags = {
    owner         = "orders-team"
    "cost-center" = "CC-2040"
  }
}

data "aws_iam_policy_document" "wildcard" {
  #checkov:skip=CKV_AWS_1: SEC-001-1.1 — Action:*/Resource:* is this role's own cataloged finding (orders-demo-wildcard-policy)
  #checkov:skip=CKV_AWS_49: SEC-001-1.1 — see above
  #checkov:skip=CKV_AWS_107: SEC-001-1.1 — see above
  #checkov:skip=CKV2_AWS_40: SEC-001-1.1 — see above
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "wildcard" {
  name   = "orders-demo-wildcard-policy"
  policy = data.aws_iam_policy_document.wildcard.json
}

resource "aws_iam_role_policy_attachment" "legacy_admin_wildcard" {
  role       = aws_iam_role.legacy_admin.name
  policy_arn = aws_iam_policy.wildcard.arn
}
