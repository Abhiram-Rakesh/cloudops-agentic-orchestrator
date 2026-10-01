#!/usr/bin/env bash
# Simulates 4 ClickOps changes made *outside* Terraform against the live
# demo stack, matching the `post_clickops` rows in
# tests/fixtures/scenario_demo/demo_matrix.yaml — for drift.yml (or the
# next weekly review run) to find. Human-run only, requires local AWS
# credentials and CONFIRM=yes (never invoked by an agent).
set -euo pipefail

if [ "${CONFIRM:-}" != "yes" ]; then
  echo "This modifies real AWS resources outside Terraform. Re-run as: CONFIRM=yes $0" >&2
  exit 1
fi

REGION="ap-south-1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INFRA_DIR="$SCRIPT_DIR/../infra"
STATE_FILE="$SCRIPT_DIR/.temp_debug_sg_id"

cd "$INFRA_DIR"
APP_SG_ID="$(terraform output -raw app_security_group_id)"
WEB_INSTANCE_ID="$(terraform output -raw web_instance_id)"
ASSETS_BUCKET="$(terraform output -raw assets_bucket_name)"
VPC_ID="$(terraform output -raw vpc_id)"
cd - >/dev/null

echo "==> Step 1 (DRIFT-003-3.1): opening tcp/8080 to 0.0.0.0/0 on $APP_SG_ID (orders-demo-app-sg)"
aws ec2 authorize-security-group-ingress \
  --region "$REGION" \
  --group-id "$APP_SG_ID" \
  --ip-permissions 'IpProtocol=tcp,FromPort=8080,ToPort=8080,IpRanges=[{CidrIp=0.0.0.0/0,Description="clickops-demo"}]'

echo "==> Step 2 (DRIFT-002-2.2/DRIFT-003-3.1): tagging $WEB_INSTANCE_ID (orders-demo-web) with cost-center=CC-1042, change-ticket=CHG-2211"
aws ec2 create-tags \
  --region "$REGION" \
  --resources "$WEB_INSTANCE_ID" \
  --tags Key=cost-center,Value=CC-1042 Key=change-ticket,Value=CHG-2211

echo "==> Step 3 (DRIFT-003-3.1/SEC-003-3.5): suspending versioning on $ASSETS_BUCKET (orders-demo-assets)"
aws s3api put-bucket-versioning \
  --region "$REGION" \
  --bucket "$ASSETS_BUCKET" \
  --versioning-configuration Status=Suspended

echo "==> Step 4 (DRIFT-UNMANAGED/SEC-002-2.5): creating unmanaged orders-demo-temp-debug-sg with tcp/5432 open from 0.0.0.0/0"
TEMP_SG_ID="$(aws ec2 create-security-group \
  --region "$REGION" \
  --group-name orders-demo-temp-debug-sg \
  --description "Unmanaged SG created by simulate_clickops.sh (DRIFT-UNMANAGED demo)" \
  --vpc-id "$VPC_ID" \
  --query 'GroupId' --output text)"
aws ec2 create-tags --region "$REGION" --resources "$TEMP_SG_ID" \
  --tags Key=Name,Value=orders-demo-temp-debug-sg Key=app,Value=orders-demo
aws ec2 authorize-security-group-ingress \
  --region "$REGION" \
  --group-id "$TEMP_SG_ID" \
  --ip-permissions 'IpProtocol=tcp,FromPort=5432,ToPort=5432,IpRanges=[{CidrIp=0.0.0.0/0,Description="clickops-demo"}]'
echo "$TEMP_SG_ID" >"$STATE_FILE"

echo
echo "Done. 4 ClickOps changes applied outside Terraform."
echo "Run 'make reset-drift' to revert them without re-applying Terraform,"
echo "or trigger drift.yml / wait for the next weekly review run to see them found."
