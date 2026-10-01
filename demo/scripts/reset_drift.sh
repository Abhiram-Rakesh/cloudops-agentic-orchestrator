#!/usr/bin/env bash
# Reverts the 4 ClickOps changes simulate_clickops.sh made, *without*
# re-applying Terraform (a real `terraform apply` would also fix them, but
# this script exists so drift can be cleared without touching state —
# e.g. mid-demo, before the next `terraform plan` would show it). Human-run
# only, requires local AWS credentials.
set -euo pipefail

REGION="ap-south-1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INFRA_DIR="$SCRIPT_DIR/../infra"
STATE_FILE="$SCRIPT_DIR/.temp_debug_sg_id"

cd "$INFRA_DIR"
APP_SG_ID="$(terraform output -raw app_security_group_id)"
WEB_INSTANCE_ID="$(terraform output -raw web_instance_id)"
ASSETS_BUCKET="$(terraform output -raw assets_bucket_name)"
cd - >/dev/null

echo "==> Step 1: revoking tcp/8080 from 0.0.0.0/0 on $APP_SG_ID (orders-demo-app-sg)"
aws ec2 revoke-security-group-ingress \
  --region "$REGION" \
  --group-id "$APP_SG_ID" \
  --ip-permissions 'IpProtocol=tcp,FromPort=8080,ToPort=8080,IpRanges=[{CidrIp=0.0.0.0/0}]' \
  || echo "    (already reverted or never applied — continuing)"

echo "==> Step 2: removing cost-center/change-ticket tags from $WEB_INSTANCE_ID (orders-demo-web)"
aws ec2 delete-tags \
  --region "$REGION" \
  --resources "$WEB_INSTANCE_ID" \
  --tags Key=cost-center Key=change-ticket \
  || echo "    (already reverted or never applied — continuing)"

echo "==> Step 3: re-enabling versioning on $ASSETS_BUCKET (orders-demo-assets)"
aws s3api put-bucket-versioning \
  --region "$REGION" \
  --bucket "$ASSETS_BUCKET" \
  --versioning-configuration Status=Enabled

echo "==> Step 4: deleting orders-demo-temp-debug-sg"
if [ -f "$STATE_FILE" ]; then
  TEMP_SG_ID="$(cat "$STATE_FILE")"
  aws ec2 delete-security-group --region "$REGION" --group-id "$TEMP_SG_ID" \
    || echo "    (already deleted — continuing)"
  rm -f "$STATE_FILE"
else
  echo "    (no $STATE_FILE — was simulate_clickops.sh ever run? skipping)"
fi

echo
echo "Done. Terraform state was never touched — 'terraform plan' should now show no drift."
