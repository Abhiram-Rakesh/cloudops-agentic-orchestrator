#!/usr/bin/env bash
# Seeds GuardDuty sample findings (Phase A / trial period only — see
# README.md (Security trial lifecycle)) so the security domain agent has GuardDuty
# findings to triage even without real threat activity in the account.
# Sample findings are free and auto-archive; safe to run repeatedly.
# Human-run only, requires local AWS credentials.
set -euo pipefail

REGION="ap-south-1"

DETECTOR_ID="$(aws guardduty list-detectors --region "$REGION" --query 'DetectorIds[0]' --output text)"
if [ -z "$DETECTOR_ID" ] || [ "$DETECTOR_ID" = "None" ]; then
  echo "No GuardDuty detector found in $REGION — is modules/security_trial deployed with enable_guardduty=true?" >&2
  exit 1
fi

echo "==> Seeding sample findings on detector $DETECTOR_ID"
aws guardduty create-sample-findings --region "$REGION" --detector-id "$DETECTOR_ID"

echo
echo "Done. Sample findings (prefixed [SAMPLE]) will appear in GuardDuty and flow through"
echo "Security Hub into the next collect step — Security Hub's collector filters WorkflowStatus"
echo "in {NEW, NOTIFIED}, which sample findings satisfy."
