# Demo Stack Violations

Generated from `tests/fixtures/scenario_demo/demo_matrix.yaml` by
`scripts/gen_demo_artifacts.py` — do not hand-edit this file.

Every row below is an intentional, safe-by-construction SOP violation
the demo stack (`demo/infra`) is built to exhibit, so the CloudOps
agents have something real to find, triage, and (with approval) fix.

| Resource | Domain | Clause(s) | Severity | Action | Tier | Notes |
|---|---|---|---|---|---|---|
| `orders-demo-vpc` | security | SEC-002-2.3 | medium | manual_ticket | T1 | No VPC Flow Logs configured |
| `orders-demo-vpc-default-sg` | security | SEC-002-2.2 | medium | manual_ticket | T1 | Default VPC security group left at AWS default (unmanaged by Terraform) |
| `orders-demo-web-admin-sg` | security | SEC-002-2.1 | high | ssm_automation | T1 | Ingress tcp/22 from 0.0.0.0/0 |
| `orders-demo-app-sg` | drift | DRIFT-003-3.1 | medium | terraform_revert_dispatch | T1 | simulate_clickops.sh step 1: authorizes tcp/8080 from 0.0.0.0/0 — security-weakening, unticketed -> revert |
| `orders-demo-web` | security | SEC-002-2.4 | medium | manual_ticket | T2 | Public IPv4 outside the approved public tier |
| `orders-demo-web` | security | SEC-005-5.1 | high | ssm_automation | T1 | http_tokens=optional (IMDSv1 permitted) |
| `orders-demo-web` | security | SEC-005-5.2 | medium | manual_ticket | T1 | No instance profile; not SSM-managed |
| `orders-demo-web` | security | SEC-003-3.3 | medium | manual_ticket | T2 | Unencrypted root volume |
| `orders-demo-web` | cost | COST-001-1.1 | medium | ssm_automation | T1 | Missing cost-center tag |
| `orders-demo-web` | cost | COST-005-5.1 | low | ssm_automation | T1 | Missing schedule tag |
| `orders-demo-web` | drift | DRIFT-002-2.2, DRIFT-003-3.1 | medium | terraform_pr | T1 | simulate_clickops.sh step 2: tags cost-center=CC-1042, change-ticket=CHG-2211 — ticketed & benign -> codify |
| `orders-demo-batch-worker` | cost | COST-002-2.1 | medium | ssm_automation | T1 | Idle non-prod instance (CPU < 5%, net < 5MB/day); only present when enable_idle_instance=true (requires `enable_idle_instance=true`) |
| `orders-demo-batch-worker` | cost | COST-001-1.1 | medium | ssm_automation | T1 | Missing owner and cost-center tags (requires `enable_idle_instance=true`) |
| `orders-demo-batch-worker` | security | SEC-005-5.2 | medium | manual_ticket | T1 | No instance profile (requires `enable_idle_instance=true`) |
| `orders-demo-scratch` | security | SEC-003-3.3 | medium | manual_ticket | T2 | Unencrypted 1 GiB gp2 volume |
| `orders-demo-scratch` | cost | COST-002-2.2 | medium | ssm_automation | T2 | Unattached for more than 7 days |
| `orders-demo-scratch` | cost | COST-003-3.1 | low | manual_ticket | T1 | gp2 volume type |
| `orders-demo-scratch` | cost | COST-001-1.1 | medium | ssm_automation | T1 | Missing required tags |
| `orders-demo-eip-unused` | cost | COST-002-2.3 | low | ssm_automation | T1 | Unassociated Elastic IP |
| `orders-demo-eip-unused` | cost | COST-001-1.1 | medium | ssm_automation | T1 | Missing required tags |
| `orders-demo-exports` | security | SEC-003-3.2 | high | ssm_automation | T1 | BPA off + public-read policy on public/* prefix (enable_public_bucket_violation=true) |
| `orders-demo-exports` | security | SEC-003-3.4 | medium | manual_ticket | T1 | No TLS-only bucket policy |
| `orders-demo-exports` | security | SEC-004-4.3 | low | manual_ticket | T1 | No server access logging |
| `orders-demo-exports` | cost | COST-001-1.1 | medium | ssm_automation | T1 | Missing cost-center tag |
| `orders-demo-exports` | cost | COST-003-3.3 | low | manual_ticket | T1 | No lifecycle policy |
| `orders-demo-assets` | drift | DRIFT-003-3.1, SEC-003-3.5 | medium | terraform_revert_dispatch | T1 | simulate_clickops.sh step 3: suspends versioning — security-weakening -> revert |
| `orders-demo-legacy-payments` | security | SEC-003-3.4, SHARED-004-4.1 | medium | manual_ticket | T3 | No TLS-only policy, but tagged cloudops:protected=true -> forced T3/manual regardless of clause's own catalog tier |
| `orders-demo-legacy-admin-role` | security | SEC-001-1.1 | high | manual_ticket | T3 | orders-demo-wildcard-policy grants Action:* Resource:* — automation boundary (SHARED-002-2.5) forces T3 even though iac_managed=true |
| `orders-demo-temp-debug-sg` | drift | DRIFT-001-1.2 | medium | manual_ticket | T2 | simulate_clickops.sh step 4: creates an unmanaged SG (tag app=orders-demo, no managed-by) |
| `orders-demo-temp-debug-sg` | security | SEC-002-2.5 | critical | ssm_automation | T1 | simulate_clickops.sh step 4: tcp/5432 open from 0.0.0.0/0 on the unmanaged SG — exercises the SSM executor path in dry-run since iac_managed=false |
