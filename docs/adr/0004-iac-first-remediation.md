# 0004 — IaC-first remediation: PR or pipeline re-apply, never a direct API call on a managed resource

## Status

Accepted.

## Context

A finding on a Terraform-managed resource can be fixed two ways: call the
AWS API directly (fast, but the next `terraform plan` sees an unexplained
diff and either fights the manual change or reverts it), or change the
Terraform source and let the normal apply pipeline pick it up (slower, but
the infrastructure's source of truth never drifts from its actual state).

Alternatives considered: always remediate via direct API call regardless
of IaC status, with a follow-up step to "reconcile" Terraform afterward
(rejected — this is exactly the ClickOps pattern `demo/`'s drift scenarios
exist to catch and revert; building a system that does it on purpose to
its own targets would be inconsistent with SHARED-002-2.3's own rule);
giving the Terraform PR agent broader repo access to fix things faster
(rejected — see ADR 0007's blast-radius reasoning, extended here to the
remediation agent specifically).

## Decision

`policy/engine.py::_validate_iac_managed_action` rejects any recommendation
whose target has `iac_managed=true` and whose `action_type` isn't
`terraform_pr`, `terraform_revert_dispatch`, or `manual_ticket` —
downgrading to `manual_ticket`/T3 with `rejected_reason` set, never
silently dropped. This is enforced **in the policy engine**, independent of
whatever the LLM proposed, and independently re-checked by
`remediation/path_guard.py` + `.github/workflows/agent-pr-guard.yml` for
the specific case of the Terraform PR agent's own file writes.

## Consequences

- A finding on an IaC-managed resource always produces either a PR (for a
  configuration fix), a `workflow_dispatch` revert (for reverting an
  unauthorized/security-weakening ClickOps change — see
  `knowledge_base/drift/DRIFT-003.md`'s disposition table), or a manual
  ticket — never a same-run automated API fix, even at T1.
- This is strictly safer but slower: a T1 SSM-automation fix on an
  unmanaged resource can execute the same run it's approved; an IaC-managed
  fix waits on a PR review cycle. Accepted as the right tradeoff for
  anything with a durable source of truth to protect.
- The demo stack's `orders-demo-web-admin-sg` (EC2.13, `iac_managed=true`)
  is deliberately chosen to exercise exactly this rejection path end to
  end — see `tests/unit/test_policy_engine.py`.
