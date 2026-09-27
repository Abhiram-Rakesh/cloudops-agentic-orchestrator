## Summary

<!-- What changed and why. For a `cloudops-agent` PR this is auto-filled with
     the finding, evidence diff, and SOP citations. -->

## Finding / evidence

<!-- Fingerprint(s), rule ID(s), evidence link(s). -->

## SOP citations

<!-- clause_id — verbatim quote -->

## Approval record

<!-- action_id, plan_hash (prefix), approvers, decided_at -->

## Reviewer checklist

- [ ] Change is scoped only to `demo/infra/**` (or another explicitly
      allow-listed path) — see `remediation/path_guard.py`.
- [ ] `terraform plan` output (posted by `demo-plan.yml`) matches the intent
      described above and touches no unrelated resources.
- [ ] No secrets, credentials, or real account identifiers are introduced.
- [ ] If this reverts drift: the revert is dispatched via
      `demo-apply.yml`, never applied directly.
- [ ] If this codifies drift: the change ticket referenced in the
      commit/PR matches the `change-ticket` tag on the resource.

## Risk tier

<!-- T0 / T1 / T2 / T3 and required approvals, per config/policy/risk_tiers.yaml -->
