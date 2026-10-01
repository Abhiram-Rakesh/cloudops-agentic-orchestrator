# Knowledge Base

These are the Standard Operating Procedures the Security, Cost and Drift
agents are grounded on. They are written as realistic enterprise SOPs for a
**fictional company, Meridian Retail Technologies** — a mid-size online
retailer running its platform on AWS. No resemblance to any real
organization's policies is intended; this content exists purely to give the
agents (and this repo's tests) something concrete, internally
consistent, and normative to cite.

## Why fictional-but-realistic

The agents must never cite a clause that doesn't exist, and never paraphrase
— every citation is validated as a verbatim substring of a retrieved clause
(`policy/engine.py` rule 3). Realistic SOPs, with real compliance-mapping
tables and RACI charts, are what make that citation discipline meaningful to
test: a thin one-line policy would let every retrieval/citation test pass
trivially.

## Structure

```
knowledge_base/
├── shared/    SHARED-001 .. SHARED-004  (severity, tiers, exceptions, protection — referenced by all domains)
├── security/  SEC-001 .. SEC-006
├── cost/      COST-001 .. COST-005
└── drift/     DRIFT-001 .. DRIFT-004
```

19 documents total. Each is 1,200–2,500 words with: Purpose, Scope, Roles &
Responsibilities (RACI), Definitions, Policy Clauses, Procedures, Exceptions,
Compliance Mapping, and Revision History.

## The clause is the contract

Every `### <ID> — <title>` clause is followed by a fenced ` ```clause-meta ` YAML
block (`controls`, `prowler_checks`, `severity`, `default_action`,
`iac_managed_action`, `risk_tier`, `references`). Those fields are consumed
directly by:

- `kb/parser.py` / `kb/chunker.py` — retrieval metadata,
- `config/prowler_control_map.yaml` — must map every listed `prowler_checks`
  entry to the same `controls`,
- `config/policy/risk_tiers.yaml` and the policy engine — tier/action
  validation,
- `tests/fixtures/scenario_demo/demo_matrix.yaml` — the
  single source of truth for "given this finding, what clause, action and
  tier should the agent land on."

Changing a clause's `severity`, `default_action` or `risk_tier` here without
updating those four is exactly the kind of drift `tests/unit/test_kb_control_coverage.py`
and the pipeline tests in `tests/graph/` are meant to catch.

## Security Hub control IDs and Prowler check IDs

Control IDs (`EC2.13`, `S3.1`, …) and Prowler check IDs
(`ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22`, …) were
written from current public documentation and Prowler's own naming
convention, not confirmed against a live account or a live `prowler
--list-checks` run (Hard Rule #5 — no AWS/paid API calls while building this
repo). **Re-verify both against a live account before the first `prowler.yml`
/ `deploy.yml` run** — see the README's Troubleshooting section.
