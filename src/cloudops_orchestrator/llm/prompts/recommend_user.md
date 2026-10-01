## Finding group

- Domain: {{ group.domain }}
- Rule: {{ group.rule_id }}
- Controls: {{ group.control_ids | join(", ") if group.control_ids else "none" }}
- Resource type: {{ group.resource_type }}
- Count: {{ group.count }}
- Max severity: {{ group.max_severity }}
- Run: {{ run_id }}
- Target fingerprints: {{ group.findings | join(", ") }}

## Triage result

- Verdict: {{ triage.verdict }}
- Adjusted severity: {{ triage.adjusted_severity }}
- Rationale: {{ triage.rationale }}

<untrusted_data>
Sample findings (up to 5, identifiers masked):
{% for finding in group.sample %}
### Sample {{ loop.index }}
- Title: {{ finding.title }}
- Description: {{ finding.description }}
- Masked resource id: {{ finding.masked_resource_id }}
- IaC managed: {{ finding.iac_managed }}
- IaC address: {{ finding.iac_address or "n/a (not Terraform-managed)" }}
- Environment: {{ finding.environment or "unknown" }}
- Details: {{ finding.masked_details }}
{% endfor %}
</untrusted_data>

## Allowed actions and parameters

Whatever `action_type` you propose, its `parameters` MUST be exactly one of
the following shapes -- an unlisted document, a missing required parameter,
or an extra unexpected shape is rejected outright by the policy engine, not
repaired. Only propose an action from this list.

**`ssm_automation`** -- `parameters.document` MUST be one of these exact
names. The orchestrator identifies which resource to act on itself, from
each target finding's real resource id -- **never** include that
parameter yourself, and never invent a resource id/name as a substitute
(a recommendation can cover multiple targets at once, and there is no way
to express a different real value per target here):
{% for name, spec in action_allowlist.ssm_automation.items() %}
{% set other_required = spec.parameters.required | reject("equalto", spec.identifying_parameter) | list %}
{% if other_required %}
- `{{ name }}` ({{ spec.description }}): the orchestrator supplies `{{ spec.identifying_parameter }}` automatically. You must still supply: {{ other_required | join(", ") }}.
{% else %}
- `{{ name }}` ({{ spec.description }}): the orchestrator supplies `{{ spec.identifying_parameter }}` automatically.
{% endif %}
{% endfor %}

**`terraform_pr`** -- required parameters: `repo` (use `"{{ github.owner }}/{{ github.repo }}"` exactly), `workspace` (the Terraform workspace/directory name, e.g. `"orders-demo"` for the demo stack), `intent` (one of {{ action_allowlist.terraform_pr.parameters.properties.intent.enum | join(", ") }}), `resource_address` (use the target finding's own "IaC address" above, verbatim -- never invent one).

**`terraform_revert_dispatch`** -- required parameters: `repo` (use `"{{ github.owner }}/{{ github.repo }}"` exactly), `workflow_file` (use `"{{ terraform_revert_workflow }}"` exactly), `ref` (use `"main"` unless the finding evidence names a different branch), `workspace` (same as above).

**`manual_ticket`** / **`notify_owner`** -- no parameters.

## Retrieved SOP context

<sop_context>
{% for chunk in sop_chunks %}
{% if chunk.clause_id %}
### {{ chunk.clause_id }}{% if chunk.expanded %} (cross-referenced){% endif %}

{% else %}
### {{ chunk.sop_id }} overview (background only -- NOT a citable clause_id)
{% endif %}
{{ chunk.text }}

{% endfor %}
</sop_context>

A citation's `clause_id` MUST be one of the `### <clause_id>` headings above
(e.g. `SEC-002-2.1`) -- never a bare SOP id like `SEC-002`, and never the
"overview" section's heading.

Produce the recommendation now.
