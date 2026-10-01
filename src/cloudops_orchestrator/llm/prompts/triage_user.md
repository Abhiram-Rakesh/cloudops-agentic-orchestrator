## Finding group

- Domain: {{ group.domain }}
- Rule: {{ group.rule_id }}
- Controls: {{ group.control_ids | join(", ") if group.control_ids else "none" }}
- Resource type: {{ group.resource_type }}
- Count: {{ group.count }} finding(s) matching this rule + resource type
- Max severity observed: {{ group.max_severity }}

<untrusted_data>
Sample findings (up to 5, identifiers masked):
{% for finding in group.sample %}
### Sample {{ loop.index }}
- Title: {{ finding.title }}
- Description: {{ finding.description }}
- Masked resource id: {{ finding.masked_resource_id }}
- IaC managed: {{ finding.iac_managed }}
- Environment: {{ finding.environment or "unknown" }}
- Details: {{ finding.masked_details }}
{% endfor %}
</untrusted_data>

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
{% if not sop_chunks %}
(No relevant SOP clause was retrieved for this finding group.)
{% endif %}
</sop_context>

A citation's `clause_id` MUST be one of the `### <clause_id>` headings above
(e.g. `SEC-002-2.1`) -- never a bare SOP id like `SEC-002`, and never the
"overview" section's heading.

Triage this finding group now.
