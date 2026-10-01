## Approved recommendation

- Intent: {{ intent }}
- Resource address: {{ resource_address }}
- Recommendation: {{ recommendation.title }}
- Summary: {{ recommendation.summary }}
- Rationale: {{ recommendation.rationale }}

## Current HCL

<untrusted_data>
File: {{ file_path }}

```hcl
{{ current_hcl }}
```
</untrusted_data>

## SOP citations backing this change

{% for citation in recommendation.citations %}
- {{ citation.clause_id }}: "{{ citation.quote }}"
{% endfor %}

Produce the `HclEdit` now, editing only the `{{ resource_address }}` block.
