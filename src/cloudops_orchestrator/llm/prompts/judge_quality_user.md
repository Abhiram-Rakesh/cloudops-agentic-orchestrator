## Finding group

- Domain: {{ group.domain }}
- Rule: {{ group.rule_id }}
- Resource type: {{ group.resource_type }}

<untrusted_data>
### Triage
- Verdict: {{ triage.verdict }}
- Adjusted severity: {{ triage.adjusted_severity }}
- Rationale: {{ triage.rationale }}
- Citations: {{ triage.citations }}

### Recommendation
{% if recommendation %}
- Action type: {{ recommendation.action_type }}
- Effective risk tier: {{ recommendation.effective_risk_tier }}
- Summary: {{ recommendation.summary }}
- Rationale: {{ recommendation.rationale }}
- Blast radius: {{ recommendation.blast_radius }}
- Citations: {{ recommendation.citations }}
{% else %}
(No recommendation was produced -- the triage verdict was not "actionable".)
{% endif %}
</untrusted_data>

Score this triage/recommendation now.
