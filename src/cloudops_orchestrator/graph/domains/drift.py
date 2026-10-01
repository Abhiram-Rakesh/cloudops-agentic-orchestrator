from __future__ import annotations

from cloudops_orchestrator.graph.domains.base import DomainSpec
from cloudops_orchestrator.models.enums import Domain

DRIFT_SPEC = DomainSpec(
    domain=Domain.DRIFT,
    guidance="""
Apply the DRIFT-003-3.1 decision table exactly, in order: a resource tagged
`cloudops:protected=true` is always `manual_ticket`/T3 regardless of any
other factor. A security-weakening change (opens ingress, disables
encryption, suspends versioning, removes Block Public Access) is always a
revert (`terraform_revert_dispatch`), even if it carries a valid change
ticket — a ticket authorizes the change process, it never authorizes
weakening a control. A cost-increasing, unticketed change is also a revert.
A ticketed, benign change (neither security-weakening nor cost-increasing)
is a codify (`terraform_pr`, `intent: codify_drift`), and the resulting PR
must reference the change ticket. An unticketed, benign change is still a
revert — "benign" does not mean "authorized." If CloudTrail attribution is
missing entirely (no actor, event, or source IP could be determined for
this change), set verdict `needs_human` and do not propose an action — do
not guess at intent from the change's content alone.
""".strip(),
)

__all__ = ["DRIFT_SPEC"]
