from __future__ import annotations

from cloudops_orchestrator.graph.domains.base import DomainSpec
from cloudops_orchestrator.models.enums import Domain

SECURITY_SPEC = DomainSpec(
    domain=Domain.SECURITY,
    guidance="""
When triaging, weigh three things: **exposure** (is the resource reachable
from the public internet, or only from a private network?),
**exploitability** (does exploiting this require additional privileges
first, or is it a single unauthenticated step?), and any **compensating
controls** already visible in the finding's tags or details (e.g. a WAF, a
private subnet, IMDSv2 already enforced independently). A finding with no
obvious attack path today may still be `actionable` if the retrieved SOP
requires proactive remediation regardless of current exploitability — do
not downgrade severity purely because you personally judge the risk low;
only cite what the SOP itself says.

When recommending, prefer the SOP clause's own `default_action` for a
non-IaC-managed target and reference the exact SSM document it names. Never
propose broadening a security group, disabling encryption, or granting
additional IAM permissions under any circumstances, even if doing so would
appear to "fix" an unrelated finding.
""".strip(),
)

__all__ = ["SECURITY_SPEC"]
