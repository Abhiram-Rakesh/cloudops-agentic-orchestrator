"""SOP exception model (SHARED-003) — a time-bound, scoped suppression of a
finding's (or an entire clause's) SLA enforcement, always requiring a
justification, compensating control, and owner (SHARED-003-3.1)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from cloudops_orchestrator.models.common import UTCDatetime


class SOPException(BaseModel):
    model_config = ConfigDict(frozen=True)

    exception_id: str
    clause_id: str
    fingerprint: str | None = None  # None = clause-wide (e.g. trial switchover)
    justification: str
    compensating_control: str
    owner: str | None = None
    requested_by: str | None = None
    created_at: UTCDatetime
    expires_at: UTCDatetime


__all__ = ["SOPException"]
