"""The Terraform PR agent's structured LLM output."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class HclEdit(BaseModel):
    """A proposed edit to one Terraform resource block. ``original_block``
    must match the located block text exactly (validated by the caller,
    not the model itself) so the agent can never silently edit the wrong
    thing; ``new_block`` replaces it verbatim."""

    model_config = ConfigDict(frozen=True)

    file_path: str
    original_block: str
    new_block: str
    explanation: str
    risk_notes: str


__all__ = ["HclEdit"]
