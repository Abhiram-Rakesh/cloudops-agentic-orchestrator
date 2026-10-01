"""Shared collector context/result types.

Every collector implements ``collect(ctx) -> CollectorResult``. In fixture
mode (``ctx.fixtures_dir`` set — driven by ``cloudops run --fixtures PATH``)
a collector reads its own fixture file instead of calling AWS, but runs
through the *same* parsing/normalization code as the live path — see each
collector module's docstring for its exact fixture file.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from cloudops_orchestrator.config import AccountConfig, Settings
from cloudops_orchestrator.models.findings import Finding


@dataclass(frozen=True)
class CollectorContext:
    run_id: str
    settings: Settings
    account: AccountConfig
    now: datetime
    fixtures_dir: Path | None = None


@dataclass
class CollectorResult:
    findings: list[Finding] = field(default_factory=list)
    raw_evidence: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


__all__ = ["CollectorContext", "CollectorResult"]
