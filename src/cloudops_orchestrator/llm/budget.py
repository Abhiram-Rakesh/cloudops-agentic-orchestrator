"""LLM cost tracking and per-run budget enforcement.

Priced from ``config/settings.*.yaml``'s ``llm.prices_per_mtok`` table (USD
per 1M tokens); cache reads are 0.1x the model's input price, cache writes
1.25x, matching Anthropic's published prompt-caching discount/premium.
``BudgetTracker.record`` raises ``BudgetExceeded`` the instant a run's
running total crosses ``max_cost_usd_per_run`` — the caller (``steps/
run_domain_batch.py``) catches this and finishes the batch gracefully
with a partial result flagged ``budget_exhausted``, never mid-write.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cloudops_orchestrator.config import LLMConfig
from cloudops_orchestrator.models.report import LLMUsage, ModelUsage

CACHE_READ_MULTIPLIER = 0.1
CACHE_WRITE_MULTIPLIER = 1.25


class BudgetExceeded(Exception):
    def __init__(self, spent_usd: float, limit_usd: float) -> None:
        self.spent_usd = spent_usd
        self.limit_usd = limit_usd
        super().__init__(f"LLM spend ${spent_usd:.4f} exceeded the ${limit_usd:.4f} run budget")


@dataclass
class BudgetTracker:
    config: LLMConfig
    max_cost_usd_per_run: float
    _per_model: dict[str, ModelUsage] = field(default_factory=dict)
    _total_cost_usd: float = 0.0
    budget_exhausted: bool = False

    def _price_for(self, model_name: str) -> tuple[float, float] | None:
        price = self.config.prices_per_mtok.get(model_name)
        if price is None:
            return None
        return price.input_per_mtok, price.output_per_mtok

    def record(
        self,
        *,
        model_name: str,
        input_tokens: int,
        output_tokens: int,
        cache_read_tokens: int = 0,
        cache_creation_tokens: int = 0,
    ) -> float:
        """Record one LLM call's usage; returns that call's cost in USD.

        Raises ``BudgetExceeded`` (after recording — the caller sees the
        real running total in the exception) once the run total exceeds
        ``max_cost_usd_per_run``.
        """
        prices = self._price_for(model_name)
        if prices is None:
            cost = 0.0
        else:
            input_per_mtok, output_per_mtok = prices
            cost = (
                (input_tokens / 1_000_000) * input_per_mtok
                + (output_tokens / 1_000_000) * output_per_mtok
                + (cache_read_tokens / 1_000_000) * input_per_mtok * CACHE_READ_MULTIPLIER
                + (cache_creation_tokens / 1_000_000) * input_per_mtok * CACHE_WRITE_MULTIPLIER
            )

        existing = self._per_model.get(model_name, ModelUsage())
        self._per_model[model_name] = existing.model_copy(
            update={
                "input_tokens": existing.input_tokens + input_tokens,
                "output_tokens": existing.output_tokens + output_tokens,
                "cache_read_tokens": existing.cache_read_tokens + cache_read_tokens,
                "cache_creation_tokens": existing.cache_creation_tokens + cache_creation_tokens,
                "cost_usd": existing.cost_usd + cost,
            }
        )
        self._total_cost_usd += cost

        if self._total_cost_usd > self.max_cost_usd_per_run:
            self.budget_exhausted = True
            raise BudgetExceeded(self._total_cost_usd, self.max_cost_usd_per_run)
        return cost

    def absorb(self, usage: LLMUsage) -> None:
        """Fold in usage recorded elsewhere, e.g. by another Lambda's batch.

        Never raises: that spend has already happened. Marks the run as
        exhausted if the combined total is over ``max_cost_usd_per_run`` or
        the absorbed usage was itself exhausted.
        """
        for model_name, other in usage.per_model.items():
            existing = self._per_model.get(model_name, ModelUsage())
            self._per_model[model_name] = existing.model_copy(
                update={
                    "input_tokens": existing.input_tokens + other.input_tokens,
                    "output_tokens": existing.output_tokens + other.output_tokens,
                    "cache_read_tokens": existing.cache_read_tokens + other.cache_read_tokens,
                    "cache_creation_tokens": existing.cache_creation_tokens
                    + other.cache_creation_tokens,
                    "cost_usd": existing.cost_usd + other.cost_usd,
                }
            )
        self._total_cost_usd += usage.total_cost_usd
        if usage.budget_exhausted or self._total_cost_usd > self.max_cost_usd_per_run:
            self.budget_exhausted = True

    @property
    def total_cost_usd(self) -> float:
        return self._total_cost_usd

    def usage(self) -> LLMUsage:
        return LLMUsage(
            per_model=dict(self._per_model),
            total_cost_usd=self._total_cost_usd,
            budget_exhausted=self.budget_exhausted,
        )


__all__ = ["CACHE_READ_MULTIPLIER", "CACHE_WRITE_MULTIPLIER", "BudgetExceeded", "BudgetTracker"]
