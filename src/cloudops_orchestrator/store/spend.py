"""Month-to-date LLM spend (``SPEND#<yyyy-mm>`` / ``LLM``).

``InitRun`` (``steps/init_run.py``) reads this before collecting to
enforce ``llm.max_cost_usd_per_month``; ``aggregate`` adds the run's actual
spend once the run finishes.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

from cloudops_orchestrator.store.serialization import from_dynamo_value


def spend_key(year_month: str) -> dict[str, str]:
    return {"pk": f"SPEND#{year_month}", "sk": "LLM"}


def get_month_to_date_spend(table: Any, year_month: str) -> float:
    response = table.get_item(Key=spend_key(year_month))
    item = response.get("Item")
    if item is None:
        return 0.0
    return float(from_dynamo_value(item.get("total_cost_usd", Decimal(0))))


def add_spend(table: Any, year_month: str, amount_usd: float) -> float:
    """Atomically add ``amount_usd`` to the month's running total; returns the new total."""
    response = table.update_item(
        Key=spend_key(year_month),
        UpdateExpression="SET total_cost_usd = if_not_exists(total_cost_usd, :zero) + :amt",
        ExpressionAttributeValues={":amt": Decimal(str(amount_usd)), ":zero": Decimal(0)},
        ReturnValues="UPDATED_NEW",
    )
    return float(response["Attributes"]["total_cost_usd"])


__all__ = ["add_spend", "get_month_to_date_spend", "spend_key"]
