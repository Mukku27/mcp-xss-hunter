"""Keep the agent-facing response inside a fixed budget.

Evidence keeps the detail; the tool response stays small enough for an agent
to read in one turn. When a list is capped, ``totals`` still reports the real
count and ``truncated`` is true.
"""

from __future__ import annotations

import json

from .models import ScanResponse

MAX_CONFIRMED = 5
MAX_HELD = 8
MAX_BLOCKED = 3
MAX_REFUSALS = 5
MAX_DETAIL = 160


def _trim(text: str, limit: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


def bound_scan(response: ScanResponse) -> ScanResponse:
    totals = response.totals.model_copy(
        update={
            "confirmed": len(response.confirmed),
            "tested_held": len(response.tested_held),
            "could_not_proceed": len(response.could_not_proceed),
        }
    )
    held = [
        entry.model_copy(update={"detail": _trim(entry.detail, MAX_DETAIL)})
        for entry in response.tested_held[:MAX_HELD]
    ]
    truncated = (
        len(response.confirmed) > MAX_CONFIRMED
        or len(response.tested_held) > MAX_HELD
        or len(response.could_not_proceed) > MAX_BLOCKED
        or len(response.scope_refusals) > MAX_REFUSALS
    )
    return response.model_copy(
        update={
            "confirmed": response.confirmed[:MAX_CONFIRMED],
            "tested_held": held,
            "could_not_proceed": response.could_not_proceed[:MAX_BLOCKED],
            "scope_refusals": response.scope_refusals[:MAX_REFUSALS],
            "totals": totals,
            "truncated": truncated,
        }
    )


def serialized_bytes(response: ScanResponse) -> int:
    return len(json.dumps(response.model_dump(mode="json"), ensure_ascii=False).encode("utf-8"))
