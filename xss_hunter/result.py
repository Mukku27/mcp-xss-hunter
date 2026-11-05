"""Keep the agent-facing response inside a fixed budget.

Evidence keeps the detail; the tool response stays small enough for an agent
to read in one turn. Lists are capped first, then optional text is shortened,
then entries are dropped from the least important list until the serialized
response fits ``MAX_BYTES``. ``totals`` always reports the real counts and
``truncated`` says that the arrays are not the whole run.
"""

from __future__ import annotations

import json

from .models import ScanResponse

MAX_BYTES = 4096
MAX_CONFIRMED = 3
MAX_HELD = 4
MAX_BLOCKED = 2
MAX_REFUSALS = 2
MAX_DETAIL = 160
MAX_SIGNAL_DETAIL = 160
MAX_PAYLOAD = 300
MAX_HELD_PAYLOADS = 3
MAX_REPRODUCE = 240
MAX_EVIDENCE = 240
MAX_URL = 600
MAX_REFUSAL_URL = 300


def _trim(text: str, limit: int) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


def serialized_bytes(response: ScanResponse) -> int:
    return len(json.dumps(response.model_dump(mode="json"), ensure_ascii=False).encode("utf-8"))


def _fits(response: ScanResponse) -> bool:
    return serialized_bytes(response) <= MAX_BYTES


def bound_scan(response: ScanResponse) -> ScanResponse:
    totals = response.totals.model_copy(
        update={
            "confirmed": len(response.confirmed),
            "tested_held": len(response.tested_held),
            "could_not_proceed": len(response.could_not_proceed),
        }
    )
    truncated = (
        len(response.confirmed) > MAX_CONFIRMED
        or len(response.tested_held) > MAX_HELD
        or len(response.could_not_proceed) > MAX_BLOCKED
        or len(response.scope_refusals) > MAX_REFUSALS
    )
    error = response.error
    if error is not None:
        error = error.model_copy(
            update={
                "message": _trim(error.message, MAX_DETAIL),
                "needs": _trim(error.needs, MAX_DETAIL) if error.needs else None,
            }
        )
    candidate = response.model_copy(
        update={
            "target": response.target.model_copy(
                update={"url": _trim(response.target.url, MAX_URL)}
            ),
            "confirmed": [
                finding.model_copy(
                    update={
                        "url": _trim(finding.url, MAX_URL),
                        "signal_detail": _trim(finding.signal_detail, MAX_SIGNAL_DETAIL),
                        "evidence": _trim(finding.evidence, MAX_EVIDENCE),
                        "reproduce": _trim(finding.reproduce, MAX_REPRODUCE),
                    }
                )
                for finding in response.confirmed[:MAX_CONFIRMED]
            ],
            "tested_held": [
                entry.model_copy(
                    update={
                        "detail": _trim(entry.detail, MAX_DETAIL),
                        "payloads": [
                            _trim(payload, MAX_PAYLOAD)
                            for payload in entry.payloads[:MAX_HELD_PAYLOADS]
                        ],
                    }
                )
                for entry in response.tested_held[:MAX_HELD]
            ],
            "could_not_proceed": response.could_not_proceed[:MAX_BLOCKED],
            "scope_refusals": [
                refusal.model_copy(
                    update={"url": _trim(refusal.url, MAX_REFUSAL_URL)}
                )
                for refusal in response.scope_refusals[:MAX_REFUSALS]
            ],
            "totals": totals,
            "error": error,
            "truncated": truncated,
        }
    )

    # A long URL or a very large payload can still exceed the budget after the
    # caps. Drop whole entries rather than emitting invalid JSON or raw HTML.
    # Findings are the last thing to go: an agent should see the proof first.
    while not _fits(candidate):
        for field in ("scope_refusals", "could_not_proceed", "tested_held", "confirmed"):
            entries = getattr(candidate, field)
            if entries:
                candidate = candidate.model_copy(update={field: entries[:-1]})
                truncated = True
                break
        else:
            # Nothing left to drop; the scalar fields already have hard caps.
            break

    return candidate.model_copy(update={"truncated": truncated})
