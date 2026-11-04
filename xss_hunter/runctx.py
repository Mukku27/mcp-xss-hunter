"""Per-run state: counters, refusal capture, and the one scope guard.

The allowlist is resolved once by the server and handed to each run. Nothing a
target returns can mutate it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

from .ids import new_run_id
from .logging_jsonl import JsonlLogger, ScopeGuard, utc_now
from .models import Limits, ScopeRefusal
from .scope import Scope, ScopeDecision


@dataclass
class RunContext:
    tool: str
    parameter: str
    scope: Scope
    logger: JsonlLogger
    evidence_dir: Path
    run_id: str = field(default_factory=new_run_id)
    started: float = field(default_factory=time.monotonic)
    http_requests: int = 0
    payloads_sent: int = 0
    browser_contexts: int = 0
    refusals: list[ScopeRefusal] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._guard = ScopeGuard(self.scope, self.logger, self.run_id, self.tool)

    def check(self, url: str, checkpoint: str, *, log_allow: bool = True) -> ScopeDecision:
        decision = self._guard.check(url, checkpoint, log_allow=log_allow)
        if decision.refused:
            self.refusals.append(
                ScopeRefusal(
                    ts=utc_now(),
                    host=decision.host,
                    url=decision.url,
                    reason=decision.reason,
                    checkpoint=decision.checkpoint,
                )
            )
        return decision

    def limits(self) -> Limits:
        return Limits(
            duration_ms=int((time.monotonic() - self.started) * 1000),
            http_requests=self.http_requests,
            payloads_sent=self.payloads_sent,
            browser_contexts=self.browser_contexts,
        )
