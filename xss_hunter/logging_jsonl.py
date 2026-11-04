"""Append-only JSONL log for scope decisions and run events.

The log is the auditable half of the scope boundary: a refusal that is not
recorded is not enforced. It never receives cookies, auth headers, or bodies.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from .scope import ScopeDecision

_MAX_URL = 300
_MAX_DETAIL = 500
def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class JsonlLogger:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(
        self,
        *,
        event: str,
        run_id: str,
        tool: str,
        url: str = "",
        host: str = "",
        reason: str = "",
        checkpoint: str = "",
        detail: str = "",
    ) -> None:
        if event not in {"allow", "refuse", "scan_start", "finding", "error"}:
            event = "error"
        record = {
            "ts": utc_now(),
            "event": event,
            "run_id": run_id,
            "tool": tool,
            "url": str(url)[:_MAX_URL],
            "host": str(host)[:200],
            "reason": str(reason)[:200],
            "checkpoint": str(checkpoint)[:16],
            "detail": str(detail)[:_MAX_DETAIL],
        }
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
        # O_APPEND makes each small line an atomic append on POSIX, so
        # concurrent tool calls cannot interleave a record.
        fd = os.open(self.path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)

    def decision(self, decision: ScopeDecision, *, run_id: str, tool: str) -> None:
        self.log(
            event="allow" if decision.allowed else "refuse",
            run_id=run_id,
            tool=tool,
            url=decision.url,
            host=decision.host,
            reason=decision.reason,
            checkpoint=decision.checkpoint,
            detail=decision.detail,
        )


class ScopeGuard:
    """Every scope check goes through here so every decision is logged."""

    def __init__(self, scope, logger: JsonlLogger, run_id: str, tool: str):
        self.scope = scope
        self.logger = logger
        self.run_id = run_id
        self.tool = tool

    def check(self, url: str, checkpoint: str, *, log_allow: bool = True) -> ScopeDecision:
        decision = self.scope.check(url, checkpoint)
        if decision.refused or log_allow:
            self.logger.decision(decision, run_id=self.run_id, tool=self.tool)
        return decision
