"""Scan one third-party lab row against an already running local instance.

Used for the Juice Shop and DVWA phases of ``docs/lab-trials.md``. It takes the
allowlist from the shipped config, so an unlisted host is refused exactly as it
would be through MCP. It never adds a host and never logs in.

    uv run python scripts/external_trial.py http://127.0.0.1:3000/ q
    uv run python scripts/external_trial.py http://127.0.0.1:3000/rest/products/search q

Output is one JSON object: tri-state, run id, finding or held reasons.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from xss_hunter.logging_jsonl import JsonlLogger
from xss_hunter.scan import scan
from xss_hunter.scope import Scope, config_path_from_env, load_scope_config


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    url, parameter = argv[1], argv[2]
    scope = Scope(load_scope_config(config_path_from_env()))
    tmp = Path(tempfile.mkdtemp(prefix="external-trial-"))
    result = scan(
        url=url,
        parameter=parameter,
        context_override=None,
        scope=scope,
        logger=JsonlLogger(tmp / "scope.jsonl"),
        evidence_dir=tmp / "evidence",
    )
    print(
        json.dumps(
            {
                "url": url,
                "parameter": parameter,
                "status": result.status,
                "run_id": result.run_id,
                "confirmed": result.totals.confirmed,
                "held": result.totals.tested_held,
                "could_not_proceed": result.totals.could_not_proceed,
                "error": result.error.model_dump() if result.error else None,
                "findings": [
                    {
                        "finding_id": item.finding_id,
                        "context": f"{item.context}/{item.sub_context}",
                        "payload": item.payload,
                        "requires_interaction": item.requires_interaction,
                    }
                    for item in result.confirmed
                ],
                "held_details": [
                    {
                        "context": item.context,
                        "reason": item.reason,
                        "detail": item.detail,
                    }
                    for item in result.tested_held
                ],
                "blocked": [
                    {"stage": item.stage, "reason": item.reason, "needs": item.needs}
                    for item in result.could_not_proceed
                ],
                "limits": result.limits.model_dump(),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
