"""Run the own-site trial rows and print one scorecard line per scan.

This is the Phase 1 evidence collector. It starts the bundled lab on an
ephemeral port, scans the realistic pages one at a time with the same
``scan`` entry point the MCP tool uses, and prints run id, tri-state, finding
ids and held reasons. Nothing here is a new code path.

    uv run python scripts/lab_trials.py
"""

from __future__ import annotations

import json
import tempfile
import threading
from pathlib import Path

from labapp.app import make_server
from xss_hunter.logging_jsonl import JsonlLogger
from xss_hunter.scan import scan
from xss_hunter.scope import Scope

ROWS = (
    ("/catalog?sort=price", "q", "confirmed"),
    ("/products?sku=VF-101", "sku", "confirmed"),
    ("/support", "topic", "confirmed"),
    ("/share", "next", "confirmed"),
    ("/reviews", "q", "held"),
    ("/search", "q", "held"),
    ("/suggest", "q", "held"),
)


def main() -> None:
    server = make_server(0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host = f"127.0.0.1:{server.server_port}"
    base = f"http://{host}"
    tmp = Path(tempfile.mkdtemp(prefix="lab-trials-"))
    logger = JsonlLogger(tmp / "scope.jsonl")
    rows = []
    try:
        for path, parameter, expected in ROWS:
            result = scan(
                url=base + path,
                parameter=parameter,
                context_override=None,
                scope=Scope([host]),
                logger=logger,
                evidence_dir=tmp / "evidence",
            )
            rows.append(
                {
                    "path": path,
                    "parameter": parameter,
                    "expected": expected,
                    "status": result.status,
                    "confirmed": result.totals.confirmed,
                    "held": result.totals.tested_held,
                    "could_not_proceed": result.totals.could_not_proceed,
                    "run_id": result.run_id,
                    "findings": [
                        {
                            "finding_id": item.finding_id,
                            "context": f"{item.context}/{item.sub_context}",
                            "payload": item.payload,
                            "requires_interaction": item.requires_interaction,
                        }
                        for item in result.confirmed
                    ],
                    "held_reasons": sorted({item.reason for item in result.tested_held}),
                }
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    print(json.dumps({"host": host, "rows": rows}, indent=2))


if __name__ == "__main__":
    main()
