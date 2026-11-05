#!/usr/bin/env python3
"""Print a readable trace of `codex exec --json` from stdin.

This is a demo aid, not part of the MCP server. It prints the real tool calls,
their real result summaries, and the agent's final message. It never rewrites a
failure into a success.
"""

from __future__ import annotations

import json
import sys


def emit(line: str) -> None:
    print(line, flush=True)


def main() -> None:
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            continue

        kind = event.get("type")
        item = event.get("item") or {}

        if kind == "item.started" and item.get("type") == "mcp_tool_call":
            args = json.dumps(item.get("arguments") or {}, ensure_ascii=False)
            emit(f"-> {item.get('server')}.{item.get('tool')} {args}")

        elif kind == "item.completed" and item.get("type") == "mcp_tool_call":
            result = item.get("result") or {}
            content = result.get("content") or []
            text = content[0].get("text", "") if content else ""
            emit(f"<- {text}")

            structured = result.get("structured_content") or {}
            for finding in structured.get("confirmed") or []:
                replay = finding.get("replay") or {}
                emit(
                    "   finding {id} | {context}/{sub} | {payload} | signal={signal} "
                    "| replay={replay} | interaction={interaction}".format(
                        id=finding.get("finding_id"),
                        context=finding.get("context"),
                        sub=finding.get("sub_context"),
                        payload=finding.get("payload"),
                        signal=finding.get("signal"),
                        replay=replay.get("verified"),
                        interaction=finding.get("requires_interaction"),
                    )
                )
                emit(f"   evidence {finding.get('evidence')}")
            for held in structured.get("tested_held") or []:
                emit(
                    "   held {context}/{sub} | {reason} | {detail} | payloads={payloads}".format(
                        context=held.get("context"),
                        sub=held.get("sub_context"),
                        reason=held.get("reason"),
                        detail=held.get("detail"),
                        payloads=held.get("payloads"),
                    )
                )
            for blocked in structured.get("could_not_proceed") or []:
                emit(
                    "   blocked {stage} | {reason} | needs={needs}".format(
                        stage=blocked.get("stage"),
                        reason=blocked.get("reason"),
                        needs=blocked.get("needs"),
                    )
                )
            error = structured.get("error")
            if error:
                emit(
                    "   error {code} | checkpoint={checkpoint} | {message}".format(
                        code=error.get("code"),
                        checkpoint=error.get("checkpoint"),
                        message=error.get("message"),
                    )
                )

        elif kind == "item.completed" and item.get("type") == "agent_message":
            emit(f"\nagent: {item.get('text', '')}\n")

        elif kind == "turn.completed":
            emit("[turn completed]")


if __name__ == "__main__":
    main()
