"""One real MCP client: tools/list, a refusal, and typed input errors over stdio."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

REPO = Path(__file__).resolve().parents[1]


def run_client(tmp_path: Path) -> dict:
    scope_file = tmp_path / "scope.toml"
    scope_file.write_text('[scope]\nhosts = ["127.0.0.1:5117"]\n')
    env = {
        **os.environ,
        "XSS_HUNTER_SCOPE_CONFIG": str(scope_file),
        "XSS_HUNTER_LOG_PATH": str(tmp_path / "scope.jsonl"),
        "XSS_HUNTER_EVIDENCE_DIR": str(tmp_path / "evidence"),
    }
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "xss_hunter"],
        cwd=str(REPO),
        env=env,
    )

    async def main() -> dict:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                init = await session.initialize()
                tools = await session.list_tools()
                scope = await session.call_tool("list_scope", {})
                refused = await session.call_tool(
                    "scan_xss",
                    {"url": "http://127.0.0.1:59999/never", "parameter": "q"},
                )
                invalid = await session.call_tool(
                    "scan_xss",
                    {"url": "http://127.0.0.1:5117/body", "parameter": "q&x=1"},
                )
                evidence = await session.call_tool(
                    "get_evidence", {"finding_id": "not-a-finding-id"}
                )
                return {
                    "protocol": init.protocol_version,
                    "tools": [(tool.name, tool.input_schema) for tool in tools.tools],
                    "scope": scope.structured_content,
                    "refused": refused.structured_content,
                    "refused_is_error": refused.is_error,
                    "invalid": invalid.structured_content,
                    "evidence": evidence.structured_content,
                }

    return asyncio.run(main())


def test_stdio_client_can_list_and_call_every_tool(tmp_path):
    result = run_client(tmp_path)

    assert result["protocol"] == "2025-11-25"
    names = [name for name, _ in result["tools"]]
    assert names == ["scan_xss", "get_evidence", "list_scope"]
    scan_schema = dict(result["tools"])["scan_xss"]
    assert scan_schema["required"] == ["url", "parameter"]
    assert scan_schema["properties"]["url"]["maxLength"] == 2048
    assert scan_schema["properties"]["parameter"]["maxLength"] == 128
    assert scan_schema["properties"]["context_override"]["anyOf"][0]["enum"] == [
        "html_body",
        "attribute",
        "script",
        "url",
    ]

    assert result["scope"]["hosts"] == ["127.0.0.1:5117"]
    assert result["scope"]["count"] == 1
    assert result["scope"]["ports_matter"] is True
    assert result["scope"]["wildcards"] is False

    refused = result["refused"]
    assert result["refused_is_error"] is False
    assert refused["status"] == "refused"
    assert refused["error"]["code"] == "OUT_OF_SCOPE"
    assert refused["error"]["checkpoint"] == "S1"
    assert refused["limits"]["http_requests"] == 0
    assert refused["confirmed"] == []
    assert refused["totals"]["confirmed"] == 0

    assert result["invalid"]["status"] == "invalid"
    assert result["invalid"]["error"]["code"] == "INVALID_INPUT"

    assert result["evidence"]["status"] == "invalid"
    assert result["evidence"]["error"]["code"] == "INVALID_INPUT"

    log = [
        json.loads(line)
        for line in (tmp_path / "scope.jsonl").read_text().splitlines()
    ]
    refusal = next(line for line in log if line["event"] == "refuse")
    assert refusal["run_id"] == refused["run_id"]
    assert refusal["host"] == "127.0.0.1:59999"
    assert refusal["tool"] == "scan_xss"
    assert refusal["reason"] == "host_not_allowlisted"
    assert refusal["checkpoint"] == "S1"
    assert refusal["ts"]
