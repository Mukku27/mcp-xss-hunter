"""MCP server: three tools over stdio, bounded structured results, no crashes.

The functions are synchronous. The MCP SDK runs sync tools on a worker thread,
which keeps the synchronous Playwright API off the protocol's event loop.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Literal

from mcp.server import MCPServer
from mcp.types import CallToolResult, TextContent
from pydantic import BaseModel

from . import __version__
from .ids import is_finding_id
from .logging_jsonl import JsonlLogger
from .models import (
    ErrorInfo,
    EvidenceResponse,
    ScanResponse,
    ScopeResponse,
    Totals,
)
from .scan import scan
from .scope import Scope, ScopeConfigError, config_path_from_env, load_scope_config

SCAN_DESCRIPTION = """\
Test one parameter on one authorized URL for XSS, with browser-verified execution.

Call this when you have a single URL and a single query parameter and want to know
whether a payload actually executes. It probes a unique marker, classifies where the
marker lands (HTML body, attribute, script, URL), sends a payload built for that
context, loads the real page in headless Chromium, and publishes a finding only if
the payload executes and then executes again in a fresh browser context.

Returns confirmed findings only, plus tested_held (tried and did not execute) and
could_not_proceed (blocked). Refuses hosts outside the allowlist before sending a
request and records the refusal in logs/scope.jsonl. Default budget: 30 seconds.
"""

EVIDENCE_DESCRIPTION = """\
Return the evidence bundle for a confirmed finding.

Call this after scan_xss returns a finding_id. Returns the payload, context,
execution signal, fresh-context replay result, artifact paths with sha256 hashes,
and a reproduce command. Returns INVALID_INPUT for an unknown or malformed id.
It never inlines screenshots or raw response bodies.
"""

SCOPE_DESCRIPTION = """\
Return the hosts this server is allowed to test.

Call this before scan_xss if you are unsure whether a target is in scope. Read-only
and idempotent. Matching is exact host:port; ports always participate. An empty
list means every target is refused.
"""


def _tool_result(model: BaseModel, summary: str) -> CallToolResult:
    """One-line text plus structured JSON; no duplicated full JSON in text."""
    return CallToolResult(
        content=[TextContent(type="text", text=summary)],
        structured_content=model.model_dump(mode="json"),
        is_error=False,
    )


def _summary_scan(result: ScanResponse) -> str:
    if result.status == "invalid":
        message = result.error.message if result.error else "invalid input"
        return f"scan_xss: invalid input ({message}) [run {result.run_id}]"
    if result.status == "refused":
        checkpoint = result.error.checkpoint if result.error else "?"
        return (
            f"scan_xss: refused OUT_OF_SCOPE at {checkpoint}; no request sent "
            f"[run {result.run_id}]"
        )
    totals = result.totals
    return (
        f"scan_xss: {totals.confirmed} confirmed, {totals.tested_held} held, "
        f"{totals.could_not_proceed} blocked [run {result.run_id}]"
    )


class Hunter:
    def __init__(
        self,
        *,
        scope: Scope,
        logger: JsonlLogger,
        evidence_dir: Path,
        config_error: str | None = None,
    ):
        self.scope = scope
        self.logger = logger
        self.evidence_dir = evidence_dir
        self.config_error = config_error

    def scan(self, url: str, parameter: str, context_override: str | None) -> ScanResponse:
        return scan(
            url=url,
            parameter=parameter,
            context_override=context_override,
            scope=self.scope,
            logger=self.logger,
            evidence_dir=self.evidence_dir,
        )

    def evidence(self, finding_id: str) -> EvidenceResponse:
        if not is_finding_id(finding_id):
            return EvidenceResponse(
                status="invalid",
                error=ErrorInfo(
                    code="INVALID_INPUT",
                    message="finding_id must match f-[0-9a-f]{12}",
                    needs="a finding_id returned by scan_xss",
                ),
            )
        # Implemented in M5 once the evidence tree exists.
        return EvidenceResponse(
            status="invalid",
            error=ErrorInfo(
                code="INVALID_INPUT",
                message="finding not found",
                needs="a finding_id returned by scan_xss in this repository",
            ),
        )


def build_server(
    *,
    scope: Scope,
    logger: JsonlLogger,
    evidence_dir: Path,
    config_error: str | None = None,
) -> MCPServer:
    hunter = Hunter(
        scope=scope,
        logger=logger,
        evidence_dir=evidence_dir,
        config_error=config_error,
    )
    server = MCPServer(
        name="xss-hunter",
        version=__version__,
        instructions=(
            "Context-aware XSS testing for one authorized URL and one parameter. "
            "Findings are published only after a headless browser executes the payload "
            "and it executes again in a fresh context. Scope is an exact host:port "
            "allowlist; out-of-scope targets are refused before any request is sent. "
            "Call list_scope first if unsure."
        ),
    )

    @server.tool(name="scan_xss", description=SCAN_DESCRIPTION)
    def scan_xss(
        url: str,
        parameter: str,
        context_override: Literal["html_body", "attribute", "script", "url"] | None = None,
    ) -> ScanResponse:
        try:
            result = hunter.scan(url, parameter, context_override)
        except Exception as exc:  # noqa: BLE001 - the server must not crash
            logger.log(
                event="error",
                run_id="unknown",
                tool="scan_xss",
                url=url if isinstance(url, str) else "",
                reason="internal_error",
                detail=type(exc).__name__,
            )
            result = ScanResponse(
                status="blocked",
                run_id="unknown",
                target={"url": "", "host": "", "scope": "unknown"},  # type: ignore[arg-type]
                parameter=parameter if isinstance(parameter, str) else "",
                limits={"duration_ms": 0, "http_requests": 0, "payloads_sent": 0, "browser_contexts": 0},  # type: ignore[arg-type]
                totals=Totals(confirmed=0, tested_held=0, could_not_proceed=1),
                error=ErrorInfo(
                    code="INTERNAL_ERROR",
                    message="the scan stopped unexpectedly; no finding was published",
                    needs="the server log for the failing stage",
                ),
            )
        return _tool_result(result, _summary_scan(result))  # type: ignore[return-value]

    @server.tool(name="get_evidence", description=EVIDENCE_DESCRIPTION)
    def get_evidence(finding_id: str) -> EvidenceResponse:
        try:
            result = hunter.evidence(finding_id)
        except Exception as exc:  # noqa: BLE001
            logger.log(
                event="error",
                run_id="unknown",
                tool="get_evidence",
                reason="internal_error",
                detail=type(exc).__name__,
            )
            result = EvidenceResponse(
                status="invalid",
                error=ErrorInfo(code="INTERNAL_ERROR", message="evidence lookup failed"),
            )
        summary = (
            f"get_evidence: {result.finding.finding_id} at {result.finding.evidence}"
            if result.finding
            else "get_evidence: not found"
        )
        return _tool_result(result, summary)  # type: ignore[return-value]

    @server.tool(name="list_scope", description=SCOPE_DESCRIPTION)
    def list_scope() -> ScopeResponse:
        result = ScopeResponse(
            hosts=list(scope.hosts),
            count=len(scope.hosts),
            note=(
                "exact normalized host:port; missing target ports normalize to 80/443; "
                "wildcards are not supported; empty means everything is refused"
            ),
            error=(
                ErrorInfo(code="SCOPE_CONFIG_INVALID", message=config_error)
                if config_error
                else None
            ),
        )
        summary = f"list_scope: {result.count} allowed host(s)"
        return _tool_result(result, summary)  # type: ignore[return-value]

    return server


def default_paths() -> tuple[Path, Path]:
    log_path = Path(os.environ.get("XSS_HUNTER_LOG_PATH", "logs/scope.jsonl")).expanduser()
    evidence_dir = Path(os.environ.get("XSS_HUNTER_EVIDENCE_DIR", "evidence")).expanduser()
    return log_path, evidence_dir


def main() -> None:
    # stdout belongs to the MCP protocol. Diagnostics go to stderr.
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
    log_path, evidence_dir = default_paths()
    logger = JsonlLogger(log_path)

    config_error: str | None = None
    try:
        scope = Scope(load_scope_config(config_path_from_env()))
    except ScopeConfigError as exc:
        # Fail closed: a broken allowlist must not become "everything allowed".
        config_error = str(exc)
        scope = Scope([])
        logger.log(
            event="error",
            run_id="startup",
            tool="server",
            reason="scope_config_invalid",
            detail=config_error,
        )

    server = build_server(
        scope=scope,
        logger=logger,
        evidence_dir=evidence_dir,
        config_error=config_error,
    )
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
