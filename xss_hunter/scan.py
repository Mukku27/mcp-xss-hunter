"""Input validation and the scan pipeline.

M1 scope: validation + the scope refusal path. The probe/classify/verify stages
are added in M2-M5. Keeping the pipeline synchronous lets the MCP SDK run it on
a worker thread and lets the tests call it directly.
"""

from __future__ import annotations

import re
from pathlib import Path

from .logging_jsonl import JsonlLogger
from .models import (
    Blocked,
    ErrorInfo,
    ScanResponse,
    Target,
    Totals,
)
from .result import bound_scan
from .runctx import RunContext
from .scope import Scope

PARAMETER_RE = re.compile(r"^[A-Za-z0-9_.\[\]-]{1,128}$")
CONTEXT_OVERRIDES = frozenset({"html_body", "attribute", "script", "url"})


def _base_response(run: RunContext, url: str, host: str, scope: str) -> ScanResponse:
    return ScanResponse(
        status="completed",
        run_id=run.run_id,
        target=Target(url=url, host=host, scope=scope),
        parameter=run.parameter,
        limits=run.limits(),
        totals=Totals(confirmed=0, tested_held=0, could_not_proceed=0),
    )


def scan(
    *,
    url: str,
    parameter: str,
    context_override: str | None,
    scope: Scope,
    logger: JsonlLogger,
    evidence_dir: Path,
) -> ScanResponse:
    """Run one scan. This function never raises for expected failures."""
    parameter = parameter if isinstance(parameter, str) else ""
    run = RunContext(
        tool="scan_xss",
        parameter=parameter,
        scope=scope,
        logger=logger,
        evidence_dir=evidence_dir,
    )

    # Validate BEFORE any network access. A bad parameter is a client mistake,
    # not a target finding, and it still gets a run id in the log.
    if not isinstance(url, str) or not url.strip():
        logger.log(event="error", run_id=run.run_id, tool="scan_xss", reason="invalid_url")
        return _invalid(run, url if isinstance(url, str) else "", "missing_url", "url is required")
    if not PARAMETER_RE.fullmatch(parameter):
        logger.log(
            event="error",
            run_id=run.run_id,
            tool="scan_xss",
            url=url,
            reason="invalid_parameter",
        )
        return _invalid(
            run,
            url,
            "parameter",
            "parameter must match ^[A-Za-z0-9_.\\[\\]-]{1,128}$",
        )
    if context_override is not None and context_override not in CONTEXT_OVERRIDES:
        logger.log(
            event="error",
            run_id=run.run_id,
            tool="scan_xss",
            url=url,
            reason="invalid_context_override",
        )
        return _invalid(
            run,
            url,
            "context_override",
            "context_override must be one of html_body, attribute, script, url",
        )

    logger.log(event="scan_start", run_id=run.run_id, tool="scan_xss", url=url)

    # S0/S1: normalize and decide before the first request exists.
    decision = run.check(url, "S1")
    if decision.refused:
        response = _base_response(run, decision.url, decision.host, "refused")
        return bound_scan(
            response.model_copy(
                update={
                    "status": "refused",
                    "scope_refusals": run.refusals,
                    "error": ErrorInfo(
                        code="OUT_OF_SCOPE",
                        message=f"refused at {decision.checkpoint}: {decision.reason}",
                        checkpoint=decision.checkpoint,
                    ),
                }
            )
        )

    # M1 stops here. The next milestone replaces this with probe -> classify ->
    # verify. It is reported as blocked, never as "no XSS".
    response = _base_response(run, decision.url, decision.host, "allowed")
    return bound_scan(
        response.model_copy(
            update={
                "could_not_proceed": [
                    Blocked(
                        stage="probe",
                        reason="not_implemented",
                        needs="the M2 probe stage",
                    )
                ],
                "totals": Totals(confirmed=0, tested_held=0, could_not_proceed=1),
            }
        )
    )


def _invalid(run: RunContext, url: str, field: str, message: str) -> ScanResponse:
    response = _base_response(run, url[:300], "", "unknown")
    return bound_scan(
        response.model_copy(
            update={
                "status": "invalid",
                "error": ErrorInfo(
                    code="INVALID_INPUT",
                    message=f"{field}: {message}",
                    needs="a corrected tool argument",
                ),
                "totals": Totals(confirmed=0, tested_held=0, could_not_proceed=0),
            }
        )
    )
