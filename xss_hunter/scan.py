"""Input validation and the scan pipeline.

Stages run in the order the proof requires: scope -> probe -> classify ->
payload -> browser -> replay -> evidence -> result. Each stage can only
downgrade an outcome, never promote one.
"""

from __future__ import annotations

import re
from pathlib import Path

from .ids import new_nonce
from .logging_jsonl import JsonlLogger
from .models import (
    Blocked,
    ErrorInfo,
    Held,
    ScanResponse,
    Target,
    Totals,
)
from .probe import probe
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


def _finish(run: RunContext, response: ScanResponse) -> ScanResponse:
    """Stamp measured limits/refusals at the end, then bound the arrays."""
    return bound_scan(
        response.model_copy(
            update={"limits": run.limits(), "scope_refusals": run.refusals}
        )
    )


def _blocked(
    run: RunContext,
    base: ScanResponse,
    *,
    code: str,
    stage: str,
    reason: str,
    needs: str,
    checkpoint: str | None = None,
) -> ScanResponse:
    return _finish(
        run,
        base.model_copy(
            update={
                "status": "blocked",
                "could_not_proceed": [Blocked(stage=stage, reason=reason, needs=needs)],
                "totals": Totals(confirmed=0, tested_held=0, could_not_proceed=1),
                "error": ErrorInfo(
                    code=code,
                    message=f"{stage}: {reason}",
                    needs=needs,
                    checkpoint=checkpoint,
                ),
            }
        ),
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
        return _finish(
            run,
            response.model_copy(
                update={
                    "status": "refused",
                    "error": ErrorInfo(
                        code="OUT_OF_SCOPE",
                        message=f"refused at {decision.checkpoint}: {decision.reason}",
                        checkpoint=decision.checkpoint,
                    ),
                }
            ),
        )

    base = _base_response(run, decision.url, decision.host, "allowed")

    marker = new_nonce()
    outcome = probe(decision.url, parameter, marker, run)
    if not outcome.ok:
        failure = outcome.failure
        assert failure is not None
        return _blocked(
            run,
            base,
            code=failure.code,
            stage="probe",
            reason=failure.reason,
            needs=failure.needs,
            checkpoint=failure.decision.checkpoint if failure.decision else None,
        )

    if not outcome.reflected:
        # R1 failed. This is a held result, never "no XSS".
        return _finish(
            run,
            base.model_copy(
                update={
                    "tested_held": [
                        Held(
                            context="unknown",
                            reason="param_not_reflected",
                            detail=(
                                f"marker absent from a {outcome.status_code} response "
                                f"({outcome.body_bytes} bytes, {len(outcome.redirects)} redirects)"
                            ),
                            payloads_tried=0,
                        )
                    ],
                    "totals": Totals(confirmed=0, tested_held=1, could_not_proceed=0),
                }
            ),
        )

    # M2 stops after locating the marker. M3 replaces this with classification.
    return _blocked(
        run,
        base,
        code="INTERNAL_ERROR",
        stage="classify",
        reason="not_implemented",
        needs="the M3 classifier",
    )


def _invalid(run: RunContext, url: str, field: str, message: str) -> ScanResponse:
    response = _base_response(run, url[:300], "", "unknown")
    return _finish(
        run,
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
        ),
    )
