"""Input validation and the scan pipeline.

Stages run in the order the proof requires: scope -> probe -> classify ->
payload -> browser -> replay -> evidence -> result. Each stage can only
downgrade an outcome, never promote one.
"""

from __future__ import annotations

import re
from pathlib import Path

from .classify import classify, distinct_points
from .evidence import write_finding, write_observation, write_run, write_status
from .ids import finding_id, new_nonce, path_of
from .logging_jsonl import JsonlLogger, utc_now
from .models import (
    Blocked,
    ErrorInfo,
    Finding,
    Held,
    ReplayProof,
    ScanResponse,
    Target,
    Totals,
)
from .payloads import PayloadAttempt, select, select_override
from .probe import probe, with_parameter
from .result import bound_scan
from .runctx import BUDGET_NEEDS, RunContext
from .scope import Scope
from .verify import BrowserSession, Verification

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
    """Stamp measured limits/refusals, record the full run, return a bounded copy."""
    prepared = response.model_copy(
        update={"limits": run.limits(), "scope_refusals": run.refusals}
    )
    bounded = bound_scan(prepared)
    try:
        # Evidence keeps every held/blocked entry even when the agent-facing
        # response is capped; run.json still records the real totals.
        write_run(
            run,
            prepared.model_copy(
                update={"totals": bounded.totals, "truncated": bounded.truncated}
            ),
        )
        write_status(run, prepared)
    except Exception as exc:  # noqa: BLE001 - evidence I/O must not crash a scan
        run.logger.log(
            event="error",
            run_id=run.run_id,
            tool=run.tool,
            reason="evidence_write_failed",
            detail=type(exc).__name__,
        )
    return bounded


def _blocked(
    run: RunContext,
    base: ScanResponse,
    *,
    code: str,
    stage: str,
    reason: str,
    needs: str,
    checkpoint: str | None = None,
    held: list[Held] | None = None,
    confirmed: list[Finding] | None = None,
) -> ScanResponse:
    held = held or []
    confirmed = confirmed or []
    return _finish(
        run,
        base.model_copy(
            update={
                "status": "blocked",
                "confirmed": confirmed,
                "tested_held": held,
                "could_not_proceed": [Blocked(stage=stage, reason=reason, needs=needs)],
                "totals": Totals(
                    confirmed=len(confirmed),
                    tested_held=len(held),
                    could_not_proceed=1,
                ),
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

    # R2: name the syntax around every occurrence, then choose one reviewed
    # payload per distinct context. Classification is a hypothesis; nothing is
    # published until the browser executes it (R3) and replay executes it again
    # (R4).
    points = classify(outcome.body, marker)
    unique = distinct_points(points)

    if context_override is not None:
        # A reviewer-forced context is an explicit hypothesis, not a
        # classification. It still has to pass the same browser proof gate.
        candidates = [(points[0], select_override(context_override, new_nonce()))]
    else:
        candidates = [(point, select(point, new_nonce())) for point in unique]

    unsupported = [
        Held(
            context=point.context,
            sub_context=point.sub_context,
            reason="context_not_supported",
            detail=f"{point.context}/{point.sub_context} has no reviewed payload",
            payloads_tried=0,
        )
        for point, attempt in candidates
        if attempt is None
    ]
    supported = [(point, attempt) for point, attempt in candidates if attempt is not None]
    if not supported:
        # Every occurrence sits in a context with no reviewed payload (for
        # example a comment). Say so; do not promote an untried payload.
        return _finish(
            run,
            base.model_copy(
                update={
                    "tested_held": unsupported,
                    "totals": Totals(
                        confirmed=0, tested_held=len(unsupported), could_not_proceed=0
                    ),
                }
            ),
        )

    # R3: observe the payload in a real browser. A baseline navigation with a
    # benign value runs first, so a signal that appears without the payload is
    # caught before any candidate is trusted.
    if run.expired():
        return _blocked(
            run,
            base,
            code="TIMEOUT",
            stage="browser",
            reason="run_budget_exhausted",
            needs=BUDGET_NEEDS,
            held=unsupported,
        )
    with BrowserSession(run) as browser:
        if not browser.ok:
            failure = browser.failure
            assert failure is not None
            return _blocked(
                run,
                base,
                code=failure.code,
                stage="browser",
                reason=failure.reason,
                needs=failure.needs,
                checkpoint=failure.checkpoint,
                held=unsupported,
            )

        baseline = browser.baseline(
            outcome.url,
            parameter,
            value=outcome.marker,
            nonces={attempt.nonce for _, attempt in supported},
        )
        if not baseline.ok:
            failure = baseline.failure
            assert failure is not None
            return _blocked(
                run,
                base,
                code=failure.code,
                stage="baseline",
                reason=failure.reason,
                needs=failure.needs,
                checkpoint=failure.checkpoint,
                held=unsupported,
            )
        if baseline.executed:
            return _blocked(
                run,
                base,
                code="BROWSER_ERROR",
                stage="baseline",
                reason="nonce_signal_without_payload",
                needs="a benchmark page that does not already contain the nonce",
                held=unsupported,
            )

        held = list(unsupported)
        observed: list[tuple[PayloadAttempt, Verification, str]] = []
        browser_failure = None

        for point, attempt in supported:
            if run.expired():
                return _blocked(
                    run,
                    base,
                    code="TIMEOUT",
                    stage="verify",
                    reason="run_budget_exhausted",
                    needs=BUDGET_NEEDS,
                    held=held,
                )
            fid = finding_id(
                decision.host,
                path_of(outcome.url),
                parameter,
                attempt.context,
                attempt.family,
            )
            verification = browser.attempt(
                outcome.url,
                parameter,
                attempt.payload,
                attempt.nonce,
                attempt.requires_interaction,
            )

            observation_error = ""
            try:
                write_observation(
                    run, decision.host, fid, outcome.url, attempt, verification
                )
            except Exception as exc:  # noqa: BLE001 - evidence I/O is reported, not fatal
                observation_error = type(exc).__name__
                run.logger.log(
                    event="error",
                    run_id=run.run_id,
                    tool=run.tool,
                    url=outcome.url,
                    reason="observation_write_failed",
                    detail=observation_error,
                )

            if not verification.ok:
                browser_failure = verification.failure
                break
            if verification.executed:
                observed.append((attempt, verification, observation_error))
            else:
                held.append(
                    Held(
                        context=attempt.context,
                        sub_context=attempt.sub_context,
                        reason="payload_did_not_execute",
                        detail=verification.signal_detail,
                        payloads=[attempt.payload],
                        payloads_tried=1,
                    )
                )

        if browser_failure is not None:
            return _blocked(
                run,
                base,
                code=browser_failure.code,
                stage="verify",
                reason=browser_failure.reason,
                needs=browser_failure.needs,
                checkpoint=browser_failure.checkpoint,
                held=held,
            )

        if not observed:
            return _finish(
                run,
                base.model_copy(
                    update={
                        "tested_held": held,
                        "totals": Totals(
                            confirmed=0, tested_held=len(held), could_not_proceed=0
                        ),
                    }
                ),
            )

        # R4: a second signal in a fresh context is the difference between a
        # candidate and a finding. One signal downgrades; it never publishes.
        findings: list[Finding] = []
        could_not_proceed: list[Blocked] = []

        for attempt, verification, observation_error in observed:
            if run.expired():
                could_not_proceed.append(
                    Blocked(
                        stage="replay",
                        reason="run_budget_exhausted",
                        needs=BUDGET_NEEDS,
                    )
                )
                continue
            if not verification.screenshot:
                could_not_proceed.append(
                    Blocked(
                        stage="evidence",
                        reason="observation_screenshot_missing",
                        needs="a browser screenshot of the first signal",
                    )
                )
                continue

            replay = browser.replay(
                outcome.url,
                parameter,
                attempt.payload,
                attempt.nonce,
                attempt.requires_interaction,
            )
            if not replay.ok:
                failure = replay.failure
                assert failure is not None
                if failure.code == "OUT_OF_SCOPE":
                    return _blocked(
                        run,
                        base,
                        code=failure.code,
                        stage="replay",
                        reason=failure.reason,
                        needs=failure.needs,
                        checkpoint=failure.checkpoint,
                        held=held,
                        confirmed=findings,
                    )
                could_not_proceed.append(
                    Blocked(
                        stage="replay",
                        reason=failure.reason,
                        needs=failure.needs,
                    )
                )
                continue

            if not replay.executed:
                could_not_proceed.append(
                    Blocked(
                        stage="replay",
                        reason="non_deterministic",
                        needs="a payload that executes on both independent loads",
                    )
                )
                continue

            fid = finding_id(
                decision.host,
                path_of(base.target.url),
                parameter,
                attempt.context,
                attempt.family,
            )
            finding = Finding(
                finding_id=fid,
                url=base.target.url,
                injection_url=with_parameter(outcome.url, parameter, attempt.payload),
                parameter=parameter,
                context=attempt.context,
                sub_context=attempt.sub_context,
                payload=attempt.payload,
                nonce=attempt.nonce,
                signal=verification.signal,
                signal_detail=verification.signal_detail,
                requires_interaction=attempt.requires_interaction,
                replay=ReplayProof(
                    verified=True,
                    session="fresh",
                    nonce=attempt.nonce,
                    signal=replay.signal,
                ),
                evidence="",
                reproduce=(
                    f'scan_xss(url="{base.target.url}", parameter="{parameter}")'
                ),
                browser=verification.browser or replay.browser,
                timestamp=utc_now(),
            )

            try:
                stored = write_finding(
                    run,
                    decision.host,
                    finding,
                    verification.screenshot,
                    replay.screenshot,
                )
            except Exception as exc:  # noqa: BLE001 - no bundle means no finding
                run.logger.log(
                    event="error",
                    run_id=run.run_id,
                    tool=run.tool,
                    url=outcome.url,
                    reason="finding_write_failed",
                    detail=(
                        f"{type(exc).__name__}; observation {observation_error or 'ok'}"
                    ),
                )
                could_not_proceed.append(
                    Blocked(
                        stage="evidence",
                        reason="finding_write_failed",
                        needs="a writable evidence directory",
                    )
                )
                continue

            published = finding.model_copy(update={"evidence": stored.evidence})
            findings.append(published)
            run.logger.log(
                event="finding",
                run_id=run.run_id,
                tool=run.tool,
                url=outcome.url,
                host=decision.host,
                reason="confirmed",
                detail=f"{attempt.context}/{attempt.sub_context}",
            )

        return _finish(
            run,
            base.model_copy(
                update={
                    "confirmed": findings,
                    "tested_held": held,
                    "could_not_proceed": could_not_proceed,
                    "totals": Totals(
                        confirmed=len(findings),
                        tested_held=len(held),
                        could_not_proceed=len(could_not_proceed),
                    ),
                }
            ),
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
