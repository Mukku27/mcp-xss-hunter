"""Reflection probe with manual redirect handling.

The HTTP client never follows a redirect itself. Each hop is normalized and
scope-checked before the next request exists (S1 for the first hop, S2 for
every Location). A client that follows redirects would bypass the allowlist;
this one cannot.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import httpx

from .runctx import RunContext
from .scope import ScopeDecision

MAX_REDIRECTS = 5
MAX_BODY_BYTES = 2_000_000
TIMEOUT_SECONDS = 10.0
USER_AGENT = "xss-hunter/0.1 (authorized local lab)"


@dataclass(frozen=True)
class RedirectHop:
    from_url: str
    to_url: str
    status: int


@dataclass
class ProbeFailure:
    code: str
    reason: str
    needs: str
    detail: str = ""
    decision: ScopeDecision | None = None


@dataclass
class ProbeOutcome:
    url: str = ""
    host: str = ""
    status_code: int = 0
    body: str = ""
    body_bytes: int = 0
    content_type: str = ""
    response_sha256: str = ""
    marker: str = ""
    occurrences: list[int] = field(default_factory=list)
    redirects: list[RedirectHop] = field(default_factory=list)
    failure: ProbeFailure | None = None

    @property
    def ok(self) -> bool:
        return self.failure is None

    @property
    def reflected(self) -> bool:
        return bool(self.occurrences)


def with_parameter(url: str, parameter: str, value: str) -> str:
    """Replace (or add) one query parameter, keeping the other parameters."""
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    updated: list[tuple[str, str]] = []
    for key, old_value in pairs:
        if key == parameter:
            updated.append((key, value))
            replaced = True
        else:
            updated.append((key, old_value))
    if not replaced:
        updated.append((parameter, value))
    query = urlencode(updated, doseq=True)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", query, parsed.fragment))


def _get_once(url: str) -> httpx.Response:
    # A new client per hop: no cookie jar carries across hosts or hops, and no
    # auth profile exists to leak.
    with httpx.Client(
        follow_redirects=False,
        timeout=TIMEOUT_SECONDS,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
        },
    ) as client:
        return client.get(url)


def probe(url: str, parameter: str, marker: str, run: RunContext) -> ProbeOutcome:
    """Send the marker once and locate every occurrence in the response body."""
    # The parameter is set here, not by the caller, so every scan sends a
    # unique marker in the requested parameter and never sprays other inputs.
    current = with_parameter(url, parameter, marker)
    redirects: list[RedirectHop] = []

    for hop in range(MAX_REDIRECTS + 1):
        checkpoint = "S1" if hop == 0 else "S2"
        decision = run.check(current, checkpoint)
        if decision.refused:
            return ProbeOutcome(
                url=decision.url,
                host=decision.host,
                marker=marker,
                redirects=redirects,
                failure=ProbeFailure(
                    code="OUT_OF_SCOPE",
                    reason=f"redirect_refused_{decision.reason}",
                    needs="an allowlisted redirect target",
                    detail=decision.detail,
                    decision=decision,
                ),
            )
        current = decision.url

        try:
            response = _get_once(current)
        except httpx.TimeoutException:
            return ProbeOutcome(
                url=current,
                marker=marker,
                redirects=redirects,
                failure=ProbeFailure(
                    code="TIMEOUT",
                    reason="probe_timeout",
                    needs="a faster target or a higher timeout",
                    detail=f"no response within {TIMEOUT_SECONDS:g}s",
                ),
            )
        except httpx.HTTPError as exc:
            return ProbeOutcome(
                url=current,
                marker=marker,
                redirects=redirects,
                failure=ProbeFailure(
                    code="TARGET_UNREACHABLE",
                    reason="connection_failed",
                    needs="a reachable in-scope target",
                    detail=type(exc).__name__,
                ),
            )

        run.http_requests += 1

        if response.is_redirect:
            location = response.headers.get("location")
            if not location:
                run.logger.log(
                    event="error",
                    run_id=run.run_id,
                    tool=run.tool,
                    url=current,
                    reason="redirect_without_location",
                )
                return ProbeOutcome(
                    url=current,
                    marker=marker,
                    redirects=redirects,
                    failure=ProbeFailure(
                        code="REDIRECT_ERROR",
                        reason="redirect_without_location",
                        needs="an allowlisted redirect target or a direct URL",
                    ),
                )
            next_url = urljoin(current, location)
            redirects.append(RedirectHop(from_url=current, to_url=next_url, status=response.status_code))
            current = next_url
            continue

        body_bytes = response.content
        if len(body_bytes) > MAX_BODY_BYTES:
            return ProbeOutcome(
                url=current,
                marker=marker,
                redirects=redirects,
                status_code=response.status_code,
                failure=ProbeFailure(
                    code="TARGET_UNREACHABLE",
                    reason="response_too_large",
                    needs="a smaller response body",
                    detail=f"{len(body_bytes)} bytes exceeds {MAX_BODY_BYTES}",
                ),
            )

        body = response.text
        occurrences: list[int] = []
        start = 0
        while True:
            index = body.find(marker, start)
            if index == -1:
                break
            occurrences.append(index)
            start = index + len(marker)
        return ProbeOutcome(
            url=current,
            host=urlsplit(current).netloc,
            status_code=response.status_code,
            body=body,
            body_bytes=len(body_bytes),
            content_type=response.headers.get("content-type", ""),
            response_sha256=hashlib.sha256(body_bytes).hexdigest(),
            marker=marker,
            occurrences=occurrences,
            redirects=redirects,
        )

    run.logger.log(
        event="error",
        run_id=run.run_id,
        tool=run.tool,
        url=current,
        reason="redirect_limit",
    )
    return ProbeOutcome(
        url=current,
        marker=marker,
        redirects=redirects,
        failure=ProbeFailure(
            code="REDIRECT_ERROR",
            reason="redirect_limit",
            needs="a target that resolves within five redirects",
            detail=f"more than {MAX_REDIRECTS} redirects",
        ),
    )
