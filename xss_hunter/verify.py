"""Headless-browser verification.

One browser, one observation context, one fresh context for replay. Every
network request the browser makes passes the S5 fence: a CDP ``Fetch`` pause
handler scope-checks the URL before Chrome may send it. Playwright's
``context.route`` was measured and did **not** see redirect hops, so it is not
used here.

The only proof accepted is a signal containing the attempt nonce: a dialog
message, a console line, or a DOM element whose id/text is the nonce. A
reflection in the page source is not a signal.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from playwright.sync_api import (
    Browser,
    BrowserContext,
    CDPSession,
    Error as PlaywrightError,
    Page,
    TimeoutError as PlaywrightTimeoutError,
    sync_playwright,
)

from .probe import with_parameter
from .runctx import BUDGET_NEEDS, RunContext

NAVIGATION_TIMEOUT_MS = 10_000
CLICK_TIMEOUT_MS = 3_000
SETTLE_MS = 500
MAX_SIGNAL_TEXT = 200
MAX_MESSAGES = 20


@dataclass
class BrowserFailure:
    code: str
    reason: str
    needs: str
    detail: str = ""
    checkpoint: str | None = None


@dataclass
class Verification:
    executed: bool = False
    signal: str = "none"
    signal_detail: str = ""
    final_url: str = ""
    dialogs: list[str] = field(default_factory=list)
    consoles: list[str] = field(default_factory=list)
    activation: str = ""
    screenshot: bytes = b""
    screenshot_error: str = ""
    browser: str = ""
    failure: BrowserFailure | None = None

    @property
    def ok(self) -> bool:
        return self.failure is None


@dataclass
class _PageState:
    blocked: list[str] = field(default_factory=list)
    dialogs: list[str] = field(default_factory=list)
    consoles: list[str] = field(default_factory=list)
    page_errors: list[str] = field(default_factory=list)


_BROWSER_ARGS = [
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-default-apps",
    "--disable-sync",
    "--metrics-recording-only",
    "--no-first-run",
    "--safebrowsing-disable-auto-update",
    "--disable-features=Translate,OptimizationHints,MediaRouter",
]

_CONTEXT_OPTIONS = {
    "service_workers": "block",
    "viewport": {"width": 1280, "height": 800},
}

# Find the element whose URL-bearing attribute carries the attempt nonce, then
# mark it so Playwright can activate it by selector.
_TAG_CLICKABLE = """
(nonce) => {
  const nodes = Array.from(document.querySelectorAll(
    'a[href], area[href], button[formaction], input[formaction], form[action]'
  ));
  for (const el of nodes) {
    const raw = el.tagName === 'FORM'
      ? el.getAttribute('action')
      : (el.getAttribute('href') || el.getAttribute('formaction'));
    if (raw && raw.indexOf(nonce) !== -1) {
      el.setAttribute('data-xsh-click', '1');
      return el.tagName;
    }
  }
  return '';
}
"""

# A DOM signal means an element id or leaf text equals the nonce. The nonce is
# not in the raw server response for this attempt, so this distinguishes
# JS-created content from server-reflected markup.
_DOM_SIGNAL = """
(nonces) => {
  if (!document.body) return '';
  for (const nonce of nonces) {
    if (document.getElementById(nonce)) return 'element id';
    const nodes = document.querySelectorAll('body *');
    for (const el of nodes) {
      if (el.children.length === 0 && el.textContent && el.textContent.trim() === nonce) {
        return 'leaf text in <' + el.tagName.toLowerCase() + '>';
      }
    }
  }
  return '';
}
"""

_ANNOTATE = """
([detail, nonce, phase]) => {
  const el = document.createElement('div');
  el.setAttribute('data-xsh-proof', nonce);
  el.textContent = 'xss-hunter observed (' + phase + '): ' + detail +
    ' [nonce ' + nonce + ']';
  el.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:2147483647;' +
    'background:#111;color:#fff;padding:8px;font:13px monospace;white-space:pre-wrap';
  document.documentElement.appendChild(el);
}
"""


def _truncate(text: str, limit: int = MAX_SIGNAL_TEXT) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


def _error_name(exc: Exception) -> str:
    return type(exc).__name__


def _is_unreachable(message: str) -> bool:
    return any(
        token in message
        for token in (
            "ERR_CONNECTION_REFUSED",
            "ERR_NAME_NOT_RESOLVED",
            "ERR_CONNECTION_TIMED_OUT",
            "ERR_ADDRESS_UNREACHABLE",
        )
    )


class BrowserSession:
    """One Chromium process, one observation context, fresh contexts on demand."""

    def __init__(self, run: RunContext):
        self.run = run
        self.failure: BrowserFailure | None = None
        self.browser: Browser | None = None
        self.context: BrowserContext | None = None
        self.version = ""
        self._playwright = None
        self._replay_contexts: list[BrowserContext] = []

    def __enter__(self) -> "BrowserSession":
        try:
            self._playwright = sync_playwright().start()
            self.browser = self._playwright.chromium.launch(
                headless=True, args=_BROWSER_ARGS
            )
            self.version = self.browser.version
            self.context = self.browser.new_context(**_CONTEXT_OPTIONS)
            self.run.browser_contexts += 1
        except Exception as exc:  # noqa: BLE001 - a browser failure is a typed result
            self.failure = BrowserFailure(
                code="BROWSER_ERROR",
                reason="browser_launch_failed",
                needs="a working Chromium install (playwright install chromium)",
                detail=_error_name(exc),
            )
            self._close()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._close()

    def _close(self) -> None:
        for context in [self.context, *self._replay_contexts]:
            if context is not None:
                try:
                    context.close()
                except Exception:  # noqa: BLE001
                    pass
        self._replay_contexts.clear()
        self.context = None
        if self.browser is not None:
            try:
                self.browser.close()
            except Exception:  # noqa: BLE001
                pass
            self.browser = None
        if self._playwright is not None:
            try:
                self._playwright.stop()
            except Exception:  # noqa: BLE001
                pass
            self._playwright = None

    @property
    def ok(self) -> bool:
        return self.failure is None and self.browser is not None

    def baseline(
        self, url: str, parameter: str, value: str, nonces: set[str]
    ) -> Verification:
        """Load the page with a benign value and prove no nonce signal occurs."""
        if not self.ok or self.context is None:
            return Verification(failure=self.failure, browser=self.version)
        target = with_parameter(url, parameter, value)
        decision = self.run.check(target, "S3")
        if decision.refused:
            return Verification(
                final_url=decision.url,
                browser=self.version,
                failure=BrowserFailure(
                    code="OUT_OF_SCOPE",
                    reason=f"browser_navigation_refused_{decision.reason}",
                    needs="an allowlisted URL",
                    detail=decision.detail,
                    checkpoint="S3",
                ),
            )
        return self._navigate(
            self.context,
            target,
            sorted(nonces),
            requires_interaction=False,
            activate_nonce=None,
            phase="baseline",
        )

    def attempt(
        self,
        url: str,
        parameter: str,
        payload: str,
        nonce: str,
        requires_interaction: bool,
    ) -> Verification:
        """Load the payload URL once and look for one nonce-bearing signal."""
        if not self.ok or self.context is None:
            return Verification(failure=self.failure, browser=self.version)
        target = with_parameter(url, parameter, payload)
        decision = self.run.check(target, "S3")
        if decision.refused:
            return Verification(
                final_url=decision.url,
                browser=self.version,
                failure=BrowserFailure(
                    code="OUT_OF_SCOPE",
                    reason=f"browser_navigation_refused_{decision.reason}",
                    needs="an allowlisted URL",
                    detail=decision.detail,
                    checkpoint="S3",
                ),
            )
        self.run.payloads_sent += 1
        return self._navigate(
            self.context,
            target,
            [nonce],
            requires_interaction=requires_interaction,
            activate_nonce=nonce,
            phase="first load",
        )

    def replay(
        self,
        url: str,
        parameter: str,
        payload: str,
        nonce: str,
        requires_interaction: bool,
    ) -> Verification:
        """Repeat the payload in a brand-new context with no shared state."""
        if not self.ok or self.browser is None:
            return Verification(failure=self.failure, browser=self.version)
        target = with_parameter(url, parameter, payload)
        decision = self.run.check(target, "S3")
        if decision.refused:
            return Verification(
                final_url=decision.url,
                browser=self.version,
                failure=BrowserFailure(
                    code="OUT_OF_SCOPE",
                    reason=f"browser_navigation_refused_{decision.reason}",
                    needs="an allowlisted URL",
                    detail=decision.detail,
                    checkpoint="S3",
                ),
            )
        try:
            context = self.browser.new_context(**_CONTEXT_OPTIONS)
        except Exception as exc:  # noqa: BLE001
            return Verification(
                browser=self.version,
                failure=BrowserFailure(
                    code="BROWSER_ERROR",
                    reason="context_creation_failed",
                    needs="a working Chromium install",
                    detail=_error_name(exc),
                ),
            )
        self._replay_contexts.append(context)
        self.run.browser_contexts += 1
        self.run.payloads_sent += 1
        try:
            return self._navigate(
                context,
                target,
                [nonce],
                requires_interaction=requires_interaction,
                activate_nonce=nonce,
                phase="fresh-context replay",
            )
        finally:
            try:
                context.close()
            except Exception:  # noqa: BLE001
                pass
            if context in self._replay_contexts:
                self._replay_contexts.remove(context)

    # -- internals ---------------------------------------------------------

    def _new_page(self, context: BrowserContext) -> tuple[Page, CDPSession, _PageState]:
        page = context.new_page()
        page.set_default_timeout(NAVIGATION_TIMEOUT_MS)
        page.set_default_navigation_timeout(NAVIGATION_TIMEOUT_MS)
        state = _PageState()

        def on_dialog(dialog) -> None:
            state.dialogs.append(_truncate(dialog.message))
            try:
                dialog.dismiss()
            except Exception:  # noqa: BLE001 - the dialog may already be gone
                pass

        def on_console(message) -> None:
            if len(state.consoles) < MAX_MESSAGES:
                state.consoles.append(_truncate(message.text))

        def on_page_error(error) -> None:
            if len(state.page_errors) < MAX_MESSAGES:
                state.page_errors.append(_truncate(str(error)))

        page.on("dialog", on_dialog)
        page.on("console", on_console)
        page.on("pageerror", on_page_error)

        cdp = context.new_cdp_session(page)

        def on_request(event) -> None:
            request_url = event["request"]["url"]
            decision = self.run.check(request_url, "S5", log_allow=False)
            if decision.refused:
                state.blocked.append(_truncate(request_url, 300))
                try:
                    cdp.send(
                        "Fetch.failRequest",
                        {
                            "requestId": event["requestId"],
                            "errorReason": "BlockedByClient",
                        },
                    )
                except Exception:  # noqa: BLE001
                    pass
            else:
                try:
                    cdp.send(
                        "Fetch.continueRequest", {"requestId": event["requestId"]}
                    )
                    self.run.http_requests += 1
                except Exception:  # noqa: BLE001
                    pass

        cdp.on("Fetch.requestPaused", on_request)
        cdp.send(
            "Fetch.enable",
            {"patterns": [{"urlPattern": "*", "requestStage": "Request"}]},
        )
        return page, cdp, state

    def _navigate(
        self,
        context: BrowserContext,
        url: str,
        nonces: list[str],
        *,
        requires_interaction: bool,
        activate_nonce: str | None,
        phase: str,
    ) -> Verification:
        remaining_ms = int(self.run.remaining_seconds() * 1000)
        if remaining_ms <= 0:
            return Verification(
                failure=BrowserFailure(
                    code="TIMEOUT",
                    reason="run_budget_exhausted",
                    needs=BUDGET_NEEDS,
                    detail="the 30-second run budget expired before navigation",
                )
            )
        timeout_ms = min(NAVIGATION_TIMEOUT_MS, remaining_ms)
        page, cdp, state = self._new_page(context)
        failure: BrowserFailure | None = None
        activation = ""
        try:
            try:
                page.goto(url, wait_until="load", timeout=timeout_ms)
            except PlaywrightTimeoutError:
                failure = BrowserFailure(
                    code="TIMEOUT",
                    reason="browser_navigation_timeout",
                    needs="a faster target or a higher timeout",
                    detail=f"no load within {timeout_ms} ms",
                )
            except PlaywrightError as exc:
                message = str(exc)
                code = "TARGET_UNREACHABLE" if _is_unreachable(message) else "BROWSER_ERROR"
                failure = BrowserFailure(
                    code=code,
                    reason="browser_navigation_failed",
                    needs="a reachable in-scope target",
                    detail=_error_name(exc),
                )

            if failure is None:
                page.wait_for_timeout(SETTLE_MS)
                if requires_interaction and activate_nonce:
                    activated, activation = self._activate(page, activate_nonce)
                    if activated:
                        page.wait_for_timeout(SETTLE_MS)

            if state.blocked:
                # S5 takes precedence over any navigation error it caused.
                failure = BrowserFailure(
                    code="OUT_OF_SCOPE",
                    reason="browser_request_refused",
                    needs="an allowlisted page with no off-scope resources or redirects",
                    detail=(
                        f"{len(state.blocked)} request(s) blocked; first: "
                        f"{state.blocked[0]}"
                    ),
                    checkpoint="S5",
                )

            final_url = ""
            try:
                final_url = page.url
            except Exception:  # noqa: BLE001
                pass

            if failure is None:
                decision = self.run.check(final_url, "S4")
                if decision.refused:
                    failure = BrowserFailure(
                        code="OUT_OF_SCOPE",
                        reason=f"post_navigation_refused_{decision.reason}",
                        needs="an in-scope final URL",
                        detail=decision.detail,
                        checkpoint="S4",
                    )

            signal = "none"
            detail = ""
            if failure is None:
                signal, detail = self._signal(page, state, nonces)

            verification = Verification(
                executed=signal != "none",
                signal=signal,
                signal_detail=detail,
                final_url=final_url,
                dialogs=list(state.dialogs),
                consoles=list(state.consoles),
                activation=activation,
                browser=f"chromium/{self.version}",
                failure=failure,
            )

            if verification.executed and failure is None:
                verification.screenshot, verification.screenshot_error = self._screenshot(
                    page, signal, detail, nonces, phase
                )
            return verification
        finally:
            try:
                cdp.send("Fetch.disable")
            except Exception:  # noqa: BLE001
                pass
            try:
                page.close()
            except Exception:  # noqa: BLE001
                pass

    def _activate(self, page: Page, nonce: str) -> tuple[bool, str]:
        try:
            tag = page.evaluate(_TAG_CLICKABLE, nonce)
        except PlaywrightError as exc:
            return False, f"activation lookup failed: {_error_name(exc)}"
        if not tag:
            return False, "no clickable element carried the nonce"
        try:
            if tag == "FORM":
                control = page.query_selector(
                    'form[data-xsh-click="1"] button, '
                    'form[data-xsh-click="1"] input[type="submit"]'
                )
                if control is not None:
                    control.click(timeout=CLICK_TIMEOUT_MS)
                    return True, "clicked the form submit control"
                page.eval_on_selector(
                    'form[data-xsh-click="1"]', "form => form.requestSubmit()"
                )
                return True, "submitted the form"
            page.click('[data-xsh-click="1"]', timeout=CLICK_TIMEOUT_MS)
            return True, f"clicked <{tag.lower()}>"
        except PlaywrightError as exc:
            return False, f"activation failed: {_error_name(exc)}"

    def _signal(
        self, page: Page, state: _PageState, nonces: list[str]
    ) -> tuple[str, str]:
        for message in state.dialogs:
            if any(nonce in message for nonce in nonces):
                return "dialog", f"dialog message contained the nonce: {message}"
        for message in state.consoles:
            if any(nonce in message for nonce in nonces):
                return "console", f"console message contained the nonce: {message}"
        try:
            dom = page.evaluate(_DOM_SIGNAL, nonces)
        except PlaywrightError:
            dom = ""
        if dom:
            return "dom", f"DOM signal: {dom}"
        return (
            "none",
            f"no signal contained the nonce (dialogs={len(state.dialogs)}, "
            f"console={len(state.consoles)})",
        )

    def _screenshot(
        self, page: Page, signal: str, detail: str, nonces: list[str], phase: str
    ) -> tuple[bytes, str]:
        try:
            nonce = nonces[0] if nonces else ""
            page.evaluate(_ANNOTATE, [f"{signal}: {detail}", nonce, phase])
            return page.screenshot(full_page=False), ""
        except PlaywrightError as exc:
            return b"", f"screenshot_failed: {_error_name(exc)}"
