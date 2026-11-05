# Decision log

Every entry records a choice, the reason, and the evidence that the choice behaves as described.
Dates are the build dates. The contract is `context/00-founder-requirements.md`.

---

## D1. Python, three runtime dependencies

**Choice.** Python 3.11–3.13, `mcp`, `httpx`, `playwright`. `pytest` is the only dev dependency.
The HTML tokenizer, TOML reader, HTTP lab server, hashing, and JSON handling come from the standard
library.

**Why.** Each dependency is used directly: the official MCP SDK, an HTTP client that can be told not
to follow redirects, and a browser driver. A second HTTP stack, an HTML parser library, or a web
framework would add code without adding proof.

**Cost.** Playwright downloads a Chromium build (about 150 MB). The README makes that step explicit.

---

## D2. MCP SDK and protocol revision

**Choice.** Official `mcp` Python SDK 2.3.0, high-level `MCPServer` API, stdio transport. Three tools.
Return-type annotations generate the output schemas.

**Evidence.** The server negotiates protocol revision `2025-11-25` with the Inspector CLI, Codex CLI,
and the Python SDK client. A client that requested `2026-07-28` still received `2025-11-25`.

**Why it matters.** The implementation plan warned that the SDK documentation and the negotiated
revision could differ. They do. The README and submission claim `2025-11-25` only. A future review
should re-run the handshake before claiming a newer revision.

**Rejected.** HTTP/SSE transport. The brief asks for an agent-callable server, and stdio removes a
listener, an auth story, and a port from the threat model.

**Rejected.** A hand-written JSON-RPC layer. The official SDK is tested against real clients and keeps
the protocol details out of the security code.

---

## D3. Three tools, typed results, no crashing protocol errors

**Choice.** `scan_xss`, `get_evidence`, `list_scope`. Expected failures return a structured result
with an `error` object (`status` = `invalid`, `refused`, or `blocked`). They are not MCP protocol
errors. `is_error` stays `false`.

**Why.** An agent can read `OUT_OF_SCOPE` and `needs` from the same shape as a normal result. A
protocol error often loses the structured detail and can look like a transport failure. The server
also catches unexpected exceptions at the tool boundary and returns `INTERNAL_ERROR` with no finding,
so one bad run cannot take the process down.

**Tradeoff.** A caller that only checks `is_error` will not see the failure. The one-line text
summary and `status` make it visible; the README documents the contract.

---

## D4. Scope is an exact normalized `host:port`

**Choice.** Deny by default. Exact match after normalization: lowercase, trailing dot removed, IDN to
punycode, missing port expanded to 80/443. Wildcards are rejected when the config loads. Userinfo,
non-HTTP schemes, backslashes, control characters, and percent-encoded hosts are refused. An empty
allowlist refuses everything.

**Why.** A wildcard or a "same domain" rule turns one authorization decision into an open set. Ports
participate because two local apps on different ports are different applications. Failing closed on
ambiguity is the only behavior that survives a hostile URL.

**Evidence.** `tests/test_scope.py` covers userinfo, subdomain, trailing dot, case, IDN, encoded host,
non-HTTP scheme, empty allowlist, missing port, and malformed URLs. `tests/test_scan_refusal.py`
asserts the refusal result, the JSONL line, and zero requests to a canary.

**Rejected.** Path prefixes as a scope unit. A path is not a security boundary; a redirect or a
route change can move the same origin. Ports and hosts are the boundary.

**Rejected.** Implicit `localhost`. An empty allowlist must not quietly allow the machine it runs on.

---

## D5. Manual redirects, then a browser-level fence

**Choice.** `httpx` follows no redirects. `probe.py` reads each `Location`, normalizes it, checks
scope at S2, and caps the chain at five hops. A missing `Location` or a sixth hop fails closed.

**Why.** A client that follows redirects checks scope once and then trusts the network. The manual
loop makes every hop a decision.

**Evidence.** `/redirect?to=…:59999` is blocked at S2 with one request (the allowlisted redirector).
`tests/test_probe.py` covers the hop cap, missing `Location`, and the body cap.
`tests/test_scan_refusal.py` asserts the `OUT_OF_SCOPE` result and log checkpoint.

---

## D6. Context classification is a hypothesis, not a verdict

**Choice.** Use the stdlib `HTMLParser` for text nodes, tag ranges, script CDATA, RCDATA, and
comments. Add a small per-tag attribute scanner and a JS string scanner. Classify every marker
occurrence independently; deduplicate by `(context, sub_context)`.

**Why.** A regex over the whole body cannot tell a text node from a quoted attribute or a JavaScript
string. The tokenizer already yields those ranges. A wrong classification can only choose a payload
that fails to execute; the browser still decides. That makes parser mistakes safe.

**Evidence.** `tests/test_classify.py` is a table over HTML body, attribute quotes, unquoted
attributes, event handlers, URL attributes, script strings, template literals, raw script, JSON, RCDATA,
comments, and multiple reflections.

**Tradeoff.** The classifier is conservative. A pathological document may land in `unclassified` and
be reported as held with `context_not_supported` rather than guessing.

---

## D7. One reviewed payload per context family

**Choice.** A small catalogue: HTML text image, textarea/title/style breakouts, quote-matched
attribute breakouts, JavaScript string breakout, JSON/script breakout, and a `javascript:` URL with
a click verifier.

**Why.** The brief asks for context-matched payloads, not a fuzzer. One payload per family is
auditable, non-destructive, and easy to explain. Each entry states its context, why it works, and the
expected signal.

**Evidence.** Four canonical runs confirm body, attribute, script, and URL. `/multi` returns two
findings in one response. `tests/test_payloads.py` checks context matching and nonce stamping.

**Rejected.** A generic payload list tried against every reflection. That is the behavior the brief
calls out as the gap.

**Rejected.** An LLM choosing payloads at run time. It would make the result harder to reproduce and
add a network dependency to a safety path.

---

## D8. Proof requires two signals: observe, then fresh-context replay

**Choice.** A baseline load runs first with a benign marker. A candidate payload then loads with a
unique nonce. A dialog, console line, or DOM element must contain the nonce. If that happens, the same
payload and nonce run again in a brand-new browser context. Only two signals produce a finding.

**Why.** A reflection, a 200 status, or a screenshot with no signal is not execution. A single signal
can be a cache, a stale dialog, or a race. The fresh context makes the second signal independent.

**Evidence.** `/body` fires `dialog` twice and is confirmed. `/encoded` reflects the marker but fires
nothing and is held twice. `tests/test_verify.py` checks the baseline, the dialog signal, the encoded
page, and the fresh-context replay.

**Downgrade rule.** One signal becomes `could_not_proceed: non_deterministic`. It never becomes a
finding. This is enforced in `scan.py`, not just in documentation.

---

## D9. S5 uses CDP `Fetch`, not Playwright `context.route` — measured

**Choice.** Intercept every browser request with CDP `Fetch.enable` + `Fetch.requestPaused`. A
non-allowlisted request is answered with `Fetch.failRequest` and recorded. The final URL is checked
again at S4.

**Why.** The implementation plan proposed `context.route("**/*")`. A canary test measured that the
route handler did **not** receive the document request for a redirect hop: the browser sent it and the
canary recorded the hit. The fence was switched to CDP, which pauses the request before it leaves the
browser. The canary now records zero hits for the redirect, subresource, and meta-refresh tests.

**Evidence.** `tests/test_scan_refusal.py:test_s5_blocks_an_off_scope_subresource_before_any_canary_hit`
and `test_s5_blocks_a_meta_refresh_to_an_off_scope_host`; `tests/test_verify.py` has the browser-level
version. The run's `scope_refusals` list records the S5 URL and reason.

**Cost.** CDP is Chromium-specific. That matches the browser decision and is stated as a limitation.
A page that needs a third-party asset can fail to execute; the strict fence is the intended tradeoff.

---

## D10. URL context uses a `javascript:` URL and a click

**Choice.** For clickable URL attributes (`href`, `action`, `formaction`), the payload is
`javascript:alert('<nonce>')`. The verifier finds the element whose URL contains the nonce, marks it,
and clicks it. The finding sets `requires_interaction: true`.

**Why.** A `javascript:` URL does not execute on page load. Reporting it as zero-click would be false.
The click is a real browser action, and the dialog is still tied to the nonce.

**Evidence.** `/url` confirms `url/href` with `requires_interaction: true`; the replay clicks again in
a fresh context. Resource URL attributes use a quote-matched breakout instead, because a `javascript:`
URL in `src` does not execute.

---

## D11. Script context uses one breakout for every sub-context

**Choice.** `</script><img src=x onerror=alert('<nonce>')>` is used for JavaScript strings, template
literals, raw script, and JSON inside a script element.

**Why.** The HTML parser ends script CDATA at `</script>` regardless of the JavaScript syntax inside.
One reviewed payload covers the family without shipping a JavaScript parser. The browser still decides.

**Tradeoff.** If a target escapes `</script>` specially, the attempt is held rather than trying a
second, more tailored payload. The catalogue is deliberately one payload per family.

---

## D12. Evidence is a tree with a self-checking record

**Choice.** `evidence/<target-slug>/<run-id>/` with `run.json`, `held.json`, `blocked.json`,
`observations/<finding-id>/`, and `findings/<finding-id>/{finding.json,proof.png,replay.png,replay.md}`.
`finding.json` carries a SHA-256 over its canonical JSON with the hash field removed. `get_evidence`
recomputes it and refuses a mismatch.

**Why.** A finding must be re-derivable and tamper-evident. A screenshot alone is not proof; the
record names the payload, nonce, signal, replay result, browser, and artifact hashes. The hash makes a
hand-edited record detectable.

**Evidence.** `tests/test_evidence.py` covers the layout, hash verification, and tamper refusal. The
canonical bundle is in `docs/sample-evidence/`.

**Tradeoff.** Evidence is written to disk, not to a database. A reviewer can read it with `cat`,
`jq`, and an image viewer.

---

## D13. Output is bounded at 4096 bytes

**Choice.** Arrays cap at 3 confirmed, 4 held, 2 blocked, 2 refusals. Text fields are trimmed. If the
serialized response is still over 4096 bytes, whole entries are dropped from refusals, then blocked,
then held, then confirmed. `totals` keeps the real counts and `truncated` is set.

**Why.** An agent should be able to read the result in one turn. Raw HTML, stack traces, and base64
screenshots are excluded. Evidence keeps the full lists even when the response drops entries.

**Evidence.** `tests/test_result.py` checks the caps, the byte budget, valid JSON, real totals, and
the `truncated` flag. A canonical body response is about 1.2 KB; a two-finding response is about 2 KB.

**Tradeoff.** A run with many held contexts may show fewer than all of them to the agent. The full
list is in `held.json`; `totals` says how many there were.

---

## D14. The 30-second run budget is enforced

**Choice.** `RunContext` records a monotonic start. The remaining budget is checked before the probe,
before the browser, before each attempt, and before each replay. The next HTTP request or navigation
timeout is the smaller of its own limit and the remaining budget. An expired budget returns `TIMEOUT`
with `needs`, not "no XSS".

**Why.** The safety section requires bounded wall-clock time with documented defaults. A per-operation
timeout alone does not bound a run with several operations.

**Evidence.** `tests/test_scan_refusal.py:test_run_budget_is_bounded_and_reported` forces the budget to
zero and asserts a blocked `TIMEOUT` result with zero HTTP requests.

**Tradeoff.** The check is between stages. An operation that is already in flight can take up to its
own 10-second cap, so the worst case is slightly over 30 seconds. The README states this rather than
claiming a hard stop.

---

## D15. The lab is part of the repository

**Choice.** `labapp/` is a stdlib `http.server` app bound to `127.0.0.1:5117`. It reflects one
parameter into HTML body, attribute, script, URL, textarea, JSON, and a two-point page. It also has
`/encoded`, `/redirect`, `/redirect-missing`, `/loop`, `/external`, and `/meta`.

**Why.** Every acceptance test must run from a fresh clone without a container, a database, or a
third-party app. The routes make each context deterministic. The app is marked deliberately
vulnerable in every response.

**Rejected.** Juice Shop as the default anchor. Its well-known XSS is DOM-based, so the HTTP
reflection probe would not see it. DVWA needs PHP and MySQL. Both remain documented alternatives.

---

## D16. Two clients were tested; Claude Code was not usable

**Choice.** Validate with MCP Inspector CLI and Codex CLI 0.166.0. The Python SDK client in the test
suite is a third caller.

**Evidence.** `docs/validation.md` records the Inspector commands and the Codex transcript. Codex
called `list_scope`, `scan_xss` (`/body`), and `get_evidence`, and reported the nonce-bearing dialog
and replay result.

**What failed.** Claude Code 2.1.318 headless returned exit 1 with "OAuth session expired and could
not be refreshed." It never reached a tool call. The README does not claim Claude Code was tested.

**Why it matters.** The implementation plan warned that the protocol revision and GUI client support
could differ. Testing two clients found no protocol problem, but the failed Claude login is recorded
rather than hidden.

---

## D17. Rejected features

| Feature | Why it was not built |
|---|---|
| Crawler/spider | The brief is one URL and one parameter; a crawler widens scope without authorization |
| Dashboard / web UI | The client is the agent; a UI adds a server and a session model |
| Database / queue / workers | One run, one process, local files; a queue adds failure modes with no proof value |
| Authenticated scanning | Cookies and sessions create a credential boundary the brief does not ask for |
| WAF fuzzing / large payload lists | The brief asks for context-matched payloads, not a bypass competition |
| Stored / blind XSS infrastructure | Needs a second identity and an external callback; out of scope |
| External proof callback | Puts a request on a third-party host and makes proof depend on the network |
| LLM payload selection | Adds an unreproducible step to the proof path |
| DalFox / XSStrike wrapper | Reproduces the reflection gap the brief names |
| HTTP/SSE transport | stdio is enough for an agent client and removes a listener |
| `context.route` for S5 | Measured failure: redirect hops bypassed it |
| `.env` auto-loading | Hidden configuration is harder to audit; the environment is explicit |

---

## D18. Open issues a reviewer should know

1. **DOM-only and stored XSS are out of scope.** The classifier sees the server response. A sink
   created entirely by client-side code is not reachable by this design.
2. **DNS rebinding is not mitigated.** The allowlist matches the URL host, not the resolved address.
3. **The strict S5 fence can cause false held results on pages that need third-party assets.** This
   is the intended tradeoff for a local lab.
4. **The URL context needs a click.** It is marked, not hidden.
5. **One payload per family.** A blocked payload does not prove the surface is safe; it proves this
   attempt did not execute.
6. **The video and the public repository are still manual steps.** The code, evidence, tests, and
   script are ready.
