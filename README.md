# mcp-xss-hunter

**One URL. One parameter. Proof, held, or blocked.**

Most XSS scanners stop when a payload shows up in the response. That is a reflection, not an
execution. This MCP server takes one authorized URL and one parameter, works out where the input
lands — HTML body, attribute, script, or URL — sends a payload built for that context, and lets
headless Chromium decide. A result becomes a finding only when the payload executes, then executes
again in a fresh browser context. Everything else is reported as **tested held** or **could not
proceed**, with a reason. Out-of-scope hosts are refused before a request is sent, and every refusal
is appended to a JSONL log.

Built for the BountyKai AI Engineer build task. Not affiliated with BountyKai.

---

## What a run proves

| Acceptance test | Target | Observed result |
|---|---|---|
| True positive | `/body` | 1 confirmed: `html_body/html_text`, payload fired a dialog containing the run nonce, then fired again in a fresh context (`r-20261105T053144Z-4f04`) |
| False positive rejected, twice | `/encoded` | 0 confirmed, 1 held each time: `payload_did_not_execute`, payload listed, no nonce signal (`r-20261105T053148Z-af59`, `r-20261105T053151Z-7386`) |
| Scope refusal | `127.0.0.1:59999` | refused at S1, `http_requests: 0`, JSONL refusal written (`r-20261105T053217Z-a4fb`) |
| Redirect escape | `/redirect?to=…:59999` | blocked at S2 before the target request (`r-20261105T053218Z-0514`) |
| Four context families | `/body`, `/attribute`, `/script`, `/url` | 1 confirmed in each; URL context required a click and is marked `requires_interaction: true` |
| Multiple reflection points | `/multi` | 2 confirmed in one response (`html_body/html_text`, `attribute/quoted_double`) |

Every run above is reproducible with the commands in [Reproduce the claims](#reproduce-the-claims).
A copy of the evidence bundles is in [`docs/sample-evidence/`](docs/sample-evidence/).

---

## 1. What it is

An MCP server with three tools over stdio:

- `scan_xss(url, parameter)` — test one parameter on one authorized URL.
- `get_evidence(finding_id)` — return the stored bundle for a confirmed finding.
- `list_scope()` — return the hosts this server may test.

The server is not a crawler, a dashboard, or a fuzzing platform. Scope is one URL and one parameter.
The output is three separate arrays so an agent can tell a finding from a held attempt from a blocked
stage without guessing.

## 2. Why

Reflection is cheap to produce and cheap to mistake for a finding. A payload in the response body
may be HTML-encoded, inside a JavaScript string, or placed where the browser will never execute it.
DalFox v3 removed its headless browser; XSStrike is unmaintained and GPL-3.0. Wrapping either one
would reproduce the problem the brief names.

This build adds the missing step: a real browser must execute the payload, and then execute it again
in a fresh context, before the word "confirmed" is used. The classifier only chooses which payload to
try. The browser is the arbiter, so a classification mistake can select a payload that fails, but it
cannot create a finding.

## 3. How a run works

```
agent
  │  scan_xss(url, parameter)
  ▼
S0/S1  normalize URL, exact host:port allowlist ──refuse──▶ OUT_OF_SCOPE + JSONL line
  ▼
probe  send a unique marker, follow redirects manually, re-check every hop (S2)
  ▼
locate every marker occurrence in the response body
  ▼
classify each occurrence: html_body | attribute | script | url  (+ sub-context)
  ▼
select one reviewed payload per distinct context, stamped with a unique nonce
  ▼
browser  baseline load → payload load → watch dialog / DOM / console for the nonce
         every request passes the S5 fence; final URL re-checked at S4
  ▼
replay   same payload, same nonce, brand-new browser context
  ▼
evidence finding.json + proof.png + replay.png + replay.md + sha256
  ▼
result   confirmed[] | tested_held[] | could_not_proceed[] + limits + totals
```

| Module | Responsibility |
|---|---|
| `xss_hunter/server.py` | MCP registration, input schemas, typed tool results, shutdown-safe error handling |
| `xss_hunter/scope.py` | URL normalization, allowlist match, no fail-open path |
| `xss_hunter/logging_jsonl.py` | Append-only `logs/scope.jsonl`, one line per scope decision and run event |
| `xss_hunter/runctx.py` | Per-run counters, refusal capture, 30-second wall-clock budget |
| `xss_hunter/probe.py` | Marker request, manual redirects, per-hop scope check |
| `xss_hunter/classify.py` | stdlib HTML tokenizer plus targeted attribute/JS scanners |
| `xss_hunter/payloads.py` | One reviewed payload per context family, nonce-stamped, non-destructive |
| `xss_hunter/verify.py` | Playwright, CDP request fence, signal capture, click activation, screenshots |
| `xss_hunter/evidence.py` | Per-target/run/finding tree, canonical hash, integrity-checked lookup |
| `xss_hunter/result.py` | 4 KB output budget, array caps, real totals, `truncated` |
| `labapp/` | Deliberately vulnerable local lab, bound to `127.0.0.1` only |

### The verification ladder

| Rung | Question | On failure |
|---|---|---|
| R1 reflection | Is the marker in the response? | `tested_held: param_not_reflected` |
| R2 context | Where exactly? | `tested_held: context_not_supported` |
| R3 execution | Did the browser fire a signal containing the nonce? | `tested_held: payload_did_not_execute` |
| R4 replay | Did it fire again in a fresh context? | `could_not_proceed: non_deterministic` |
| R5 evidence | Was the bundle written and hashed? | not published |

Only R5 produces a `confirmed` entry. A failure at any rung downgrades; none promote.

## 4. Setup

Requirements: Python 3.11–3.13, [uv](https://docs.astral.sh/uv/), and Node 22+ only if you want to use
the MCP Inspector CLI. The server itself has no Node dependency.

```bash
git clone https://github.com/Mukku27/mcp-xss-hunter.git
cd mcp-xss-hunter
uv sync
uv run playwright install chromium
```

Start the bundled lab in one terminal and leave it running:

```bash
uv run python -m labapp
# Deliberately vulnerable lab on http://127.0.0.1:5117 (localhost only; do not deploy)
```

The MCP server is normally started by the client over stdio. To smoke-test it with the Inspector CLI:

```bash
npx -y @modelcontextprotocol/inspector --cli --cwd "$PWD" \
  uv run python -m xss_hunter --method tools/list
```

One real run against the lab:

```bash
npx -y @modelcontextprotocol/inspector --cli --cwd "$PWD" \
  uv run python -m xss_hunter --method tools/call \
  --tool-name scan_xss \
  --tool-arg url=http://127.0.0.1:5117/body \
  --tool-arg parameter=q
```

No environment variables are required. Defaults:

| Variable | Default | Meaning |
|---|---|---|
| `XSS_HUNTER_SCOPE_CONFIG` | `config/scope.toml` | Allowlist file |
| `XSS_HUNTER_LOG_PATH` | `logs/scope.jsonl` | Append-only decision log |
| `XSS_HUNTER_EVIDENCE_DIR` | `evidence` | Evidence tree root |
| `XSS_HUNTER_LAB_PORT` | `5117` | Port used by `python -m labapp` only |

See [`.env.example`](.env.example). The server reads the environment; it does not load `.env`
implicitly.

## 5. MCP client configuration

### Codex CLI (tested)

```toml
# ~/.codex/config.toml
[mcp_servers.xss-hunter]
command = "uv"
args = ["run", "--directory", "/abs/path/to/mcp-xss-hunter", "python", "-m", "xss_hunter"]
startup_timeout_sec = 20
tool_timeout_sec = 120
```

Or add it with the CLI:

```bash
codex mcp add xss-hunter -- uv run --directory "$PWD" python -m xss_hunter
```

### Standard `mcpServers` JSON

Clients that use the common `mcpServers` shape can use:

```json
{
  "mcpServers": {
    "xss-hunter": {
      "command": "uv",
      "args": ["run", "--directory", "/abs/path/to/mcp-xss-hunter", "python", "-m", "xss_hunter"]
    }
  }
}
```

### What was actually tested

- **MCP Inspector CLI** (current `@modelcontextprotocol/inspector`): `tools/list`, `scan_xss`,
  `get_evidence`, `list_scope`, refusal, and redirect runs.
- **Codex CLI 0.166.0**: a model session that called `list_scope`, then `scan_xss`, then
  `get_evidence`, and reported the returned finding. The transcript is in
  [`docs/validation.md`](docs/validation.md).
- **Official MCP Python SDK client** in `tests/test_server_stdio.py`.

The server negotiated MCP protocol revision `2025-11-25` in all three. This repository does not claim
support for a newer revision or for "any MCP client"; those two clients and the SDK client were
exercised.

## 6. Tools exposed

### `scan_xss(url, parameter, context_override=None)`

Test one parameter on one authorized URL. Probes the reflection, classifies the injection context,
sends a payload built for that context, verifies execution in headless Chromium, and replays in a
fresh context. Refuses out-of-scope hosts before sending a request. Run budget: 30 seconds, checked
between stages and applied to the next network or browser operation.

- `url`: required, HTTP(S), max 2048 characters.
- `parameter`: required, `^[A-Za-z0-9_.\[\]-]{1,128}$`.
- `context_override`: optional, one of `html_body`, `attribute`, `script`, `url`. It forces the
  hypothesis but still has to pass the browser proof gate.

### `get_evidence(finding_id)`

Return the stored bundle for a confirmed finding: payload, context, signal, replay result, artifact
paths and hashes, and a reproduce command. It recomputes `finding_sha256` before returning anything.
Screenshots are referenced by path, never inlined.

### `list_scope()`

Return the allowlist, its count, and the matching rules. Read-only and idempotent.

### Response shape

A successful run returns a one-line text summary plus `structuredContent`:

```json
{
  "status": "completed",
  "run_id": "r-20261105T053144Z-4f04",
  "target": {"url": "http://127.0.0.1:5117/body", "host": "127.0.0.1:5117", "scope": "allowed"},
  "parameter": "q",
  "confirmed": [{
    "finding_id": "f-70a19cebb2d3",
    "url": "http://127.0.0.1:5117/body",
    "injection_url": "http://127.0.0.1:5117/body?q=%3Cimg+src%3Dx+onerror%3Dalert%28%27xsh589ab985%27%29%3E",
    "context": "html_body",
    "sub_context": "html_text",
    "payload": "<img src=x onerror=alert('xsh589ab985')>",
    "nonce": "xsh589ab985",
    "signal": "dialog",
    "signal_detail": "dialog message contained the nonce: xsh589ab985",
    "requires_interaction": false,
    "replay": {"verified": true, "session": "fresh", "nonce": "xsh589ab985", "signal": "dialog"},
    "evidence": "evidence/127_0_0_1_5117/r-20261105T053144Z-4f04/findings/f-70a19cebb2d3",
    "browser": "chromium/156.0.8078.4"
  }],
  "tested_held": [],
  "could_not_proceed": [],
  "limits": {"duration_ms": 2099, "http_requests": 6, "payloads_sent": 2, "browser_contexts": 2},
  "truncated": false,
  "totals": {"confirmed": 1, "tested_held": 0, "could_not_proceed": 0}
}
```

Selected fields are shown. The live response also carries `reproduce`, `timestamp`, and a top-level
`scope_refusals` list. Arrays are capped at 3 confirmed / 4 held / 2 blocked / 2 refusals; if the
serialized result would exceed 4096 bytes, whole entries are dropped from the least important list
first and `truncated` is set. `totals` always reports the real counts.

### Error and status codes

| Code / reason | Where | Meaning |
|---|---|---|
| `INVALID_INPUT` | any tool | Bad URL, parameter, context override, or finding id |
| `OUT_OF_SCOPE` | S0–S5 | Scope refused at the named checkpoint |
| `SCOPE_CONFIG_INVALID` | `list_scope` | Allowlist could not be loaded; every target is refused |
| `TARGET_UNREACHABLE` | probe/browser | Connection failed or body exceeded 2 MB |
| `TIMEOUT` | probe/browser | Per-operation timeout or the 30-second run budget expired |
| `REDIRECT_ERROR` | probe | Missing `Location` or more than five redirects |
| `BROWSER_ERROR` | browser | Chromium failed to launch or complete the load |
| `INTERNAL_ERROR` | any tool | Unexpected failure; no finding was published |

Held reasons: `param_not_reflected`, `payload_did_not_execute`, `context_not_supported`.
Blocked reasons include `non_deterministic`, `observation_screenshot_missing`,
`finding_write_failed`, and `run_budget_exhausted`.

## 7. Safety

### Scope is a precondition, not a filter

The allowlist is an exact normalized `host:port` list. Ports always participate. A URL with no port
normalizes to 80 or 443 before matching. Wildcards are rejected at config load. An empty or broken
allowlist refuses everything. Userinfo, non-HTTP schemes, backslashes, control characters, and
percent-encoded hosts are refused. The default `config/scope.toml` contains only the bundled lab and
the conventional local Juice Shop / DVWA ports.

| Checkpoint | Where | Catches |
|---|---|---|
| S0 | URL normalization | userinfo tricks, IDN, case, trailing dot, bad schemes |
| S1 | before the probe | direct out-of-scope target |
| S2 | before each redirect hop | `302` to a disallowed host |
| S3 | before every browser navigation | URL built from a redirect or a discovered link |
| S4 | after navigation completes | meta refresh / JS redirect off-scope |
| S5 | every browser request, via CDP `Fetch` | browser-followed redirects and third-party subresources |

The S5 fence pauses every request before Chrome can send it. A refused request is failed with
`BlockedByClient` and appended to the run's refusal list. It is not a Playwright route handler:
`context.route` was measured not to see redirect hops, so it was replaced (see
[`docs/decision-log.md`](docs/decision-log.md)).

### Refusal log

`logs/scope.jsonl` is append-only. Each line has `ts`, `event`, `run_id`, `tool`, `url`, `host`,
`reason`, `checkpoint`, and `detail`. A refusal example:

```json
{"ts":"2026-11-05T05:32:17.467+00:00","event":"refuse","run_id":"r-20261105T053217Z-a4fb","tool":"scan_xss","url":"http://127.0.0.1:59999/never","host":"127.0.0.1:59999","reason":"host_not_allowlisted","checkpoint":"S1","detail":"127.0.0.1:59999 is not in the allowlist"}
```

### Blast radius

- One probe chain: at most 5 redirect hops, 10-second request timeout.
- One baseline load, then one attempt and one replay per distinct `(context, sub_context)` pair.
  The classifier's sub-context set is fixed (HTML text, RCDATA, style, comment, attribute quotes,
  event handler, URL attribute names, and script sub-contexts). A page with many distinct pairs is
  stopped by the 30-second budget rather than an unbounded loop.
- Each navigation is capped at 10 seconds; the run budget is checked between stages and folded into
  the next operation timeout.
- One browser context for observation plus one fresh context per replay, each discarded afterwards.
- No cookies, auth profiles, service workers, telemetry, external callbacks, or persistence.

### Payloads

The catalogue is deliberately small. Each entry creates a dialog containing the run nonce or, for
URL attributes, a `javascript:` URL that does the same. No payload reads cookies, calls an external
host, writes storage, changes server state, or persists after the context closes. The proof is a
local dialog, not a callback.

### Lab only

`labapp/` binds `127.0.0.1` and is marked deliberately vulnerable in every response. Do not deploy it.
The default allowlist contains no public host. The test suite uses a local canary server to assert
that refused requests never arrive.

## 8. Design choices

**Context before payload.** A stdlib `HTMLParser` records tag ranges, script CDATA ranges, RCDATA
ranges, and comments; a small attribute scanner and a JS string scanner classify each marker
occurrence. A regex over the whole body would confuse a marker in a text node with one in a quoted
attribute. The classifier can be wrong without creating a finding, because the browser must execute
the result.

**A real browser is the only proof.** The nonce is unique per attempt and appears only if the payload
runs. A reflection in the source, a 200 response, or a screenshot with no signal is explicitly not a
finding. The baseline load runs first with a benign marker, so a page that already contains the nonce
is caught before any candidate is trusted.

**Replay in a fresh context.** One signal can come from a cached page, a stale dialog, or a race.
The same payload and the same nonce run again in a new browser context. Two independent signals are
required; one signal becomes `could_not_proceed: non_deterministic`.

**Tri-state output.** `confirmed`, `tested_held`, and `could_not_proceed` are separate arrays with
separate counts. Held and blocked entries are not findings. `totals` reports the real counts even
when the agent-facing arrays are capped.

**Exact `host:port`, no wildcards.** A wildcard turns one authorization decision into an open set.
Subdomains are not implied. Ports participate because `localhost:3000` and `localhost:8080` can be
different applications. Ambiguity fails closed.

**Why the S5 fence uses CDP, not `context.route`.** A canary test showed that Playwright's route
handler did not receive the document request for a redirect hop. The browser sent it. CDP
`Fetch.requestPaused` does receive it and can fail it before it leaves the process. The test asserts
zero canary hits. This was measured, not assumed.

**Why no external callbacks.** A proof callback would put a request on a third-party host and make the
proof depend on the network. The dialog signal is local, synchronous, and tied to a nonce.

**Why the output is shaped this way.** An agent needs one line it can quote and a small JSON object it
can reason over. The hard budget is 4096 bytes. Screenshots stay on disk and are referenced by path.
Raw HTML and stack traces never enter the response. The full held and blocked lists remain in the
evidence tree even when the response drops entries.

**Why the evidence hash exists.** `get_evidence` recomputes `finding_sha256` over the canonical
record. A hand-edited `finding.json` is refused, so a finding cannot be changed after the fact
without detection.

**What was deliberately not built.** A crawler, a dashboard, a database, authenticated scanning, WAF
fuzzing, stored/blind XSS infrastructure, an LLM choosing payloads, a DalFox wrapper, HTTP/SSE
transport, scheduling, and cross-run diffing. Each is outside the brief or would weaken the proof
gate.

## 9. Limitations

- **Reflected input only.** The classifier sees what the server returns. DOM-only sinks (for example
  Juice Shop's search) and stored XSS are out of scope.
- **One parameter, one URL, GET query string.** No crawling, forms, headers, JSON bodies, or
  multi-step flows.
- **No authentication.** No cookies, sessions, or logged-in profiles are used or accepted.
- **Chromium only.** The recorded browser is Chromium; other engines are not tested.
- **Strict network fence.** Pages that need a third-party CDN or font may fail to execute because S5
  blocks the asset. This is the intended tradeoff for a local lab target.
- **WAF evasion is not attempted.** A WAF response is simply a page that did not execute the payload;
  it becomes held or blocked with the observed reason.
- **DNS rebinding is not mitigated.** The allowlist matches the URL's host, not the resolved address.
  Pin DNS or use a host you control if that matters.
- **URL context needs a click.** The finding is real, but it is marked `requires_interaction: true`.
  A zero-click claim would be false.
- **One payload per context family.** A target that blocks the chosen payload may still be
  injectable with a different one. That attempt was not made.
- **No continuity.** Finding IDs are stable across runs for the same host/path/parameter/context/family,
  but the tool does not diff runs or schedule retests.

## 10. Demo

The 2–3 minute demo follows [`docs/demo-script.md`](docs/demo-script.md). It is scripted to show an
agent calling `list_scope`, `scan_xss`, and `get_evidence`; a confirmed finding with the dialog nonce
and the fresh-context replay; the `/encoded` negative case returning 0 confirmed; and an out-of-scope
refusal with the JSONL line on screen.

Video link: `<add the unlisted video URL before submission>`

The recording is the one deliverable this repository cannot generate by itself. The script includes
the exact commands and the beats that must be visible.

## Reproduce the claims

Start the lab first:

```bash
uv run python -m labapp
```

Then run any of these in a second terminal. The Inspector CLI prints the full tool result.

```bash
INSPECTOR='npx -y @modelcontextprotocol/inspector --cli --cwd'
RUN='uv run python -m xss_hunter'

# AC-01: true positive
$INSPECTOR "$PWD" $RUN --method tools/call --tool-name scan_xss \
  --tool-arg url=http://127.0.0.1:5117/body --tool-arg parameter=q

# AC-02: reflection-only negative; run it twice
$INSPECTOR "$PWD" $RUN --method tools/call --tool-name scan_xss \
  --tool-arg url=http://127.0.0.1:5117/encoded --tool-arg parameter=q

# AC-03: out-of-scope refusal
$INSPECTOR "$PWD" $RUN --method tools/call --tool-name scan_xss \
  --tool-arg url=http://127.0.0.1:59999/never --tool-arg parameter=q

# AC-04: redirect escape
$INSPECTOR "$PWD" $RUN --method tools/call --tool-name scan_xss \
  --tool-arg 'url=http://127.0.0.1:5117/redirect?to=http%3A%2F%2F127.0.0.1%3A59999%2Fescape' \
  --tool-arg parameter=q

# AC-05: the other three context families
$INSPECTOR "$PWD" $RUN --method tools/call --tool-name scan_xss \
  --tool-arg url=http://127.0.0.1:5117/attribute --tool-arg parameter=q
$INSPECTOR "$PWD" $RUN --method tools/call --tool-name scan_xss \
  --tool-arg url=http://127.0.0.1:5117/script --tool-arg parameter=q
$INSPECTOR "$PWD" $RUN --method tools/call --tool-name scan_xss \
  --tool-arg url=http://127.0.0.1:5117/url --tool-arg parameter=q

# Multiple reflection points
$INSPECTOR "$PWD" $RUN --method tools/call --tool-name scan_xss \
  --tool-arg url=http://127.0.0.1:5117/multi --tool-arg parameter=q

# Evidence lookup
$INSPECTOR "$PWD" $RUN --method tools/call --tool-name get_evidence \
  --tool-arg finding_id=f-70a19cebb2d3
```

Note: zsh treats `$INSPECTOR "$PWD" $RUN` as words, which is what these commands rely on. If you use
a different shell, write the command out in full.

The refusal line:

```bash
tail -5 logs/scope.jsonl
```

## 11. Tests

```bash
uv run pytest -q
```

119 tests, all passing on Python 3.12.14 with Chromium 156.0.8078.4.

| Suite | What it proves |
|---|---|
| `tests/test_scope.py` | Userinfo, subdomain, trailing dot, case, IDN, encoded host, scheme, empty allowlist, missing port |
| `tests/test_classify.py` | Table-driven fixtures for HTML body, attribute, script, URL, RCDATA, JSON, comments |
| `tests/test_payloads.py` | Context matching, nonce stamping, non-destructive payload shapes |
| `tests/test_probe.py` | Manual redirects, hop cap, missing `Location`, body cap |
| `tests/test_verify.py` | Baseline, dialog signal, encoded page with no signal, fresh-context replay, S5 canary |
| `tests/test_scan_refusal.py` | AC-01, AC-02 twice, AC-03, AC-04, S5 subresource and meta refresh, URL-click finding, multi-reflection, stable IDs, run budget |
| `tests/test_result.py` | Array caps, 4 KB budget, valid JSON, real totals, `truncated` |
| `tests/test_evidence.py` | Evidence tree, hash integrity, tamper refusal |
| `tests/test_server_stdio.py` | A real MCP Python SDK client over stdio: `tools/list`, refusal, invalid input, log line |
| `tests/test_scan_contexts.py` | Full browser pipeline for attribute and script contexts |

The test suite uses a local canary HTTP server for the scope tests. No test targets a public host.

## 12. What was verified, held, and blocked

Verified:

- `/body`: `html_body/html_text`, payload `<img src=x onerror=alert('xsh589ab985')>`, signal
  `dialog`, replay verified in a fresh context, bundle
  `evidence/127_0_0_1_5117/r-20261105T053144Z-4f04/findings/f-70a19cebb2d3`.
- `/attribute`: `attribute/quoted_double`, quote breakout.
- `/script`: `script/js_string_double`, `</script>` breakout.
- `/url`: `url/href`, `javascript:` URL, click activated, `requires_interaction: true`.
- `/textarea`: `html_body/html_textarea`.
- `/json`: `script/js_json`.
- `/multi`: two independent findings in one response.

Held:

- `/encoded` twice: 0 confirmed, 1 held each time. The payload was tried and listed; the browser
  produced no nonce signal. This is the negative case that decides the thesis.

Blocked:

- Out-of-scope host: refused at S1 with `http_requests: 0`.
- Redirect to an out-of-scope host: blocked at S2; only the allowlisted redirector was requested.
- Off-scope subresource and meta refresh: blocked at S5 in the test suite; the canary received zero
  requests.

## 13. Traceability

| Req | Implemented in | Verified by | Status |
|---|---|---|---|
| FR-1 | `server.py`, `scan.py` | `test_server_stdio.py`, every canonical run | Met |
| FR-2 | `classify.py`, `payloads.py` | `test_classify.py`, `test_payloads.py`, four context runs | Met |
| FR-3 | `verify.py` | `test_verify.py`, `test_scan_refusal.py` | Met |
| FR-4 | `models.py`, `scan.py`, `evidence.py` | `test_scan_refusal.py`, evidence bundles | Met |
| FR-5 | pipeline modules | unit and integration suites | Met |
| FR-6 | `classify.py`, `scan.py` | `/multi` test and run | Met |
| FR-7 | `models.py`, `scan.py` | `context`, `sub_context`, `injection_url` in `finding.json` | Met |
| GR-1 | `server.py` | Inspector CLI, Codex CLI, Python SDK client; 4 KB budget | Met |
| GR-2 | `scope.py`, `logging_jsonl.py`, `verify.py` | scope suite, S5 canary, JSONL assertions | Met |
| GR-3 | `config/scope.toml`, `labapp/` | default config audit, canary tests | Met |
| GR-4 | all modules | 119 tests, small files, comments explain why | Met |
| DL-1 | `README.md`, repo | fresh-clone test | Fresh-clone test pending; publication pending |
| DL-2 | `docs/demo-script.md` | video recording | Pending recording |
| DL-3 | submission email | send by 8 Nov 2026, 23:59 IST | Pending |
| AC-01 | `verify.py`, `scan.py` | `r-20261105T053144Z-4f04` | Met |
| AC-02 | proof gate | `r-20261105T053148Z-af59`, `r-20261105T053151Z-7386`; test run twice | Met |
| AC-03 | `scope.py`, log | `r-20261105T053217Z-a4fb` | Met |
| AC-04 | `probe.py` S2 | `r-20261105T053218Z-0514`, canary test | Met |
| AC-05 | four families | four canonical runs plus textarea/json/multi | Met |
| AC-06 | `pyproject.toml`, README setup | fresh-clone test | Pending fresh-clone test |
| AC-07 | `result.py` | `test_result.py`, raw stdio response check | Met |
| AC-08 | this README | section audit | Met |
| AC-09 | demo | runtime and content | Pending recording |
| AC-10 | scope + lab only | git history, logs, evidence audit | Met |
| AC-11 | Reproduce section | every cited run ID has a command | Met |

## 14. What I would build next

Retest continuity (the stable finding ID already exists), stored XSS with two identities, authenticated
runs with an explicit credential boundary, and a second browser engine. Each adds a failure mode, so
each would need its own proof gate before it could publish a finding.

## 15. License

MIT. See [`LICENSE`](LICENSE). The code remains the author's; the repository contains no third-party
code.
