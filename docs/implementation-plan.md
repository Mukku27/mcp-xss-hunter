# Implementation Plan — Context-Aware XSS Hunter (MCP)

> Status: **plan only**. No production code is written in this document's session.
> Contract: `context/00-founder-requirements.md`. Company shaping: `context/01`–`05`. Where this
> plan derives a choice beyond the founder's words, it is marked **[derived]** and traced to a
> principle (`N1`–`N12`) or requirement ID (`FR-*`, `GR-*`, `AC-*`, `DL-*`).
> Every compatibility claim below was verified against a primary source on 2026-11-04; see the
> Reuse Map for the sources.

---

## 1. Product summary

**Thesis (one sentence).** An MCP server that takes one authorized URL and one parameter, works out
where the input lands in the response, sends a payload built for *that* syntax, and reports a finding
**only after a headless browser executes the payload twice — once to observe, once to replay in a
fresh context** — reporting everything else as *held* or *blocked*, never as a finding.

**End-to-end run** (the product, `FR-1`…`FR-5`, mirrors `assignment.md` §3):

1. Agent calls `list_scope()` to see what it may test (`GR-1`, `N11`).
2. Agent calls `scan_xss(url, parameter)`.
3. **Normalize + scope-check the input URL** before any byte leaves the process (`S0`/`S1`, `GR-2`).
4. **Probe**: send a unique benign marker `xsh<nonce>` in the parameter; follow redirects manually,
   re-checking scope at every hop (`S2`).
5. **Locate** every occurrence of the marker in the response (`FR-6`).
6. **Classify** the syntactic context of each occurrence: HTML body / attribute / script / URL
   (`FR-2`, `C1`–`C4`).
7. **Select** a small, context-matched, auto-firing, non-destructive payload per occurrence.
8. **Verify** in headless Chromium with a baseline navigation first, a dialog/DOM/console signal
   tied to the run nonce (`FR-3`, R3).
9. **Replay** the winning payload in a fresh browser context; two signals = confirmed, one = not
   (`N3`, R4).
10. **Record** evidence per target/run/finding with a hash and `replay.md` (`N7`, R5).
11. Return three separate arrays — `confirmed` / `tested_held` / `could_not_proceed` — plus measured
    limits (`N4`, `FR-4`). Out-of-scope hosts are refused before any request and logged (`GR-2`,
    `AC-03`).

---

## 2. Scope

### In scope (must-have, each traces to an ID)

- One URL + one parameter in, confirmed XSS out (`FR-1`).
- Context classification for the four mandated families (`FR-2`, `AC-05`).
- Multiple reflection points handled independently (`FR-6`).
- Headless-browser execution proof with nonce (`FR-3`, `FR-4`).
- Fresh-context replay before publish (`N3`, `[derived]` from "a claim is checked before it is a
  finding").
- Tri-state result contract (`N4`).
- Deny-by-default allowlist, six checkpoints, JSONL refusal log (`GR-2`, `AC-03`, `AC-04`, `N1`/`N2`).
- Per-target evidence tree + `get_evidence` (`N7`, `N10`).
- 2–3 MCP tools over stdio, bounded JSON output (`GR-1`, `AC-07`).
- A bundled, localhost-bound deliberately-vulnerable lab app so every AC is reproducible from a
  clean clone (`GR-3`, `AC-06`, `AC-11`).
- README (all required sections) + two-client validation + demo video plan (`DL-1`, `DL-2`,
  `AC-08`, `AC-09`).

### Out of scope (founder's fence, `00` §9) — do **not** build

Crawler/spider; authenticated/session scanning; WAF-bypass research or large-scale fuzzing; web
UI/dashboard; database/queue/worker fleet; an LLM inside the tool choosing payloads; a
DalFox/XSStrike wrapper; stored/blind XSS infra or public callbacks; PDF/Slack/CI/scheduler; a
rewrite for prestige; Docker Compose with many services.

### Cut list to stay inside 6–10 h (cut in this order, `00` §15)

1. FP/FN evaluation harness (the one `[O]` stretch). 2. Extra sub-contexts beyond one payload per
family. 3. Pretty CLI. 4. HTTP/SSE transport. **Never cut:** allowlist, proof gate, the negative
case in the video, README design-choices section.

---

## 3. Architecture

### 3.1 Components (small modules, one job each — `GR-4`)

| Module | Responsibility |
|--------|----------------|
| `server.py` | MCP server: registers `scan_xss`, `get_evidence`, `list_scope`; maps exceptions to typed tool-result errors; never crashes. |
| `scope.py` | The single scope decision. URL normalization + allowlist match + per-hop re-check. No `try/except` that returns allow. |
| `probe.py` | Sends the marker; manual redirect follow with per-hop scope check; returns body + where the marker landed. |
| `classify.py` | Streaming HTML parse → context (`C1`–`C4`) + sub-context + surrounding snippet, for **every** marker occurrence. |
| `payloads.py` | Tiny auditable catalogue: one payload per context family, each commented with target context, why it works, expected signal, nonce slot. |
| `verify.py` | Playwright: baseline nav, inject payload, watch dialog/DOM/console for the nonce; fresh-context replay; screenshot. |
| `evidence.py` | Writes `run.json`, `findings/<id>/{finding.json,proof.png,replay.md}`, `held.json`, `blocked.json`; hashes artifacts. |
| `logging_jsonl.py` | Append-only `logs/scope.jsonl`; one line per scope decision/run event; never logs cookies/headers/bodies. |
| `result.py` | Assembles and size-bounds the tri-state response; caps arrays; sets `truncated`. |
| `labapp/` | Localhost-only Flask/stdlib vuln app for the demo and integration tests (clearly marked insecure). |

### 3.2 Data flow

```
agent → scan_xss(url, param)
  → scope.check(url)            [S0 normalize, S1 pre-probe]  ──refuse──► log + OUT_OF_SCOPE result
  → probe.send(marker)          [S2 per redirect hop]         ──no match─► tested_held(param_not_reflected)
  → classify.contexts(body)     → [ (offset, context, sub, snippet), … ]  (FR-6: all occurrences)
  → payloads.select(context)    → candidate payloads (nonce-stamped)
  → verify.execute(url, payload)[S3 pre-goto, S4 post-nav, S5 route abort]
        baseline nav (nonce absent?) → inject → signal? ──no──► tested_held(reason)
  → verify.replay(fresh ctx)    → second signal? ──no──► could_not_proceed(non_deterministic)
  → evidence.write(...)         → finding.json + proof.png + replay.md + sha256
  → result.assemble()           → { confirmed[], tested_held[], could_not_proceed[], limits }
```

### 3.3 Verification ladder (`context/03` §3) — a finding only reaches the top

| Rung | Question | Produces | On failure |
|------|----------|----------|------------|
| R1 Reflection | Marker in response? | offset, response hash | `tested_held` (not reflected) |
| R2 Context | Where exactly? | context + sub-context + snippet | `tested_held` (unclassified) |
| R3 Execution | Did the browser fire the nonce signal? | signal type, nonce, screenshot | `tested_held` (encoded/stripped/no sink) |
| R4 Replay | Fires again in a **fresh** context? | second signal + screenshot | `could_not_proceed` (non_deterministic) |
| R5 Evidence | Bundle complete + re-derivable? | artifacts + sha256 + replay.md | do not publish |

R1–R2 are diagnostics, never findings. R3 alone is a *candidate*. R4 is the differentiator. A
failure at R4 **downgrades**, never upgrades.

### 3.4 Scope checkpoints (`context/03` §4) — all six

| # | Where | Catches |
|---|-------|---------|
| S0 | normalize + parse input | userinfo trick, case, trailing dot, IDN, non-http scheme |
| S1 | before the probe request | direct out-of-scope target |
| S2 | before following each redirect | 302 to a disallowed host |
| S3 | before `page.goto()` | URL built from a redirect/discovered link |
| S4 | after navigation completes | meta-refresh / JS redirect off-scope |
| S5 | every browser request (document + subresource) via `context.route` abort | browser-followed redirect or third-party asset escaping the check |

S5 default is **strict** (abort any non-allowlisted request before it leaves the process). This can
break pages needing external CDNs; acceptable because the target is a local lab. Documented as such.

---

## 4. MCP surface (`GR-1`, `00` §8)

**Transport:** stdio only. **SDK:** official MCP Python SDK (`mcp`), high-level decorator API
(`@mcp.tool()`); return-type annotations generate the output schema and `structuredContent`.
**Tools: 3.**

### `scan_xss(url: str, parameter: str) -> ScanResult`
Test one parameter on one authorized URL: probe → classify → inject → verify → fresh-context replay.
Returns confirmed findings only, plus tested-held and blocked results. Refuses out-of-scope hosts
before any request and records the refusal. Default budget 30 s.

- **Input schema:** `url` (required, `http`/`https`, max length ~2048), `parameter` (required,
  `^[A-Za-z0-9_.\-\[\]]{1,128}$`). No free-form blobs. Optional `context_override` enum
  (`html_body|attribute|script|url`) for reviewers, default none.
- **Output:** the tri-state contract in `context/03` §5 — `run_id`, `target{url,host,scope}`,
  `parameter`, `confirmed[]`, `tested_held[]`, `could_not_proceed[]`, `limits{duration_ms,
  http_requests, payloads_sent, browser_contexts}`, optional `scope_refusals[]`, `truncated`.
  Arrays capped (10 confirmed / 20 held / 5 blocked) with `truncated: true` + totals when exceeded.
  Plus a one-line human summary in text content.

### `get_evidence(finding_id: str) -> Evidence`
Return the evidence bundle for a confirmed finding: payload, context, signal, replay result,
screenshot path, reproduction command, hash. Refuses unknown IDs (`INVALID_INPUT`). Returns
**pointers + metadata**, never inlined base64 (`AC-07`, `N7`).

### `list_scope() -> Scope`
Return the hosts this server may test (`allow[]`, `wildcards`, `ports_matter: true`). Read-only,
idempotent; call before `scan_xss` if unsure (`N11`).

**Typed errors** (returned as tool results, server never crashes): `OUT_OF_SCOPE`, `INVALID_INPUT`,
`TARGET_UNREACHABLE`, `NO_REFLECTION`, `NO_EXECUTION`, `TIMEOUT`, `BROWSER_ERROR`. `NO_REFLECTION`
and `NO_EXECUTION` are also expressible as negative results (not hard errors) so a clean run is a
first-class outcome, not a failure (`00` §7.4, `N4`).

**Output budget:** target ≤ 4 KB; no raw HTML, no payload catalogue dump, no stack traces.

**Client config (copy-paste, stdio).** For Cursor (`~/.cursor/mcp.json`) / Claude Desktop
(`claude_desktop_config.json`), same `mcpServers` shape:

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

**"Any MCP client" is a claim — test it (`00` §8, `AC-06`).** Validate two clients: MCP Inspector
CLI (`npx @modelcontextprotocol/inspector --cli <cmd> --method tools/list` then `tools/call`) as the
scriptable second client, and one GUI client (Cursor or Claude Desktop). See Risk R-6 on protocol
revision.

---

## 5. Context model (`FR-2`, `FR-6`, `00` §6)

**Approach [derived]: hybrid — a streaming HTML parser (Python stdlib `html.parser.HTMLParser`)
plus targeted per-occurrence checks.** Not a single regex over the whole body (`00` §6.1 step 3).
Rationale: the stdlib parser already yields exactly the signals the four families need
(`handle_data` for text nodes, `handle_starttag` with decoded attrs for attribute values, CDATA
mode for `<script>`), with `getpos()` for location. If it misclassifies on pathological markup the
*only* consequence is a payload that fails to execute → `tested_held`. **The browser is the ground
truth; the parser just picks the payload.** That makes a wrong guess safe (never a false finding).

**Multiple reflections (`FR-6`).** Find every marker occurrence, classify each independently, dedupe
by `(context, sub_context)`, and try a payload per distinct context. A fixture with two reflection
points yields two classified candidates.

| ID | Context | Detection signal | Sub-contexts | Payload strategy (auto-firing, non-destructive) |
|----|---------|------------------|--------------|--------------------------------------------------|
| C1 | HTML body | marker in a text node (not in CDATA, not in a tag) | element content, `<textarea>`/`<title>` RCDATA breakout | tag-injection that fires without interaction, e.g. `<img src=x onerror=…nonce…>` |
| C2 | attribute | marker inside a tag's attribute value | quoted `"`/`'`, unquoted, `on*` handler, URL-bearing (`href`/`src`/`action`) | match the quote and break out; inside `on*` inject an expression; URL-bearing → `javascript:` where honored |
| C3 | `<script>` | marker inside script CDATA | JS string, template literal, raw expression, JSON blob | close the string/expression correctly respecting JS escaping, or break out of the element |
| C4 | URL | marker in a URL position (attribute or page-built URL) | URL-bearing attribute; redirect sink where cheap | `javascript:` scheme where honored, else attribute breakout; mark if a click is required |

**URL interpretation [derived, `00` §17.1]:** cover URL-bearing attributes (C4 overlaps C2's
URL-bearing sub-context) and, where cheap, redirect sinks. Stated in the README.

**Encoding-aware (`00` §6.3).** The classifier records the raw bytes around the marker; the proof
gate judges what the browser actually executes, not what was sent. HTML-entity / URL / JS escaping
that neutralizes a payload surfaces as a `tested_held` with a specific reason — this is the AC-02
mechanism.

**Catalogue rules.** Small and auditable (one payload per family to start), each commented with
context + why + expected signal; unique nonce per attempt; no exfiltration/persistence/destructive
DOM changes beyond the proof marker (`00` §6.3, §5.3).

---

## 6. Proof model (`FR-3`, `FR-4`, `00` §7)

**Nonce.** `xsh-<finding_id>` (per attempt), embedded in the proof action so a stale reflection or
cached page cannot masquerade as execution (`00` §6.3).

**Valid proof (any one, recorded with artifacts):**
- a **dialog** captured via Playwright `page.on("dialog")` whose `message` contains the nonce
  (handler attached **before** navigation, else the page stalls — verified behavior);
- a **DOM marker** created by executed JS (element id/text == nonce), read via `page.evaluate`
  **after** load and proven absent in the raw server HTML (distinguishes JS-created from
  server-reflected markup — `00` §7.2);
- a **console** message containing the nonce.

Primary signal = dialog (unambiguous JS execution). DOM marker / console are fallbacks for contexts
where a dialog is awkward.

**Never reported as XSS (`00` §7.2):** payload string present in the HTTP body; a node present
because the *server* reflected it; `alert(1)` found by regex in source; a WAF page / 200 / a
screenshot with no signal; "looks injectable."

**False-positive exclusions.** Baseline navigation first (confirm the nonce signal is absent without
the payload); unique nonce per attempt; dialog handler attached before `goto`; require the nonce in
the signal payload; fresh-context replay (R4) eliminates cached-page / stale-dialog / race classes.

**Replay (`N3`, R4).** After R3, open a **new browser context** (incognito-equivalent, verified
isolated: separate cookies/storage) and re-run the same payload with the same nonce. Two independent
signals = `confirmed`. One signal = `could_not_proceed(non_deterministic)` — downgrade, never
upgrade.

**Evidence bundle (per finding, `00` §7.3, `context/03` §6).** `finding.json` (fields: `finding_id`,
`run_id`, `url`, `parameter`, `context`, `sub_context`, `payload`, `nonce`, `signal`,
`signal_detail`, `timestamp`, `browser` = `chromium/<version>`, `screenshot`, `reproduce`,
`artifact_sha256`); `proof.png`; `replay.md` (human steps + expected signal). **Rule:** if the
signal cannot be re-derived from stored artifacts, it is not confirmed and is not returned.

**Stable finding ID (`N6`, cheap continuity):** `hash(host + path + parameter + context +
payload_family)` truncated — survives payload edits. `run.json` records the allowlist snapshot,
counts, timings, tool version, optional `previous_run_id`. A README line states what a second run
would reuse; scheduling/diffing is explicitly out of scope.

---

## 7. Safety (`GR-2`, `GR-3`, `00` §5, `N1`/`N2`/`N10`)

**Allowlist normalization (`scope.py`, one decision function, no fail-open path):**
- deny by default — empty/missing allowlist ⇒ refuse everything; no implicit `localhost`;
- lowercase host, strip trailing dot, IDN → punycode before compare;
- reject URLs with userinfo (`http://allowed@evil/`) — never read host from the wrong side of `@`;
- `http`/`https` targets only; block `file:`, `data:`, `gopher:`, `ftp:`, browser-internal schemes;
- **exact `host:port`** match (ports participate; `localhost:3000` explicit) [decision §12];
- subdomain = exact host only; wildcards opt-in + explicit in config + documented;
- IP literals only if explicitly listed.

**Redirects.** HTTP client follows **no** redirects automatically (`httpx` `follow_redirects=False`);
a manual loop caps hops (5) and runs S2 on each `Location`; missing/malformed `Location` ⇒ fail
closed.

**Browser-level interception (S5).** A `context.route("**/*")` handler aborts any request whose host
is not allowlisted — **including the document request of a redirect target** — so "no request
reached an out-of-scope host" holds at the browser layer, not just the HTTP client. Block service
workers (`service_workers="block"`) so interception is complete.

**Fail-closed defaults (`N2`).** Unresolvable host, malformed URL, missing `Location`, browser crash
⇒ refuse/stop with a typed reason. Unknown ⇒ `OUT_OF_SCOPE`.

**Refusal logging (`00` §5.2, `AC-03`).** Append-only JSONL at `logs/scope.jsonl`. Every entry:
`ts` (ISO-8601), `event` (`allow|refuse|scan_start|finding|error`), `run_id`, `tool`, `url`, `host`,
`reason`, and the deciding `checkpoint` (`N1`/`N2` signal). A refusal is logged **even when the tool
returns an error**. Never log cookies, auth headers, or full bodies.

**Lab-only (`GR-3`, `00` §5.3).** Ship `config/scope.toml` with lab hosts only (`localhost`,
`127.0.0.1`, and the bundled lab app's host:port). No telemetry, no outbound third-party calls, no
external proof callbacks. Payloads non-destructive (no exfil/persistence/credential access/DoS).

**Blast radius (`00` §5.4).** Bounded requests/payloads/wall-clock with documented defaults; one
browser context per run, discarded after; per-host concurrency 1–2; timeouts on every network and
browser op; a timeout is `TIMEOUT`, never "no XSS."

**DNS rebinding [decision §12]:** disclosed as a known limitation in the README (not mitigated in
this budget). Do not claim protection not implemented (`N9`).

---

## 8. Test plan (`00` §10.2, §4)

**Runner:** `pytest`. **Browser tests:** `pytest` + Playwright sync API against the bundled lab app.

### Unit
- **Allowlist bypass table (`scope.py`):** userinfo, subdomain (`evil-allowed.com` ∌ `allowed.com`),
  trailing dot, case, non-http scheme, IP literal, empty allowlist, `host` vs `host:port`, a
  redirect `Location` to an off-scope host. Each asserts refuse + a log line.
- **Classifier table (`classify.py`):** fixtures for C1–C4 and multi-reflection, asserting
  `(context, sub_context)` per occurrence (`AC-05`, `FR-6`).
- **Proof gate (`verify.py` decision logic):** a reflection-only / HTML-encoded fixture yields
  **zero** findings (`AC-02` at the unit level).
- **Result bounding (`result.py`):** arrays cap and set `truncated`; output stays ≤ 4 KB; no HTML.

### Integration (against the bundled lab app, localhost)
- Full pipeline on a known-vulnerable route for each of C1–C4.
- Redirect route (allowlisted → off-scope) blocked at the hop.

### The four acceptance tests (decide the outcome, `AC-01`–`AC-04`)
1. **True positive:** vulnerable parameter → ≥1 `confirmed` with exact payload + browser signal + a
   second replay signal.
2. **Reflection-only held (the money test):** parameter that reflects but HTML-encodes → `0`
   confirmed, a `tested_held` entry with a specific reason; run twice to rule out flakiness.
3. **Out-of-scope refusal:** non-allowlisted host → `OUT_OF_SCOPE`, zero requests to it, a JSONL
   line with ts/host/tool/reason/run_id.
4. **Redirect escape:** allowlisted host 302s off-scope → blocked at the hop and logged (asserted at
   both the HTTP-client hop and the browser route layer).

---

## 9. Milestones (vertical slices, 6–10 h, aligned to `00` §15)

Each slice ends demonstrable. Build in this order so the safety spine and the proof gate exist
before breadth.

| # | Slice | Output | Est. |
|---|-------|--------|------|
| M1 | MCP skeleton + `scope.py` + `list_scope` + JSONL log | server starts, `tools/list` works, `AC-03` refusal + log | 1.0 h |
| M2 | Bundled lab app + `probe.py` (marker, manual redirects, S2) | reflection located; `AC-04` redirect blocked | 1.0 h |
| M3 | `classify.py` + `payloads.py` (C1–C4, one payload each) | four contexts classified on fixtures (`AC-05`) | 1.5 h |
| M4 | `verify.py` headless proof + `evidence.py` + S3/S4/S5 | real execution signal, artifacts stored (`AC-01`) | 2.0 h |
| M5 | Fresh-context replay (R4) + `result.py` tri-state + `get_evidence` | replay-verified finding; bounded tri-state output | 1.0 h |
| M6 | Tests (unit suites + 4 ACs) | suites green, including `AC-02` run twice | 1.0 h |
| M7 | README (all sections) + two-client validation | reviewer-ready, one copy-paste config | 1.0 h |
| M8 | Demo video + fresh-clone + claim audit | 2–3 min, negative case + refusal on camera | 1.0 h |
| — | Buffer (flake handling) | | 1–2 h |

Total lands in the 6–10 h window with buffer. If time runs short, apply the §2 cut list.

---

## 10. Risks and unknowns (each with a conservative default)

| # | Risk / unknown | Conservative default |
|---|----------------|----------------------|
| R-1 | **DOM-based XSS (e.g. Juice Shop search) never appears in the HTTP response**, so the HTTP-reflection classifier cannot see it. | Anchor on **server-reflected** XSS (bundled lab app / DVWA). State DOM & stored XSS as explicit README limitations; do not claim them. |
| R-2 | Browser flakiness (timing, dialog races) causes false negatives or non-determinism. | Baseline nav, nonce check, dialog handler before `goto`, per-op timeouts; R4 downgrades flaky results to `could_not_proceed`. Never upgrade on flake. |
| R-3 | Payload fires on observe but not on replay. | Report `could_not_proceed(non_deterministic)`; never publish a one-signal candidate (`N3`). |
| R-4 | Over-strict S5 route abort breaks a page that needs an external asset → false negative. | Keep strict default (lab target has no external deps); document the behavior and the tradeoff. |
| R-5 | DNS rebinding (host passes check, resolves to a different address). | Disclose as a limitation; do not claim mitigation (`N9`). |
| R-6 | **MCP SDK protocol revision vs client support.** The current SDK speaks the 2026-07-28 revision; some GUI clients' support for it is unconfirmed, and the SDK recently renamed its high-level class. | **Pin the SDK version** in the lockfile; at build time run the M7 two-client check (Inspector CLI + one GUI client) and only then claim "any MCP client." If a GUI client rejects the modern revision, pin the SDK version that negotiates the revision that client accepts. Decision §12.5. |
| R-7 | Chromium-only coverage. | Acceptable and honest (`00` §17.5); state it. |
| R-8 | 6–10 h overrun. | Apply the §2 cut list; never cut allowlist, proof gate, negative case, or design-choices README. |

---

## 11. README outline and demo storyboard

### README (order from `context/03` §9, content required by `00` §10.1)
1. Title + thesis — "A scanner reports what it saw. This reports what it proved." (not "this is an
   MCP server") — `04` voice.
2. The gap — DalFox/XSStrike: run by hand, reflection-heavy, no browser-execution proof.
3. What it does — URL + parameter → context → payload → browser → replay → verified finding.
4. What it refuses — crawl, authenticate, widen scope, report unverified results.
5. Architecture — the 6-stage pipeline (one numbered list / diagram).
6. Setup — fresh-clone commands incl. starting the bundled lab app and `playwright install chromium`.
7. MCP client config — the copy-paste JSON from §4.
8. Tools — names, inputs, outputs, error codes, one short example response.
9. Result contract — the three arrays, briefly.
10. Safety — six checkpoints, fail-closed, JSONL refusals, S5 network fence, lab-only defaults.
11. Design choices (mandatory) — context-first classification, why a real browser, why replay, why
    tri-state, why `host:port`, why no external callbacks, what was deliberately not built.
12. What was verified / held / blocked — the actual demo run, including the negative.
13. Honest caveats — DOM & stored XSS, auth flows, WAF, DNS rebinding, Chromium-only, flakiness.
14. Reproduce — exact commands for every claim (`AC-11`).
15. What I'd build next — continuity/retest, stored XSS with two identities, authenticated runs.
16. License (MIT/Apache-2.0) + a traceability matrix (`00` §16).

Forbidden words (`04` §1): potential, suspected, likely, confidence, severity levels, robust,
comprehensive, 100%, zero false positives, etc.

### Demo storyboard (2:20–2:50; `00` §11, `03` §10, `04` §5) — order ends on discipline
| Time | Beat | On screen |
|------|------|-----------|
| 0:00–0:20 | Problem | "Most scanners stop at reflection. Reflection is not execution." |
| 0:20–0:40 | Setup | MCP client connected; `tools/list`; `list_scope` shows lab-only hosts. |
| 0:40–1:10 | Agent acts | Agent calls `scan_xss` with the lab URL + parameter — the real tool call. |
| 1:10–1:50 | Proof | Context + payload; browser dialog/DOM marker with nonce; then **fresh-context replay fires again**; screenshot/evidence. |
| 1:50–2:15 | **Negative case** | A reflected-but-encoded parameter → **0 confirmed**, held with a reason. (Proves the thesis.) |
| 2:15–2:35 | Safety | Out-of-scope host → refusal + the `scope.jsonl` line on screen. |
| 2:35–2:50 | Close | One design tradeoff, one limitation, repo link. |

Never cut the negative case or the refusal. Do not re-record over a flake — show the retry.

---

## 12. Decision list (resolved with conservative defaults; a human may override before coding)

1. **Lab anchor.** *Default:* ship a tiny localhost-bound **own deliberately-vulnerable app**
   (`labapp/`) that server-reflects one parameter into all four contexts plus one HTML-encoding
   route — founder-sanctioned ("your own app"), one-command, deterministic for all ACs. Document
   DVWA as an alternative; note Juice Shop's XSS is DOM-based and out of this tool's wheelhouse.
   *Override only if* the reviewer requires DVWA specifically.
2. **URL context.** *Default:* cover URL-bearing attributes and, where cheap, redirect sinks; state
   the interpretation (`00` §17.1).
3. **Allowlist granularity.** *Default:* exact **`host:port`**; path is not a security boundary;
   wildcards forbidden unless explicit in config (`00` §17.2/§17.3).
4. **DNS rebinding.** *Default:* disclose as a limitation, do not mitigate in this budget
   (`00` §17.4).
5. **MCP SDK version + the two clients.** *Default:* pin the official `mcp` SDK version in the
   lockfile and validate against **MCP Inspector CLI** + **one GUI client (Cursor or Claude
   Desktop)**; only claim "any MCP client" after M7 passes. This is the one place a wrong assumption
   silently breaks `GR-1` — see Risk R-6.

---

## Reuse map

Verified against primary sources on 2026-11-04.

| Candidate | What it does | License | Maintained | Reuse / Avoid | How it fits |
|-----------|--------------|---------|-----------|---------------|-------------|
| **MCP Python SDK** (`mcp`, modelcontextprotocol/python-sdk) | Official MCP server/client; stdio + structured output; `@mcp.tool()` with type-hint schemas; Python 3.11+ | MIT | Yes (v2 docs speak 2026-07-28 revision) | **Reuse** as the server. Pin the version (v2 renamed `FastMCP`→`MCPServer`; decorator API stable). | `server.py`; stdio; typed output = agent-sized JSON (`GR-1`). |
| **MCP Inspector** (`@modelcontextprotocol/inspector`) | Reference test client — Web/CLI/TUI; negotiates legacy vs 2026-07-28; Node 22.19+ | MIT | Yes | **Reuse** as the scriptable second client + CI smoke test. | Satisfies two-client validation (`AC-06`). |
| **Playwright for Python** | Headless Chromium; `page.on("dialog")`, `context.route`/`page.route` abort (incl. document request), isolated `new_context`, `service_workers="block"` | Apache-2.0 | Yes | **Reuse** as the browser driver. | `verify.py` proof + replay + S5 network fence (`FR-3`, `N3`). |
| **Python stdlib `html.parser`** | Streaming HTML tokenizer: `handle_data`, `handle_starttag` w/ decoded attrs, CDATA mode for `<script>`, `getpos()` | PSF (stdlib) | Yes | **Reuse** (+ targeted checks). Avoid pulling parse5/lxml. | `classify.py` C1–C4; lenient failure is safe (browser is arbiter). |
| **httpx** | HTTP client with `follow_redirects=False` + manual next-hop inspection | BSD-3 | Yes | **Reuse** for the probe (likely already transitive via the SDK). Alternative: stdlib `urllib`. | `probe.py` per-hop scope re-check (S2). |
| **Python stdlib `tomllib`** | Read TOML config (3.11+) | PSF (stdlib) | Yes | **Reuse** for `config/scope.toml`. | Zero-dependency scope config (`N11`). |
| **pytest** | Test runner; table-driven fixtures | MIT | Yes | **Reuse** as the test runner. | Allowlist/classifier/proof-gate suites (`00` §10.2). |
| **DalFox v3** (hahwul) | Rust XSS scanner; reflected/stored/DOM via DOM/AST static analysis; **removed its headless browser**; MIT; has its own MCP stdio server | MIT | Yes (v3.2.4, 2026-10) | **Avoid as a dependency/wrapper** (`00` §9). | The reference point for the gap: its `V` ≠ browser execution. We add the proof it dropped. |
| **XSStrike** (s0md3v) | Python XSS suite; handwritten parsers + context analysis + fuzzing/crawler | **GPL-3.0** | **No** (author declared unmaintained 2024; last release 3.1.6, 2025-03) | **Avoid** (viral license + unmaintained). | Borrow the *idea* — context analysis before payload selection — not the code. |
| **OWASP Juice Shop** | SPA lab app; famous XSS is **DOM-based** (search via Angular `trustAsHtml`; payload not in server response) | MIT | Yes | **Avoid as the anchor** for an HTTP-reflection classifier; cite as a DOM-XSS limitation. | Out of this tool's wheelhouse; honest caveat. |
| **DVWA** | PHP lab app with genuine **server-reflected** XSS | GPL-3.0 (run as a service, not linked) | Yes | **Optional alternative** target (reviewer-pointable). | Needs PHP+MySQL — heavier than the bundled lab app; documented, not default. |

---

## First 60 minutes (build session kickoff)

0–10 min — `git init` discipline aside: create `pyproject.toml`/`uv` project (Python 3.11+), pin
`mcp`, `playwright`, `httpx`, `pytest`; `playwright install chromium`; add `config/scope.toml` with
lab hosts only and `.env.example`.

10–25 min — Write `scope.py` (normalize + exact `host:port` match + deny-by-default) and
`logging_jsonl.py`. Write the allowlist bypass unit table **first** (userinfo/subdomain/trailing
dot/case/scheme/empty). This is the spine; it must be red→green before anything touches the network.

25–45 min — Stand up `server.py` with the three tools returning stub tri-state results; wire
`scan_xss` to call `scope.check` and log + return `OUT_OF_SCOPE` on refusal. Confirm with MCP
Inspector CLI: `--method tools/list`, then a `scan_xss` call against an out-of-scope host →
`AC-03` passes with a `scope.jsonl` line.

45–60 min — Add the bundled `labapp/` (one route reflecting a parameter into HTML body) and
`probe.py` with `follow_redirects=False`. Confirm the marker is located and a redirect to an
off-scope host is refused at the hop. Now M1–M2 are demonstrable and the rest of the ladder (M3–M5)
builds on a proven safety spine.

Do not start M3+ until the allowlist table and the `AC-03` refusal-with-log are green.
