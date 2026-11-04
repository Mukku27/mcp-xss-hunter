# Founder Requirements — BountyKai AI Engineer Build Task

> **Status:** Canonical specification. This file is the source of truth for *what* to build and *what not* to build.
> **Read this completely before writing a single line of code.** Re-read §9 before adding any feature.
> **Owner:** Mukesh Vemulapalli
> **Source:** Email from Gokul Ravi (Founder, BountyKai), Mon 2 Nov 2026, 18:45 IST, replying to the AI Engineer application.
> **Deadline:** Sunday, 8 Nov 2026, 23:59 IST — repo + demo video links replied to the same email thread.
> **Effort budget:** 6–10 hours. This is a scoping instruction, not a target to pad.

---

## 0. How an AI agent must use this document

1. **Read all of it first.** Then read the section relevant to your task again before you start.
2. **Every change must map to a requirement ID** (`FR-*`, `GR-*`, `DL-*`, `AC-*`). If you cannot name the ID a change satisfies, you are off-brief — stop.
3. **Labeling convention:**
   - `[F]` — stated by the founder. **Non-negotiable.** Do not reinterpret, soften, or "improve" it.
   - `[D]` — derived engineering requirement. The minimum needed to satisfy an `[F]` without loopholes. Binding unless it conflicts with an `[F]`.
   - `[O]` — optional / stretch. Only after **all** MUST items pass **and** only if it costs under 1 hour.
4. **Conflict order:** founder's words → this document's derived rules → your own preference. Ambiguity is resolved conservatively, then written down in §17 and the README's "Open questions".
5. **Never fabricate.** No invented metrics, benchmark numbers, screenshots, logs, or "it works" claims. Every claim in the README or video MUST be reproducible from the repo with a documented command. This is the single fastest way to fail this task.
6. **Do not expand scope.** The founder asked for one sharp tool, not a platform. §9 is a hard fence.

### TL;DR — the ten rules that matter most

1. The differentiator is **execution proof, not reflection**. If it is reflected but did not run, it is **not a finding**.
2. Payloads are **selected per injection context** (HTML body, attribute, inside `<script>`, URL) — not sprayed blindly.
3. A **headless browser** decides truth. HTTP response bodies never do.
4. Return **only confirmed XSS**, each with the exact payload and evidence of execution.
5. Ship an **MCP server** any MCP client can drive, with **short, structured** output.
6. **Deny-by-default allowlist.** Refuse **and log** every out-of-scope host.
7. **Never** touch a site you do not own. Local lab only: Juice Shop / DVWA / your own app.
8. Public repo + README covering **setup, tools, design choices**.
9. **2–3 minute** video of a real agent using it. Hard cap at 3:00.
10. Stay inside **6–10 hours**. Small, clean, explainable.

---

## 1. The mission in one sentence

> Build a **context-aware XSS hunter that an AI agent drives over MCP**, which injects payloads matched to the reflection context and reports a vulnerability **only after a headless browser proves the payload executed**.

The founder's framing of the gap, verbatim:

> "Tools like DalFox and XSStrike hunt for cross-site scripting, but they're run by hand and often flag reflections that never actually execute. Build a version an AI agent can drive through MCP tools."

And the cultural bar he set in the very first line of his reply:

> "Your focus on only reporting what you can verify is exactly how we think."

**Implication:** this repo is not judged primarily on payload count or scanner breadth. It is judged on whether the verification loop is real, visible, and honest.

---

## 2. Founder's brief (verbatim, do not paraphrase when implementing)

```
Your task: a context-aware XSS hunter built for AI agents

Tools like DalFox and XSStrike hunt for cross-site scripting, but they're run by hand and
often flag reflections that never actually execute. Build a version an AI agent can drive
through MCP tools. It should:
- Take a URL and a parameter to test
- Inject XSS payloads chosen for where the input lands (HTML body, attribute, inside a script, URL)
- Use a headless browser to confirm the payload actually executes, not just that it's reflected
- Return only confirmed XSS, each with the payload and proof of execution

Ground rules:
- Expose it as an MCP server that any MCP client can use. Keep outputs short and structured,
  made for an agent to read.
- Enforce a scope allowlist. Refuse and log any host outside it.
- Test only on your own setup or a deliberately vulnerable app like OWASP Juice Shop or DVWA.
  Never point it at a site you don't own.
- AI coding tools are fine. We'll walk through your code together on a short call.

What to send back:
- A public GitHub repo (the code stays yours) with a README covering setup, the tools it
  exposes and your design choices
- A 2-3 minute demo video of an agent using it

Aim for 6-10 hours of work, and reply here with your links by Sunday, 8 Nov, 11:59 PM IST.
If you need a couple more days, just let me know.
```

---

## 3. Requirement register

### 3.1 Functional requirements

| ID | Requirement | Type | Test that proves it |
|----|-------------|------|---------------------|
| **FR-1** | Accept a **URL** and a **parameter name** to test as the primary input. | `[F]` | Tool call with `{url, parameter}` returns a result without extra required config. |
| **FR-2** | Choose payloads **based on where the input lands**, covering at minimum: **HTML body, attribute, inside a script, URL**. | `[F]` | Each of the four contexts is detected and mapped to a context-appropriate payload (tests + demo). |
| **FR-3** | Use a **headless browser** to confirm the payload **actually executes**, not merely that it is reflected. | `[F]` | A reflection-only control returns **zero** findings; an executable payload returns a finding with a browser execution signal. |
| **FR-4** | Return **only confirmed XSS**, each with **the payload** and **proof of execution**. | `[F]` | Result array contains no reflection-only, "potential", or "suspected" items. Every item carries payload + evidence. |
| **FR-5** | Instrument the full loop: reflection probe → context classification → context-specific payloads → browser verification → evidence capture. | `[D]` | Code path is traceable end to end; each stage is unit-testable. |
| **FR-6** | Handle **multiple reflection points** in one response, not just the first match. | `[D]` | Fixture with two reflection points yields two candidates, each classified separately. |
| **FR-7** | Report the **context** and **injection point** for every finding. | `[D]` | Finding schema contains `context`, `parameter`, `injection_url`. |

### 3.2 Ground rules

| ID | Requirement | Type | Enforcement |
|----|-------------|------|-------------|
| **GR-1** | Expose the tool as an **MCP server usable by any MCP client**. Outputs **short and structured**, written for an agent to read. | `[F]` | Verified with ≥2 clients (e.g. Claude Desktop/Code + MCP Inspector); responses are bounded JSON, no raw HTML dumps. |
| **GR-2** | Enforce a **scope allowlist**. **Refuse and log** any host outside it. | `[F]` | Denied host returns a typed error, **zero requests reach it**, and an append-only log entry is written. |
| **GR-3** | Test **only** your own setup or a deliberately vulnerable app (OWASP Juice Shop, DVWA). **Never** point it at a site you do not own. | `[F]` | Shipped default allowlist contains only local/lab hosts; no public host appears in git history, logs, or video. |
| **GR-4** | AI coding tools are permitted, but the author must be able to **walk through the code** on a short call. | `[F]` | Code is readable, comments explain *why*, no opaque generated blobs, author can defend every design decision. |

### 3.3 Deliverables

| ID | Requirement | Type | Definition of done |
|----|-------------|------|--------------------|
| **DL-1** | **Public GitHub repo** (code remains the author's) with a README covering **setup**, **tools exposed**, and **design choices**. | `[F]` | Fresh clone → documented commands → running server. README has all three named sections plus safety and limitations. |
| **DL-2** | **2–3 minute demo video** of an **agent** using it. | `[F]` | 2:00–3:00 runtime, real (not staged) agent session, shows confirmation proof. |
| **DL-3** | Reply to the email thread with **both links** by the deadline. | `[F]` | Sent before Sun 8 Nov 2026, 23:59 IST. |

### 3.4 Logistics

| ID | Requirement | Type | Note |
|----|-------------|------|------|
| **CT-1** | Aim for **6–10 hours** of work. | `[F]` | Overbuilding is a failure mode, not a bonus. |
| **CT-2** | Deadline **Sunday, 8 Nov 2026, 23:59 IST**. | `[F]` | Extension is available *if asked before the deadline*: "just let me know." |
| **CT-3** | Code ownership stays with the author. | `[F]` | Any permissive license (MIT/Apache-2.0) is fine. |

---

## 4. Acceptance criteria (testable, in priority order)

A build is not done until every **AC** below passes. AC-01 through AC-04 are the ones that decide the outcome.

| ID | Criterion | Pass condition |
|----|-----------|----------------|
| **AC-01** | **True positive, proven.** | On the local lab, a parameter with a known XSS returns ≥1 finding containing the exact payload and a browser-derived execution signal. |
| **AC-02** | **False positive rejected — the money test.** | A parameter that reflects the payload but encodes/neutralizes it so it cannot execute returns **0 confirmed findings**, with an explicit "no confirmed XSS" result listing what was tried. |
| **AC-03** | **Scope refusal works and is logged.** | A non-allowlisted host produces `OUT_OF_SCOPE`, **no HTTP request is sent to that host**, and a JSONL log line records timestamp, host, tool, reason, run id. |
| **AC-04** | **Redirect cannot escape scope.** | An allowlisted host that 302s to a non-allowlisted host is blocked at the hop and logged. |
| **AC-05** | **All four contexts covered.** | HTML body, attribute, script, and URL contexts each have a demonstrated detection + payload strategy. |
| **AC-06** | **Portable setup.** | Fresh clone + documented commands starts the MCP server and answers `tools/list`; no undocumented manual steps. |
| **AC-07** | **Agent-sized output.** | Every tool response is valid JSON, stable keys, bounded size (target ≤ 4 KB), no raw response bodies, evidence referenced by path/id. |
| **AC-08** | **README complete.** | Setup, tools, design choices present — plus scope/safety, limitations, and how to reproduce the demo. |
| **AC-09** | **Video correct.** | 2:00–3:00, shows an agent driving the tool end to end, includes proof of execution and one safety control. |
| **AC-10** | **No public target ever touched.** | Verified against git history, evidence logs, browser history artifacts, and the video. |
| **AC-11** | **Claims are reproducible.** | Every number and capability statement in README/video regenerates via a documented command. |

---

## 5. Safety invariants — GR-2 and GR-3 made unbypassable

These are the rules most likely to be silently broken by a naive implementation. Treat them as invariants, not features.

### 5.1 Allowlist

- **Deny by default.** Empty or missing allowlist ⇒ every target is refused. No implicit `localhost` fallback hidden in code; ship an explicit default config file.
- **Match on normalized host**, not raw string:
  - lowercase, strip trailing dot, convert IDN to punycode before comparison;
  - reject URLs containing userinfo (`http://allowed.com@evil.com`) — never parse the host from the wrong side of `@`;
  - allow only `http` and `https` schemes for targets;
  - decide and document whether the port participates in matching (recommended: yes, exact `host:port`, with `localhost:3000` explicit).
- **Re-check every redirect hop.** Do not let the HTTP client or the browser auto-follow into a non-allowlisted host. Follow manually, cap hops (e.g. 5), validate each `Location`.
- **Re-check at navigation time**, not only at input parse time. The browser must never be pointed at an unchecked URL.
- **Intercept at the browser layer.** A redirect can be followed by the browser before any post-navigation check runs. Abort non-allowlisted document and subresource requests in the driver (e.g. a Playwright route handler), so the block happens *before* the request leaves the process.
- **Subdomain rule:** exact host only. Wildcards are opt-in, explicit in config, and documented. `evil-allowed.com` must not match `allowed.com`.
- **IP literals:** only allowed if explicitly listed. Block `file:`, `data:`, `gopher:`, `ftp:`, and browser-internal schemes as targets.
- **DNS rebinding:** either pin/validate the resolved address, or state it plainly as a known limitation in the README. Do not claim protection you did not implement.

### 5.2 Refusal logging

- Append-only **JSONL** at a documented path (e.g. `logs/scope.jsonl`).
- Refusals MUST be logged **even when the tool call returns an error**.
- Required fields: `ts` (ISO-8601), `event` (`allow` / `refuse` / `scan_start` / `finding` / `error`), `run_id`, `tool`, `url`, `host`, `reason`.
- Never log cookies, auth headers, or full response bodies.
- The log must be inspectable in the demo — showing the refusal line on camera is the cheapest, strongest proof that GR-2 is real.

### 5.3 Lab-only testing

- Default config ships with lab hosts only (`localhost`, `127.0.0.1`, and the documented Juice Shop/DVWA hostnames).
- Documentation tells the reviewer how to point it at **their own** local Juice Shop/DVWA.
- No telemetry, no analytics, no outbound calls to third-party infrastructure at runtime.
- **No external callbacks** for proof (no public collaborator/beacon service). Proof must be observable inside the page/driver. If a callback is ever used, it must be a localhost listener, documented as such.
- Payloads must be **non-destructive**: no data exfiltration, no persistence writes, no credential access, no denial of service, no lateral movement.

### 5.4 Blast-radius limits

- Bounded requests per scan, bounded payloads per context, bounded wall-clock time, documented defaults.
- One browser context per run, discarded afterwards; no reused authenticated profile.
- Per-host concurrency 1–2. Timeouts on every network and browser operation.
- Clear failure over silent partial success: a timeout is `TIMEOUT`, not "no XSS".

---

## 6. Context model — FR-2

The tool MUST NOT spray a generic payload list. It must first learn **where** the input lands, then choose payloads for that syntax.

### 6.1 Required pipeline

1. **Probe** — send a unique, benign marker (e.g. `xsh<nonce>`) in the target parameter.
2. **Locate** — find **every** occurrence of the marker in the response.
3. **Classify** — determine the syntactic context around each occurrence using an HTML parser plus targeted checks (not a single regex over the whole body).
4. **Select** — choose payloads from the catalogue for that context and sub-context.
5. **Verify** — load the real URL in a headless browser, with a baseline navigation first, and watch for the proof signal.
6. **Record** — only on a positive execution signal, emit a finding with payload, context, and evidence.

### 6.2 The four mandated context families

| ID | Context | Typical landing spots | Detection signal | Payload strategy |
|----|---------|----------------------|------------------|------------------|
| **C1** | **HTML body** | Between tags, inside a container element | Marker sits in text node / element content | Tag-injection payload that fires automatically (`onerror`, `onload`); avoid relying on user interaction. |
| **C2** | **Attribute** | Quoted (`"`/`'`) or unquoted attribute value; `href`/`src`/`action`; `on*` handler | Marker appears inside a tag's attribute value | Match the quote style and break out; for URL-bearing attributes consider `javascript:`; if already inside an `on*` handler, inject an expression directly. |
| **C3** | **Inside `<script>`** | JS string literal, template literal, JSON blob, raw expression | Marker appears within a script element | Close the string/expression correctly, or break out of the script element where the parser allows; respect JS escaping. |
| **C4** | **URL** | Marker lands in `href`/`src`/`action`/redirect parameter or a URL built by the page | Marker appears in a URL position | `javascript:` scheme where the browser honors it, otherwise attribute breakout; note when execution requires a click. |

> **Ambiguity to flag (§17):** "URL" can mean *input reflected into a URL attribute* or *input used to build a URL/redirect*. Implement the interpretation that covers URL-bearing attributes and, where cheap, redirect sinks. State the chosen interpretation in the README.

### 6.3 Payload catalogue rules

- **Small and auditable.** Each payload has a comment: target context, why it works, expected proof signal. No 500-line dump.
- **Unique nonce per attempt**, embedded in the proof action, so a stale reflection or a cached page cannot masquerade as fresh execution.
- **Self-contained and minimal.** One payload proves one thing.
- **Auto-firing preferred.** Avoid payloads that need a click unless the context requires it; if interaction is required, the tool must say so in the finding.
- **No exfiltration, no persistence, no destructive DOM changes** beyond the proof marker.
- **Encoding-aware.** HTML entities, URL encoding, and JS escaping may neutralize a payload; the tool must test what the browser actually receives, not what was sent.

### 6.4 What "context-aware" does NOT mean here

It does not mean an LLM guesses payloads at runtime. The **agent** is the LLM driving the MCP tools. Inside the tool, context classification must be deterministic and testable. That is what makes the proof trustworthy.

---

## 7. Proof standard — FR-3 and FR-4

### 7.1 Valid proof (any one, recorded with artifacts)

- A **browser dialog** observed via the driver's dialog event, containing the run nonce.
- A **DOM marker** created by executed JavaScript (element id/text equal to the nonce) observed after load.
- A **console message** emitted by executed JavaScript containing the nonce.
- A **localhost-only** callback hit, if implemented, tied to the nonce.

### 7.2 Invalid proof (must never be reported as XSS)

- The payload string appears in the HTTP response body.
- The payload appears in the DOM because the **server** reflected it (must distinguish server-rendered markup from JS-created nodes).
- `alert(1)` text found by regex in source.
- A WAF block page, a 200 status, or a screenshot with no execution signal.
- "It looks injectable."

### 7.3 Evidence bundle (per finding)

```json
{
  "finding_id": "…",
  "run_id": "…",
  "url": "http://localhost:3000/…",
  "parameter": "…",
  "context": "html_body | attribute | script | url",
  "sub_context": "…",
  "payload": "…",
  "nonce": "…",
  "signal": "dialog | dom_marker | console | callback",
  "signal_detail": "…",
  "timestamp": "ISO-8601",
  "browser": "chromium/<version>",
  "screenshot": "evidence/<run_id>/<finding_id>.png",
  "reproduce": "documented command",
  "artifact_sha256": "…"
}
```

**Rule:** if the execution signal cannot be re-derived from the stored artifacts, the finding is not confirmed and must not be returned.

### 7.4 Result semantics

- Confirmed XSS only. No `"severity": "potential"`, no `"confidence": "maybe"`.
- If nothing is confirmed, return an explicit negative result: `confirmed: 0`, plus the contexts tested and a short reason per attempt. A negative result is a first-class outcome, not an error.
- Sort deterministically. Cap the list. Reference artifacts by path; never inline base64.

---

## 8. MCP interface rules — GR-1

- **Transport:** stdio first (maximum client compatibility). Any HTTP/SSE variant is `[O]` and must not replace stdio.
- **SDK:** use the official MCP SDK for the chosen language. Do not hand-roll the protocol.
- **Tool count: 2–3 maximum.** Suggested shape `[D]`:
  - `scan_xss(url, parameter)` — run probe → classify → inject → verify, return confirmed findings only.
  - `get_evidence(finding_id)` — fetch the stored evidence bundle for a finding.
  - `list_scope()` — return the allowlist so the agent knows what it may test before wasting a call.
- **Names are verb-first and literal.** No cute names.
- **Descriptions are for an LLM, not for humans.** Each tool description MUST state: purpose, when to call it, required inputs, output shape, what it refuses, and the time bound.
- **Strict input schema:** required fields, enums for context overrides, max lengths, no free-form blobs.
- **Structured output:** JSON with a documented schema; prefer MCP structured content where supported, plus a one-line human summary. Stable keys across runs.
- **Output budget:** short. No raw HTML, no full payload catalogue, no stack traces. Truncate with an explicit `truncated: true` and counts.
- **Typed errors, returned as tool results** (do not crash the server): `OUT_OF_SCOPE`, `INVALID_INPUT`, `TARGET_UNREACHABLE`, `NO_REFLECTION`, `NO_EXECUTION`, `TIMEOUT`, `BROWSER_ERROR`.
- **No interactive prompts, no TTY assumptions, no client-specific hacks.** Any compliant client must work.
- **Idempotent enough:** repeated scans of the same lab target do not corrupt state; evidence is namespaced by `run_id`.
- **Bounded execution:** documented default timeout; the agent must never hang.

**"Any MCP client" is a claim — test it.** Validate with at least two clients and document one copy-paste config.

---

## 9. Scope guard — what NOT to build

Every item below is **out of scope by the founder's brief**. Building any of them costs hours, adds review surface, and signals you did not read the task.

| Do not build | Why |
|--------------|-----|
| A crawler / spider / asset discovery | The input is a URL **and a parameter**. Crawling is a different product. |
| Authenticated / session-based scanning | Not requested; expands safety and complexity. |
| WAF-bypass research, payload fuzzing at scale | Proves nothing extra; the requirement is context + execution proof. |
| A web UI, dashboard, or chat app | The demo is an **agent** using MCP tools. A UI is a time sink. |
| A database, queue, worker fleet, multi-tenant SaaS | Local single-process tool. |
| An LLM inside the tool to "pick payloads" | Determinism is required for trust; the agent is the LLM. |
| A DalFox/XSStrike wrapper as the core | That reproduces the exact limitation the founder criticized. |
| Stored/blind XSS infrastructure, public callback servers | Out of scope and violates the "own sites only / no exfil" spirit. |
| Report generation, PDFs, Slack bots, CI integrations | Not requested. |
| Rewriting in Rust/Go for prestige, or microservices | Language is a means; the reviewer reads the code with you. |
| Docker Compose with five services | One-command local run beats "impressive" infrastructure. |

**Allowed and expected:** a small, well-factored codebase; a tiny test suite; a local lab target (Juice Shop/DVWA); a `Makefile`/`justfile` or equivalent; a short design doc if it clarifies tradeoffs.

**The one optional stretch** `[O]`, only if everything else is green and it costs < 1 hour: a small reproducible evaluation (TP/FP/FN against the local lab), because verifiability is the founder's stated value. Cut it before cutting the video or the README.

---

## 10. Repo, README, and code quality — DL-1 and GR-4

### 10.1 README required sections (order matters)

1. **What it is** — one paragraph: context-aware XSS hunter, MCP-driven, execution-verified.
2. **Why** — reflection ≠ execution; DalFox/XSStrike gap; what this does differently.
3. **Architecture** — the 6-stage pipeline in one diagram or numbered list.
4. **Setup** — exact commands for a fresh machine, including the local lab target. Verified from a clean clone.
5. **MCP client configuration** — copy-paste JSON for at least one real client.
6. **Tools exposed** — names, inputs, outputs, error codes, one example response (short).
7. **Safety** — allowlist behavior, refusal logging, lab-only defaults, payload non-destructiveness.
8. **Design choices** — mandatory. Justify: context classification approach, why a real browser, why the allowlist is checked at every hop, why no external callbacks, why output is shaped this way, what was deliberately not built.
9. **Limitations** — honest list (DOM XSS, stored XSS, auth flows, WAF evasion, DNS rebinding if unmitigated, browser coverage).
10. **Demo** — video link + the exact reproduction steps shown in it.
11. **Tests** — how to run, what they prove.
12. **License / ownership.**

### 10.2 Code quality (because of GR-4)

- Readable over clever. Small modules with one job each.
- Comments explain **why**, not what. No AI-slop comment spam.
- No dead code, no commented-out experiments, no unused dependencies.
- No secrets, no personal tokens, no absolute machine paths. Provide `.env.example`.
- Meaningful commit history — the reviewer may read it.
- **You must be able to explain every line on the call.** If you cannot, delete it and write it yourself.
- Minimum test coverage that mirrors the rules:
  - allowlist: bypass attempts (userinfo, subdomain, trailing dot, case, redirect, scheme);
  - context classifier: table-driven fixtures for all four contexts;
  - proof gate: a reflection-only fixture must yield zero findings.

---

## 11. Demo video spec — DL-2

**Hard constraints:** 2:00–3:00 runtime. Real session, not a mock. An **agent** (MCP client + model) drives the tool.

### Suggested storyboard (~2:40)

| Time | Beat | Must be visible |
|------|------|-----------------|
| 0:00–0:20 | Problem | "Scanners flag reflections that never execute." One sentence, no preamble. |
| 0:20–0:40 | Setup | MCP client with the server connected; `tools/list` output; `list_scope` shows lab-only hosts. |
| 0:40–1:10 | Agent acts | Agent picks the lab URL + parameter and calls `scan_xss` — show the actual tool call, not a summary. |
| 1:10–1:50 | Proof | Context selected, payload, browser signal (dialog/DOM marker with nonce), screenshot/evidence bundle. |
| 1:50–2:15 | Negative case | A reflected-but-not-executed parameter returns **0 confirmed**. This is the segment that proves the thesis. |
| 2:15–2:35 | Safety | Attempt against a non-allowlisted host → refusal + the log line on screen. |
| 2:35–2:50 | Close | One design tradeoff, one limitation, repo link. |

### Video rules

- Do not fake, re-record over failures, or hide error output. If something flakes, show the retry.
- Show real timestamps and the real terminal/browser; no static mockups.
- 1080p, legible font, clear audio, no music required.
- Host it somewhere reviewers can open without an account (unlisted YouTube, Loom, or similar).
- Put the link in the README **and** the submission email.
- If it runs long, cut setup narration — never cut the negative case or the safety refusal.

---

## 12. Pre-submission verification protocol

Run this in order. Do not skip because "it worked earlier."

1. **Fresh-clone test.** Clone into a new directory, follow the README literally, start the server. Fix every undocumented step.
2. **Client test.** Connect from two different MCP clients. Confirm `tools/list` and one real scan.
3. **AC-01.** Confirmed finding with payload + proof.
4. **AC-02.** Reflection-only parameter → 0 findings. Repeat twice to rule out flakiness.
5. **AC-03.** Out-of-scope host → refusal, no request sent, log line written.
6. **AC-04.** Redirect to out-of-scope → blocked and logged.
7. **AC-10 audit.** `git log -p` for public hostnames; check logs, evidence, and video frames.
8. **Claim audit.** Read the README line by line. Delete or measure every unverified adjective ("robust", "fast", "comprehensive", any percentage).
9. **Token audit.** Inspect a raw tool response. If it is over ~4 KB or contains HTML, cut it.
10. **Video audit.** Runtime between 2:00 and 3:00; audio audible; links clickable.
11. **Link audit.** Repo public (not 404, not private), video accessible in a private browser window, README renders.
12. **Email.** Reply in the same thread with both links and a 3-line summary. Send before the deadline, not at 23:58.

---

## 13. What will impress him — and what will sink this

Given his own words, the highest-signal evidence is not feature count.

### Impresses

1. **The negative case, on camera.** A payload that reflects but does not execute, correctly rejected. That is the entire thesis, demonstrated in 20 seconds.
2. **Safety demonstrated, not asserted.** A refusal and its log line, visible.
3. **Proof that is checkable.** Evidence bundle + reproduction command + hash. He can re-run it.
4. **Discipline.** Small repo, clean diff, 6–10 hours respected, no vanity features.
5. **Honest limitations.** Naming what the tool cannot do reads as senior; hiding it reads as junior.
6. **A code walkthrough you can actually survive.** Every design choice has a reason and a tradeoff.

### Sinks this

1. Reporting a reflection as XSS — the exact failure he named.
2. An allowlist that a redirect, subdomain, or `user@host` trick defeats.
3. A wall of JSON or raw HTML in the tool output.
4. Touching any public site, even "just one request" — disqualifying by the stated rule.
5. Invented metrics or a demo that hides a failure.
6. A crawler, dashboard, or platform that ignores the brief and blows the time budget.
7. A DalFox wrapper with no context model and no browser proof.

---

## 14. Commitments already made in the application (self-binding)

These were written in the application email. Contradicting them in the artifact damages credibility more than a missing feature.

- "Only report what you can verify." → The tool's core invariant.
- A **custom false-positive metric** on the scorecard, because "a detector that cries wolf is worthless." → If you include an evaluation, report **FP and FN**, not just TP.
- Reproducible training and evaluation so numbers are "checkable rather than claimed." → One command reproduces every number in the README.
- "Nothing reported before the grader agrees, passes and misses both on record." → Keep a ground-truth table for the lab; record false negatives too. Do not cherry-pick.

---

## 15. Time budget (6–10 h) `[D]`

| Block | Hours | Output |
|-------|-------|--------|
| MCP skeleton + config + allowlist + logging | 1.0 | Server starts, `tools/list`, scope denial works |
| Probe → context classifier → payload catalogue | 1.5 | Four contexts classified on fixtures |
| Headless verification + evidence capture | 2.0 | Real execution proof, artifacts stored |
| Tests (scope bypass, classifier, proof gate) | 1.0 | Three suites green |
| README + design choices + limitations | 1.0 | Reviewer-ready |
| Demo video (record + edit) | 1.0 | 2–3 min |
| Fresh-clone + claim audit + polish | 0.5 | Submission-ready |
| **Buffer** | **1–2** | Flake handling, retries |

**Cut order if time runs out:** evaluation harness → extra contexts/sub-contexts → pretty CLI → HTTP transport. **Never cut:** allowlist, proof gate, negative case in the video, README design choices.

---

## 16. Traceability matrix (fill in as you build)

| Req | Implemented in (file/function) | Verified by (test / demo timestamp) | Status |
|-----|-------------------------------|-------------------------------------|--------|
| FR-1 | | | ☐ |
| FR-2 | | | ☐ |
| FR-3 | | | ☐ |
| FR-4 | | | ☐ |
| FR-5 | | | ☐ |
| FR-6 | | | ☐ |
| FR-7 | | | ☐ |
| GR-1 | | | ☐ |
| GR-2 | | | ☐ |
| GR-3 | | | ☐ |
| GR-4 | | | ☐ |
| DL-1 | | | ☐ |
| DL-2 | | | ☐ |
| DL-3 | | | ☐ |
| AC-01 … AC-11 | | | ☐ |

---

## 17. Open questions to resolve (and mention on the call)

Decide conservatively, document the choice in the README, and be ready to defend it.

1. **"URL" context** — URL-bearing attribute vs. redirect sink. (Recommended: cover both where cheap; state the interpretation.)
2. **Allowlist granularity** — host only, host:port, or origin with path prefix. (Recommended: exact host:port; path is not a security boundary.)
3. **Wildcard subdomains** — support or forbid. (Recommended: forbid unless explicit in config.)
4. **DNS rebinding** — mitigate or disclose. (Recommended: disclose as a limitation if not mitigated; never overclaim.)
5. **Browser coverage** — Chromium only with a documented limitation is acceptable and honest.
6. **Authenticated lab targets** — out of scope; say so.
7. **Extension request** — only if genuinely needed; ask before the deadline, not after.

---

## 18. Submission checklist

- [ ] Public repo, MIT/Apache-2.0 licensed, README renders.
- [ ] README covers setup, tools, design choices, safety, limitations, demo reproduction.
- [ ] Fresh clone works with documented commands only.
- [ ] MCP server validated with two clients; one config snippet included.
- [ ] AC-01 true positive proven; AC-02 negative case proven; AC-03/AC-04 scope proven and logged.
- [ ] No public hostname anywhere in code, config, logs, evidence, history, or video.
- [ ] Video 2:00–3:00, real agent session, shows proof + negative case + refusal.
- [ ] Every README/video claim reproducible; no invented numbers.
- [ ] Traceability matrix (§16) filled.
- [ ] Email reply sent to Gokul in the same thread, before **Sun 8 Nov 2026, 23:59 IST**, with repo + video links and a 3-line summary (what it does, what is proven, known limits).

---

*This document captures the founder's brief exactly and derives only what is required to satisfy it without loopholes. If a future change cannot be traced to an ID here, it does not belong in this build.*
