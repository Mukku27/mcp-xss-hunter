# 03 — Build Implications: Making the Hunter Feel Like BountyKai

> This file translates company DNA into concrete decisions. It is **guidance**, not a second
> contract. If anything here conflicts with `00-founder-requirements.md`, the contract wins.
> Everything below fits inside the 6–10 hour budget.

## 1. The framing decision

Most submissions will build "an MCP server that scans for XSS." That is the generic read of the
task. The BountyKai read is:

> **A scoped, reversible probe that returns a verified finding only when a browser has executed the
> payload twice — once to observe, once to replay — and reports what held and what blocked.**

Same features as the brief. Different product center of gravity. This framing should be visible in
the README's first paragraph, the tool descriptions, the result schema, and the demo.

**Do not** write "BountyKai-style" all over the repo or imply affiliation. Show it through behavior.

---

## 2. Principle → decision map

| Company principle | Concrete build decision | Cost | Priority |
|-------------------|-------------------------|------|----------|
| N1 scope locked | Immutable allowlist loaded at run start; check at 5 points | S | **Must** |
| N2 fail closed | One scope function; unknown ⇒ refuse; no fallback host | S | **Must** |
| N3 replay proves | Re-run the winning payload in a **fresh browser context** | M | **High** |
| N4 tri-state | `confirmed` / `tested_held` / `could_not_proceed` arrays | S | **High** |
| N5 recovery | One retry on expired token/session, marked `recovered` | M | Optional |
| N6 continuity | Stable finding IDs + `run.json`; document retest path | S | **High** |
| N7 evidence | Per-finding folder + `replay.md` + hash | S | **Must** |
| N8 publish misses | Demo shows a held case and a refusal | S | **High** |
| N9 earned numbers | No invented metrics; counts show denominators | S | **Must** |
| N10 isolation | `evidence/<target>/<run>/`; fresh context per run | S | **Must** |
| N11 zero setup | stdio + one config file + one command | S | **Must** |
| N12 ask for missing | `needs` field on blocked entries | S | **High** |

S ≈ under 30 min · M ≈ 1–2 h · Priority reflects value per hour, not the founder's wording.

---

## 3. The verification ladder

Replace the binary "reflected / not reflected" with five rungs. A finding only reaches the top.

| Rung | Question | Evidence produced | If it fails |
|------|----------|-------------------|-------------|
| **R1 Reflection** | Does the marker appear in the response? | marker, byte offset, response hash | `tested_held` (not reflected) |
| **R2 Context** | Where exactly does it land? | context + sub-context + surrounding snippet | `tested_held` (unclassified) |
| **R3 Execution** | Did the browser fire the proof signal? | signal type, nonce, screenshot | `tested_held` (encoded / stripped / CSP / no sink) |
| **R4 Replay** | Does it fire again from a **fresh context**? | second signal, second screenshot | `could_not_proceed` (non-deterministic) |
| **R5 Evidence** | Is the bundle complete and re-derivable? | artifacts + sha256 + `replay.md` | do not publish |

**Rules.**

- R1–R2 are *diagnostics*, never findings. Do not return them as XSS.
- R3 alone is a **candidate**. The demo may show it, but the result must not count it as confirmed.
- R4 is the BountyKai move: "fresh session, same result, so it is a finding."
- A failure at R4 must **downgrade**, never upgrade. Flaky ≠ confirmed.
- R5 is a publish gate, not a formatting step.

**Why replay matters here.** XSS proofs are unusually easy to fake accidentally: a cached page, a
dialog left open by a previous navigation, a payload reflected into the DOM but never executed, a
browser extension. A fresh context with a new nonce eliminates most of that class of self-deception.

---

## 4. Scope enforcement — six checkpoints

The allowlist is the company's spine (`01` §6). Enforce it at every transition, not just at input.

| # | Checkpoint | What it catches |
|---|------------|-----------------|
| **S0** | Normalize and parse the input URL | userinfo trick, casing, trailing dot, IDN, non-http scheme |
| **S1** | Before the probe request | direct out-of-scope target |
| **S2** | Before following each redirect | 302 to a host that is not allowed |
| **S3** | Before `page.goto()` | a URL built from a redirect or a discovered link |
| **S4** | After navigation completes | meta refresh / JS redirect to an out-of-scope host |
| **S5** | Every browser request — navigation and subresources (recommended) | a browser-followed redirect or a third-party asset escaping the check |

**S5 note.** A Playwright route handler can abort any request whose host is not allowlisted —
**including the document request for a redirect target**, not just images and scripts. That is what
makes "no request reached an out-of-scope host" true at the browser layer, not only at the HTTP
client layer. It can break pages that depend on external CDNs and cause false negatives; recommended
default is **strict**, documented, with the local lab as the intended target. If you make it
configurable, the default must still be strict.

**Fail-closed defaults.**

- Empty/missing allowlist ⇒ refuse everything.
- Unresolvable host, malformed URL, missing `Location`, browser crash ⇒ refuse/stop with a reason.
- No implicit `localhost`; ship an explicit default config.
- A refused action still writes a log line, even when the tool call returns an error.

---

## 5. The result contract — three arrays, no ambiguity

Keep `confirmed` pure. The other two arrays are **run status**, not findings. This is what makes the
tool honest without violating "return only confirmed XSS."

```json
{
  "run_id": "r-20261104T131500Z-a1b2",
  "target": {
    "url": "http://localhost:3000/#/search?q=test",
    "host": "localhost:3000",
    "scope": "allowed"
  },
  "parameter": "q",
  "confirmed": [
    {
      "finding_id": "f-9f2c1e",
      "context": "html_body",
      "sub_context": "textarea_breakout",
      "payload": "<img src=x onerror=alert('xsh-9f2c1e')>",
      "signal": "dialog",
      "signal_detail": "xsh-9f2c1e",
      "replay": { "verified": true, "session": "fresh", "nonce": "xsh-9f2c1e" },
      "evidence": "evidence/localhost_3000/r-20261104T131500Z-a1b2/f-9f2c1e/",
      "reproduce": "xss-hunter evidence --run r-20261104T131500Z-a1b2 --finding f-9f2c1e"
    }
  ],
  "tested_held": [
    {
      "context": "attribute",
      "reason": "value_html_encoded",
      "payloads_tried": 3,
      "detail": "quotes and angle brackets encoded; no breakout"
    }
  ],
  "could_not_proceed": [
    {
      "stage": "verification",
      "reason": "login_required",
      "needs": "a test account for the target"
    }
  ],
  "limits": {
    "duration_ms": 8421,
    "http_requests": 14,
    "payloads_sent": 6,
    "browser_contexts": 2
  }
}
```

**Contract rules.**

- `confirmed` contains **only** R4/R5 findings. No severity, no confidence, no "potential".
- `tested_held` must explain *why* it held, not just list payloads.
- `could_not_proceed` must name what is missing; `needs` is a request, not a guess.
- Counts in `limits` are measured, not estimated.
- `scope_refusals` may also appear as a short array; the full record lives in the JSONL log.
- Stable key order and stable IDs make output diffable across runs.
- Cap the arrays (for example 10 confirmed / 20 held / 5 blocked) and add `truncated: true` with
  totals when you do. The evidence tree holds the detail; the tool response stays agent-sized.

**What this buys.** The agent driving the tool can decide what to do next: retry, ask for an account,
try another parameter, or report a confirmed bug. That is what "made for an agent to read" means in
practice.

---

## 6. Evidence layout

Mirror the shape of BountyKai's public CVE-Bench evidence repo, in miniature.

```
evidence/
  localhost_3000/                      # target-slug → isolation boundary (N10)
    r-20261104T131500Z-a1b2/
      run.json                         # target, scope decision, counts, timings, tool version
      scope.jsonl                      # allow / refuse, with the checkpoint that decided
      findings/
        f-9f2c1e/
          finding.json                 # payload, context, signal, replay, hashes
          proof.png                    # screenshot at the moment of proof
          replay.md                    # exact steps + expected signal
      held.json                        # tested, did not execute, with reasons
      blocked.json                     # could not proceed, with needs
```

**Rules.**

- `replay.md` is written for a human reviewer: URL, payload, what to expect, how to re-run.
- `run.json` includes the allowlist snapshot, so a reviewer can prove scope was locked.
- Hash artifacts; a finding without a hash is not publishable.
- No cookies, auth headers, or full response bodies in logs.
- Commit a small, sanitized demo run so the reviewer can inspect the shape without running anything.

This is the single strongest "product thinker" signal in the repo: it shows you understand that a
finding is a *record*, not a JSON object.

---

## 7. The continuity nod (cheap, do not overbuild)

You are not building a scheduler. You are making a second run *possible*.

- **Stable finding ID:** `hash(host + path + parameter + context + payload_family)`, truncated.
  Not the exact payload — families survive payload edits.
- **`run.json`:** target, scope snapshot, tool version, counts, start/end, `previous_run_id` if any.
- **README line:** "A second run can reuse `finding_id` to check whether a confirmed finding still
  reproduces. Scheduling/diffing is deliberately out of scope for this build."

That paragraph is worth more than a half-built diff engine. It shows you know where the product
goes without pretending you built it.

---

## 8. Blocked-state taxonomy

Use typed reasons so the agent can act on them. Proposed set:

| `reason` | Meaning | `needs` example |
|----------|---------|-----------------|
| `login_required` | Target redirected to auth | a test account |
| `account_locked` | Test identity cannot proceed | an unlocked account |
| `param_not_reflected` | Marker absent from response | a different parameter |
| `no_execution_sink` | Reflected but no executable sink found | manual review |
| `waf_blocked` | Request blocked by a WAF | allowlisting the test source |
| `browser_unavailable` | Headless browser failed to start | environment fix |
| `timeout` | Step exceeded its budget | a higher limit |
| `scope_unresolved` | Host could not be normalized/resolved | a valid in-scope URL |

**Do not** collapse these into `"error": "failed"`. The whole point of N12 is that the next action is
legible.

---

## 9. README narrative (BountyKai-shaped)

Follow the founder's required content, but order it the way this company argues.

1. **Title + thesis.** "A scanner reports what it saw. This reports what it proved."
2. **The gap.** Two sentences on DalFox/XSStrike: manual, reflection-heavy, no execution proof.
3. **What this does.** URL + parameter → context → payload → browser → replay → verified finding.
4. **What it refuses to do.** Crawl, authenticate, widen scope, report unverified results.
5. **Architecture.** The 6-stage pipeline, one diagram or numbered list.
6. **Setup.** Fresh-clone commands.
7. **MCP client config.** Copy-paste.
8. **Tools.** Names, inputs, outputs, error codes.
9. **Result contract.** The three arrays, briefly.
10. **Safety model.** Six checkpoints, fail-closed, JSONL refusals, network fence, lab-only defaults.
11. **Design choices.** Why context-first, why a real browser, why replay, why tri-state, why no
    external callbacks, what was deliberately not built.
12. **What was verified / what held / what blocked.** The actual demo run, including the negative.
13. **Honest caveats.** Browser coverage, DOM/stored XSS limits, DNS rebinding, flakiness.
14. **Reproduce.** Exact commands for the demo.
15. **What I'd build next.** Continuity/retest, stored XSS with two identities, authenticated runs.
16. **License.**

**Do not** open with "This is an MCP server for XSS." Open with the verification thesis. The MCP
part is how it is delivered, not why it matters.

---

## 10. Demo narrative (same 2–3 minutes, different emphasis)

Use the storyboard in `00` §11, but narrate it with the company's rhythm:

| Beat | Line (paraphrase, do not copy marketing copy) |
|------|-----------------------------------------------|
| Problem | "Most scanners stop at reflection. Reflection is not execution." |
| Scope | "The scope is locked before the first request. This host is not in it." |
| Action | "The agent gives it a URL and a parameter; the tool decides the context." |
| Proof | "The browser fired the payload. Now a fresh context, same payload — it fires again." |
| Held | "This parameter reflects, but the encoding holds. That is a held result, not a finding." |
| Refusal | "Out-of-scope host: refused, and logged. No request left the tool." |
| Close | "What was proven, what held, what blocked. No silence labeled 'nothing found.'" |

**Order matters.** Show the confirmed hit before the held case? No — show the hit, then the held
case, then the refusal. The held case is the proof of the thesis; the refusal is the proof of
discipline. End on discipline.

---

## 11. Differentiators ranked by value per hour

| Rank | Move | Time | Why it lands |
|------|------|------|--------------|
| 1 | Tri-state result contract | 30 min | Instantly distinguishes the tool from every binary scanner |
| 2 | Fresh-context replay | 1–2 h | Turns "proof" into "reproducible proof" |
| 3 | Six-checkpoint scope gate + JSONL | already required | Makes the allowlist auditable, not just present |
| 4 | `needs` on blocked entries | 15 min | Shows product empathy for the agent operator |
| 5 | Evidence tree + `replay.md` | 30 min | Mirrors BountyKai's public evidence repo |
| 6 | Stable IDs + `run.json` | 20 min | Makes continuity a stated next step, not a fantasy |
| 7 | Honest caveats section | 20 min | Preempts the reviewer's objections |
| 8 | Voice pass over README/tool text | 30 min | Removes generic AI-marketing tone |
| 9 | Tiny FP/FN eval on the lab | 1–2 h | Mirrors the applicant's own false-positive metric; **optional** |
| 10 | Retest/diff mode | 4+ h | Real continuity — **do not build** in this budget |

If you only do the top five, the submission already reads like it was built by someone who studied
the company.

---

## 12. What not to borrow

| Don't borrow | Why |
|--------------|-----|
| The sign-in/account engine | Out of brief; auth is a separate product surface |
| App mapping / crawling | Out of brief; the input is one URL and one parameter |
| The scheduler / change detection | Out of budget; describe it as future work |
| Slack/Teams alerts | Not requested; adds a dependency with no demo value |
| Pricing/plan language | Irrelevant to a build task |
| A database | One command, no setup; files are enough |
| The full vulnerability taxonomy | You are building XSS, not a mini-BountyKai |
| CVE-Bench claims | Not your result; cite theirs only with attribution, if at all |
| Their marketing copy verbatim | Echo the vocabulary, not the brochure |

---

## 13. "Nuanced" checklist

Before you call it done, every line should be true:

- [ ] The README's first paragraph is about **proof**, not about MCP.
- [ ] A reflection-only payload is explicitly reported as **held**, with a reason.
- [ ] A blocked run says **what is missing**, not just "error".
- [ ] Every finding has a **second, fresh-context** signal.
- [ ] The scope log shows the **checkpoint** that allowed or refused each action.
- [ ] The evidence tree is **per target** and includes a human-readable `replay.md`.
- [ ] No number appears without a denominator and a grader.
- [ ] The demo shows a **failure** (held or blocked) without hiding it.
- [ ] The README has an **Honest caveats** section that names what the tool cannot do.
- [ ] The tool text uses **finding / held / blocked / scope** — not "potential" or "confidence".
- [ ] Setup is one command and one config file; no DB, no UI, no daemon.
- [ ] A "what I'd build next" paragraph names continuity and stored XSS, and explains why they were
      out of scope for 6–10 hours.
