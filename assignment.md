# Assignment — Context-Aware XSS Hunter for AI Agents

> **This is the build brief, not the implementation spec.**
> It describes *what* to build and *why*, in product terms. The stack, libraries, file layout and
> algorithms are yours to choose — and to defend.
>
> **Precedence:** the founder's email (quoted in `context/00-founder-requirements.md`) is the
> contract. `context/00` is its detailed enforcement. This brief is the narrative entry point. If
> they disagree, the founder wins.
>
> **Deadline:** Sunday, 8 Nov 2026, 23:59 IST. **Effort:** aim for 6–10 hours.

---

## 1. What you are building

An **MCP server** that lets an AI agent test **one parameter on one authorized URL** for cross-site
scripting, and reports a finding **only when a real browser proves the payload executed**.

Most XSS tools stop when they see the payload reflected in the response. Reflection is not
execution. Your job is to close that gap:

1. Find where the input lands.
2. Send a payload built for *that* context.
3. Let a headless browser decide whether it actually ran.
4. Report the proof — or report honestly that it did not run.

That is the whole product. Everything else exists to make that loop trustworthy.

---

## 2. Who it is for

The primary user is an **AI agent**, not a human with a browser open.

That changes the interface:

- The agent needs to discover what it may test.
- It needs to call one capability with a URL and a parameter.
- It needs a short, structured answer it can reason about — not a wall of HTML.
- It needs to know what was proven, what was tried and held, and what blocked the run.
- It needs typed errors it can act on, not a stack trace.

A human may read the README or watch the demo, but the product is designed for the agent in the
loop. Optimize for that.

---

## 3. The run, end to end

This is the experience the build should deliver.

1. **The agent checks scope.** It confirms the target host is allowed before doing anything.
2. **The agent submits a URL and a parameter.** One target, one input.
3. **The tool probes.** It sends a benign, unique marker and locates every place it appears in the
   response.
4. **The tool classifies the context.** HTML body, attribute, inside a script, or a URL. It records
   the injection point, not just "reflected: yes."
5. **The tool chooses payloads for that context.** Not a generic list sprayed at everything.
6. **A headless browser loads the real URL.** It watches for an execution signal tied to a unique
   run nonce — a dialog, a DOM marker, a console event.
7. **The tool replays the winning payload in a fresh browser context.** Same payload, clean state.
   If it fires again, the finding is confirmed. If it does not, it is not published.
8. **The tool returns three things, kept separate:**
   - **Confirmed** — only verified XSS, each with the exact payload and proof of execution.
   - **Held** — what was tested and did not execute, with the reason.
   - **Blocked** — what could not be tested, with what is missing (for example, a login).
9. **Evidence is stored per target, per run, per finding.** Payload, context, signal, screenshot,
   replay steps. A reviewer can check the claim without trusting the tool.
10. **Out-of-scope hosts are refused before any request is sent**, and the refusal is recorded.

Steps 1–10 are the product. If a step is missing, the result is a scanner, not a hunter.

---

## 4. The non-negotiables

These come from the founder. They are not suggestions.

| The ask | In plain terms |
|---------|----------------|
| Take a URL and a parameter | One target, one input — not a crawler |
| Payloads chosen for where the input lands | HTML body, attribute, inside a script, URL |
| A headless browser confirms execution | Proof, not a reflection check |
| Return only confirmed XSS, with payload and proof | No "potential", "suspected" or "likely" findings |
| An MCP server any MCP client can use | Agent-native interface, short structured output |
| A scope allowlist | Refuse **and log** any host outside it |
| Test only your own lab | Juice Shop, DVWA, or your own app — never a public site |
| AI coding tools are fine | Use them, but you must be able to explain every line on a short call |
| A public repo, README and 2–3 minute video | The deliverable, not an afterthought |

**The one-sentence test:** if the payload is reflected but did not run, the tool must return **zero
confirmed findings** for that parameter. If it returns a finding, the product has failed.

---

## 5. What "done" looks like

A reviewer should be able to do all of this without asking you a question:

- **True positive.** On the local lab, a known-vulnerable parameter returns a finding with the exact
  payload and a browser-derived execution signal.
- **False positive rejected.** A parameter that reflects the payload but encodes or neutralizes it
  returns **zero confirmed findings**, with a clear reason it was held.
- **Scope refusal.** A non-allowlisted host is refused **before a request is sent**, and the refusal
  appears in an append-only log with a timestamp and a reason.
- **Redirect escape blocked.** An allowlisted host that redirects to a non-allowlisted host is
  stopped at the hop and logged.
- **Portable.** A fresh clone plus the documented commands starts the server and answers an MCP
  client.
- **Agent-sized output.** Every tool response is valid, bounded JSON. No raw HTML, no stack traces.
- **Demonstrable.** The 2–3 minute video shows an agent doing all of the above, including one case
  that is *not* a finding.

The last point matters. A demo that only shows a successful hit proves you can run a payload. A demo
that shows a reflection correctly rejected proves you built the product.

---

## 6. What not to build

Every item here is outside the brief. Building one costs hours, adds review surface, and signals
that the task was not read carefully.

- A crawler, spider, or asset-discovery engine.
- Authenticated or session-based scanning.
- WAF-bypass research or large-scale payload fuzzing.
- A web UI, dashboard, or chat interface.
- A database, queue, worker fleet, or multi-tenant service.
- An LLM inside the tool that "chooses" payloads at runtime.
- A DalFox/XSStrike wrapper with no context model and no browser proof.
- Stored/blind XSS infrastructure or public callback servers.
- PDF reports, Slack bots, CI integrations, or a scheduler.
- A rewrite in another language for prestige, or a microservice split.

If an idea is genuinely valuable but outside this list, write it under **"what I'd build next"** in
the README. Do not build it now.

---

## 7. Choices that are yours

The brief constrains the behavior, not the implementation. You choose:

- **Language and runtime** — whatever you can defend in a code walkthrough.
- **MCP SDK and transport** — stdio is the safe default for client compatibility.
- **Browser driver** — whichever gives reliable dialog/DOM instrumentation.
- **HTML parsing and context classification** — parser, heuristics, or a hybrid.
- **Test runner and fixtures.**
- **Config format and file layout.**
- **Tool names and count** — keep it small; two or three is plenty.
- **Lab target** — OWASP Juice Shop, DVWA, or your own deliberately vulnerable app.

Pick the smallest dependency set that makes the proof reliable. Boring, maintained libraries beat
clever, custom ones.

---

## 8. Research before you build

Do not rebuild what already exists. Before the plan is final, look at the current ecosystem and
decide what to **reuse, adapt, or avoid**.

At minimum, research:

| Area | What to look for |
|------|------------------|
| MCP | Official SDK patterns, stdio servers, structured tool output, client compatibility |
| XSS scanners | DalFox, XSStrike and similar — what they do well, where reflection-only reporting fails |
| Context classification | HTML parsing approaches, attribute/script/URL detection, existing libraries |
| Browser verification | Playwright/Puppeteer dialog and DOM instrumentation, fresh-context isolation |
| Payload design | Context-specific payload catalogues, nonce-based proof, non-destructive tests |
| Evidence | How security tools structure findings, replay artifacts, and proof bundles |
| Safety | URL normalization, allowlist enforcement, redirect handling, SSRF-style bypasses |

For each candidate, note: **what it does, its license, whether it is maintained, what to reuse, what
to avoid, and how it fits.** A short reuse map in the plan is more valuable than a long list of
links.

**Rules for reuse:** adapt, don't copy blindly. Respect licenses and attribution. Keep the
dependency surface small. If a library does one thing well, use it; if it drags in a framework you
do not need, do not.

---

## 9. Recommended product touches (not founder requirements)

These come from the company context in `context/`. They are optional, cheap, and make the result
feel like a product rather than a script. The plan should decide whether to include them.

1. **Three outcomes, not two.** Keep `confirmed`, `tested_held`, and `could_not_proceed` separate.
   The last two are run status, never findings. It is the difference between "nothing found" and
   "here is what I could and could not test."
2. **Replay before publish.** After the execution signal, run the payload again in a fresh browser
   context. Two signals = confirmed. One = not confirmed.
3. **Evidence tree.** `evidence/<target>/<run>/findings/<id>/` with the finding, screenshot, and
   replay steps. Per-target isolation.
4. **A `needs` field on blocked results.** Name the missing input ("a test account"), not just
   "error".
5. **Honest caveats in the README.** State what the tool cannot do before the reviewer finds it.

If you add these, they must not break the founder's rule: **the confirmed list contains only
confirmed XSS.** Do not merge the arrays, and do not count held/blocked as findings.

---

## 10. Deliverables

- **Public GitHub repo** (the code stays yours) with a README covering:
  - setup, from a fresh clone;
  - the MCP tools exposed, with inputs and outputs;
  - your design choices and the tradeoffs behind them;
  - safety and scope behavior;
  - honest limitations.
- **2–3 minute demo video** of a real AI agent using the tool, including one non-finding.
- **Both links replied to the founder's email** before the deadline.

---

## 11. How to work

1. **Read the context pack** (`context/00`–`05`) before proposing anything.
2. **Research the ecosystem** (§8) and write a reuse map.
3. **Write the plan first.** Architecture, tool surface, context model, scope enforcement, test
   matrix, milestones, risks, cut list.
4. **Get the plan approved** before writing production code, if a human is in the loop.
5. **Build in vertical slices.** Each slice should be demonstrable: scope refusal, then reflection
   probe, then context classification, then browser proof, then replay, then evidence.
6. **Keep a decision log.** Every choice that is not obvious gets one line: what you chose, why, and
   what you gave up.
7. **Stop at 10 hours.** Cut optional features before cutting the README, the negative case, or the
   demo.

---

## 12. Decisions the plan must resolve

Do not ask the human these questions unless you are genuinely blocked. Make a conservative call,
write it down, and move on.

- Which lab target and which known-vulnerable route/parameter will anchor the demo?
- How will context be classified — parser, regex, or hybrid — and how will multiple reflection
  points be handled?
- What payload families map to each context and sub-context?
- What counts as execution proof, and how will false positives (cached dialogs, stale pages) be
  excluded?
- How will the fresh-context replay work without introducing flakiness?
- Where exactly are the scope checks, including redirects and browser-level requests?
- What is the minimal evidence bundle that a reviewer can re-derive?
- What is the tool surface — names, inputs, outputs, error codes — and what is the output budget?
- What is explicitly cut to stay inside 6–10 hours?

---

## 13. Where to read more

| File | Why |
|------|-----|
| `context/00-founder-requirements.md` | The full contract: every rule, acceptance criterion and non-goal |
| `context/01-company-context.md` | What BountyKai is and how its product behaves |
| `context/02-product-dna.md` | 12 principles behind the product |
| `context/03-build-implications.md` | Concrete schema, verification ladder, evidence layout |
| `context/04-voice-and-demo.md` | Vocabulary, README narrative, demo script, email tone |
| `context/05-sources-and-unknowns.md` | Quotes, sources, and what not to assume |
| `AGENTS.md` | The short enforcement summary |

**The bar:** a reviewer should finish the README, watch the video, and think *"this person
understood what we are building, not just what we asked for."*
