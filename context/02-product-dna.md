# 02 — Product DNA: 12 Principles Worth Building Around

> These are not features. They are the operating logic behind BountyKai's product, extracted from
> its site and its public CVE-Bench evidence. Each one has a cheap way to show up in a 6–10 hour
> build — and a generic way to be ignored.

Read this before making design decisions. The build implications are proposals, not founder
requirements; `00-founder-requirements.md` remains the contract.

---

## N1. Scope is locked before the first request

> "Scope is set before it acts."
> "It does not add hosts, environments or preview URLs on its own."
> "A link it finds does not widen scope."

**Principle.** Scope is not a filter applied to results. It is a precondition for acting. It is
frozen at run start and cannot be mutated by anything discovered mid-run.

**Why it matters.** Every scanner that expands scope through a redirect, a link, or a discovered
subdomain has turned an authorized test into an unauthorized one. The company treats this as a
legal boundary, not a config option.

**Build implication.** Load the allowlist once at run start, treat it as immutable for the run, and
check it at every hop — parse, pre-request, redirect, pre-navigation, post-navigation. A discovered
URL is a *candidate*, never a *target*.

---

## N2. Fail closed, never fail open

> "If scope cannot be resolved, it fails closed and stops."
> "An out-of-scope action is rejected and recorded."

**Principle.** Ambiguity resolves to "no." A DNS failure, a malformed URL, an unparsable host, an
empty allowlist, a redirect with no `Location` — all stop the action. There is no best-effort
fallback.

**Why it matters.** Most scope bypasses are not clever attacks; they are error paths where the
check was skipped because something unexpected happened.

**Build implication.** One function decides scope. It has no `try/except` that returns `True`.
Unknown ⇒ `OUT_OF_SCOPE`, with a reason. The refusal path is tested as hard as the happy path.

---

## N3. A finding is a claim that survived replay

> "A claim is checked before it is called a finding."
> "replay: fresh session as account A · result: same response, so it is a finding"

**Principle.** Verification is not "we saw something once." It is **reproduction from a clean
state**. BountyKai's example replays in a fresh session before publishing.

**Why it matters.** A single observation can be a cached page, a stale dialog, a race, a fluke, or
an artifact of the test harness. Replay is what separates evidence from a screenshot.

**Build implication.** After the browser fires the execution signal, **open a new browser context
and do it again**. Two independent signals = confirmed. One signal = not confirmed. This is the
cheapest, most credible differentiator in the entire build.

---

## N4. Three outcomes, not two — and never silence

> "The report shows what was tried, what came back, what held and what blocked."
> "If a surface held, the report says so. If the run could not proceed, it says what blocked it.
> You do not get silence labeled 'nothing found.'"

**Principle.** A run ends in one of three states: **finding**, **held**, or **blocked**. "No
findings" is not a result; it is an admission that the report is incomplete.

**Why it matters.** Binary scanners lie by omission. A parameter that was never reached, a login
that was never available, a browser that crashed — all become "0 vulnerabilities" unless the
product distinguishes them.

**Build implication.** Keep three separate arrays in the result:

- `confirmed` — verified findings only (this is the only thing that may be called XSS).
- `tested_held` — contexts/payloads that were tried and did not execute, with the reason.
- `could_not_proceed` — stages that were blocked, with what is missing.

Never merge them. Never count `held` or `blocked` as findings. Never return a bare empty array with
no explanation.

---

## N5. Recovery is part of autonomy

> "It notices when a step fails, picks another way through, and tests again."
> "step failed: the form wants a fresh token → reload the form and try again · recovered"

**Principle.** Autonomy is not "run a fixed script unattended." It is noticing a failed step and
choosing a next action. BountyKai surfaces the recovery in the run narrative, not just the outcome.

**Why it matters.** Real apps expire sessions, rotate CSRF tokens, rate-limit, and redirect. A tool
that treats the first failure as "not vulnerable" produces false negatives at scale.

**Build implication.** Retry once on a *recoverable* condition (expired nonce/token, session reset,
transient navigation failure), then report `recovered: true` in the run. Do not retry blindly; a
timeout is a timeout, not a finding.

---

## N6. Continuity beats a snapshot

> "When the application changes, it tests what changed, starting from what it already confirmed.
> The next run is not a blank scan."

**Principle.** The unit of value is not a scan; it is a **baseline plus a diff**. Confirmed findings
become state that future runs build on.

**Why it matters.** A one-time test describes a version that is already gone. This is the company's
core market claim.

**Build implication.** Full continuity is out of scope for 6–10 hours — do not build a scheduler.
But make it *possible*: stable finding IDs derived from target + parameter + context + payload
family, a `run.json` manifest, and evidence namespaced by target and run. Say in the README what a
second run would reuse. That is product thinking without scope creep.

---

## N7. Evidence over assertion

> "Every finding includes evidence."
> "What was tried · what came back · evidence attached"
> "The proof is not 'trust our screenshots.'"

**Principle.** A result must be independently checkable. BountyKai ships the grader's verdict, the
request/response, and a replayable proof — not a claim with a severity label.

**Why it matters.** "Trust me" does not survive a security review. Evidence does.

**Build implication.** Every finding gets a folder: the payload, the context, the exact URL, the
signal, a screenshot, the replay steps, and a hash. `get_evidence` returns a pointer, not a wall of
JSON. If the evidence cannot be re-derived, the finding is not confirmed.

---

## N8. Publish the misses

> "Every task's grade, every time, every miss."
> "Nothing is cherry-picked."

**Principle.** Credibility comes from showing the denominator, including what failed. The CVE-Bench
evidence repo ships verdicts for passes **and** failures, plus an "Honest caveats" section.

**Why it matters.** A demo that only shows wins is a marketing asset. A demo that shows a
reflection-only payload being correctly rejected is a *product* demonstration.

**Build implication.** In the repo and the video, show at least one **held** result and one
**blocked** result. Include the run manifest with counts. If you run an evaluation, report FP and FN
— not just TP. Mirror the "Honest caveats" heading verbatim in spirit.

---

## N9. No numbers it has not earned

> "We leave out how it is built, and numbers it has not earned."
> "Every figure is the grader's, not ours."

**Principle.** Precision is a claim. If a metric was not measured by a neutral grader, it does not
belong in the README, the video, or the email.

**Why it matters.** The founder's entire public posture is calibrated claims. One invented "99%
accuracy" would undo the credibility of the whole submission.

**Build implication.** No invented percentages, no "zero false positives," no "100% coverage." If
you report `3/3 confirmed`, show the three cases and who graded them (the browser). Attribute every
number to its source.

---

## N10. Isolate every target

> "Each target has its own isolated store: captured sessions, traffic, screenshots, proof and
> findings stay with that one target."

**Principle.** Test data is sensitive by default. Isolation is per target, not per customer or per
run.

**Why it matters.** A session cookie or screenshot from one target must never appear in another
target's evidence, logs, or browser context.

**Build implication.** `evidence/<target-slug>/<run-id>/…`; a fresh browser context per run; no
reuse of cookies across hosts; no global evidence directory. State the isolation rule in the README.

---

## N11. Zero setup, agent-native

> "Nothing to connect."
> "You do not assemble the workflow."
> "The next action depends on what the application just did."

**Principle.** The agent is the orchestrator. The product exposes capabilities, not a workflow
builder. Setup is a URL and a scope.

**Why it matters.** Every required config file, database, or dashboard is a reason an agent cannot
pick the tool up cold.

**Build implication.** One command to start the MCP server; one small config file for scope; stdio
transport; no DB, no daemon, no UI. Tool descriptions must let an agent choose the next action
without a human reading docs.

---

## N12. Ask only for what is missing

> "It asks you only for something it does not have, such as access you have not granted."
> "No admin test account was added. Next: add an admin test account."

**Principle.** A blocked run should end with a **specific, actionable request**, not a generic
error.

**Why it matters.** It converts a dead end into a next step, and it makes the boundary legible:
the tool stopped because it lacked authorization, not because it failed.

**Build implication.** `could_not_proceed` entries carry `reason` and `needs` (e.g.
`reason: "login_required"`, `needs: "a test account for the target"`). No guessing, no credential
harvesting, no "trying anyway."

---

## What this DNA forbids

| Generic scanner behavior | Why it is off-DNA |
|--------------------------|-------------------|
| Reporting `alert(1)` in the response body as XSS | Violates N3 and the founder's core requirement |
| A `confidence: "high" \| "medium" \| "low"` field | Probabilities are not proof; N3/N9 |
| Returning `[]` when the target was unreachable | Silence labeled "nothing found"; N4 |
| Following a redirect and testing the new host | Scope expansion; N1/N2 |
| Auto-adding `localhost` when the allowlist is empty | Fail-open; N2 |
| A dashboard or web UI to show results | Not agent-native; N11, and out of brief |
| Reusing one browser profile across targets | Cross-target contamination; N10 |
| "We tested 500 payloads" with no proof | Unearned numbers; N9 |
| A demo that only shows a successful hit | Cherry-picking; N8 |

## Six places to signal the DNA (cheap, high-signal)

1. **Result schema** — three arrays, typed reasons (`N4`, `N12`).
2. **Scope log** — JSONL with `allow` / `refuse` and the hop that decided (`N1`, `N2`).
3. **Replay field** — `replay: {verified: true, session: "fresh"}` on every finding (`N3`).
4. **Evidence tree** — per-target, per-run, per-finding, with `replay.md` (`N7`, `N10`).
5. **README headings** — "What was verified", "What held", "What blocked", "Honest caveats" (`N8`).
6. **Demo** — one held case, one refusal, one confirmed hit, in that order of narrative tension
   (`N4`, `N8`).
