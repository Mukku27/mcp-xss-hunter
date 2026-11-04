# 04 — Voice, README, Demo, Email

> BountyKai's copy is unusually precise: short sentences, concrete nouns, no hype, and a visible
> distinction between what was tested, what held, and what blocked. The build should sound like it
> came from the same engineering culture — without copying the brochure.

## 1. Vocabulary

| Use | Avoid | Why |
|-----|-------|-----|
| **run**, **test**, **probe** | "scan" as the product noun | A run has a scope, a start, an end, and a record |
| **verified finding** | "vulnerability", "bug", "issue" (for unconfirmed) | A finding is a claim that survived replay |
| **proof of execution** | "proof of concept" (for XSS) | The proof is that the payload ran, not that a PoC exists |
| **tested held** | "not vulnerable", "clean", "passed" | "Held" means the surface resisted *this* attempt |
| **could not proceed** / **blocked** | "error", "failed", "skipped" | Names the stage and what is missing |
| **out of scope** / **refused** | "filtered", "disallowed", "ignored" | Scope is a decision, not a filter |
| **scope is locked** | "scope configured" | Locked before the first request |
| **replay** | "re-check", "retest" (for the same proof) | A fresh context, same payload, same signal |
| **evidence** | "screenshot" (as the whole proof) | A bundle: payload, signal, context, replay, hash |
| **authorized target** | "target" alone | Authorization is the precondition |
| **needs** | "next steps" | A specific missing input, not a to-do list |

**Words that should not appear in the repo at all:** *potential, suspected, likely, confidence,
severity: high/medium/low, AI-powered, cutting-edge, robust, comprehensive, seamless, revolutionary,
100%, zero false positives, military-grade.*

If you catch yourself writing "robust," delete the sentence and state the actual behavior.

## 2. Sentence patterns

BountyKai's copy uses a few reliable shapes. Reuse the shapes, not the lines.

**Contrast, then consequence**
> "A scanner reports what it saw. This reports what it proved."

**State the boundary as an action**
> "Out-of-scope hosts are refused before a request is sent, and the refusal is recorded."

**Distinguish the three outcomes**
> "If the payload executes, it is a finding. If the encoding holds, it is a held result. If the
> browser cannot reach the page, the run is blocked and says what it needs."

**Admit the limit before the reviewer finds it**
> "This build covers reflected and DOM-style execution on a single parameter. Stored XSS needs a
> second identity and is out of scope."

**No adjectives where a number or a behavior will do**
> Bad: "Extremely fast, highly accurate detection."
> Good: "Two browser contexts per finding, a 30-second default budget, zero findings without a
> replay."

## 3. README opening (draft — rewrite in your own words, keep the shape)

> Most XSS scanners stop when a payload shows up in the response. That is a reflection, not an
> execution. This MCP server takes one URL and one parameter, works out where the input lands —
> HTML body, attribute, inside a script, or a URL — sends a payload built for that context, and lets
> a headless browser decide. A result is published only if the payload executes twice: once to
> observe, once in a fresh context to replay. Everything else is reported as held or blocked, with a
> reason. Out-of-scope hosts are refused before a request is sent, and every refusal is logged.

Why it works: four sentences, one idea each, no hype, and the reader already knows the product.

**Optional subtitle**, echoing their "One application. One scope. One report." structure without
copying it:

> "One URL. One parameter. Proof, held, or blocked."

**Do not** open with "This project is an MCP server built with Python/TypeScript that…" — the
transport is not the point.

## 4. MCP tool descriptions (agent-facing copy)

Tool descriptions are prompts. Write them like a contract, not a brochure.

```text
scan_xss(url, parameter)
  Test one parameter on one authorized URL. Probes the reflection, classifies the injection
  context, sends payloads built for that context, and verifies execution in a headless browser
  with a fresh-context replay. Returns confirmed findings only, plus tested-held and blocked
  results. Refuses hosts outside the allowlist before sending a request, and records the refusal.
  Default budget: 30 seconds.

get_evidence(finding_id)
  Return the evidence bundle for a confirmed finding: payload, context, execution signal,
  replay result, screenshot path, and reproduction steps. Refuses unknown IDs.

list_scope()
  Return the hosts this server is allowed to test. Call this before scan_xss if you are unsure
  whether a target is in scope.
```

**Rules for tool text:** state what it does, what it returns, what it refuses, and how long it
takes. No exclamation marks, no "powerful", no "advanced".

## 5. Demo narration (2:20–2:50)

Use the storyboard in `00` §11. These lines are timing-ready; paraphrase them so they sound like you.

| Time | On screen | Say (approximately) |
|------|-----------|---------------------|
| 0:00 | Title / terminal | "Most scanners stop at reflection. Reflection is not execution." |
| 0:12 | MCP client, `tools/list` | "This is an MCP server, so the agent drives it directly — no scripts, no UI." |
| 0:25 | `list_scope` | "The scope is locked before the first request. Only this lab host is allowed." |
| 0:35 | Agent calls `scan_xss` | "One URL, one parameter. The tool probes it and classifies where the input lands." |
| 0:55 | Context + payload in output | "It landed in an HTML body, so the payload is built for that context — not sprayed from a list." |
| 1:10 | Browser dialog / DOM marker | "The browser fired it. That is the execution signal, with a run nonce." |
| 1:25 | Fresh context replay | "Now a fresh browser context, same payload. It fires again — so it is a finding, not a fluke." |
| 1:40 | Held case | "This parameter reflects, but the encoding holds. That is a held result, not a finding." |
| 2:00 | Out-of-scope refusal + log | "Out of scope: refused before the request, and recorded. The agent can see exactly why." |
| 2:20 | Evidence bundle | "Payload, context, signal, replay, screenshot, hash. Everything needed to check the claim." |
| 2:35 | Repo | "What was proven, what held, what blocked. No silence labeled 'nothing found.'" |

**Do not** narrate every click. Silence while the browser works is fine; cut dead air, not failures.

## 6. Submission email (draft)

Keep it to the shape of the founder's own writing: short, specific, no preamble.

```text
Subject: Re: AI Engineer — build task

Hi Gokul,

Repo:  <link>
Video: <link> (2:4x)

It's an MCP server that takes a URL and a parameter, classifies the injection context, and reports
XSS only after a headless browser executes the payload — twice, the second time in a fresh context.
Out-of-scope hosts are refused before the request and logged.

What's proven: a confirmed finding on the local lab, a reflection-only parameter correctly held, and
an out-of-scope refusal. What it doesn't do: stored XSS, authenticated flows, or crawling — noted in
the README's caveats.

Happy to walk through the code whenever works for you.

Best,
Mukesh
```

**Rules.** No "I hope you like it." No feature list longer than three lines. No claim you cannot
show in the video. One caveat is stronger than five adjectives.

## 7. Tone cautions

1. **Do not name-drop the company constantly.** One precise alignment in the README is enough. A
   repo that says "BountyKai" in every heading reads as flattery, not fit.
2. **Do not claim affiliation.** This is an application build task. Say "built for the BountyKai
   build task" at most once, in the README intro or the email.
3. **Do not quote their marketing back at them.** If you use a phrase like "what held and what
   blocked," make it your own sentence.
4. **Do not call it production-ready.** It is a scoped lab tool with documented limits. Say that.
5. **Do not apologize for the scope.** "Stored XSS is out of scope" is a decision, not a confession.
6. **Prefer the concrete failure to the polished success.** A shown held case is more persuasive than
   a montage of green checkmarks.

## 8. The voice test

Read the README aloud. If a sentence could appear on any AI security startup's landing page, rewrite
it until it contains a specific behavior, a number, or a boundary.
