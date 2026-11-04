# AGENTS.md — binding rules for this repo

**Read `assignment.md` first, then `context/00-founder-requirements.md` in full.** The first is the
product-level brief; the second is the canonical contract derived from the founder's brief. This
file is only the enforcement summary.

## Reading order

1. `assignment.md` — what to build and why, in product terms.
2. `context/00-founder-requirements.md` — the contract: every founder rule, acceptance criterion and non-goal.
3. `context/01-company-context.md` — what BountyKai is and how its product behaves.
4. `context/02-product-dna.md` — 12 principles to build around.
5. `context/03-build-implications.md` — concrete schema, verification ladder, evidence layout.
6. `context/04-voice-and-demo.md` — vocabulary, README narrative, demo script, email tone.
7. `context/05-sources-and-unknowns.md` — quotes, URLs, and what not to assume.

`context/README.md` is the index. If anything conflicts with the founder's words quoted in `00`, the
founder's words win.

## Non-negotiable invariants

1. **Reflection is not a finding.** Report XSS only after a headless browser proves execution. No
   "potential", "suspected", or "reflected" items in results.
2. **Context before payload.** Probe → locate → classify (HTML body / attribute / script / URL) →
   select payload → verify. Never spray a generic payload list.
3. **Proof or silence.** Every finding carries the payload, the execution signal, and a stored
   evidence artifact. If it cannot be re-derived from artifacts, it is not confirmed.
4. **Deny-by-default allowlist.** Exact normalized host match. Re-check every redirect hop and at
   browser navigation time. Refuse **and** append a JSONL log entry. No request may reach a
   non-allowlisted host. Fail closed on ambiguity.
5. **Lab only.** Local Juice Shop / DVWA / own app. Never a public site — not even one request. No
   outbound third-party calls, no external proof callbacks, no destructive payloads.
6. **MCP for agents.** stdio transport, official SDK, 2–3 tools, strict input schemas, bounded
   structured JSON output, typed error codes, no raw HTML dumps, no crashes.
7. **Scope is the task.** URL + parameter in, confirmed XSS out. No crawler, dashboard, UI,
   database, auth scanning, WAF fuzzing, or DalFox wrapper. See `00` §9 before adding any feature.
8. **Stay in budget.** 6–10 hours. Small, readable, explainable code — the author must survive a
   line-by-line walkthrough.

## Definition of done

- AC-01 true positive with payload + proof.
- AC-02 reflection-only input returns **zero** findings (the key test).
- AC-03 out-of-scope host refused, no request sent, logged.
- AC-04 redirect to out-of-scope blocked and logged.
- README: setup, tools, design choices, safety, limitations.
- Demo video 2:00–3:00 of a real agent using it.
- Every claim reproducible by a documented command. No invented numbers.
- Traceability matrix (`00` §16) filled.

## Product-DNA additions (not founder requirements, but high-signal)

- **Tri-state result:** `confirmed` / `tested_held` / `could_not_proceed`. Never merge, never count the
  last two as findings.
- **Replay before publish:** after the execution signal, verify again in a fresh browser context.
- **Evidence tree:** `evidence/<target>/<run>/findings/<id>/` with `finding.json`, `proof.png`,
  `replay.md`. Per-target isolation.
- **`needs` on blocked entries:** name the missing input, not just "error".
- **Honest caveats:** state what the tool cannot do before the reviewer finds it.

## Forbidden shortcuts

- Do not claim "any MCP client" without testing at least two.
- Do not hide a failing run in the demo.
- Do not add features that cannot be traced to `FR-*`, `GR-*`, or `DL-*`.
- Do not commit secrets, absolute paths, or evidence from non-lab hosts.
- Do not rewrite the stack for prestige. Readability and proof beat novelty.
- Do not imply affiliation with BountyKai or copy its marketing copy.

## Where to look

| Question | Section |
|----------|---------|
| What exactly did the founder ask? | `00` §2, §3 |
| Is this done? | `00` §4 |
| Allowlist / logging details | `00` §5 |
| How should context detection work? | `00` §6 |
| What counts as proof? | `00` §7 |
| MCP output rules | `00` §8 |
| Am I overbuilding? | `00` §9 |
| README requirements | `00` §10 |
| Video plan | `00` §11 |
| Pre-submit checks | `00` §12 |
| Time allocation | `00` §15 |
| Company context | `context/01-company-context.md` |
| Product principles | `context/02-product-dna.md` |
| Concrete schema / evidence layout | `context/03-build-implications.md` |
| Voice / demo script / email | `context/04-voice-and-demo.md` |
| Quotes and unknowns | `context/05-sources-and-unknowns.md` |
