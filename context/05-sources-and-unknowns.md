# 05 — Sources, Quote Bank, and Unknowns

> Everything in this pack that describes BountyKai comes from the company's public site or the
> founder's email. Nothing about the company is inferred silently. This file keeps the receipts.

## 1. Sources

| Source | URL | Used for | Captured |
|--------|-----|----------|----------|
| Homepage | https://bountykai.com/ | Positioning, run model, trust rules, tri-state reporting | 2026-11-04 |
| How it works | https://bountykai.com/features/ | 7-step run model, scope behavior, coverage taxonomy | 2026-11-04 |
| About | https://bountykai.com/about/ | Company framing, "numbers it has not earned" | 2026-11-04 |
| Integrations | https://bountykai.com/integrations/ | "Nothing to connect"; Slack/Teams roadmap | 2026-11-04 |
| Pricing | https://bountykai.com/pricing/ | Starter $450/mo; plan inclusions | 2026-11-04 |
| Research index | https://bountykai.com/research/ | Publication philosophy | 2026-11-04 |
| CVE-Bench post | https://bountykai.com/research/cve-bench/ | Benchmark numbers, method, disclosure policy | 2026-11-04 |
| CVE-Bench evidence repo | https://github.com/bountykai-inc/cvebench-evidence | Evidence layout, honest caveats, publish/withhold | 2026-11-04 |
| Terms | https://bountykai.com/terms/ | Authorization, isolation, liability | 2026-11-04 |
| Privacy | https://bountykai.com/privacy/ | Per-target isolation, data handling | 2026-11-04 |
| Contact | https://bountykai.com/contact/ | "A test starts in the app, not in an email" | 2026-11-04 |
| Company overview | Supplied by the user | Industry, size, specialties | 2026-11-04 |
| Founder email | Gmail thread, 2026-11-02 18:45 | The build task itself | 2026-11-04 |

**Site version note.** The site is a marketing surface and will change. If a quote here is later
missing, the context pack is still a snapshot, not a live contract. The founder's email is the
contract.

## 2. Quote bank (verbatim)

Some entries join two adjacent lines from the same **illustrative** site example; those are marked
`[composite]` so they are not mistaken for a single sentence. Everything else is a contiguous quote.

### Positioning

> "Bountykai is an AI-native product: an AI red teaming agent. Give it a URL and the scope you are
> allowed to test. It works the web application and its APIs, stays inside that scope, and hands you
> a report." — *homepage*

> "One application. One scope. One report." — *homepage*

> "Bountykai tests the application the way an attacker would." — *company overview*

> "Software changes every week, while security testing happens once or twice a year." — *overview*

> "A penetration test once a year describes a version that is already gone." — *about*

> "A scanner pass lists names." — *about*

### Verification

> "A claim is checked before it is called a finding." — *homepage, features, pricing*

> "A finding shows what was tried and what came back. An unchecked claim is not published as a
> result." — *features*

> "[composite] replay: fresh session as account A · result: same response, so it is a finding"
> — *homepage example*

> "The proof is not 'trust our screenshots.'" — *CVE-Bench evidence README*

> "Every figure is the grader's, not ours." — *CVE-Bench post*

### Tri-state reporting

> "The report shows what was tried, what came back, what held and what blocked." — *about*

> "If a surface held, the report says so. If the run could not proceed, it says what blocked it. You
> do not get silence labeled 'nothing found.'" — *homepage*

> "You do not get silence labeled 'nothing found.' It asks you only for something it does not have,
> such as access you have not granted." — *features*

> "[composite] tested: password reset · held — A used reset link did not work a second time."
> — *homepage example*

> "[composite] could not proceed: admin pages need an admin login — No admin test account was added.
> Next: add an admin test account." — *homepage example*

### Scope and safety

> "Scope is set before it acts." — *homepage, features, about*

> "It does not add hosts, environments or preview URLs on its own." — *homepage*

> "A link it finds does not widen scope. Coming back after a change never means going wider." — *homepage*

> "Every boundary is enforced and logged. An out-of-scope action is rejected and recorded. If scope
> cannot be resolved, it fails closed and stops." — *homepage*

> "A link found along the way is tested only when it is already inside what you allowed, and signing
> in does not widen scope." — *features*

> "A new link or a redirect does not add targets." — *about*

> "Each target has its own isolated store: captured sessions, traffic, screenshots, proof and
> findings stay with that one target." — *homepage, privacy*

> "Authorized applications only. Bountykai stays inside the scope you set." — *site footer*

> "You may use BountyKai to test only applications, domains, APIs, and environments that you own or
> are explicitly authorized in writing by the owner to test." — *Terms §4*

> "Pointing the service at any target you are not authorized to test is a material breach of these
> Terms." — *Terms §4*

### Continuity

> "When the application changes, it tests what changed, starting from what it already confirmed. The
> next run is not a blank scan." — *homepage*

> "It notices when a step fails, picks another way through, and tests again." — *features*

> "[composite] step failed: the form wants a fresh token → reload the form and try again · recovered"
> — *homepage example*

### Product surface

> "Nothing to connect." — *integrations*

> "It signs in and drives your application itself, so there's no connector to configure to run it." — *integrations*

> "You do not assemble the workflow." — *features*

> "A test starts in the app, not in an email." — *contact*

### Research integrity

> "We publish our benchmarks and findings the way we report to a customer: the outcome, the proof,
> and the honest caveats. What the agent broke into — not how it was built." — *research index*

> "We publish the outcome and its proof. We withhold the mechanism." — *CVE-Bench evidence README*

> "Nothing is cherry-picked." — *CVE-Bench evidence README*

> "We would rather state these ourselves than have a reader find them." — *CVE-Bench evidence README*

> "We leave out how it is built, and numbers it has not earned." — *about*

### CVE-Bench facts (their published result, not ours)

| Field | Value |
|-------|-------|
| Benchmark | CVE-Bench v2.2.0, 40 tasks |
| Setting | Zero-day, URL + objective only |
| Metric | success@1, one attempt, 20-minute cap |
| Solved | 24 / 40; 24 / 39 bootable = 61.5% |
| Speed | 16 of 24 in ≤ 5 min; median 4 min |
| Evidence | Grader verdict for all 39 bootable targets, including failures |
| Replay | 12 of 24 solves ship a replayable proof-of-exploit |

If the README mentions these numbers, attribute them: **"BountyKai's published CVE-Bench result"** —
never "our benchmark" or "we scored."

## 3. What the site does **not** say (do not invent)

| Unknown | Why it matters |
|---------|----------------|
| Founding date, funding, investors | Do not write a company history |
| Team names beyond Gokul Ravi | Do not invent colleagues or org structure |
| Headcount beyond "2–10" | Do not state a precise team size |
| Customers, logos, case studies | None are public on the site; do not imply any |
| Model providers, prompts, orchestration | Explicitly withheld; do not speculate |
| Whether BountyKai uses MCP internally | Not stated; do not claim alignment at the protocol level |
| Whether the product exposes a public API | Not stated |
| SOC 2 / ISO / other certifications | Not claimed; do not imply compliance |
| Exact SLAs, retention windows, uptime | Not published |
| Whether the build task is scored by rubric | Not stated; build to the brief, not a guessed rubric |
| Whether the video must be public vs unlisted | Not stated; make it accessible without an account |
| Whether "6–10 hours" is a hard cap | Framed as an aim; do not pad, do not overshoot wildly |

## 4. Marketing vs evidence

Two different kinds of text live on the site. Keep them separate in your head:

- **Product copy** (homepage, features, pricing): describes intended behavior. The run examples are
  explicitly labeled **"Example run, illustrative."** They are not real customer runs and must never
  be cited as proof.
- **Research evidence** (CVE-Bench post + GitHub repo): a published benchmark result with a
  methodology, grader verdicts, a full results table including misses, and stated caveats. This is
  the credible material. If you reference anything, reference this.

**Rule:** never cite an illustrative example as evidence of how the product behaves. Cite the
benchmark, or cite the founder's brief.

## 5. Re-verification

If a claim in this pack matters to a decision, re-open the source before relying on it:

```bash
curl -s https://bountykai.com/ | sed -n '1,200p'
curl -s https://bountykai.com/features/
curl -s https://bountykai.com/research/cve-bench/
curl -s https://raw.githubusercontent.com/bountykai-inc/cvebench-evidence/main/README.md
```

The quote bank is a snapshot, not a substitute for the live page. If the site changes, update this
file and note the date.

## 6. Attribution and fair use

Quotes are short excerpts used to align an application build with the company's public product
language. They are not a license to reuse BountyKai's copy, brand, or code. Do not put the BountyKai
logo in the repo, do not imply endorsement, and do not reproduce long passages of marketing copy in
the README or video.
