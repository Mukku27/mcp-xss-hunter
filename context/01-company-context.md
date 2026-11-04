# 01 — Company Context: BountyKai

> Captured from `bountykai.com` on **2026-11-04**, plus the company overview supplied by the
> founder's side. Marketing copy is quoted, not paraphrased, so it can be checked.
> See `05-sources-and-unknowns.md` for URLs and gaps.

## 1. Snapshot

| Field | Value |
|-------|-------|
| Name | **BountyKai** (site styling also uses "Bountykai") |
| Category | AI red teaming / autonomous penetration testing for **web applications and APIs** |
| Industry | Computer and Network Security |
| Company size | 2–10 employees *(provided overview)* |
| Founder | **Gokul Ravi**, Founder, BountyKai *(email signature)* |
| Website | https://bountykai.com |
| Product | An AI-native red-teaming agent: give it a URL and a scope, it tests inside that scope and returns a report with evidence |
| Entry price | **$450 USD / month** (Starter); Growth and Enterprise are custom |
| Delivery | SaaS at `app.bountykai.com`; no installation, no connector, no workflow to build |
| Jurisdiction | India; courts of Bengaluru, Karnataka *(Terms, §16)* |
| Specialties *(overview)* | AI red teaming, penetration testing, continuous penetration testing, web application security, API security, application security, offensive security, SaaS security, business logic testing |

**Positioning in one line:** continuous, agentic, evidence-backed testing for teams that ship weekly
— not an annual snapshot, and not a fixed-checklist scanner.

## 2. The problem they sell against

BountyKai's public materials draw three contrasts:

1. **The annual pentest is a snapshot.**
   > "A penetration test once a year describes a version that is already gone."
2. **Scanners list names, not proof.**
   > "A scanner pass lists names."
   > "Scanners run continuously, but they follow fixed checks, generate false positives and miss the
   > issues behind real breaches."
3. **Neither stays on the application.**
   > "Neither one stays on the application, tries the API the page just started calling, and comes
   > back when the application changes."
   > "Software changes every week, while security testing happens once or twice a year."

The product thesis follows: **the application changes every week, so testing must too — and every
result must be verified.**

> "Bountykai is that continuity."

## 3. What the product is

> "Bountykai is an AI-native product: an AI red teaming agent. Give it a URL and the scope you are
> allowed to test. It works the web application and its APIs, stays inside that scope, and hands you
> a report."

> "Bountykai signs in, works through the application and its APIs, and investigates access control,
> authentication, session handling, injection, business logic and the rest of a full web and API
> assessment. Each issue is verified before it is reported, and every finding includes evidence.
> When the application changes, Bountykai retests what changed." — *company overview*

Three product promises recur on every page:

| Promise | Their words |
|---------|-------------|
| **Scope is a hard boundary** | "Scope is set before it acts." · "It does not add hosts, environments or preview URLs on its own." |
| **Findings are verified** | "A claim is checked before it is called a finding." |
| **The report is complete about itself** | "The report shows what was tried, what came back, what held and what blocked." |

## 4. How a run works (their 7-step model)

From `/features/`:

1. **Scope is set before it acts.** The target, its APIs, the accounts and the rules are fixed
   before the run. Scope is locked.
2. **It maps the application.** What exists in scope, how the pieces connect, where the APIs are.
3. **It tries the paths that matter.** Including endpoints a click-through never calls.
4. **It recovers when a step fails.** "It notices when a step fails, picks another way through, and
   tests again." Example: an expired invite link → fetch a fresh one → retry.
5. **It checks a claim before calling it a finding.** A finding shows what was tried and what came
   back. An unchecked claim is not published.
6. **It reports what held and what blocked.** "You do not get silence labeled 'nothing found.'"
7. **It comes back when the application changes.** "It tests what changed, starting from what it
   already confirmed. The next run is not a blank scan."

Two details worth internalizing:

- **Signing in does not widen scope.** The agent uses its own test account, inside the same scope.
- **A found link does not widen scope.** In-scope links may be tested; out-of-scope links are
  refused, not added.

## 5. Coverage (their taxonomy)

The site groups a full web and API assessment into three families:

| Family | Classes |
|--------|---------|
| **Access & identity** | Access control (IDOR-class), authentication (login, MFA edges, reset, takeover paths), sessions (cookie/token handling, fixation, lifecycle), mass assignment |
| **Injection & forgery** | Injection (SQL, command, server-side), **cross-site scripting (stored, reflected, DOM)**, CSRF, SSRF |
| **Logic, data & config** | Business logic, file handling, security misconfiguration, sensitive data exposure |

**Why this matters for the assignment:** XSS is one line item in a much larger product. The build
task isolates it. Do not try to reproduce the whole taxonomy; make the XSS slice feel like it
belongs to this taxonomy — same vocabulary, same evidence discipline, same scope model.

## 6. The trust model — "The lines it does not cross"

Quoted from the homepage. This is the most reusable section of the entire site.

| Rule | Verbatim |
|------|----------|
| Scope precedes action | "Scope is set before it acts." |
| No self-expansion | "It does not add hosts, environments or preview URLs on its own." |
| Links don't widen scope | "A link it finds does not widen scope. Coming back after a change never means going wider." |
| Boundaries are enforced **and logged** | "Every boundary is enforced and logged. An out-of-scope action is rejected and recorded." |
| Fail closed | "If scope cannot be resolved, it fails closed and stops." |
| Data isolation | "Each target has its own isolated store: captured sessions, traffic, screenshots, proof and findings stay with that one target." |
| Authorization | "Testing is limited to applications customers own or are authorized to test." |

The footer of every page repeats: **"Authorized applications only. Bountykai stays inside the scope
you set."**

## 7. The reporting model — tri-state, not binary

This is the most important product idea to borrow.

| State | Meaning | Example from the site |
|-------|---------|----------------------|
| **Finding** | A claim that was **replayed and confirmed** | "replay: fresh session as account A · result: same response, so it is a finding" |
| **Held** | Tested, did not break | "tested: password reset · held" — "A used reset link did not work a second time." |
| **Blocked** | Could not test, and the report says why | "could not proceed: admin pages need an admin login" → "Next: add an admin test account" |

> "If a surface held, the report says so. If the run could not proceed, it says what blocked it.
> You do not get silence labeled 'nothing found.'"

Note the **third state is not a failure of the product** — it is a first-class outcome with a
requested next action. This is how a mature security product avoids lying by omission.

## 8. Continuity model

> "When the application changes, it tests what changed, starting from what it already confirmed.
> The next run is not a blank scan."

Implications:

- Confirmed findings become a **baseline**, not a trophy.
- A re-run is **change-aware**, not a fresh crawl.
- Coming back never widens scope: "A new link or a redirect does not add targets."
- Their run example shows a revised result after a change: `export endpoint · held · revised`.

For a 6–10 hour build, full continuity is out of scope. But **stable finding IDs and a run
manifest** cost almost nothing and make continuity possible later. See `03` §7.

## 9. Research credibility — CVE-Bench

The company's public benchmark post is the clearest statement of its epistemic standard.
Read it as a template for how to present results.

| Fact | Value |
|------|-------|
| Benchmark | CVE-Bench v2.2.0, 40 real web CVEs |
| Setting | **Zero-day**: URL + objective only, no CVE number, no hint, no source |
| Metric | **success@1** — one attempt per target |
| Limit | 20 minutes per task |
| Result | **24 / 40** solved; **24 / 39** (61.5%) of targets that booted |
| Speed | 16 of 24 in ≤ 5 min; median 4 min |
| Verification | The benchmark's own grader, verdict shipped verbatim for every target |
| Disclosure | Every task published, **including the 15 misses** and the target that never booted |

Their stated publication policy:

> "We publish the outcome and the proof, not the engine."

And the integrity line that should govern our README:

> "We leave out how it is built, and numbers it has not earned." *(/about/)*

And from the evidence repo:

> "Nothing is cherry-picked."
> "We would rather state these ourselves than have a reader find them."

**Translation for this build:** every number needs a denominator and a grader; every miss stays on
the record; every limitation is stated before a reviewer finds it.

## 10. Commercial context (useful for product judgment, not for the build)

- Starter at **$450/month**, aimed at founders and small teams testing the app they ship.
- Growth/Enterprise: more applications, custom limits, priority support.
- Every plan includes: scope enforcement, web app + APIs, full-class coverage, verified findings,
  evidence, "nothing to connect," **an isolated database per target**, dedicated support, community.
- Slack and Microsoft Teams alerts are "coming soon" — the only integrations on the roadmap.
- The contact page refuses to start tests over email: **"A test starts in the app, not in an email."**
  Scope is configured in-product, not in a message with a production URL attached. That is a
  security posture, not just UX.

**Signal:** BountyKai is opinionated about *product surface* — no connectors, no workflow builder,
no setup. A build task submission that requires a database, a queue, or a dashboard will feel
foreign to this company.

## 11. Legal and authorization posture

From the Terms (last updated 2026-10-22):

- Business/professional use only; not for consumers.
- Testing only applications the customer **owns or is explicitly authorized in writing** to test.
- BountyKai relies on the customer's scope designation and does **not** independently verify
  ownership.
- Pointing the service at an unauthorized target is a **material breach**.
- Automated testing is inherently limited; no guarantee of completeness or zero false
  positives/negatives.
- Findings and testing data belong to the customer; each target is kept in an isolated store.

**Why this matters:** the allowlist in our build is not a nice-to-have feature. It is the same
control that makes BountyKai's business lawful. Treat it with that seriousness.

## 12. What this means for the XSS hunter

1. **It is a module, not a mini-product.** One capability of an agentic red team: take a URL and a
   parameter, determine context, prove execution, report honestly.
2. **The scope model is the company's spine.** Deny by default, never widen on discovery, fail
   closed, log every boundary decision.
3. **The report is tri-state.** Confirmed findings, tested-held results, and blocked runs — kept
   separate, never merged.
4. **Verification is a replay, not a screenshot.** The claim must survive an independent fresh
   session.
5. **The execution proof is the product.** Everything else — payload catalogue, browser driver,
   CLI — exists to make that proof trustworthy.

## 13. What NOT to infer from this page

- BountyKai does **not** say it uses MCP internally. Do not claim that.
- It does **not** publish its models, prompts, orchestration or pricing internals beyond the plans.
- It does **not** claim zero false positives; its Terms explicitly disclaim that.
- It does **not** offer a public API or self-hosted edition on the site.
- It does **not** authorize testing anything you do not own, and neither does this build task.

See `05-sources-and-unknowns.md` for the full list of unknowns.
