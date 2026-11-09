# Lab trials — own site, Juice Shop, DVWA

Three labs, one at a time. The point is to find out what `scan_xss` can prove on a page that does
not announce its sink, then on two third-party labs, before changing any scanner code.

The submission lab is still the bundled one. These trials are extra evidence, not a replacement for
AC-01 through AC-05, whose fixtures are the canonical routes in `labapp/app.py`.

## Reading a row

| Column | Meaning |
|---|---|
| URL + parameter | Exactly what was passed to `scan_xss`. |
| Contract | `in` = one GET parameter reflected into the HTML body. `out` = needs POST, a cookie, a click that the tool does not model, or a client-side-only sink. |
| Expected | What the tool should say if it respects its own documented limits. |
| Actual | The run's real tri-state. |
| Run id | Printed by the collector for that run. `logs/` is not committed, so a re-run mints new ids and the same tri-states. |

Tri-state is `confirmed` (a browser executed the payload and replay re-executed it), `tested_held`
(the payload was sent and did not execute, or the parameter never reflected), or
`could_not_proceed` (a stage refused or failed, with `needs` naming the missing input).

## Phase 1 — the professional own site

`labapp/site.py` renders an ordinary storefront: home, catalog, product detail, support, share,
reviews, search, suggestions. The header, footer and stylesheet are shared, the copy reads like a
shop, and nothing on the page says "vulnerable". The canonical acceptance routes are still served
but linked from nowhere, so the UI no longer gives the game away.

Each sink below is a normal-looking page element. The caller still supplies the URL and parameter,
so the tool's job is unchanged; what changed is that the reflection is not the obvious subject of
the page.

Collected with `scripts/lab_trials.py` against one ephemeral instance. Run ids below are from that
run; re-running produces new ids and the same tri-states.

| URL + parameter | Contract | Expected | Actual | Run id |
|---|---|---|---|---|
| `/catalog?sort=price` + `q` | in | confirmed | confirmed x2 — `html_body/html_text` and `attribute/quoted_double` | `r-20261108T074914Z-7c93` |
| `/products?sku=VF-101` + `sku` | in | confirmed | confirmed — `attribute/quoted_double` | `r-20261108T074918Z-6238` |
| `/support` + `topic` | in | confirmed | confirmed — `script/js_string_double` | `r-20261108T074920Z-38a8` |
| `/share` + `next` | in | confirmed | confirmed — `url/href`, `requires_interaction: true` | `r-20261108T074922Z-b000` |
| `/reviews` + `q` | in | held | held — `payload_did_not_execute` | `r-20261108T074925Z-1632` |
| `/search` + `q` | out (POST only) | held | held — `param_not_reflected` | `r-20261108T074927Z-47fa` |
| `/suggest` + `q` | out (client-side only) | held | held — `param_not_reflected` | `r-20261108T074927Z-6c41` |

### What the catalog row actually shows

`/catalog` renders the search term three times: escaped in the heading, raw in the filter chip (a
text node), and raw on the product grid as `data-query`. The classifier collapses the two text-node
copies to one attempt, because a context is classified by syntax, not by whether escaping happened
upstream. The browser then executes the raw chip and the escaped heading stays inert. A second
finding lands for `data-query`, which is an attribute context, not part of the chip.

That is the nuance worth keeping: a page can be half-escaped, and the result is still a true
positive, with the inert copy held rather than reported. A scanner that stopped at "the value is in
the HTML" would not have known which copy to trust.

### Why `/search` and `/suggest` are diagnostics, not bugs

`/search` only echoes a term on POST. `/suggest` filters a static list in the browser and never
writes the term into the document. Both are outside the documented contract, so a held result is
correct. They exist so the scorecard distinguishes "buried but in contract" from "outside the tool"
instead of letting a zero be read as a scanner failure.

### Reproduce

```bash
uv run python -m pytest tests/test_scan_contexts.py -q
uv run python scripts/lab_trials.py
```

`scripts/lab_trials.py` starts the lab on an ephemeral port, calls the same `scan()` entry point the
MCP tool uses, and prints one JSON line per row. It needs no Docker and no allowlist edit.

## Phase 2 — local OWASP Juice Shop

Image `bkimminich/juice-shop:latest`, published as `127.0.0.1:3000:3000` only. The local
`/api/Challenges` scoreboard listed nine XSS challenges. Each candidate below was checked with two
plain GETs first — one with a marker, one with an encoded `<img onerror>` payload — and in every
case the marker was absent from the response body. The scan rows record what the tool then did.

| URL + parameter | Contract | Expected | Actual | Run id |
|---|---|---|---|---|
| `/` + `q` | out (Angular SPA shell) | held | held — `param_not_reflected`, 9984-byte shell | `r-20261108T075318Z-a86b` |
| `/rest/products/search` + `q` | out (JSON API, searched term is not echoed) | held | held — `param_not_reflected`, 30-byte JSON | `r-20261108T075320Z-1549` |
| `/api/Challenges` + `name` | out (JSON API, filter applied server-side) | held | held — `param_not_reflected`, 30-byte JSON | `r-20261108T075320Z-b837` |
| `/rest/user/whoami` + `q` | out (JSON API) | held | held — `param_not_reflected`, 11-byte JSON | `r-20261108T075321Z-1d08` |
| `/rest/products/1/reviews` + `q` | out (JSON API) | held | held — `param_not_reflected`, 395-byte JSON | `r-20261108T075321Z-319a` |

### Why every row is a held result and not a miss

Juice Shop is an Angular single-page app. The server sends one HTML shell and the search, basket,
and product views are rendered in the browser from JSON and from the URL fragment. `scan_xss` takes
one URL and one GET parameter and classifies what the HTTP response contains; a fragment is not sent
to the server, and a JSON API that applies a filter does not echo the term. The marker therefore
never appears in a response body, and the documented outcome for that is `param_not_reflected`.

That is the same limit README §9 already states in one line ("DOM-only sinks, for example Juice
Shop's search, are out of scope"). Running it turned a documented limitation into a measured one:
zero requests left localhost, no payload was sent, and the tool named the reason instead of
returning an empty success.

Juice Shop's XSS challenges remain reachable by a human in a browser. Proving them would need a
client-side renderer in the hunt path and a fragment-aware target model, which is a different
product from the founder's one-URL-one-parameter brief. Not attempted here.

Container stopped after the rows were recorded.

## Phase 3 — local DVWA

Image `vulnerables/web-dvwa:latest`, published as `127.0.0.1:8080:80` only. First-run database setup
was completed by hand against the local instance (a CSRF-token POST to `/setup.php`) because that is
a setup step, not a scan. The scan itself carried no cookie and no session.

| URL + parameter | Contract | Expected | Actual | Run id |
|---|---|---|---|---|
| `/vulnerabilities/xss_r/` + `name` | out (login wall) | held | held — `param_not_reflected`, 1 redirect, 1523-byte login page | `r-20261108T075625Z-c420` |

`list_scope` returned `allowed=True` for `127.0.0.1:8080` before the scan, so the result is a real
measurement and not a scope refusal.

### What the run proves

DVWA puts every vulnerability page behind `login.php`. An unauthenticated GET is answered with a 302
to the login form, so the response body never contains the marker. The tool made two requests, sent
zero payloads, and said `param_not_reflected` — the same honest answer as Juice Shop, for a different
reason (auth wall rather than client-side rendering).

DVWA's own reflected page would very likely confirm if a session were supplied. That is deliberately
not done: README §9 and founder §9 both put authenticated scanning out of scope, and adding a cookie
jar to satisfy one lab would change the safety surface for every target. The row records the limit
rather than papering over it.

Container stopped after the row was recorded.

## Gap memo

Three labs, twelve rows, one scanner. What separates the misses from the limits:

### In-contract, and it worked

| Page | Why it is a real test |
|---|---|
| `/catalog` | Escaped heading, raw chip, and raw `data-query`. Two findings (text and attribute); the escaped heading stays inert. |
| `/products` | Sink behind a non-default parameter name (`sku`) inside a normal card attribute. |
| `/support` | Sink inside an inline widget config object, surrounded by ordinary JavaScript. |
| `/share` | Sink in a `href` on a button that reads like a checkout flow. Reported with `requires_interaction: true`. |
| `/reviews` | Visually identical to `/catalog`, fully escaped. Zero findings, one held. This is the AC-02 analogue on a realistic page. |

The catalog row is the one that would have fooled a weaker tool. Both copies of the term sit in the
same text context, and the classifier collapses them to one attempt; the browser then proves the raw
copy and leaves the escaped copy inert. A scanner that reported "reflected therefore vulnerable"
would have produced a finding it could not replay, and a scanner that gave up at the first escaped
occurrence would have missed a live sink on the same page.

### Documented limits, confirmed by measurement

| Lab | Limit |
|---|---|
| Juice Shop | Angular SPA. Server returns one shell; the sink is rendered in the browser from JSON and the URL fragment. Not visible to an HTTP-body classifier. |
| DVWA | Login wall. Every vulnerability page 302s to `login.php` without a session, and sessions are out of scope. |
| Own site `/search` | POST-only echo. The tool is GET-only by design. |
| Own site `/suggest` | Client-side-only sink. Nothing to classify server-side. |

### What this does and does not justify

It does not justify adding a crawler, a headless renderer in the probe path, a fragment-aware target
model, or a cookie jar. Each of those widens what the server may touch, and the founder's brief is one
URL and one parameter.

It does justify two small, cheaper improvements if a later pass wants them:

1. A `content_type` note in the held detail when the response is not HTML (Juice Shop's 30-byte JSON
   reads better as `response_was_json` than as a bare marker absence).
2. A `auth_required` hint when the redirect chain ends on a login path, so `needs` names the missing
   session instead of a generic reflection failure.

Both are wording changes to an existing held result. Neither changes what the tool may do, and
neither is implemented in this plan.

