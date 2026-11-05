# Demo script — 2:20 to 2:50

The recording is the one deliverable that has to be made on a machine with a microphone. This script
is the plan; the repository ships everything it calls.

**Status:** recorded as [`docs/demo.mp4`](demo.mp4). `ffprobe` reports 178.433333 seconds.
Narration is the macOS Samantha voice, named in the opening frame. The submission email is still
unsent.

---

## What the video must show

1. An agent (not a script) calling the MCP tools.
2. `list_scope` with the lab-only allowlist.
3. A confirmed finding: context, payload, nonce-bearing browser signal, replay result.
4. The `/encoded` negative case: 0 confirmed, 1 held, payload and reason visible.
5. An out-of-scope refusal and the JSONL line.
6. One design tradeoff and one limitation.

Do not cut the negative case or the refusal. If something flakes, show the retry. Do not re-record
over a failure and present the second take as the first.

---

## Before recording

Use a checkout with the lab and the dependencies installed:

```bash
cd /abs/path/to/mcp-xss-hunter
uv sync
uv run playwright install chromium
```

Make sure Codex is authenticated:

```bash
codex login status
```

Register the server once. Remove a previous entry first if you have one:

```bash
codex mcp remove xss-hunter 2>/dev/null || true
codex mcp add xss-hunter -- uv run --directory "$PWD" python -m xss_hunter
codex mcp list
```

Start the lab in terminal 1 and leave it running:

```bash
uv run python -m labapp
```

Clean the on-screen evidence tree so the demo shows one run at a time. This moves old files aside; it
does not delete them:

```bash
mkdir -p /tmp/xsh-demo-backup
mv evidence/127_0_0_1_5117 /tmp/xsh-demo-backup/ 2>/dev/null || true
mv logs/scope.jsonl /tmp/xsh-demo-backup/ 2>/dev/null || true
```

Screen setup:

- 1080p or larger, terminal font at least 16 pt.
- Two terminals: lab on the left, demo on the right.
- Close notifications. Do not show `~/.codex/auth.json` or any token.
- Keep `logs/scope.jsonl` and the evidence tree visible in a file manager or a third terminal if the
  layout allows.

---

## Storyboard

### 0:00–0:15 — Problem

On screen: a terminal with the repository name, then the lab banner.

Say:

> Most XSS scanners stop at reflection. Reflection is not execution. This server makes a browser
> prove the payload ran, then makes a second browser prove it again.

### 0:15–0:35 — Setup

Run:

```bash
npx -y @modelcontextprotocol/inspector --cli --cwd "$PWD" \
  uv run python -m xss_hunter --method tools/list
npx -y @modelcontextprotocol/inspector --cli --cwd "$PWD" \
  uv run python -m xss_hunter --method tools/call --tool-name list_scope
```

On screen: three tool names, then the six lab hosts.

Say:

> Three tools over stdio. The scope is locked before the first request: exact `host:port`, no
> wildcards, and an empty list refuses everything.

### 0:35–1:05 — The agent acts

Run the real Codex session. The formatter prints the tool calls and the result, not a mock:

```bash
codex exec --json --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check \
  "Use only the xss-hunter MCP tools. Call list_scope. Then call scan_xss with url http://127.0.0.1:5117/body and parameter q. Then call get_evidence with the finding_id from the scan result. Reply with the run_id, finding_id, context, payload, signal, and replay result." \
  </dev/null | python3 scripts/demo_stream.py
```

On screen:

```text
-> xss-hunter.list_scope {}
<- list_scope: 6 allowed host(s)
-> xss-hunter.scan_xss {"url": "http://127.0.0.1:5117/body", "parameter": "q"}
<- scan_xss: 1 confirmed, 0 held, 0 blocked [run r-...]
   finding f-70a19cebb2d3 | html_body/html_text | <img src=x onerror=alert('xsh...')> | signal=dialog | replay=True
```

Say:

> The agent picked one URL and one parameter. The tool probed the reflection, classified it as an
> HTML text node, and sent a payload built for that context. Not a generic list.

### 1:05–1:30 — Proof

The formatter already printed the finding. Open the bundle:

```bash
BUNDLE=$(dirname "$(ls -t evidence/127_0_0_1_5117/*/findings/*/finding.json | head -1)")
python3 -m json.tool "$BUNDLE/finding.json"
open "$BUNDLE/proof.png"
```

On screen: `payload`, `nonce`, `signal: dialog`, `signal_detail`, `replay.verified: true`, the
artifact hashes, and the screenshot.

Say:

> The browser fired a dialog containing the nonce. Then the same payload ran again in a fresh browser
> context and fired the same nonce. Two independent signals, so this is a finding. The evidence
> record carries the payload, both signals, the screenshot, and a hash over its own contents.

### 1:30–1:50 — Negative case

Run:

```bash
codex exec --json --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check \
  "Use only the xss-hunter MCP tools. Call scan_xss for http://127.0.0.1:5117/encoded with parameter q. Reply with the confirmed count, the held count, the held reason, and the payload that was tried." \
  </dev/null | python3 scripts/demo_stream.py
```

On screen:

```text
<- scan_xss: 0 confirmed, 1 held, 0 blocked [run r-...]
   held html_body/html_text | payload_did_not_execute | no signal contained the nonce | payloads=['<img src=x onerror=alert('xsh...')>']
```

Say:

> This parameter reflects, but the encoding holds. Zero confirmed, one held result, and the payload
> that was tried is still in the output. Held is not a finding, and it is not "nothing found."

### 1:50–2:15 — Safety refusal

Run:

```bash
codex exec --json --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check \
  "Use only the xss-hunter MCP tools. Call scan_xss for http://127.0.0.1:59999/never with parameter q. Reply with the status, error code, checkpoint, and whether any request was sent." \
  </dev/null | python3 scripts/demo_stream.py
```

Then:

```bash
tail -2 logs/scope.jsonl
```

On screen: `refused`, `OUT_OF_SCOPE`, checkpoint `S1`, and a log line with `ts`, `host`, `tool`,
`reason`, and `run_id`.

Say:

> Out of scope: refused before the request, and recorded. The refusal is a decision, not a filter
> that runs after a request.

### 2:15–2:35 — Evidence and design tradeoff

If the bundle is not already on screen, run:

```bash
cat "$BUNDLE/replay.md"
```

Say:

> One design tradeoff: the browser fence uses CDP, not Playwright's route handler. I measured the
> route handler missing a redirect hop, so the fence moved to CDP and the canary test now records
> zero hits. The cost is Chromium-only interception, which is documented.

### 2:35–2:50 — Close

On screen: repository name, README, and the limitation section.

Say:

> What it does not do: DOM-only XSS, stored XSS, authenticated flows, or crawling. Those are in the
> README's limitations, next to the proof commands. One URL, one parameter: proof, held, or blocked.

---

## If a run flakes

- Keep recording. Run the same command again and say what happened.
- If the browser fails to launch, show the `BROWSER_ERROR` and the `needs` field; that is a real
  result.
- If Codex prints a model-refresh warning to stderr, it is not a tool failure. Leave it in the frame
  or scroll it away; do not edit it out of the terminal history.

## After recording

- Runtime must be 2:00–3:00. Check the file duration, not the stopwatch.
  `docs/demo.mp4` measures 178.433333 seconds.
- The negative case and the refusal are both in that cut.
- The file is in the repository. The README links to the GitHub blob, which plays in a browser.
- Put that link in the submission email. The email has not been sent.
- Optional cleanup: `codex mcp remove xss-hunter`.
