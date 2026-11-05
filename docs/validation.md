# Client validation

Two real MCP clients were exercised against the final server. The Python SDK client in
`tests/test_server_stdio.py` is a third caller. The negotiated protocol revision was `2025-11-25` in
every case.

Commands below use `/abs/path/to/mcp-xss-hunter`; substitute the checkout path. The lab must be
running (`uv run python -m labapp`).

---

## 1. MCP Inspector CLI

### Tool discovery

```bash
npx -y @modelcontextprotocol/inspector --cli \
  --cwd /abs/path/to/mcp-xss-hunter \
  uv run python -m xss_hunter --method tools/list
```

Observed: three tools, each with a JSON input schema and an output schema generated from the return
type.

```text
scan_xss     required: url, parameter     optional: context_override
get_evidence required: finding_id
list_scope   required: none
```

`scan_xss` advertises `url` maxLength 2048, `parameter` maxLength 128, and the four-value
`context_override` enum. `get_evidence` advertises `finding_id` maxLength 64.

### Confirmed run

```bash
npx -y @modelcontextprotocol/inspector --cli \
  --cwd /abs/path/to/mcp-xss-hunter \
  uv run python -m xss_hunter --method tools/call \
  --tool-name scan_xss \
  --tool-arg url=http://127.0.0.1:5117/body \
  --tool-arg parameter=q
```

Observed text content:

```text
scan_xss: 1 confirmed, 0 held, 0 blocked [run r-20261105T053144Z-4f04]
```

Observed `structuredContent` (selected fields):

```json
{
  "status": "completed",
  "run_id": "r-20261105T053144Z-4f04",
  "confirmed": [{
    "finding_id": "f-70a19cebb2d3",
    "context": "html_body",
    "sub_context": "html_text",
    "payload": "<img src=x onerror=alert('xsh589ab985')>",
    "signal": "dialog",
    "signal_detail": "dialog message contained the nonce: xsh589ab985",
    "replay": {"verified": true, "session": "fresh", "nonce": "xsh589ab985", "signal": "dialog"},
    "evidence": "evidence/127_0_0_1_5117/r-20261105T053144Z-4f04/findings/f-70a19cebb2d3"
  }],
  "totals": {"confirmed": 1, "tested_held": 0, "could_not_proceed": 0}
}
```

### Reflection-only run

```bash
npx -y @modelcontextprotocol/inspector --cli \
  --cwd /abs/path/to/mcp-xss-hunter \
  uv run python -m xss_hunter --method tools/call \
  --tool-name scan_xss \
  --tool-arg url=http://127.0.0.1:5117/encoded \
  --tool-arg parameter=q
```

Observed twice (`r-20261105T053148Z-af59`, `r-20261105T053151Z-7386`):

```text
scan_xss: 0 confirmed, 1 held, 0 blocked
```

```json
{
  "tested_held": [{
    "context": "html_body",
    "sub_context": "html_text",
    "reason": "payload_did_not_execute",
    "detail": "no signal contained the nonce (dialogs=0, console=0)",
    "payloads": ["<img src=x onerror=alert('xsh1a2e7b1f')>"],
    "payloads_tried": 1
  }]
}
```

### Refusal

```bash
npx -y @modelcontextprotocol/inspector --cli \
  --cwd /abs/path/to/mcp-xss-hunter \
  uv run python -m xss_hunter --method tools/call \
  --tool-name scan_xss \
  --tool-arg url=http://127.0.0.1:59999/never \
  --tool-arg parameter=q
```

Observed (`r-20261105T053217Z-a4fb`):

```text
scan_xss: refused OUT_OF_SCOPE at S1; no request sent [run r-20261105T053217Z-a4fb]
```

`limits.http_requests` was `0`. The JSONL line is in the README and in
`docs/sample-evidence/refused/run.json`.

### Redirect escape

```bash
npx -y @modelcontextprotocol/inspector --cli \
  --cwd /abs/path/to/mcp-xss-hunter \
  uv run python -m xss_hunter --method tools/call \
  --tool-name scan_xss \
  --tool-arg 'url=http://127.0.0.1:5117/redirect?to=http%3A%2F%2F127.0.0.1%3A59999%2Fescape' \
  --tool-arg parameter=q
```

Observed (`r-20261105T053218Z-0514`): `status: blocked`, `error.code: OUT_OF_SCOPE`,
`error.checkpoint: S2`, and one request to the allowlisted redirector. The escape host received none.

---

## 2. Codex CLI 0.166.0

Configuration used:

```toml
[mcp_servers.xss-hunter]
command = "uv"
args = ["run", "--directory", "/abs/path/to/mcp-xss-hunter", "python", "-m", "xss_hunter"]
startup_timeout_sec = 20
tool_timeout_sec = 120
```

Command:

```bash
codex exec --json \
  "Call list_scope, then scan_xss for http://127.0.0.1:5117/body with parameter q,
   then get_evidence for the finding_id. Report the values the tools returned."
```

The agent made three MCP tool calls. Tool results below are quoted from the JSONL transcript; the
agent's final paragraph is its own summary.

```text
list_scope {}
  list_scope: 6 allowed host(s)

scan_xss {"url": "http://127.0.0.1:5117/body", "parameter": "q"}
  scan_xss: 1 confirmed, 0 held, 0 blocked [run r-20261105T053707Z-f035]
  finding f-70a19cebb2d3
  context html_body / html_text
  payload <img src=x onerror=alert('xsh50abe267')>
  signal dialog
  replay verified true

get_evidence {"finding_id": "f-70a19cebb2d3"}
  get_evidence: f-70a19cebb2d3 at
  evidence/127_0_0_1_5117/r-20261105T053707Z-f035/findings/f-70a19cebb2d3
  status ok, 3 artifacts, finding_sha256 recorded
```

Agent's final message:

> Run `r-20261105T053707Z-f035` confirmed finding `f-70a19cebb2d3` in context `html_body`,
> sub_context `html_text`, using payload `<img src=x onerror=alert('xsh50abe267')>`; the execution
> signal was `dialog`, and fresh-context replay verified was `true`.

This is the run an agent can perform without a UI. The model chose the tool arguments; the server did
the probing and the browser work.

---

## 3. Python SDK client

`tests/test_server_stdio.py` starts the server with `stdio_client`, then:

1. `initialize` — records the negotiated revision.
2. `list_tools` — asserts tool names, required fields, and length limits.
3. `list_scope` — asserts the six lab hosts.
4. `scan_xss` against an out-of-scope host — asserts `refused`, `OUT_OF_SCOPE`, S1, and zero requests.
5. `scan_xss` with an invalid parameter — asserts `INVALID_INPUT`.
6. `get_evidence` with a malformed id — asserts `INVALID_INPUT`.
7. Reads `logs/scope.jsonl` and asserts the refusal line fields.

Run it with `uv run pytest -q tests/test_server_stdio.py`.

---

## 4. What did not work

Claude Code 2.1.318 was installed and its MCP configuration loaded, but a headless `claude -p` turn
exited 1 before any tool call:

```text
OAuth session expired and could not be refreshed
```

It is not counted as a tested client. The server's stdio handshake was not the failure; the CLI could
not authenticate. Re-testing with a fresh login is a reasonable follow-up before the call.
