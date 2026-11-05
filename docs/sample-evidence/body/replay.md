# Replay — f-70a19cebb2d3

## What was observed

- Target: `http://127.0.0.1:5117/body`
- Parameter: `q`
- Injection URL: `http://127.0.0.1:5117/body?q=%3Cimg+src%3Dx+onerror%3Dalert%28%27xsh589ab985%27%29%3E`
- Context: `html_body/html_text`
- Payload: `<img src=x onerror=alert('xsh589ab985')>`
- Nonce: `xsh589ab985`
- First signal: `dialog` — dialog message contained the nonce: xsh589ab985
- Fresh-context replay: `dialog` — the same nonce fired again in a new browser context
- Browser: chromium/156.0.8078.4
- Timestamp: 2026-11-05T05:31:47.016+00:00

## How to re-derive it

1. Start the bundled lab: `uv run python -m labapp`.
2. Call `scan_xss` with the target URL and parameter shown above.
3. Open the returned URL in Chromium and confirm the dialog contains the nonce.
4. Run the same scan again in a new browser session; the dialog must contain the
   same nonce in both the first load and the fresh-context replay.

## Artifacts

- `proof.png` — 14918 bytes, sha256 `72db3dea90a067c474e9565e381bfeba3721e51305ae37321e7a6a300b50a73f`
- `replay.png` — 15454 bytes, sha256 `5f1d01f706a6acf84a378ba3f6d492e2a8a85d0ec8dbfa2c95a2e94a87364c64`

The screenshot banner is added by the verifier after the signal is observed;
it labels the evidence, it is not the execution itself. The dialog message
recorded in `finding.json` is the proof.

`replay.md` is this file; its sha256 is recorded in `finding.json`.
