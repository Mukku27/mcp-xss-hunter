# Sample evidence

These files are copies of real artifacts from the canonical runs. They exist so a reviewer can open
the bundle without running the lab first. The live tree is `evidence/<target>/<run-id>/`; that is what
`get_evidence` reads.

| Directory | Run | What it shows |
|---|---|---|
| `body/` | `r-20261105T053144Z-4f04` | A confirmed `html_body/html_text` finding, both signals, both screenshots, and the replay instructions |
| `encoded/` | `r-20261105T053148Z-af59` | 0 confirmed, 1 held: the payload was tried, no nonce signal fired |
| `refused/` | `r-20261105T053217Z-a4fb` | `OUT_OF_SCOPE` at S1 with `http_requests: 0` |
| `redirect/` | `r-20261105T053218Z-0514` | `OUT_OF_SCOPE` at S2; only the allowlisted redirector was requested |

`body/finding.json` carries `finding_sha256`. It is the hash of the canonical JSON with the hash field
removed. The copy is byte-identical to the live file; the `artifacts[].path` values still point at the
live tree so the bundle's origin is visible. If you run the same scan yourself, `get_evidence` will
find the newest copy of the same stable `finding_id`.

`body/proof.png` has a black banner added by the verifier after the signal. The banner labels the
artifact; the dialog message recorded in `finding.json` is the execution signal. `replay.png` is the
second load in the fresh context. `replay.md` is the human reproduction sheet.

The lab is deliberately vulnerable and binds `127.0.0.1` only. These artifacts contain no public host
and no third-party request.
