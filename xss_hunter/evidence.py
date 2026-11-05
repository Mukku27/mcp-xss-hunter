"""Per-target evidence tree.

Layout::

    evidence/<target-slug>/<run-id>/
      run.json
      held.json
      blocked.json
      observations/<finding-id>/observe.{json,png}
      findings/<finding-id>/
        finding.json
        proof.png
        replay.png          (when the replay screenshot exists)
        replay.md

``finding.json`` is self-contained: it carries the payload, both signals, the
artifact hashes, and a hash over its own contents. ``get_evidence`` recomputes
that hash before returning anything, so a hand-edited record is refused.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .ids import target_slug
from .logging_jsonl import utc_now
from .models import (
    Artifact,
    ErrorInfo,
    Evidence,
    EvidenceResponse,
    Finding,
    ScanResponse,
)
from .payloads import PayloadAttempt
from .runctx import RunContext
from .verify import Verification

FINDING_FILE = "finding.json"
PROOF_FILE = "proof.png"
REPLAY_PROOF_FILE = "replay.png"
REPLAY_FILE = "replay.md"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(data: dict) -> bytes:
    return (
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _write_bytes(path: Path, data: bytes) -> Artifact:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return Artifact(path=str(path), sha256=_sha256(data), bytes=len(data))


def _write_json(path: Path, data: dict) -> Artifact:
    return _write_bytes(path, _json_bytes(data))


def run_directory(run: RunContext, host: str) -> Path:
    return run.evidence_dir / target_slug(host) / run.run_id


def write_run(run: RunContext, response: ScanResponse) -> Path:
    """Record one run's scope snapshot and measured limits."""
    directory = run_directory(run, response.target.host or "unknown")
    data = {
        "run_id": response.run_id,
        "tool": run.tool,
        "started_at": run.created_at,
        "finished_at": utc_now(),
        "status": response.status,
        "target": response.target.model_dump(mode="json"),
        "parameter": response.parameter,
        "allowlist": list(run.scope.hosts),
        "totals": response.totals.model_dump(mode="json"),
        "limits": response.limits.model_dump(mode="json"),
        "truncated": response.truncated,
        "error": response.error.model_dump(mode="json") if response.error else None,
    }
    _write_json(directory / "run.json", data)
    return directory


def write_status(run: RunContext, response: ScanResponse) -> None:
    """Record the held and blocked lists beside run.json."""
    directory = run_directory(run, response.target.host or "unknown")
    if response.tested_held:
        _write_json(
            directory / "held.json",
            {"run_id": response.run_id, "tested_held": [h.model_dump(mode="json") for h in response.tested_held]},
        )
    if response.could_not_proceed:
        _write_json(
            directory / "blocked.json",
            {
                "run_id": response.run_id,
                "could_not_proceed": [b.model_dump(mode="json") for b in response.could_not_proceed],
                "error": response.error.model_dump(mode="json") if response.error else None,
            },
        )


def write_observation(
    run: RunContext,
    host: str,
    finding_id: str,
    url: str,
    attempt: PayloadAttempt,
    verification: Verification,
) -> Path:
    """Store what one browser attempt saw, before replay decides its fate."""
    directory = run_directory(run, host) / "observations" / finding_id
    directory.mkdir(parents=True, exist_ok=True)
    screenshot = None
    if verification.screenshot:
        screenshot = _write_bytes(directory / "observe.png", verification.screenshot)
    data = {
        "finding_id": finding_id,
        "url": url,
        "context": attempt.context,
        "sub_context": attempt.sub_context,
        "family": attempt.family,
        "payload": attempt.payload,
        "nonce": attempt.nonce,
        "requires_interaction": attempt.requires_interaction,
        "why": attempt.why,
        "signal": verification.signal,
        "signal_detail": verification.signal_detail,
        "final_url": verification.final_url,
        "activation": verification.activation,
        "dialogs": verification.dialogs,
        "consoles": verification.consoles,
        "browser": verification.browser,
        "screenshot": screenshot.model_dump(mode="json") if screenshot else None,
        "screenshot_error": verification.screenshot_error,
        "timestamp": utc_now(),
    }
    _write_json(directory / "observe.json", data)
    return directory


def _replay_markdown(finding: Finding, artifacts: list[Artifact]) -> str:
    artifact_lines = "\n".join(
        f"- `{Path(item.path).name}` — {item.bytes} bytes, sha256 `{item.sha256}`"
        for item in artifacts
    )
    return f"""# Replay — {finding.finding_id}

## What was observed

- Target: `{finding.url}`
- Parameter: `{finding.parameter}`
- Injection URL: `{finding.injection_url}`
- Context: `{finding.context}/{finding.sub_context}`
- Payload: `{finding.payload}`
- Nonce: `{finding.nonce}`
- First signal: `{finding.signal}` — {finding.signal_detail}
- Fresh-context replay: `{finding.replay.signal}` — the same nonce fired again in a new browser context
- Browser: {finding.browser}
- Timestamp: {finding.timestamp}

## How to re-derive it

1. Start the bundled lab: `uv run python -m labapp`.
2. Call `scan_xss` with the target URL and parameter shown above.
3. Open the returned URL in Chromium and confirm the dialog contains the nonce.
4. Run the same scan again in a new browser session; the dialog must contain the
   same nonce in both the first load and the fresh-context replay.

## Artifacts

{artifact_lines}

The screenshot banner is added by the verifier after the signal is observed;
it labels the evidence, it is not the execution itself. The dialog message
recorded in `finding.json` is the proof.

`replay.md` is this file; its sha256 is recorded in `finding.json`.
"""


def write_finding(
    run: RunContext,
    host: str,
    finding: Finding,
    screenshot: bytes,
    replay_screenshot: bytes = b"",
) -> Evidence:
    """Write the final bundle and return its public pointer record."""
    directory = run_directory(run, host) / "findings" / finding.finding_id
    directory.mkdir(parents=True, exist_ok=True)

    artifacts: list[Artifact] = []
    if screenshot:
        artifacts.append(_write_bytes(directory / PROOF_FILE, screenshot))
    if replay_screenshot:
        artifacts.append(_write_bytes(directory / REPLAY_PROOF_FILE, replay_screenshot))

    markdown = _replay_markdown(finding, artifacts)
    markdown_artifact = _write_bytes(directory / REPLAY_FILE, markdown.encode("utf-8"))
    artifacts.append(markdown_artifact)

    data = finding.model_dump(mode="json")
    data["run_id"] = run.run_id
    data["evidence"] = str(directory)
    data["screenshot"] = PROOF_FILE if screenshot else ""
    data["artifacts"] = [item.model_dump(mode="json") for item in artifacts]
    raw = _json_bytes(data)
    data["finding_sha256"] = _sha256(raw)
    _write_json(directory / FINDING_FILE, data)
    return Evidence.model_validate(data)


def load_evidence(evidence_dir: Path, finding_id: str) -> EvidenceResponse:
    """Find and integrity-check a stored finding. Never raises."""
    try:
        candidates = sorted(
            evidence_dir.rglob(f"findings/{finding_id}/{FINDING_FILE}"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
    except OSError:
        candidates = []

    if not candidates:
        return EvidenceResponse(
            status="invalid",
            error=ErrorInfo(
                code="INVALID_INPUT",
                message="finding not found",
                needs="a finding_id returned by scan_xss in this repository",
            ),
        )

    path = candidates[0]
    try:
        if not path.resolve().is_relative_to(evidence_dir.resolve()):
            raise ValueError("path outside evidence directory")
        data = json.loads(path.read_text(encoding="utf-8"))
        recorded = data.get("finding_sha256", "")
        body = {key: value for key, value in data.items() if key != "finding_sha256"}
        if not recorded or recorded != _sha256(_json_bytes(body)):
            return EvidenceResponse(
                status="invalid",
                error=ErrorInfo(
                    code="INVALID_INPUT",
                    message="evidence hash does not match the recorded finding",
                    needs="the original finding.json produced by scan_xss",
                ),
            )
        data["evidence"] = str(path.parent)
        return EvidenceResponse(status="ok", finding=Evidence.model_validate(data))
    except Exception:  # noqa: BLE001 - unreadable evidence is a typed result
        return EvidenceResponse(
            status="invalid",
            error=ErrorInfo(
                code="INVALID_INPUT",
                message="evidence unreadable",
                needs="a finding.json written by this server",
            ),
        )
