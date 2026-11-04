"""M4: evidence is self-contained, hashed, and refuses a tampered record."""

from __future__ import annotations

import json
from pathlib import Path

from xss_hunter.evidence import load_evidence, write_finding
from xss_hunter.logging_jsonl import JsonlLogger
from xss_hunter.models import Finding, ReplayProof
from xss_hunter.runctx import RunContext
from xss_hunter.scope import Scope


def make_run(tmp_path):
    return RunContext(
        tool="scan_xss",
        parameter="q",
        scope=Scope(["127.0.0.1:5117"]),
        logger=JsonlLogger(tmp_path / "scope.jsonl"),
        evidence_dir=tmp_path / "evidence",
    )


def make_finding():
    nonce = "xshtest123"
    return Finding(
        finding_id="f-0123456789ab",
        url="http://127.0.0.1:5117/body",
        parameter="q",
        context="html_body",
        sub_context="html_text",
        payload=f"<img src=x onerror=alert('{nonce}')>",
        nonce=nonce,
        signal="dialog",
        signal_detail=f"dialog message contained the nonce: {nonce}",
        requires_interaction=False,
        replay=ReplayProof(
            verified=True, session="fresh", nonce=nonce, signal="dialog"
        ),
        evidence="",
        reproduce='scan_xss(url="http://127.0.0.1:5117/body", parameter="q")',
        browser="chromium/test",
        timestamp="2026-11-04T00:00:00.000+00:00",
    )


def test_write_then_load_round_trips_and_lists_artifacts(tmp_path):
    run = make_run(tmp_path)
    finding = make_finding()

    stored = write_finding(
        run, "127.0.0.1:5117", finding, b"png-bytes", b"replay-bytes"
    )
    loaded = load_evidence(run.evidence_dir, finding.finding_id)

    assert stored.finding_sha256
    assert loaded.status == "ok"
    assert loaded.finding is not None
    assert loaded.finding.payload == finding.payload
    assert loaded.finding.replay.verified is True
    assert loaded.finding.evidence.endswith(
        f"findings/{finding.finding_id}"
    )
    names = {Path(item.path).name for item in loaded.finding.artifacts}
    assert names == {"proof.png", "replay.png", "replay.md"}


def test_tampered_finding_json_is_refused(tmp_path):
    run = make_run(tmp_path)
    finding = make_finding()
    write_finding(run, "127.0.0.1:5117", finding, b"png-bytes")

    path = next(
        (run.evidence_dir).rglob(f"findings/{finding.finding_id}/finding.json")
    )
    data = json.loads(path.read_text())
    data["payload"] = "<img src=x onerror=alert('tampered')>"
    path.write_text(json.dumps(data))

    loaded = load_evidence(run.evidence_dir, finding.finding_id)

    assert loaded.status == "invalid"
    assert loaded.error is not None
    assert "hash" in loaded.error.message


def test_unknown_finding_is_invalid(tmp_path):
    loaded = load_evidence(tmp_path / "evidence", "f-000000000000")
    assert loaded.status == "invalid"
    assert loaded.error is not None
    assert loaded.error.message == "finding not found"
