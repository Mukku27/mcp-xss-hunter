"""M4: the browser observes a nonce signal, and S5 stops off-scope requests."""

from __future__ import annotations

from urllib.parse import quote

from xss_hunter.logging_jsonl import JsonlLogger
from xss_hunter.runctx import RunContext
from xss_hunter.scope import Scope
from xss_hunter.verify import BrowserSession


def make_run(hosts, tmp_path):
    return RunContext(
        tool="scan_xss",
        parameter="q",
        scope=Scope(list(hosts)),
        logger=JsonlLogger(tmp_path / "scope.jsonl"),
        evidence_dir=tmp_path / "evidence",
    )


def test_baseline_is_clean_then_payload_fires(lab, tmp_path):
    base, host, _ = lab
    run = make_run([host], tmp_path)
    nonce = "xshverify1"

    with BrowserSession(run) as browser:
        assert browser.ok
        baseline = browser.baseline(
            f"{base}/body", "q", "xshbaseline", {nonce}
        )
        attempt = browser.attempt(
            f"{base}/body",
            "q",
            f"<img src=x onerror=alert('{nonce}')>",
            nonce,
            requires_interaction=False,
        )

    assert baseline.ok
    assert baseline.executed is False
    assert attempt.ok
    assert attempt.executed is True
    assert attempt.signal == "dialog"
    assert nonce in attempt.signal_detail
    assert attempt.screenshot
    assert attempt.browser.startswith("chromium/")
    assert run.browser_contexts == 1
    assert run.payloads_sent == 1
    assert run.http_requests >= 2


def test_encoded_page_has_no_execution_signal(lab, tmp_path):
    base, host, _ = lab
    run = make_run([host], tmp_path)
    nonce = "xshverify2"

    with BrowserSession(run) as browser:
        attempt = browser.attempt(
            f"{base}/encoded",
            "q",
            f"<img src=x onerror=alert('{nonce}')>",
            nonce,
            requires_interaction=False,
        )

    assert attempt.ok
    assert attempt.executed is False
    assert attempt.signal == "none"
    assert attempt.screenshot == b""


def test_a_javascript_url_runs_after_a_click(lab, tmp_path):
    base, host, _ = lab
    run = make_run([host], tmp_path)
    nonce = "xshverify3"

    with BrowserSession(run) as browser:
        attempt = browser.attempt(
            f"{base}/url",
            "q",
            f"javascript:alert('{nonce}')",
            nonce,
            requires_interaction=True,
        )

    assert attempt.ok
    assert attempt.executed is True
    assert attempt.signal == "dialog"
    assert nonce in attempt.signal_detail
    assert "clicked" in attempt.activation


def test_replay_uses_a_fresh_context_and_fires_again(lab, tmp_path):
    base, host, _ = lab
    run = make_run([host], tmp_path)
    nonce = "xshverify4"

    with BrowserSession(run) as browser:
        attempt = browser.attempt(
            f"{base}/body",
            "q",
            f"<img src=x onerror=alert('{nonce}')>",
            nonce,
            requires_interaction=False,
        )
        replay = browser.replay(
            f"{base}/body",
            "q",
            f"<img src=x onerror=alert('{nonce}')>",
            nonce,
            requires_interaction=False,
        )

    assert attempt.executed is True
    assert replay.ok
    assert replay.executed is True
    assert replay.signal == "dialog"
    assert nonce in replay.signal_detail
    assert attempt.screenshot != replay.screenshot
    assert run.browser_contexts == 2
    assert run.payloads_sent == 2


def test_s5_blocks_an_off_scope_subresource(lab, canary, tmp_path):
    base, host, _ = lab
    canary_base, hits = canary
    run = make_run([host], tmp_path)

    with BrowserSession(run) as browser:
        baseline = browser.baseline(
            f"{base}/external?to={quote(canary_base + '/escape', safe='')}",
            "q",
            "xshbaseline",
            set(),
        )

    assert baseline.ok is False
    assert baseline.failure.code == "OUT_OF_SCOPE"
    assert baseline.failure.checkpoint == "S5"
    assert hits == []
    assert any(refusal.checkpoint == "S5" for refusal in run.refusals)


def test_s5_blocks_a_meta_refresh(lab, canary, tmp_path):
    base, host, _ = lab
    canary_base, hits = canary
    run = make_run([host], tmp_path)

    with BrowserSession(run) as browser:
        baseline = browser.baseline(
            f"{base}/meta?to={quote(canary_base + '/escape', safe='')}",
            "q",
            "xshbaseline",
            set(),
        )

    assert baseline.ok is False
    assert baseline.failure.code == "OUT_OF_SCOPE"
    assert baseline.failure.checkpoint == "S5"
    assert hits == []
