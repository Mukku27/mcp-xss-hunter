"""M1: the refusal path is real before any other stage exists."""

from __future__ import annotations

import json
from urllib.parse import quote

from xss_hunter.logging_jsonl import JsonlLogger
from xss_hunter.evidence import load_evidence
from xss_hunter.scan import scan
from xss_hunter.scope import Scope


def run(url, parameter="q", hosts=("127.0.0.1:5117",), tmp_path=None):
    logger = JsonlLogger(tmp_path / "scope.jsonl")
    return scan(
        url=url,
        parameter=parameter,
        context_override=None,
        scope=Scope(list(hosts)),
        logger=logger,
        evidence_dir=tmp_path / "evidence",
    )


def test_out_of_scope_is_refused_before_any_request(canary, tmp_path):
    base, hits = canary
    result = run(f"{base}/never", tmp_path=tmp_path)

    assert hits == []
    assert result.status == "refused"
    assert result.error.code == "OUT_OF_SCOPE"
    assert result.error.checkpoint == "S1"
    assert result.confirmed == []
    assert result.tested_held == []
    assert result.limits.http_requests == 0

    log = [json.loads(line) for line in (tmp_path / "scope.jsonl").read_text().splitlines()]
    refusal = [line for line in log if line["event"] == "refuse"]
    assert len(refusal) == 1
    assert refusal[0]["host"] == f"127.0.0.1:{base.rsplit(':', 1)[1]}"
    assert refusal[0]["reason"] == "host_not_allowlisted"
    assert refusal[0]["checkpoint"] == "S1"
    assert refusal[0]["run_id"] == result.run_id
    assert refusal[0]["tool"] == "scan_xss"
    assert refusal[0]["ts"]


def test_invalid_parameter_is_typed_input_error(tmp_path):
    result = run("http://127.0.0.1:5117/body", parameter="q&x=1", tmp_path=tmp_path)
    assert result.status == "invalid"
    assert result.error.code == "INVALID_INPUT"
    assert "parameter" in result.error.message


def test_empty_allowlist_refuses(tmp_path):
    result = run("http://127.0.0.1:5117/body", hosts=(), tmp_path=tmp_path)
    assert result.status == "refused"
    assert result.error.code == "OUT_OF_SCOPE"
    assert any(r.reason == "empty_allowlist" for r in result.scope_refusals)


def test_true_positive_is_confirmed_only_after_a_fresh_context_replay(lab, tmp_path):
    # AC-01: the payload fires, then fires again in a brand-new context. Only
    # then is it a finding, with an evidence bundle on disk.
    base, host, _ = lab
    result = run(f"{base}/body", hosts=(host,), tmp_path=tmp_path)

    assert result.status == "completed"
    assert len(result.confirmed) == 1
    finding = result.confirmed[0]
    assert finding.context == "html_body"
    assert finding.sub_context == "html_text"
    assert finding.url == f"{base}/body"
    assert finding.injection_url.startswith(f"{base}/body?q=")
    assert "onerror" in finding.injection_url
    assert f"{base}/body" in finding.reproduce
    assert finding.payload.startswith("<img")
    assert finding.signal == "dialog"
    assert finding.replay.verified is True
    assert finding.replay.session == "fresh"
    assert finding.replay.signal == "dialog"
    assert finding.replay.nonce == finding.nonce
    assert finding.evidence
    assert result.totals.confirmed == 1
    assert result.totals.tested_held == 0
    assert result.limits.browser_contexts == 2
    assert result.limits.payloads_sent == 2

    loaded = load_evidence(tmp_path / "evidence", finding.finding_id)
    assert loaded.status == "ok"
    assert loaded.finding is not None
    assert loaded.finding.payload == finding.payload
    assert loaded.finding.replay.verified is True


def test_two_reflection_points_produce_two_independent_findings(lab, tmp_path):
    base, host, _ = lab
    result = run(f"{base}/multi", hosts=(host,), tmp_path=tmp_path)

    assert result.status == "completed"
    assert len(result.confirmed) == 2
    contexts = {(item.context, item.sub_context) for item in result.confirmed}
    assert contexts == {
        ("html_body", "html_text"),
        ("attribute", "quoted_double"),
    }
    assert len({item.finding_id for item in result.confirmed}) == 2
    for item in result.confirmed:
        assert item.replay.verified is True
        assert item.evidence


def test_a_javascript_url_is_confirmed_after_the_verifier_clicks_it(lab, tmp_path):
    base, host, _ = lab
    result = run(f"{base}/url", hosts=(host,), tmp_path=tmp_path)

    assert result.status == "completed"
    assert len(result.confirmed) == 1
    finding = result.confirmed[0]
    assert finding.context == "url"
    assert finding.requires_interaction is True
    assert finding.payload.startswith("javascript:")
    assert finding.replay.verified is True


def test_finding_id_is_stable_across_runs(lab, tmp_path):
    base, host, _ = lab
    first = run(f"{base}/body", hosts=(host,), tmp_path=tmp_path / "one")
    second = run(f"{base}/body", hosts=(host,), tmp_path=tmp_path / "two")

    assert first.confirmed[0].finding_id == second.confirmed[0].finding_id
    assert first.confirmed[0].nonce != second.confirmed[0].nonce


def test_run_budget_is_bounded_and_reported(monkeypatch, tmp_path):
    # Force the wall-clock budget to be already spent. The run must stop before
    # any network request and name the budget, not report "no XSS".
    import xss_hunter.runctx as runctx

    monkeypatch.setattr(runctx, "RUN_BUDGET_SECONDS", 0.0)
    result = run("http://127.0.0.1:5117/body", tmp_path=tmp_path)

    assert result.status == "blocked"
    assert result.error.code == "TIMEOUT"
    assert result.limits.http_requests == 0
    assert result.could_not_proceed[0].needs


def test_reflection_only_encoded_parameter_is_held_not_confirmed(lab, tmp_path):
    # The money test, run twice: the marker reflects, the payload does not
    # execute, and the run is a held result with a specific reason.
    base, host, _ = lab
    for attempt in (1, 2):
        result = run(
            f"{base}/encoded",
            hosts=(host,),
            tmp_path=tmp_path / f"run{attempt}",
        )
        assert result.status == "completed", attempt
        assert result.confirmed == [], attempt
        assert result.could_not_proceed == [], attempt
        assert len(result.tested_held) == 1, attempt
        held = result.tested_held[0]
        assert held.reason == "payload_did_not_execute", attempt
        assert held.payloads_tried == 1, attempt
        assert held.payloads and "onerror" in held.payloads[0], attempt
        assert "nonce" in held.detail, attempt
        assert result.totals.confirmed == 0, attempt


def test_s5_blocks_an_off_scope_subresource_before_any_canary_hit(lab, canary, tmp_path):
    base, host, _ = lab
    canary_base, hits = canary
    result = run(
        f"{base}/external?to={quote(canary_base + '/escape', safe='')}",
        hosts=(host,),
        tmp_path=tmp_path,
    )

    assert result.status == "blocked"
    assert result.error.code == "OUT_OF_SCOPE"
    assert result.error.checkpoint == "S5"
    assert hits == []
    assert any(refusal.checkpoint == "S5" for refusal in result.scope_refusals)


def test_s5_blocks_a_meta_refresh_to_an_off_scope_host(lab, canary, tmp_path):
    base, host, _ = lab
    canary_base, hits = canary
    result = run(
        f"{base}/meta?to={quote(canary_base + '/escape', safe='')}",
        hosts=(host,),
        tmp_path=tmp_path,
    )

    assert result.status == "blocked"
    assert result.error.code == "OUT_OF_SCOPE"
    assert result.error.checkpoint == "S5"
    assert hits == []
