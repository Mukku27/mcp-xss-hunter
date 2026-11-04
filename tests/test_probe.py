"""M2: the probe locates the marker and never follows an off-scope redirect."""

from __future__ import annotations

import json
from urllib.parse import quote

from xss_hunter.logging_jsonl import JsonlLogger
from xss_hunter.probe import probe, with_parameter
from xss_hunter.runctx import RunContext
from xss_hunter.scan import scan
from xss_hunter.scope import Scope


def make_run(hosts, tmp_path):
    logger = JsonlLogger(tmp_path / "scope.jsonl")
    run = RunContext(
        tool="scan_xss",
        parameter="q",
        scope=Scope(list(hosts)),
        logger=logger,
        evidence_dir=tmp_path / "evidence",
    )
    return run, logger


def test_with_parameter_replaces_in_place_and_keeps_others():
    url = with_parameter("http://127.0.0.1:5117/body?a=1&q=old&b=2", "q", "new")
    assert url == "http://127.0.0.1:5117/body?a=1&q=new&b=2"
    added = with_parameter("http://127.0.0.1:5117/body?a=1", "q", "new")
    assert added == "http://127.0.0.1:5117/body?a=1&q=new"


def test_probe_locates_every_marker_occurrence(lab, tmp_path):
    base, host, _ = lab
    run, _ = make_run([host], tmp_path)
    marker = "xshdeadbeef"

    outcome = probe(f"{base}/multi", "q", marker, run)

    assert outcome.ok
    assert outcome.reflected
    assert len(outcome.occurrences) == 2
    assert outcome.occurrences[0] < outcome.occurrences[1]
    assert outcome.status_code == 200
    assert outcome.response_sha256
    assert run.http_requests == 1


def test_probe_follows_an_allowed_redirect_manually(lab, tmp_path):
    base, host, _ = lab
    run, _ = make_run([host], tmp_path)
    marker = "xshcafebabe"
    target = f"/body?q={marker}"
    url = f"{base}/redirect?to={quote(target, safe='')}"

    outcome = probe(url, "q", marker, run)

    assert outcome.ok
    assert outcome.reflected
    assert len(outcome.redirects) == 1
    assert outcome.redirects[0].status == 302
    assert run.http_requests == 2


def test_probe_refuses_an_off_scope_redirect_before_request(lab, canary, tmp_path):
    base, host, _ = lab
    canary_base, hits = canary
    run, _ = make_run([host], tmp_path)
    url = f"{base}/redirect?to={quote(canary_base + '/escape', safe='')}"

    outcome = probe(url, "q", "xsh12345678", run)

    assert not outcome.ok
    assert outcome.failure.code == "OUT_OF_SCOPE"
    assert outcome.failure.decision.checkpoint == "S2"
    assert hits == []
    assert run.http_requests == 1
    log = [json.loads(line) for line in (tmp_path / "scope.jsonl").read_text().splitlines()]
    assert any(line["event"] == "refuse" and line["checkpoint"] == "S2" for line in log)


def test_missing_location_fails_closed(lab, tmp_path):
    base, host, _ = lab
    run, _ = make_run([host], tmp_path)
    outcome = probe(f"{base}/redirect-missing", "q", "xsh12345678", run)
    assert not outcome.ok
    assert outcome.failure.code == "REDIRECT_ERROR"
    assert outcome.failure.reason == "redirect_without_location"


def test_redirect_loop_hits_the_hop_cap(lab, tmp_path):
    base, host, _ = lab
    run, _ = make_run([host], tmp_path)
    outcome = probe(f"{base}/loop", "q", "xsh12345678", run)
    assert not outcome.ok
    assert outcome.failure.code == "REDIRECT_ERROR"
    assert outcome.failure.reason == "redirect_limit"


def test_scan_stops_at_an_off_scope_redirect(lab, canary, tmp_path):
    base, host, _ = lab
    canary_base, hits = canary
    url = f"{base}/redirect?to={quote(canary_base + '/escape', safe='')}"

    result = scan(
        url=url,
        parameter="q",
        context_override=None,
        scope=Scope([host]),
        logger=JsonlLogger(tmp_path / "scan.jsonl"),
        evidence_dir=tmp_path / "evidence",
    )

    assert result.status == "blocked"
    assert result.error.code == "OUT_OF_SCOPE"
    assert result.error.checkpoint == "S2"
    assert result.confirmed == []
    assert result.could_not_proceed[0].reason.startswith("redirect_refused")
    assert hits == []
    assert result.limits.http_requests == 1
    assert any(r.checkpoint == "S2" for r in result.scope_refusals)


def test_scan_reports_no_reflection_as_held(lab, tmp_path):
    base, host, _ = lab
    result = scan(
        url=f"{base}/body",
        parameter="missing_param",
        context_override=None,
        scope=Scope([host]),
        logger=JsonlLogger(tmp_path / "scan.jsonl"),
        evidence_dir=tmp_path / "evidence",
    )
    assert result.status == "completed"
    assert result.confirmed == []
    assert result.tested_held[0].reason == "param_not_reflected"
    assert result.could_not_proceed == []
