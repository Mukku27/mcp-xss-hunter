"""M1: the refusal path is real before any other stage exists."""

from __future__ import annotations

import json

from xss_hunter.logging_jsonl import JsonlLogger
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


def test_allowed_target_does_not_claim_a_result_yet(lab, tmp_path):
    # M2 locates the marker but has no classifier. It must say "blocked",
    # never "no XSS", and never invent a finding.
    base, host, _ = lab
    result = run(f"{base}/body", hosts=(host,), tmp_path=tmp_path)
    assert result.status == "blocked"
    assert result.confirmed == []
    assert result.could_not_proceed[0].stage == "classify"
