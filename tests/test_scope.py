"""Tests for the scope spine. This table must stay green before anything
touches the network or a browser.
"""

from __future__ import annotations

import json

import pytest

from xss_hunter.logging_jsonl import JsonlLogger, ScopeGuard
from xss_hunter.scope import (
    Scope,
    ScopeConfigError,
    load_scope_config,
    normalize_allow_entry,
)


def test_allows_exact_host_and_port(tmp_path):
    scope = Scope(["127.0.0.1:5117"])
    decision = scope.check("http://127.0.0.1:5117/body?q=x", "S1")
    assert decision.allowed
    assert decision.host == "127.0.0.1:5117"
    assert decision.reason == "allowed"


def test_refuses_subdomain_lookalike(tmp_path):
    scope = Scope(["allowed.test:80"])
    decision = scope.check("http://evil-allowed.test:80/", "S1")
    assert decision.refused
    assert decision.reason == "host_not_allowlisted"


def test_refuses_host_without_the_allowed_port():
    scope = Scope(["127.0.0.1:5117"])
    decision = scope.check("http://127.0.0.1/", "S1")
    assert decision.refused
    assert decision.host == "127.0.0.1:80"


def test_refuses_userinfo_trick():
    scope = Scope(["allowed.test:80"])
    decision = scope.check("http://allowed.test:80@evil.test:80/", "S0")
    assert decision.refused
    assert decision.reason == "userinfo_not_allowed"


def test_refuses_backslash_trick():
    scope = Scope(["allowed.test:80"])
    decision = scope.check("http://allowed.test:80\\@evil.test:80/", "S0")
    assert decision.refused


@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "ftp://127.0.0.1:21/",
    "gopher://127.0.0.1:70/",
])
def test_refuses_non_http_schemes(url):
    scope = Scope(["127.0.0.1:80"])
    decision = scope.check(url, "S0")
    assert decision.refused
    assert decision.reason == "scheme_not_allowed"


def test_refuses_empty_allowlist():
    scope = Scope([])
    decision = scope.check("http://127.0.0.1:5117/", "S1")
    assert decision.refused
    assert decision.reason == "empty_allowlist"


def test_refuses_ip_not_explicitly_listed():
    scope = Scope(["localhost:5117"])
    decision = scope.check("http://127.0.0.1:5117/", "S1")
    assert decision.refused


def test_allows_ip_when_explicitly_listed():
    scope = Scope(["127.0.0.1:5117"])
    assert scope.check("http://127.0.0.1:5117/", "S1").allowed


def test_case_and_trailing_dot_are_normalized():
    scope = Scope(["allowed.test:80"])
    assert scope.check("http://ALLOWED.TEST.:80/", "S0").allowed


def test_idn_is_punycoded_before_compare():
    scope = Scope(["xn--bcher-kva.test:80"])
    decision = scope.check("http://bücher.test:80/", "S0")
    assert decision.allowed
    assert decision.host == "xn--bcher-kva.test:80"


def test_refuses_encoded_host():
    scope = Scope(["evil.test:80"])
    decision = scope.check("http://%65vil.test:80/", "S0")
    assert decision.refused


def test_refuses_malformed_urls():
    scope = Scope(["allowed.test:80"])
    for url in ["", "not a url", "http://", "http://allowed.test:99999/", "http:///path"]:
        assert scope.check(url, "S0").refused, url


def test_refuses_encoded_control_characters_in_path():
    scope = Scope(["allowed.test:80"])
    decision = scope.check("http://allowed.test:80/%0d%0aX-Test:1", "S0")
    assert decision.refused
    assert decision.reason == "control_characters"


def test_default_ports_are_normalized():
    scope = Scope(["allowed.test:80", "secure.test:443"])
    assert scope.check("http://allowed.test/", "S0").host == "allowed.test:80"
    assert scope.check("https://secure.test/", "S0").host == "secure.test:443"


def test_ipv6_is_supported_when_explicitly_listed():
    scope = Scope(["[::1]:5117"])
    assert scope.check("http://[::1]:5117/", "S1").allowed


def test_refuses_wildcard_entries():
    with pytest.raises(ScopeConfigError):
        normalize_allow_entry("*.allowed.test:80")


def test_config_must_have_explicit_port(tmp_path):
    path = tmp_path / "scope.toml"
    path.write_text('[scope]\nhosts = ["allowed.test"]\n')
    with pytest.raises(ScopeConfigError):
        load_scope_config(path)


def test_config_can_be_empty_and_denies_everything(tmp_path):
    path = tmp_path / "scope.toml"
    path.write_text("[scope]\nhosts = []\n")
    scope = Scope(load_scope_config(path))
    assert scope.hosts == ()
    assert scope.check("http://localhost:5117/", "S1").refused


def test_config_rejects_wildcards(tmp_path):
    path = tmp_path / "scope.toml"
    path.write_text('[scope]\nhosts = ["*.localhost:5117"]\n')
    with pytest.raises(ScopeConfigError):
        load_scope_config(path)


def test_every_decision_is_logged_with_required_fields(tmp_path):
    log_path = tmp_path / "scope.jsonl"
    logger = JsonlLogger(log_path)
    guard = ScopeGuard(Scope(["127.0.0.1:5117"]), logger, "r-test", "scan_xss")

    guard.check("http://127.0.0.1:5117/body", "S1")
    guard.check("http://evil.test:80/", "S1")

    lines = [json.loads(line) for line in log_path.read_text().splitlines()]
    assert len(lines) == 2
    assert lines[0]["event"] == "allow"
    assert lines[1]["event"] == "refuse"
    for line in lines:
        assert line["ts"]
        assert line["run_id"] == "r-test"
        assert line["tool"] == "scan_xss"
        assert line["checkpoint"] == "S1"
    assert lines[1]["host"] == "evil.test:80"
    assert lines[1]["reason"] == "host_not_allowlisted"


def test_log_never_contains_a_body(tmp_path):
    log_path = tmp_path / "scope.jsonl"
    logger = JsonlLogger(log_path)
    logger.log(
        event="refuse",
        run_id="r",
        tool="scan_xss",
        url="http://evil.test/",
        host="evil.test:80",
        reason="host_not_allowlisted",
        detail="<html>SECRET BODY</html>",
    )
    # Detail is caller-supplied; the logger's API has no body field at all.
    record = json.loads(log_path.read_text())
    assert set(record) == {
        "ts", "event", "run_id", "tool", "url", "host", "reason", "checkpoint", "detail"
    }
