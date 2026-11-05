"""Full pipeline for the attribute and script context families (AC-05)."""

from __future__ import annotations

from pathlib import Path

from xss_hunter.logging_jsonl import JsonlLogger
from xss_hunter.scan import scan
from xss_hunter.scope import Scope


def run(url, host, tmp_path):
    return scan(
        url=url,
        parameter="q",
        context_override=None,
        scope=Scope([host]),
        logger=JsonlLogger(tmp_path / "scope.jsonl"),
        evidence_dir=tmp_path / "evidence",
    )


def test_attribute_context_is_confirmed_with_a_quote_breakout(lab, tmp_path):
    base, host, _ = lab
    result = run(f"{base}/attribute", host, tmp_path)

    assert result.status == "completed"
    assert len(result.confirmed) == 1
    finding = result.confirmed[0]
    assert (finding.context, finding.sub_context) == ("attribute", "quoted_double")
    assert finding.payload.startswith('">')
    assert finding.signal == "dialog"
    assert finding.requires_interaction is False
    assert finding.replay.verified is True


def test_script_context_is_confirmed_with_an_element_breakout(lab, tmp_path):
    base, host, _ = lab
    result = run(f"{base}/script", host, tmp_path)

    assert result.status == "completed"
    assert len(result.confirmed) == 1
    finding = result.confirmed[0]
    assert (finding.context, finding.sub_context) == ("script", "js_string_double")
    assert finding.payload.startswith("</script>")
    assert finding.signal == "dialog"
    assert finding.requires_interaction is False
    assert finding.replay.verified is True
