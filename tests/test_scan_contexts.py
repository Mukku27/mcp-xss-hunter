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


def test_a_product_page_reflection_is_confirmed_on_a_non_default_parameter(lab, tmp_path):
    """A storefront page buries the same attribute sink behind a realistic name."""
    base, host, _ = lab
    result = scan(
        url=f"{base}/products?sku=VF-101",
        parameter="sku",
        context_override=None,
        scope=Scope([host]),
        logger=JsonlLogger(tmp_path / "scope.jsonl"),
        evidence_dir=tmp_path / "evidence",
    )

    assert result.status == "completed"
    assert len(result.confirmed) == 1
    finding = result.confirmed[0]
    assert (finding.context, finding.sub_context) == ("attribute", "quoted_double")
    assert finding.parameter == "sku"
    assert finding.replay.verified is True


def test_a_lookalike_page_that_only_escapes_reflects_but_never_confirms(lab, tmp_path):
    """Same layout, every echo escaped: a held result, never a finding."""
    base, host, _ = lab
    result = run(f"{base}/reviews", host, tmp_path)

    assert result.status == "completed"
    assert result.confirmed == []
    assert [held.reason for held in result.tested_held] == ["payload_did_not_execute"]


def test_the_storefront_does_not_announce_the_acceptance_fixtures():
    """The canonical routes stay live but are linked from nowhere."""
    from urllib.request import urlopen

    from labapp.app import make_server
    import threading

    server = make_server(0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with urlopen(f"http://127.0.0.1:{server.server_port}/", timeout=5) as response:
            body = response.read().decode("utf-8")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert "Verity" in body
    for fixture in ("/body", "/attribute", "/script", "/url", "/encoded", "/multi"):
        assert f'href="{fixture}"' not in body
