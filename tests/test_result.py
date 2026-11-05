"""Output bounding: the agent gets a small, valid, complete-enough result."""

from __future__ import annotations

import json

from xss_hunter.models import (
    Blocked,
    Finding,
    Held,
    Limits,
    ReplayProof,
    ScanResponse,
    ScopeRefusal,
    Target,
    Totals,
)
from xss_hunter.result import MAX_BYTES, bound_scan, serialized_bytes

NONCE = "xshdeadbeef"


def finding(index: int = 0, url: str = "http://127.0.0.1:5117/body") -> Finding:
    return Finding(
        finding_id=f"f-{index:012x}",
        url=url,
        parameter="q",
        context="html_body",
        sub_context="html_text",
        payload=f"<img src=x onerror=alert('{NONCE}')>",
        nonce=NONCE,
        signal="dialog",
        signal_detail=f"dialog message contained the nonce: {NONCE}",
        requires_interaction=False,
        replay=ReplayProof(
            verified=True, session="fresh", nonce=NONCE, signal="dialog"
        ),
        evidence=f"evidence/127_0_0_1_5117/r-20261105T000000Z-{index:04x}/findings/f-{index:012x}",
        reproduce=f'scan_xss(url="{url}", parameter="q")',
        browser="chromium/156.0.8078.4",
        timestamp="2026-11-05T00:00:00.000+00:00",
    )


def held(index: int = 0) -> Held:
    return Held(
        context="html_body",
        sub_context="html_text",
        reason="payload_did_not_execute",
        detail=(
            "the nonce was reflected but no dialog, DOM marker, or console "
            f"message carried it after two independent loads (attempt {index})"
        ),
        payloads_tried=1,
    )


def blocked(index: int = 0) -> Blocked:
    return Blocked(
        stage="replay",
        reason=f"non_deterministic_{index}",
        needs="a payload that executes on both independent loads",
    )


def refusal(index: int = 0) -> ScopeRefusal:
    return ScopeRefusal(
        ts="2026-11-05T00:00:00.000+00:00",
        host=f"evil{index}.test:80",
        url=f"http://evil{index}.test:80/never",
        reason="host_not_allowlisted",
        checkpoint="S1",
    )


def response(*, url: str = "http://127.0.0.1:5117/body") -> ScanResponse:
    return ScanResponse(
        status="completed",
        run_id="r-20261105T000000Z-abcd",
        target=Target(url=url, host="127.0.0.1:5117", scope="allowed"),
        parameter="q",
        limits=Limits(
            duration_ms=1200,
            http_requests=12,
            payloads_sent=4,
            browser_contexts=2,
        ),
        totals=Totals(confirmed=0, tested_held=0, could_not_proceed=0),
    )


def test_arrays_are_capped_and_totals_report_the_real_run():
    original = response().model_copy(
        update={
            "confirmed": [finding(i) for i in range(6)],
            "tested_held": [held(i) for i in range(9)],
            "could_not_proceed": [blocked(i) for i in range(5)],
            "scope_refusals": [refusal(i) for i in range(6)],
        }
    )

    bounded = bound_scan(original)

    assert len(bounded.confirmed) == 3
    assert len(bounded.tested_held) == 4
    assert len(bounded.could_not_proceed) == 2
    assert len(bounded.scope_refusals) == 2
    assert bounded.totals.confirmed == 6
    assert bounded.totals.tested_held == 9
    assert bounded.totals.could_not_proceed == 5
    assert bounded.truncated is True


def test_a_long_response_stays_under_the_byte_budget_and_is_valid_json():
    long_url = "http://127.0.0.1:5117/" + ("a" * 2000)
    original = response(url=long_url).model_copy(
        update={
            "confirmed": [finding(i, long_url) for i in range(8)],
            "tested_held": [held(i) for i in range(12)],
            "could_not_proceed": [blocked(i) for i in range(6)],
            "scope_refusals": [refusal(i) for i in range(8)],
        }
    )

    bounded = bound_scan(original)
    encoded = json.dumps(bounded.model_dump(mode="json"), ensure_ascii=False)

    assert serialized_bytes(bounded) <= MAX_BYTES
    assert json.loads(encoded)["run_id"] == original.run_id
    assert bounded.totals.confirmed == 8
    assert bounded.truncated is True
    assert "<html" not in encoded.lower()
    assert "<!doctype" not in encoded.lower()


def test_a_normal_result_is_not_truncated():
    original = response().model_copy(
        update={"confirmed": [finding()], "tested_held": [held()]}
    )

    bounded = bound_scan(original)

    assert serialized_bytes(bounded) <= MAX_BYTES
    assert len(bounded.confirmed) == 1
    assert len(bounded.tested_held) == 1
    assert bounded.truncated is False
