"""M3: payloads are context-matched, nonce-stamped, and non-destructive."""

from __future__ import annotations

import pytest

from xss_hunter.classify import InjectionPoint
from xss_hunter.payloads import (
    NONCE_SLOT,
    PAYLOADS,
    select,
    select_override,
)

NONCE = "xshabc12345"


def point(context, sub_context, *, attribute=None, quote=None):
    return InjectionPoint(
        offset=0,
        context=context,
        sub_context=sub_context,
        tag=None,
        attribute=attribute,
        quote=quote,
        snippet="",
    )


@pytest.mark.parametrize(
    ("context", "sub_context", "attribute", "quote", "family", "prefix", "interaction"),
    [
        ("html_body", "html_text", None, None, "html_text", "<img", False),
        ("html_body", "html_textarea", None, None, "html_textarea", "</textarea>", False),
        ("html_body", "html_title", None, None, "html_title", "</title>", False),
        ("html_body", "html_style", None, None, "html_style", "</style>", False),
        ("attribute", "quoted_double", "value", '"', "attribute_double", '">', False),
        ("attribute", "quoted_single", "value", "'", "attribute_single", "'>", False),
        ("attribute", "unquoted", "value", None, "attribute_unquoted", "x>", False),
        ("attribute", "event_handler", "onclick", '"', "attribute_event", '">', False),
        ("attribute", "event_handler", "onclick", "'", "attribute_event", "'>", False),
        ("attribute", "event_handler", "onclick", None, "attribute_event", "x>", False),
        ("script", "js_string_double", None, None, "script_breakout", "</script>", False),
        ("script", "js_string_single", None, None, "script_breakout", "</script>", False),
        ("script", "js_template", None, None, "script_breakout", "</script>", False),
        ("script", "js_raw", None, None, "script_breakout", "</script>", False),
        ("script", "js_json", None, None, "script_breakout", "</script>", False),
        ("script", "js_comment", None, None, "script_breakout", "</script>", False),
        ("url", "href", "href", '"', "url_javascript", "javascript:", True),
        ("url", "action", "action", "'", "url_javascript", "javascript:", True),
        ("url", "src", "src", '"', "url_breakout", '">', False),
        ("url", "src", "src", "'", "url_breakout", "'>", False),
        ("url", "src", "src", None, "url_breakout", "x>", False),
    ],
)
def test_selection_matches_the_classified_context(
    context, sub_context, attribute, quote, family, prefix, interaction
):
    attempt = select(point(context, sub_context, attribute=attribute, quote=quote), NONCE)

    assert attempt is not None
    assert attempt.family == family
    assert attempt.payload.startswith(prefix)
    assert NONCE in attempt.payload
    assert attempt.requires_interaction is interaction


@pytest.mark.parametrize(
    "context,sub_context,attribute,quote",
    [
        ("html_body", "html_comment", None, None),
        ("html_body", "unclassified", None, None),
        ("attribute", "attribute_name", "value", None),
        ("attribute", "tag_syntax", None, None),
    ],
)
def test_unsupported_contexts_have_no_payload(context, sub_context, attribute, quote):
    assert select(point(context, sub_context, attribute=attribute, quote=quote), NONCE) is None


def test_every_payload_has_exactly_one_nonce_slot():
    for payload in PAYLOADS:
        assert payload.template.count(NONCE_SLOT) == 1, payload.family
        rendered = payload.template.replace(NONCE_SLOT, NONCE)
        assert rendered.count(NONCE) == 1, payload.family
        assert NONCE_SLOT not in rendered, payload.family


def test_payloads_are_non_destructive():
    forbidden = (
        "fetch(",
        "XMLHttpRequest",
        "document.cookie",
        "document.domain",
        "localStorage",
        "sessionStorage",
        "indexedDB",
        "eval(",
        "window.open",
        "import(",
        "http://",
        "https://",
        "location=",
        "top.location",
    )
    for payload in PAYLOADS:
        for token in forbidden:
            assert token not in payload.template, (payload.family, token)


def test_select_renders_the_requested_nonce_once():
    attempt = select(point("html_body", "html_text"), NONCE)
    assert attempt.payload.count(NONCE) == 1
    assert NONCE_SLOT not in attempt.payload


@pytest.mark.parametrize(
    ("context", "family", "interaction"),
    [
        ("html_body", "html_text", False),
        ("attribute", "attribute_double", False),
        ("script", "script_breakout", False),
        ("url", "url_javascript", True),
    ],
)
def test_reviewer_override_uses_the_primary_payload(context, family, interaction):
    attempt = select_override(context, NONCE)

    assert attempt.context == context
    assert attempt.sub_context == "reviewer_override"
    assert attempt.family == family
    assert attempt.requires_interaction is interaction
    assert NONCE in attempt.payload
