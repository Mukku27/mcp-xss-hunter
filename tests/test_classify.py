"""M3: the classifier names the syntax around every marker occurrence."""

from __future__ import annotations

import pytest

from xss_hunter.classify import classify, distinct_points

MARKER = "xshmarker01"


@pytest.mark.parametrize(
    ("body", "context", "sub_context", "tag", "attribute", "quote"),
    [
        # C1: HTML body.
        (f"<div>Results for: {MARKER}</div>", "html_body", "html_text", None, None, None),
        (f"<p class='x'>{MARKER}</p>", "html_body", "html_text", None, None, None),
        (f"<textarea>{MARKER}</textarea>", "html_body", "html_textarea", "textarea", None, None),
        (f"<title>{MARKER}</title>", "html_body", "html_title", "title", None, None),
        (f"<style>.x{{color:red}}{MARKER}</style>", "html_body", "html_style", "style", None, None),
        # C2: attribute values and handlers.
        (f'<input value="{MARKER}">', "attribute", "quoted_double", "input", "value", '"'),
        (f"<input value='{MARKER}'>", "attribute", "quoted_single", "input", "value", "'"),
        (f"<input value={MARKER}>", "attribute", "unquoted", "input", "value", None),
        (
            f'<button onclick="alert(\'{MARKER}\')">go</button>',
            "attribute",
            "event_handler",
            "button",
            "onclick",
            '"',
        ),
        # C3: script CDATA.
        (f'<script>var q = "{MARKER}";</script>', "script", "js_string_double", "script", None, None),
        (f"<script>var q = '{MARKER}';</script>", "script", "js_string_single", "script", None, None),
        (f"<script>var q = `{MARKER}`;</script>", "script", "js_template", "script", None, None),
        (f"<script>var q = {MARKER};</script>", "script", "js_raw", "script", None, None),
        (
            f'<script type="application/json">{{"q":"{MARKER}"}}</script>',
            "script",
            "js_json",
            "script",
            None,
            None,
        ),
        (f"<script>var q = 1; // {MARKER}\n</script>", "script", "js_comment", "script", None, None),
        (f"<script>var q = 1; /* {MARKER} */</script>", "script", "js_comment", "script", None, None),
        # C4: URL-bearing attributes.
        (f'<a href="{MARKER}">open</a>', "url", "href", "a", "href", '"'),
        (f"<img src='{MARKER}'>", "url", "src", "img", "src", "'"),
        (f"<form action={MARKER}>", "url", "action", "form", "action", None),
        # Unsupported-but-recognized contexts still get a name.
        (f"<!-- {MARKER} -->", "html_body", "html_comment", None, None, None),
        (f"<div {MARKER}='x'></div>", "attribute", "attribute_name", "div", MARKER.lower(), None),
    ],
)
def test_context_table(body, context, sub_context, tag, attribute, quote):
    points = classify(body, MARKER)

    assert len(points) == 1
    point = points[0]
    assert point.offset == body.index(MARKER)
    assert (point.context, point.sub_context) == (context, sub_context)
    assert point.tag == tag
    assert point.attribute == attribute
    assert point.quote == quote
    assert point.snippet


def test_offsets_follow_multiline_documents():
    body = "<!doctype html>\n<html>\n  <body>\n    <div>hello " + MARKER + "</div>\n  </body>\n</html>"
    point = classify(body, MARKER)[0]
    assert point.offset == body.index(MARKER)
    assert point.context == "html_body"


def test_each_occurrence_is_classified_independently():
    body = f'<div>Results for: {MARKER}</div><input value="{MARKER}">'
    points = classify(body, MARKER)

    assert [point.offset for point in points] == [
        body.index(MARKER),
        body.rindex(MARKER),
    ]
    assert [(p.context, p.sub_context) for p in points] == [
        ("html_body", "html_text"),
        ("attribute", "quoted_double"),
    ]


def test_distinct_points_collapses_identical_contexts_but_keeps_order():
    body = f'<p>{MARKER}</p><p>{MARKER}</p><input value="{MARKER}">'
    points = classify(body, MARKER)
    assert len(points) == 3

    unique = distinct_points(points)
    assert [(p.context, p.sub_context) for p in unique] == [
        ("html_body", "html_text"),
        ("attribute", "quoted_double"),
    ]
    assert unique[0].offset == points[0].offset


def test_no_marker_returns_no_points():
    assert classify("<div>nothing here</div>", MARKER) == []


def test_malformed_markup_does_not_raise_and_names_the_text_context():
    body = f'<div value="unterminated {MARKER}'
    points = classify(body, MARKER)

    assert len(points) == 1
    assert points[0].offset == body.index(MARKER)
    assert points[0].context in {"html_body", "attribute"}


def test_script_breakout_after_an_escaped_quote_is_still_script_data():
    body = f'<script>var q = "a\\"{MARKER}";</script>'
    point = classify(body, MARKER)[0]
    assert (point.context, point.sub_context) == ("script", "js_string_double")
