"""Classify where a marker landed, one occurrence at a time.

The HTML parser is the stdlib tokenizer, not a regex over the whole body. It
gives us tag ranges, script CDATA ranges, RCDATA ranges, and comments; a small
per-tag attribute scanner and a small JS string scanner finish the job.

A wrong classification can only choose a payload that fails to execute. The
browser remains the arbiter, so a parser mistake can never create a finding.
"""

from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser

URL_ATTRIBUTES = frozenset({
    "href", "src", "action", "formaction", "data", "poster", "background",
    "cite", "longdesc", "usemap", "manifest", "ping", "srcset", "base",
})
RCDATA_TAGS = frozenset({"textarea", "title"})


@dataclass(frozen=True)
class InjectionPoint:
    offset: int
    context: str  # html_body | attribute | script | url
    sub_context: str
    tag: str | None
    attribute: str | None
    quote: str | None
    snippet: str


@dataclass(frozen=True)
class _Region:
    start: int
    end: int


@dataclass(frozen=True)
class _TagRegion:
    tag: str
    start: int
    end: int
    raw: str


@dataclass(frozen=True)
class _Attribute:
    name: str
    name_start: int
    name_end: int
    value_start: int | None
    value_end: int | None
    quote: str | None


class _RegionParser(HTMLParser):
    def __init__(self, body: str):
        super().__init__(convert_charrefs=False)
        self.body = body
        self.line_starts = [0] + [i + 1 for i, ch in enumerate(body) if ch == "\n"]
        self.tags: list[_TagRegion] = []
        self.scripts: list[tuple[_Region, str]] = []
        self.styles: list[_Region] = []
        self.rcdata: list[tuple[_Region, str]] = []
        self.comments: list[_Region] = []
        self._cdata_tag: str | None = None
        self._cdata_start: int | None = None
        self._cdata_type: str = ""
        self._rcdata_tag: str | None = None
        self._rcdata_start: int | None = None

    def _absolute(self) -> int:
        line, column = self.getpos()
        if 1 <= line <= len(self.line_starts):
            return self.line_starts[line - 1] + column
        return 0

    def _close_cdata(self, end: int) -> None:
        if self._cdata_tag == "script" and self._cdata_start is not None:
            self.scripts.append((_Region(self._cdata_start, end), self._cdata_type))
        elif self._cdata_tag == "style" and self._cdata_start is not None:
            self.styles.append(_Region(self._cdata_start, end))
        self._cdata_tag = None
        self._cdata_start = None
        self._cdata_type = ""

    def _close_rcdata(self, end: int) -> None:
        if self._rcdata_tag and self._rcdata_start is not None:
            self.rcdata.append((_Region(self._rcdata_start, end), self._rcdata_tag))
        self._rcdata_tag = None
        self._rcdata_start = None

    def handle_starttag(self, tag, attrs):  # noqa: N802 - stdlib naming
        tag = tag.lower()
        raw = self.get_starttag_text() or ""
        start = self._absolute()
        self.tags.append(_TagRegion(tag, start, start + len(raw), raw))

        if self._cdata_tag is not None or self._rcdata_tag is not None:
            return
        if tag in {"script", "style"}:
            self._cdata_tag = tag
            self._cdata_start = start + len(raw)
            self._cdata_type = dict(attrs).get("type", "") or ""
        elif tag in RCDATA_TAGS:
            self._rcdata_tag = tag
            self._rcdata_start = start + len(raw)

    def handle_endtag(self, tag):  # noqa: N802
        tag = tag.lower()
        position = self._absolute()
        if self._cdata_tag == tag:
            self._close_cdata(position)
        elif self._rcdata_tag == tag:
            self._close_rcdata(position)

    def handle_comment(self, data):  # noqa: N802
        start = self._absolute()
        self.comments.append(_Region(start, start + len(data) + 7))

    def close(self):
        super().close()
        self._close_cdata(len(self.body))
        self._close_rcdata(len(self.body))


def _scan_attributes(raw: str) -> list[_Attribute]:
    """Small deterministic scanner over one raw start tag."""
    attrs: list[_Attribute] = []
    i = 1
    while i < len(raw) and not raw[i].isspace() and raw[i] not in "/>":
        i += 1

    def skip_space(index: int) -> int:
        while index < len(raw) and raw[index].isspace():
            index += 1
        return index

    while i < len(raw):
        i = skip_space(i)
        while i < len(raw) and raw[i] == "/":
            i += 1
            i = skip_space(i)
        if i >= len(raw) or raw[i] == ">":
            break

        name_start = i
        while i < len(raw) and not raw[i].isspace() and raw[i] not in "=/>":
            i += 1
        name_end = i
        name = raw[name_start:name_end].lower()
        i = skip_space(i)

        quote: str | None = None
        value_start: int | None = None
        value_end: int | None = None
        if i < len(raw) and raw[i] == "=":
            i += 1
            i = skip_space(i)
            if i < len(raw) and raw[i] in "\"'":
                quote = raw[i]
                i += 1
                value_start = i
                while i < len(raw) and raw[i] != quote:
                    i += 1
                value_end = i
                if i < len(raw):
                    i += 1
            else:
                value_start = i
                while i < len(raw) and not raw[i].isspace() and raw[i] != ">":
                    i += 1
                value_end = i
        attrs.append(
            _Attribute(
                name=name,
                name_start=name_start,
                name_end=name_end,
                value_start=value_start,
                value_end=value_end,
                quote=quote,
            )
        )
    return attrs


def _js_context(content: str, position: int, script_type: str) -> str:
    if "json" in script_type.lower():
        return "js_json"
    state = "code"
    quote = ""
    i = 0
    while i < position:
        if state == "string":
            if content[i] == "\\":
                i += 2
                continue
            if content[i] == quote:
                state = "code"
                quote = ""
            i += 1
            continue
        if content.startswith("//", i):
            end = content.find("\n", i)
            if end == -1 or position < end:
                return "js_comment"
            i = end + 1
            continue
        if content.startswith("/*", i):
            end = content.find("*/", i + 2)
            if end == -1 or position < end:
                return "js_comment"
            i = end + 2
            continue
        ch = content[i]
        if ch in "'\"`":
            state = "string"
            quote = ch
        i += 1
    if state == "string":
        return {"'": "js_string_single", '"': "js_string_double", "`": "js_template"}[quote]
    return "js_raw"


def _snippet(body: str, offset: int, length: int, width: int = 40) -> str:
    left = max(0, offset - width)
    right = min(len(body), offset + length + width)
    text = " ".join(body[left:right].replace("\x00", " ").split())
    return text[:120]


def _classify_offset(
    body: str,
    offset: int,
    marker: str,
    parser: _RegionParser,
) -> InjectionPoint:
    length = len(marker)
    snippet = _snippet(body, offset, length)

    # 1. Inside a start tag: attribute context (including URL-bearing attrs).
    for region in parser.tags:
        if region.start <= offset < region.end:
            relative = offset - region.start
            for attr in _scan_attributes(region.raw):
                if attr.value_start is not None and attr.value_start <= relative < attr.value_end:
                    if attr.name in URL_ATTRIBUTES:
                        return InjectionPoint(
                            offset, "url", attr.name, region.tag, attr.name, attr.quote, snippet
                        )
                    if attr.name.startswith("on") and len(attr.name) > 2:
                        return InjectionPoint(
                            offset, "attribute", "event_handler", region.tag,
                            attr.name, attr.quote, snippet
                        )
                    sub = {
                        '"': "quoted_double",
                        "'": "quoted_single",
                        None: "unquoted",
                    }[attr.quote]
                    return InjectionPoint(
                        offset, "attribute", sub, region.tag, attr.name, attr.quote, snippet
                    )
                if attr.name_start <= relative < attr.name_end:
                    return InjectionPoint(
                        offset, "attribute", "attribute_name", region.tag, attr.name, None, snippet
                    )
            return InjectionPoint(offset, "attribute", "tag_syntax", region.tag, None, None, snippet)

    # 2. Inside a script element: JS context.
    for region, script_type in parser.scripts:
        if region.start <= offset < region.end:
            content = body[region.start:region.end]
            return InjectionPoint(
                offset,
                "script",
                _js_context(content, offset - region.start, script_type),
                "script",
                None,
                None,
                snippet,
            )

    # 3. Inside RCDATA or style: still HTML-like, but needs a specific breakout.
    for region, tag in parser.rcdata:
        if region.start <= offset < region.end:
            return InjectionPoint(offset, "html_body", f"html_{tag}", tag, None, None, snippet)
    for region in parser.styles:
        if region.start <= offset < region.end:
            return InjectionPoint(offset, "html_body", "html_style", "style", None, None, snippet)

    # 4. Inside a comment: parser cannot break out, so it is not a sink.
    for region in parser.comments:
        if region.start <= offset < region.end:
            return InjectionPoint(offset, "html_body", "html_comment", None, None, None, snippet)

    return InjectionPoint(offset, "html_body", "html_text", None, None, None, snippet)


def classify(body: str, marker: str) -> list[InjectionPoint]:
    """Return one point per marker occurrence, in document order."""
    offsets: list[int] = []
    start = 0
    while True:
        index = body.find(marker, start)
        if index == -1:
            break
        offsets.append(index)
        start = index + len(marker)
    if not offsets:
        return []

    parser = _RegionParser(body)
    try:
        parser.feed(body)
        parser.close()
    except Exception:
        # Lenient failure is safe: no payload is chosen from a failed parse.
        return [
            InjectionPoint(offset, "html_body", "unclassified", None, None, None, "")
            for offset in offsets
        ]

    return [_classify_offset(body, offset, marker, parser) for offset in offsets]


def distinct_points(points: list[InjectionPoint]) -> list[InjectionPoint]:
    """One attempt per distinct (context, sub_context), first occurrence wins."""
    seen: set[tuple[str, str]] = set()
    unique: list[InjectionPoint] = []
    for point in points:
        key = (point.context, point.sub_context)
        if key not in seen:
            seen.add(key)
            unique.append(point)
    return unique
