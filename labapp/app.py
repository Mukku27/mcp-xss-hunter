"""A deliberately vulnerable local lab.

This app exists so every acceptance test is reproducible from a clean clone
without pulling a third-party container. It binds 127.0.0.1 only, sends no
external requests, and must never be deployed anywhere.

Every route is intentionally unsafe. The point is to make the four injection
contexts and one reflection-only negative case deterministic.
"""

from __future__ import annotations

import html
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

BANNER = (
    '<div style="border:2px solid #b00;padding:8px;margin-bottom:16px;'
    'font-family:monospace">DELIBERATELY VULNERABLE LAB. LOCALHOST ONLY. '
    "DO NOT DEPLOY.</div>"
)


def _param(query: str, name: str = "q") -> str:
    values = parse_qs(query, keep_blank_values=True).get(name)
    return values[0] if values else ""


def _page(title: str, body: str) -> bytes:
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        f"<title>{title}</title></head><body>{BANNER}{body}</body></html>"
    ).encode("utf-8")


class LabHandler(BaseHTTPRequestHandler):
    server_version = "XSSHunterLab/0.1"

    def _send(self, body: bytes, status: int = 200, content_type: str = "text/html; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Lab-Warning", "deliberately-vulnerable-localhost-only")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        # Keep pytest/demo output readable; the tool's own JSONL log is the record.
        return

    def do_GET(self):  # noqa: N802 - stdlib naming
        parsed = urlsplit(self.path)
        route = parsed.path
        q = _param(parsed.query)

        if route == "/health":
            return self._send(b"ok", content_type="text/plain")
        if route == "/":
            links = "".join(
                f'<li><a href="{path}?q=test">{path}</a></li>'
                for path in (
                    "/body", "/attribute", "/script", "/url",
                    "/encoded", "/multi", "/textarea", "/json",
                )
            )
            return self._send(_page("lab", f"<ul>{links}</ul>"))
        if route == "/body":
            # C1: raw marker lands directly in a text node.
            return self._send(_page("body", f"<div>Results for: {q}</div>"))
        if route == "/attribute":
            # C2: raw marker inside a double-quoted attribute value.
            return self._send(
                _page("attribute", f'<input id="search" value="{q}" autocomplete="off">')
            )
        if route == "/script":
            # C3: raw marker inside a double-quoted JavaScript string.
            return self._send(
                _page(
                    "script",
                    '<div id="out"></div>'
                    f'<script>var q = "{q}"; document.getElementById("out").textContent = q;</script>',
                )
            )
        if route == "/url":
            # C4: raw marker in a URL-bearing attribute.
            return self._send(
                _page("url", f'<a id="go" href="{q}">open</a>')
            )
        if route == "/textarea":
            # C1 sub-context: RCDATA, needs a closing tag to break out.
            return self._send(_page("textarea", f"<textarea>{q}</textarea>"))
        if route == "/json":
            # C3 sub-context: JSON inside a script element.
            return self._send(
                _page(
                    "json",
                    f'<script type="application/json">{{"q":"{q}"}}</script>'
                    '<div id="out">json</div>',
                )
            )
        if route == "/multi":
            # Two reflection points with different contexts in one response.
            return self._send(
                _page(
                    "multi",
                    f'<div>Results for: {q}</div><input value="{q}">',
                )
            )
        if route == "/external":
            # A reflected parameter plus one off-scope subresource. The probe
            # sees only the HTML; the browser's S5 fence must stop the image.
            target = _param(parsed.query, "to")
            return self._send(
                _page(
                    "external",
                    f'<div>Results for: {q}</div>'
                    f'<img id="extern" src="{target}" alt="external">',
                )
            )
        if route == "/encoded":
            # The negative case: the marker reflects, but every dangerous
            # character is HTML-encoded, so no payload can break out.
            safe = html.escape(q, quote=True)
            return self._send(_page("encoded", f"<div>Results for: {safe}</div>"))
        if route == "/redirect":
            # An open redirector used to prove the hop check. No fetch here.
            target = _param(parsed.query, "to")
            if not target:
                return self._send(b"missing to", status=400, content_type="text/plain")
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Content-Length", "0")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return None
        if route == "/redirect-missing":
            # A malformed redirect: 302 with no Location. Must fail closed.
            self.send_response(302)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return None
        if route == "/loop":
            # An endless redirect used to prove the hop cap.
            self.send_response(302)
            self.send_header("Location", "/loop")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return None

        if route == "/meta":
            # A browser-level redirect target, used to exercise the S5 fence.
            # q is reflected so the probe can reach this page before the browser
            # follows the refresh.
            target = _param(parsed.query, "to")
            return self._send(
                _page(
                    "meta",
                    f'<div>Results for: {q}</div>'
                    f'<meta http-equiv="refresh" content="0;url={target}">',
                )
            )

        return self._send(_page("not found", "<p>not found</p>"), status=404)


def make_server(port: int = 5117) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", port), LabHandler)
    server.daemon_threads = True
    return server


def main() -> None:
    port = int(os.environ.get("XSS_HUNTER_LAB_PORT", "5117"))
    server = make_server(port)
    print(
        f"Deliberately vulnerable lab on http://127.0.0.1:{server.server_port} "
        "(localhost only; do not deploy)",
        file=sys.stderr,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
