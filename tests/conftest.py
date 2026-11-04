"""Shared fixtures: a canary server that must never be reached, and the lab."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


class _CanaryHandler(BaseHTTPRequestHandler):
    hits: list[str] = []

    def do_GET(self):  # noqa: N802 - stdlib naming
        type(self).hits.append(self.path)
        body = b"canary"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # keep test output clean
        return


@pytest.fixture
def canary():
    """An out-of-scope HTTP server with a hit counter."""
    hits: list[str] = []
    handler = type("CanaryHandler", (_CanaryHandler,), {"hits": hits})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", hits
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.fixture
def lab():
    """The bundled vulnerable app on an ephemeral localhost port."""
    from labapp.app import make_server

    server = make_server(0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host = f"127.0.0.1:{server.server_port}"
    try:
        yield f"http://{host}", host, server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

