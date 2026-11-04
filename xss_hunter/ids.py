"""Small deterministic identifiers.

A finding ID is stable across runs for the same target + parameter + context +
payload family, so a later run can ask "does this still reproduce?" without
depending on a nonce. Scheduling and diffing are deliberately out of scope.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from datetime import datetime, timezone
from urllib.parse import urlsplit

_FINDING_RE = re.compile(r"^f-[0-9a-f]{12}$")


def new_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"r-{stamp}-{secrets.token_hex(2)}"


def new_nonce() -> str:
    # Alphanumeric so it survives HTML/JS/URL quoting untouched. The browser
    # signal must contain this exact value.
    return f"xsh{secrets.token_hex(4)}"


def target_slug(host: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", host.lower()).strip("_")
    return slug or "unknown"


def finding_id(host: str, path: str, parameter: str, context: str, family: str) -> str:
    material = "\x1f".join((host.lower(), path or "/", parameter, context, family))
    return "f-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]


def is_finding_id(value: str) -> bool:
    return bool(_FINDING_RE.fullmatch(value))


def path_of(url: str) -> str:
    try:
        return urlsplit(url).path or "/"
    except ValueError:
        return "/"
