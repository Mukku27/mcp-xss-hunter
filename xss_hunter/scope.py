"""The single scope decision.

Every URL that the tool is about to request is normalized and matched here.
There is deliberately no code path that returns "allowed" on an error: every
unexpected input becomes a refusal with a typed reason.

Matching rules (see README):
  * exact normalized ``host:port``; ports always participate;
  * a URL with no port is normalized to the scheme default (80/443);
  * lowercase, trailing dot stripped, IDN converted to punycode;
  * userinfo, non-http(s) schemes, backslashes, control characters and
    percent-encoded hosts are refused;
  * wildcards are not supported and are rejected at config load time;
  * an empty allowlist refuses everything.
"""

from __future__ import annotations

import ipaddress
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import unquote, urlsplit, urlunsplit

ALLOWED_SCHEMES = frozenset({"http", "https"})
DEFAULT_PORTS = {"http": 80, "https": 443}

# ASCII hostnames plus underscore (some lab vhosts use it). IPv6 is handled
# separately. IDN input is converted to punycode before this check.
_HOST_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9._-]*[a-z0-9_])?$")
_ENTRY_RE = re.compile(r"^\[[0-9a-f:.]+\]:\d{1,5}$|^[a-z0-9_](?:[a-z0-9._-]*[a-z0-9_])?:\d{1,5}$")


class ScopeConfigError(ValueError):
    """The allowlist file is malformed. The caller must deny everything."""


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    url: str
    host: str
    reason: str
    checkpoint: str
    detail: str = ""

    @property
    def refused(self) -> bool:
        return not self.allowed


def _normalize_host(raw_host: str) -> str:
    """Return a lowercase ASCII host without brackets or a trailing dot."""
    host = raw_host.strip().lower()
    if not host:
        raise ValueError("missing_host")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    host = host.rstrip(".")
    if not host:
        raise ValueError("missing_host")

    # An IPv6 literal is the only host that may contain a colon after
    # urlsplit has removed the brackets.
    if ":" in host:
        try:
            return str(ipaddress.IPv6Address(host))
        except ValueError as exc:
            raise ValueError("invalid_host") from exc

    if "%" in host:
        # Percent-decoding a host is a parser-differential trap; refuse it
        # rather than guess what another parser will do.
        raise ValueError("encoded_host")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid_host") from exc
    if not _HOST_RE.fullmatch(host):
        raise ValueError("invalid_host")
    return host


def normalize_url(raw_url: str) -> tuple[str, str]:
    """Normalize a target URL.

    Returns ``(url, host_key)``. Raises ``ValueError`` with a short reason on
    anything ambiguous. The returned URL is rebuilt from parsed components so
    the rest of the program never hands a raw user string to a client.
    """
    if not isinstance(raw_url, str) or not raw_url:
        raise ValueError("missing_url")
    if len(raw_url) > 2048:
        raise ValueError("url_too_long")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in raw_url):
        raise ValueError("control_characters")
    if any(ch.isspace() for ch in raw_url):
        raise ValueError("whitespace_in_url")
    if "\\" in raw_url:
        raise ValueError("backslash_in_url")

    try:
        parsed = urlsplit(raw_url)
    except ValueError as exc:
        raise ValueError("malformed_url") from exc

    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise ValueError("scheme_not_allowed")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        # http://allowed@evil/ -- never read the host from the wrong side of @.
        raise ValueError("userinfo_not_allowed")
    if not parsed.hostname:
        raise ValueError("missing_host")

    try:
        host = _normalize_host(parsed.hostname)
        port = parsed.port if parsed.port is not None else DEFAULT_PORTS[scheme]
    except ValueError as exc:
        reason = str(exc)
        if reason not in {"missing_host", "invalid_host", "encoded_host"}:
            reason = "invalid_port"
        raise ValueError(reason) from exc
    if not 1 <= port <= 65535:
        raise ValueError("invalid_port")

    # Percent-encoded CR/LF/NUL could change the meaning of a request in
    # another parser. Refuse them in every component we send.
    for component in (parsed.path, parsed.query, parsed.fragment):
        decoded = unquote(component)
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in decoded):
            raise ValueError("control_characters")

    host_key = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    path = parsed.path or "/"
    normalized = urlunsplit((scheme, host_key, path, parsed.query, parsed.fragment))
    return normalized, host_key


def normalize_allow_entry(entry: str) -> str:
    """Validate one config entry. Entries must be explicit ``host:port``."""
    if not isinstance(entry, str):
        raise ScopeConfigError("allowlist entries must be strings")
    if "*" in entry:
        raise ScopeConfigError("wildcards are not supported")
    if "://" in entry or "/" in entry or "@" in entry or "\\" in entry:
        raise ScopeConfigError(f"allowlist entry must be host:port, got {entry!r}")
    if any(ch.isspace() for ch in entry):
        raise ScopeConfigError("allowlist entries must not contain whitespace")
    if not _ENTRY_RE.fullmatch(entry.strip().lower()):
        raise ScopeConfigError(f"allowlist entry must be host:port with an explicit port: {entry!r}")

    text = entry.strip().lower()
    if text.startswith("["):
        host_part, port_part = text.rsplit("]:", 1)
        host_part = host_part[1:]
    else:
        host_part, port_part = text.rsplit(":", 1)

    host = _normalize_host(host_part)
    port = int(port_part)
    if not 1 <= port <= 65535:
        raise ScopeConfigError(f"port out of range in {entry!r}")
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def load_scope_config(path: Path) -> frozenset[str]:
    """Read and validate an allowlist file. Never returns an implicit host."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ScopeConfigError(f"cannot read scope config: {exc}") from exc

    scope = data.get("scope")
    if not isinstance(scope, dict):
        raise ScopeConfigError("config must contain a [scope] table")
    hosts = scope.get("hosts")
    if not isinstance(hosts, list):
        raise ScopeConfigError("[scope] hosts must be a list")
    if not hosts:
        # This is valid and intentionally means "refuse everything". It is not
        # replaced with localhost.
        return frozenset()
    return frozenset(normalize_allow_entry(entry) for entry in hosts)


def config_path_from_env() -> Path:
    """Resolve the config path without assuming the caller's cwd.

    Priority: XSS_HUNTER_SCOPE_CONFIG, ./config/scope.toml, then the repo
    checkout that contains this package.
    """
    import os

    env = os.environ.get("XSS_HUNTER_SCOPE_CONFIG")
    if env:
        return Path(env).expanduser()
    cwd_config = Path.cwd() / "config" / "scope.toml"
    if cwd_config.is_file():
        return cwd_config
    return Path(__file__).resolve().parents[1] / "config" / "scope.toml"


class Scope:
    """An immutable allowlist for one server process or test run."""

    def __init__(self, hosts: Iterable[str]):
        self._hosts = frozenset(normalize_allow_entry(h) for h in hosts)

    @property
    def hosts(self) -> tuple[str, ...]:
        return tuple(sorted(self._hosts))

    def check(self, raw_url: str, checkpoint: str) -> ScopeDecision:
        try:
            url, host = normalize_url(raw_url)
        except ValueError as exc:
            reason = str(exc) or "malformed_url"
            # Best-effort host for the log; never used for the decision.
            host = ""
            try:
                host = urlsplit(raw_url).netloc.lower()[:200]
            except ValueError:
                pass
            return ScopeDecision(
                allowed=False,
                url=str(raw_url)[:300],
                host=host,
                reason=reason,
                checkpoint=checkpoint,
                detail="URL could not be normalized safely; refusing",
            )

        if not self._hosts:
            return ScopeDecision(
                allowed=False,
                url=url,
                host=host,
                reason="empty_allowlist",
                checkpoint=checkpoint,
                detail="the allowlist is empty; every target is refused",
            )
        if host not in self._hosts:
            return ScopeDecision(
                allowed=False,
                url=url,
                host=host,
                reason="host_not_allowlisted",
                checkpoint=checkpoint,
                detail=f"{host} is not in the allowlist",
            )
        return ScopeDecision(
            allowed=True,
            url=url,
            host=host,
            reason="allowed",
            checkpoint=checkpoint,
            detail="",
        )
