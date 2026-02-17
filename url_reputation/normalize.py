"""Canonicalization and indicator typing (T9).

We keep canonicalization conservative but consistent.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse, urlunparse


@dataclass(frozen=True)
class NormalizedIndicator:
    input: str
    type: str  # url|domain|ip
    canonical: str
    domain: str | None = None


def _to_punycode(host: str) -> str:
    """Convert unicode hostname to punycode (idna)."""
    try:
        return host.encode("idna").decode("ascii")
    except Exception:
        return host


def _strip_default_port(scheme: str, netloc: str) -> str:
    if ":" not in netloc:
        return netloc
    # Preserve userinfo if present
    userinfo = ""
    hostport = netloc
    if "@" in netloc:
        userinfo, hostport = netloc.rsplit("@", 1)
        userinfo += "@"

    host, port = hostport.rsplit(":", 1)
    if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
        return f"{userinfo}{host}"
    return netloc


def normalize_indicator(value: str) -> NormalizedIndicator:
    raw = value.strip()

    # IP
    try:
        ipaddress.ip_address(raw)
        return NormalizedIndicator(input=value, type="ip", canonical=raw)
    except Exception:
        pass

    has_scheme = raw.startswith(("http://", "https://"))
    looks_like_url = has_scheme or "/" in raw or "?" in raw or "#" in raw

    if looks_like_url:
        url = raw
        if not has_scheme:
            url = "http://" + url

        parsed = urlparse(url)
        scheme = (parsed.scheme or "http").lower()

        # Normalize netloc: lowercase host, idna punycode, strip default ports
        netloc = parsed.netloc
        userinfo = ""
        hostport = netloc
        if "@" in netloc:
            userinfo, hostport = netloc.rsplit("@", 1)
            userinfo += "@"

        host = hostport
        port = ""
        if ":" in hostport:
            host, port = hostport.rsplit(":", 1)

        host = _to_punycode(host.lower())
        rebuilt = f"{userinfo}{host}{(':' + port) if port else ''}"
        rebuilt = _strip_default_port(scheme, rebuilt)

        canonical = urlunparse((scheme, rebuilt, parsed.path or "", "", parsed.query or "", ""))
        domain = host

        return NormalizedIndicator(input=value, type="url", canonical=canonical, domain=domain)

    # Domain
    domain = _to_punycode(raw.rstrip(".").lower())
    return NormalizedIndicator(input=value, type="domain", canonical=domain, domain=domain)
