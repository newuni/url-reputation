"""Redirect-chain enrichment.

Goal: for URL indicators, follow redirects (with limits) and return the chain +
final URL.

We avoid downloading bodies by preferring HEAD, with a GET fallback for servers
that do not support HEAD properly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urljoin
from urllib.request import Request, urlopen

from .base import Enricher, EnrichmentContext


@dataclass(frozen=True)
class RedirectStep:
    url: str
    status: int
    location: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {"url": self.url, "status": self.status, "location": self.location}


class RedirectsEnricher(Enricher):
    name = "redirects"

    def __init__(self, *, max_hops: int = 10):
        self.max_hops = max_hops

    def enrich(self, indicator: str, ctx: EnrichmentContext) -> dict[str, Any]:
        if ctx.indicator_type != "url":
            return {"skipped": True, "reason": "redirects enrichment requires indicator_type=url"}

        chain: list[RedirectStep] = []
        current = indicator

        for _ in range(self.max_hops + 1):
            status, location = _fetch_redirect(current, timeout=ctx.timeout)
            chain.append(RedirectStep(url=current, status=status, location=location))

            if location is None or status < 300 or status >= 400:
                # Not a redirect.
                break

            current = urljoin(current, location)
        else:
            return {
                "error": "max_redirects_exceeded",
                "max_hops": self.max_hops,
                "chain": [s.to_dict() for s in chain],
            }

        return {
            "final_url": current,
            "hops": max(0, len(chain) - 1),
            "chain": [s.to_dict() for s in chain],
        }


def _fetch_redirect(url: str, *, timeout: int) -> tuple[int, Optional[str]]:
    """Return (status, location) for a single request without following redirects."""

    # We do not let urllib follow redirects. If a redirect happens, urlopen will
    # raise HTTPError (subclass of URLError) which still contains headers.

    def _do(method: str):
        req = Request(url, method=method, headers={"User-Agent": "url-reputation/redirects"})
        return urlopen(req, timeout=timeout)

    try:
        resp = _do("HEAD")
        status = getattr(resp, "status", 200)
        location = resp.headers.get("Location")
        return int(status), location
    except Exception as e:
        # HTTPError path (3xx/4xx) still has code + headers; other errors won't.
        code = getattr(e, "code", None)
        headers = getattr(e, "headers", None)
        if code is not None:
            location = None
            try:
                if headers is not None:
                    location = headers.get("Location")
            except Exception:
                location = None
            return int(code), location

        # HEAD sometimes fails; retry with GET.
        try:
            resp = _do("GET")
            status = getattr(resp, "status", 200)
            location = resp.headers.get("Location")
            return int(status), location
        except Exception as e2:
            code2 = getattr(e2, "code", None)
            headers2 = getattr(e2, "headers", None)
            if code2 is not None:
                location = None
                try:
                    if headers2 is not None:
                        location = headers2.get("Location")
                except Exception:
                    location = None
                return int(code2), location

            # Unknown failure.
            return 0, None
