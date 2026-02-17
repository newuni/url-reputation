"""Built-in enrichers.

- dns, whois: domain-based enrichers
- redirects: URL-based enrichment (follow redirect chain)

Enrichers are intentionally lightweight wrappers to keep core deps minimal.
"""

from __future__ import annotations

from typing import Any

from ..enrich import enrich_dns, enrich_whois
from .base import Enricher, EnrichmentContext
from .redirects import RedirectsEnricher


class _FnEnricher(Enricher):
    def __init__(self, name: str, fn):
        self.name = name
        self._fn = fn

    def enrich(self, indicator: str, ctx: EnrichmentContext) -> dict[str, Any]:
        # These legacy enrichers expect a domain string.
        # Callers should pass a domain indicator when indicator_type=domain/url.
        return self._fn(indicator, timeout=ctx.timeout)


def builtin_enrichers() -> dict[str, Enricher]:
    return {
        "dns": _FnEnricher("dns", enrich_dns),
        "whois": _FnEnricher("whois", enrich_whois),
        "redirects": RedirectsEnricher(max_hops=10),
    }
