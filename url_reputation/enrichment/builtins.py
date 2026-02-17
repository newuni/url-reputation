"""Built-in enrichers (dns, whois) wrapping existing functions."""

from __future__ import annotations

from typing import Any

from ..enrich import enrich_dns, enrich_whois
from .base import Enricher, EnrichmentContext


class _FnEnricher(Enricher):
    def __init__(self, name: str, fn):
        self.name = name
        self._fn = fn

    def enrich(self, domain: str, ctx: EnrichmentContext) -> dict[str, Any]:
        return self._fn(domain, timeout=ctx.timeout)


def builtin_enrichers() -> dict[str, Enricher]:
    return {
        "dns": _FnEnricher("dns", enrich_dns),
        "whois": _FnEnricher("whois", enrich_whois),
    }
