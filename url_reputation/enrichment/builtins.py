"""Built-in enrichers.

- dns, whois: domain-based enrichers
- redirects: URL-based enrichment (follow redirect chain)

Enrichers are intentionally lightweight wrappers to keep core deps minimal.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from ..enrich import enrich_dns, enrich_whois
from .asn_geo import AsnGeoEnricher
from .base import Enricher, EnrichmentContext
from .redirects import RedirectsEnricher
from .screenshot import ScreenshotEnricher
from .ssl import SslCertEnricher, TlsEnricher


class _FnEnricher(Enricher):
    def __init__(self, name: str, fn: Callable[..., Any]):
        self.name = name
        self._fn = fn

    def enrich(self, indicator: str, ctx: EnrichmentContext) -> dict[str, Any]:
        # These legacy enrichers expect a domain string.
        # Callers should pass a domain indicator when indicator_type=domain/url.
        out = self._fn(indicator, timeout=ctx.timeout)
        if isinstance(out, dict):
            return out
        return {"error": "enricher returned non-dict result"}


def builtin_enrichers() -> dict[str, Enricher]:
    asn_geo = AsnGeoEnricher()
    ssl_enricher = SslCertEnricher()
    tls_enricher = TlsEnricher()
    return {
        "dns": _FnEnricher("dns", enrich_dns),
        "whois": _FnEnricher("whois", enrich_whois),
        "redirects": RedirectsEnricher(max_hops=10),
        # T16 canonical name (and a short alias to match the roadmap wording).
        "asn_geo": asn_geo,
        "asn": asn_geo,
        "ssl": ssl_enricher,
        "tls_cert": ssl_enricher,
        "tls": tls_enricher,
        "screenshot": ScreenshotEnricher(),
    }
