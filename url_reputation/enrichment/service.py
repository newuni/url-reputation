"""High-level enrichment service using registry (T10).

Supports both domain- and URL-based enrichers.
"""

from __future__ import annotations

from typing import Any, Iterable

from .base import EnrichmentContext, IndicatorType
from .builtins import builtin_enrichers
from .registry import EnrichmentRegistry


def enrich_indicator(
    indicator: str,
    *,
    indicator_type: IndicatorType,
    types: Iterable[str],
    timeout: int = 30,
) -> dict[str, Any]:
    reg = EnrichmentRegistry(builtin_enrichers())
    ctx = EnrichmentContext(timeout=timeout, indicator_type=indicator_type)

    out: dict[str, Any] = {}
    for enricher in reg.select(types):
        # Domain-based enrichers should be fed a domain when available.
        if enricher.name in {"dns", "whois"} and indicator_type == "url":
            # In URL mode, `indicator` is expected to be a canonical URL; extract host.
            try:
                from urllib.parse import urlparse

                out_indicator = urlparse(indicator).hostname or indicator
            except Exception:
                out_indicator = indicator
        else:
            out_indicator = indicator

        out[enricher.name] = enricher.enrich(out_indicator, ctx)

    return out


# Backwards-compatible alias
def enrich_domain(domain: str, *, types: Iterable[str], timeout: int = 30) -> dict[str, Any]:
    return enrich_indicator(domain, indicator_type="domain", types=types, timeout=timeout)
