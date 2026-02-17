"""High-level enrichment service using registry (T10)."""

from __future__ import annotations

from typing import Any, Iterable

from .base import EnrichmentContext
from .builtins import builtin_enrichers
from .registry import EnrichmentRegistry


def enrich_domain(domain: str, *, types: Iterable[str], timeout: int = 30) -> dict[str, Any]:
    reg = EnrichmentRegistry(builtin_enrichers())
    ctx = EnrichmentContext(timeout=timeout)

    out: dict[str, Any] = {}
    for enricher in reg.select(types):
        out[enricher.name] = enricher.enrich(domain, ctx)
    return out
