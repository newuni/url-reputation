"""Enrichment interface (T10).

NOTE:
- Originally enrichment was domain-only.
- To support URL-based enrichment (e.g. redirects), enrichers now receive the
  *indicator* string plus an `indicator_type` in the context.

This is intentionally lightweight (no pydantic dependency).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

IndicatorType = Literal["url", "domain", "ip"]


@dataclass(frozen=True)
class EnrichmentContext:
    timeout: int = 30
    indicator_type: IndicatorType = "domain"


class Enricher:
    name: str

    def enrich(self, indicator: str, ctx: EnrichmentContext) -> dict[str, Any]:
        raise NotImplementedError
