"""Enrichment interface (T10)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class EnrichmentContext:
    timeout: int = 30


class Enricher:
    name: str

    def enrich(self, domain: str, ctx: EnrichmentContext) -> dict[str, Any]:
        raise NotImplementedError
