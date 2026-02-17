"""Enrichment registry."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from .base import Enricher


@dataclass
class EnrichmentRegistry:
    enrichers: dict[str, Enricher]

    def list_names(self) -> list[str]:
        return sorted(self.enrichers.keys())

    def select(self, names: Optional[Iterable[str]] = None) -> list[Enricher]:
        if names is None:
            names = self.list_names()
        selected = []
        for n in names:
            if n in self.enrichers:
                selected.append(self.enrichers[n])
        return selected
