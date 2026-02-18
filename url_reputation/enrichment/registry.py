"""Enrichment registry."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from importlib import metadata
from typing import Any, Optional

from .base import Enricher


def _iter_entry_points(group: str) -> list[metadata.EntryPoint]:
    """Return entry points for a group across importlib.metadata API variants."""
    eps: Any = metadata.entry_points()
    # Python 3.10+ returns EntryPoints with .select().
    try:
        sel = getattr(eps, "select", None)
        if callable(sel):
            return list(sel(group=group))
    except Exception:
        pass

    # Older variants: dict-like mapping group -> list[EntryPoint]
    if isinstance(eps, dict):
        group_eps = eps.get(group, [])
        return list(group_eps) if isinstance(group_eps, Iterable) else []

    # Fallback: iterable of EntryPoint with .group attribute.
    out: list[metadata.EntryPoint] = []
    try:
        for ep in eps:
            if getattr(ep, "group", None) == group:
                out.append(ep)
    except Exception:
        return []
    return out


@dataclass
class EnrichmentRegistry:
    enrichers: dict[str, Enricher]

    @staticmethod
    def load_entrypoints(group: str = "url_reputation.enrichers") -> dict[str, Enricher]:
        """Load Enricher plugins via Python entry points.

        Mirrors the provider plugin loader behavior:
        - never raises (best-effort)
        - supports either an Enricher instance or a factory returning one
        - registers by `enricher.name`
        """
        loaded: dict[str, Enricher] = {}
        try:
            eps = _iter_entry_points(group)
        except Exception:
            return loaded

        for ep in eps:
            try:
                obj = ep.load()
                enricher = obj() if callable(obj) else obj
                if isinstance(enricher, Enricher):
                    loaded[enricher.name] = enricher
            except Exception:
                continue

        return loaded

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
