"""Provider registry + selection helpers."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from importlib import metadata
from typing import Any

from .base import Provider


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
class Registry:
    providers: dict[str, Provider]

    @staticmethod
    def load_entrypoints(group: str = "url_reputation.providers") -> dict[str, Provider]:
        loaded: dict[str, Provider] = {}
        try:
            eps = _iter_entry_points(group)
        except Exception:
            return loaded

        for ep in eps:
            try:
                obj = ep.load()
                # Allow either an instance or a factory.
                provider = obj() if callable(obj) else obj
                if isinstance(provider, Provider):
                    loaded[provider.name] = provider
            except Exception:
                continue

        return loaded

    def get(self, name: str) -> Provider:
        return self.providers[name]

    def list_names(self) -> list[str]:
        return sorted(self.providers.keys())

    def select(
        self,
        names: Iterable[str] | None = None,
        *,
        only_available: bool = True,
    ) -> list[Provider]:
        if names is None:
            names = self.list_names()

        selected: list[Provider] = []
        for name in names:
            if name not in self.providers:
                continue
            p = self.providers[name]
            if only_available and not p.is_available():
                continue
            selected.append(p)
        return selected
