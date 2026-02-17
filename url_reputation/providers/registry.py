"""Provider registry + selection helpers."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from importlib import metadata
from typing import Optional

from .base import Provider


@dataclass
class Registry:
    providers: dict[str, Provider]

    @staticmethod
    def load_entrypoints(group: str = "url_reputation.providers") -> dict[str, Provider]:
        loaded: dict[str, Provider] = {}
        try:
            eps = metadata.entry_points(group=group)
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
        names: Optional[Iterable[str]] = None,
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
