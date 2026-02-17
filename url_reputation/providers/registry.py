"""Provider registry + selection helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from .base import Provider


@dataclass
class Registry:
    providers: dict[str, Provider]

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
