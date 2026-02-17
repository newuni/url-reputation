"""Provider interface.

A Provider is a thin adapter over an external reputation source.
It must be safe to run in parallel.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional


@dataclass(frozen=True)
class ProviderContext:
    timeout: int = 30


class Provider:
    """Base interface for providers."""

    # Stable provider name used in CLI flags and output.
    name: str

    def is_available(self) -> bool:
        """Whether this provider can run in the current environment.

        Example: requires an API key.
        """
        return True

    def check(self, indicator: str, domain: str, ctx: ProviderContext) -> dict[str, Any]:
        """Return a JSON-serializable dict.

        On failure, raise or return {'error': '...'}.
        """
        raise NotImplementedError

    def parse_rate_limit(self, payload: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Optional: extract rate-limit metadata from a provider payload."""
        return None
