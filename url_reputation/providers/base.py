"""Provider interface.

A Provider is a thin adapter over an external reputation source.
It must be safe to run in parallel.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from ..rate_limit import parse_rate_limit_info


@dataclass(frozen=True)
class ProviderContext:
    timeout: int = 30


class Provider:
    """Base interface for providers."""

    # Stable provider name used in CLI flags and output.
    name: str

    # Concurrency limit across the whole process (applies mainly in batch mode).
    # The checker will enforce this with a semaphore.
    max_concurrency: int = 5

    # Retry policy: providers can override.
    retry_retries: int = 2

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
        """Extract rate-limit metadata from a provider payload when possible.

        Built-in sources attach a JSON-safe HTTP metadata blob under `_http`.
        """

        http = payload.get("_http")
        if not isinstance(http, dict):
            return None
        headers_any = http.get("headers")
        if not isinstance(headers_any, dict):
            return None

        # Coerce to a Mapping[str, str] for parsing (and for mypy).
        headers: dict[str, str] = {}
        for k, v in headers_any.items():
            if k is None or v is None:
                continue
            headers[str(k)] = str(v)

        info = parse_rate_limit_info(self.name, headers)
        return info.to_public_dict() if info else None
