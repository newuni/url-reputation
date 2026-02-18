"""Models for url-reputation.

We keep the core library lightweight (no mandatory pydantic dependency).
These dataclasses define the *stable* output contract for schema v1.

All public JSON outputs should include:
- schema_version: "1"

See docs/schema-v1.md.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

IndicatorType = Literal["url", "domain", "ip"]
Verdict = Literal["CLEAN", "LOW_RISK", "MEDIUM_RISK", "HIGH_RISK", "ERROR"]


@dataclass(frozen=True)
class IndicatorV1:
    """Normalized input indicator."""

    input: str
    type: IndicatorType

    # Canonical normalized value of the indicator.
    # - url: canonical_url
    # - domain: canonical_domain
    # - ip: canonical_ip
    canonical: str

    # Convenience: extracted parts when applicable
    domain: str | None = None


@dataclass(frozen=True)
class RateLimitV1:
    limit: int | None = None
    remaining: int | None = None
    reset_at: str | None = None  # ISO-8601 timestamp


@dataclass(frozen=True)
class SourceResultV1:
    name: str

    # Whether the provider ran and returned a meaningful answer.
    status: Literal["ok", "error", "skipped"]

    # Provider-specific verdict/flags are provider-defined, but we try to expose
    # a couple of common fields.
    listed: bool | None = None
    score: float | None = None

    # Raw provider payload (JSON-serializable dict) for transparency/debug.
    raw: dict[str, Any] = field(default_factory=dict)

    error: str | None = None
    rate_limit: RateLimitV1 | None = None
    # Rich rate-limit metadata (when available). JSON-safe dict derived from RateLimitInfo.
    rate_limit_info: dict[str, Any] | None = None


@dataclass(frozen=True)
class ResultV1:
    schema_version: Literal["1"]
    indicator: IndicatorV1

    verdict: Verdict
    risk_score: int
    checked_at: str  # ISO-8601 UTC

    sources: list[SourceResultV1]

    enrichment: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
