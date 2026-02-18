"""Models for url-reputation.

We keep the core library lightweight (no mandatory pydantic dependency).
These dataclasses define the *stable* output contract for schema v1.

All public JSON outputs should include:
- schema_version: "1"

See docs/schema-v1.md.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal, Optional

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
    domain: Optional[str] = None


@dataclass(frozen=True)
class RateLimitV1:
    limit: Optional[int] = None
    remaining: Optional[int] = None
    reset_at: Optional[str] = None  # ISO-8601 timestamp


@dataclass(frozen=True)
class SourceResultV1:
    name: str

    # Whether the provider ran and returned a meaningful answer.
    status: Literal["ok", "error", "skipped"]

    # Provider-specific verdict/flags are provider-defined, but we try to expose
    # a couple of common fields.
    listed: Optional[bool] = None
    score: Optional[float] = None

    # Raw provider payload (JSON-serializable dict) for transparency/debug.
    raw: dict[str, Any] = field(default_factory=dict)

    error: Optional[str] = None
    rate_limit: Optional[RateLimitV1] = None
    # Rich rate-limit metadata (when available). JSON-safe dict derived from RateLimitInfo.
    rate_limit_info: Optional[dict[str, Any]] = None


@dataclass(frozen=True)
class ResultV1:
    schema_version: Literal["1"]
    indicator: IndicatorV1

    verdict: Verdict
    risk_score: int
    checked_at: str  # ISO-8601 UTC

    sources: list[SourceResultV1]

    enrichment: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
