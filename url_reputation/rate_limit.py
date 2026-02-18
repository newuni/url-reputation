"""Rate limit parsing helpers.

This module normalizes provider-specific rate limit headers to a common structure.

We keep the internal representation typed (with datetime), and expose a JSON-safe
dict for attaching to result payloads.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Any


@dataclass(frozen=True)
class RateLimitInfo:
    limit: int | None = None
    remaining: int | None = None
    reset_at: datetime | None = None  # UTC
    reset_in_ms: int | None = None
    retry_after_ms: int | None = None
    raw: dict[str, str] = field(default_factory=dict)
    provider: str = ""

    def to_public_dict(self) -> dict[str, Any]:
        # JSON-safe representation (datetime -> ISO-8601 string)
        return {
            "limit": self.limit,
            "remaining": self.remaining,
            "reset_at": self.reset_at.isoformat() if self.reset_at else None,
            "reset_in_ms": self.reset_in_ms,
            "retry_after_ms": self.retry_after_ms,
            "raw": dict(self.raw),
            "provider": self.provider,
        }


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        # Avoid accepting floats; many APIs return plain integers.
        return int(str(value).strip())
    except Exception:
        return None


def _header_map(headers: Mapping[str, str]) -> dict[str, tuple[str, str]]:
    """Lowercase->(original_key, value) mapping for case-insensitive lookups."""
    out: dict[str, tuple[str, str]] = {}
    for k, v in headers.items():
        if k is None:
            continue
        out[str(k).lower()] = (str(k), str(v))
    return out


def _collect_relevant_raw(headers: Mapping[str, str]) -> dict[str, str]:
    ci = _header_map(headers)
    raw: dict[str, str] = {}
    for lk, (ok, v) in ci.items():
        if lk == "retry-after":
            raw[ok] = v
            continue
        if lk.startswith("x-ratelimit-") or lk.startswith("ratelimit-"):
            raw[ok] = v
            continue
        if lk.startswith("x-rate-limit-") or lk.startswith("rate-limit-"):
            raw[ok] = v
            continue
    return raw


def _pick(ci: Mapping[str, tuple[str, str]], candidates_lc: list[str]) -> tuple[str, str] | None:
    for cand in candidates_lc:
        hit = ci.get(cand)
        if hit is not None:
            return hit
    return None


def _parse_retry_after(
    headers: Mapping[str, str], *, now: datetime
) -> tuple[int | None, datetime | None]:
    ci = _header_map(headers)
    hit = ci.get("retry-after")
    if hit is None:
        return None, None
    _k, raw_val = hit
    raw_val = raw_val.strip()

    # 1) delta-seconds
    seconds = _as_int(raw_val)
    if seconds is not None:
        if seconds < 0:
            seconds = 0
        reset_at = now + timedelta(seconds=seconds)
        return seconds * 1000, reset_at

    # 2) HTTP-date
    try:
        dt = parsedate_to_datetime(raw_val)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        reset_at = dt.astimezone(timezone.utc)
        ms = int(max(0.0, (reset_at - now).total_seconds()) * 1000)
        return ms, reset_at
    except Exception:
        return None, None


def _parse_limit_remaining_reset(
    headers: Mapping[str, str], *, now: datetime
) -> tuple[int | None, int | None, datetime | None]:
    """Parse common limit/remaining/reset header triplets.

    Supports both legacy X-* and RFC-ish RateLimit-* forms.
    Reset semantics:
    - If reset value looks like an epoch seconds/ms timestamp, treat it as such.
    - Otherwise treat as delta-seconds from now.
    """

    ci = _header_map(headers)

    limit_hit = _pick(
        ci,
        [
            "x-ratelimit-limit",
            "x-rate-limit-limit",
            "ratelimit-limit",
            "rate-limit-limit",
        ],
    )
    remaining_hit = _pick(
        ci,
        [
            "x-ratelimit-remaining",
            "x-rate-limit-remaining",
            "ratelimit-remaining",
            "rate-limit-remaining",
        ],
    )
    reset_hit = _pick(
        ci,
        [
            "x-ratelimit-reset",
            "x-rate-limit-reset",
            "ratelimit-reset",
            "rate-limit-reset",
        ],
    )

    limit = _as_int(limit_hit[1]) if limit_hit else None
    remaining = _as_int(remaining_hit[1]) if remaining_hit else None
    reset_at: datetime | None = None

    reset_raw = reset_hit[1] if reset_hit else None
    reset_val = _as_int(reset_raw) if reset_raw is not None else None
    if reset_val is not None:
        # Heuristic: big numbers are timestamps.
        if reset_val >= 1_000_000_000_000:
            reset_at = datetime.fromtimestamp(reset_val / 1000.0, tz=timezone.utc)
        elif reset_val >= 1_000_000_000:
            reset_at = datetime.fromtimestamp(reset_val, tz=timezone.utc)
        else:
            # delta-seconds
            if reset_val < 0:
                reset_val = 0
            reset_at = now + timedelta(seconds=reset_val)

    return limit, remaining, reset_at


def parse_rate_limit_info(
    provider: str,
    headers: Mapping[str, str] | None,
    *,
    now: datetime | None = None,
) -> RateLimitInfo | None:
    """Parse rate limit info from HTTP headers.

    Returns RateLimitInfo when at least one meaningful field is discovered.
    """

    if not headers:
        return None
    if now is None:
        now = _utc_now()
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    now = now.astimezone(timezone.utc)

    raw = _collect_relevant_raw(headers)

    limit, remaining, reset_at = _parse_limit_remaining_reset(headers, now=now)
    retry_after_ms, retry_reset_at = _parse_retry_after(headers, now=now)

    # Prefer an explicit reset timestamp from limit headers; otherwise use Retry-After.
    if reset_at is None:
        reset_at = retry_reset_at

    reset_in_ms: int | None = None
    if reset_at is not None:
        reset_in_ms = int(max(0.0, (reset_at - now).total_seconds()) * 1000)

    if (
        all(v is None for v in (limit, remaining, reset_at, reset_in_ms, retry_after_ms))
        and not raw
    ):
        return None

    return RateLimitInfo(
        limit=limit,
        remaining=remaining,
        reset_at=reset_at,
        reset_in_ms=reset_in_ms,
        retry_after_ms=retry_after_ms,
        raw=raw,
        provider=provider,
    )
