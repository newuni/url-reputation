"""Retry utilities (exponential backoff + jitter)."""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Callable, TypeVar

T = TypeVar("T")


@dataclass(frozen=True)
class RetryPolicy:
    retries: int = 2  # total attempts = 1 + retries
    base_delay_seconds: float = 0.5
    max_delay_seconds: float = 10.0
    jitter: float = 0.2  # 20% jitter


def _sleep_seconds(attempt: int, policy: RetryPolicy) -> float:
    # attempt starts at 1 for the first retry sleep
    delay = policy.base_delay_seconds * (2 ** (attempt - 1))
    delay = min(delay, policy.max_delay_seconds)
    # jitter in range [1-jitter, 1+jitter]
    factor = 1.0 + random.uniform(-policy.jitter, policy.jitter)
    return max(0.0, delay * factor)


def retry_call(fn: Callable[[], T], policy: RetryPolicy, should_retry: Callable[[Exception], bool]) -> T:
    """Call fn with retries.

    - Retries on exceptions that satisfy should_retry.
    - Raises the last exception if all attempts fail.
    """
    attempts = 1 + max(policy.retries, 0)
    last_err: Exception | None = None

    for i in range(attempts):
        try:
            return fn()
        except Exception as e:  # noqa: BLE001
            last_err = e
            if i == attempts - 1 or not should_retry(e):
                raise
            time.sleep(_sleep_seconds(i + 1, policy))

    # unreachable, but keeps mypy happy
    raise last_err  # type: ignore[misc]
