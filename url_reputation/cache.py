"""SQLite cache for url-reputation.

Goal: reduce latency and provider quota usage by caching results.

This cache is intentionally simple:
- key -> JSON payload + timestamps
- TTL handled at read time

NOTE: Cache is opt-in via CLI flags (see `url_reputation/cli.py`).
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Optional


def default_cache_path() -> str:
    base = os.getenv("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return os.path.join(base, "url-reputation", "cache.sqlite")


def _ensure_parent_dir(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)


def make_cache_key(
    *,
    schema_version: str,
    indicator_canonical: str,
    providers: list[str],
    enrich: Optional[list[str]] = None,
) -> str:
    providers_key = ",".join(sorted(providers))
    enrich_key = ",".join(sorted(enrich or []))
    raw = f"v={schema_version}|i={indicator_canonical}|p={providers_key}|e={enrich_key}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def parse_ttl(ttl: str) -> int:
    """Parse TTL strings like: 3600, 10m, 24h, 7d."""
    s = ttl.strip().lower()
    if s.isdigit():
        return int(s)

    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    unit = s[-1]
    if unit not in units:
        raise ValueError(f"Invalid TTL unit: {ttl}")
    num = int(s[:-1])
    return num * units[unit]


@dataclass
class Cache:
    path: str

    def __post_init__(self) -> None:
        _ensure_parent_dir(self.path)
        with self._connect() as con:
            con.execute(
                """
                CREATE TABLE IF NOT EXISTS cache (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path)

    def get(self, key: str, ttl_seconds: int) -> Optional[dict[str, Any]]:
        now = time.time()
        with self._connect() as con:
            row = con.execute(
                "SELECT value, updated_at FROM cache WHERE key = ?",
                (key,),
            ).fetchone()
        if not row:
            return None
        value_json, updated_at = row
        if ttl_seconds >= 0 and (now - float(updated_at)) > ttl_seconds:
            return None
        try:
            return json.loads(value_json)
        except Exception:
            return None

    def set(self, key: str, value: dict[str, Any]) -> None:
        now = time.time()
        value_json = json.dumps(value, ensure_ascii=False)
        with self._connect() as con:
            con.execute(
                """
                INSERT INTO cache (key, value, created_at, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value=excluded.value,
                    updated_at=excluded.updated_at
                """,
                (key, value_json, now, now),
            )
            con.commit()
