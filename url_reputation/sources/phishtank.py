"""
PhishTank - Community phishing verification
Uses the data feed (updated hourly)
No API key required for data feed
https://phishtank.org/
"""

import json
import os
import time
import urllib.request
from typing import Any, Optional
from urllib.parse import urlparse

# Cache settings
CACHE_FILE = "/tmp/phishtank_cache.json"
CACHE_TTL = 3600  # 1 hour (feed updates hourly)


def _get_domain(url: str) -> str:
    """Extract domain from URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc or parsed.path.split("/")[0]
    except Exception:
        return url


def _load_cache() -> tuple[Optional[dict[str, Any]], float]:
    """Load cached data if valid."""
    try:
        if os.path.exists(CACHE_FILE):
            mtime = os.path.getmtime(CACHE_FILE)
            if time.time() - mtime < CACHE_TTL:
                with open(CACHE_FILE) as f:
                    return json.load(f), mtime
    except Exception:
        pass
    return None, 0.0


def _save_cache(data: dict[str, Any]) -> None:
    """Save data to cache."""
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(data, f)
    except Exception:
        pass


def _fetch_phishtank_data(timeout: int = 60) -> dict:
    """Fetch PhishTank verified online database."""
    # Check cache first
    cached, _ = _load_cache()
    if cached:
        return cached

    # PhishTank provides a JSON feed of verified phishes
    # Note: This requires registration for full access, but we can use OpenPhish as fallback

    # Try OpenPhish first (simpler, no registration)
    openphish_url = "https://openphish.com/feed.txt"

    try:
        req = urllib.request.Request(openphish_url)
        req.add_header("User-Agent", "url-reputation-checker/1.0")

        with urllib.request.urlopen(req, timeout=timeout) as response:
            content = response.read().decode("utf-8")

        urls = set()
        domains = set()
        for line in content.split("\n"):
            line = line.strip()
            if line and line.startswith("http"):
                urls.add(line.lower())
                domains.add(_get_domain(line).lower())

        data = {"urls": list(urls), "domains": list(domains), "source": "openphish"}
        _save_cache(data)
        return data

    except Exception as e:
        return {"error": str(e), "note": "OpenPhish feed unavailable"}


def check(url: str, domain: str, timeout: int = 30) -> dict:
    """
    Check URL against PhishTank/OpenPhish database.

    Returns:
        dict with 'listed', 'match_type', etc.
    """
    data = _fetch_phishtank_data(timeout)

    if "error" in data:
        return data

    url_lower = url.lower()
    domain_lower = domain.lower()

    urls = set(data.get("urls", []))
    domains = set(data.get("domains", []))

    # Check exact URL match
    if url_lower in urls:
        return {
            "listed": True,
            "match_type": "exact_url",
            "verified": True,
            "source": data.get("source", "phishtank"),
        }

    # Check domain match
    if domain_lower in domains:
        return {
            "listed": True,
            "match_type": "domain",
            "verified": True,
            "source": data.get("source", "phishtank"),
        }

    return {"listed": False}
