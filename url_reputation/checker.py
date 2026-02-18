"""URL Reputation Checker - Core logic.

This module returns results in the **Schema v1** contract.
See `docs/schema-v1.md`.
"""

from __future__ import annotations

import threading
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, cast
from urllib.parse import urlparse

# Load .env file if present
try:
    from dotenv import load_dotenv

    # Try current dir, then home dir
    for env_path in [Path(".env"), Path.home() / ".env", Path.home() / ".urlreputation.env"]:
        if env_path.exists():
            load_dotenv(env_path)
            break
except ImportError:
    pass  # dotenv not installed, rely on environment variables

from .models import IndicatorType, IndicatorV1, RateLimitV1, ResultV1, SourceResultV1
from .providers import Provider, ProviderContext, Registry, builtin_providers
from .retry import RetryPolicy, retry_call
from .scoring import aggregate_risk_score
from .sources import (
    abuseipdb,
    alienvault_otx,
    dnsbl,
    ipqualityscore,
    phishtank,
    safebrowsing,
    threatfox,
    urlhaus,
    urlscan,
    virustotal,
)

# NOTE: ALL_SOURCES/FREE_SOURCES are kept for backwards-compat/tests.
ALL_SOURCES = {
    # Free sources (no API key required)
    "urlhaus": urlhaus.check,
    "phishtank": phishtank.check,
    "dnsbl": dnsbl.check,
    "alienvault_otx": alienvault_otx.check,
    "threatfox": threatfox.check,
    # API key required
    "virustotal": virustotal.check,
    "urlscan": urlscan.check,
    "safebrowsing": safebrowsing.check,
    "abuseipdb": abuseipdb.check,
    "ipqualityscore": ipqualityscore.check,
}

FREE_SOURCES = ["urlhaus", "phishtank", "dnsbl", "alienvault_otx"]


def get_default_registry() -> Registry:
    return Registry(builtin_providers())


# Process-wide concurrency controls (useful in batch mode).
_GLOBAL_SEM: threading.Semaphore | None = None
_PROVIDER_SEMS: dict[str, threading.Semaphore] = {}

THREAT_WEIGHTS = {
    "malware": 40,
    "phishing": 35,
    "spam": 20,
    "suspicious": 15,
    "unknown": 10,
}


def canonicalize_indicator(value: str) -> IndicatorV1:
    """Canonicalization and indicator typing (T9).

    Uses `url_reputation.normalize.normalize_indicator`.
    """

    from .normalize import normalize_indicator

    n = normalize_indicator(value)
    return IndicatorV1(
        input=n.input,
        type=cast(IndicatorType, n.type),
        canonical=n.canonical,
        domain=n.domain,
    )


def extract_domain(url: str) -> str:
    """Extract the network location from a URL.

    Backwards-compat helper used by some callers/tests.
    Note: this returns the raw `netloc` which may include userinfo and port.
    """
    value = url
    if not value.startswith(("http://", "https://")):
        value = "http://" + value
    parsed = urlparse(value)
    return parsed.netloc or parsed.path.split("/")[0]


def calculate_risk_score(results: dict) -> tuple[int, str]:
    """Calculate aggregated risk score from all source results.

    Backwards-compatible wrapper returning (risk_score, verdict).
    For explainability, use `url_reputation.scoring.aggregate_risk_score`.
    """

    agg = aggregate_risk_score(results)
    return agg.risk_score, agg.verdict


def check_url_reputation(
    url: str,
    sources: Optional[list[str]] = None,
    timeout: int = 30,
    *,
    cache_path: str | None = None,
    cache_ttl_seconds: int | None = None,
    enrichment_types: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Check reputation across multiple sources.

    Returns a dict conforming to **Schema v1**.
    """

    indicator = canonicalize_indicator(url)
    domain = indicator.domain or indicator.canonical

    if sources is None:
        sources = list(ALL_SOURCES.keys())

    registry = get_default_registry()
    providers = registry.select(sources, only_available=True)
    ctx = ProviderContext(timeout=timeout)

    # Cache lookup (opt-in)
    cache = None
    cache_key: str | None = None
    ttl = cache_ttl_seconds
    if cache_path and (ttl is not None):
        from .cache import Cache, make_cache_key

        cache = Cache(cache_path)
        cache_key = make_cache_key(
            schema_version="1",
            indicator_canonical=indicator.canonical,
            providers=[p.name for p in providers],
        )
        cached = cache.get(cache_key, ttl_seconds=ttl)
        if cached:
            # Additive fields introduced in newer schema v1 revisions (T19).
            cached.setdefault("score_breakdown", [])
            cached.setdefault("reasons", [])
            return cached

    results_map: dict[str, dict[str, Any]] = {}

    global_limit = int(__import__("os").getenv("URL_REPUTATION_MAX_CONCURRENCY", "20"))
    global _GLOBAL_SEM
    if _GLOBAL_SEM is None:
        _GLOBAL_SEM = threading.Semaphore(global_limit)
    global_sem = _GLOBAL_SEM
    assert global_sem is not None
    provider_sems = _PROVIDER_SEMS

    def _get_provider_sem(pname: str, limit: int) -> threading.Semaphore:
        if pname not in provider_sems:
            provider_sems[pname] = threading.Semaphore(max(1, limit))
        return provider_sems[pname]

    def _should_retry_exc(e: Exception) -> bool:
        msg = str(e).lower()
        return any(s in msg for s in ["429", "rate limit", "timeout", "timed out", "temporarily"])

    def _run_provider(p: Provider) -> dict[str, Any]:
        sem = _get_provider_sem(p.name, p.max_concurrency)

        def _call() -> dict[str, Any]:
            with global_sem, sem:
                return p.check(indicator.canonical, domain, ctx)

        policy = RetryPolicy(retries=p.retry_retries)
        return retry_call(_call, policy=policy, should_retry=_should_retry_exc)

    if providers:
        with ThreadPoolExecutor(max_workers=len(providers)) as executor:
            futures = {executor.submit(_run_provider, p): p.name for p in providers}

            for future in as_completed(futures):
                name = futures[future]
                try:
                    results_map[name] = future.result()
                except Exception as e:
                    results_map[name] = {"error": str(e)}

    # Optional enrichment (e.g., redirects, whois domain age) can contribute to score.
    enrichment = None
    if enrichment_types:
        try:
            from .enrichment.service import enrich_indicator

            enrichment = enrich_indicator(
                str(indicator.canonical),
                indicator_type=indicator.type,
                types=enrichment_types,
                timeout=timeout,
            )
        except Exception as e:
            enrichment = {"error": str(e)}

    agg = aggregate_risk_score(results_map, enrichment=enrichment)
    risk_score, verdict = agg.risk_score, agg.verdict

    sources_list: list[SourceResultV1] = []
    for p in providers:
        name = p.name
        payload = results_map.get(name) or {}

        rate_limit_info = None
        rate_limit = None
        try:
            rl = p.parse_rate_limit(payload)
            if isinstance(rl, dict):
                rate_limit_info = rl
                rate_limit = RateLimitV1(
                    limit=rl.get("limit"),
                    remaining=rl.get("remaining"),
                    reset_at=rl.get("reset_at"),
                )
        except Exception:
            rate_limit_info = None
            rate_limit = None

        if payload.get("error"):
            sources_list.append(
                SourceResultV1(
                    name=name,
                    status="error",
                    raw={k: v for k, v in payload.items() if k != "error"},
                    error=str(payload.get("error")),
                    rate_limit=rate_limit,
                    rate_limit_info=rate_limit_info,
                )
            )
            continue

        listed = None
        if "listed" in payload:
            listed = bool(payload.get("listed"))
        elif "malicious" in payload:
            listed = bool(payload.get("malicious"))

        score = None
        if isinstance(payload.get("risk_score"), (int, float)):
            score = float(payload["risk_score"])
        elif isinstance(payload.get("abuse_score"), (int, float)):
            score = float(payload["abuse_score"])

        sources_list.append(
            SourceResultV1(
                name=name,
                status="ok",
                listed=listed,
                score=score,
                raw=payload,
                rate_limit=rate_limit,
                rate_limit_info=rate_limit_info,
            )
        )

    checked_at = datetime.now(timezone.utc).isoformat()
    result = ResultV1(
        schema_version="1",
        indicator=indicator,
        verdict=verdict,
        risk_score=risk_score,
        checked_at=checked_at,
        sources=sources_list,
        enrichment=enrichment,
    )

    # Backwards-compatible convenience fields (non-schema)
    out = result.to_dict()
    out["url"] = indicator.input
    out["domain"] = domain
    # Additive explainability fields (T19).
    out["score_breakdown"] = agg.score_breakdown
    out["reasons"] = agg.reasons

    if cache and cache_key:
        cache.set(cache_key, out)

    return out


def check_urls_batch(
    urls: list[str], sources: Optional[list[str]] = None, timeout: int = 30, max_workers: int = 5
) -> list[dict[str, Any]]:
    """
    Check multiple URLs in parallel.

    Args:
        urls: List of URLs to check
        sources: List of sources to use (default: all available)
        timeout: Timeout in seconds for each source
        max_workers: Maximum parallel workers

    Returns:
        List of results for each URL (in original order)
    """
    if not urls:
        return []

    results: list[dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url: dict[Future[dict[str, Any]], str] = {
            executor.submit(check_url_reputation, url, sources, timeout): url for url in urls
        }

        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                results.append({"url": url, "error": str(e), "verdict": "ERROR"})

    # Sort by original order
    url_order = {url: i for i, url in enumerate(urls)}
    results.sort(key=lambda r: url_order.get(r["url"], 999))

    return results
