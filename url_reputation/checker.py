"""URL Reputation Checker - Core logic.

This module returns results in the **Schema v1** contract.
See `docs/schema-v1.md`.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

# Load .env file if present
try:
    from dotenv import load_dotenv
    # Try current dir, then home dir
    for env_path in [Path('.env'), Path.home() / '.env', Path.home() / '.urlreputation.env']:
        if env_path.exists():
            load_dotenv(env_path)
            break
except ImportError:
    pass  # dotenv not installed, rely on environment variables

from .models import IndicatorV1, RateLimitV1, ResultV1, SourceResultV1
from .providers import ProviderContext, Registry, builtin_providers
from .retry import RetryPolicy, retry_call
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
    'urlhaus': urlhaus.check,
    'phishtank': phishtank.check,
    'dnsbl': dnsbl.check,
    'alienvault_otx': alienvault_otx.check,
    'threatfox': threatfox.check,
    # API key required
    'virustotal': virustotal.check,
    'urlscan': urlscan.check,
    'safebrowsing': safebrowsing.check,
    'abuseipdb': abuseipdb.check,
    'ipqualityscore': ipqualityscore.check,
}

FREE_SOURCES = ['urlhaus', 'phishtank', 'dnsbl', 'alienvault_otx']


def get_default_registry() -> Registry:
    return Registry(builtin_providers())

THREAT_WEIGHTS = {
    'malware': 40,
    'phishing': 35,
    'spam': 20,
    'suspicious': 15,
    'unknown': 10,
}


def canonicalize_indicator(value: str) -> IndicatorV1:
    """Canonicalization and indicator typing (T9).

    Uses `url_reputation.normalize.normalize_indicator`.
    """

    from .normalize import normalize_indicator

    n = normalize_indicator(value)
    return IndicatorV1(input=n.input, type=n.type, canonical=n.canonical, domain=n.domain)


def extract_domain(url: str) -> str:
    """Extract the network location from a URL.

    Backwards-compat helper used by some callers/tests.
    Note: this returns the raw `netloc` which may include userinfo and port.
    """
    value = url
    if not value.startswith(('http://', 'https://')):
        value = 'http://' + value
    parsed = urlparse(value)
    return parsed.netloc or parsed.path.split('/')[0]


def calculate_risk_score(results: dict) -> tuple[int, str]:
    """Calculate aggregated risk score from all source results."""
    score = 0
    
    for source, data in results.items():
        if data.get('error'):
            continue
            
        if source == 'virustotal' and data.get('detected', 0) > 0:
            ratio = data['detected'] / max(data.get('total', 70), 1)
            score += int(ratio * 50)
            
        elif source == 'urlhaus' and data.get('listed'):
            score += THREAT_WEIGHTS.get('malware', 30)
            
        elif source == 'phishtank' and data.get('listed'):
            score += THREAT_WEIGHTS.get('phishing', 35)
            
        elif source in ('spamhaus_dbl', 'surbl') and data.get('listed'):
            score += THREAT_WEIGHTS.get('spam', 20)
            
        elif source == 'dnsbl' and data.get('listed'):
            score += THREAT_WEIGHTS.get('spam', 20)
            
        elif source == 'safebrowsing' and data.get('threats'):
            score += THREAT_WEIGHTS.get('malware', 35)
            
        elif source == 'abuseipdb' and data.get('abuse_score', 0) > 50:
            score += int(data['abuse_score'] * 0.4)
            
        elif source == 'urlscan' and data.get('malicious'):
            score += THREAT_WEIGHTS.get('suspicious', 25)
            
        elif source == 'alienvault_otx':
            # OTX: pulses indicate threat intel reports
            if data.get('has_pulses') and not data.get('is_whitelisted'):
                pulse_count = data.get('pulse_count', 0)
                if pulse_count >= 5:
                    score += THREAT_WEIGHTS.get('malware', 30)
                elif pulse_count >= 1:
                    score += THREAT_WEIGHTS.get('suspicious', 15)
                    
        elif source == 'threatfox' and data.get('listed'):
            score += THREAT_WEIGHTS.get('malware', 40)
            
        elif source == 'ipqualityscore':
            if data.get('malware'):
                score += THREAT_WEIGHTS.get('malware', 40)
            elif data.get('phishing'):
                score += THREAT_WEIGHTS.get('phishing', 35)
            elif data.get('suspicious') or data.get('risk_score', 0) >= 75:
                score += THREAT_WEIGHTS.get('suspicious', 20)
    
    score = min(score, 100)
    
    if score <= 20:
        verdict = 'CLEAN'
    elif score <= 50:
        verdict = 'LOW_RISK'
    elif score <= 75:
        verdict = 'MEDIUM_RISK'
    else:
        verdict = 'HIGH_RISK'
    
    return score, verdict


def check_url_reputation(
    url: str,
    sources: Optional[list[str]] = None,
    timeout: int = 30,
    *,
    cache_path: str | None = None,
    cache_ttl_seconds: int | None = None,
) -> dict:
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
    cache_key = None
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
            return cached

    results_map: dict[str, dict] = {}

    # Concurrency controls (process-wide), useful in batch mode.
    import threading

    global_limit = int(__import__("os").getenv("URL_REPUTATION_MAX_CONCURRENCY", "20"))
    if not hasattr(check_url_reputation, "_global_sem"):
        check_url_reputation._global_sem = threading.Semaphore(global_limit)  # type: ignore[attr-defined]
        check_url_reputation._provider_sems = {}  # type: ignore[attr-defined]

    global_sem = check_url_reputation._global_sem  # type: ignore[attr-defined]
    provider_sems: dict[str, threading.Semaphore] = check_url_reputation._provider_sems  # type: ignore[attr-defined]

    def _get_provider_sem(pname: str, limit: int) -> threading.Semaphore:
        if pname not in provider_sems:
            provider_sems[pname] = threading.Semaphore(max(1, limit))
        return provider_sems[pname]

    def _should_retry_exc(e: Exception) -> bool:
        msg = str(e).lower()
        return any(s in msg for s in ["429", "rate limit", "timeout", "timed out", "temporarily"])

    def _run_provider(p):
        sem = _get_provider_sem(p.name, getattr(p, "max_concurrency", 5))

        def _call():
            with global_sem:
                with sem:
                    return p.check(indicator.canonical, domain, ctx)

        policy = RetryPolicy(retries=getattr(p, "retry_retries", 2))
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

    risk_score, verdict = calculate_risk_score(results_map)

    sources_list: list[SourceResultV1] = []
    for p in providers:
        name = p.name
        payload = results_map.get(name, {})
        if payload.get('error'):
            sources_list.append(
                SourceResultV1(
                    name=name,
                    status="error",
                    raw={k: v for k, v in payload.items() if k != 'error'},
                    error=str(payload.get('error')),
                )
            )
            continue

        listed = None
        if 'listed' in payload:
            listed = bool(payload.get('listed'))
        elif 'malicious' in payload:
            listed = bool(payload.get('malicious'))

        score = None
        if isinstance(payload.get('risk_score'), (int, float)):
            score = float(payload['risk_score'])
        elif isinstance(payload.get('abuse_score'), (int, float)):
            score = float(payload['abuse_score'])

        rate_limit = None
        try:
            rl = p.parse_rate_limit(payload)
            if isinstance(rl, dict):
                rate_limit = RateLimitV1(
                    limit=rl.get("limit"),
                    remaining=rl.get("remaining"),
                    reset_at=rl.get("reset_at"),
                )
        except Exception:
            rate_limit = None

        sources_list.append(
            SourceResultV1(
                name=name,
                status="ok",
                listed=listed,
                score=score,
                raw=payload,
                rate_limit=rate_limit,
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
        enrichment=None,
    )

    # Backwards-compatible convenience fields (non-schema)
    out = result.to_dict()
    out["url"] = indicator.input
    out["domain"] = domain

    if cache and cache_key:
        cache.set(cache_key, out)

    return out


def check_urls_batch(
    urls: list[str],
    sources: Optional[list[str]] = None,
    timeout: int = 30,
    max_workers: int = 5
) -> list[dict]:
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
    
    results = []
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {
            executor.submit(check_url_reputation, url, sources, timeout): url
            for url in urls
        }
        
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                results.append({
                    'url': url,
                    'error': str(e),
                    'verdict': 'ERROR'
                })
    
    # Sort by original order
    url_order = {url: i for i, url in enumerate(urls)}
    results.sort(key=lambda r: url_order.get(r['url'], 999))
    
    return results
