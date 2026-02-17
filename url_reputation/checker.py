"""URL Reputation Checker - Core logic.

This module returns results in the **Schema v1** contract.
See `docs/schema-v1.md`.
"""

import os
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse
from typing import Optional
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

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

from .sources import urlhaus, phishtank, dnsbl, virustotal, urlscan, safebrowsing, abuseipdb
from .sources import alienvault_otx, ipqualityscore, threatfox
from .models import ResultV1, IndicatorV1, SourceResultV1
from .providers import Registry, ProviderContext, builtin_providers

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


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False


def canonicalize_indicator(value: str) -> IndicatorV1:
    """Best-effort indicator typing + canonicalization.

    Rules (v1):
    - If it's an IP literal -> type=ip
    - Else if it has scheme or looks like a URL path -> type=url
    - Else -> type=domain

    Canonicalization is intentionally conservative in v1.
    """
    raw = value.strip()

    if _is_ip(raw):
        return IndicatorV1(input=value, type="ip", canonical=raw, domain=None)

    has_scheme = raw.startswith(("http://", "https://"))
    looks_like_url = has_scheme or "/" in raw or "?" in raw

    if looks_like_url:
        url = raw
        if not has_scheme:
            url = "http://" + url
        parsed = urlparse(url)
        # Normalize scheme + hostname casing; keep path/query as-is.
        scheme = (parsed.scheme or "http").lower()
        netloc = parsed.netloc.lower()
        # Strip fragment.
        canonical = urlunparse((scheme, netloc, parsed.path or "", parsed.params or "", parsed.query or "", ""))
        domain = netloc.split("@")[ -1 ].split(":")[0] if netloc else None
        return IndicatorV1(input=value, type="url", canonical=canonical, domain=domain)

    # Domain
    domain = raw.rstrip(".").lower()
    return IndicatorV1(input=value, type="domain", canonical=domain, domain=domain)


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
    timeout: int = 30
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

    results_map: dict[str, dict] = {}

    if providers:
        with ThreadPoolExecutor(max_workers=len(providers)) as executor:
            futures = {
                executor.submit(p.check, indicator.canonical, domain, ctx): p.name
                for p in providers
            }

            for future in as_completed(futures):
                name = futures[future]
                try:
                    results_map[name] = future.result()
                except Exception as e:
                    results_map[name] = {'error': str(e)}

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

        sources_list.append(
            SourceResultV1(
                name=name,
                status="ok",
                listed=listed,
                score=score,
                raw=payload,
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
    out['url'] = indicator.input
    out['domain'] = domain
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
