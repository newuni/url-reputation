"""
URL Reputation Checker - Core logic
"""

import os
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from .sources import urlhaus, phishtank, dnsbl, virustotal, urlscan, safebrowsing, abuseipdb
from .sources import alienvault_otx, ipqualityscore, threatfox

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

THREAT_WEIGHTS = {
    'malware': 40,
    'phishing': 35,
    'spam': 20,
    'suspicious': 15,
    'unknown': 10,
}


def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed = urlparse(url)
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
    """
    Check URL reputation across multiple sources.
    
    Args:
        url: URL or domain to check
        sources: List of sources to use (default: all available)
        timeout: Timeout in seconds for each source
        
    Returns:
        Dict with risk_score, verdict, and per-source results
    """
    domain = extract_domain(url)
    
    if sources is None:
        sources = list(ALL_SOURCES.keys())
    
    # Filter to only sources that have required API keys
    available_sources = []
    for source in sources:
        if source in FREE_SOURCES:
            available_sources.append(source)
        elif source == 'virustotal' and os.getenv('VIRUSTOTAL_API_KEY'):
            available_sources.append(source)
        elif source == 'urlscan' and os.getenv('URLSCAN_API_KEY'):
            available_sources.append(source)
        elif source == 'safebrowsing' and os.getenv('GOOGLE_SAFEBROWSING_API_KEY'):
            available_sources.append(source)
        elif source == 'abuseipdb' and os.getenv('ABUSEIPDB_API_KEY'):
            available_sources.append(source)
        elif source == 'ipqualityscore' and os.getenv('IPQUALITYSCORE_API_KEY'):
            available_sources.append(source)
        elif source == 'threatfox' and os.getenv('THREATFOX_API_KEY'):
            available_sources.append(source)
    
    results = {}
    
    with ThreadPoolExecutor(max_workers=len(available_sources)) as executor:
        futures = {
            executor.submit(ALL_SOURCES[source], url, domain, timeout): source
            for source in available_sources
        }
        
        for future in as_completed(futures):
            source = futures[future]
            try:
                results[source] = future.result()
            except Exception as e:
                results[source] = {'error': str(e)}
    
    risk_score, verdict = calculate_risk_score(results)
    
    return {
        'url': url,
        'domain': domain,
        'risk_score': risk_score,
        'verdict': verdict,
        'checked_at': datetime.now(timezone.utc).isoformat(),
        'sources': results,
    }


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
