#!/usr/bin/env python3
"""
URL Reputation Checker - Multi-source security analysis
"""

import argparse
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

# Import source modules
from sources import abuseipdb, dnsbl, phishtank, safebrowsing, urlhaus, urlscan, virustotal

ALL_SOURCES = {
    # Free sources (no API key required)
    'urlhaus': urlhaus.check,
    'phishtank': phishtank.check,
    'dnsbl': dnsbl.check,
    # API key required
    'virustotal': virustotal.check,
    'urlscan': urlscan.check,
    'safebrowsing': safebrowsing.check,
    'abuseipdb': abuseipdb.check,
}

FREE_SOURCES = ['urlhaus', 'phishtank', 'dnsbl']

# Risk weights for different threat types
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
    detections = 0
    
    for source, data in results.items():
        if data.get('error'):
            continue
            
        if source == 'virustotal' and data.get('detected', 0) > 0:
            # VirusTotal: scale based on detection ratio
            ratio = data['detected'] / max(data.get('total', 70), 1)
            score += int(ratio * 50)
            detections += 1
            
        elif source == 'urlhaus' and data.get('listed'):
            threat = data.get('threat_type', 'malware')
            score += THREAT_WEIGHTS.get('malware', 30)
            detections += 1
            
        elif source == 'phishtank' and data.get('listed'):
            score += THREAT_WEIGHTS.get('phishing', 35)
            detections += 1
            
        elif source in ('spamhaus_dbl', 'surbl') and data.get('listed'):
            score += THREAT_WEIGHTS.get('spam', 20)
            detections += 1
            
        elif source == 'safebrowsing' and data.get('threats'):
            score += THREAT_WEIGHTS.get('malware', 35)
            detections += 1
            
        elif source == 'abuseipdb' and data.get('abuse_score', 0) > 50:
            score += int(data['abuse_score'] * 0.4)
            detections += 1
            
        elif source == 'urlscan' and data.get('malicious'):
            score += THREAT_WEIGHTS.get('suspicious', 25)
            detections += 1
    
    # Cap at 100
    score = min(score, 100)
    
    # Determine verdict
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
    
    # Determine which sources to use
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
    
    results = {}
    
    # Run checks in parallel
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
    
    # Calculate aggregated score
    risk_score, verdict = calculate_risk_score(results)
    
    return {
        'url': url,
        'domain': domain,
        'risk_score': risk_score,
        'verdict': verdict,
        'checked_at': datetime.now(timezone.utc).isoformat(),
        'sources': results,
    }


def main():
    parser = argparse.ArgumentParser(
        description='Check URL/domain reputation across multiple security sources'
    )
    parser.add_argument('url', help='URL or domain to check')
    parser.add_argument(
        '--sources', '-s',
        help='Comma-separated list of sources (default: all available)',
        default=None
    )
    parser.add_argument(
        '--json', '-j',
        action='store_true',
        help='Output as JSON'
    )
    parser.add_argument(
        '--timeout', '-t',
        type=int,
        default=30,
        help='Timeout per source in seconds (default: 30)'
    )
    
    args = parser.parse_args()
    
    sources = args.sources.split(',') if args.sources else None
    result = check_url_reputation(args.url, sources, args.timeout)
    
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        # Human-readable output
        print("\n🔍 URL Reputation Report")
        print(f"{'='*50}")
        print(f"URL:    {result['url']}")
        print(f"Domain: {result['domain']}")
        print(f"{'='*50}")
        
        verdict_emoji = {
            'CLEAN': '✅',
            'LOW_RISK': '⚠️',
            'MEDIUM_RISK': '🟠',
            'HIGH_RISK': '🔴'
        }
        
        print(f"\n{verdict_emoji.get(result['verdict'], '❓')} Verdict: {result['verdict']}")
        print(f"📊 Risk Score: {result['risk_score']}/100")
        
        print("\n📋 Source Results:")
        print(f"{'-'*50}")
        
        for source, data in result['sources'].items():
            if data.get('error'):
                print(f"  {source}: ❌ Error - {data['error']}")
            elif source == 'virustotal':
                detected = data.get('detected', 0)
                total = data.get('total', 0)
                status = '🔴' if detected > 0 else '✅'
                print(f"  {source}: {status} {detected}/{total} engines detected")
            elif data.get('listed'):
                threat = data.get('threat_type', 'unknown')
                print(f"  {source}: 🔴 Listed ({threat})")
            elif data.get('malicious'):
                print(f"  {source}: 🔴 Malicious")
            elif data.get('threats'):
                print(f"  {source}: 🔴 Threats found")
            elif data.get('abuse_score', 0) > 50:
                print(f"  {source}: 🟠 Abuse score: {data['abuse_score']}")
            else:
                print(f"  {source}: ✅ Clean")
        
        print(f"\n⏱️  Checked at: {result['checked_at']}")


if __name__ == '__main__':
    main()
