#!/usr/bin/env python3
"""
URL Reputation Checker - CLI entry point
"""

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from .checker import check_url_reputation
from .webhook import notify_on_risk
from .enrich import enrich


def main():
    parser = argparse.ArgumentParser(
        description='Check URL/domain reputation across multiple security sources'
    )
    parser.add_argument(
        'url',
        nargs='?',
        help='URL or domain to check (optional if using --file)'
    )
    parser.add_argument(
        '--file', '-f',
        help='File with URLs to check (one per line)',
        default=None
    )
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
    parser.add_argument(
        '--workers', '-w',
        type=int,
        default=5,
        help='Max parallel workers for batch processing (default: 5)'
    )
    parser.add_argument(
        '--webhook',
        help='Webhook URL for notifications (or set WEBHOOK_URL env var)',
        default=None
    )
    parser.add_argument(
        '--webhook-secret',
        help='Webhook HMAC secret (or set WEBHOOK_SECRET env var)',
        default=None
    )
    parser.add_argument(
        '--notify-on',
        help='Risk level to notify on: all, high, medium (default: medium)',
        choices=['all', 'high', 'medium'],
        default='medium'
    )
    parser.add_argument(
        '--enrich',
        help='Enrichment data to include: dns,whois (comma-separated)',
        default=None
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.url and not args.file:
        parser.error("Either URL or --file is required")
    
    sources = args.sources.split(',') if args.sources else None
    
    # Batch mode: process file
    if args.file:
        results = check_urls_from_file(
            args.file,
            sources=sources,
            timeout=args.timeout,
            max_workers=args.workers
        )
        
        if args.json:
            print(json.dumps(results, indent=2))
        else:
            print_batch_results(results)
    else:
        # Single URL mode
        result = check_url_reputation(args.url, sources, args.timeout)
        
        # Add enrichment if requested
        if args.enrich:
            enrich_types = [t.strip() for t in args.enrich.split(',')]
            result['enrichment'] = enrich(result['domain'], enrich_types, args.timeout)
        
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print_human_readable(result)
            if args.enrich:
                print_enrichment(result.get('enrichment', {}))
        
        # Send webhook notification if configured
        _maybe_send_webhook(result, args)


def check_urls_from_file(
    filepath: str,
    sources: list = None,
    timeout: int = 30,
    max_workers: int = 5
) -> list:
    """
    Check multiple URLs from a file.
    
    Args:
        filepath: Path to file with URLs (one per line)
        sources: List of sources to use
        timeout: Timeout per source
        max_workers: Maximum parallel workers
        
    Returns:
        List of results for each URL
    """
    # Read URLs from file
    urls = []
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            # Skip empty lines and comments
            if line and not line.startswith('#'):
                urls.append(line)
    
    if not urls:
        return []
    
    results = []
    
    # Process URLs in parallel
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


def _maybe_send_webhook(result: dict, args):
    """Send webhook notification if configured and criteria met."""
    webhook_url = args.webhook or os.getenv('WEBHOOK_URL')
    if not webhook_url:
        return
    
    # Determine notification criteria
    notify_levels = {
        'all': (['CLEAN', 'LOW_RISK', 'MEDIUM_RISK', 'HIGH_RISK'], 0),
        'medium': (['MEDIUM_RISK', 'HIGH_RISK'], 50),
        'high': (['HIGH_RISK'], 76),
    }
    verdicts, min_score = notify_levels.get(args.notify_on, notify_levels['medium'])
    
    response = notify_on_risk(
        result,
        webhook_url=webhook_url,
        webhook_secret=args.webhook_secret,
        min_risk_score=min_score,
        verdicts=verdicts
    )
    
    if response:
        if response.get('success'):
            print(f"\n📤 Webhook sent: {response.get('status_code')}")
        else:
            print(f"\n⚠️ Webhook failed: {response.get('error')}")


def print_enrichment(enrichment: dict):
    """Print enrichment data in human-readable format."""
    if not enrichment:
        return
    
    print(f"\n📋 Enrichment Data:")
    print(f"{'-'*50}")
    
    # DNS
    if 'dns' in enrichment:
        dns = enrichment['dns']
        print(f"\n🌐 DNS Records:")
        if dns.get('a_records'):
            print(f"  A:     {', '.join(dns['a_records'])}")
        if dns.get('aaaa_records'):
            print(f"  AAAA:  {', '.join(dns['aaaa_records'][:2])}...")
        if dns.get('mx_records'):
            mx = dns['mx_records']
            if isinstance(mx[0], dict):
                print(f"  MX:    {mx[0].get('host', mx[0])}")
            else:
                print(f"  MX:    {mx[0]}")
        if dns.get('ns_records'):
            print(f"  NS:    {', '.join(dns['ns_records'][:2])}")
        
        # Security
        spf = '✅' if dns.get('has_spf') else '❌'
        dmarc = '✅' if dns.get('has_dmarc') else '❌'
        print(f"  SPF:   {spf}  DMARC: {dmarc}")
    
    # Whois
    if 'whois' in enrichment:
        whois = enrichment['whois']
        print(f"\n📝 Whois:")
        if whois.get('creation_date'):
            age = whois.get('domain_age_days', '?')
            new_badge = ' ⚠️ NEW!' if whois.get('is_new_domain') else ''
            print(f"  Created:   {whois['creation_date'][:10]} ({age} days){new_badge}")
        if whois.get('registrar'):
            print(f"  Registrar: {whois['registrar'][:40]}")
        if whois.get('registrant_country'):
            print(f"  Country:   {whois['registrant_country']}")
        if whois.get('error'):
            print(f"  ⚠️ {whois['error']}")
    
    # Risk indicators
    if 'risk_indicators' in enrichment:
        print(f"\n⚠️ Risk Indicators:")
        for indicator in enrichment['risk_indicators']:
            print(f"  • {indicator}")


def print_batch_results(results: list):
    """Print batch results in human-readable format."""
    print(f"\n🔍 URL Reputation Batch Report")
    print(f"{'='*60}")
    print(f"Total URLs: {len(results)}")
    
    # Summary counts
    verdicts = {}
    for r in results:
        v = r.get('verdict', 'ERROR')
        verdicts[v] = verdicts.get(v, 0) + 1
    
    print(f"\n📊 Summary:")
    verdict_emoji = {
        'CLEAN': '✅',
        'LOW_RISK': '⚠️',
        'MEDIUM_RISK': '🟠',
        'HIGH_RISK': '🔴',
        'ERROR': '❌'
    }
    for verdict, count in sorted(verdicts.items()):
        emoji = verdict_emoji.get(verdict, '❓')
        print(f"  {emoji} {verdict}: {count}")
    
    print(f"\n{'='*60}")
    print(f"📋 Results:")
    print(f"{'-'*60}")
    
    for result in results:
        url = result.get('url', 'unknown')
        verdict = result.get('verdict', 'ERROR')
        score = result.get('risk_score', '-')
        emoji = verdict_emoji.get(verdict, '❓')
        
        if verdict == 'ERROR':
            print(f"  {emoji} {url}")
            print(f"      Error: {result.get('error', 'Unknown error')}")
        else:
            print(f"  {emoji} [{score:>3}/100] {verdict:<12} {url}")
    
    print()


def print_human_readable(result: dict):
    """Print human-readable output."""
    print(f"\n🔍 URL Reputation Report")
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
    
    print(f"\n📋 Source Results:")
    print(f"{'-'*50}")
    
    # Schema v1: sources is a list of source results
    for src in result.get('sources', []):
        source = src.get('name', 'unknown')
        status = src.get('status')
        data = src.get('raw', {})
        err = src.get('error')

        if status == 'error' or err:
            print(f"  {source}: ❌ Error - {err or 'Unknown error'}")
        elif source == 'virustotal':
            detected = data.get('detected', 0)
            total = data.get('total', 0)
            icon = '🔴' if detected > 0 else '✅'
            print(f"  {source}: {icon} {detected}/{total} engines detected")
        elif data.get('listed'):
            threat = data.get('threat_type', data.get('match_type', 'unknown'))
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
