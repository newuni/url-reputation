#!/usr/bin/env python3
"""
URL Reputation Checker - CLI entry point
"""

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from .checker import check_url_reputation


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
        
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print_human_readable(result)


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
    
    for source, data in result['sources'].items():
        if data.get('error'):
            print(f"  {source}: ❌ Error - {data['error']}")
        elif source == 'virustotal':
            detected = data.get('detected', 0)
            total = data.get('total', 0)
            status = '🔴' if detected > 0 else '✅'
            print(f"  {source}: {status} {detected}/{total} engines detected")
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
