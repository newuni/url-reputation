#!/usr/bin/env python3
"""
URL Reputation Checker - CLI entry point
"""

import argparse
import json
import sys

from .checker import check_url_reputation


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
        print_human_readable(result)


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
