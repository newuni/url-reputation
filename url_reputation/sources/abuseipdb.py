"""
AbuseIPDB - IP address reputation database
Requires API key (free tier: 1000 requests/day)
https://www.abuseipdb.com/
"""

import json
import os
import socket
import urllib.parse
import urllib.request

from .http_meta import error_meta, response_meta


def check(url: str, domain: str, timeout: int = 30) -> dict:
    """
    Check IP reputation via AbuseIPDB.
    Resolves domain to IP first.
    
    Requires ABUSEIPDB_API_KEY environment variable.
    
    Returns:
        dict with 'abuse_score', 'total_reports', 'country', etc.
    """
    api_key = os.getenv('ABUSEIPDB_API_KEY')
    if not api_key:
        return {'error': 'ABUSEIPDB_API_KEY not set'}
    
    # Resolve domain to IP
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        return {'error': f'Could not resolve domain: {domain}'}
    
    api_url = "https://api.abuseipdb.com/api/v2/check"
    
    params = urllib.parse.urlencode({
        'ipAddress': ip,
        'maxAgeInDays': 90,
        'verbose': ''
    })
    
    full_url = f"{api_url}?{params}"
    
    try:
        req = urllib.request.Request(full_url)
        req.add_header('Key', api_key)
        req.add_header('Accept', 'application/json')
        
        with urllib.request.urlopen(req, timeout=timeout) as response:
            http = response_meta(response)
            result = json.loads(response.read().decode('utf-8'))
        
        data = result.get('data', {})
        
        return {
            'ip': ip,
            'abuse_score': data.get('abuseConfidenceScore', 0),
            'total_reports': data.get('totalReports', 0),
            'num_distinct_users': data.get('numDistinctUsers', 0),
            'country': data.get('countryCode'),
            'isp': data.get('isp'),
            'domain': data.get('domain'),
            'is_tor': data.get('isTor', False),
            'is_whitelisted': data.get('isWhitelisted', False),
            'last_reported': data.get('lastReportedAt'),
            '_http': http,
        }
        
    except urllib.error.HTTPError as e:
        if e.code == 401:
            return {'error': 'Invalid API key', '_http': error_meta(e)}
        elif e.code == 429:
            return {'error': 'Rate limited - daily limit exceeded', '_http': error_meta(e)}
        return {'error': f'HTTP {e.code}: {e.reason}', '_http': error_meta(e)}
    except Exception as e:
        return {'error': str(e)}


def report_ip(ip: str, categories: list[int], comment: str, api_key: str = None, timeout: int = 30) -> dict:
    """
    Report an IP address to AbuseIPDB.
    
    Categories (common ones):
    - 18: Brute-Force
    - 19: Bad Web Bot
    - 20: Exploited Host
    - 21: Web App Attack
    - 22: SSH
    - 23: IoT Targeted
    
    See https://www.abuseipdb.com/categories for full list.
    """
    api_key = api_key or os.getenv('ABUSEIPDB_API_KEY')
    if not api_key:
        return {'error': 'ABUSEIPDB_API_KEY not set'}
    
    api_url = "https://api.abuseipdb.com/api/v2/report"
    
    data = urllib.parse.urlencode({
        'ip': ip,
        'categories': ','.join(str(c) for c in categories),
        'comment': comment,
    }).encode('utf-8')
    
    try:
        req = urllib.request.Request(api_url, data=data)
        req.add_header('Key', api_key)
        req.add_header('Accept', 'application/json')
        
        with urllib.request.urlopen(req, timeout=timeout) as response:
            http = response_meta(response)
            result = json.loads(response.read().decode('utf-8'))
        
        return {
            'reported': True,
            'abuse_score': result.get('data', {}).get('abuseConfidenceScore'),
            '_http': http,
        }
        
    except Exception as e:
        return {'error': str(e)}
