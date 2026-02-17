"""
VirusTotal - Multi-engine URL scanner
Requires API key (free tier: 4 requests/minute)
https://www.virustotal.com/
"""

import base64
import json
import os
import urllib.parse
import urllib.request


def check(url: str, domain: str, timeout: int = 30) -> dict:
    """
    Check URL against VirusTotal.
    
    Requires VIRUSTOTAL_API_KEY environment variable.
    
    Returns:
        dict with 'detected', 'total', 'scan_date', 'permalink', etc.
    """
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    if not api_key:
        return {'error': 'VIRUSTOTAL_API_KEY not set'}
    
    # URL must be base64 encoded (without padding) for the API
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    try:
        req = urllib.request.Request(api_url)
        req.add_header('x-apikey', api_key)
        req.add_header('Accept', 'application/json')
        
        with urllib.request.urlopen(req, timeout=timeout) as response:
            result = json.loads(response.read().decode('utf-8'))
        
        data = result.get('data', {})
        attributes = data.get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        detected = stats.get('malicious', 0) + stats.get('suspicious', 0)
        total = sum(stats.values())
        
        return {
            'detected': detected,
            'total': total,
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'harmless': stats.get('harmless', 0),
            'undetected': stats.get('undetected', 0),
            'scan_date': attributes.get('last_analysis_date'),
            'reputation': attributes.get('reputation', 0),
            'categories': attributes.get('categories', {}),
        }
        
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # URL not in database, submit for scanning
            return _submit_url(url, api_key, timeout)
        elif e.code == 401:
            return {'error': 'Invalid API key'}
        elif e.code == 429:
            return {'error': 'Rate limited - wait before retrying'}
        return {'error': f'HTTP {e.code}: {e.reason}'}
    except Exception as e:
        return {'error': str(e)}


def _submit_url(url: str, api_key: str, timeout: int = 30) -> dict:
    """Submit URL for scanning if not in database."""
    api_url = "https://www.virustotal.com/api/v3/urls"
    
    data = urllib.parse.urlencode({'url': url}).encode('utf-8')
    
    try:
        req = urllib.request.Request(api_url, data=data)
        req.add_header('x-apikey', api_key)
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        
        with urllib.request.urlopen(req, timeout=timeout) as response:
            result = json.loads(response.read().decode('utf-8'))
        
        return {
            'detected': 0,
            'total': 0,
            'submitted': True,
            'analysis_id': result.get('data', {}).get('id'),
            'note': 'URL submitted for scanning - check back in a few minutes',
        }
        
    except Exception as e:
        return {'error': f'Failed to submit URL: {str(e)}'}
