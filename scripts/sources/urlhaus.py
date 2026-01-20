"""
URLhaus (abuse.ch) - Malware URL database
No API key required
https://urlhaus.abuse.ch/
"""

import urllib.request
import urllib.parse
import json


def check(url: str, domain: str, timeout: int = 30) -> dict:
    """
    Check URL against URLhaus database.
    
    Returns:
        dict with 'listed', 'threat_type', 'tags', etc.
    """
    api_url = "https://urlhaus-api.abuse.ch/v1/url/"
    
    data = urllib.parse.urlencode({'url': url}).encode('utf-8')
    
    try:
        req = urllib.request.Request(api_url, data=data)
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        
        with urllib.request.urlopen(req, timeout=timeout) as response:
            result = json.loads(response.read().decode('utf-8'))
        
        if result.get('query_status') == 'ok':
            return {
                'listed': True,
                'threat_type': result.get('threat', 'malware_download'),
                'tags': result.get('tags', []),
                'url_status': result.get('url_status', 'unknown'),
                'date_added': result.get('date_added'),
                'urlhaus_reference': result.get('urlhaus_reference'),
            }
        else:
            return {'listed': False}
            
    except Exception as e:
        return {'error': str(e)}


def check_host(domain: str, timeout: int = 30) -> dict:
    """Check host/domain against URLhaus."""
    api_url = "https://urlhaus-api.abuse.ch/v1/host/"
    
    data = urllib.parse.urlencode({'host': domain}).encode('utf-8')
    
    try:
        req = urllib.request.Request(api_url, data=data)
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        
        with urllib.request.urlopen(req, timeout=timeout) as response:
            result = json.loads(response.read().decode('utf-8'))
        
        if result.get('query_status') == 'ok':
            return {
                'listed': True,
                'url_count': result.get('url_count', 0),
                'urls': result.get('urls', [])[:5],  # First 5 URLs
            }
        else:
            return {'listed': False}
            
    except Exception as e:
        return {'error': str(e)}
