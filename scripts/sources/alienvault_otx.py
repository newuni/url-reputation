"""
AlienVault OTX (Open Threat Exchange) - Community threat intelligence
No API key required for basic lookups (key gives higher rate limits)
https://otx.alienvault.com/
"""

import json
import os
import urllib.request


def check(url: str, domain: str, timeout: int = 30) -> dict:
    """
    Check domain against AlienVault OTX.
    
    Optional: OTX_API_KEY for higher rate limits
    
    Returns:
        dict with 'pulses', 'reputation', 'validation', etc.
    """
    api_key = os.getenv('OTX_API_KEY')
    
    api_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    
    try:
        req = urllib.request.Request(api_url)
        req.add_header('User-Agent', 'url-reputation-checker/1.0')
        if api_key:
            req.add_header('X-OTX-API-KEY', api_key)
        
        with urllib.request.urlopen(req, timeout=timeout) as response:
            result = json.loads(response.read().decode('utf-8'))
        
        pulse_info = result.get('pulse_info', {})
        pulse_count = pulse_info.get('count', 0)
        validation = result.get('validation', [])
        
        # Check for whitelisted/false positive
        is_whitelisted = any(
            v.get('source') in ('whitelist', 'false_positive', 'majestic')
            for v in validation
        )
        
        # Get Alexa rank if available
        alexa_rank = None
        for v in validation:
            if v.get('source') == 'alexa':
                msg = v.get('message', '')
                if '#' in msg:
                    try:
                        alexa_rank = int(msg.split('#')[1].split()[0].replace(',', ''))
                    except:
                        pass
        
        return {
            'pulse_count': pulse_count,
            'has_pulses': pulse_count > 0,
            'is_whitelisted': is_whitelisted,
            'alexa_rank': alexa_rank,
            'validation': [v.get('name') for v in validation],
            'pulses': [
                {
                    'name': p.get('name'),
                    'tags': p.get('tags', [])[:5],
                    'created': p.get('created'),
                }
                for p in pulse_info.get('pulses', [])[:3]  # First 3 pulses
            ],
        }
        
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {'pulse_count': 0, 'has_pulses': False}
        return {'error': f'HTTP {e.code}'}
    except Exception as e:
        return {'error': str(e)}


def check_url_indicators(url: str, domain: str, timeout: int = 30) -> dict:
    """Check URL-specific indicators."""
    api_key = os.getenv('OTX_API_KEY')
    
    import urllib.parse
    encoded_url = urllib.parse.quote(url, safe='')
    api_url = f"https://otx.alienvault.com/api/v1/indicators/url/{encoded_url}/general"
    
    try:
        req = urllib.request.Request(api_url)
        req.add_header('User-Agent', 'url-reputation-checker/1.0')
        if api_key:
            req.add_header('X-OTX-API-KEY', api_key)
        
        with urllib.request.urlopen(req, timeout=timeout) as response:
            result = json.loads(response.read().decode('utf-8'))
        
        return {
            'pulse_count': result.get('pulse_info', {}).get('count', 0),
            'alexa': result.get('alexa'),
        }
        
    except:
        return {}
