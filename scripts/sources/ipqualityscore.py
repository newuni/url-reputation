"""
IPQualityScore - Malicious URL Scanner & Fraud Detection
Requires API key (free tier: 5000 requests/month)
https://www.ipqualityscore.com/
"""

import urllib.request
import urllib.parse
import json
import os


def check(url: str, domain: str, timeout: int = 30) -> dict:
    """
    Check URL against IPQualityScore.
    
    Requires IPQUALITYSCORE_API_KEY environment variable.
    
    Returns:
        dict with 'risk_score', 'suspicious', 'phishing', 'malware', etc.
    """
    api_key = os.getenv('IPQUALITYSCORE_API_KEY')
    if not api_key:
        return {'error': 'IPQUALITYSCORE_API_KEY not set'}
    
    encoded_url = urllib.parse.quote(url, safe='')
    api_url = f"https://ipqualityscore.com/api/json/url/{api_key}/{encoded_url}"
    
    try:
        req = urllib.request.Request(api_url)
        req.add_header('User-Agent', 'url-reputation-checker/1.0')
        
        with urllib.request.urlopen(req, timeout=timeout) as response:
            result = json.loads(response.read().decode('utf-8'))
        
        if not result.get('success', False):
            return {'error': result.get('message', 'API error')}
        
        return {
            'risk_score': result.get('risk_score', 0),
            'suspicious': result.get('suspicious', False),
            'phishing': result.get('phishing', False),
            'malware': result.get('malware', False),
            'spamming': result.get('spamming', False),
            'adult': result.get('adult', False),
            'parking': result.get('parking', False),
            'unsafe': result.get('unsafe', False),
            'domain_rank': result.get('domain_rank'),
            'dns_valid': result.get('dns_valid', True),
            'category': result.get('category'),
            'domain_age': result.get('domain_age', {}).get('human'),
        }
        
    except urllib.error.HTTPError as e:
        if e.code == 402:
            return {'error': 'API quota exceeded'}
        return {'error': f'HTTP {e.code}'}
    except Exception as e:
        return {'error': str(e)}
