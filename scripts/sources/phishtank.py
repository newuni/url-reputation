"""
PhishTank - Community phishing verification
No API key required for basic lookups
https://phishtank.org/
"""

import urllib.request
import urllib.parse
import json
import base64


def check(url: str, domain: str, timeout: int = 30) -> dict:
    """
    Check URL against PhishTank database.
    
    Returns:
        dict with 'listed', 'verified', 'phish_detail_page', etc.
    """
    api_url = "https://checkurl.phishtank.com/checkurl/"
    
    # PhishTank requires URL to be in a specific format
    encoded_url = base64.b64encode(url.encode('utf-8')).decode('utf-8')
    
    data = urllib.parse.urlencode({
        'url': url,
        'format': 'json',
        'app_key': '',  # Optional, allows more requests
    }).encode('utf-8')
    
    try:
        req = urllib.request.Request(api_url, data=data)
        req.add_header('Content-Type', 'application/x-www-form-urlencoded')
        req.add_header('User-Agent', 'url-reputation-checker/1.0')
        
        with urllib.request.urlopen(req, timeout=timeout) as response:
            result = json.loads(response.read().decode('utf-8'))
        
        results = result.get('results', {})
        in_database = results.get('in_database', False)
        
        if in_database:
            return {
                'listed': results.get('valid', False),
                'verified': results.get('verified', False),
                'verified_at': results.get('verified_at'),
                'phish_id': results.get('phish_id'),
                'phish_detail_page': results.get('phish_detail_page'),
            }
        else:
            return {'listed': False}
            
    except urllib.error.HTTPError as e:
        if e.code == 509:
            return {'error': 'Rate limited - too many requests'}
        return {'error': f'HTTP {e.code}: {e.reason}'}
    except Exception as e:
        return {'error': str(e)}
