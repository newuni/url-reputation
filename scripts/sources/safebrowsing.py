"""
Google Safe Browsing - Phishing and malware detection
Requires API key (free tier: 10,000 requests/day)
https://safebrowsing.google.com/
"""

import urllib.request
import json
import os


def check(url: str, domain: str, timeout: int = 30) -> dict:
    """
    Check URL against Google Safe Browsing.
    
    Requires GOOGLE_SAFEBROWSING_API_KEY environment variable.
    
    Returns:
        dict with 'threats' list if URL is flagged
    """
    api_key = os.getenv('GOOGLE_SAFEBROWSING_API_KEY')
    if not api_key:
        return {'error': 'GOOGLE_SAFEBROWSING_API_KEY not set'}
    
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    
    payload = {
        'client': {
            'clientId': 'url-reputation-checker',
            'clientVersion': '1.0.0'
        },
        'threatInfo': {
            'threatTypes': [
                'MALWARE',
                'SOCIAL_ENGINEERING',
                'UNWANTED_SOFTWARE',
                'POTENTIALLY_HARMFUL_APPLICATION'
            ],
            'platformTypes': ['ANY_PLATFORM'],
            'threatEntryTypes': ['URL'],
            'threatEntries': [
                {'url': url}
            ]
        }
    }
    
    data = json.dumps(payload).encode('utf-8')
    
    try:
        req = urllib.request.Request(api_url, data=data)
        req.add_header('Content-Type', 'application/json')
        
        with urllib.request.urlopen(req, timeout=timeout) as response:
            result = json.loads(response.read().decode('utf-8'))
        
        matches = result.get('matches', [])
        
        if matches:
            threats = []
            for match in matches:
                threats.append({
                    'type': match.get('threatType'),
                    'platform': match.get('platformType'),
                    'cache_duration': match.get('cacheDuration'),
                })
            
            return {
                'threats': threats,
                'threat_types': list(set(m['type'] for m in threats)),
            }
        
        return {'threats': []}
        
    except urllib.error.HTTPError as e:
        if e.code == 400:
            return {'error': 'Bad request - check API key'}
        return {'error': f'HTTP {e.code}: {e.reason}'}
    except Exception as e:
        return {'error': str(e)}
