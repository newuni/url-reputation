"""
URLhaus (abuse.ch) - Malware URL database
Uses the plaintext/JSON dumps (updated every 5 minutes)
No API key required
https://urlhaus.abuse.ch/
"""

import urllib.request
import json
import os
import time
from urllib.parse import urlparse

# Cache settings
CACHE_FILE = "/tmp/urlhaus_cache.json"
CACHE_TTL = 300  # 5 minutes


def _get_domain(url: str) -> str:
    """Extract domain from URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc or parsed.path.split('/')[0]
    except:
        return url


def _load_cache() -> tuple[dict, float]:
    """Load cached data if valid."""
    try:
        if os.path.exists(CACHE_FILE):
            mtime = os.path.getmtime(CACHE_FILE)
            if time.time() - mtime < CACHE_TTL:
                with open(CACHE_FILE, 'r') as f:
                    return json.load(f), mtime
    except:
        pass
    return None, 0


def _save_cache(data: dict):
    """Save data to cache."""
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(data, f)
    except:
        pass


def _fetch_urlhaus_data(timeout: int = 30) -> dict:
    """Fetch recent URLhaus data."""
    # Check cache first
    cached, _ = _load_cache()
    if cached:
        return cached
    
    # Fetch online URLs (smaller, faster)
    url = "https://urlhaus.abuse.ch/downloads/json_online/"
    
    try:
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'url-reputation-checker/1.0')
        
        with urllib.request.urlopen(req, timeout=timeout) as response:
            # It's a zip file, but let's try the text version instead
            pass
    except:
        pass
    
    # Try plaintext version (simpler)
    text_url = "https://urlhaus.abuse.ch/downloads/text_online/"
    
    try:
        req = urllib.request.Request(text_url)
        req.add_header('User-Agent', 'url-reputation-checker/1.0')
        
        with urllib.request.urlopen(req, timeout=timeout) as response:
            content = response.read().decode('utf-8')
        
        # Parse URLs into a set for fast lookup
        urls = set()
        domains = set()
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#'):
                urls.add(line.lower())
                domains.add(_get_domain(line).lower())
        
        data = {'urls': list(urls), 'domains': list(domains)}
        _save_cache(data)
        return data
        
    except Exception as e:
        return {'error': str(e)}


def check(url: str, domain: str, timeout: int = 30) -> dict:
    """
    Check URL against URLhaus database.
    
    Returns:
        dict with 'listed', 'match_type', etc.
    """
    data = _fetch_urlhaus_data(timeout)
    
    if 'error' in data:
        return data
    
    url_lower = url.lower()
    domain_lower = domain.lower()
    
    # Check exact URL match
    urls = set(data.get('urls', []))
    if url_lower in urls:
        return {
            'listed': True,
            'match_type': 'exact_url',
            'threat_type': 'malware_download',
        }
    
    # Check domain match
    domains = set(data.get('domains', []))
    if domain_lower in domains:
        return {
            'listed': True,
            'match_type': 'domain',
            'threat_type': 'malware_host',
        }
    
    return {'listed': False}
