"""
DNS-based Blocklists (DNSBL)
Checks Spamhaus DBL and SURBL for domain reputation
No API key required
"""

import socket
from typing import Any
from urllib.parse import urlparse

# DNSBL zones to check
DNSBLS = {
    'spamhaus_dbl': 'dbl.spamhaus.org',
    'surbl': 'multi.surbl.org',
    'spamhaus_zen': 'zen.spamhaus.org',  # For IPs
}


def _extract_domain(url: str) -> str:
    """Extract base domain from URL."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split('/')[0]
    # Remove port if present
    domain = domain.split(':')[0]
    return domain


def _reverse_ip(ip: str) -> str:
    """Reverse IP octets for DNSBL lookup."""
    return '.'.join(reversed(ip.split('.')))


def _check_dnsbl(query: str, dnsbl: str, timeout: int = 5) -> bool:
    """Check if query is listed in DNSBL."""
    lookup = f"{query}.{dnsbl}"
    
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(lookup)
        return True
    except socket.gaierror:
        # NXDOMAIN = not listed
        return False
    except socket.timeout:
        return False
    except Exception:
        return False


def check(url: str, domain: str, timeout: int = 30) -> dict:
    """
    Check domain against multiple DNSBLs.
    
    Returns:
        dict with results from each DNSBL
    """
    results: dict[str, dict[str, Any]] = {}
    listed_any = False
    
    # Check domain-based DNSBLs
    for name, zone in [('spamhaus_dbl', 'dbl.spamhaus.org'), ('surbl', 'multi.surbl.org')]:
        try:
            is_listed = _check_dnsbl(domain, zone, timeout=min(timeout, 10))
            results[name] = {'listed': is_listed}
            if is_listed:
                listed_any = True
        except Exception as e:
            results[name] = {'error': str(e)}
    
    # Try to resolve domain to IP and check IP-based DNSBLs
    try:
        ip = socket.gethostbyname(domain)
        reversed_ip = _reverse_ip(ip)
        
        is_listed = _check_dnsbl(reversed_ip, 'zen.spamhaus.org', timeout=min(timeout, 10))
        results['spamhaus_zen'] = {'listed': is_listed, 'ip': ip}
        if is_listed:
            listed_any = True
    except socket.gaierror:
        results['spamhaus_zen'] = {'error': 'Could not resolve domain'}
    except Exception as e:
        results['spamhaus_zen'] = {'error': str(e)}
    
    return {
        'listed': listed_any,
        'details': results,
    }
