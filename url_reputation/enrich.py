"""
Enrichment modules for DNS and Whois data.
"""

import contextlib
import re
import socket
import subprocess
from datetime import datetime
from typing import Any, Optional


def enrich_dns(domain: str, timeout: int = 10) -> dict[str, Any]:
    """
    Get DNS records for a domain.

    Uses socket for basic resolution, dnspython if available for full records.

    Returns:
        dict with a_records, aaaa_records, mx_records, ns_records, txt_records
    """
    result: dict[str, Any] = {
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "ns_records": [],
        "txt_records": [],
    }

    # Try dnspython first (more complete)
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout

        # A records
        try:
            answers = resolver.resolve(domain, "A")
            result["a_records"] = [str(r) for r in answers]
        except Exception:
            pass

        # AAAA records
        try:
            answers = resolver.resolve(domain, "AAAA")
            result["aaaa_records"] = [str(r) for r in answers]
        except Exception:
            pass

        # MX records
        try:
            answers = resolver.resolve(domain, "MX")
            result["mx_records"] = [
                {"priority": r.preference, "host": str(r.exchange).rstrip(".")} for r in answers
            ]
        except Exception:
            pass

        # NS records
        try:
            answers = resolver.resolve(domain, "NS")
            result["ns_records"] = [str(r).rstrip(".") for r in answers]
        except Exception:
            pass

        # TXT records
        try:
            answers = resolver.resolve(domain, "TXT")
            result["txt_records"] = [str(r).strip('"') for r in answers]
        except Exception:
            pass

        # Extract security indicators from TXT
        result["has_spf"] = any("v=spf1" in txt for txt in result["txt_records"])
        result["has_dmarc"] = False

        # Check DMARC
        try:
            dmarc = resolver.resolve(f"_dmarc.{domain}", "TXT")
            result["has_dmarc"] = any("v=DMARC1" in str(r) for r in dmarc)
        except Exception:
            pass

    except ImportError:
        # Fallback to socket (only A records)
        try:
            socket.setdefaulttimeout(timeout)
            result["a_records"] = list(
                set(info[4][0] for info in socket.getaddrinfo(domain, None, socket.AF_INET))
            )
        except Exception:
            pass

        with contextlib.suppress(Exception):
            result["aaaa_records"] = list(
                set(info[4][0] for info in socket.getaddrinfo(domain, None, socket.AF_INET6))
            )

    # Add IP geolocation for first A record
    if result["a_records"]:
        result["primary_ip"] = result["a_records"][0]

    return result


def enrich_whois(domain: str, timeout: int = 10) -> dict:
    """
    Get Whois information for a domain.

    Tries python-whois library first, falls back to CLI.

    Returns:
        dict with creation_date, registrar, domain_age_days, etc.
    """
    result: dict[str, Any] = {
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "registrar": None,
        "registrant_country": None,
        "domain_age_days": None,
        "is_new_domain": None,  # < 30 days
    }

    # Try python-whois first
    try:
        import whois

        w = whois.whois(domain)

        # Handle dates (can be list or single value)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            result["creation_date"] = (
                creation.isoformat() if hasattr(creation, "isoformat") else str(creation)
            )
            if isinstance(creation, datetime):
                age = (datetime.now() - creation).days
                result["domain_age_days"] = age
                result["is_new_domain"] = age < 30

        expiration = w.expiration_date
        if isinstance(expiration, list):
            expiration = expiration[0]
        if expiration:
            result["expiration_date"] = (
                expiration.isoformat() if hasattr(expiration, "isoformat") else str(expiration)
            )

        result["registrar"] = w.registrar
        result["registrant_country"] = w.get("country")
        result["name_servers"] = w.name_servers if w.name_servers else []

        return result

    except ImportError:
        pass
    except Exception as e:
        result["error"] = f"whois library error: {str(e)}"

    # Fallback to CLI whois
    try:
        proc = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=timeout)

        if proc.returncode == 0:
            output = proc.stdout

            # Parse creation date
            for pattern in [
                r"Creation Date:\s*(.+)",
                r"Created:\s*(.+)",
                r"created:\s*(.+)",
                r"Registration Date:\s*(.+)",
            ]:
                match = re.search(pattern, output, re.IGNORECASE)
                if match:
                    result["creation_date"] = match.group(1).strip()
                    # Try to calculate age
                    try:
                        for fmt in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d", "%d-%b-%Y"]:
                            try:
                                dt = datetime.strptime(result["creation_date"][:19], fmt)
                                result["domain_age_days"] = (datetime.now() - dt).days
                                result["is_new_domain"] = result["domain_age_days"] < 30
                                break
                            except Exception:
                                continue
                    except Exception:
                        pass
                    break

            # Parse registrar
            match = re.search(r"Registrar:\s*(.+)", output, re.IGNORECASE)
            if match:
                result["registrar"] = match.group(1).strip()

            # Parse country
            match = re.search(r"Registrant Country:\s*(.+)", output, re.IGNORECASE)
            if match:
                result["registrant_country"] = match.group(1).strip()

    except FileNotFoundError:
        result["error"] = "whois CLI not available"
    except subprocess.TimeoutExpired:
        result["error"] = "whois timeout"
    except Exception as e:
        result["error"] = str(e)

    return result


def enrich(domain: str, types: Optional[list[str]] = None, timeout: int = 10) -> dict[str, Any]:
    """
    Run enrichment for specified types.

    Args:
        domain: Domain to enrich
        types: List of enrichment types ('dns', 'whois'). Default: all
        timeout: Timeout per enrichment

    Returns:
        dict with enrichment data
    """
    types_list: Optional[list[str]] = types
    if types_list is None:
        types_list = ["dns", "whois"]

    result: dict[str, Any] = {}

    if "dns" in types_list:
        result["dns"] = enrich_dns(domain, timeout)

    if "whois" in types_list:
        result["whois"] = enrich_whois(domain, timeout)

    # Calculate risk indicators
    risk_indicators: list[str] = []

    if "whois" in result:
        whois = result["whois"]
        if whois.get("is_new_domain"):
            risk_indicators.append("Domain registered < 30 days ago")
        if whois.get("domain_age_days") and whois["domain_age_days"] < 7:
            risk_indicators.append("Domain registered < 7 days ago (very suspicious)")

    if "dns" in result:
        dns = result["dns"]
        if not dns.get("a_records"):
            risk_indicators.append("No A records found")
        if not dns.get("mx_records"):
            risk_indicators.append("No MX records (no email capability)")
        if not dns.get("has_spf"):
            risk_indicators.append("No SPF record")

    if risk_indicators:
        result["risk_indicators"] = risk_indicators

    return result
