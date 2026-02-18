"""
ThreatFox (abuse.ch) - IOC (Indicators of Compromise) database
Requires Auth-Key (free registration at https://auth.abuse.ch/)
https://threatfox.abuse.ch/
"""

import json
import os
import urllib.request
from typing import Any, Optional

from .http_meta import error_meta, response_meta


def check(url: str, domain: str, timeout: int = 30) -> Optional[dict[str, Any]]:
    """
    Check domain/URL against ThreatFox IOC database.

    Requires THREATFOX_API_KEY environment variable.

    Returns:
        dict with 'listed', 'iocs', 'malware', etc.
    """
    api_key = os.getenv("THREATFOX_API_KEY")
    if not api_key:
        return {"error": "THREATFOX_API_KEY not set"}

    api_url = "https://threatfox-api.abuse.ch/api/v1/"

    # Search by domain/host
    payload = json.dumps({"query": "search_ioc", "search_term": domain}).encode("utf-8")

    try:
        req = urllib.request.Request(api_url, data=payload)
        req.add_header("Content-Type", "application/json")
        req.add_header("Auth-Key", api_key)
        req.add_header("User-Agent", "url-reputation-checker/1.0")

        with urllib.request.urlopen(req, timeout=timeout) as response:
            http = response_meta(response)
            result = json.loads(response.read().decode("utf-8"))

        query_status = result.get("query_status")

        if query_status == "ok":
            data = result.get("data", [])

            if data:
                # Aggregate findings
                malware_families = set()
                threat_types = set()
                iocs = []

                for ioc in data[:10]:  # First 10 IOCs
                    if ioc.get("malware"):
                        malware_families.add(ioc["malware"])
                    if ioc.get("threat_type"):
                        threat_types.add(ioc["threat_type"])
                    iocs.append(
                        {
                            "ioc": ioc.get("ioc"),
                            "threat_type": ioc.get("threat_type"),
                            "malware": ioc.get("malware"),
                            "confidence": ioc.get("confidence_level"),
                            "first_seen": ioc.get("first_seen"),
                        }
                    )

                return {
                    "listed": True,
                    "ioc_count": len(data),
                    "malware_families": list(malware_families),
                    "threat_types": list(threat_types),
                    "iocs": iocs[:5],  # Return top 5
                    "_http": http,
                }

        elif query_status == "no_result":
            return {"listed": False, "_http": http}

        else:
            return {"error": f"Query status: {query_status}", "_http": http}

    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.reason}", "_http": error_meta(e)}
    except Exception as e:
        return {"error": str(e)}

    return None


def check_hash(file_hash: str, timeout: int = 30) -> dict[str, Any]:
    """Check file hash against ThreatFox."""
    api_url = "https://threatfox-api.abuse.ch/api/v1/"

    payload = json.dumps({"query": "search_hash", "hash": file_hash}).encode("utf-8")

    try:
        req = urllib.request.Request(api_url, data=payload)
        req.add_header("Content-Type", "application/json")

        with urllib.request.urlopen(req, timeout=timeout) as response:
            http = response_meta(response)
            result = json.loads(response.read().decode("utf-8"))

        if result.get("query_status") == "ok":
            return {
                "found": True,
                "data": result.get("data", [])[:5],
                "_http": http,
            }

        return {"found": False, "_http": http}

    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.reason}", "_http": error_meta(e)}
    except Exception as e:
        return {"error": str(e)}
