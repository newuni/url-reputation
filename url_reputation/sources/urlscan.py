"""
URLScan.io - Website scanner and sandbox
Requires API key (free tier: 5000 requests/day)
https://urlscan.io/
"""

import json
import os
import urllib.request

from .http_meta import error_meta, response_meta


def check(url: str, domain: str, timeout: int = 30) -> dict:
    """
    Check URL against URLScan.io.

    Requires URLSCAN_API_KEY environment variable.

    Returns:
        dict with scan results including 'malicious', 'score', 'screenshot', etc.
    """
    api_key = os.getenv("URLSCAN_API_KEY")
    if not api_key:
        return {"error": "URLSCAN_API_KEY not set"}

    # First, search for existing scans of this URL
    search_result = _search_url(url, api_key, timeout)

    if search_result.get("found"):
        return search_result

    # If no recent scan, submit for scanning
    return _submit_scan(url, api_key, timeout)


def _search_url(url: str, api_key: str, timeout: int = 30) -> dict:
    """Search for existing scans of URL."""
    import urllib.parse

    encoded_url = urllib.parse.quote(url, safe="")
    api_url = f"https://urlscan.io/api/v1/search/?q=page.url:{encoded_url}"

    try:
        req = urllib.request.Request(api_url)
        req.add_header("API-Key", api_key)

        with urllib.request.urlopen(req, timeout=timeout) as response:
            http = response_meta(response)
            result = json.loads(response.read().decode("utf-8"))

        results = result.get("results", [])

        if results:
            # Get the most recent scan
            latest = results[0]
            task = latest.get("task", {})
            page = latest.get("page", {})
            verdicts = latest.get("verdicts", {})

            overall = verdicts.get("overall", {})

            return {
                "found": True,
                "malicious": overall.get("malicious", False),
                "score": overall.get("score", 0),
                "categories": overall.get("categories", []),
                "brands": overall.get("brands", []),
                "screenshot": latest.get("screenshot"),
                "scan_url": latest.get("result"),
                "scan_date": task.get("time"),
                "ip": page.get("ip"),
                "country": page.get("country"),
                "server": page.get("server"),
                "_http": http,
            }

        return {"found": False, "_http": http}

    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}", "_http": error_meta(e)}
    except Exception as e:
        return {"error": str(e)}


def _submit_scan(url: str, api_key: str, timeout: int = 30) -> dict:
    """Submit URL for scanning."""
    api_url = "https://urlscan.io/api/v1/scan/"

    data = json.dumps(
        {
            "url": url,
            "visibility": "unlisted",  # Don't make scan public
        }
    ).encode("utf-8")

    try:
        req = urllib.request.Request(api_url, data=data)
        req.add_header("API-Key", api_key)
        req.add_header("Content-Type", "application/json")

        with urllib.request.urlopen(req, timeout=timeout) as response:
            http = response_meta(response)
            result = json.loads(response.read().decode("utf-8"))

        return {
            "found": False,
            "submitted": True,
            "scan_uuid": result.get("uuid"),
            "result_url": result.get("result"),
            "note": "URL submitted for scanning - results available in ~30 seconds",
            "_http": http,
        }

    except urllib.error.HTTPError as e:
        if e.code == 429:
            return {"error": "Rate limited", "_http": error_meta(e)}
        return {"error": f"HTTP {e.code}", "_http": error_meta(e)}
    except Exception as e:
        return {"error": str(e)}
