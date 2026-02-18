"""
Webhook notifications with HMAC signature security.

Security model (similar to GitHub/Stripe webhooks):
- HMAC-SHA256 signature in X-Signature-256 header
- Timestamp in X-Timestamp header (prevents replay attacks)
- Signature = HMAC(secret, timestamp + "." + payload)
"""

import hashlib
import hmac
import json
import os
import time
import urllib.request
from typing import Optional


def _generate_signature(payload: str, secret: str, timestamp: int) -> str:
    """Generate HMAC-SHA256 signature."""
    message = f"{timestamp}.{payload}"
    signature = hmac.new(
        secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"sha256={signature}"


def send_webhook(url: str, data: dict, secret: Optional[str] = None, timeout: int = 10) -> dict:
    """
    Send webhook notification with optional HMAC signature.

    Args:
        url: Webhook endpoint URL
        data: Data to send (will be JSON encoded)
        secret: HMAC secret for signing (if None, no signature)
        timeout: Request timeout in seconds

    Returns:
        dict with 'success', 'status_code', 'error' if failed

    Headers sent:
        Content-Type: application/json
        X-Timestamp: Unix timestamp
        X-Signature-256: sha256=<hmac_hex> (if secret provided)
        User-Agent: url-reputation-webhook/1.0
    """
    timestamp = int(time.time())
    payload = json.dumps(data, separators=(",", ":"), sort_keys=True)

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "url-reputation-webhook/1.0",
        "X-Timestamp": str(timestamp),
    }

    if secret:
        signature = _generate_signature(payload, secret, timestamp)
        headers["X-Signature-256"] = signature

    try:
        req = urllib.request.Request(
            url, data=payload.encode("utf-8"), headers=headers, method="POST"
        )

        with urllib.request.urlopen(req, timeout=timeout) as response:
            return {
                "success": True,
                "status_code": response.status,
                "response": response.read().decode("utf-8")[:500],
            }

    except urllib.error.HTTPError as e:
        return {
            "success": False,
            "status_code": e.code,
            "error": f"HTTP {e.code}: {e.reason}",
        }
    except urllib.error.URLError as e:
        return {
            "success": False,
            "error": f"URL Error: {e.reason}",
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
        }


def notify_on_risk(
    result: dict,
    webhook_url: Optional[str] = None,
    webhook_secret: Optional[str] = None,
    min_risk_score: int = 50,
    verdicts: Optional[list] = None,
) -> Optional[dict]:
    """
    Send webhook notification if URL meets risk criteria.

    Args:
        result: Scan result from check_url_reputation()
        webhook_url: Webhook URL (or WEBHOOK_URL env var)
        webhook_secret: HMAC secret (or WEBHOOK_SECRET env var)
        min_risk_score: Minimum score to trigger notification (default: 50)
        verdicts: List of verdicts to notify on (default: ['MEDIUM_RISK', 'HIGH_RISK'])

    Returns:
        Webhook response dict if sent, None if criteria not met
    """
    webhook_url = webhook_url or os.getenv("WEBHOOK_URL")
    webhook_secret = webhook_secret or os.getenv("WEBHOOK_SECRET")

    if not webhook_url:
        return None

    if verdicts is None:
        verdicts = ["MEDIUM_RISK", "HIGH_RISK"]

    # Check if notification criteria met
    risk_score = result.get("risk_score", 0)
    verdict = result.get("verdict", "CLEAN")

    should_notify = risk_score >= min_risk_score or verdict in verdicts

    if not should_notify:
        return None

    # Build webhook payload
    payload = {
        "event": "url.risk_detected",
        "timestamp": int(time.time()),
        "data": {
            "url": result.get("url"),
            "domain": result.get("domain"),
            "risk_score": risk_score,
            "verdict": verdict,
            "checked_at": result.get("checked_at"),
            "sources": _summarize_sources(result.get("sources", {})),
        },
    }

    return send_webhook(webhook_url, payload, webhook_secret)


def _summarize_sources(sources: dict) -> dict:
    """Create a summary of flagged sources."""
    summary = {}
    for name, data in sources.items():
        if isinstance(data, dict):
            if data.get("error"):
                summary[name] = {"status": "error", "message": data["error"]}
            elif data.get("listed") or data.get("malicious") or data.get("threats"):
                summary[name] = {"status": "flagged", "details": data}
            elif name == "virustotal" and data.get("detected", 0) > 0:
                summary[name] = {
                    "status": "flagged",
                    "detected": data["detected"],
                    "total": data["total"],
                }
            else:
                summary[name] = {"status": "clean"}
    return summary


# Verification helper for webhook receivers
def verify_signature(
    payload: str, signature: str, timestamp: str, secret: str, max_age_seconds: int = 300
) -> tuple[bool, str]:
    """
    Verify webhook signature (for use by receivers).

    Args:
        payload: Raw request body (JSON string)
        signature: X-Signature-256 header value
        timestamp: X-Timestamp header value
        secret: Shared HMAC secret
        max_age_seconds: Max age of timestamp (default: 5 minutes)

    Returns:
        (is_valid, error_message)

    Example receiver code:
        payload = request.body.decode('utf-8')
        sig = request.headers.get('X-Signature-256')
        ts = request.headers.get('X-Timestamp')

        valid, error = verify_signature(payload, sig, ts, MY_SECRET)
        if not valid:
            return HttpResponse(error, status=401)
    """
    # Check timestamp age
    try:
        ts = int(timestamp)
        age = abs(time.time() - ts)
        if age > max_age_seconds:
            return False, f"Timestamp too old: {int(age)}s > {max_age_seconds}s"
    except (ValueError, TypeError):
        return False, "Invalid timestamp"

    # Verify signature
    if not signature or not signature.startswith("sha256="):
        return False, "Invalid signature format"

    expected = _generate_signature(payload, secret, ts)

    if not hmac.compare_digest(signature, expected):
        return False, "Signature mismatch"

    return True, ""
