---
name: url-reputation
description: |
  Analyze URLs and domains for cybersecurity risks using multiple reputation sources.
  Use when checking if a URL/domain is malicious, phishing, spam, or has poor reputation.
  Supports: VirusTotal, URLScan.io, Google Safe Browsing, URLhaus, PhishTank, Spamhaus, SURBL.
  Works with partial API keys - free sources (URLhaus, PhishTank, DNSBL) always available.
---

# URL Reputation Checker

Multi-source URL/domain security analysis with aggregated risk scoring.

## Quick Start

```bash
# Check a URL (uses all available sources)
python3 scripts/check_url.py "https://example.com"

# Check with specific sources only
python3 scripts/check_url.py "https://example.com" --sources urlhaus,phishtank,dnsbl

# JSON output
python3 scripts/check_url.py "https://example.com" --json
```

## Available Sources

| Source | API Key Required | Rate Limit | Checks |
|--------|------------------|------------|--------|
| URLhaus | No | Unlimited | Malware URLs |
| PhishTank | No | Unlimited | Phishing URLs |
| DNSBL (Spamhaus/SURBL) | No | Unlimited | Spam/malware domains |
| VirusTotal | Yes | 4/min free | 70+ AV engines |
| URLScan.io | Yes | 5000/day | Sandbox analysis |
| Google Safe Browsing | Yes | 10k/day | Phishing/malware |
| AbuseIPDB | Yes | 1000/day | IP reputation |

## Environment Variables

Set API keys as environment variables:

```bash
export VIRUSTOTAL_API_KEY="your-key"
export URLSCAN_API_KEY="your-key"
export GOOGLE_SAFEBROWSING_API_KEY="your-key"
export ABUSEIPDB_API_KEY="your-key"
```

See `references/api_setup.md` for how to obtain free API keys.

## Risk Scoring

The aggregated risk score (0-100) is calculated based on:
- Number of sources flagging the URL
- Severity weighting (malware > phishing > spam)
- Confidence from multi-engine scanners (VirusTotal)

| Score | Verdict |
|-------|---------|
| 0-20 | CLEAN |
| 21-50 | LOW_RISK |
| 51-75 | MEDIUM_RISK |
| 76-100 | HIGH_RISK |

## Output Example

```json
{
  "url": "http://malicious-example.com",
  "domain": "malicious-example.com",
  "risk_score": 85,
  "verdict": "HIGH_RISK",
  "checked_at": "2026-01-20T19:00:00Z",
  "sources": {
    "urlhaus": {"listed": true, "threat_type": "malware_download"},
    "phishtank": {"listed": false},
    "spamhaus_dbl": {"listed": true},
    "surbl": {"listed": true},
    "virustotal": {"detected": 12, "total": 70, "scan_date": "2026-01-20"}
  }
}
```

## Programmatic Usage

```python
from scripts.check_url import check_url_reputation

result = check_url_reputation("https://suspicious-site.com")
print(f"Risk: {result['verdict']} ({result['risk_score']}/100)")
```
