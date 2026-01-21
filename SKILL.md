---
name: url-reputation
description: |
  Analyze URLs and domains for cybersecurity risks using 10 reputation sources.
  Use when checking if a URL/domain is malicious, phishing, spam, or has poor reputation.
  Free sources always available: URLhaus, OpenPhish, DNSBL, AlienVault OTX.
---

# URL Reputation Checker

Multi-source URL/domain security analysis with aggregated risk scoring.

## Quick Usage

```bash
# Single URL
url-reputation "https://example.com"

# JSON output
url-reputation "https://example.com" --json

# Batch from file
url-reputation --file urls.txt

# Specific sources only
url-reputation "https://example.com" --sources urlhaus,dnsbl,alienvault_otx
```

## Available Sources (10 total)

### Free (no API key)
- `urlhaus` - Malware URLs (abuse.ch)
- `phishtank` - Phishing (OpenPhish)
- `dnsbl` - Spamhaus DBL, SURBL, ZEN
- `alienvault_otx` - Community threat intel

### With API key
- `virustotal` - 70+ AV engines
- `urlscan` - Sandbox analysis
- `safebrowsing` - Google phishing/malware
- `abuseipdb` - IP reputation
- `ipqualityscore` - Fraud detection
- `threatfox` - IOCs (abuse.ch)

## Risk Scoring

| Score | Verdict |
|-------|---------|
| 0-20 | CLEAN |
| 21-50 | LOW_RISK |
| 51-75 | MEDIUM_RISK |
| 76-100 | HIGH_RISK |

## Python API

```python
from url_reputation import check_url_reputation, check_urls_batch

result = check_url_reputation("https://example.com")
print(f"{result['verdict']}: {result['risk_score']}/100")

# Batch
results = check_urls_batch(["https://a.com", "https://b.com"])
```
